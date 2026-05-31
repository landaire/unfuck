use crate::error::Error;
use crate::partial_execution::*;
use crate::smallvm::{InstructionTracker, ParsedInstr};
use bitflags::bitflags;

use crossbeam::channel::unbounded;

use log::{error, trace};

use petgraph::algo::{astar, dijkstra};
use petgraph::graph::{EdgeIndex, Graph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::{Direction, IntoWeightedEdge};
use py27_marshal::{Code, Obj};
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::fmt;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

bitflags! {
    #[derive(Default)]
    pub struct BasicBlockFlags: u32 {
        /// Offsets have already been updated on this node
        const OFFSETS_UPDATED = 0b00000001;

        /// Branch target has already been updated on this node
        const BRANCHES_UPDATED = 0b00000010;

        /// Bytecode has been written for this node
        const BYTECODE_WRITTEN = 0b00000100;

        /// This node contains a condition which could be statically asserted
        const CONSTEXPR_CONDITION = 0b00001000;

        /// This node must be kept (in some capacity) as it's
        const USED_IN_EXECUTION = 0b00010000;

        /// This node has already been checked for constexpr conditions which may be removed
        const CONSTEXPR_CHECKED = 0b00100000;

        /// This node has already had a JUMP_FORWARD 0 inserted
        const JUMP0_INSERTED = 0b01000000;
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum EdgeWeight {
    NonJump,
    Jump,
}
impl fmt::Display for EdgeWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

/// A deferred operand patch for a dead body-terminating `JUMP_ABSOLUTE` inserted by
/// [`CodeGraph::insert_decompiler_jumps`]. The operand is the merge block's offset,
/// which is only known once block layout is final.
pub(crate) struct DecompilerJumpFixup {
    /// Block holding the inserted jumps.
    pub(crate) block: NodeIndex,
    /// Merge block the dead jumps target.
    pub(crate) merge: NodeIndex,
    /// Number of dead `JUMP_ABSOLUTE`s preceding the trailing `JUMP_FORWARD`.
    pub(crate) dead_jumps: usize,
}

/// Represents a single block of code up until its next branching point
#[derive(Debug, Clone)]
pub struct BasicBlock<O: Opcode<Mnemonic = py27::Mnemonic>> {
    /// Offset of the first instruction in this BB
    pub start_offset: u64,
    /// Offset of the last instruction in this BB (note: this is the START of the last instruction)
    pub end_offset: u64,
    /// Instructions contained within this BB
    pub instrs: Vec<ParsedInstr<O>>,
    /// Whether this BB contains invalid instructions
    pub has_bad_instrs: bool,
    /// Flags used for internal purposes
    pub flags: BasicBlockFlags,
    /// The end of the last instruction
    last_instruction_end: u64,
}

impl<O: Opcode<Mnemonic = py27::Mnemonic>> Default for BasicBlock<O> {
    fn default() -> Self {
        BasicBlock {
            start_offset: 0,
            end_offset: 0,
            instrs: vec![],
            has_bad_instrs: false,
            flags: BasicBlockFlags::default(),
            last_instruction_end: 0,
        }
    }
}

impl<O: Opcode<Mnemonic = py27::Mnemonic>> fmt::Display for BasicBlock<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Flags: {:?}", self.flags)?;
        let mut offset = self.start_offset;
        for (i, instr) in self.instrs.iter().enumerate() {
            match instr {
                ParsedInstr::Good(instr) => {
                    writeln!(f, "{} @ {} {}", i, offset, instr)?;
                    offset += instr.len() as u64;
                }
                ParsedInstr::GoodDoNotRemove(instr) => {
                    writeln!(f, "{} @ {} (do_not_remove) {}", i, offset, instr)?;
                    offset += instr.len() as u64;
                }
                ParsedInstr::Bad => {
                    writeln!(f, "BAD_INSTR")?;
                }
            }
        }

        Ok(())
    }
}

impl<O: Opcode<Mnemonic = py27::Mnemonic>> BasicBlock<O> {
    /// Splits a basic block at the target absolute offset. The instruction index is calculated
    /// on-demand, walking the instructions and adding their length until the desired offset is found.
    pub fn split(&mut self, offset: u64) -> Option<(u64, BasicBlock<O>)> {
        // It does indeed land in the middle of this block. Let's figure out which
        // instruction it lands on
        let mut ins_offset = self.start_offset;
        let mut ins_index = None;
        trace!("splitting at {:?}, {:#?}", offset, self);
        for (i, ins) in self.instrs.iter().enumerate() {
            trace!("{} {:?}", ins_offset, ins);
            if offset == ins_offset {
                ins_index = Some(i);
                break;
            }

            ins_offset += match ins {
                ParsedInstr::Good(i) | ParsedInstr::GoodDoNotRemove(i) => i.len() as u64,
                _ => 1,
            }
        }

        ins_index?;

        let ins_index = ins_index.unwrap();

        let (new_bb_ins, curr_ins) = self.instrs.split_at(ins_index);

        let split_bb = BasicBlock {
            start_offset: self.start_offset,
            end_offset: ins_offset - new_bb_ins.last().unwrap().unwrap().len() as u64,
            instrs: new_bb_ins.to_vec(),
            ..Default::default()
        };

        self.start_offset = ins_offset;
        self.instrs = curr_ins.to_vec();

        Some((ins_offset, split_bb))
    }
}

/// A code object represented as a graph
pub struct CodeGraph<'a, TargetOpcode: Opcode<Mnemonic = py27::Mnemonic> + PartialEq> {
    pub(crate) root: NodeIndex,
    code: Arc<Code>,
    pub(crate) graph: Graph<BasicBlock<TargetOpcode>, EdgeWeight>,
    file_identifier: usize,
    /// Whether or not to generate dotviz graphs
    enable_dotviz_graphs: bool,
    phase: usize,
    /// Hashmap of graph file names and their data
    pub(crate) dotviz_graphs: HashMap<String, String>,
    pub(crate) on_graph_generated: Option<&'a Box<dyn Fn(&str, &str) + Send + Sync>>,
    pub(crate) on_store_to_named_var: Option<
        &'a Box<
            dyn Fn(
                    &Code,
                    &HashSet<String>,
                    &RwLock<&mut CodeGraph<TargetOpcode>>,
                    &Instruction<TargetOpcode>,
                    &(Option<Obj>, InstructionTracker<(NodeIndex<u32>, usize)>),
                ) + Send
                + Sync,
        >,
    >,
    _target_opcode_phantom: PhantomData<TargetOpcode>,
}

impl<'a, TargetOpcode: 'static + Opcode<Mnemonic = py27::Mnemonic> + PartialEq>
    CodeGraph<'a, TargetOpcode>
{
    /// Converts bytecode to a graph. Returns the root node index and the graph.
    pub fn from_code(
        code: Arc<Code>,
        file_identifier: usize,
        enable_dotviz_graphs: bool,
        on_graph_generated: Option<&'a Box<dyn Fn(&str, &str) + Send + Sync>>,
        on_store_to_named_var: Option<
            &'a Box<
                dyn Fn(
                        &Code,
                        &HashSet<String>,
                        &RwLock<&mut CodeGraph<TargetOpcode>>,
                        &Instruction<TargetOpcode>,
                        &(Option<Obj>, InstructionTracker<(NodeIndex<u32>, usize)>),
                    ) + Send
                    + Sync,
            >,
        >,
    ) -> Result<CodeGraph<'a, TargetOpcode>, Error<TargetOpcode>> {
        let debug = false;

        let analyzed_instructions = crate::smallvm::const_jmp_instruction_walker(
            code.code.as_slice(),
            Arc::clone(&code.consts),
            |_instr, _offset| {
                // We don't care about instructions that are executed
                crate::smallvm::WalkerState::Continue
            },
        )?;

        let copy = analyzed_instructions.clone();
        if true || debug {
            trace!("analyzed\n{:#?}", analyzed_instructions);
        }

        let mut curr_basic_block = BasicBlock::default();
        let mut code_graph = petgraph::Graph::<BasicBlock<TargetOpcode>, EdgeWeight>::new();
        let mut edges = vec![];
        let mut root_node_id = None;
        let mut has_invalid_jump_sites = false;

        let mut join_at_queue = Vec::new();

        for (offset, instr) in analyzed_instructions {
            if curr_basic_block.instrs.is_empty() {
                curr_basic_block.start_offset = offset;
                curr_basic_block.last_instruction_end = offset;
            }

            // If this is a bad opcode let's abort this BB immediately
            if offset != curr_basic_block.last_instruction_end {
                // we are not adding this instruction -- it's a bad target site
                continue;
            }
            let instr = match instr {
                ParsedInstr::Good(instr) => {
                    // valid instructions always get added to the previous bb
                    curr_basic_block
                        .instrs
                        .push(ParsedInstr::Good(instr.clone()));

                    curr_basic_block.last_instruction_end += instr.len() as u64;

                    instr
                }
                ParsedInstr::GoodDoNotRemove(instr) => {
                    // valid instructions always get added to the previous bb
                    curr_basic_block
                        .instrs
                        .push(ParsedInstr::GoodDoNotRemove(instr.clone()));

                    curr_basic_block.last_instruction_end += instr.len() as u64;

                    instr
                }
                ParsedInstr::Bad => {
                    curr_basic_block.end_offset = offset;
                    curr_basic_block.instrs.push(ParsedInstr::Bad);
                    curr_basic_block.has_bad_instrs = true;
                    let node_idx = code_graph.add_node(curr_basic_block);
                    if root_node_id.is_none() {
                        root_node_id = Some(node_idx);
                    }

                    curr_basic_block = BasicBlock::default();
                    continue;
                }
            };

            if matches!(
                instr.opcode.mnemonic(),
                Mnemonic::RETURN_VALUE | Mnemonic::RAISE_VARARGS
            ) {
                curr_basic_block.end_offset = offset;
                // We need to see if a previous BB landed in the middle of this block.
                // If so, we should split it
                for (_from, to, weight) in &mut edges {
                    let _weight = *weight;

                    if *to > curr_basic_block.start_offset && *to <= curr_basic_block.end_offset {
                        if let Some((ins_offset, split_bb)) = curr_basic_block.split(*to) {
                            edges.push((split_bb.end_offset, ins_offset, EdgeWeight::NonJump));
                            code_graph.add_node(split_bb);
                            break;
                        } else {
                            // this node jumped to a bad address... let's change this
                            *to = 0xFFFF;
                            break;
                        }
                    }
                }
                let node_idx = code_graph.add_node(curr_basic_block);
                if root_node_id.is_none() {
                    root_node_id = Some(node_idx);
                }

                curr_basic_block = BasicBlock::default();
                continue;
            }

            let next_instr = offset + instr.len() as u64;
            // whether or not this next instruction is where a different code path
            // joins
            let next_is_join = join_at_queue
                .last()
                .is_some_and(|next_join| next_instr == *next_join);
            // If this is the end of this basic block...
            if instr.opcode.is_jump() || next_is_join {
                if next_is_join {
                    join_at_queue.pop();
                }

                curr_basic_block.end_offset = offset;

                // We need to see if a previous BB landed in the middle of this block.
                // If so, we should split it
                let mut split_at = BTreeSet::new();
                for (_from, to, weight) in &edges {
                    let _weight = *weight;
                    if *to > curr_basic_block.start_offset && *to <= curr_basic_block.end_offset {
                        split_at.insert(*to);
                    }
                }

                // Push the next instruction
                if instr.opcode.is_conditional_jump()
                    || instr.opcode.is_other_conditional_jump()
                    || (!instr.opcode.is_jump())
                {
                    edges.push((curr_basic_block.end_offset, next_instr, EdgeWeight::NonJump));
                }

                let mut next_bb_end = None;
                if instr.opcode.is_jump() {
                    let target = if instr.opcode.is_absolute_jump() {
                        instr.arg.unwrap() as u64
                    } else {
                        offset + instr.len() as u64 + instr.arg.unwrap() as u64
                    };

                    let mut bad_jump_target =
                        matches!(&copy.get(&target), Some(ParsedInstr::Bad) | None);

                    let edge_weight = if matches!(
                        instr.opcode.mnemonic(),
                        Mnemonic::JUMP_FORWARD | Mnemonic::JUMP_ABSOLUTE,
                    ) {
                        EdgeWeight::NonJump
                    } else {
                        EdgeWeight::Jump
                    };

                    // Check if this block is self-referencing
                    if target > curr_basic_block.start_offset
                        && target <= curr_basic_block.end_offset
                    {
                        split_at.insert(target);
                    } else if !bad_jump_target {
                        // Check if this jump lands us in the middle of a block that's already
                        // been parsed
                        if let Some(root) = root_node_id.as_ref() {
                            // Special case for splitting up an existing node we're pointing to
                            for nx in code_graph.node_indices() {
                                let target_node = &mut code_graph[nx];
                                if target > target_node.start_offset
                                    && target <= target_node.end_offset
                                {
                                    // println!("{:?}", copy.get(&target));
                                    // println!("{:?}", target_node);
                                    if let Some((ins_offset, split_bb)) = target_node.split(target)
                                    {
                                        edges.push((
                                            split_bb.end_offset,
                                            ins_offset,
                                            EdgeWeight::NonJump,
                                        ));
                                        let new_node_id = code_graph.add_node(split_bb);
                                        if nx == *root {
                                            root_node_id = Some(new_node_id);
                                        }
                                        break;
                                    } else {
                                        // this node jumped to a bad address... let's change this
                                        bad_jump_target = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if bad_jump_target {
                        // we land on a bad instruction. we should just make an edge to
                        // our known "invalid jump site"
                        edges.push((curr_basic_block.end_offset, 0xFFFF, edge_weight));
                        has_invalid_jump_sites = true;
                    } else {
                        edges.push((curr_basic_block.end_offset, target, edge_weight));
                    }

                    if instr.opcode.is_conditional_jump() {
                        // We use this to force the "else" basic block to end
                        // at a set position
                        next_bb_end = Some(target);
                    }
                }

                for split_at in split_at {
                    if let Some((ins_offset, split_bb)) = curr_basic_block.split(split_at) {
                        //println!("Splitting at instruction offset: {}", ins_offset);
                        edges.push((split_bb.end_offset, ins_offset, EdgeWeight::NonJump));
                        code_graph.add_node(split_bb);
                    }
                }

                let node_idx = code_graph.add_node(curr_basic_block);
                if root_node_id.is_none() {
                    root_node_id = Some(node_idx);
                }

                curr_basic_block = BasicBlock::default();
                if let Some(next_bb_end) = next_bb_end {
                    join_at_queue.push(next_bb_end);
                }
            }
        }

        if has_invalid_jump_sites {
            let _invalid_jump_site = code_graph.add_node(BasicBlock {
                start_offset: 0xFFFF,
                end_offset: 0xFFFF,
                instrs: vec![ParsedInstr::Bad],
                has_bad_instrs: true,
                ..Default::default()
            });
        }

        let edges = edges
            .iter()
            .filter_map(|(from, to, weight)| {
                let new_edge = (
                    code_graph
                        .node_indices()
                        .find(|i| code_graph[*i].end_offset == *from),
                    code_graph
                        .node_indices()
                        .find(|i| code_graph[*i].start_offset == *to),
                );

                if new_edge.0.is_some() && new_edge.1.is_some() {
                    Some((new_edge.0.unwrap(), new_edge.1.unwrap(), weight).into_weighted_edge())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        code_graph.extend_with_edges(edges.as_slice());

        Ok(CodeGraph {
            root: root_node_id.unwrap(),
            graph: code_graph,
            code: Arc::clone(&code),
            file_identifier,
            enable_dotviz_graphs,
            phase: 0,
            dotviz_graphs: HashMap::new(),
            on_graph_generated,
            on_store_to_named_var,
            _target_opcode_phantom: Default::default(),
        })
    }

    /// Returns the instruction at the given `node_idx` and `instr_idx`.
    pub fn instr_at(
        &self,
        node_idx: NodeIndex<u32>,
        instr_idx: usize,
    ) -> &ParsedInstr<TargetOpcode> {
        &self.graph[node_idx].instrs[instr_idx]
    }

    pub(crate) fn generate_file_name(&self, stage: Option<&str>) -> String {
        format!(
            "{}_phase{}_{}_{}_{}.dot",
            self.file_identifier,
            self.phase,
            self.code.filename.to_string().replace("/", ""),
            self.code.name.to_string().replace("/", ""),
            stage.unwrap_or("")
        )
    }

    /// Write out the current graph in dot format. The file will be output to current directory, named
    /// $FILENUMBER_$FILENAME_$NAME_$STAGE.dot. This function will check global args to see if
    /// dot writing was enabled
    pub fn generate_dot_graph(&mut self, stage: &str) {
        let force_graphs = std::env::var("UNFUCK_WRITE_GRAPHS").is_ok();
        if !self.enable_dotviz_graphs && !force_graphs {
            return;
        }

        use petgraph::dot::{Config, Dot};

        let filename = self.generate_file_name(Some(stage));

        self.phase += 1;

        let dot_data = format!("{}", Dot::with_config(&self.graph, &[Config::EdgeNoLabel]));
        if force_graphs {
            let mut output_file = File::create(&filename).expect("failed to create dot file");
            output_file
                .write_all(dot_data.as_bytes())
                .expect("failed to write dot data");
        }
        if let Some(callback) = self.on_graph_generated.as_ref() {
            callback(filename.as_ref(), dot_data.as_ref())
        }

        self.dotviz_graphs.insert(filename, dot_data);
    }

    fn invoke_partial_execution(
        &mut self,
        mapped_function_names: &mut HashMap<String, String>,
        _plain_loaded_modules: &mut HashSet<String>,
    ) -> Vec<ExecutionPath> {
        // create our thread communication channels
        let (completed_paths_sender, completed_paths_receiver) = unbounded();

        let new_mapped_function_names: Mutex<HashMap<String, String>> = Default::default();
        let plain_loaded_modules: Mutex<HashSet<String>> = Default::default();

        {
            // we could use atomic bools here, but that would introduce a problem if
            // threads transition while we're examining them
            let code = Arc::clone(&self.code);
            let root = self.root;
            let graph = std::sync::RwLock::new(self);
            let graph = &graph;
            let new_mapped_function_names = &new_mapped_function_names;
            let new_plain_loaded_modules = &plain_loaded_modules;
            let completed_paths_sender = &completed_paths_sender;

            let running_tasks = Arc::new(AtomicUsize::new(0));
            rayon::scope(|s| {
                let code = Arc::clone(&code);

                running_tasks.fetch_add(1, Ordering::SeqCst);

                s.spawn(move |s| {
                    perform_partial_execution(
                        root,
                        graph,
                        Mutex::new(ExecutionPath::default()),
                        new_mapped_function_names,
                        new_plain_loaded_modules,
                        Arc::clone(&code),
                        s,
                        completed_paths_sender,
                    );

                    running_tasks.fetch_sub(1, Ordering::SeqCst);
                });
            });
        }

        drop(completed_paths_sender);

        // copy the mapped function names
        *mapped_function_names = new_mapped_function_names.lock().unwrap().clone();

        // Get the completed paths
        completed_paths_receiver
            .iter()
            .map(|path| path.into_inner().unwrap())
            .collect()
    }

    /// Removes conditions that can be statically evaluated to be constant.
    pub(crate) fn remove_const_conditions(
        &mut self,
        mapped_function_names: &mut HashMap<String, String>,
        plain_loaded_modules: &mut HashSet<String>,
    ) {
        self.generate_dot_graph("before_dead");

        let completed_paths =
            self.invoke_partial_execution(mapped_function_names, plain_loaded_modules);
        self.generate_dot_graph("after_dead");

        let mut nodes_to_remove = std::collections::BTreeSet::<NodeIndex>::new();
        let mut insns_to_remove = HashMap::<NodeIndex, std::collections::BTreeSet<usize>>::new();

        // We want to pre-compute which nodes were used by each path. This will allow us to determine the
        // set of paths not taken which can be removed.
        let mut node_branch_direction = HashMap::<NodeIndex, EdgeWeight>::new();
        let mut potentially_unused_nodes = BTreeSet::<NodeIndex>::new();

        // TODO: high runtime complexity
        for path in &completed_paths {
            // Filtered list of all the conditions we reached _and_ reached a condition for
            let conditions_reached = path.condition_results.iter().filter_map(|(node, result)| {
                if result.is_some() {
                    Some((node, result.as_ref().unwrap()))
                } else {
                    None
                }
            });

            'conditions: for (node, result) in conditions_reached {
                self.graph[*node].flags |= BasicBlockFlags::USED_IN_EXECUTION;

                // we already did the work for this node
                if node_branch_direction.contains_key(node) {
                    continue;
                }

                let branch_taken = result.0;

                let mut path_instructions = vec![];

                for other_path in &completed_paths {
                    match other_path.condition_results.get(node) {
                        Some(Some(current_path_value)) => {
                            // we have a mismatch -- we cannot safely remove this
                            if branch_taken != current_path_value.0 {
                                continue 'conditions;
                            } else {
                                // these match!
                                path_instructions
                                    .extend_from_slice(current_path_value.1.as_slice());
                            }
                        }
                        Some(None) => {
                            // this path was unable to evaluate this condition
                            // and therefore we cannot safely remove this value
                            continue 'conditions;
                        }
                        None => {
                            // this branch never hit this bb -- this is safe to remove
                        }
                    }
                }

                // We've found that all nodes agree on this value. The access tracker
                // accumulates every instruction that ever touched the operands, so it
                // is polluted with live instructions from other blocks (a call whose
                // result feeds an unrelated variable, comparisons on other paths).
                // Removing those corrupts the function. The instructions that actually
                // compute this jump's condition are the local slice in the jump's own
                // block; only those are safe to remove. A tainted instruction in
                // another block is left in place (it may be dead, but the IR's own
                // simplification drops genuinely dead code without risking corruption).
                let condition_node = *node;
                for (instr_node, idx) in path_instructions {
                    self.graph[instr_node].flags |= BasicBlockFlags::USED_IN_EXECUTION;
                    if instr_node == condition_node {
                        insns_to_remove.entry(instr_node).or_default().insert(idx);
                    }
                }

                node_branch_direction.insert(*node, branch_taken);

                // We know which branch all of these nodes took, so therefore we also know
                // which branch they *did not* take. Let's remove the edge
                // for the untaken paths.
                let unused_path = self
                    .graph
                    .edges_directed(*node, Direction::Outgoing)
                    .find_map(|e| {
                        if *e.weight() != branch_taken {
                            Some((e.id(), e.target()))
                        } else {
                            None
                        }
                    });

                match unused_path {
                    Some(unused_path) => {
                        potentially_unused_nodes.insert(unused_path.1);
                        self.graph.remove_edge(unused_path.0);

                        // If the node now has exactly 1 outgoing edge and its last
                        // instruction is a conditional jump, convert it to an
                        // unconditional JUMP_FORWARD so that join_blocks() can
                        // merge it with the successor block.  Without this,
                        // the orphaned conditional survives into update_branches()
                        // and becomes a JUMP_FORWARD 0 that breaks uncompyle6.
                        let outgoing_count = self
                            .graph
                            .edges_directed(*node, Direction::Outgoing)
                            .count();
                        if outgoing_count == 1 {
                            let node_bb = &mut self.graph[*node];
                            if let Some(last_instr) = node_bb.instrs.last()
                                && last_instr.unwrap().opcode.is_conditional_jump()
                            {
                                let last_instr_mut =
                                    node_bb.instrs.last_mut().unwrap().unwrap_mut();
                                Arc::make_mut(last_instr_mut).opcode =
                                    Mnemonic::JUMP_FORWARD.into();
                            }
                        }
                    }
                    None => {
                        if self
                            .graph
                            .edges_directed(*node, Direction::Outgoing)
                            .count()
                            == 0
                        {
                            error!(
                                "Could not find an outgoing path from node that was not taken. Outgoing node count is 0 -- this may be a bug"
                            )
                        }
                    }
                }
            }
        }

        if node_branch_direction.is_empty() {
            // no obfuscation?
            return;
        }

        self.generate_dot_graph("unused_partially_removed_edges");

        // The dead code is exactly the set of nodes no longer reachable from the
        // root once the untaken arms of folded opaque predicates are disconnected.
        // Remove those, and only those. The previous criterion -- keep a node only
        // if the partial executor walked it or it is downgraph of a walked condition
        // -- wrongly dropped live blocks the executor simply never walked (forwarding
        // trampolines, arms reached only past the fork-depth cap). Dropping a live
        // node severs a real edge, which leaves an orphaned jump and a spurious
        // fall-through return, corrupting the function.
        let mut reachable = BTreeSet::new();
        let mut stack = vec![self.root];
        while let Some(nx) = stack.pop() {
            if reachable.insert(nx) {
                let children = self
                    .graph
                    .edges_directed(nx, Direction::Outgoing)
                    .map(|edge| edge.target())
                    .collect::<Vec<_>>();
                stack.extend(children);
            }
        }
        for nx in self.graph.node_indices() {
            if !reachable.contains(&nx) {
                nodes_to_remove.insert(nx);
            }
        }

        self.generate_dot_graph("unused_all_removed_edges");

        for (nx, insns_to_remove) in insns_to_remove {
            for ins_idx in insns_to_remove.iter().rev().cloned() {
                let current_node = &mut self.graph[nx];
                let ins = current_node.instrs.remove(ins_idx);
                assert!(
                    !matches!(ins, ParsedInstr::GoodDoNotRemove(_)),
                    "Removed instruction is a permanent instruction: {:#x?}. File: {}",
                    ins,
                    self.generate_file_name(None)
                );
            }
        }

        self.generate_dot_graph("instructions_removed");

        // go over the empty nodes, merge them into their parent
        for node in self.graph.node_indices() {
            self.generate_dot_graph("last_merged");
            // TODO: This leaves some nodes that are empty
            if self.graph[node].instrs.is_empty() {
                let outgoing_nodes = self
                    .graph
                    .edges_directed(node, Direction::Outgoing)
                    .map(|e| e.target())
                    .filter(|target| {
                        // make sure these nodes aren't circular
                        !self.is_downgraph(*target, node)
                    })
                    .collect::<Vec<_>>();

                assert!(outgoing_nodes.len() <= 1);

                if let Some(child) = outgoing_nodes.first() {
                    self.join_block(node, *child);
                    nodes_to_remove.insert(*child);
                }
            }
            self.generate_dot_graph("last_merged");
        }

        let mut needs_new_root = false;
        let root = self.root;
        self.graph.retain_nodes(|g, node| {
            if nodes_to_remove.contains(&node) {
                trace!("removing node starting at: {}", g[node].start_offset);
                if node == root {
                    // find the new root
                    needs_new_root = true;
                }
                false
            } else {
                true
            }
        });

        self.generate_dot_graph("target");

        if needs_new_root {
            trace!("{:#?}", self.graph.node_indices().collect::<Vec<_>>());
            self.root = self.graph.node_indices().next().unwrap();
        }
        trace!("root node is now: {:#?}", self.graph[self.root]);
    }

    pub(crate) fn clear_flags(&mut self, root: NodeIndex, flags: BasicBlockFlags) {
        let mut bfs = Bfs::new(&self.graph, root);
        while let Some(nx) = bfs.next(&self.graph) {
            self.graph[nx].flags.remove(flags);
        }
    }

    /// Updates basic block offsets following the expected code flow order. i.e. non-target conditional jumps will always
    /// be right after the jump instruction and the point at which the two branches "meet" will be sequential.
    pub(crate) fn update_bb_offsets(&mut self) {
        let mut current_offset = 0;
        let mut stop_at_queue = Vec::new();
        let mut node_queue = Vec::new();
        let mut updated_nodes = BTreeSet::new();
        node_queue.push(self.root);
        trace!("beginning bb offset updating visitor");
        while let Some(nx) = node_queue.pop() {
            trace!("current: {:#?}", self.graph[nx]);
            if let Some(stop_at) = stop_at_queue.last()
                && *stop_at == nx
            {
                stop_at_queue.pop();
            }

            if updated_nodes.contains(&nx) {
                continue;
            }

            updated_nodes.insert(nx);

            let current_node = &mut self.graph[nx];

            trace!("current offset: {}", current_offset);
            let end_offset = current_node
                .instrs
                .iter()
                .fold(0, |accum, instr| accum + instr.unwrap().len());

            let end_offset = end_offset as u64;
            current_node.start_offset = current_offset;
            current_node.end_offset = current_offset
                + (end_offset - current_node.instrs.last().unwrap().unwrap().len() as u64);

            current_offset += end_offset;

            trace!("next offset: {}", current_offset);

            let mut targets = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .map(|edge| (edge.target(), *edge.weight()))
                .collect::<Vec<_>>();

            // Sort the targets so that the non-branch path is last. THIS IS IMPORTANT!!!!!
            // we need to ensure that the path we're taking is added FIRST so that it's further
            // down the stack
            targets.sort_by(|(_a, aweight), (_b, bweight)| bweight.cmp(aweight));

            // Add the non-constexpr path to the "stop_at_queue" so that we don't accidentally
            // go down that path before handling it ourself
            let jump_path = targets.iter().find_map(|(target, weight)| {
                if *weight == EdgeWeight::Jump {
                    Some(*target)
                } else {
                    None
                }
            });

            if let Some(jump_path) = jump_path {
                trace!("jump path is to: {:#?}", self.graph[jump_path])
            }

            for (target, _weight) in targets {
                trace!("target loop");
                // If this is the next node in the nodes to ignore, don't add it
                if let Some(pending) = stop_at_queue.last() {
                    trace!("Pending: {:#?}", self.graph[*pending]);
                    if *pending == target {
                        continue;
                    }

                    // we need to find this path to see if it goes through a node that has already
                    // had its offsets touched
                    if self.is_downgraph(*pending, target) {
                        let path = astar(
                            &self.graph,
                            *pending,
                            |finish| finish == target,
                            |_e| 0,
                            |_| 0,
                        )
                        .unwrap()
                        .1;
                        let goes_through_updated_node =
                            path.iter().any(|node| updated_nodes.contains(node));

                        // If this does not go through an updated node, we can ignore
                        // the fact that the target is downgraph
                        if !goes_through_updated_node {
                            continue;
                        }
                    }
                }

                if updated_nodes.contains(&target) {
                    continue;
                }

                node_queue.push(target);
            }

            if let Some(jump_path) = jump_path
                && !updated_nodes.contains(&jump_path)
            {
                // the other node may add this one
                if let Some(pending) = stop_at_queue.last() {
                    if !self.is_downgraph(*pending, jump_path) {
                        stop_at_queue.push(jump_path);
                    }
                } else {
                    stop_at_queue.push(jump_path);
                }
            }
        }
    }


    /// Re-insert the body-terminating jumps that the Python 2.7 compiler emits at the
    /// end of an `if`/`elif` body.
    ///
    /// The deobfuscator reconstructs a minimal control-flow graph: a block that simply
    /// falls through into the merge point of an `if` carries no jump. The Python 2.7
    /// compiler, however, always terminates such a body with a jump to the merge point
    /// (`JUMP_FORWARD 0` when the merge is the next instruction). uncompyle6 relies on
    /// that jump to place a `COME_FROM` at the merge and recover the `if` boundary;
    /// without it the parser fails at the first instruction of the code object.
    ///
    /// For every block `B` that does not already end in a jump or `RETURN_VALUE` and
    /// whose sole fall-through successor `M` is the merge point of one or more
    /// statement-level `if`s, append the body-terminating jumps to `B` and promote the
    /// fall-through edge to a jump edge.
    ///
    /// When `K` nested `if`s all close at the same merge `M` (a guard-clause chain
    /// converging on a `return`, for instance) the compiler emits `K` jumps: `K - 1`
    /// `JUMP_ABSOLUTE`s for the enclosing bodies followed by a single `JUMP_FORWARD`
    /// for the innermost body. uncompyle6 requires that exact shape -- the trailing
    /// `JUMP_FORWARD` closes the outermost `if` and each `JUMP_ABSOLUTE` closes one more
    /// nested level. Consecutive guards that share a merge are an `and`-chain (one `if`),
    /// so they count once.
    ///
    /// The `JUMP_ABSOLUTE` operands cannot be resolved here because block offsets are not
    /// final; the returned fixups carry the merge node so [`Self::fixup_decompiler_dead_jumps`]
    /// can patch them once [`Self::update_bb_offsets`] has run.
    pub(crate) fn insert_decompiler_jumps(&mut self) -> Vec<DecompilerJumpFixup> {
        let mut fixups = Vec::new();
        let nodes: Vec<NodeIndex> = self.graph.node_indices().collect();
        for nx in nodes {
            let ends_in_terminal = match self.graph[nx].instrs.last() {
                Some(last) => {
                    let mnemonic = last.unwrap().opcode.mnemonic();
                    last.unwrap().opcode.is_jump() || mnemonic == Mnemonic::RETURN_VALUE
                }
                None => true,
            };
            if ends_in_terminal {
                continue;
            }

            // A body block has exactly one outgoing edge, the fall-through to its merge.
            let outgoing = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .map(|edge| (edge.id(), edge.target(), *edge.weight()))
                .collect::<Vec<_>>();
            let (edge_id, target) = match outgoing.as_slice() {
                [(edge_id, target, EdgeWeight::NonJump)] => (*edge_id, *target),
                _ => continue,
            };
            if target == nx {
                continue;
            }

            let group_count = self.if_group_count(target);
            if group_count == 0 {
                continue;
            }

            for _ in 1..group_count {
                self.graph[nx]
                    .instrs
                    .push(ParsedInstr::Good(Arc::new(pydis::Instr!(
                        Mnemonic::JUMP_ABSOLUTE.into(),
                        0
                    ))));
            }
            self.graph[nx]
                .instrs
                .push(ParsedInstr::Good(Arc::new(pydis::Instr!(
                    Mnemonic::JUMP_FORWARD.into(),
                    0
                ))));
            *self.graph.edge_weight_mut(edge_id).unwrap() = EdgeWeight::Jump;

            if group_count > 1 {
                fixups.push(DecompilerJumpFixup {
                    block: nx,
                    merge: target,
                    dead_jumps: group_count - 1,
                });
            }
        }
        fixups
    }

    /// Count the number of statement-level `if`s that close at `merge`.
    ///
    /// `merge` is reached by the taken branch of every guarding `POP_JUMP_IF_FALSE`/
    /// `POP_JUMP_IF_TRUE`. Guards in an `and`-chain fall through into one another, so a
    /// guard begins a new `if` only when the block that falls through into it is not
    /// itself a guard of the same merge. `JUMP_IF_*_OR_POP` targets are ignored: those
    /// are boolean-expression merges uncompyle6 handles without a terminating jump.
    fn if_group_count(&self, merge: NodeIndex) -> usize {
        let guards: HashSet<NodeIndex> = self
            .graph
            .edges_directed(merge, Direction::Incoming)
            .filter(|edge| *edge.weight() == EdgeWeight::Jump)
            .map(|edge| edge.source())
            .filter(|source| {
                self.graph[*source].instrs.last().is_some_and(|last| {
                    matches!(
                        last.unwrap().opcode.mnemonic(),
                        Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE
                    )
                })
            })
            .collect();

        guards
            .iter()
            .filter(|guard| {
                // A guard whose block also holds body statements (a `STORE`, a discarded
                // expression, ...) before its condition cannot be the continuation of an
                // `and`-chain -- the chained operands of one `if` are pure expressions.
                if self.block_contains_statement(**guard) {
                    return true;
                }
                match self.nonjump_predecessor(**guard) {
                    Some(predecessor) => !guards.contains(&predecessor),
                    None => true,
                }
            })
            .count()
    }

    /// Whether the block holds a statement-level instruction before its terminal jump.
    /// Used to distinguish an `if` body that ends in a guard (`x = ...; if y:`) from a
    /// continuation of an `and`-chain (`if x and y:`), whose operands are pure expressions.
    fn block_contains_statement(&self, node: NodeIndex) -> bool {
        let instrs = &self.graph[node].instrs;
        let body = instrs.len().saturating_sub(1);
        instrs[..body].iter().any(|instr| {
            let mnemonic = instr.unwrap().opcode.mnemonic();
            let name = format!("{:?}", mnemonic);
            name.starts_with("STORE_")
                || name.starts_with("DELETE_")
                || name.starts_with("PRINT_")
                || matches!(
                    mnemonic,
                    Mnemonic::POP_TOP
                        | Mnemonic::IMPORT_NAME
                        | Mnemonic::IMPORT_FROM
                        | Mnemonic::IMPORT_STAR
                        | Mnemonic::EXEC_STMT
                )
        })
    }

    /// Returns the block that falls through (the `NonJump` edge) into `node`, if any.
    fn nonjump_predecessor(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.graph
            .edges_directed(node, Direction::Incoming)
            .find(|edge| *edge.weight() == EdgeWeight::NonJump)
            .map(|edge| edge.source())
    }

    /// Resolve the `JUMP_ABSOLUTE` operands of the dead body-terminating jumps inserted
    /// by [`Self::insert_decompiler_jumps`]. Must run after [`Self::update_bb_offsets`]
    /// so the merge offset is final. The trailing `JUMP_FORWARD` of each block is left
    /// to [`Self::update_branches`], which resolves it from the edge.
    pub(crate) fn fixup_decompiler_dead_jumps(&mut self, fixups: &[DecompilerJumpFixup]) {
        for fixup in fixups {
            let merge_offset = self.graph[fixup.merge].start_offset as u16;
            let block = &mut self.graph[fixup.block];
            let last = block.instrs.len() - 1;
            for offset in 1..=fixup.dead_jumps {
                let instr = block.instrs[last - offset].unwrap_mut();
                Arc::make_mut(instr).arg = Some(merge_offset);
            }
        }
    }


    /// Ensure every leaf node (no outgoing edges) ends with RETURN_VALUE.
    /// Python's compiler always emits an implicit 'return None' at the end of
    /// every code object.  If the deobfuscator removes dead code that contained
    /// the return, uncompyle6 fails with a parse error.
    pub(crate) fn ensure_terminal_returns(&mut self, code: &Code) {
        let node_indices: Vec<_> = self.graph.node_indices().collect();
        for nx in node_indices {
            let outgoing = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .count();
            if outgoing != 0 {
                continue;
            }
            let bb = &self.graph[nx];
            let needs_return = match bb.instrs.last() {
                Some(instr) => instr.unwrap().opcode.mnemonic() != Mnemonic::RETURN_VALUE,
                None => true,
            };
            if needs_return {
                let const_idx = code
                    .consts
                    .iter()
                    .enumerate()
                    .find_map(|(idx, obj)| {
                        if matches!(obj, Obj::None) {
                            Some(idx)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let bb = &mut self.graph[nx];
                bb.instrs.push(ParsedInstr::Good(Arc::new(Instruction {
                    opcode: Mnemonic::LOAD_CONST.into(),
                    arg: Some(const_idx as u16),
                })));
                bb.instrs.push(ParsedInstr::Good(Arc::new(Instruction {
                    opcode: Mnemonic::RETURN_VALUE.into(),
                    arg: None,
                })));
            }
        }
    }

    /// Fixes up the bytecode so that "implicit" returns can be in separate
    /// paths to make the job easier for a decompiler
    pub(crate) fn massage_returns_for_decompiler(&mut self) {
        let mut bfs = Bfs::new(&self.graph, self.root);
        while let Some(nx) = bfs.next(&self.graph) {
            let bb = &self.graph[nx];
            if let Some(instr) = bb.instrs.first()
                && instr.unwrap().opcode.mnemonic() == Mnemonic::FOR_ITER
            {
                // let's get this target node -- if it's just a RETURN_VALUE with other
                // people returning as well, we should just use our own
                //
                // Basically, we want to force the code into this pattern:
                //
                //
                // def foo():
                //     y = ['a', 'b', 'c']
                //     if true:
                //         return [c for c in y if c != 'c']
                //     else:
                //         return y

                let (edge, target) = self
                    .graph
                    .edges_directed(nx, Direction::Outgoing)
                    .find_map(|edge| {
                        if *edge.weight() == EdgeWeight::Jump {
                            Some((edge.id(), edge.target()))
                        } else {
                            None
                        }
                    })
                    .unwrap();

                let target_bb = &self.graph[target];
                if target_bb.instrs.len() == 1
                    && target_bb.instrs[0].unwrap().opcode.mnemonic() == Mnemonic::RETURN_VALUE
                    && self
                        .graph
                        .edges_directed(target, Direction::Incoming)
                        .count()
                        > 1
                {
                    self.graph.remove_edge(edge);
                    let return_bb = BasicBlock {
                        instrs: vec![crate::smallvm::ParsedInstr::Good(Arc::new(pydis::Instr!(
                            Mnemonic::RETURN_VALUE.into()
                        )))],
                        ..Default::default()
                    };
                    let new_return_node = self.graph.add_node(return_bb);
                    self.graph.add_edge(nx, new_return_node, EdgeWeight::Jump);
                }
            }
        }
    }

    /// Update branching instructions to reflect the correct offset for their target, which may have changed since the
    /// graph was created.
    pub(crate) fn update_branches(&mut self) {
        let mut updated_nodes = BTreeSet::new();

        let mut bfs = Bfs::new(&self.graph, self.root);
        while let Some(nx) = bfs.next(&self.graph) {
            updated_nodes.insert(nx);

            // Update any paths to this node -- we need to update their jump instructions
            // if they exist
            let incoming_edges = self
                .graph
                .edges_directed(nx, Direction::Incoming)
                .map(|edge| (*edge.weight(), edge.source()))
                .collect::<Vec<_>>();

            for (weight, incoming_edge) in incoming_edges {
                let outgoing_edges_from_parent = self
                    .graph
                    .edges_directed(incoming_edge, Direction::Outgoing)
                    .count();

                // We only update edges that are jumping to us
                if weight != EdgeWeight::Jump && outgoing_edges_from_parent > 1 {
                    continue;
                }

                let source_node = &mut self.graph[incoming_edge];
                let last_ins_ref = source_node.instrs.last().unwrap().unwrap();

                if !last_ins_ref.opcode.is_jump() {
                    continue;
                }

                assert!(last_ins_ref.opcode.has_arg());

                let last_ins_len = last_ins_ref.len();
                let last_ins_is_abs_jump_initial =
                    last_ins_ref.opcode.mnemonic() == Mnemonic::JUMP_ABSOLUTE;
                drop(last_ins_ref);

                let target_node = &self.graph[nx];
                let target_node_start = target_node.start_offset;

                let source_node = &mut self.graph[incoming_edge];
                let end_of_jump_ins = source_node.end_offset + last_ins_len as u64;

                if last_ins_is_abs_jump_initial && target_node_start > source_node.start_offset {
                    let last_ins = source_node.instrs.last_mut().unwrap().unwrap_mut();
                    Arc::make_mut(last_ins).opcode = Mnemonic::JUMP_FORWARD.into();
                }

                // Re-check after potential mutation above
                let is_fwd_jump = source_node
                    .instrs
                    .last()
                    .unwrap()
                    .unwrap()
                    .opcode
                    .mnemonic()
                    == Mnemonic::JUMP_FORWARD;
                if is_fwd_jump && target_node_start < end_of_jump_ins {
                    let last_ins = source_node.instrs.last_mut().unwrap().unwrap_mut();
                    Arc::make_mut(last_ins).opcode = Mnemonic::JUMP_ABSOLUTE.into();
                }

                let last_ins_is_abs_jump = source_node
                    .instrs
                    .last()
                    .unwrap()
                    .unwrap()
                    .opcode
                    .is_absolute_jump();

                let new_arg = if last_ins_is_abs_jump {
                    target_node_start
                } else {
                    if target_node_start < source_node.end_offset {
                        // Target is behind source -- relative offset would be negative.
                        // Convert to JUMP_ABSOLUTE so we can use an absolute target.
                        let last_ins = source_node.instrs.last_mut().unwrap().unwrap_mut();
                        Arc::make_mut(last_ins).opcode = Mnemonic::JUMP_ABSOLUTE.into();
                        target_node_start
                    } else {
                        target_node_start - end_of_jump_ins
                    }
                };

                let last_ins = source_node.instrs.last_mut().unwrap().unwrap_mut();
                Arc::make_mut(last_ins).arg = Some(new_arg as u16);
            }
        }
    }

    /// Write out the object bytecode.
    pub(crate) fn write_bytecode(&mut self, root: NodeIndex, new_bytecode: &mut Vec<u8>) {
        let mut stop_at_queue = Vec::new();
        let mut node_queue = Vec::new();
        node_queue.push(root);
        trace!("beginning bytecode bb visitor");
        'node_visitor: while let Some(nx) = node_queue.pop() {
            if let Some(stop_at) = stop_at_queue.last()
                && *stop_at == nx
            {
                stop_at_queue.pop();
            }

            let current_node = &mut self.graph[nx];
            if current_node
                .flags
                .intersects(BasicBlockFlags::BYTECODE_WRITTEN)
            {
                continue;
            }

            current_node.flags |= BasicBlockFlags::BYTECODE_WRITTEN;

            for instr in current_node.instrs.iter().map(|i| i.unwrap()) {
                new_bytecode.push(instr.opcode.to_u8().unwrap());
                if let Some(arg) = instr.arg {
                    new_bytecode.extend_from_slice(&arg.to_le_bytes()[..]);
                }
            }

            let mut targets = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .map(|edge| (edge.target(), *edge.weight()))
                .collect::<Vec<_>>();

            // Sort the targets so that the non-branch path is last
            targets.sort_by(|(_a, aweight), (_b, bweight)| bweight.cmp(aweight));

            // Add the non-constexpr path to the "stop_at_queue" so that we don't accidentally
            // go down that path before handling it ourself
            let jump_path = targets.iter().find_map(|(target, weight)| {
                if *weight == EdgeWeight::Jump {
                    Some(*target)
                } else {
                    None
                }
            });

            for (target, _weight) in targets {
                // If this is the next node in the nodes to ignore, don't add it
                if let Some(pending) = stop_at_queue.last() {
                    // we need to find this path to see if it goes through a node that has already
                    // had its offsets touched
                    if self.is_downgraph(*pending, target) {
                        let path = astar(
                            &self.graph,
                            *pending,
                            |finish| finish == target,
                            |_e| 0,
                            |_| 0,
                        )
                        .unwrap()
                        .1;
                        let mut goes_through_updated_node = false;
                        for node in path {
                            if self.graph[node]
                                .flags
                                .intersects(BasicBlockFlags::BYTECODE_WRITTEN)
                            {
                                goes_through_updated_node = true;
                                break;
                            }
                        }

                        // If this does not go through an updated node, we can ignore
                        // the fact that the target is downgraph
                        if !goes_through_updated_node {
                            continue;
                        }
                    }
                    if *pending == target {
                        continue;
                    }
                }

                if self.graph[target]
                    .flags
                    .contains(BasicBlockFlags::BYTECODE_WRITTEN)
                {
                    continue;
                }

                node_queue.push(target);
            }

            if let Some(jump_path) = jump_path
                && !self.graph[jump_path]
                    .flags
                    .contains(BasicBlockFlags::BYTECODE_WRITTEN)
            {
                // the other node may add this one
                if let Some(pending) = stop_at_queue.last() {
                    if !self.is_downgraph(*pending, jump_path) {
                        stop_at_queue.push(jump_path);
                    }
                } else {
                    stop_at_queue.push(jump_path);
                }
            }
        }
    }

    /// Fixes any [`BasicBlock`]s with bad instructions. This essentially replaces all of the
    /// instructions in a basic block with the appropriate number of `POP_TOP` instructions to clear
    /// the stack, *try* loading the `None` const item, and returning. If `None` is not in the
    /// const items, then const index 0 is returned.
    pub(crate) fn fix_bbs_with_bad_instr(&mut self, root: NodeIndex, code: &Code) {
        let mut bfs = Bfs::new(&self.graph, root);
        while let Some(nx) = bfs.next(&self.graph) {
            let current_node = &mut self.graph[nx];
            // We only operate on nodes with bad instructions
            if !current_node.has_bad_instrs {
                continue;
            }

            // We're going to change the instructions in here to return immediately
            current_node.instrs.clear();

            // We need to walk instructions to this point to get the stack size so we can balance it
            let path = astar(&self.graph, root, |finish| finish == nx, |_e| 0, |_| 0)
                .unwrap()
                .1;
            let mut stack_size = 0;
            for (idx, node) in path.iter().cloned().enumerate() {
                if node == nx {
                    break;
                }

                for instr in &self.graph[node].instrs {
                    // these ones pop only if we're not taking the branch
                    if matches!(
                        instr.unwrap().opcode.mnemonic(),
                        Mnemonic::JUMP_IF_TRUE_OR_POP | Mnemonic::JUMP_IF_FALSE_OR_POP
                    ) {
                        // Grab the edge from this node to the next
                        let edge = self.graph.find_edge(node, path[idx + 1]).unwrap();
                        if *self.graph.edge_weight(edge).unwrap() == EdgeWeight::NonJump {
                            stack_size -= 1;
                        } else {
                            // do nothing if we take the branch
                        }
                    } else if matches!(
                        instr.unwrap().opcode.mnemonic(),
                        Mnemonic::SETUP_EXCEPT | Mnemonic::SETUP_FINALLY
                            | Mnemonic::WITH_CLEANUP
                            | Mnemonic::EXTENDED_ARG
                    ) {
                        stack_size += 0;
                    } else {
                        stack_size += instr.unwrap().stack_adjustment_after();
                    }
                }
            }

            let current_node = &mut self.graph[nx];
            for _i in 0..stack_size {
                break;
                current_node
                    .instrs
                    .push(ParsedInstr::Good(Arc::new(Instruction {
                        opcode: Mnemonic::POP_TOP.into(),
                        arg: None,
                    })));
            }

            // Find the `None` constant object
            let const_idx = code
                .consts
                .iter()
                .enumerate()
                .find_map(|(idx, obj)| {
                    if matches!(obj, Obj::None) {
                        Some(idx)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            current_node
                .instrs
                .push(ParsedInstr::Good(Arc::new(Instruction {
                    opcode: Mnemonic::LOAD_CONST.into(),
                    arg: Some(const_idx as u16),
                })));
            current_node
                .instrs
                .push(ParsedInstr::Good(Arc::new(Instruction {
                    opcode: Mnemonic::RETURN_VALUE.into(),
                    arg: None,
                })));

            current_node.has_bad_instrs = false;
        }
    }

    /// Insert `JUMP_FORWARD 0` instructions at locations that jump in to
    pub(crate) fn insert_jump_0(&mut self) {
        let mut stop_at_queue = Vec::new();
        let mut node_queue = Vec::new();
        let mut updated_nodes = BTreeSet::new();
        let mut outstanding_conditions = Vec::new();
        node_queue.push(self.root);
        trace!("beginning jump 0 visitor");
        while let Some(nx) = node_queue.pop() {
            trace!("current: {:#?}", self.graph[nx]);
            if let Some(stop_at) = stop_at_queue.last()
                && *stop_at == nx
            {
                stop_at_queue.pop();
            }

            if updated_nodes.contains(&nx) {
                continue;
            }

            updated_nodes.insert(nx);

            let mut targets = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .map(|edge| (edge.target(), *edge.weight()))
                .collect::<Vec<_>>();

            // Sort the targets so that the non-branch path is last. THIS IS IMPORTANT!!!!!
            // we need to ensure that the path we're taking is added FIRST so that it's further
            // down the stack
            targets.sort_by(|(_a, aweight), (_b, bweight)| bweight.cmp(aweight));

            // Add the non-constexpr path to the "stop_at_queue" so that we don't accidentally
            // go down that path before handling it ourself
            let jump_path = targets.iter().find_map(|(target, weight)| {
                if *weight == EdgeWeight::Jump {
                    Some(*target)
                } else {
                    None
                }
            });

            if let Some(jump_path) = jump_path {
                trace!("jump path is to: {:#?}", self.graph[jump_path])
            }

            if targets.is_empty() && !node_queue.is_empty() {
                // ensure that this node does not end in a jump
                if !self.graph[nx]
                    .instrs
                    .last()
                    .unwrap()
                    .unwrap()
                    .opcode
                    .is_jump()
                {
                    self.graph[nx]
                        .instrs
                        .push(ParsedInstr::Good(Arc::new(pydis::Instr!(
                            Mnemonic::JUMP_FORWARD.into(),
                            0
                        ))));
                }
            }

            for (target, _weight) in targets {
                trace!("target loop");
                // If this is the next node in the nodes to ignore, don't add it
                if let Some(pending) = stop_at_queue.last() {
                    trace!("Pending: {:#?}", self.graph[*pending]);
                    if *pending == target {
                        // ensure that this node does not end in a jump
                        if !self.graph[nx]
                            .instrs
                            .last()
                            .unwrap()
                            .unwrap()
                            .opcode
                            .is_jump()
                            && let Some(outstanding) = outstanding_conditions.last()
                            && *outstanding == target
                        {
                            outstanding_conditions.pop();
                            self.graph[nx]
                                .instrs
                                .push(ParsedInstr::Good(Arc::new(pydis::Instr!(
                                    Mnemonic::JUMP_FORWARD.into(),
                                    0
                                ))));
                        }
                        continue;
                    }

                    // we need to find this path to see if it goes through a node that has already
                    // had its offsets touched
                    if self.is_downgraph(*pending, target) {
                        let path = astar(
                            &self.graph,
                            *pending,
                            |finish| finish == target,
                            |_e| 0,
                            |_| 0,
                        )
                        .unwrap()
                        .1;
                        let goes_through_updated_node =
                            path.iter().any(|node| updated_nodes.contains(node));

                        // If this does not go through an updated node, we can ignore
                        // the fact that the target is downgraph
                        if !goes_through_updated_node {
                            continue;
                        }
                    }
                }

                if updated_nodes.contains(&target) {
                    continue;
                }

                node_queue.push(target);
            }

            if let Some(jump_path) = jump_path
                && !updated_nodes.contains(&jump_path)
            {
                // the other node may add this one
                if let Some(pending) = stop_at_queue.last() {
                    if !self.is_downgraph(*pending, jump_path) {
                        if self.graph[nx]
                            .instrs
                            .last()
                            .unwrap()
                            .unwrap()
                            .opcode
                            .is_conditional_jump()
                        {
                            outstanding_conditions.push(jump_path);
                        }
                        stop_at_queue.push(jump_path);
                    }
                } else {
                    if self.graph[nx]
                        .instrs
                        .last()
                        .unwrap()
                        .unwrap()
                        .opcode
                        .is_conditional_jump()
                    {
                        outstanding_conditions.push(jump_path);
                    }
                    stop_at_queue.push(jump_path);
                }
            }
        }
    }

    /// Join redundant basic blocks together. This will take blocks like `(1) [NOP] -> (2) [LOAD_CONST 3]` and merge
    /// the second node into the first, forming `(1) [NOP, LOAD CONST 3]`. The 2nd node will be deleted and all of its outgoing
    /// edges will now originate from the merged node (1).
    ///
    /// This can only occur if (1) only has one outgoing edge, and (2) has only 1 incoming edge (1).
    pub(crate) fn join_blocks(&mut self) {
        let mut nodes_to_remove = BTreeSet::new();
        let mut merge_map = std::collections::BTreeMap::new();

        let mut bfs = Bfs::new(&self.graph, self.root);
        let mut nodes = vec![];
        while let Some(nx) = bfs.next(&self.graph) {
            nodes.push(nx);
        }

        for nx in nodes {
            let num_incoming = self.graph.edges_directed(nx, Direction::Incoming).count();

            // Ensure only 1 node points to this location
            if num_incoming != 1 {
                continue;
            }

            // Grab the incoming edge to this node so we can see how many outgoing the source has. We might be able
            // to combine these nodes
            let incoming_edge = self
                .graph
                .edges_directed(nx, Direction::Incoming)
                .next()
                .unwrap();

            let mut source_node_index = incoming_edge.source();
            if let Some(merged_to) = merge_map.get(&source_node_index) {
                source_node_index = *merged_to;
            }

            let parent_outgoing_edge_count = self
                .graph
                .edges_directed(source_node_index, Direction::Outgoing)
                .count();
            if parent_outgoing_edge_count != 1 {
                continue;
            }

            // Make sure that these nodes are not circular
            let are_circular = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .any(|edge| edge.target() == source_node_index);

            if are_circular {
                continue;
            }

            let mut source_or_target_is_permanent_jump_forward = false;

            let source_node = &self.graph[source_node_index];
            let dest_node = &self.graph[nx];

            if source_node.instrs.len() == 1
                && matches!(source_node.instrs[0], ParsedInstr::GoodDoNotRemove(_))
            {
                source_or_target_is_permanent_jump_forward = true;
            }

            if dest_node.instrs.len() == 1
                && matches!(dest_node.instrs[0], ParsedInstr::GoodDoNotRemove(_))
            {
                source_or_target_is_permanent_jump_forward = true;
            }

            if source_or_target_is_permanent_jump_forward {
                continue;
            }

            self.join_block(source_node_index, nx);

            nodes_to_remove.insert(nx);
            merge_map.insert(nx, source_node_index);
        }

        self.graph
            .retain_nodes(|_graph, node| !nodes_to_remove.contains(&node));

        for node in self.graph.node_indices() {
            if self
                .graph
                .edges_directed(node, Direction::Incoming)
                .next()
                .is_none()
            {
                self.root = node;
                break;
            }
        }
    }

    /// Merges dest into source
    pub fn join_block(&mut self, source_node_index: NodeIndex, dest: NodeIndex) {
        let incoming_edges = self
            .graph
            .edges_directed(dest, Direction::Incoming)
            .map(|edge| edge.id())
            .collect::<Vec<_>>();

        // Capture the destination's outgoing edges by target node index, not by
        // start offset. join_blocks removes nodes only after the whole pass, so
        // indices are stable here, while start offsets are not yet recomputed and
        // can be stale or ambiguous -- re-finding a target by offset can rewire the
        // edge onto the wrong block (e.g. an `addBan` jump drifting onto a
        // reassembled `LOG_INFO` call that now shares the trampoline's old offset).
        let outgoing_edges: Vec<(EdgeIndex, NodeIndex, EdgeWeight)> = self
            .graph
            .edges_directed(dest, Direction::Outgoing)
            .map(|edge| (edge.id(), edge.target(), *edge.weight()))
            .collect();
        let current_node = &self.graph[dest];

        let mut current_instrs = current_node.instrs.clone();
        let current_end_offset = current_node.end_offset;
        let parent_node = &mut self.graph[source_node_index];

        if let Some(last_instr) = parent_node.instrs.last().map(|i| i.unwrap())
            && last_instr.opcode.is_jump()
        {
            // Remove the last instruction -- this is our jump
            let removed_instruction = parent_node.instrs.pop().unwrap();

            trace!("{:?}", removed_instruction);
            assert!(
                !removed_instruction.unwrap().opcode.is_conditional_jump(),
                "Removed instruction is a conditional jump: {:#x?}. File: {}",
                removed_instruction,
                self.generate_file_name(None)
            );

            assert!(
                !matches!(removed_instruction, ParsedInstr::GoodDoNotRemove(_)),
                "Removed instruction is a permanent instruction: {:#x?}. File: {}",
                removed_instruction,
                self.generate_file_name(None)
            );
            // parent_node.instrs.push(ParsedInstr::Good(Arc::new(Instr!(TargetOpcode::POP_TOP))));
            // current_end_offset -= removed_instruction.unwrap().len() as u64;
            // current_end_offset += parent_node.instrs.last().unwrap().unwrap().len() as u64;
        }

        // Adjust the merged node's offsets
        parent_node.end_offset = current_end_offset;

        // Move this node's instructions into the parent
        parent_node.instrs.append(&mut current_instrs);

        let merged_node_index = source_node_index;

        // Remove the old outgoing edges -- these are no longer valid
        self.graph.retain_edges(|_graph, edge| {
            !outgoing_edges
                .iter()
                .any(|(outgoing_index, _target_offset, _weight)| *outgoing_index == edge)
                && !incoming_edges.contains(&edge)
        });

        // Re-add the old node's outgoing edges from the merged node.
        for (_edge_index, target_index, weight) in outgoing_edges {
            self.graph.add_edge(merged_node_index, target_index, weight);
        }
    }

    pub fn is_downgraph(&self, source: NodeIndex, dest: NodeIndex) -> bool {
        let node_map = dijkstra(&self.graph, source, Some(dest), |_| 1);
        node_map.get(&dest).is_some()
    }

    /// Whether a node is downgraph from a node that's used in execution
    pub fn is_downgraph_from_used_node(&self, source: NodeIndex, dest: NodeIndex) -> bool {
        if let Some(path) = astar(
            &self.graph,
            source,
            |finish| finish == dest,
            |e| {
                if self.graph[e.target()]
                    .flags
                    .contains(BasicBlockFlags::USED_IN_EXECUTION)
                {
                    1
                } else {
                    0
                }
            },
            |_| 0,
        ) {
            path.0 > 0
        } else {
            false
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::smallvm::tests::*;
    use crate::{Deobfuscator, Instr, deob};
    use pydis::opcode::Instruction;

    type TargetOpcode = pydis::opcode::py27::Standard;

    fn deobfuscate_codeobj(data: &[u8]) -> Result<Vec<Vec<u8>>, Error<TargetOpcode>> {
        let files_processed = AtomicUsize::new(0);
        Deobfuscator::new(data).deobfuscate().map(|res| {
            let mut output = vec![];
            let mut code_objects = vec![py27_marshal::read::marshal_loads(&res.data).unwrap()];

            let _files_processed = 0;
            while let Some(py27_marshal::Obj::Code(obj_mutex)) = code_objects.pop() {
                let obj = obj_mutex.read().unwrap();
                output.push(obj.code.as_ref().clone());

                for c in obj
                    .consts
                    .iter()
                    .rev()
                    .filter(|c| matches!(c, py27_marshal::Obj::Code(_)))
                {
                    code_objects.push(c.clone());
                }
            }

            output
        })
    }

    #[test]
    fn joining_multiple_jump_absolutes() {
        let mut code = default_code_obj();

        let instrs = [
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 3),
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 6),
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 9),
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph = CodeGraph::from_code(code, 0, false, None, None).unwrap();

        code_graph.join_blocks();

        assert_eq!(code_graph.graph.node_indices().count(), 1);

        let bb = &code_graph.graph[code_graph.graph.node_indices().next().unwrap()];
        assert_eq!(bb.instrs.len(), 2);
        assert_eq!(*bb.instrs[0].unwrap(), Instr!(TargetOpcode::LOAD_CONST, 0));
        assert_eq!(*bb.instrs[1].unwrap(), Instr!(TargetOpcode::RETURN_VALUE));
    }

    #[test]
    fn joining_jump_forward() {
        let mut code = default_code_obj();

        let instrs = [
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 3),
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 6),
            Instr!(TargetOpcode::JUMP_FORWARD, 0),
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph = CodeGraph::from_code(code, 0, false, None, None).unwrap();

        code_graph.join_blocks();

        assert_eq!(code_graph.graph.node_indices().count(), 1);

        let bb = &code_graph.graph[code_graph.graph.node_indices().next().unwrap()];
        assert_eq!(bb.instrs.len(), 2);
        assert_eq!(*bb.instrs[0].unwrap(), Instr!(TargetOpcode::LOAD_CONST, 0));
        assert_eq!(*bb.instrs[1].unwrap(), Instr!(TargetOpcode::RETURN_VALUE));
    }
    #[test]
    fn joining_with_conditional_jump() {
        let mut code = default_code_obj();

        let instrs = [
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 3),
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 6),
            Instr!(TargetOpcode::POP_JUMP_IF_TRUE, 13), // jump to LOAD_CONST 1
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::RETURN_VALUE),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph = CodeGraph::from_code(code, 0, false, None, None).unwrap();

        code_graph.join_blocks();

        assert_eq!(code_graph.graph.node_indices().count(), 3);

        let expected = [
            vec![
                Instr!(TargetOpcode::POP_JUMP_IF_TRUE, 13), // jump to LOAD_CONST 1
            ],
            vec![
                Instr!(TargetOpcode::LOAD_CONST, 0),
                Instr!(TargetOpcode::RETURN_VALUE),
            ],
            vec![
                Instr!(TargetOpcode::LOAD_CONST, 1),
                Instr!(TargetOpcode::RETURN_VALUE),
            ],
        ];

        for (bb_num, nx) in code_graph.graph.node_indices().enumerate() {
            let bb = &code_graph.graph[nx];

            assert_eq!(expected[bb_num].len(), bb.instrs.len());

            for (ix, instr) in bb.instrs.iter().enumerate() {
                assert_eq!(*instr.unwrap(), expected[bb_num][ix])
            }
        }
    }

    #[test]
    fn offsets_are_updated_simple() {
        let mut code = default_code_obj();

        let instrs = [
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 3),
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 6),
            Instr!(TargetOpcode::JUMP_FORWARD, 0),
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph =
            CodeGraph::<TargetOpcode>::from_code(code, 0, false, None, None).unwrap();

        code_graph.join_blocks();
        code_graph.update_bb_offsets();

        assert_eq!(code_graph.graph.node_indices().count(), 1);

        let bb = &code_graph.graph[code_graph.graph.node_indices().next().unwrap()];
        assert_eq!(bb.start_offset, 0);
        assert_eq!(bb.end_offset, 3);
    }

    #[test]
    fn for_iter_return_gets_masssaged() {
        let mut code = default_code_obj();

        let instrs = [
            // 0
            Instr!(TargetOpcode::LOAD_FAST, 4),
            // 3
            Instr!(TargetOpcode::POP_JUMP_IF_FALSE, 37),
            // 6
            Instr!(TargetOpcode::BUILD_LIST, 0),
            // 9
            Instr!(TargetOpcode::LOAD_FAST, 5),
            // 12
            Instr!(TargetOpcode::GET_ITER),
            // 13
            Instr!(TargetOpcode::FOR_ITER, 24),
            // 16
            Instr!(TargetOpcode::STORE_FAST, 8),
            // 19
            Instr!(TargetOpcode::LOAD_CONST, 4),
            // 22
            Instr!(TargetOpcode::COMPARE_OP, 5),
            // 25
            Instr!(TargetOpcode::POP_JUMP_IF_FALSE, 13),
            // 28
            Instr!(TargetOpcode::LOAD_FAST, 8),
            // 31
            Instr!(TargetOpcode::LIST_APPEND, 2),
            // 34
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 13),
            // 37
            Instr!(TargetOpcode::LOAD_FAST, 5),
            // 40
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        let mut expected = BTreeMap::<u64, _>::new();
        expected.insert(
            0,
            vec![
                Instr!(TargetOpcode::LOAD_FAST, 4),
                // 3
                Instr!(TargetOpcode::POP_JUMP_IF_FALSE, 38),
            ],
        );

        expected.insert(
            6,
            vec![
                // 6
                Instr!(TargetOpcode::BUILD_LIST, 0),
                // 9
                Instr!(TargetOpcode::LOAD_FAST, 5),
                // 12
                Instr!(TargetOpcode::GET_ITER),
            ],
        );

        expected.insert(
            13,
            vec![
                // 13
                Instr!(TargetOpcode::FOR_ITER, 21),
            ],
        );

        expected.insert(
            16,
            vec![
                // 16
                Instr!(TargetOpcode::STORE_FAST, 8),
                // 19
                Instr!(TargetOpcode::LOAD_CONST, 4),
                // 22
                Instr!(TargetOpcode::COMPARE_OP, 5),
                // 25
                Instr!(TargetOpcode::POP_JUMP_IF_FALSE, 13),
            ],
        );

        expected.insert(
            28,
            vec![
                // 28
                Instr!(TargetOpcode::LOAD_FAST, 8),
                // 31
                Instr!(TargetOpcode::LIST_APPEND, 2),
                // 34
                Instr!(TargetOpcode::JUMP_ABSOLUTE, 13),
            ],
        );

        expected.insert(
            38,
            vec![
                // 38
                Instr!(TargetOpcode::LOAD_FAST, 5),
                // 41
                Instr!(TargetOpcode::RETURN_VALUE),
            ],
        );

        expected.insert(
            37,
            vec![
                // 37
                Instr!(TargetOpcode::RETURN_VALUE),
            ],
        );

        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph = CodeGraph::from_code(code, 0, false, None, None).unwrap();
        code_graph.massage_returns_for_decompiler();
        code_graph.join_blocks();
        code_graph.update_bb_offsets();
        code_graph.update_branches();

        // println!("{:#?}", code_graph.graph);

        for nx in code_graph.graph.node_indices() {
            let bb = &code_graph.graph[nx];

            assert_eq!(expected[&bb.start_offset].len(), bb.instrs.len());

            for (ix, instr) in bb.instrs.iter().enumerate() {
                assert_eq!(*instr.unwrap(), expected[&bb.start_offset][ix])
            }
        }
    }

    #[test]
    #[ignore] // test is currently failing until we figure out the JUMP_FORWARD thing
    fn deobfuscate_known_file_compileall() {
        let obfuscated = include_bytes!("../test_data/obfuscated/compileall_stage4.pyc");
        let source_of_truth = include_bytes!("../test_data/expected/compileall.pyc");

        let deobfuscated = deobfuscate_codeobj(&obfuscated[8..]).expect("failed to deobfuscate");

        // The real bytecode should be at least the size of the deobfuscated bytecode -- use this
        // to avoid reallocating
        let mut source_of_truth_bytecode = Vec::with_capacity(deobfuscated.len());
        let mut code_objects =
            vec![py27_marshal::read::marshal_loads(&source_of_truth[8..]).unwrap()];

        let mut files_processed = 0;
        while let Some(py27_marshal::Obj::Code(obj_mutex)) = code_objects.pop() {
            let obj = obj_mutex.read().unwrap();
            let code_arc = Arc::new(obj.clone());
            let mut code_graph = CodeGraph::<TargetOpcode>::from_code(
                Arc::clone(&code_arc),
                files_processed,
                false,
                None,
                None,
            )
            .unwrap();
            // for debugging
            code_graph.generate_dot_graph("compileall");
            files_processed += 1;
            source_of_truth_bytecode.push(obj.code.as_ref().clone());

            for c in obj
                .consts
                .iter()
                .rev()
                .filter(|c| matches!(c, py27_marshal::Obj::Code(_)))
            {
                code_objects.push(c.clone());
            }
        }

        assert_eq!(deobfuscated.len(), source_of_truth_bytecode.len());

        for i in 0..deobfuscated.len() {
            assert_eq!(deobfuscated[i], source_of_truth_bytecode[i]);
            println!("Comparing {}", i);
        }
    }

    /// Takes a Python Code object and replaces its instructions with the provided
    /// slice
    pub fn change_code_instrs(code: &mut Arc<Code>, instrs: &[Instruction<TargetOpcode>]) {
        let mut bytecode = vec![];

        for instr in instrs {
            serialize_instr(instr, &mut bytecode);
        }

        Arc::get_mut(code).unwrap().code = Arc::new(bytecode);
    }

    pub fn serialize_instr(instr: &Instruction<TargetOpcode>, output: &mut Vec<u8>) {
        output.push(instr.opcode as u8);
        if let Some(arg) = instr.arg {
            output.extend_from_slice(&arg.to_le_bytes()[..]);
        }
    }
}
