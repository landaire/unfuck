use crate::error::Error;
use crate::partial_execution::*;
use crate::smallvm::{InstructionTracker, ParsedInstr};
use bitflags::bitflags;


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
                            let split_node = code_graph.add_node(split_bb);
                            // The split portion holds the entry's lower offsets; claim the
                            // root for it (see the jump-case split below).
                            if root_node_id.is_none() {
                                root_node_id = Some(split_node);
                            }
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
                        let split_node = code_graph.add_node(split_bb);
                        // The split portion holds the lower offsets, so when the very
                        // first block to be finalized is split (a jump targets the middle
                        // of the entry block), the entry -- which starts at offset 0 -- is
                        // this `split_bb`, not the remainder. Claim the root here so the
                        // reachability-based dead-node removal does not later drop the
                        // entry block and the instructions it holds (e.g. the first
                        // default-argument load of a MAKE_FUNCTION).
                        if root_node_id.is_none() {
                            root_node_id = Some(split_node);
                        }
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
        let new_mapped_function_names: Mutex<HashMap<String, String>> = Default::default();
        let plain_loaded_modules: Mutex<HashSet<String>> = Default::default();

        let mut completed_paths: Vec<ExecutionPath> = Vec::new();
        {
            let code = Arc::clone(&self.code);
            let root = self.root;
            let graph = std::sync::RwLock::new(self);
            let graph = &graph;
            let new_mapped_function_names = &new_mapped_function_names;
            let new_plain_loaded_modules = &plain_loaded_modules;

            // Explore the CFG with an explicit worklist rather than a recursive rayon
            // fan-out: nesting that inner pool inside the outer per-file/per-code-object
            // scopes could exhaust and deadlock the shared thread pool. The outer scopes
            // still provide parallelism; one code object's path walk is sequential.
            let mut worklist: Vec<(NodeIndex, ExecutionPath)> =
                vec![(root, ExecutionPath::default())];
            // Memory backstop. The fork-depth cap already bounds the normal case,
            // but a pathological code object can still queue an unreasonable
            // number of paths -- and each path clones a full execution state, so
            // unbounded growth (times every core running in parallel) can exhaust
            // machine RAM. Stop exploring past this ceiling; partial path coverage
            // still produces valid bytecode, just less deobfuscated.
            const MAX_TOTAL_PATHS: usize = 1 << 14;
            while let Some((node, path)) = worklist.pop() {
                if completed_paths.len() + worklist.len() > MAX_TOTAL_PATHS {
                    break;
                }
                // A panic on one hostile path (a bad instruction, an unhandled VM
                // state) must not abort the whole code object; contain it so the
                // remaining paths still run. The driver is single-threaded here, so
                // there is no lock to poison and no sibling to wedge.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    perform_partial_execution(
                        node,
                        graph,
                        path,
                        new_mapped_function_names,
                        new_plain_loaded_modules,
                        Arc::clone(&code),
                        &mut worklist,
                        &mut completed_paths,
                    );
                }));
            }
        }

        // copy the mapped function names
        *mapped_function_names =
            new_mapped_function_names.lock().unwrap_or_else(|e| e.into_inner()).clone();

        completed_paths
    }

    /// Removes conditions that can be statically evaluated to be constant.
    ///
    /// When `enable_cross_block` is false the cross-block dead-operand removal is
    /// skipped and only each folded predicate's own-block slice is removed. The
    /// caller uses this as a fallback when the aggressive cross-block removal yields
    /// structurally invalid bytecode (see `deobfuscate_code`).
    pub(crate) fn remove_const_conditions(
        &mut self,
        mapped_function_names: &mut HashMap<String, String>,
        plain_loaded_modules: &mut HashSet<String>,
        enable_cross_block: bool,
    ) {
        self.generate_dot_graph("before_dead");

        let completed_paths =
            self.invoke_partial_execution(mapped_function_names, plain_loaded_modules);
        self.generate_dot_graph("after_dead");

        let mut nodes_to_remove = std::collections::BTreeSet::<NodeIndex>::new();
        let mut insns_to_remove = HashMap::<NodeIndex, std::collections::BTreeSet<usize>>::new();
        // Full def-use closure of each folded predicate, collected for cross-block
        // dead-operand removal after a global liveness check (see below).
        let mut condition_closures = Vec::<Vec<(NodeIndex, usize)>>::new();

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

                // A JUMP_IF_TRUE_OR_POP / JUMP_IF_FALSE_OR_POP is a short-circuit
                // boolean operator: when its branch is taken it KEEPS the tested value
                // on the stack -- that value is the expression's result (e.g. the
                // `'Allow'` of `'Allow' if x else 'Disallow'`), not a discarded opaque
                // predicate the way POP_JUMP_IF_* is. Folding it as a constant condition
                // would remove the value-producing load and leave the stack short, so
                // leave these untouched for the IR's boolean recovery to fold.
                if let Some(last) = self.graph[*node].instrs.last()
                    && matches!(
                        last.unwrap().opcode.mnemonic(),
                        Mnemonic::JUMP_IF_TRUE_OR_POP | Mnemonic::JUMP_IF_FALSE_OR_POP
                    )
                {
                    continue 'conditions;
                }

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

                // We've found that all nodes agree on this value. With precise
                // per-value provenance (each VmStack value carries only its own
                // producers) `path_instructions` is exactly the def-use closure that
                // computes this jump's condition. The local slice in the jump's own
                // block is always safe to remove; the cross-block remainder is removed
                // too, but only after a global liveness check (below), because
                // control-flow flattening splits an opaque predicate's COMPARE/operands
                // into predecessor blocks and removing just the local slice would
                // orphan the value they push on the stack.
                let condition_node = *node;
                for (instr_node, idx) in &path_instructions {
                    self.graph[*instr_node].flags |= BasicBlockFlags::USED_IN_EXECUTION;
                    if *instr_node == condition_node {
                        insns_to_remove.entry(*instr_node).or_default().insert(*idx);
                    }
                }
                condition_closures.push(path_instructions);

                node_branch_direction.insert(*node, branch_taken);

                // We know which branch all of these nodes took, so therefore we also know
                // which branch they *did not* take. Remove the edge for the untaken path.
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

        // Partial execution never follows exception edges (entering a handler would
        // need the exception triple modeled), so an opaque predicate sitting INSIDE an
        // except/finally handler is never folded above. But a self-contained
        // `LOAD_CONST c; POP_JUMP_IF_{TRUE,FALSE}` needs no stack model: the const it
        // loads IS the value the jump pops, so its direction is statically known
        // wherever it sits. Fold those here (handler or not) the same way -- drop the
        // untaken edge, turn the conditional into an unconditional JUMP_FORWARD, and
        // remove the now-dead LOAD_CONST -- so the handler reduces to its real shape
        // (e.g. a `try: from X import * except ImportError: from Y import *` whose
        // re-raise END_FINALLY the obfuscator guarded with `LOAD_CONST 0;
        // POP_JUMP_IF_TRUE`). The reachability prune and dead-instruction removal below
        // then clean up exactly as for the partial-execution folds.
        let mut local_folds: Vec<(NodeIndex, usize)> = Vec::new();
        for node in self.graph.node_indices() {
            if node_branch_direction.contains_key(&node) {
                continue;
            }
            let bb = &self.graph[node];
            let n = bb.instrs.len();
            if n < 2 {
                continue;
            }
            let (Some(last), Some(prev)) = (bb.instrs[n - 1].get(), bb.instrs[n - 2].get()) else {
                continue;
            };
            if !matches!(
                last.opcode.mnemonic(),
                Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE
            ) || prev.opcode.mnemonic() != Mnemonic::LOAD_CONST
            {
                continue;
            }
            let Some(const_idx) = prev.arg else { continue };
            let Some(truthy) =
                self.code.consts.get(const_idx as usize).and_then(const_truthy)
            else {
                continue;
            };
            let jumps = match last.opcode.mnemonic() {
                Mnemonic::POP_JUMP_IF_TRUE => truthy,
                _ => !truthy,
            };
            // Only fold the NEVER-TAKEN case (the jump is dead, control falls through).
            // The always-taken case is a control-flow-flattening trampoline whose taken
            // target may be backward -- converting it to a forward jump is wrong, and the
            // IR's own opaque-predicate folding already handles those post-build. The
            // never-taken case is exactly the handler END_FINALLY guard this pass targets,
            // and a fall-through successor is always forward, so the JUMP_FORWARD below is
            // sound.
            if !jumps {
                local_folds.push((node, n - 2));
            }
        }
        for (node, load_idx) in local_folds {
            // Drop the dead taken-side (Jump) edge; control falls through.
            let unused = self
                .graph
                .edges_directed(node, Direction::Outgoing)
                .find_map(|e| (*e.weight() == EdgeWeight::Jump).then(|| (e.id(), e.target())));
            let Some((edge_id, target)) = unused else {
                continue;
            };
            potentially_unused_nodes.insert(target);
            self.graph.remove_edge(edge_id);
            if self.graph.edges_directed(node, Direction::Outgoing).count() == 1 {
                let bb = &mut self.graph[node];
                if let Some(last) = bb.instrs.last()
                    && last.get().is_some_and(|i| i.opcode.is_conditional_jump())
                {
                    let last_mut = bb.instrs.last_mut().unwrap().unwrap_mut();
                    Arc::make_mut(last_mut).opcode = Mnemonic::JUMP_FORWARD.into();
                }
            }
            // The LOAD_CONST only fed the now-removed condition; drop it so the
            // JUMP_FORWARD does not leave its value stranded on the stack.
            insns_to_remove.entry(node).or_default().insert(load_idx);
            node_branch_direction.insert(node, EdgeWeight::NonJump);
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

        // Cross-block dead-operand removal. Stage 1 made provenance precise, so each
        // entry of `condition_closures` is exactly the def-use closure that computes a
        // folded predicate's condition. Removing the whole closure -- not just its
        // own-block slice -- eliminates the operands the flattener pushed in
        // predecessor blocks, which would otherwise orphan on the stack and corrupt
        // the next real construct. Two guards keep it sound:
        //   1. Purity: every instruction in the closure must be a side-effect-free
        //      bind/read/arith/compare/build. A closure touching a call, attribute or
        //      subscript store, import, etc. is left to the safe own-block-only path.
        //   2. Liveness: a closure that binds a name read by any instruction *outside*
        //      every closure is feeding live code, so it is not removed. Opaque-
        //      predicate temps are read only by predicates and pass; a store the real
        //      program reads does not. This is what the old coarse tracker could not do
        //      (it over-removed live binds, e.g. processConsoleCommand's
        //      validateAndParseCmd unpack) and why the precise pass had to land first.
        if enable_cross_block {
            // Control-flow opcodes are left wherever they sit (a closure may include
            // jumps that wire the flattened junk blocks together, including other
            // folded predicates' jumps); they are not removed here, only tolerated.
            let is_control_flow = |m: Mnemonic| -> bool {
                use Mnemonic::*;
                matches!(
                    m,
                    JUMP_FORWARD | JUMP_ABSOLUTE | POP_JUMP_IF_FALSE | POP_JUMP_IF_TRUE
                        | JUMP_IF_FALSE_OR_POP | JUMP_IF_TRUE_OR_POP | CONTINUE_LOOP
                        | BREAK_LOOP | SETUP_LOOP | POP_BLOCK
                )
            };
            // A data instruction we can delete: side-effect-free, pops a fixed number
            // of operands and pushes one or more results. UNPACK_SEQUENCE (multi-
            // output) is included because the junk always binds all its outputs to
            // predicate temps, so the closure carries every consumer; the structural
            // validator in `deobfuscate_code` is the backstop if a rarer split slips
            // through. DUP_TOP/DUP_TOPX stay out (their duplicate frequently feeds
            // live code).
            let pure_data = |m: Mnemonic| -> bool {
                use Mnemonic::*;
                matches!(
                    m,
                    LOAD_CONST | LOAD_NAME | LOAD_FAST | LOAD_GLOBAL | LOAD_DEREF | LOAD_ATTR
                        | STORE_NAME | STORE_FAST | STORE_GLOBAL | STORE_DEREF | POP_TOP
                        | UNPACK_SEQUENCE
                        | ROT_TWO | ROT_THREE | ROT_FOUR | COMPARE_OP | UNARY_POSITIVE
                        | UNARY_NEGATIVE | UNARY_NOT | UNARY_CONVERT | UNARY_INVERT
                        | GET_ITER | BUILD_TUPLE | BUILD_LIST | BUILD_SET | BUILD_MAP
                        | BUILD_SLICE | BINARY_POWER | BINARY_MULTIPLY | BINARY_DIVIDE
                        | BINARY_FLOOR_DIVIDE | BINARY_TRUE_DIVIDE | BINARY_MODULO
                        | BINARY_ADD | BINARY_SUBTRACT | BINARY_SUBSC | BINARY_LSHIFT
                        | BINARY_RSHIFT | BINARY_AND | BINARY_XOR | BINARY_OR
                        | INPLACE_POWER | INPLACE_MULTIPLY | INPLACE_DIVIDE
                        | INPLACE_FLOOR_DIVIDE | INPLACE_TRUE_DIVIDE | INPLACE_MODULO
                        | INPLACE_ADD | INPLACE_SUBTRACT | INPLACE_LSHIFT | INPLACE_RSHIFT
                        | INPLACE_AND | INPLACE_XOR | INPLACE_OR
                )
            };
            // Namespace key so STORE_FAST/LOAD_FAST share a slot distinct from the
            // STORE_NAME/GLOBAL and STORE_DEREF/LOAD_DEREF spaces.
            let store_key = |m: Mnemonic, arg: Option<u16>| -> Option<(u8, u16)> {
                match m {
                    Mnemonic::STORE_FAST => arg.map(|a| (0, a)),
                    Mnemonic::STORE_NAME | Mnemonic::STORE_GLOBAL => arg.map(|a| (1, a)),
                    Mnemonic::STORE_DEREF => arg.map(|a| (2, a)),
                    _ => None,
                }
            };
            let load_key = |m: Mnemonic, arg: Option<u16>| -> Option<(u8, u16)> {
                match m {
                    Mnemonic::LOAD_FAST => arg.map(|a| (0, a)),
                    Mnemonic::LOAD_NAME | Mnemonic::LOAD_GLOBAL => arg.map(|a| (1, a)),
                    Mnemonic::LOAD_DEREF | Mnemonic::LOAD_CLOSURE => arg.map(|a| (2, a)),
                    _ => None,
                }
            };

            let in_closure: BTreeSet<(NodeIndex, usize)> =
                condition_closures.iter().flatten().copied().collect();

            // Names read anywhere outside every closure are live and must not be unbound.
            let mut loaded_outside = BTreeSet::<(u8, u16)>::new();
            for nx in self.graph.node_indices() {
                for (i, instr) in self.graph[nx].instrs.iter().enumerate() {
                    if in_closure.contains(&(nx, i)) {
                        continue;
                    }
                    if let Some(instr) = instr.get()
                        && let Some(k) = load_key(instr.opcode.mnemonic(), instr.arg)
                    {
                        loaded_outside.insert(k);
                    }
                }
            }

            for closure in &condition_closures {
                let safe = closure.iter().all(|&(nx, i)| {
                    let Some(parsed) = self.graph[nx].instrs.get(i) else {
                        return false;
                    };
                    if matches!(parsed, ParsedInstr::GoodDoNotRemove(_)) {
                        return false;
                    }
                    let Some(instr) = parsed.get() else {
                        return false;
                    };
                    let m = instr.opcode.mnemonic();
                    if is_control_flow(m) {
                        return true; // tolerated, not removed
                    }
                    if !pure_data(m) {
                        return false;
                    }
                    match store_key(m, instr.arg) {
                        Some(k) => !loaded_outside.contains(&k),
                        None => true,
                    }
                });
                if safe {
                    // Remove only the data instructions of the closure; leave its jumps
                    // in place (they wire the CFG and are folded by their own pass).
                    for &(nx, i) in closure {
                        if let Some(instr) = self.graph[nx].instrs.get(i).and_then(|x| x.get())
                            && pure_data(instr.opcode.mnemonic())
                        {
                            insns_to_remove.entry(nx).or_default().insert(i);
                        }
                    }
                }
            }
        }

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

        // Drop empty nodes (their only instructions were the condition slice of a
        // folded opaque predicate) by splicing them out: redirect each predecessor
        // straight to the empty node's single child, then remove the empty node.
        //
        // The previous code merged the child INTO the empty node and removed the
        // child, which silently dropped the child's OTHER predecessors. When the
        // child was a forwarding block shared by several jumps (e.g. the
        // `addBan`/`removeBan` jumps and a folded condition all targeting one
        // trampoline-to-return), those jumps were left with no successor, which
        // orphaned them and corrupted the function.
        for node in self.graph.node_indices() {
            if !self.graph[node].instrs.is_empty() {
                continue;
            }
            let child = self
                .graph
                .edges_directed(node, Direction::Outgoing)
                .map(|e| e.target())
                .filter(|target| !self.is_downgraph(*target, node))
                .collect::<Vec<_>>();
            // More than one forward child means this is not the simple
            // single-successor shape this pass handles; skip it rather than
            // assume the first edge.
            if child.len() > 1 {
                continue;
            }
            let Some(&child) = child.first() else {
                continue;
            };
            if child == node {
                continue;
            }
            let incoming: Vec<(NodeIndex, EdgeWeight)> = self
                .graph
                .edges_directed(node, Direction::Incoming)
                .map(|e| (e.source(), *e.weight()))
                .collect();
            for (source, weight) in incoming {
                if source != child {
                    self.graph.add_edge(source, child, weight);
                }
            }
            nodes_to_remove.insert(node);
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
                .fold(0, |accum, instr| {
                    accum + instr.get().map_or(0, |ins| ins.len())
                });

            let end_offset = end_offset as u64;
            current_node.start_offset = current_offset;
            // An emptied basic block (or one ending in an undecodable instruction)
            // has no trailing instruction to subtract; treat its last-instruction
            // length as zero rather than panic.
            let last_instr_len = current_node
                .instrs
                .last()
                .and_then(|instr| instr.get())
                .map_or(0, |ins| ins.len() as u64);
            current_node.end_offset = current_offset + (end_offset - last_instr_len);

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


    /// Make non-adjacent fall-through edges explicit. The relinearizer can place a
    /// block whose `NonJump` (fall-through) successor is not the physically next
    /// block -- e.g. a ternary's else arm, which in the original sits just before the
    /// merge that stores the result, gets laid out *after* that merge. Without a jump
    /// the arm falls into the wrong instruction (the next `else`), leaving its value
    /// on the stack. Only blocks that do not already end in a jump are handled (those
    /// have a single fall-through edge); a conditional jump's fall-through is kept
    /// adjacent by the layout itself. Returns whether anything changed, so the caller
    /// can recompute offsets. `update_branches` resolves the inserted operands.
    pub(crate) fn fixup_fallthrough_jumps(&mut self) -> bool {
        let mut changed = false;
        for nx in self.graph.node_indices().collect::<Vec<_>>() {
            let block = &self.graph[nx];
            // A block ending in a bad (unrepaired) instruction cannot be reasoned
            // about; leave it untouched rather than panicking on unwrap.
            let last = match block.instrs.last() {
                Some(ParsedInstr::Good(instr) | ParsedInstr::GoodDoNotRemove(instr)) => instr,
                _ => continue,
            };
            // A block ending in a jump carries its successor explicitly already.
            if last.opcode.is_jump() {
                continue;
            }
            let next_offset = block.end_offset + last.len() as u64;
            let nonjump = self
                .graph
                .edges_directed(nx, Direction::Outgoing)
                .find(|edge| *edge.weight() == EdgeWeight::NonJump)
                .map(|edge| (edge.id(), edge.target()));
            let Some((edge_id, target)) = nonjump else {
                continue;
            };
            if self.graph[target].start_offset == next_offset {
                continue;
            }
            self.graph[nx]
                .instrs
                .push(ParsedInstr::Good(Arc::new(pydis::Instr!(
                    Mnemonic::JUMP_ABSOLUTE.into(),
                    0
                ))));
            *self.graph.edge_weight_mut(edge_id).unwrap() = EdgeWeight::Jump;
            changed = true;
        }
        changed
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
            // A `FOR_ITER` block is a loop header, not an `if` merge. Appending a
            // body-terminating jump to a block that falls into it (the iterable's
            // `GET_ITER` block, or a list comp's filter) inserts a spurious
            // `JUMP_FORWARD 0` between `GET_ITER` and `FOR_ITER`; the IR's list
            // comprehension recovery expects them adjacent, so skip these.
            if matches!(
                self.graph[target].instrs.first(),
                Some(ParsedInstr::Good(instr) | ParsedInstr::GoodDoNotRemove(instr))
                    if instr.opcode.mnemonic() == Mnemonic::FOR_ITER
            ) {
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


    /// Strips the obfuscator's dead-store junk inserted between an `IMPORT_FROM` and
    /// its real `STORE_NAME`. In clean CPython 2.7 a `from m import a` lowers to
    /// `IMPORT_FROM a; STORE_NAME a` with nothing between, so any instructions between
    /// an `IMPORT_FROM n` and the matching `STORE_NAME n` are obfuscation: a run of
    /// `LOAD_CONST k; STORE_NAME junk` pairs and a trailing value-shadowing
    /// `LOAD_CONST` that makes the real store bind the constant instead of the imported
    /// attribute (which is then discarded). Removing them restores `IMPORT_FROM n;
    /// STORE_NAME n` so the store consumes the attribute.
    ///
    /// Conservative by construction: it only fires when every instruction between is a
    /// `LOAD_CONST` or `STORE_NAME`, and it refuses to drop a `STORE_NAME` whose name is
    /// loaded anywhere in the code object (so a store that is actually read is never
    /// removed). Must run after `remove_const_conditions`, which folds the opaque
    /// predicates that may consume those junk stores; the offsets are stale after
    /// removal, so a `update_bb_offsets` pass must follow.
    pub(crate) fn strip_import_store_junk(&mut self) {
        // Name indices read anywhere in the code object; a junk store to one of these
        // is not provably dead, so it is left in place.
        let mut loaded_names: HashSet<u16> = HashSet::new();
        for node in self.graph.node_indices() {
            for instr in &self.graph[node].instrs {
                if let Some(instr) = instr.get() {
                    if matches!(
                        instr.opcode.mnemonic(),
                        Mnemonic::LOAD_NAME
                            | Mnemonic::LOAD_GLOBAL
                            | Mnemonic::DELETE_NAME
                            | Mnemonic::DELETE_GLOBAL
                    ) {
                        if let Some(arg) = instr.arg {
                            loaded_names.insert(arg);
                        }
                    }
                }
            }
        }

        for node in self.graph.node_indices().collect::<Vec<_>>() {
            let instrs = &self.graph[node].instrs;
            let mut remove: HashSet<usize> = HashSet::new();
            let mut i = 0;
            while i < instrs.len() {
                let Some(instr) = instrs[i].get() else {
                    i += 1;
                    continue;
                };
                if instr.opcode.mnemonic() != Mnemonic::IMPORT_FROM {
                    i += 1;
                    continue;
                }
                let name = instr.arg;
                // Find the matching STORE_NAME for this import name, requiring every
                // instruction between to be removable junk (LOAD_CONST or a STORE_NAME
                // of an unread name). Anything else aborts this import untouched.
                let mut j = i + 1;
                let mut ok = true;
                let mut matched = None;
                while j < instrs.len() {
                    let Some(between) = instrs[j].get() else {
                        ok = false;
                        break;
                    };
                    let mnemonic = between.opcode.mnemonic();
                    if mnemonic == Mnemonic::STORE_NAME && between.arg == name {
                        matched = Some(j);
                        break;
                    }
                    match mnemonic {
                        Mnemonic::LOAD_CONST => {}
                        Mnemonic::STORE_NAME => {
                            if between.arg.is_some_and(|arg| loaded_names.contains(&arg)) {
                                ok = false;
                                break;
                            }
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                    j += 1;
                }
                if let (true, Some(store_idx)) = (ok, matched) {
                    if store_idx > i + 1 {
                        for between in (i + 1)..store_idx {
                            remove.insert(between);
                        }
                    }
                    i = store_idx + 1;
                } else {
                    i += 1;
                }
            }
            if !remove.is_empty() {
                let block = &mut self.graph[node];
                let mut idx = 0;
                block.instrs.retain(|_| {
                    let keep = !remove.contains(&idx);
                    idx += 1;
                    keep
                });
            }
        }
    }

    /// Strips the obfuscator's dead-store junk inserted into a `class` creation. In
    /// clean CPython 2.7 a `class C(bases): ...` lowers to `LOAD_CONST 'C'; <bases>;
    /// LOAD_CONST <body>; MAKE_FUNCTION 0; CALL_FUNCTION 0; BUILD_CLASS; STORE_NAME C`
    /// with nothing between the `MAKE_FUNCTION` and the `BUILD_CLASS` except that one
    /// `CALL_FUNCTION 0`. The obfuscator wedges dead `unknown_N = <const/arith>` stores
    /// in there (on either side of the call); their net stack effect leaves extra values
    /// below `BUILD_CLASS`, which then pops garbage instead of (name, bases, dict) and
    /// the class fails to decompile. The deob can also have peeled one such store off,
    /// leaving an unbalanced `INPLACE` before the call.
    ///
    /// Remove the whole junk region between `MAKE_FUNCTION 0` and `BUILD_CLASS`, keeping
    /// only the single class `CALL_FUNCTION 0`, which restores the clean sequence and a
    /// balanced stack regardless of the junk's internal (im)balance. Conservative: it
    /// only fires when every instruction in the region is a pure-data junk op (loads,
    /// stores-to-name, arithmetic, builds -- no call besides the one class call, no jump,
    /// import, or attribute/subscript store), and it refuses when any name the junk
    /// stores is read outside the region (so a store that is actually used is never
    /// dropped). Offsets are stale after removal, so an `update_bb_offsets` must follow.
    pub(crate) fn strip_build_class_junk(&mut self) {
        // Names read (LOAD_NAME/LOAD_GLOBAL) anywhere, with the (node, index) of each
        // read, so a read inside the junk region itself can be excluded below.
        let mut name_reads: HashMap<u16, Vec<(NodeIndex, usize)>> = HashMap::new();
        for node in self.graph.node_indices() {
            for (i, instr) in self.graph[node].instrs.iter().enumerate() {
                if let Some(instr) = instr.get()
                    && matches!(
                        instr.opcode.mnemonic(),
                        Mnemonic::LOAD_NAME | Mnemonic::LOAD_GLOBAL
                    )
                    && let Some(arg) = instr.arg
                {
                    name_reads.entry(arg).or_default().push((node, i));
                }
            }
        }

        // Analyse with the original (stable) indices, then apply removals -- avoids
        // re-deriving name_reads after each edit. Disjoint regions, so one pass suffices.
        let mut to_remove: HashMap<NodeIndex, Vec<usize>> = HashMap::new();
        for node in self.graph.node_indices() {
            let instrs = &self.graph[node].instrs;
            for bc in 0..instrs.len() {
                if instrs[bc].get().map(|i| i.opcode.mnemonic()) != Some(Mnemonic::BUILD_CLASS) {
                    continue;
                }
                // Walk back from BUILD_CLASS over the junk to the class body's
                // MAKE_FUNCTION, requiring exactly one CALL_FUNCTION 0 (the class call)
                // and only pure-data junk otherwise.
                let mut make_idx = None;
                let mut call_idx = None;
                let mut k = bc;
                while k > 0 {
                    k -= 1;
                    let Some(instr) = instrs[k].get() else {
                        break;
                    };
                    let mnemonic = instr.opcode.mnemonic();
                    if mnemonic == Mnemonic::MAKE_FUNCTION && instr.arg == Some(0) {
                        make_idx = Some(k);
                        break;
                    }
                    if mnemonic == Mnemonic::CALL_FUNCTION && instr.arg == Some(0) {
                        if call_idx.is_some() {
                            break; // a second call: not the simple class shape
                        }
                        call_idx = Some(k);
                        continue;
                    }
                    if !is_class_junk_op(mnemonic) {
                        break;
                    }
                }
                let (Some(make_idx), Some(call_idx)) = (make_idx, call_idx) else {
                    continue;
                };
                if bc - make_idx <= 2 {
                    continue; // already clean: MAKE_FUNCTION; CALL_FUNCTION; BUILD_CLASS
                }
                // Liveness: every name the junk stores must be read only inside the junk
                // region; a read elsewhere means the store is live and must stay.
                let stored = (make_idx + 1..bc).filter(|&j| j != call_idx).filter_map(|j| {
                    let instr = instrs[j].get()?;
                    (instr.opcode.mnemonic() == Mnemonic::STORE_NAME)
                        .then_some(())
                        .and(instr.arg)
                });
                let live = stored.clone().any(|name| {
                    name_reads.get(&name).is_some_and(|reads| {
                        reads
                            .iter()
                            .any(|&(rn, ri)| rn != node || !(make_idx + 1..bc).contains(&ri))
                    })
                });
                if live {
                    continue;
                }
                to_remove
                    .entry(node)
                    .or_default()
                    .extend((make_idx + 1..bc).filter(|&j| j != call_idx));
            }
        }
        for (node, mut indices) in to_remove {
            indices.sort_unstable();
            let block = &mut self.graph[node];
            for j in indices.into_iter().rev() {
                block.instrs.remove(j);
            }
        }
    }

    /// Strips the obfuscator's dead-store junk wedged between an `IMPORT_NAME` and its
    /// `IMPORT_FROM`. In clean CPython 2.7 a `from m import a` lowers to
    /// `IMPORT_NAME m; IMPORT_FROM a; STORE_NAME a` with nothing between the name and the
    /// from -- `IMPORT_FROM` peeks the module the `IMPORT_NAME` left on the stack. The
    /// obfuscator wedges dead `unknown_N = <const/arith>` stores there, whose net stack
    /// effect leaves stray values ON TOP of the module, so `IMPORT_FROM` reads garbage
    /// instead of the module and the unstacker rejects it. (Companion to
    /// `strip_import_store_junk`, which handles the junk on the `IMPORT_FROM`..`STORE_NAME`
    /// side.) Remove the whole region so `IMPORT_NAME` leads straight into `IMPORT_FROM`.
    ///
    /// Conservative in the same way as `strip_build_class_junk`: only pure-data junk ops
    /// between, and a name read outside the region keeps its store. Offsets are stale
    /// after removal, so an `update_bb_offsets` must follow.
    pub(crate) fn strip_import_name_junk(&mut self) {
        let mut name_reads: HashMap<u16, Vec<(NodeIndex, usize)>> = HashMap::new();
        for node in self.graph.node_indices() {
            for (i, instr) in self.graph[node].instrs.iter().enumerate() {
                if let Some(instr) = instr.get()
                    && matches!(
                        instr.opcode.mnemonic(),
                        Mnemonic::LOAD_NAME | Mnemonic::LOAD_GLOBAL
                    )
                    && let Some(arg) = instr.arg
                {
                    name_reads.entry(arg).or_default().push((node, i));
                }
            }
        }

        let mut to_remove: HashMap<NodeIndex, Vec<usize>> = HashMap::new();
        for node in self.graph.node_indices() {
            let instrs = &self.graph[node].instrs;
            for i in 0..instrs.len() {
                if instrs[i].get().map(|x| x.opcode.mnemonic()) != Some(Mnemonic::IMPORT_NAME) {
                    continue;
                }
                // Scan forward over pure-data junk to the first IMPORT_FROM (the anchor).
                let mut j = i + 1;
                while j < instrs.len()
                    && instrs[j].get().is_some_and(|x| is_class_junk_op(x.opcode.mnemonic()))
                {
                    j += 1;
                }
                if j == i + 1 || instrs.get(j).and_then(|x| x.get()).map(|x| x.opcode.mnemonic())
                    != Some(Mnemonic::IMPORT_FROM)
                {
                    continue; // already clean, or not the import-junk shape
                }
                let stored = (i + 1..j).filter_map(|k| {
                    let instr = instrs[k].get()?;
                    (instr.opcode.mnemonic() == Mnemonic::STORE_NAME)
                        .then_some(())
                        .and(instr.arg)
                });
                let live = stored.clone().any(|name| {
                    name_reads.get(&name).is_some_and(|reads| {
                        reads.iter().any(|&(rn, ri)| rn != node || !(i + 1..j).contains(&ri))
                    })
                });
                if live {
                    continue;
                }
                to_remove.entry(node).or_default().extend(i + 1..j);
            }
        }
        for (node, mut indices) in to_remove {
            indices.sort_unstable();
            let block = &mut self.graph[node];
            for k in indices.into_iter().rev() {
                block.instrs.remove(k);
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
                Some(ParsedInstr::Good(instr) | ParsedInstr::GoodDoNotRemove(instr)) => {
                    instr.opcode.mnemonic() != Mnemonic::RETURN_VALUE
                }
                // A trailing Bad instruction (or empty leaf) has no readable
                // terminator, so it needs an implicit `return None` appended.
                _ => true,
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
                // A leaf has no successor, so a trailing unconditional jump is dangling
                // (its target was eliminated during deobfuscation). Drop it before the
                // implicit return: left in place, the return sits unreachable after it,
                // and `update_branches` -- which only retargets a block's LAST instruction
                // -- cannot fix the stranded jump, so it keeps a stale operand that lands
                // mid-instruction (the cause of the except-into-mid-expression scrambles).
                if let Some(last) = bb.instrs.last().and_then(|ins| ins.get()) {
                    if matches!(
                        last.opcode.mnemonic(),
                        Mnemonic::JUMP_FORWARD | Mnemonic::JUMP_ABSOLUTE
                    ) {
                        bb.instrs.pop();
                    }
                }
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
                // An empty block, or one whose last slot is an undecodable
                // instruction, has no jump to retarget; skip the edge rather than
                // panic on it.
                let last_ins_ref = match source_node.instrs.last().and_then(|i| i.get()) {
                    Some(ins) => ins,
                    None => continue,
                };

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

            // An undecodable instruction has no opcode byte to emit. Skip it rather
            // than panic: the rest of the module still regenerates, and the affected
            // function is rejected later by the decoder rather than taking the whole
            // file down.
            for instr in current_node.instrs.iter().filter_map(|i| i.get()) {
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
            // Only an unconditional, removable jump can be dropped when joining
            // blocks: a conditional jump would lose a branch, and a permanent
            // (GoodDoNotRemove) instruction must be kept. If either holds this
            // join is invalid, so skip it rather than corrupt the graph.
            if last_instr.opcode.is_conditional_jump()
                || matches!(parent_node.instrs.last(), Some(ParsedInstr::GoodDoNotRemove(_)))
            {
                return;
            }

            // Remove the last instruction -- this is our jump
            let removed_instruction = parent_node.instrs.pop().unwrap();
            trace!("{:?}", removed_instruction);
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

/// Python truthiness of a constant, for statically folding a `LOAD_CONST c;
/// POP_JUMP_IF_*` opaque predicate. Returns `None` for a const whose truth value the
/// folder does not evaluate (e.g. a code object), so such a jump is left untouched.
fn const_truthy(obj: &Obj) -> Option<bool> {
    use num_traits::Zero;
    Some(match obj {
        Obj::None => false,
        Obj::Bool(b) => *b,
        Obj::Long(l) => !l.read().unwrap_or_else(|e| e.into_inner()).is_zero(),
        Obj::Float(f) => *f != 0.0,
        Obj::String(s) => !s.read().unwrap_or_else(|e| e.into_inner()).is_empty(),
        Obj::Tuple(t) => !t.read().unwrap_or_else(|e| e.into_inner()).is_empty(),
        Obj::List(l) => !l.read().unwrap_or_else(|e| e.into_inner()).is_empty(),
        Obj::Dict(d) => !d.read().unwrap_or_else(|e| e.into_inner()).is_empty(),
        Obj::Set(s) => !s.read().unwrap_or_else(|e| e.into_inner()).is_empty(),
        _ => return None,
    })
}

/// Whether `m` is a pure-data instruction the class-creation junk stripper may remove:
/// a load, store-to-name, arithmetic/bitwise op, or value build. Excludes anything with
/// a side effect or that could fault (calls, jumps, imports, attribute/subscript access,
/// `STORE_ATTR`/`STORE_SUBSCR`), so removing the run cannot change observable behaviour.
fn is_class_junk_op(m: Mnemonic) -> bool {
    use Mnemonic::*;
    let name = format!("{:?}", m);
    if name.starts_with("INPLACE_") || name.starts_with("UNARY_") {
        return true;
    }
    // Binary arithmetic/bitwise, but NOT BINARY_SUBSC (a `__getitem__` may have effects).
    if name.starts_with("BINARY_") && m != BINARY_SUBSC {
        return true;
    }
    matches!(
        m,
        LOAD_CONST
            | LOAD_NAME
            | LOAD_GLOBAL
            | STORE_NAME
            | STORE_MAP
            | UNPACK_SEQUENCE
            | BUILD_TUPLE
            | BUILD_LIST
            | BUILD_SET
            | BUILD_MAP
            | ROT_TWO
            | ROT_THREE
            | ROT_FOUR
            | DUP_TOP
            | DUP_TOPX
            | COMPARE_OP
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::smallvm::tests::*;
    use crate::{Deobfuscator, Instr, deob};
    use num_bigint::BigInt;
    use pydis::opcode::Instruction;

    type TargetOpcode = pydis::opcode::py27::Standard;

    fn deobfuscate_codeobj(data: &[u8]) -> Result<Vec<Vec<u8>>, Error<TargetOpcode>> {
        let files_processed = AtomicUsize::new(0);
        Deobfuscator::new(data).deobfuscate().map(|res| {
            let mut output = vec![];
            let mut code_objects = vec![py27_marshal::read::marshal_loads(&res.data).unwrap()];

            let _files_processed = 0;
            while let Some(py27_marshal::Obj::Code(obj_mutex)) = code_objects.pop() {
                let obj = obj_mutex.read().unwrap_or_else(|e| e.into_inner());
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
    fn folds_never_taken_const_predicate_in_handler() {
        // A self-contained never-taken opaque predicate `LOAD_CONST 0(falsy);
        // POP_JUMP_IF_TRUE <dead>` sitting INSIDE an exception handler. Partial execution
        // never follows the SETUP_EXCEPT edge, so it cannot fold this -- only the local
        // const-condition fold does. It must become a plain fall-through and the dead arm
        // must be pruned. (A predicate in normal flow is folded by partial execution
        // regardless, so the handler placement is what exercises the local fold.)
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts =
            Arc::new(vec![crate::Long!(0i64), Obj::None, crate::Long!(99i64)]);

        // SETUP_EXCEPT/LOAD_CONST/POP_JUMP_IF_TRUE/JUMP_FORWARD are 3 bytes;
        // POP_BLOCK/RETURN_VALUE are 1.
        let instrs = [
            Instr!(TargetOpcode::SETUP_EXCEPT, 7), // 0: handler at 0+3+7 = 10
            Instr!(TargetOpcode::LOAD_CONST, 1),   // 3: try body (None)
            Instr!(TargetOpcode::POP_BLOCK),       // 6
            Instr!(TargetOpcode::JUMP_FORWARD, 14), // 7: -> end at 10+14 = 24
            Instr!(TargetOpcode::LOAD_CONST, 0),   // 10: HANDLER -- falsy opaque const
            Instr!(TargetOpcode::POP_JUMP_IF_TRUE, 20), // 13: never taken -> falls to 16
            Instr!(TargetOpcode::LOAD_CONST, 1),   // 16: handler body (None)
            Instr!(TargetOpcode::RETURN_VALUE),    // 19
            Instr!(TargetOpcode::LOAD_CONST, 2),   // 20: DEAD arm
            Instr!(TargetOpcode::RETURN_VALUE),    // 23
            Instr!(TargetOpcode::LOAD_CONST, 1),   // 24: end
            Instr!(TargetOpcode::RETURN_VALUE),    // 27
        ];
        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph =
            CodeGraph::<'_, TargetOpcode>::from_code(code, 0, false, None, None).unwrap();
        let mut mapped = HashMap::new();
        let mut plain = HashSet::new();
        code_graph.remove_const_conditions(&mut mapped, &mut plain, true);

        let surviving: Vec<_> = code_graph
            .graph
            .node_indices()
            .flat_map(|nx| code_graph.graph[nx].instrs.iter().filter_map(|i| i.get()))
            .map(|i| (i.opcode.mnemonic(), i.arg))
            .collect();

        // The handler's never-taken predicate is folded away and its dead arm
        // (`LOAD_CONST 2`) pruned, even though no partial-execution path reached it.
        assert!(
            !surviving.iter().any(|(m, _)| *m == Mnemonic::POP_JUMP_IF_TRUE),
            "the handler's never-taken predicate should be folded away: {:?}",
            surviving
        );
        assert!(
            !surviving.iter().any(|(m, arg)| *m == Mnemonic::LOAD_CONST && *arg == Some(2)),
            "the dead arm should be pruned: {:?}",
            surviving
        );
    }

    #[test]
    fn strips_build_class_junk() {
        // class C(object): ... with obfuscator junk wedged between MAKE_FUNCTION and
        // BUILD_CLASS -- a balanced dead store, an unbalanced INPLACE before the call, and
        // a dead BINARY after it. The junk (which leaves stray values under BUILD_CLASS)
        // must be removed, leaving MAKE_FUNCTION 0; CALL_FUNCTION 0; BUILD_CLASS.
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts =
            Arc::new(vec![Obj::None, Obj::None, crate::Long!(99i64), Obj::None]);
        // names: 0=object, 1=unknown_0 (junk), 2=C
        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),    // class name 'C'
            Instr!(TargetOpcode::LOAD_NAME, 0),     // base: object
            Instr!(TargetOpcode::BUILD_TUPLE, 1),
            Instr!(TargetOpcode::LOAD_CONST, 1),    // class body code
            Instr!(TargetOpcode::MAKE_FUNCTION, 0),
            // --- junk before the call: a store and an unbalanced INPLACE ---
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::STORE_NAME, 1),    // unknown_0 = 99
            Instr!(TargetOpcode::LOAD_NAME, 1),
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::INPLACE_ADD),      // unbalanced: no store
            Instr!(TargetOpcode::CALL_FUNCTION, 0), // the class call
            // --- junk after the call ---
            Instr!(TargetOpcode::LOAD_NAME, 1),
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::BINARY_ADD),       // dead, leaves a stray value
            Instr!(TargetOpcode::BUILD_CLASS),
            Instr!(TargetOpcode::STORE_NAME, 2),    // C = <class>
            Instr!(TargetOpcode::LOAD_CONST, 3),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];
        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph =
            CodeGraph::<'_, TargetOpcode>::from_code(code, 0, false, None, None).unwrap();
        code_graph.strip_build_class_junk();

        let body: Vec<_> = code_graph
            .graph
            .node_indices()
            .flat_map(|nx| code_graph.graph[nx].instrs.iter().filter_map(|i| i.get()))
            .map(|i| i.opcode.mnemonic())
            .collect();

        // The junk arithmetic is gone; MAKE_FUNCTION leads straight to the call then
        // BUILD_CLASS. (The legitimate `STORE_NAME C` after BUILD_CLASS stays.)
        assert!(
            !body.iter().any(|m| *m == Mnemonic::INPLACE_ADD || *m == Mnemonic::BINARY_ADD),
            "junk arithmetic should be gone: {:?}",
            body
        );
        let make = body.iter().position(|m| *m == Mnemonic::MAKE_FUNCTION).unwrap();
        assert_eq!(body[make + 1], Mnemonic::CALL_FUNCTION, "call must follow make: {:?}", body);
        assert_eq!(body[make + 2], Mnemonic::BUILD_CLASS, "build_class must follow call: {:?}", body);
    }

    #[test]
    fn strips_import_name_junk() {
        // from m import a, with obfuscator junk wedged between IMPORT_NAME and IMPORT_FROM
        // (dead store, INPLACE, and a stray LOAD_NAME on top of the module). The junk must
        // be removed so IMPORT_NAME leads straight into IMPORT_FROM.
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts =
            Arc::new(vec![Obj::None, Obj::None, crate::Long!(99i64), Obj::None]);
        // names: 0=module, 1=imported attr, 2=unknown_0 (junk)
        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),  // -1 import level
            Instr!(TargetOpcode::LOAD_CONST, 1),  // fromlist
            Instr!(TargetOpcode::IMPORT_NAME, 0), // module on stack
            // --- junk between IMPORT_NAME and IMPORT_FROM ---
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::STORE_NAME, 2),  // unknown_0 = 99
            Instr!(TargetOpcode::LOAD_NAME, 2),
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::INPLACE_ADD),
            Instr!(TargetOpcode::STORE_NAME, 2),
            Instr!(TargetOpcode::LOAD_NAME, 2),   // stray value on top of the module
            Instr!(TargetOpcode::IMPORT_FROM, 1), // anchor: must peek the module
            Instr!(TargetOpcode::STORE_NAME, 1),  // a = <attr>
            Instr!(TargetOpcode::POP_TOP),
            Instr!(TargetOpcode::LOAD_CONST, 3),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];
        change_code_instrs(&mut code, &instrs[..]);

        let mut code_graph =
            CodeGraph::<'_, TargetOpcode>::from_code(code, 0, false, None, None).unwrap();
        code_graph.strip_import_name_junk();

        let body: Vec<_> = code_graph
            .graph
            .node_indices()
            .flat_map(|nx| code_graph.graph[nx].instrs.iter().filter_map(|i| i.get()))
            .map(|i| i.opcode.mnemonic())
            .collect();

        assert!(
            !body.iter().any(|m| *m == Mnemonic::INPLACE_ADD),
            "junk arithmetic should be gone: {:?}",
            body
        );
        let imp = body.iter().position(|m| *m == Mnemonic::IMPORT_NAME).unwrap();
        assert_eq!(
            body[imp + 1],
            Mnemonic::IMPORT_FROM,
            "IMPORT_FROM must follow IMPORT_NAME: {:?}",
            body
        );
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
            let obj = obj_mutex.read().unwrap_or_else(|e| e.into_inner());
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
