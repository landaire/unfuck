use crate::error::Error;
use crate::partial_execution::*;
use crate::smallvm::ParsedInstr;
use bitflags::bitflags;

use crossbeam::channel::unbounded;

use log::trace;

use petgraph::algo::{astar, dijkstra};
use petgraph::graph::{EdgeIndex, Graph, NodeIndex};
use petgraph::visit::{Bfs, EdgeRef};
use petgraph::{Direction, IntoWeightedEdge};
use py27_marshal::{Code, Obj};
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::fmt;

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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

/// Represents a single block of code up until its next branching point
#[derive(Debug)]
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
                ParsedInstr::Good(i) => i.len() as u64,
                _ => 1,
            }
        }

        if ins_index.is_none() {
            return None;
        }

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
pub struct CodeGraph<TargetOpcode: Opcode<Mnemonic = py27::Mnemonic>> {
    pub(crate) root: NodeIndex,
    code: Arc<Code>,
    pub(crate) graph: Graph<BasicBlock<TargetOpcode>, EdgeWeight>,
    file_identifier: usize,
    /// Whether or not to generate dotviz graphs
    enable_dotviz_graphs: bool,
    phase: usize,
    /// Hashmap of graph file names and their data
    pub(crate) dotviz_graphs: HashMap<String, String>,
    pub(crate) on_graph_generated: Option<fn(&str, &str)>,
    _target_opcode_phantom: PhantomData<TargetOpcode>,
}

impl<TargetOpcode: 'static + Opcode<Mnemonic = py27::Mnemonic>> CodeGraph<TargetOpcode> {
    /// Converts bytecode to a graph. Returns the root node index and the graph.
    pub fn from_code(
        code: Arc<Code>,
        file_identifier: usize,
        enable_dotviz_graphs: bool,
        on_graph_generated: Option<fn(&str, &str)>,
    ) -> Result<CodeGraph<TargetOpcode>, Error<TargetOpcode>> {
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
                .map_or(false, |next_join| next_instr == *next_join);
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
                    if curr_basic_block.start_offset == 755 {}
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
            _target_opcode_phantom: Default::default(),
        })
    }

    fn generate_file_name(&self, stage: Option<&str>) -> String {
format!(
            "{}_phase{}_{}_{}.dot",
            self.file_identifier,
            self.phase,
            self.code.filename.to_string().replace("/", ""),
            self.code.name.to_string().replace("/", ""),
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
    ) -> Vec<ExecutionPath> {
        // create our thread communication channels
        let (completed_paths_sender, completed_paths_receiver) = unbounded();

        let new_mapped_function_names: Mutex<HashMap<String, String>> = Default::default();

        {
            // we could use atomic bools here, but that would introduce a problem if
            // threads transition while we're examining them
            let code = Arc::clone(&self.code);
            let root = self.root;
            let graph = std::sync::RwLock::new(self);
            let graph = &graph;
            let new_mapped_function_names = &new_mapped_function_names;
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
    ) {
        let completed_paths = self.invoke_partial_execution(mapped_function_names);
        self.generate_dot_graph("after_dead");

        let mut nodes_to_remove = std::collections::BTreeSet::<NodeIndex>::new();
        let mut insns_to_remove = HashMap::<NodeIndex, std::collections::BTreeSet<usize>>::new();

        // We want to pre-compute which nodes were used by each path. This will allow us to determine the
        // set of paths not taken which can be removed.
        let mut node_branch_direction = HashMap::<NodeIndex, EdgeWeight>::new();
        let mut potentially_unused_nodes = BTreeSet::<NodeIndex>::new();
        // All of the nodes which we _know_ are used as part of some execution.
        // May not be complete.
        let mut known_used_nodes = BTreeSet::<NodeIndex>::new();

        // TODO: high runtime complexity
        for path in &completed_paths {
            known_used_nodes.extend(path.executed_nodes.iter());

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
                if node_branch_direction.contains_key(&node) {
                    continue;
                }

                let branch_taken = result.0;

                let mut path_instructions = vec![];

                for other_path in &completed_paths {
                    match other_path.condition_results.get(&node) {
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

                // We've found that all nodes agree on this value. Let's add the
                // related instructions to our list of instructions to remove
                for (node, idx) in path_instructions {
                    self.graph[node].flags |= BasicBlockFlags::USED_IN_EXECUTION;
                    insns_to_remove.entry(node).or_default().insert(idx);
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
                    })
                    .unwrap();

                potentially_unused_nodes.insert(unused_path.1);
                self.graph.remove_edge(unused_path.0);
            }
        }

        if node_branch_direction.is_empty() {
            // no obfuscation?
            return;
        }

        self.generate_dot_graph("unused_partially_removed_edges");

        // Now that we've figured out which instructions to remove, and which nodes
        // are required for execution, let's figure out the set of nodes which we
        // _know_ are never used
        for nx in self.graph.node_indices() {
            // Our criteria for removing nodes is as follows:
            // 1. It must not be any node we've reached
            // 2. It must not be downgraph from any node we've reached (ignoring
            //    cyclic nodes)

            trace!("node incides testing: {:#?}", self.graph[nx]);
            // This node is used -- it must be kept
            if self.graph[nx]
                .flags
                .contains(BasicBlockFlags::USED_IN_EXECUTION)
                || known_used_nodes.contains(&nx)
            {
                trace!("ignoring");
                continue;
            }

            let has_used_parent = node_branch_direction
                .keys()
                .any(|used_nx| self.is_downgraph(*used_nx, nx));
            trace!("has_used_parent? {:#?}", has_used_parent);

            // We don't have any paths to this node from nodes which are _actually_ used. We should
            // remove it
            if !has_used_parent {
                nodes_to_remove.insert(nx);

                // Remove this edge to any children
                let child_edges = self
                    .graph
                    .edges_directed(nx, Direction::Outgoing)
                    .map(|e| e.id())
                    .collect::<Vec<_>>();

                self.graph.retain_edges(|_g, edge| {
                    !child_edges.iter().any(|child_edge| *child_edge == edge)
                });
            }
        }

        self.generate_dot_graph("unused_all_removed_edges");

        for (nx, insns_to_remove) in insns_to_remove {
            for ins_idx in insns_to_remove.iter().rev().cloned() {
                let current_node = &mut self.graph[nx];
                current_node.instrs.remove(ins_idx);
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
            if let Some(stop_at) = stop_at_queue.last() {
                if *stop_at == nx {
                    stop_at_queue.pop();
                }
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

            if let Some(jump_path) = jump_path {
                if !updated_nodes.contains(&jump_path) {
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
    }

    /// Fixes up the bytecode so that "implicit" returns can be in separate
    /// paths to make the job easier for a decompiler
    pub(crate) fn massage_returns_for_decompiler(&mut self) {
        let mut bfs = Bfs::new(&self.graph, self.root);
        while let Some(nx) = bfs.next(&self.graph) {
            let bb = &self.graph[nx];
            if let Some(instr) = bb.instrs.first() {
                if instr.unwrap().opcode.mnemonic() == Mnemonic::FOR_ITER {
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
                            instrs: vec![crate::smallvm::ParsedInstr::Good(Arc::new(
                                pydis::Instr!(Mnemonic::RETURN_VALUE.into()),
                            ))],
                            ..Default::default()
                        };
                        let new_return_node = self.graph.add_node(return_bb);
                        self.graph.add_edge(nx, new_return_node, EdgeWeight::Jump);
                    }
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
                let mut last_ins = source_node.instrs.last_mut().unwrap().unwrap();

                if !last_ins.opcode.is_jump() {
                    continue;
                }

                assert!(last_ins.opcode.has_arg());

                let last_ins_len = last_ins.len();

                let target_node = &self.graph[nx];
                let target_node_start = target_node.start_offset;

                let source_node = &mut self.graph[incoming_edge];
                let end_of_jump_ins = source_node.end_offset + last_ins_len as u64;

                if last_ins.opcode.mnemonic() == Mnemonic::JUMP_ABSOLUTE
                    && target_node_start > source_node.start_offset
                {
                    unsafe { Arc::get_mut_unchecked(&mut last_ins) }.opcode =
                        Mnemonic::JUMP_FORWARD.into();
                }

                if last_ins.opcode.mnemonic() == Mnemonic::JUMP_FORWARD
                    && target_node_start < end_of_jump_ins
                {
                    unsafe { Arc::get_mut_unchecked(&mut last_ins) }.opcode =
                        Mnemonic::JUMP_ABSOLUTE.into();
                }

                let last_ins_is_abs_jump = last_ins.opcode.is_absolute_jump();

                let new_arg = if last_ins_is_abs_jump {
                    target_node_start
                } else {
                    if target_node_start < source_node.end_offset {
                        let target_node = &self.graph[nx];
                        let source_node = &self.graph[incoming_edge];
                        panic!(
                            "target start < source end offset\nsource: {:#?},\ntarget {:#?}",
                            source_node, target_node
                        );
                    }
                    target_node_start - end_of_jump_ins
                };

                let mut last_ins = source_node.instrs.last_mut().unwrap().unwrap();
                unsafe { Arc::get_mut_unchecked(&mut last_ins) }.arg = Some(new_arg as u16);
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
            if let Some(stop_at) = stop_at_queue.last() {
                if *stop_at == nx {
                    stop_at_queue.pop();
                }
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

            if let Some(jump_path) = jump_path {
                if !self.graph[jump_path]
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
                    } else {
                        if matches!(
                            instr.unwrap().opcode.mnemonic(),
                            Mnemonic::SETUP_EXCEPT | Mnemonic::SETUP_FINALLY
                        ) {
                            stack_size += 0;
                        } else {
                            stack_size += instr.unwrap().stack_adjustment_after();
                        }
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
            if let Some(stop_at) = stop_at_queue.last() {
                if *stop_at == nx {
                    stop_at_queue.pop();
                }
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
                        {
                            if let Some(outstanding) = outstanding_conditions.last() {
                                if *outstanding == target {
                                    outstanding_conditions.pop();
                                    self.graph[nx].instrs.push(ParsedInstr::Good(Arc::new(
                                        pydis::Instr!(Mnemonic::JUMP_FORWARD.into(), 0),
                                    )));
                                }
                            }
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

            if let Some(jump_path) = jump_path {
                if !updated_nodes.contains(&jump_path) {
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

        let outgoing_edges: Vec<(EdgeIndex, u64, EdgeWeight)> = self
            .graph
            .edges_directed(dest, Direction::Outgoing)
            .map(|edge| {
                (
                    edge.id(),
                    self.graph[edge.target()].start_offset,
                    *edge.weight(),
                )
            })
            .collect();
        let current_node = &self.graph[dest];

        let mut current_instrs = current_node.instrs.clone();
        let current_end_offset = current_node.end_offset;
        let parent_node = &mut self.graph[source_node_index];

        if let Some(last_instr) = parent_node.instrs.last().map(|i| i.unwrap()) {
            if last_instr.opcode.is_jump() {
                // Remove the last instruction -- this is our jump
                let removed_instruction = parent_node.instrs.pop().unwrap();

                trace!("{:?}", removed_instruction);
                assert!(
                    !removed_instruction.unwrap().opcode.is_conditional_jump(),
                    "Removed instruction is a conditional jump: {:#x?}. File: {}",
                    removed_instruction, self.generate_file_name(None)
                );
                // parent_node.instrs.push(ParsedInstr::Good(Arc::new(Instr!(TargetOpcode::POP_TOP))));
                // current_end_offset -= removed_instruction.unwrap().len() as u64;
                // current_end_offset += parent_node.instrs.last().unwrap().unwrap().len() as u64;
            }
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
                && !incoming_edges
                    .iter()
                    .any(|incoming_index| *incoming_index == edge)
        });

        // Re-add the old node's outgoing edges
        for (_edge_index, target_offset, weight) in outgoing_edges {
            let target_index = self
                .graph
                .node_indices()
                .find(|i| self.graph[*i].start_offset == target_offset)
                .unwrap();

            // Grab this node's index
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
    use crate::{deobfuscate_codeobj as main_deob, Instr};
    use pydis::opcode::Instruction;

    type TargetOpcode = pydis::opcode::py27::Standard;

    fn deobfuscate_codeobj(data: &[u8], on_graph_generated: Option<fn(&str, &str)>) -> Result<Vec<Vec<u8>>, Error<TargetOpcode>> {
        let files_processed = AtomicUsize::new(0);
        main_deob::<TargetOpcode>(data, &files_processed, false, on_graph_generated).map(|_res| {
            let mut output = vec![];
            let mut code_objects = vec![py27_marshal::read::marshal_loads(data).unwrap()];

            let _files_processed = 0;
            while let Some(py27_marshal::Obj::Code(obj)) = code_objects.pop() {
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

        let mut code_graph = CodeGraph::from_code(code, 0, false, None).unwrap();

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

        let mut code_graph = CodeGraph::from_code(code, 0, false, None).unwrap();

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

        let mut code_graph = CodeGraph::from_code(code, 0, false, None).unwrap();

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

        let mut code_graph = CodeGraph::<TargetOpcode>::from_code(code, 0, false, None).unwrap();

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

        let mut code_graph = CodeGraph::from_code(code, 0, false, None).unwrap();
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
    fn deobfuscate_known_file_compileall() {
        let obfuscated = include_bytes!("../test_data/obfuscated/compileall_stage4.pyc");
        let source_of_truth = include_bytes!("../test_data/expected/compileall.pyc");

        let deobfuscated = deobfuscate_codeobj(&obfuscated[8..], None).expect("failed to deobfuscate");

        let mut source_of_truth_bytecode = Vec::with_capacity(deobfuscated.len());
        let mut code_objects =
            vec![py27_marshal::read::marshal_loads(&source_of_truth[8..]).unwrap()];

        let mut files_processed = 0;
        while let Some(py27_marshal::Obj::Code(obj)) = code_objects.pop() {
            let mut code_graph =
                CodeGraph::<TargetOpcode>::from_code(Arc::clone(&obj), files_processed, false, None)
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
