//! Recovers nested `if`/`else` and `while` loops from the control-flow graph.
//!
//! Conditionals merge at their immediate post-dominator; loops are found from
//! back edges (an edge whose target dominates its source). The structurer walks
//! the graph recursively, emitting a loop when it first reaches a loop header and
//! translating jumps to the loop header or follow into `continue`/`break`.
//!
//! `if`/`else`, `while`, and `for` are recovered; short-circuit operators and
//! exceptions are not yet handled.

use std::collections::{HashMap, HashSet};

use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Reversed;

use super::cfg::{BlockId, Cfg, Terminator};
use super::expr::Stmt;
use super::IrError;

/// Guards against runaway recursion if the graph violates the reducible, well
/// nested assumptions the structurer relies on. Kept well below the point a deep
/// recursion would overflow the stack; real code never nests this far, so hitting
/// it means the graph is one the structurer cannot reduce, and it is rejected.
const MAX_DEPTH: usize = 256;

/// A point control reaches: either a block or the function exit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    Block(BlockId),
    Exit,
}

/// What a loop header looks like and where it ends.
struct LoopInfo {
    /// Blocks that belong to the loop body (including the header).
    body: HashSet<BlockId>,
    /// The block control reaches when the loop exits.
    follow: Point,
}

/// The loop currently being structured, used to translate jumps to `break`/`continue`.
#[derive(Clone, Copy)]
struct LoopFrame {
    header: BlockId,
    follow: Point,
}

/// Structures a control-flow graph into a nested statement list.
pub fn structure(cfg: &Cfg) -> Result<Vec<Stmt>, IrError> {
    let graph = Graph::build(cfg);
    let preds = predecessors(cfg);
    let loops = graph.detect_loops(cfg, &preds);
    let mut structurer = Structurer {
        cfg,
        graph: &graph,
        preds,
        loops,
        loop_stack: Vec::new(),
    };
    structurer.region(cfg.entry, Point::Exit, 0)
}

struct Structurer<'a> {
    cfg: &'a Cfg,
    graph: &'a Graph,
    preds: HashMap<BlockId, Vec<BlockId>>,
    loops: HashMap<BlockId, LoopInfo>,
    loop_stack: Vec<LoopFrame>,
}

impl Structurer<'_> {
    /// Emits the region from `start` up to (but excluding) `stop`.
    fn region(&mut self, start: BlockId, stop: Point, depth: usize) -> Result<Vec<Stmt>, IrError> {
        if depth > MAX_DEPTH {
            return Err(IrError::Unstructurable);
        }

        let mut out = Vec::new();
        let mut cursor = Some(start);
        while let Some(current) = cursor {
            if stop == Point::Block(current) {
                break;
            }

            // The first time control reaches a loop header, emit the whole loop and
            // resume at its follow.
            if self.loops.contains_key(&current) && !self.in_current_loop(current) {
                let (stmt, follow) = self.structure_loop(current, depth)?;
                out.push(stmt);
                cursor = self.point_block(follow);
                continue;
            }

            out.extend(self.cfg.block(current).stmts.iter().cloned());

            match &self.cfg.block(current).terminator {
                Terminator::Return(value) => {
                    out.push(Stmt::Return(value.clone()));
                    cursor = None;
                }
                Terminator::Raise(args) => {
                    out.push(Stmt::Raise(args.clone()));
                    cursor = None;
                }
                Terminator::Jump(target) | Terminator::Fallthrough(target) => {
                    let next = self.cfg.target(*target)?;
                    match self.loop_edge(next) {
                        Some(stmt) => {
                            out.push(stmt);
                            cursor = None;
                        }
                        None => cursor = Some(next),
                    }
                }
                Terminator::CondBranch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    let follow = self.graph.immediate_postdom(current);
                    let true_block = self.cfg.target(*if_true)?;
                    let false_block = self.cfg.target(*if_false)?;

                    let then = self.arm(true_block, follow, depth)?;
                    let els = self.arm(false_block, follow, depth)?;
                    out.push(Stmt::If {
                        cond: *cond,
                        then,
                        els,
                    });
                    cursor = self.point_block(follow);
                }
                // A ForIter block is always a loop header and is handled by the loop
                // check above; reaching it here means the back edge was missing.
                Terminator::ForIter { .. } => return Err(IrError::Unstructurable),
            }
        }
        Ok(out)
    }

    /// Structures one branch arm: empty if the arm is the merge, otherwise a
    /// `break`/`continue` if it leaves the enclosing loop, otherwise a sub-region.
    fn arm(&mut self, entry: BlockId, follow: Point, depth: usize) -> Result<Vec<Stmt>, IrError> {
        if follow == Point::Block(entry) {
            return Ok(Vec::new());
        }
        if let Some(stmt) = self.loop_edge(entry) {
            return Ok(vec![stmt]);
        }
        self.region(entry, follow, depth + 1)
    }

    /// Emits the loop headed at `header` (a `while` for a conditional header, a
    /// `for` for a `FOR_ITER` header) and returns the statement plus the follow.
    fn structure_loop(
        &mut self,
        header: BlockId,
        depth: usize,
    ) -> Result<(Stmt, Point), IrError> {
        let info = self.loops.get(&header).expect("loop header");
        let follow = info.follow;
        let body_set = info.body.clone();
        let terminator = self.cfg.block(header).terminator.clone();

        match terminator {
            Terminator::CondBranch {
                cond,
                if_true,
                if_false,
            } => {
                let true_block = self.cfg.target(if_true)?;
                let false_block = self.cfg.target(if_false)?;
                // The branch that stays inside the loop is the body; if that is the
                // false branch the loop runs while `not cond`.
                let (negated, body_entry) = if body_set.contains(&true_block) {
                    (false, true_block)
                } else if body_set.contains(&false_block) {
                    (true, false_block)
                } else {
                    return Err(IrError::Unstructurable);
                };
                let body = self.loop_body(header, body_entry, follow, depth)?;
                Ok((Stmt::While { cond, negated, body }, follow))
            }
            Terminator::ForIter { body: body_off, .. } => {
                let body_entry = self.cfg.target(body_off)?;
                let target = self
                    .cfg
                    .for_targets
                    .get(&header)
                    .cloned()
                    .ok_or(IrError::Unstructurable)?;
                // The iterable was produced by GET_ITER in the loop's entry
                // predecessor, the one predecessor outside the loop body.
                let entry_pred = self
                    .preds
                    .get(&header)
                    .and_then(|preds| preds.iter().copied().find(|p| !body_set.contains(p)))
                    .ok_or(IrError::Unstructurable)?;
                let iter = self
                    .cfg
                    .block(entry_pred)
                    .stack_out
                    .last()
                    .copied()
                    .ok_or(IrError::Unstructurable)?;
                let body = self.loop_body(header, body_entry, follow, depth)?;
                Ok((Stmt::For { target, iter, body }, follow))
            }
            // A non-conditional header would be an infinite `while True`, which the
            // game's compiled code does not produce. Reject rather than guess.
            _ => Err(IrError::Unstructurable),
        }
    }

    /// Structures a loop body, dropping the back edge's trailing `continue`.
    fn loop_body(
        &mut self,
        header: BlockId,
        body_entry: BlockId,
        follow: Point,
        depth: usize,
    ) -> Result<Vec<Stmt>, IrError> {
        self.loop_stack.push(LoopFrame { header, follow });
        let mut body = self.region(body_entry, Point::Block(header), depth + 1)?;
        self.loop_stack.pop();
        if matches!(body.last(), Some(Stmt::Continue)) {
            body.pop();
        }
        Ok(body)
    }

    /// If `target` is the header or follow of the innermost active loop, returns the
    /// `continue`/`break` that jumping there represents.
    fn loop_edge(&self, target: BlockId) -> Option<Stmt> {
        let frame = self.loop_stack.last()?;
        if frame.follow == Point::Block(target) {
            Some(Stmt::Break)
        } else if frame.header == target {
            Some(Stmt::Continue)
        } else {
            None
        }
    }

    /// Whether `block` is the header of a loop currently being structured.
    fn in_current_loop(&self, block: BlockId) -> bool {
        self.loop_stack.iter().any(|frame| frame.header == block)
    }

    fn point_block(&self, point: Point) -> Option<BlockId> {
        match point {
            Point::Block(block) => Some(block),
            Point::Exit => None,
        }
    }
}

/// The forward graph (blocks plus a virtual exit) with cached dominators.
struct Graph {
    graph: DiGraph<(), ()>,
    exit: NodeIndex,
    forward: Dominators<NodeIndex>,
    post: Dominators<NodeIndex>,
    block_count: usize,
}

impl Graph {
    fn build(cfg: &Cfg) -> Graph {
        let mut graph = DiGraph::<(), ()>::new();
        let block_nodes: Vec<NodeIndex> =
            (0..cfg.blocks.len()).map(|_| graph.add_node(())).collect();
        let exit = graph.add_node(());

        for (idx, block) in cfg.blocks.iter().enumerate() {
            let from = block_nodes[idx];
            for target in block.successors() {
                match cfg.by_offset.get(&target) {
                    Some(to) => graph.add_edge(from, block_nodes[to.0 as usize], ()),
                    None => graph.add_edge(from, exit, ()),
                };
            }
            if block.successors().is_empty() {
                graph.add_edge(from, exit, ());
            }
        }

        let forward = simple_fast(&graph, block_nodes[cfg.entry.0 as usize]);
        let post = simple_fast(Reversed(&graph), exit);
        Graph {
            graph,
            exit,
            forward,
            post,
            block_count: cfg.blocks.len(),
        }
    }

    /// Whether `a` dominates `b` in the forward graph.
    fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        let target = NodeIndex::new(a.0 as usize);
        let mut current = Some(NodeIndex::new(b.0 as usize));
        while let Some(node) = current {
            if node == target {
                return true;
            }
            let next = self.forward.immediate_dominator(node);
            current = next.filter(|n| *n != node);
        }
        false
    }

    /// Finds loop headers (back-edge targets), their body sets, and follows.
    fn detect_loops(
        &self,
        cfg: &Cfg,
        preds: &HashMap<BlockId, Vec<BlockId>>,
    ) -> HashMap<BlockId, LoopInfo> {
        let mut headers: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let source = BlockId(idx as u32);
            for target in block.successors() {
                if let Some(&header) = cfg.by_offset.get(&target) {
                    if self.dominates(header, source) {
                        headers.entry(header).or_default().push(source);
                    }
                }
            }
        }

        let mut loops = HashMap::new();
        for (header, latches) in headers {
            let body = natural_loop(header, &latches, preds);
            let follow = self.loop_follow(cfg, header, &body);
            loops.insert(header, LoopInfo { body, follow });
        }
        loops
    }

    /// The block the loop exits to: the unique header successor outside the body.
    fn loop_follow(&self, cfg: &Cfg, header: BlockId, body: &HashSet<BlockId>) -> Point {
        for target in cfg.blocks[header.0 as usize].successors() {
            match cfg.by_offset.get(&target) {
                Some(succ) if !body.contains(succ) => return Point::Block(*succ),
                None => return Point::Exit,
                _ => {}
            }
        }
        Point::Exit
    }

    /// The immediate post-dominator of a block, used as a conditional's merge point.
    fn immediate_postdom(&self, block: BlockId) -> Point {
        let node = NodeIndex::new(block.0 as usize);
        match self.post.immediate_dominator(node) {
            Some(idom) if idom != self.exit && idom.index() < self.block_count => {
                Point::Block(BlockId(idom.index() as u32))
            }
            _ => Point::Exit,
        }
    }
}

/// The natural loop of a set of latches branching back to `header`: the header
/// plus every node that reaches a latch without passing through the header.
fn natural_loop(
    header: BlockId,
    latches: &[BlockId],
    preds: &HashMap<BlockId, Vec<BlockId>>,
) -> HashSet<BlockId> {
    let mut body = HashSet::new();
    body.insert(header);
    let mut stack: Vec<BlockId> = latches.to_vec();
    while let Some(node) = stack.pop() {
        if body.insert(node) {
            if let Some(node_preds) = preds.get(&node) {
                stack.extend(node_preds.iter().copied());
            }
        }
    }
    body
}

/// Builds a predecessor map from the CFG terminators.
fn predecessors(cfg: &Cfg) -> HashMap<BlockId, Vec<BlockId>> {
    let mut preds: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for (idx, block) in cfg.blocks.iter().enumerate() {
        let source = BlockId(idx as u32);
        for target in block.successors() {
            if let Some(&succ) = cfg.by_offset.get(&target) {
                preds.entry(succ).or_default().push(source);
            }
        }
    }
    preds
}
