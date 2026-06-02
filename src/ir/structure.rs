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
use super::expr::{ExceptHandler, Stmt};
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
    let mut body = structurer.region(cfg.entry, Point::Exit, 0)?;
    cleanup(&mut body);
    Ok(body)
}

/// Tidies the structured body: recurse into children, drop unreachable statements
/// (anything after one that always transfers control), then strip the redundant
/// trailing `continue` a loop body falls through to.
fn cleanup(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If { then, els, .. } => {
                cleanup(then);
                cleanup(els);
            }
            Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::For { body, .. } => {
                cleanup(body);
                strip_tail_continue(body);
            }
            Stmt::Try { body, handlers } => {
                cleanup(body);
                for handler in handlers {
                    cleanup(&mut handler.body);
                }
            }
            Stmt::With { body, .. } => cleanup(body),
            Stmt::TryFinally { body, finalbody } => {
                cleanup(body);
                cleanup(finalbody);
            }
            _ => {}
        }
    }
    if let Some(pos) = stmts.iter().position(terminates) {
        stmts.truncate(pos + 1);
    }
}

/// Drops a redundant `continue` from the tail of a loop body: the last statement
/// if it is a bare `continue`, or recursively the tail of the arms of a trailing
/// compound statement that falls through to the loop's end -- an `if`, a `try`
/// (its body and each handler), or a `with`. After any of these, control reaches
/// the loop end and iterates anyway, so a trailing `continue` in an arm is
/// redundant. Nested loops are not descended into: a `continue` at their tail binds
/// to the inner loop. Runs after unreachable statements are pruned, so a trailing
/// dead `return` does not hide it.
fn strip_tail_continue(stmts: &mut Vec<Stmt>) {
    match stmts.last_mut() {
        Some(Stmt::Continue) => {
            stmts.pop();
        }
        Some(Stmt::If { then, els, .. }) => {
            strip_tail_continue(then);
            strip_tail_continue(els);
        }
        Some(Stmt::Try { body, handlers }) => {
            strip_tail_continue(body);
            for handler in handlers.iter_mut() {
                strip_tail_continue(&mut handler.body);
            }
        }
        Some(Stmt::With { body, .. }) => strip_tail_continue(body),
        _ => {}
    }
}

/// Whether a statement always transfers control, so nothing after it in the same
/// suite can run.
fn terminates(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise(_) => true,
        // An if terminates only when it has both arms and each one does.
        Stmt::If { then, els, .. } => {
            !then.is_empty()
                && !els.is_empty()
                && then.last().is_some_and(terminates)
                && els.last().is_some_and(terminates)
        }
        _ => false,
    }
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

            // A cursor that lands on the innermost active loop's own header is a
            // `continue` of that loop, not a re-entry into the header block. This
            // happens when the region's `stop` is not the header -- e.g. an `if` inside
            // the loop whose other arm returns has the function exit as its
            // post-dominator, so this arm's region runs with `stop == Exit` -- and
            // control then flows back to the header. Without this the header's
            // ForIter/while terminator is emitted as a plain block and rejected. (The
            // `stop == header` case is the normal loop-body end, already handled above.)
            if self.loop_stack.last().is_some_and(|frame| frame.header == current) {
                out.push(Stmt::Continue);
                break;
            }

            // A block that could not be lowered is reachable here, so the function
            // genuinely needs it; surface the error that poisoned it. (Opaque-dead
            // poison blocks are never reached.)
            if let Some(error) = &self.cfg.block(current).poison {
                return Err(error.clone());
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
                Terminator::Try { body, handlers, end } => {
                    // A merge-less try (`end` is `None`) has no merge of its own: the
                    // body always raises or returns, so any merge is reached only
                    // through a handler that falls through. Such a handler continues to
                    // wherever the enclosing region continues, so its arm follows the
                    // enclosing `stop` rather than the function exit. Following the exit
                    // would absorb code past the enclosing boundary -- e.g. the cleanup
                    // of an enclosing try/finally that the fall-through path shares --
                    // into the arm, where the finally structurer also emits it (double
                    // execution). Bounding at `stop` keeps that shared code outside.
                    let follow = match end {
                        Some(end) => Point::Block(self.cfg.target(*end)?),
                        None => stop,
                    };
                    let try_body = self.region(self.cfg.target(*body)?, follow, depth + 1)?;
                    let mut arms = Vec::with_capacity(handlers.len());
                    for handler in handlers {
                        let arm_body = self.region(self.cfg.target(handler.body)?, follow, depth + 1)?;
                        arms.push(ExceptHandler {
                            exc_type: handler.exc_type,
                            name: handler.name.clone(),
                            body: arm_body,
                        });
                    }
                    // The body of a merge-less try must terminate: its missing POP_BLOCK
                    // means it has no normal exit. If that does not hold (e.g. a nested
                    // merge-less try miscounted the block depth), reject rather than
                    // mis-structure.
                    if end.is_none() && !try_body.last().is_some_and(terminates) {
                        return Err(IrError::Unstructurable);
                    }
                    out.push(Stmt::Try { body: try_body, handlers: arms });
                    cursor = self.point_block(follow);
                }
                Terminator::With { body, end, target } => {
                    // The context manager is the value the block left on its stack
                    // before SETUP_WITH (it is not consumed by the terminator).
                    let context = self
                        .cfg
                        .block(current)
                        .stack_out
                        .last()
                        .copied()
                        .ok_or(IrError::Unstructurable)?;
                    let target = target.clone();
                    let follow = Point::Block(self.cfg.target(*end)?);
                    let with_body = self.region(self.cfg.target(*body)?, follow, depth + 1)?;
                    out.push(Stmt::With { context, target, body: with_body });
                    cursor = self.point_block(follow);
                }
                Terminator::Finally { body, finalbody, end } => {
                    let follow = Point::Block(self.cfg.target(*end)?);
                    let final_at = Point::Block(self.cfg.target(*finalbody)?);
                    // The protected body converges at the finally clause; the clause
                    // then converges at the merge.
                    let try_body = self.region(self.cfg.target(*body)?, final_at, depth + 1)?;
                    let final_body = self.region(self.cfg.target(*finalbody)?, follow, depth + 1)?;
                    out.push(Stmt::TryFinally { body: try_body, finalbody: final_body });
                    cursor = self.point_block(follow);
                }
                // A ForIter block is always a loop header and is handled by the loop
                // check above (including the synthesized no-back-edge case); reaching it
                // here means even that synthesis did not register it -- e.g. its FOR_ITER
                // target was not a block leader. Reject rather than mis-structure.
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
            // A non-conditional header reached by a back edge is `while True:`: the
            // loop has no condition test at the header and exits only via
            // break/return/raise. Its follow is the break target -- the one block a
            // body block reaches outside the loop -- not the header's own successors,
            // which are all in-body, so recompute it from the body.
            _ => {
                let follow = self.infinite_loop_follow(&body_set);
                let body = self.infinite_loop_body(header, follow, depth)?;
                Ok((Stmt::Loop { body }, follow))
            }
        }
    }

    /// The follow of a `while True:` loop: the block a body block reaches outside the
    /// loop (the `break` target / the SETUP_LOOP exit). A truly infinite loop with no
    /// break has none, so control continues at the function exit. Picks the smallest
    /// such block id for determinism; a well-formed loop has exactly one.
    fn infinite_loop_follow(&self, body_set: &HashSet<BlockId>) -> Point {
        let mut exits: Vec<BlockId> = Vec::new();
        for &block in body_set {
            for target in self.cfg.block(block).successors() {
                if let Some(&succ) = self.cfg.by_offset.get(&target) {
                    if !body_set.contains(&succ) {
                        exits.push(succ);
                    }
                }
            }
        }
        match exits.into_iter().min() {
            Some(block) => Point::Block(block),
            None => Point::Exit,
        }
    }

    /// Structures the body of a `while True:` loop. The header is the first body block
    /// (unlike a conditional/for loop, where the header is a branch and the body a
    /// separate block), so its statements are emitted directly and the rest of the body
    /// is structured up to the back edge. A trailing `continue` the body falls through
    /// to is dropped.
    fn infinite_loop_body(
        &mut self,
        header: BlockId,
        follow: Point,
        depth: usize,
    ) -> Result<Vec<Stmt>, IrError> {
        self.loop_stack.push(LoopFrame { header, follow });
        let outcome = self.infinite_loop_body_inner(header, depth);
        self.loop_stack.pop();
        let mut body = outcome?;
        if matches!(body.last(), Some(Stmt::Continue)) {
            body.pop();
        }
        // An empty body would emit `while True: pass`. A genuine infinite loop always
        // has work in it; an empty one means the real body and its break collapsed --
        // a break mis-resolved to a block inside the loop (an optimized `while 1:
        // break`, or urlparse's segment-removal loops whose POP_BLOCK exit the deob
        // stripped). Reject so the function fails rather than emitting an infinite loop
        // that silently drops the break.
        if body.is_empty() {
            return Err(IrError::Unstructurable);
        }
        Ok(body)
    }

    fn infinite_loop_body_inner(
        &mut self,
        header: BlockId,
        depth: usize,
    ) -> Result<Vec<Stmt>, IrError> {
        let mut body = self.cfg.block(header).stmts.clone();
        // The header's terminator leads back into the loop. Only a plain edge is the
        // `while True:` shape; a conditional or for header is handled above, and a
        // try/with/finally at the header is a shape this does not yet recover.
        let cont = match &self.cfg.block(header).terminator {
            Terminator::Jump(target) | Terminator::Fallthrough(target) => self.cfg.target(*target)?,
            _ => return Err(IrError::Unstructurable),
        };
        if cont == header {
            // The header jumps straight back to itself: the whole body is the header.
        } else if let Some(stmt) = self.loop_edge(cont) {
            body.push(stmt);
        } else {
            let rest = self.region(cont, Point::Block(header), depth + 1)?;
            body.extend(rest);
        }
        Ok(body)
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

        // Post-dominance is computed over normal control flow only, so a try's merge
        // point post-dominates the try even when a handler returns or raises (an
        // exceptional edge would otherwise route to the exit and defeat the merge).
        // The node layout matches `graph` (blocks 0..n, then exit), so post-dominator
        // indices map back to the same blocks.
        let mut normal = DiGraph::<(), ()>::new();
        let normal_nodes: Vec<NodeIndex> =
            (0..cfg.blocks.len()).map(|_| normal.add_node(())).collect();
        let normal_exit = normal.add_node(());
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let from = normal_nodes[idx];
            let successors = block.normal_successors();
            for target in &successors {
                match cfg.by_offset.get(target) {
                    Some(to) => normal.add_edge(from, normal_nodes[to.0 as usize], ()),
                    None => normal.add_edge(from, normal_exit, ()),
                };
            }
            if successors.is_empty() {
                normal.add_edge(from, normal_exit, ());
            }
        }

        let forward = simple_fast(&graph, block_nodes[cfg.entry.0 as usize]);
        let post = simple_fast(Reversed(&normal), normal_exit);
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

        // A FOR_ITER is always a loop header, but a body that always returns, raises,
        // or breaks leaves no back edge, so the dominator scan above never registers
        // it. Synthesize the loop straight from the terminator: the `body` successor
        // is the loop body, the `exit` successor its follow. Such a loop runs its body
        // at most once, but it is still a `for` statement; without this it reaches
        // region() as a bare ForIter and is rejected as unstructurable. Detected loops
        // are left untouched, so this only ever turns a failure into a recovery.
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let header = BlockId(idx as u32);
            if loops.contains_key(&header) {
                continue;
            }
            if let Terminator::ForIter { body: body_off, exit } = &block.terminator {
                let follow = match cfg.by_offset.get(exit) {
                    Some(&follow_block) => Point::Block(follow_block),
                    None => Point::Exit,
                };
                let Some(&body_entry) = cfg.by_offset.get(body_off) else {
                    continue;
                };
                let follow_block = match follow {
                    Point::Block(block) => Some(block),
                    Point::Exit => None,
                };
                let body = forward_body(cfg, header, body_entry, follow_block);
                loops.insert(header, LoopInfo { body, follow });
            }
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

/// The body of a back-edge-less `FOR_ITER` loop: the header plus every block
/// forward-reachable from `body_entry` without passing through the loop's `follow`
/// (the FOR_ITER exit) or re-entering the header. A break edge targets `follow`, so
/// excluding it keeps the post-loop code out of the body.
fn forward_body(
    cfg: &Cfg,
    header: BlockId,
    body_entry: BlockId,
    follow_block: Option<BlockId>,
) -> HashSet<BlockId> {
    let mut body = HashSet::new();
    body.insert(header);
    let mut stack = vec![body_entry];
    while let Some(node) = stack.pop() {
        if node == header || Some(node) == follow_block {
            continue;
        }
        if body.insert(node) {
            for target in cfg.blocks[node.0 as usize].successors() {
                if let Some(&succ) = cfg.by_offset.get(&target) {
                    stack.push(succ);
                }
            }
        }
    }
    body
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
