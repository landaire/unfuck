//! A general structural-analysis structurer, used only as a *verified fallback* when
//! the primary region-walk ([`super::structure::structure`]) cannot reduce a control-flow
//! graph.
//!
//! The primary structurer is a recursive forward walk tuned to the deobfuscator's block
//! layout; it bails ([`IrError::Unstructurable`]) on shapes whose loops do not nest
//! cleanly -- most often a loop whose `break` target differs from the loop header's own
//! exit (a `for ... else`, or a relinearized loop), which makes a break arm walk past the
//! loop into an enclosing loop's header.
//!
//! This module recomputes loop follows from the *convergence of every edge that leaves
//! the loop body* (with a `break` going to its terminator's `follow`), so the follow is
//! correct regardless of layout, and resolves `break`/`continue` against the innermost
//! loop only. It builds a block-id-tagged [`Region`] tree, then **independently
//! re-derives the control-flow edges implied by that tree and checks them against the
//! immutable CFG** ([`Analyzer::verify`]): every reachable block must appear exactly once
//! and its derived successors (with the same true/false and for-body/for-exit labels the
//! CFG carries) must match. Only on a full match is the tree lowered to statements;
//! otherwise the function returns `None` and the honest failure stands. Because it runs
//! solely on a prior failure and self-verifies, it can only turn a failure into a
//! recovery, never change an object the primary path already handles.
//!
//! Scope: blocks whose terminators are `Fallthrough`/`Jump`/`CondBranch`/`Return`/`Raise`/
//! `Break`/`ForIter`. A `Try`/`With`/`Finally` terminator, an irreducible back edge, or
//! any shape it cannot prove makes the whole attempt return `None`.

use std::collections::{HashMap, HashSet};

use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::graph::{DiGraph, NodeIndex};

use super::cfg::{BlockId, Cfg, Terminator};
use super::expr::{ExceptHandler, LValue, Stmt, ValueId};

/// A control-flow destination: a block, or the function exit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Dest {
    Block(BlockId),
    Exit,
}

/// The label on a control-flow edge, so the verifier matches the true arm of a branch
/// against the true arm and not merely "some successor".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Edge {
    Seq,
    True,
    False,
    ForBody,
    ForExit,
    /// The `try` block's edge to its protected body.
    TryBody,
    /// The `try` block's edge to one `except` handler.
    TryHandler,
}

/// A recovered region of the CFG, tagged with the blocks it covers so the result can be
/// verified against the graph before it is trusted.
enum Region {
    /// A block's straight-line statements; its terminator's transfer is realized by the
    /// surrounding region (a plain edge to the sequence continuation, or `Return`/`Raise`).
    Linear(BlockId),
    Seq(Vec<Region>),
    /// A two-way branch headed by a `CondBranch` block.
    If {
        header: BlockId,
        then: Box<Region>,
        els: Box<Region>,
    },
    /// A `for` loop headed by a `ForIter` block. `els` is the `for ... else` clause (the
    /// region at the `FOR_ITER` exit, before the real follow); empty when there is none.
    ForLoop {
        header: BlockId,
        body: Box<Region>,
        els: Vec<Region>,
        follow: Option<BlockId>,
    },
    /// A `while cond:` loop headed by a pure `CondBranch` test block. `els` is the
    /// `while ... else` clause (the region the exit arm runs before the real follow, which
    /// `break` skips); empty when there is none.
    WhileLoop {
        header: BlockId,
        negated: bool,
        body: Box<Region>,
        els: Vec<Region>,
        follow: Option<BlockId>,
    },
    /// A `while True:` loop: the header is the first block of `body` (processed inline),
    /// and the loop is left only by `break`/`return`/`raise`.
    InfLoop {
        header: BlockId,
        body: Box<Region>,
        follow: Option<BlockId>,
    },
    /// A `try`/`except` region headed by a `SETUP_EXCEPT` block. The body and every
    /// handler converge at `follow` (the merge); `follow` is `None` for a merge-less try
    /// (the body always exits, so a handler that falls through continues to the enclosing
    /// region's stop).
    Try {
        header: BlockId,
        body: Box<Region>,
        handlers: Vec<TryHandler>,
        follow: Option<BlockId>,
    },
    Break,
    Continue,
    Empty,
}

/// One recovered `except` clause within a [`Region::Try`].
struct TryHandler {
    exc_type: Option<ValueId>,
    name: Option<LValue>,
    body: Region,
}

/// The kind and resolved shape of a natural loop.
struct LoopShape {
    body: HashSet<BlockId>,
    kind: LoopKind,
    /// Where control goes when the loop is left (the unique convergence of every edge
    /// leaving the body). `None` for a loop left only by `return`/`raise`.
    follow: Option<BlockId>,
    /// The block the loop body begins at (the `FOR_ITER` body, the in-body arm of a
    /// `while` test, or the header itself for an infinite loop).
    body_entry: BlockId,
    /// For a `for ... else`, the block the else clause begins at (the `FOR_ITER` exit).
    else_start: Option<BlockId>,
}

enum LoopKind {
    Infinite,
    While { negated: bool },
    For,
}

/// A loop currently being structured, for resolving `break`/`continue`.
#[derive(Clone, Copy)]
struct Frame {
    header: BlockId,
    follow: Option<BlockId>,
}

const MAX_DEPTH: usize = 400;

/// Structures `cfg` with general structural analysis, or returns `None` if it cannot
/// prove the result faithful. Intended only as a fallback after the primary structurer
/// has failed.
pub fn structure(cfg: &Cfg) -> Option<Vec<Stmt>> {
    let analyzer = Analyzer::build(cfg)?;
    let mut frames: Vec<Frame> = Vec::new();
    let region = analyzer.build_region(cfg.entry, None, &mut frames, 0)?;
    analyzer.verify(&region)?;
    let mut body = analyzer.lower(&region);
    super::structure::cleanup(&mut body);
    Some(body)
}

struct Analyzer<'a> {
    cfg: &'a Cfg,
    loops: HashMap<BlockId, LoopShape>,
    /// Forward dominators, for classifying back edges and ordering nested loops.
    dom: Dominators<NodeIndex>,
    /// Blocks reachable from the entry (over CFG-graph edges).
    reachable: HashSet<BlockId>,
    /// Immediate post-dominators (over normal edges), for choosing branch merges.
    postdom: Dominators<NodeIndex>,
    exit_node: NodeIndex,
    block_count: usize,
}

impl<'a> Analyzer<'a> {
    fn build(cfg: &'a Cfg) -> Option<Analyzer<'a>> {
        // Only the plain control-flow terminators are in scope; a Try/With/Finally is left
        // to the primary structurer (and its absence here keeps the graph model simple).
        for block in &cfg.blocks {
            match block.terminator {
                Terminator::Fallthrough(_)
                | Terminator::Jump(_)
                | Terminator::CondBranch { .. }
                | Terminator::Return(_)
                | Terminator::Raise(_)
                | Terminator::Break { .. }
                | Terminator::ForIter { .. }
                | Terminator::Try { .. } => {}
                // `With`/`Finally` are not yet handled by this fallback.
                _ => return None,
            }
        }

        let mut graph = DiGraph::<(), ()>::new();
        let nodes: Vec<NodeIndex> = (0..cfg.blocks.len()).map(|_| graph.add_node(())).collect();
        let exit_node = graph.add_node(());
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let from = nodes[idx];
            let succ = block.successors();
            if succ.is_empty() {
                graph.add_edge(from, exit_node, ());
            }
            for target in succ {
                match cfg.by_offset.get(&target) {
                    Some(to) => graph.add_edge(from, nodes[to.0 as usize], ()),
                    None => graph.add_edge(from, exit_node, ()),
                };
            }
        }
        let entry_node = nodes[cfg.entry.0 as usize];
        let dom = simple_fast(&graph, entry_node);

        // Post-dominators over SEMANTIC, normal edges: a `Break` reaches its `follow` (not
        // its in-loop `fallback`), so a loop's real merge -- reachable only via the break
        // targets -- post-dominates the blocks before it; and a try's merge post-dominates
        // the try even when a handler returns/raises (an exceptional edge would route to the
        // exit and defeat the merge). Without this the merge is unreachable on the graph
        // edges and the post-dominator collapses to the function exit, which makes branch
        // merges and loop follows wrong. The dominator graph above stays on the raw CFG
        // edges so loop bodies still include break-arm and trampoline blocks.
        let normal_semantic = |block: &super::cfg::Block| -> Vec<Dest> {
            match &block.terminator {
                // A try's handlers run only on an exception; normal flow is the body.
                Terminator::Try { body, .. } => vec![dest_of(cfg, *body)],
                Terminator::With { body, end, .. } => vec![dest_of(cfg, *body), dest_of(cfg, *end)],
                Terminator::Finally { body, finalbody, .. } => {
                    let mut v = vec![dest_of(cfg, *body)];
                    v.extend(finalbody.map(|fb| dest_of(cfg, fb)));
                    v
                }
                Terminator::Break { follow, .. } => vec![dest_of(cfg, *follow)],
                _ => block
                    .successors()
                    .iter()
                    .map(|o| dest_of(cfg, *o))
                    .collect(),
            }
        };
        let mut rev = DiGraph::<(), ()>::new();
        let rnodes: Vec<NodeIndex> = (0..cfg.blocks.len()).map(|_| rev.add_node(())).collect();
        let rexit = rev.add_node(());
        for (idx, block) in cfg.blocks.iter().enumerate() {
            let from = rnodes[idx];
            let succ = normal_semantic(block);
            if succ.is_empty() {
                rev.add_edge(from, rexit, ());
            }
            for d in succ {
                match d {
                    Dest::Block(to) => rev.add_edge(from, rnodes[to.0 as usize], ()),
                    Dest::Exit => rev.add_edge(from, rexit, ()),
                };
            }
        }
        let postdom = simple_fast(petgraph::visit::Reversed(&rev), rexit);

        let mut analyzer = Analyzer {
            cfg,
            loops: HashMap::new(),
            dom,
            reachable: HashSet::new(),
            postdom,
            exit_node,
            block_count: cfg.blocks.len(),
        };
        // Reachability over *semantic* edges (a `break` reaches its `follow`, not its
        // in-loop `fallback`), so a loop follow reached only by `break` counts as live
        // and the coverage check expects exactly the blocks that actually execute.
        let mut reachable = HashSet::new();
        let mut stack = vec![cfg.entry];
        while let Some(b) = stack.pop() {
            if !reachable.insert(b) {
                continue;
            }
            for (_, d) in analyzer.ground_truth(b) {
                if let Dest::Block(t) = d {
                    stack.push(t);
                }
            }
        }
        analyzer.reachable = reachable;
        analyzer.detect_loops()?;
        Some(analyzer)
    }

    /// Whether `a` dominates `b` in the forward graph.
    fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        let target = NodeIndex::new(a.0 as usize);
        let mut current = Some(NodeIndex::new(b.0 as usize));
        while let Some(node) = current {
            if node == target {
                return true;
            }
            let next = self.dom.immediate_dominator(node);
            current = next.filter(|n| *n != node);
        }
        false
    }

    /// Predecessors (over CFG-graph edges) of every block.
    fn predecessors(&self) -> HashMap<BlockId, Vec<BlockId>> {
        let mut preds: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (idx, block) in self.cfg.blocks.iter().enumerate() {
            let source = BlockId(idx as u32);
            for target in block.successors() {
                if let Some(&succ) = self.cfg.by_offset.get(&target) {
                    preds.entry(succ).or_default().push(source);
                }
            }
        }
        preds
    }

    /// The block a terminator offset resolves to, or `Exit`.
    fn dest(&self, offset: super::expr::Offset) -> Dest {
        match self.cfg.by_offset.get(&offset) {
            Some(&b) => Dest::Block(b),
            None => Dest::Exit,
        }
    }

    /// The *semantic* labelled successors of a block: a `Break` goes to its `follow`
    /// (where the emitted `break` lands), not its in-loop `fallback`. This is the ground
    /// truth the verifier checks the recovered structure against.
    fn ground_truth(&self, b: BlockId) -> Vec<(Edge, Dest)> {
        match &self.cfg.block(b).terminator {
            Terminator::Fallthrough(t) | Terminator::Jump(t) => vec![(Edge::Seq, self.dest(*t))],
            Terminator::Return(_) | Terminator::Raise(_) => vec![(Edge::Seq, Dest::Exit)],
            Terminator::Break { follow, .. } => vec![(Edge::Seq, self.dest(*follow))],
            Terminator::CondBranch { if_true, if_false, .. } => {
                vec![(Edge::True, self.dest(*if_true)), (Edge::False, self.dest(*if_false))]
            }
            Terminator::ForIter { body, exit } => {
                vec![(Edge::ForBody, self.dest(*body)), (Edge::ForExit, self.dest(*exit))]
            }
            Terminator::Try { body, handlers, .. } => {
                let mut edges = vec![(Edge::TryBody, self.dest(*body))];
                for h in handlers {
                    edges.push((Edge::TryHandler, self.dest(h.body)));
                }
                edges
            }
            // Out of scope; build() already rejected these.
            _ => vec![],
        }
    }

    /// The in-graph block successors of `b` (a `Break` uses its in-loop `fallback`, as the
    /// CFG graph does), for loop-body and reachability computations.
    fn graph_succ(&self, b: BlockId) -> Vec<BlockId> {
        self.cfg
            .block(b)
            .successors()
            .iter()
            .filter_map(|o| self.cfg.by_offset.get(o).copied())
            .collect()
    }

    fn detect_loops(&mut self) -> Option<()> {
        let preds = self.predecessors();
        // Reachability over the CFG GRAPH edges (a `Break` uses its in-loop `fallback`), so
        // a relinearizer trampoline reached only by a break's fallback -- the block that
        // actually carries the loop's back edge -- still counts as a latch. (Using the
        // semantic reachable set here would drop it and leave the loop body incomplete.)
        let graph_reachable = {
            let mut seen = HashSet::new();
            let mut stack = vec![self.cfg.entry];
            while let Some(b) = stack.pop() {
                if !seen.insert(b) {
                    continue;
                }
                stack.extend(self.graph_succ(b));
            }
            seen
        };
        // Headers are back-edge targets. A back edge whose target does not dominate its
        // source is irreducible -- reject the whole function.
        let mut headers: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (idx, block) in self.cfg.blocks.iter().enumerate() {
            let source = BlockId(idx as u32);
            if !graph_reachable.contains(&source) {
                continue;
            }
            for target in block.successors() {
                if let Some(&h) = self.cfg.by_offset.get(&target) {
                    // A retreating edge: target appears at or above source in the DFS. Use
                    // dominance: a back edge has the header dominating the latch.
                    if self.is_back_edge(source, h) {
                        if !self.dominates(h, source) {
                            return None; // irreducible
                        }
                        headers.entry(h).or_default().push(source);
                    }
                }
            }
        }

        let mut shapes = HashMap::new();
        for (header, latches) in &headers {
            let mut body = natural_loop(*header, latches, &preds);
            // Natural-loop walks predecessors, which can pull in unreachable junk blocks;
            // keep only reachable members (the header always stays).
            body.retain(|b| self.reachable.contains(b) || b == header);
            let shape = self.loop_shape(*header, body)?;
            shapes.insert(*header, shape);
        }

        // A FOR_ITER with no back edge (a body that always breaks/returns) is still a
        // `for` loop. Synthesize it from the terminator when the dominance scan missed it.
        for (idx, block) in self.cfg.blocks.iter().enumerate() {
            let header = BlockId(idx as u32);
            if !self.reachable.contains(&header) || shapes.contains_key(&header) {
                continue;
            }
            if let Terminator::ForIter { body: body_off, exit } = &block.terminator {
                let Some(&body_entry) = self.cfg.by_offset.get(body_off) else {
                    return None;
                };
                let exit_block = self.cfg.by_offset.get(exit).copied();
                let body = forward_loop_body(self.cfg, header, body_entry, exit_block);
                let shape = self.loop_shape(header, body)?;
                shapes.insert(header, shape);
            }
        }

        self.loops = shapes;
        Some(())
    }

    /// A back edge: an edge `source -> header` where `header` dominates `source` (so the
    /// edge retreats to an enclosing header). The entry is never a back-edge target from
    /// itself unless it truly self-loops.
    fn is_back_edge(&self, source: BlockId, header: BlockId) -> bool {
        self.dominates(header, source)
    }

    /// Every distinct block reached by a *semantic* edge leaving the body (a `break`
    /// reaches its `follow`). Used to find an infinite loop's follow by convergence.
    fn out_targets(&self, body: &HashSet<BlockId>) -> Vec<BlockId> {
        let mut out: Vec<BlockId> = Vec::new();
        for &b in body {
            for (_, d) in self.ground_truth(b) {
                if let Dest::Block(t) = d {
                    if !body.contains(&t) && !out.contains(&t) {
                        out.push(t);
                    }
                }
            }
        }
        out
    }

    /// Resolves a natural loop's kind, follow, body entry, and optional else clause, or
    /// `None` if the shape is one this structurer will not commit to. A `for`/`while`
    /// loop's follow is the header's immediate post-dominator (the unique block every
    /// path out of the loop converges on, regardless of how `break` arms are laid out);
    /// an infinite loop's follow is the convergence of the body's out-edges.
    fn loop_shape(&self, header: BlockId, body: HashSet<BlockId>) -> Option<LoopShape> {
        match &self.cfg.block(header).terminator {
            Terminator::ForIter { body: body_off, exit } => {
                let body_entry = self.cfg.by_offset.get(body_off).copied()?;
                let normal_exit = self.cfg.by_offset.get(exit).copied()?;
                // The follow is the post-dominator of the header; if the loop has no
                // normal exit at all (a body that always returns), it is the FOR_ITER exit.
                let follow = self.immediate_postdom(header).unwrap_or(normal_exit);
                // `for ... else`: the FOR_ITER exit reaches the follow through an else
                // region. With no breaks, the exit *is* the follow and there is no else.
                let else_start = if normal_exit != follow { Some(normal_exit) } else { None };
                Some(LoopShape {
                    body,
                    kind: LoopKind::For,
                    follow: Some(follow),
                    body_entry,
                    else_start,
                })
            }
            Terminator::CondBranch { if_true, if_false, .. } => {
                let t = self.cfg.by_offset.get(if_true).copied();
                let f = self.cfg.by_offset.get(if_false).copied();
                let t_in = t.is_some_and(|b| body.contains(&b));
                let f_in = f.is_some_and(|b| body.contains(&b));
                let pd = self.immediate_postdom(header);
                match (t_in, f_in) {
                    // A `while` test: one arm is the loop body, the other leaves the loop.
                    // The follow is the header's post-dominator (where the normal exit and
                    // every `break` converge). When the exit arm reaches the follow through
                    // a region rather than directly, that region is the `while ... else`
                    // clause; `break` skips it.
                    (true, false) => {
                        let exit_arm = f?;
                        let follow = pd.or(Some(exit_arm))?;
                        let else_start = if exit_arm != follow { Some(exit_arm) } else { None };
                        Some(LoopShape {
                            body,
                            kind: LoopKind::While { negated: false },
                            follow: Some(follow),
                            body_entry: t?,
                            else_start,
                        })
                    }
                    (false, true) => {
                        let exit_arm = t?;
                        let follow = pd.or(Some(exit_arm))?;
                        let else_start = if exit_arm != follow { Some(exit_arm) } else { None };
                        Some(LoopShape {
                            body,
                            kind: LoopKind::While { negated: true },
                            follow: Some(follow),
                            body_entry: f?,
                            else_start,
                        })
                    }
                    // Both arms stay in the loop: a `while True:` whose header begins the
                    // body and breaks from within. Its follow is the post-dominator, or the
                    // break convergence when the graph edges leave the follow unreachable.
                    (true, true) => {
                        let follow = match pd {
                            Some(p) if !body.contains(&p) => Some(p),
                            _ => self.converge(&self.out_targets(&body), &body)?,
                        };
                        Some(LoopShape {
                            body,
                            kind: LoopKind::Infinite,
                            follow,
                            body_entry: header,
                            else_start: None,
                        })
                    }
                    (false, false) => None,
                }
            }
            // A plain-edge header that is a loop header is an infinite loop beginning at it.
            Terminator::Fallthrough(_) | Terminator::Jump(_) | Terminator::Break { .. } => {
                let follow = self.converge(&self.out_targets(&body), &body)?;
                Some(LoopShape {
                    body,
                    kind: LoopKind::Infinite,
                    follow,
                    body_entry: header,
                    else_start: None,
                })
            }
            _ => None,
        }
    }

    /// The single block every out-target converges to: the one out-target reachable (over
    /// non-body blocks) from every other out-target. `None` if there are no out-targets
    /// (an exit-by-return loop). Returns `None` (bail) if there is no unique convergence.
    fn converge(&self, out_targets: &[BlockId], body: &HashSet<BlockId>) -> Option<Option<BlockId>> {
        if out_targets.is_empty() {
            return Some(None);
        }
        if out_targets.len() == 1 {
            return Some(Some(out_targets[0]));
        }
        // The follow is an out-target reachable from all out-targets without re-entering
        // the body, and which itself reaches no other out-target (the sink).
        let mut candidate = None;
        for &c in out_targets {
            let reached_by_all = out_targets
                .iter()
                .all(|&t| t == c || self.reaches_outside(t, c, body));
            let reaches_other = out_targets
                .iter()
                .any(|&t| t != c && self.reaches_outside(c, t, body));
            if reached_by_all && !reaches_other {
                if candidate.is_some() {
                    return None; // ambiguous
                }
                candidate = Some(c);
            }
        }
        candidate.map(Some)
    }

    /// Whether `target` is reachable from `from` without entering `body` (used to find a
    /// loop's convergence point among the blocks after it).
    fn reaches_outside(&self, from: BlockId, target: BlockId, body: &HashSet<BlockId>) -> bool {
        let mut stack = vec![from];
        let mut seen = HashSet::new();
        seen.insert(from);
        while let Some(b) = stack.pop() {
            for s in self.graph_succ(b) {
                if s == target {
                    return true;
                }
                if !body.contains(&s) && seen.insert(s) {
                    stack.push(s);
                }
            }
        }
        false
    }

    // ----- region construction -----

    /// Builds the region from `start` until control reaches the region's `stop` block (or
    /// a `break`/`continue`/return ends it). `frames` is the enclosing loop stack.
    fn build_region(
        &self,
        start: BlockId,
        stop: Option<BlockId>,
        frames: &mut Vec<Frame>,
        depth: usize,
    ) -> Option<Region> {
        if depth > MAX_DEPTH {
            return None;
        }
        let mut seq: Vec<Region> = Vec::new();
        let mut cursor = Some(start);
        let mut visited: HashSet<BlockId> = HashSet::new();
        let mut first = true;
        while let Some(cur) = cursor {
            if Some(cur) == stop {
                break;
            }
            if !first {
                if let Some(frame) = frames.last() {
                    if frame.header == cur {
                        seq.push(Region::Continue);
                        break;
                    }
                    if frame.follow == Some(cur) {
                        seq.push(Region::Break);
                        break;
                    }
                }
            }
            first = false;
            if !visited.insert(cur) {
                return None;
            }
            if self.cfg.block(cur).poison.is_some() {
                return None;
            }

            // Entering a new (not-yet-open) loop.
            if self.loops.contains_key(&cur) && !frames.iter().any(|f| f.header == cur) {
                let (region, follow) = self.build_loop(cur, frames, depth)?;
                seq.push(region);
                match follow {
                    Some(f) => cursor = Some(f),
                    None => {
                        cursor = None;
                    }
                }
                continue;
            }

            match &self.cfg.block(cur).terminator {
                Terminator::Return(_) | Terminator::Raise(_) => {
                    seq.push(Region::Linear(cur));
                    cursor = None;
                }
                Terminator::Fallthrough(t) | Terminator::Jump(t) => {
                    seq.push(Region::Linear(cur));
                    cursor = self.cfg.by_offset.get(t).copied();
                    if cursor.is_none() {
                        // A plain edge to the function exit: nothing follows.
                        break;
                    }
                }
                Terminator::Break { follow, .. } => {
                    // The block runs, then breaks out of the innermost loop. Its `follow`
                    // must be that loop's follow, or the emitted `break` would be wrong.
                    let follow_block = self.cfg.by_offset.get(follow).copied();
                    if frames.last().map(|f| f.follow) != Some(follow_block) {
                        return None;
                    }
                    seq.push(Region::Linear(cur));
                    seq.push(Region::Break);
                    cursor = None;
                }
                Terminator::CondBranch { if_true, if_false, .. } => {
                    let true_block = self.cfg.by_offset.get(if_true).copied();
                    let false_block = self.cfg.by_offset.get(if_false).copied();
                    let merge = self.branch_merge(cur, stop, frames);
                    let then = self.build_arm(true_block, merge, frames, depth)?;
                    let els = self.build_arm(false_block, merge, frames, depth)?;
                    let both_terminate = region_terminates(&then) && region_terminates(&els);
                    seq.push(Region::If {
                        header: cur,
                        then: Box::new(then),
                        els: Box::new(els),
                    });
                    cursor = if both_terminate { None } else { merge };
                }
                Terminator::Try { body, handlers, end } => {
                    // The body and every handler converge at `end` (the merge). A
                    // merge-less try (`end` None) has no merge: the body always exits, so a
                    // handler that falls through continues to the enclosing region's stop.
                    let body_off = *body;
                    let handlers = handlers.clone();
                    let end = *end;
                    let follow = match end {
                        Some(e) => Some(self.cfg.by_offset.get(&e).copied()?),
                        None => stop,
                    };
                    let body_entry = self.cfg.by_offset.get(&body_off).copied()?;
                    let body_region = self.build_region(body_entry, follow, frames, depth + 1)?;
                    // A merge-less try's body must terminate (no normal exit), or the
                    // recovery would be wrong; reject otherwise.
                    if end.is_none() && !region_terminates(&body_region) {
                        return None;
                    }
                    let mut arms = Vec::with_capacity(handlers.len());
                    for h in &handlers {
                        let hb = self.cfg.by_offset.get(&h.body).copied()?;
                        let arm = self.build_region(hb, follow, frames, depth + 1)?;
                        arms.push(TryHandler {
                            exc_type: h.exc_type,
                            name: h.name.clone(),
                            body: arm,
                        });
                    }
                    seq.push(Region::Try {
                        header: cur,
                        body: Box::new(body_region),
                        handlers: arms,
                        follow,
                    });
                    cursor = follow;
                    if cursor.is_none() {
                        break;
                    }
                }
                // A ForIter is always a loop header, handled by the loop check above.
                Terminator::ForIter { .. } => return None,
                _ => return None,
            }
        }
        Some(Region::Seq(seq))
    }

    /// One arm of a branch: empty if it is the merge, a `break`/`continue` if it is an
    /// edge straight to the innermost loop's follow/header, otherwise a sub-region.
    fn build_arm(
        &self,
        entry: Option<BlockId>,
        merge: Option<BlockId>,
        frames: &mut Vec<Frame>,
        depth: usize,
    ) -> Option<Region> {
        let Some(entry) = entry else {
            // An arm that branches to the function exit: a bare region that returns is not
            // expressible as a CondBranch arm here. Reject.
            return None;
        };
        if Some(entry) == merge {
            return Some(Region::Empty);
        }
        if let Some(frame) = frames.last() {
            if frame.header == entry {
                return Some(Region::Continue);
            }
            if frame.follow == Some(entry) {
                return Some(Region::Break);
            }
        }
        self.build_region(entry, merge, frames, depth + 1)
    }

    /// The merge block where a branch's arms reconverge: the immediate post-dominator,
    /// falling back to the enclosing region's `stop` when the branch has no merge of its
    /// own (an arm returns/breaks so the post-dominator is the function exit).
    fn branch_merge(
        &self,
        header: BlockId,
        stop: Option<BlockId>,
        frames: &[Frame],
    ) -> Option<BlockId> {
        match self.immediate_postdom(header) {
            Some(pd) => {
                // A post-dominator that is an enclosing loop's header/follow is not a real
                // in-region merge; bound at the enclosing stop instead.
                if frames
                    .iter()
                    .any(|f| f.header == pd || f.follow == Some(pd))
                {
                    stop
                } else {
                    Some(pd)
                }
            }
            None => stop,
        }
    }

    fn immediate_postdom(&self, block: BlockId) -> Option<BlockId> {
        let node = NodeIndex::new(block.0 as usize);
        match self.postdom.immediate_dominator(node) {
            Some(idom) if idom != self.exit_node && idom.index() < self.block_count => {
                Some(BlockId(idom.index() as u32))
            }
            _ => None,
        }
    }

    /// Builds the loop headed at `header`, returning the region and the block control
    /// resumes at afterwards (the follow).
    fn build_loop(
        &self,
        header: BlockId,
        frames: &mut Vec<Frame>,
        depth: usize,
    ) -> Option<(Region, Option<BlockId>)> {
        let shape = self.loops.get(&header)?;
        let follow = shape.follow;
        frames.push(Frame { header, follow });
        let body = self.build_region(shape.body_entry, None, frames, depth + 1);
        frames.pop();
        let mut body = body?;
        strip_trailing_continue(&mut body);

        let region = match shape.kind {
            LoopKind::For => {
                let els = match shape.else_start {
                    Some(start) => {
                        let els = self.build_region(start, follow, frames, depth + 1)?;
                        flatten(els)
                    }
                    None => Vec::new(),
                };
                Region::ForLoop {
                    header,
                    body: Box::new(body),
                    els,
                    follow,
                }
            }
            LoopKind::While { negated } => {
                let els = match shape.else_start {
                    Some(start) => flatten(self.build_region(start, follow, frames, depth + 1)?),
                    None => Vec::new(),
                };
                Region::WhileLoop {
                    header,
                    negated,
                    body: Box::new(body),
                    els,
                    follow,
                }
            }
            LoopKind::Infinite => Region::InfLoop {
                header,
                body: Box::new(body),
                follow,
            },
        };
        Some((region, follow))
    }

    // ----- verification -----

    /// Re-derives the control-flow edges the recovered region implies and checks them
    /// against the CFG ground truth. Returns `None` on any mismatch or missing/extra
    /// block, so a structurally wrong recovery is never trusted.
    fn verify(&self, region: &Region) -> Option<()> {
        let mut derived: HashMap<BlockId, Vec<(Edge, Dest)>> = HashMap::new();
        let mut frames: Vec<Frame> = Vec::new();
        self.simulate(region, Dest::Exit, &mut frames, &mut derived)?;

        // Coverage: exactly the reachable blocks, each once, each matching ground truth.
        if derived.len() != self.reachable.len() {
            return None;
        }
        for &b in &self.reachable {
            let mut got = derived.get(&b)?.clone();
            let mut want = self.ground_truth(b);
            got.sort_by_key(|(e, d)| (edge_key(*e), dest_key(*d)));
            want.sort_by_key(|(e, d)| (edge_key(*e), dest_key(*d)));
            if got != want {
                return None;
            }
        }
        Some(())
    }

    /// Records the edges `region` implies, with `cont` the destination after it.
    fn simulate(
        &self,
        region: &Region,
        cont: Dest,
        frames: &mut Vec<Frame>,
        derived: &mut HashMap<BlockId, Vec<(Edge, Dest)>>,
    ) -> Option<()> {
        match region {
            Region::Empty | Region::Break | Region::Continue => Some(()),
            Region::Linear(b) => {
                let edges = match &self.cfg.block(*b).terminator {
                    Terminator::Return(_) | Terminator::Raise(_) => vec![(Edge::Seq, Dest::Exit)],
                    Terminator::Fallthrough(_) | Terminator::Jump(_) | Terminator::Break { .. } => {
                        vec![(Edge::Seq, cont)]
                    }
                    // A CondBranch/ForIter must be an If/loop node, never Linear.
                    _ => return None,
                };
                if derived.insert(*b, edges).is_some() {
                    return None; // block emitted twice
                }
                Some(())
            }
            Region::Seq(items) => {
                for (i, item) in items.iter().enumerate() {
                    let next = if i + 1 < items.len() {
                        self.entry_dest(&items[i + 1..], cont, frames)?
                    } else {
                        cont
                    };
                    self.simulate(item, next, frames, derived)?;
                }
                Some(())
            }
            Region::If { header, then, els } => {
                let t = self.entry_dest(std::slice::from_ref(then.as_ref()), cont, frames)?;
                let f = self.entry_dest(std::slice::from_ref(els.as_ref()), cont, frames)?;
                if derived.insert(*header, vec![(Edge::True, t), (Edge::False, f)]).is_some() {
                    return None;
                }
                self.simulate(then, cont, frames, derived)?;
                self.simulate(els, cont, frames, derived)?;
                Some(())
            }
            Region::ForLoop { header, body, els, follow } => {
                let after = cont;
                let exit_dest = if els.is_empty() {
                    after
                } else {
                    self.entry_dest(els, after, frames)?
                };
                let body_dest = {
                    frames.push(Frame { header: *header, follow: *follow });
                    let d = self.entry_dest(std::slice::from_ref(body.as_ref()), Dest::Block(*header), frames);
                    frames.pop();
                    d?
                };
                if derived
                    .insert(*header, vec![(Edge::ForBody, body_dest), (Edge::ForExit, exit_dest)])
                    .is_some()
                {
                    return None;
                }
                frames.push(Frame { header: *header, follow: *follow });
                self.simulate(body, Dest::Block(*header), frames, derived)?;
                frames.pop();
                for (i, item) in els.iter().enumerate() {
                    let next = if i + 1 < els.len() {
                        self.entry_dest(&els[i + 1..], after, frames)?
                    } else {
                        after
                    };
                    self.simulate(item, next, frames, derived)?;
                }
                Some(())
            }
            Region::WhileLoop { header, negated, body, els, follow } => {
                let after = cont;
                let exit_dest = if els.is_empty() {
                    after
                } else {
                    self.entry_dest(els, after, frames)?
                };
                let body_dest = {
                    frames.push(Frame { header: *header, follow: *follow });
                    let d = self.entry_dest(std::slice::from_ref(body.as_ref()), Dest::Block(*header), frames);
                    frames.pop();
                    d?
                };
                let edges = if *negated {
                    vec![(Edge::True, exit_dest), (Edge::False, body_dest)]
                } else {
                    vec![(Edge::True, body_dest), (Edge::False, exit_dest)]
                };
                if derived.insert(*header, edges).is_some() {
                    return None;
                }
                frames.push(Frame { header: *header, follow: *follow });
                self.simulate(body, Dest::Block(*header), frames, derived)?;
                frames.pop();
                for (i, item) in els.iter().enumerate() {
                    let next = if i + 1 < els.len() {
                        self.entry_dest(&els[i + 1..], after, frames)?
                    } else {
                        after
                    };
                    self.simulate(item, next, frames, derived)?;
                }
                Some(())
            }
            Region::InfLoop { header, body, follow } => {
                frames.push(Frame { header: *header, follow: *follow });
                let r = self.simulate(body, Dest::Block(*header), frames, derived);
                frames.pop();
                r
            }
            Region::Try { header, body, handlers, follow } => {
                // The body and handlers converge at the merge (`follow`); a merge-less try
                // continues to `cont` (the enclosing continuation).
                let after = match follow {
                    Some(b) => Dest::Block(*b),
                    None => cont,
                };
                let mut edges =
                    vec![(Edge::TryBody, self.entry_dest(std::slice::from_ref(body.as_ref()), after, frames)?)];
                for h in handlers {
                    edges.push((
                        Edge::TryHandler,
                        self.entry_dest(std::slice::from_ref(&h.body), after, frames)?,
                    ));
                }
                if derived.insert(*header, edges).is_some() {
                    return None;
                }
                self.simulate(body, after, frames, derived)?;
                for h in handlers {
                    self.simulate(&h.body, after, frames, derived)?;
                }
                Some(())
            }
        }
    }

    /// The first concrete destination a sequence of regions transfers control to.
    fn entry_dest(&self, items: &[Region], cont: Dest, frames: &[Frame]) -> Option<Dest> {
        for item in items {
            match item {
                Region::Empty => continue,
                Region::Break => return Some(self.frame_follow(frames)?),
                Region::Continue => return Some(Dest::Block(frames.last()?.header)),
                Region::Linear(b)
                | Region::If { header: b, .. }
                | Region::ForLoop { header: b, .. }
                | Region::WhileLoop { header: b, .. }
                | Region::InfLoop { header: b, .. }
                | Region::Try { header: b, .. } => return Some(Dest::Block(*b)),
                Region::Seq(inner) => {
                    let d = self.entry_dest(inner, cont, frames)?;
                    // An all-empty inner sequence falls through to the next item.
                    if let Dest::Block(_) = d {
                        return Some(d);
                    }
                    if !inner.iter().all(is_empty_region) {
                        return Some(d);
                    }
                }
            }
        }
        Some(cont)
    }

    fn frame_follow(&self, frames: &[Frame]) -> Option<Dest> {
        match frames.last()?.follow {
            Some(b) => Some(Dest::Block(b)),
            None => None,
        }
    }

    // ----- lowering -----

    fn lower(&self, region: &Region) -> Vec<Stmt> {
        let mut out = Vec::new();
        self.lower_into(region, &mut out);
        out
    }

    fn lower_into(&self, region: &Region, out: &mut Vec<Stmt>) {
        match region {
            Region::Empty => {}
            Region::Break => out.push(Stmt::Break),
            Region::Continue => out.push(Stmt::Continue),
            Region::Linear(b) => {
                out.extend(self.cfg.block(*b).stmts.iter().cloned());
                match &self.cfg.block(*b).terminator {
                    Terminator::Return(v) => out.push(Stmt::Return(v.clone())),
                    Terminator::Raise(a) => out.push(Stmt::Raise(a.clone())),
                    _ => {}
                }
            }
            Region::Seq(items) => {
                for item in items {
                    self.lower_into(item, out);
                }
            }
            Region::If { header, then, els } => {
                out.extend(self.cfg.block(*header).stmts.iter().cloned());
                let cond = self.cond_of(*header);
                out.push(Stmt::If {
                    cond,
                    then: self.lower(then),
                    els: self.lower(els),
                });
            }
            Region::ForLoop { header, body, els, .. } => {
                let target = self.cfg.for_targets.get(header).cloned();
                let iter = self.for_iter(*header);
                let (Some(target), Some(iter)) = (target, iter) else {
                    return;
                };
                let body = self.lower(body);
                if els.is_empty() {
                    out.push(Stmt::For { target, iter, body });
                } else {
                    let mut e = Vec::new();
                    for item in els {
                        self.lower_into(item, &mut e);
                    }
                    out.push(Stmt::ForElse { target, iter, body, els: e });
                }
            }
            Region::WhileLoop { header, negated, body, els, .. } => {
                let cond = self.cond_of(*header);
                let body = self.lower(body);
                if els.is_empty() {
                    out.push(Stmt::While { cond, negated: *negated, body });
                } else {
                    let mut e = Vec::new();
                    for item in els {
                        self.lower_into(item, &mut e);
                    }
                    out.push(Stmt::WhileElse { cond, negated: *negated, body, els: e });
                }
            }
            Region::InfLoop { body, .. } => {
                out.push(Stmt::Loop { body: self.lower(body) });
            }
            Region::Try { header, body, handlers, .. } => {
                out.extend(self.cfg.block(*header).stmts.iter().cloned());
                let handlers = handlers
                    .iter()
                    .map(|h| ExceptHandler {
                        exc_type: h.exc_type,
                        name: h.name.clone(),
                        body: self.lower(&h.body),
                    })
                    .collect();
                out.push(Stmt::Try { body: self.lower(body), handlers });
            }
        }
    }

    fn cond_of(&self, header: BlockId) -> ValueId {
        match &self.cfg.block(header).terminator {
            Terminator::CondBranch { cond, .. } => *cond,
            _ => unreachable!("cond_of on non-branch"),
        }
    }

    /// The iterable of a `for` loop: the value GET_ITER left on the stack of the loop's
    /// entry predecessor -- the one predecessor outside the loop, i.e. not dominated by
    /// the header (back edges come from inside, which the header dominates).
    fn for_iter(&self, header: BlockId) -> Option<ValueId> {
        let preds = self.predecessors();
        let entry_pred = preds
            .get(&header)?
            .iter()
            .copied()
            .find(|p| !self.dominates(header, *p))?;
        self.cfg.block(entry_pred).stack_out.last().copied()
    }
}

/// Whether a region always transfers control out of its sequence (so nothing after it in
/// the same suite runs): a break/continue/return/raise, or an `if` whose arms both do.
fn region_terminates(region: &Region) -> bool {
    match region {
        Region::Break | Region::Continue => true,
        Region::Linear(_) => false, // Return/Raise are handled via the surrounding seq's cont
        Region::Seq(items) => items.last().is_some_and(region_terminates),
        Region::If { then, els, .. } => region_terminates(then) && region_terminates(els),
        // A merge-less try has no continuation (its body exits, its handlers absorb the
        // rest), so nothing follows it in the sequence.
        Region::Try { follow, .. } => follow.is_none(),
        _ => false,
    }
}

fn is_empty_region(region: &Region) -> bool {
    match region {
        Region::Empty => true,
        Region::Seq(items) => items.iter().all(is_empty_region),
        _ => false,
    }
}

fn flatten(region: Region) -> Vec<Region> {
    match region {
        Region::Seq(items) => items,
        other => vec![other],
    }
}

/// Drops a redundant trailing `continue` (the natural fall-through to a loop's back edge).
fn strip_trailing_continue(region: &mut Region) {
    if let Region::Seq(items) = region {
        if matches!(items.last(), Some(Region::Continue)) {
            items.pop();
        }
    }
}

/// The body of a back-edge-less `FOR_ITER` loop: the header plus every block forward
/// reachable from the body entry without passing through the exit or re-entering the
/// header.
fn forward_loop_body(
    cfg: &Cfg,
    header: BlockId,
    body_entry: BlockId,
    exit_block: Option<BlockId>,
) -> HashSet<BlockId> {
    let mut body = HashSet::new();
    body.insert(header);
    let mut stack = vec![body_entry];
    while let Some(node) = stack.pop() {
        if node == header || Some(node) == exit_block {
            continue;
        }
        if body.insert(node) {
            for target in cfg.block(node).successors() {
                if let Some(&succ) = cfg.by_offset.get(&target) {
                    stack.push(succ);
                }
            }
        }
    }
    body
}

/// The natural loop of a set of latches branching back to `header`: the header plus every
/// node that reaches a latch without passing through the header.
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

/// Resolves a terminator offset to a [`Dest`] using only the CFG (usable before the
/// [`Analyzer`] exists).
fn dest_of(cfg: &Cfg, offset: super::expr::Offset) -> Dest {
    match cfg.by_offset.get(&offset) {
        Some(&b) => Dest::Block(b),
        None => Dest::Exit,
    }
}

fn edge_key(e: Edge) -> u8 {
    match e {
        Edge::Seq => 0,
        Edge::True => 1,
        Edge::False => 2,
        Edge::ForBody => 3,
        Edge::ForExit => 4,
        Edge::TryBody => 5,
        Edge::TryHandler => 6,
    }
}

fn dest_key(d: Dest) -> u32 {
    match d {
        Dest::Block(b) => b.0,
        Dest::Exit => u32::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::cfg::Block;
    use crate::ir::expr::{Expr, ExprArena, Offset};

    /// Builds a `Cfg` whose block `i` starts at offset `i * 10`, so a terminator targets
    /// block `j` with `Offset(j * 10)`.
    fn cfg_of(blocks: Vec<(Vec<Stmt>, Terminator)>, arena: ExprArena) -> Cfg {
        let by_offset = (0..blocks.len())
            .map(|i| (Offset(i as u32 * 10), BlockId(i as u32)))
            .collect();
        let blocks = blocks
            .into_iter()
            .enumerate()
            .map(|(i, (stmts, terminator))| Block {
                start: Offset(i as u32 * 10),
                stmts,
                terminator,
                stack_out: Vec::new(),
                poison: None,
            })
            .collect();
        Cfg {
            blocks,
            entry: BlockId(0),
            by_offset,
            arena,
            for_targets: HashMap::new(),
            for_else: HashMap::new(),
        }
    }

    fn off(block: u32) -> Offset {
        Offset(block * 10)
    }

    /// `while True:` with two conditional breaks -- the relinearized read-loop shape the
    /// primary structurer bails on, recovered as a `Loop` containing nested `if`s.
    #[test]
    fn infinite_loop_with_two_breaks() {
        let mut arena = ExprArena::new();
        let c1 = arena.alloc(Expr::Const(crate::ir::expr::ConstId(0)));
        let c2 = arena.alloc(Expr::Const(crate::ir::expr::ConstId(1)));
        let ret = arena.alloc(Expr::Const(crate::ir::expr::ConstId(2)));
        // B0 entry -> B1; B1 header: if c1 -> B2(break) else B3; B3: if c2 -> B4(break)
        // else B5; B5: back edge -> B1; B6: return.
        let cfg = cfg_of(
            vec![
                (vec![], Terminator::Fallthrough(off(1))),
                (vec![], Terminator::CondBranch { cond: c1, if_true: off(2), if_false: off(3) }),
                (vec![], Terminator::Break { follow: off(6), fallback: off(5) }),
                (vec![], Terminator::CondBranch { cond: c2, if_true: off(4), if_false: off(5) }),
                (vec![], Terminator::Break { follow: off(6), fallback: off(5) }),
                (vec![], Terminator::Jump(off(1))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );

        let body = structure(&cfg).expect("should structure and verify");
        // A single `while True:` loop, then the return.
        assert!(matches!(body.last(), Some(Stmt::Return(_))), "got: {:?}", body);
        let loop_body = body
            .iter()
            .find_map(|s| match s {
                Stmt::Loop { body } => Some(body),
                _ => None,
            })
            .expect("expected a Loop");
        // The loop's body is `if c1: break else: (if c2: break else: ...)`.
        let breaks = count_breaks(loop_body);
        assert_eq!(breaks, 2, "expected two breaks, got {:?}", loop_body);
    }

    fn count_breaks(stmts: &[Stmt]) -> usize {
        stmts
            .iter()
            .map(|s| match s {
                Stmt::Break => 1,
                Stmt::If { then, els, .. } => count_breaks(then) + count_breaks(els),
                Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::For { body, .. } => {
                    count_breaks(body)
                }
                _ => 0,
            })
            .sum()
    }

    /// An irreducible two-entry cycle has no clean structure; the analyzer must refuse it.
    #[test]
    fn irreducible_returns_none() {
        let mut arena = ExprArena::new();
        let c = arena.alloc(Expr::Const(crate::ir::expr::ConstId(0)));
        // B0: if c -> B1 else B2; B1 -> B2; B2 -> B1 (cycle entered at two points).
        let cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond: c, if_true: off(1), if_false: off(2) }),
                (vec![], Terminator::Jump(off(2))),
                (vec![], Terminator::Jump(off(1))),
            ],
            arena,
        );
        assert!(structure(&cfg).is_none(), "irreducible CFG must not be structured");
    }

    /// A nested-loop archetype: a `for` whose break target is *past* its FOR_ITER exit
    /// (the FOR_ITER exit is a `for ... else` clause). The follow is the header's
    /// post-dominator, not an out-edge target, so the convergence heuristic alone would
    /// miss it -- this exercises the post-dominator follow.
    #[test]
    fn for_else_with_break() {
        use crate::ir::expr::{ConstId, LValue, VarId};
        let mut arena = ExprArena::new();
        let it = arena.alloc(Expr::Const(ConstId(0)));
        let cond = arena.alloc(Expr::Const(ConstId(1)));
        let body_stmt = arena.alloc(Expr::Const(ConstId(2)));
        let else_stmt = arena.alloc(Expr::Const(ConstId(3)));
        let ret = arena.alloc(Expr::Const(ConstId(4)));
        // B0 -> B1; B1 ForIter body=B2 exit=B3; B2 if cond -> B4(break) else B1(continue);
        // B3 else-clause -> B5; B4 break-arm -> B5(=follow, past the FOR_ITER exit); B5 return.
        let mut cfg = cfg_of(
            vec![
                (vec![], Terminator::Fallthrough(off(1))),
                (vec![], Terminator::ForIter { body: off(2), exit: off(3) }),
                (
                    vec![],
                    Terminator::CondBranch { cond, if_true: off(4), if_false: off(1) },
                ),
                (vec![Stmt::Expr(else_stmt)], Terminator::Fallthrough(off(5))),
                (vec![Stmt::Expr(body_stmt)], Terminator::Jump(off(5))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        cfg.for_targets.insert(BlockId(1), LValue::Local(VarId(0)));
        cfg.blocks[0].stack_out = vec![it]; // GET_ITER value for the loop's iterable

        let body = structure(&cfg).expect("for-else with break should structure and verify");
        let forelse = body.iter().find(|s| matches!(s, Stmt::ForElse { .. }));
        let Some(Stmt::ForElse { body, els, .. }) = forelse else {
            panic!("expected a ForElse, got: {:?}", body);
        };
        assert_eq!(count_breaks(body), 1, "break should be inside the for body");
        assert!(!els.is_empty(), "else clause should be recovered");
    }

    /// A `try`/`except` whose body and handler converge at a merge, then a tail block.
    #[test]
    fn try_except_with_merge() {
        use crate::ir::cfg::HandlerArm;
        use crate::ir::expr::ConstId;
        let mut arena = ExprArena::new();
        let exc = arena.alloc(Expr::Const(ConstId(0)));
        let body_v = arena.alloc(Expr::Const(ConstId(1)));
        let hand_v = arena.alloc(Expr::Const(ConstId(2)));
        let ret = arena.alloc(Expr::Const(ConstId(3)));
        // B0 try(body=B1, except->B2, end=B3); B1 body -> B3; B2 handler -> B3; B3 return.
        let cfg = cfg_of(
            vec![
                (
                    vec![],
                    Terminator::Try {
                        body: off(1),
                        handlers: vec![HandlerArm { exc_type: Some(exc), name: None, body: off(2) }],
                        end: Some(off(3)),
                    },
                ),
                (vec![Stmt::Expr(body_v)], Terminator::Fallthrough(off(3))),
                (vec![Stmt::Expr(hand_v)], Terminator::Fallthrough(off(3))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&cfg).expect("try/except should structure and verify");
        let Some(Stmt::Try { handlers, .. }) = body.iter().find(|s| matches!(s, Stmt::Try { .. }))
        else {
            panic!("expected a Try, got: {:?}", body);
        };
        assert_eq!(handlers.len(), 1, "expected one except handler");
        assert!(matches!(body.last(), Some(Stmt::Return(_))), "tail return after try");
    }

    /// `while c: if d: break; ... else: els` -- a `break` skips the else clause, so the
    /// else is distinct from after-loop code (without the break the two are equivalent).
    #[test]
    fn while_else_with_break() {
        use crate::ir::expr::ConstId;
        let mut arena = ExprArena::new();
        let cond = arena.alloc(Expr::Const(ConstId(0)));
        let d = arena.alloc(Expr::Const(ConstId(1)));
        let else_v = arena.alloc(Expr::Const(ConstId(2)));
        let ret = arena.alloc(Expr::Const(ConstId(3)));
        // B0 header: if c -> B1 (body) else B3 (else); B1: if d -> B2 (break) else B0
        // (continue); B2: break -> B4; B3 else -> B4; B4 return.
        let cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond, if_true: off(1), if_false: off(3) }),
                (vec![], Terminator::CondBranch { cond: d, if_true: off(2), if_false: off(0) }),
                (vec![], Terminator::Jump(off(4))),
                (vec![Stmt::Expr(else_v)], Terminator::Fallthrough(off(4))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&cfg).expect("while/else+break should structure and verify");
        let Some(Stmt::WhileElse { body: wbody, els, .. }) =
            body.iter().find(|s| matches!(s, Stmt::WhileElse { .. }))
        else {
            panic!("expected a WhileElse, got: {:?}", body);
        };
        assert!(!els.is_empty(), "else clause should be recovered");
        assert_eq!(count_breaks(wbody), 1, "break should be inside the while body");
    }
}
