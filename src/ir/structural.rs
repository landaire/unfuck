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
use super::expr::{BoolKind, ExceptHandler, Expr, LValue, Offset, Stmt, ValueId};

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
    /// A two-way branch whose condition is a short-circuit chain of `CondBranch` headers
    /// (`if A and B:` / `if A or B:`), folded into one `if` so the shared exit arm is not
    /// duplicated. `headers` are the chain blocks in order; the folded condition is looked
    /// up in [`Analyzer::sc`].
    ShortCircuit {
        headers: Vec<BlockId>,
        kind: BoolKind,
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
        /// The `else:` suite (run when the body raised nothing), or `None`.
        els: Option<Box<Region>>,
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
pub fn structure(cfg: &mut Cfg) -> Option<Vec<Stmt>> {
    // Detect short-circuit condition chains (`if A and B:`, `if A or B:`) and pre-allocate
    // their folded `BoolOp` condition into the arena, while it is still mutable. A chain of
    // `CondBranch` headers that share an exit target is then recovered as ONE `if` rather
    // than nested `if`s that would duplicate the shared arm (which the verifier rejects).
    let raw = detect_short_circuits(cfg);
    let sc = allocate_chain_conds(cfg, raw);
    let analyzer = Analyzer::build(cfg, sc)?;
    let mut frames: Vec<Frame> = Vec::new();
    let entry = analyzer.resolve(cfg.entry);
    let region = analyzer.build_region(entry, None, &mut frames, 0)?;
    analyzer.verify(&region)?;
    let mut body = analyzer.lower(&region);
    super::structure::cleanup(&mut body);
    Some(body)
}

/// A detected short-circuit chain: a run of `CondBranch` headers folded into one boolean
/// condition. For an `And` chain `[H1..Hn]` each header's false arm goes to the shared
/// `els_off` and `Hi.true -> H(i+1)`, with `Hn.true -> then_off`; for `Or`, true arms share
/// `then_off` and `Hi.false -> H(i+1)`, with `Hn.false -> els_off`.
struct ScChain {
    kind: BoolKind,
    headers: Vec<BlockId>,
    cond: ValueId,
    then_off: Offset,
    els_off: Offset,
}

/// The same chain before its folded condition is allocated.
struct ScChainRaw {
    kind: BoolKind,
    headers: Vec<BlockId>,
    then_off: Offset,
    els_off: Offset,
}

/// Finds short-circuit chains headed at each `CondBranch`. A chain extends while the
/// continuation arm lands on another *statement-free* `CondBranch` that shares the same
/// exit target on its other arm; the head may carry statements (they compute the first
/// operand and run before the `if`), the continuations may not. Headers are resolved
/// through pure-jump trampolines, as everywhere else.
fn detect_short_circuits(cfg: &Cfg) -> HashMap<BlockId, ScChainRaw> {
    let thread = build_thread_map(cfg);
    let resolve = |o: Offset| -> Option<BlockId> { cfg.by_offset.get(&o).map(|&b| *thread.get(&b).unwrap_or(&b)) };
    let cond_branch = |b: BlockId| -> Option<(Offset, Offset)> {
        match cfg.block(b).terminator {
            Terminator::CondBranch { if_true, if_false, .. } => Some((if_true, if_false)),
            _ => None,
        }
    };
    let mut out = HashMap::new();
    for (idx, block) in cfg.blocks.iter().enumerate() {
        let head = BlockId(idx as u32);
        if thread.contains_key(&head) {
            continue;
        }
        let Some((h_true, h_false)) = cond_branch(head) else { continue };
        // Try to extend an `And` chain (continuation = true arm, shared exit = false arm)
        // and an `Or` chain (continuation = false arm, shared exit = true arm); keep the
        // longer (>= 2 headers).
        let and = extend_chain(cfg, &resolve, &cond_branch, head, h_true, h_false, true);
        let or = extend_chain(cfg, &resolve, &cond_branch, head, h_false, h_true, false);
        let best = match (and, or) {
            (Some(a), Some(o)) => Some(if a.headers.len() >= o.headers.len() { a } else { o }),
            (a, o) => a.or(o),
        };
        if let Some(chain) = best {
            out.insert(head, chain);
        }
    }
    out
}

/// Extends a chain from `head`: `cont0` is the head's continuation arm, `shared0` its exit
/// arm. `is_and` selects which arm continues for the deeper headers. Returns a chain of >= 2
/// headers or `None`.
fn extend_chain(
    cfg: &Cfg,
    resolve: &dyn Fn(Offset) -> Option<BlockId>,
    cond_branch: &dyn Fn(BlockId) -> Option<(Offset, Offset)>,
    head: BlockId,
    cont0: Offset,
    shared0: Offset,
    is_and: bool,
) -> Option<ScChainRaw> {
    let shared = resolve(shared0)?;
    let mut headers = vec![head];
    let mut cur_cont = cont0;
    let mut seen = HashSet::new();
    seen.insert(head);
    loop {
        let Some(next) = resolve(cur_cont) else { break };
        if !seen.insert(next) {
            break; // a cycle of conditionals is a loop, not a chain
        }
        // The continuation must be a statement-free CondBranch that shares the same exit.
        if !cfg.block(next).stmts.is_empty() || cfg.block(next).poison.is_some() {
            break;
        }
        let Some((n_true, n_false)) = cond_branch(next) else { break };
        let (n_cont, n_shared) = if is_and { (n_true, n_false) } else { (n_false, n_true) };
        if resolve(n_shared) != Some(shared) {
            break;
        }
        headers.push(next);
        cur_cont = n_cont;
        // The chain can keep going only if the next continuation is again a shared-exit
        // CondBranch; otherwise this header is the last and `cur_cont` is the final target.
        if resolve(cur_cont).and_then(|b| cond_branch(b)).is_none() {
            break;
        }
    }
    if headers.len() < 2 {
        return None;
    }
    // `cur_cont` is the final continuation (consequent for And, alternative for Or).
    let (then_off, els_off) = if is_and { (cur_cont, shared0) } else { (shared0, cur_cont) };
    Some(ScChainRaw { kind: if is_and { BoolKind::And } else { BoolKind::Or }, headers, then_off, els_off })
}

/// Allocates each chain's folded `BoolOp(kind, [cond_i])` into the arena.
fn allocate_chain_conds(cfg: &mut Cfg, raw: HashMap<BlockId, ScChainRaw>) -> HashMap<BlockId, ScChain> {
    let mut out = HashMap::new();
    for (head, chain) in raw {
        let conds: Option<Vec<ValueId>> = chain
            .headers
            .iter()
            .map(|h| match cfg.block(*h).terminator {
                Terminator::CondBranch { cond, .. } => Some(cond),
                _ => None,
            })
            .collect();
        let Some(conds) = conds else { continue };
        let cond = cfg.arena.alloc(Expr::BoolOp(chain.kind, conds));
        out.insert(
            head,
            ScChain { kind: chain.kind, headers: chain.headers, cond, then_off: chain.then_off, els_off: chain.els_off },
        );
    }
    out
}

struct Analyzer<'a> {
    cfg: &'a Cfg,
    /// Short-circuit chains keyed by head block (see [`detect_short_circuits`]).
    sc: HashMap<BlockId, ScChain>,
    /// Pure-jump trampolines threaded to their ultimate target (see [`build_thread_map`]).
    thread: HashMap<BlockId, BlockId>,
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
    fn build(cfg: &'a Cfg, sc: HashMap<BlockId, ScChain>) -> Option<Analyzer<'a>> {
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

        // Pure-jump trampolines are threaded out of every graph: an edge that lands on one
        // resolves straight to its ultimate target, and the trampoline itself carries no
        // edges (so it is unreachable and excluded from coverage). This dissolves a
        // continue/break trampoline reached from several branch arms, which would otherwise
        // be walked -- and duplicated -- in each arm.
        let thread = build_thread_map(cfg);
        let resolve_off = |off: Offset| -> Dest {
            match cfg.by_offset.get(&off) {
                Some(&b) => Dest::Block(*thread.get(&b).unwrap_or(&b)),
                None => Dest::Exit,
            }
        };
        let is_tramp = |b: BlockId| thread.contains_key(&b);

        // Forward graph for dominators. Each block keeps its raw CFG successors (a `Break`
        // uses its in-loop `fallback`) AND, for a `Break`, an extra edge to its `follow`.
        // The follow edge is what makes a second loop reached only through the first loop's
        // break target -- whose blocks are unreachable on the raw edges -- reachable here,
        // so its back edge is dominated and detected; the fallback edge keeps the first
        // loop's body intact. (Both together = the union of raw and semantic edges.)
        let mut graph = DiGraph::<(), ()>::new();
        let nodes: Vec<NodeIndex> = (0..cfg.blocks.len()).map(|_| graph.add_node(())).collect();
        let exit_node = graph.add_node(());
        for (idx, block) in cfg.blocks.iter().enumerate() {
            if is_tramp(BlockId(idx as u32)) {
                continue;
            }
            let from = nodes[idx];
            let mut targets = block.successors();
            if let Terminator::Break { follow, .. } = &block.terminator {
                if !targets.contains(follow) {
                    targets.push(*follow);
                }
            }
            if targets.is_empty() {
                graph.add_edge(from, exit_node, ());
            }
            for target in targets {
                match resolve_off(target) {
                    Dest::Block(to) => graph.add_edge(from, nodes[to.0 as usize], ()),
                    Dest::Exit => graph.add_edge(from, exit_node, ()),
                };
            }
        }
        let entry_node = nodes[thread.get(&cfg.entry).copied().unwrap_or(cfg.entry).0 as usize];
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
                Terminator::Try { body, .. } => vec![dest_of(cfg, &thread, *body)],
                Terminator::With { body, end, .. } => {
                    vec![dest_of(cfg, &thread, *body), dest_of(cfg, &thread, *end)]
                }
                Terminator::Finally { body, finalbody, .. } => {
                    let mut v = vec![dest_of(cfg, &thread, *body)];
                    v.extend(finalbody.map(|fb| dest_of(cfg, &thread, fb)));
                    v
                }
                Terminator::Break { follow, .. } => vec![dest_of(cfg, &thread, *follow)],
                _ => block
                    .successors()
                    .iter()
                    .map(|o| dest_of(cfg, &thread, *o))
                    .collect(),
            }
        };
        let mut rev = DiGraph::<(), ()>::new();
        let rnodes: Vec<NodeIndex> = (0..cfg.blocks.len()).map(|_| rev.add_node(())).collect();
        let rexit = rev.add_node(());
        for (idx, block) in cfg.blocks.iter().enumerate() {
            if is_tramp(BlockId(idx as u32)) {
                continue;
            }
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
            sc,
            thread,
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
        let mut stack = vec![analyzer.resolve(cfg.entry)];
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

    /// Predecessors (over CFG-graph edges, threading trampolines) of every block. A
    /// trampoline is never a predecessor: its in-edges are attributed to the block its
    /// chain resolves to.
    fn predecessors(&self) -> HashMap<BlockId, Vec<BlockId>> {
        let mut preds: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (idx, block) in self.cfg.blocks.iter().enumerate() {
            let source = BlockId(idx as u32);
            if self.is_tramp(source) {
                continue;
            }
            for target in block.successors() {
                if let Some(&succ) = self.cfg.by_offset.get(&target) {
                    preds.entry(self.resolve(succ)).or_default().push(source);
                }
            }
        }
        preds
    }

    /// Threads a block through any pure-jump trampoline chain to its ultimate target.
    fn resolve(&self, b: BlockId) -> BlockId {
        *self.thread.get(&b).unwrap_or(&b)
    }

    /// Whether `b` is a pure-jump trampoline threaded away from the graph.
    fn is_tramp(&self, b: BlockId) -> bool {
        self.thread.contains_key(&b)
    }

    /// The block a terminator offset resolves to (threading trampolines), or `Exit`.
    fn dest(&self, offset: super::expr::Offset) -> Dest {
        match self.cfg.by_offset.get(&offset) {
            Some(&b) => Dest::Block(self.resolve(b)),
            None => Dest::Exit,
        }
    }

    /// The block a terminator offset resolves to, threading trampolines; `None` for the
    /// function exit.
    fn resolve_off(&self, offset: super::expr::Offset) -> Option<BlockId> {
        self.cfg.by_offset.get(&offset).map(|&b| self.resolve(b))
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
            .filter_map(|o| self.resolve_off(*o))
            .collect()
    }

    fn detect_loops(&mut self) -> Option<()> {
        let preds = self.predecessors();
        // Reachability over BOTH the raw CFG edges (a `Break` uses its in-loop `fallback`)
        // and the semantic edges (a `Break` reaches its `follow`). The union is needed
        // because a back-edge source can hide behind either: a relinearizer trampoline is
        // reached only by a break's fallback, while a *second* loop following the first is
        // reached only by the first loop's break `follow` (its blocks are unreachable on the
        // raw edges). Filtering candidate latches by this union keeps both kinds of loop
        // visible while still excluding genuine orphan junk blocks.
        let graph_reachable = {
            let mut seen = HashSet::new();
            let mut stack = vec![self.resolve(self.cfg.entry)];
            while let Some(b) = stack.pop() {
                if !seen.insert(b) {
                    continue;
                }
                stack.extend(self.graph_succ(b));
                for (_, d) in self.ground_truth(b) {
                    if let Dest::Block(t) = d {
                        stack.push(t);
                    }
                }
            }
            seen
        };
        // Headers are back-edge targets. A back edge whose target does not dominate its
        // source is irreducible -- reject the whole function.
        let mut headers: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
        for (idx, block) in self.cfg.blocks.iter().enumerate() {
            let source = BlockId(idx as u32);
            if !graph_reachable.contains(&source) || self.is_tramp(source) {
                continue;
            }
            for target in block.successors() {
                if let Some(&h0) = self.cfg.by_offset.get(&target) {
                    let h = self.resolve(h0);
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
                let Some(body_entry) = self.resolve_off(*body_off) else {
                    return None;
                };
                let exit_block = self.resolve_off(*exit);
                let body = self.forward_loop_body(header, body_entry, exit_block);
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

    /// The body of a back-edge-less `FOR_ITER` loop: the header plus every block forward
    /// reachable (over trampoline-threaded edges) from the body entry without passing
    /// through the exit or re-entering the header.
    fn forward_loop_body(
        &self,
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
                stack.extend(self.graph_succ(node));
            }
        }
        body
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
                let body_entry = self.resolve_off(*body_off)?;
                let normal_exit = self.resolve_off(*exit)?;
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
                let t = self.resolve_off(*if_true);
                let f = self.resolve_off(*if_false);
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
                    cursor = self.resolve_off(*t);
                    if cursor.is_none() {
                        // A plain edge to the function exit: nothing follows.
                        break;
                    }
                }
                Terminator::Break { follow, .. } => {
                    // The block runs, then breaks out of the innermost loop. Its `follow`
                    // must be that loop's follow, or the emitted `break` would be wrong.
                    let follow_block = self.resolve_off(*follow);
                    if frames.last().map(|f| f.follow) != Some(follow_block) {
                        return None;
                    }
                    seq.push(Region::Linear(cur));
                    seq.push(Region::Break);
                    cursor = None;
                }
                Terminator::CondBranch { if_true, if_false, .. } => {
                    // A short-circuit chain headed here folds into one `if` (with the
                    // pre-allocated `BoolOp` condition), so its shared exit arm is emitted
                    // once. Only when no *absorbed* header (every header past the first) is a
                    // loop header -- such a header must stay a real loop, not be folded away.
                    let chain = self.sc.get(&cur).filter(|c| {
                        c.headers[1..].iter().all(|h| !self.loops.contains_key(h))
                    });
                    let (true_off, false_off) = match chain {
                        Some(c) => (c.then_off, c.els_off),
                        None => (*if_true, *if_false),
                    };
                    let true_block = self.resolve_off(true_off);
                    let false_block = self.resolve_off(false_off);
                    let merge = self.branch_merge(cur, stop, frames);
                    let then = self.build_arm(true_block, merge, frames, depth)?;
                    let els = self.build_arm(false_block, merge, frames, depth)?;
                    let both_terminate = self.region_terminates(&then) && self.region_terminates(&els);
                    let region = match chain {
                        Some(c) => Region::ShortCircuit {
                            headers: c.headers.clone(),
                            kind: c.kind,
                            then: Box::new(then),
                            els: Box::new(els),
                        },
                        None => Region::If {
                            header: cur,
                            then: Box::new(then),
                            els: Box::new(els),
                        },
                    };
                    seq.push(region);
                    cursor = if both_terminate { None } else { merge };
                }
                Terminator::Try { body, handlers, end, els } => {
                    // The body and every handler converge at `end` (the merge). A
                    // merge-less try (`end` None) has no merge: the body always exits, so a
                    // handler that falls through continues to the enclosing region's stop.
                    let body_off = *body;
                    let handlers = handlers.clone();
                    let end = *end;
                    let els = *els;
                    let follow = match end {
                        Some(e) => Some(self.resolve_off(e)?),
                        None => stop,
                    };
                    // On success the body flows into the `else:` suite (when present),
                    // which converges at the merge; the else is not protected.
                    let els_entry = match els {
                        Some(e) => Some(self.resolve_off(e)?),
                        None => None,
                    };
                    let body_follow = match els_entry {
                        Some(e) => Some(e),
                        None => follow,
                    };
                    let body_entry = self.resolve_off(body_off)?;
                    let body_region = self.build_region(body_entry, body_follow, frames, depth + 1)?;
                    // A merge-less try's body must terminate (no normal exit), or the
                    // recovery would be wrong; reject otherwise.
                    if end.is_none() && !self.region_terminates(&body_region) {
                        return None;
                    }
                    let els_region = match els_entry {
                        Some(e) => Some(Box::new(self.build_region(e, follow, frames, depth + 1)?)),
                        None => None,
                    };
                    let mut arms = Vec::with_capacity(handlers.len());
                    for h in &handlers {
                        let hb = self.resolve_off(h.body)?;
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
                        els: els_region,
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
                match derived.get(b) {
                    None => {
                        derived.insert(*b, edges);
                    }
                    // A *tail* block -- one whose control leaves via return/raise/break/
                    // continue/self-loop, never falling through to a distinct following
                    // block -- may be reached from several mutually-exclusive paths and so
                    // emitted more than once. Each copy runs only on its own path, so the
                    // duplication is faithful; it is admitted only when every copy derives
                    // the identical edge (so they agree with the ground truth) and the block
                    // is such a tail (a tail has no tree-successor, so this never cascades
                    // into the rest of the function being duplicated).
                    Some(prev) if *prev == edges && self.is_dup_tail(*b, frames) => {}
                    Some(_) => return None, // a non-tail block emitted twice: reject
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
            Region::ShortCircuit { headers, kind, then, els } => {
                // The whole chain leaves to `then` (final consequent) or `els` (final
                // alternative); each header's chaining arm goes to the next header. Derive
                // each header's labelled edges so the verifier checks every chain block.
                let t = self.entry_dest(std::slice::from_ref(then.as_ref()), cont, frames)?;
                let f = self.entry_dest(std::slice::from_ref(els.as_ref()), cont, frames)?;
                for (i, h) in headers.iter().enumerate() {
                    let last = i + 1 == headers.len();
                    let edges = match kind {
                        BoolKind::And => {
                            let true_dest = if last { t } else { Dest::Block(headers[i + 1]) };
                            vec![(Edge::True, true_dest), (Edge::False, f)]
                        }
                        BoolKind::Or => {
                            let false_dest = if last { f } else { Dest::Block(headers[i + 1]) };
                            vec![(Edge::True, t), (Edge::False, false_dest)]
                        }
                    };
                    if derived.insert(*h, edges).is_some() {
                        return None;
                    }
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
            Region::Try { header, body, handlers, els, follow } => {
                // The body and handlers converge at the merge (`follow`); a merge-less try
                // continues to `cont` (the enclosing continuation).
                let after = match follow {
                    Some(b) => Dest::Block(*b),
                    None => cont,
                };
                // On success the body flows into the `else:` suite (when present), which
                // then converges at the merge.
                let body_after = match els {
                    Some(e) => self.entry_dest(std::slice::from_ref(e.as_ref()), after, frames)?,
                    None => after,
                };
                let mut edges = vec![(
                    Edge::TryBody,
                    self.entry_dest(std::slice::from_ref(body.as_ref()), body_after, frames)?,
                )];
                for h in handlers {
                    edges.push((
                        Edge::TryHandler,
                        self.entry_dest(std::slice::from_ref(&h.body), after, frames)?,
                    ));
                }
                if derived.insert(*header, edges).is_some() {
                    return None;
                }
                self.simulate(body, body_after, frames, derived)?;
                if let Some(e) = els {
                    self.simulate(e, after, frames, derived)?;
                }
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
                Region::ShortCircuit { headers, .. } => return Some(Dest::Block(headers[0])),
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

    /// Whether `b` is a *tail* block: its control leaves the current suite for good --
    /// `return`/`raise` (to the function exit), `break` (to a loop follow), or an
    /// unconditional jump that is a `continue` (to an enclosing loop header) or a `break`
    /// (to an enclosing loop follow). Such a block has no fall-through to a distinct
    /// following block, so emitting it on several mutually-exclusive paths is faithful and
    /// never duplicates anything after it. A plain forward `Fallthrough`/`Jump` to some
    /// other block is NOT a tail (duplicating it would cascade into its successor).
    ///
    /// A loop header is NOT a duplicable tail: a `Jump`-to-self self-loop (an empty
    /// `while True: pass`) reached from several arms is a deobfuscator control-flow-
    /// flattening artifact -- the original had a `break` there -- not real source, so it
    /// must fall to an honest stub rather than be emitted as a wrong infinite loop. (Its own
    /// header sits in `frames`, which would otherwise make the self-jump look like a
    /// `continue` to an enclosing loop.)
    fn is_dup_tail(&self, b: BlockId, frames: &[Frame]) -> bool {
        if frames.iter().any(|f| f.header == b) {
            return false;
        }
        match &self.cfg.block(b).terminator {
            Terminator::Return(_) | Terminator::Raise(_) | Terminator::Break { .. } => true,
            Terminator::Fallthrough(t) | Terminator::Jump(t) => {
                let dest = self.resolve_off(*t);
                frames
                    .iter()
                    .any(|f| dest == Some(f.header) || (f.follow.is_some() && dest == f.follow))
            }
            _ => false,
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
            Region::ShortCircuit { headers, then, els, .. } => {
                // The head's statements compute the first operand and run before the `if`;
                // the absorbed headers are statement-free. The folded condition was
                // pre-allocated in the arena.
                out.extend(self.cfg.block(headers[0]).stmts.iter().cloned());
                let cond = self.sc.get(&headers[0]).map(|c| c.cond).unwrap_or_else(|| self.cond_of(headers[0]));
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
            Region::Try { header, body, handlers, els, .. } => {
                out.extend(self.cfg.block(*header).stmts.iter().cloned());
                let handlers = handlers
                    .iter()
                    .map(|h| ExceptHandler {
                        exc_type: h.exc_type,
                        name: h.name.clone(),
                        body: self.lower(&h.body),
                    })
                    .collect();
                let els = els.as_ref().map(|e| self.lower(e)).unwrap_or_default();
                out.push(Stmt::Try { body: self.lower(body), handlers, els });
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

    /// Whether a region always transfers control out of its sequence (so nothing after it
    /// in the same suite runs): a break/continue, a `Linear` whose terminator is a
    /// `return`/`raise`, or an `if` whose arms both do.
    fn region_terminates(&self, region: &Region) -> bool {
        match region {
            Region::Break | Region::Continue => true,
            Region::Linear(b) => matches!(
                self.cfg.block(*b).terminator,
                Terminator::Return(_) | Terminator::Raise(_)
            ),
            Region::Seq(items) => items.last().is_some_and(|r| self.region_terminates(r)),
            Region::If { then, els, .. } | Region::ShortCircuit { then, els, .. } => {
                self.region_terminates(then) && self.region_terminates(els)
            }
            // A merge-less try has no continuation (its body exits, its handlers absorb the
            // rest), so nothing follows it in the sequence.
            Region::Try { follow, .. } => follow.is_none(),
            _ => false,
        }
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
/// [`Analyzer`] exists), threading pure-jump trampolines.
fn dest_of(cfg: &Cfg, thread: &HashMap<BlockId, BlockId>, offset: super::expr::Offset) -> Dest {
    match cfg.by_offset.get(&offset) {
        Some(&b) => Dest::Block(*thread.get(&b).unwrap_or(&b)),
        None => Dest::Exit,
    }
}

/// Maps each pure-`Jump` continue/break trampoline -- an empty block (no statements, no
/// values carried across, not poisoned) whose only terminator is an unconditional
/// `Jump`/`Fallthrough` to a real block -- to the ultimate non-trampoline block its chain
/// reaches. Every edge that lands on a trampoline is then resolved straight to that target
/// (so a branch arm jumping to a continue-trampoline becomes a `continue` directly),
/// removing the duplication that a trampoline reached from multiple arms would otherwise
/// cause. A trampoline whose chain cycles back on itself (a `while True: pass` self-loop
/// header) is left unthreaded: it is a real loop, not a pass-through.
///
/// A block that is the `fallback` of a `Break` is never threaded: the relinearizer routes
/// a flat loop's back edge through such a block, so it carries the loop's structure and the
/// existing nested-loop recovery depends on it staying in the graph.
fn build_thread_map(cfg: &Cfg) -> HashMap<BlockId, BlockId> {
    let break_fallbacks: HashSet<Offset> = cfg
        .blocks
        .iter()
        .filter_map(|b| match b.terminator {
            Terminator::Break { fallback, .. } => Some(fallback),
            _ => None,
        })
        .collect();
    let tramp_target = |b: &super::cfg::Block| -> Option<Offset> {
        if !b.stmts.is_empty() || !b.stack_out.is_empty() || b.poison.is_some() {
            return None;
        }
        if break_fallbacks.contains(&b.start) {
            return None;
        }
        match b.terminator {
            Terminator::Jump(t) | Terminator::Fallthrough(t) => Some(t),
            _ => None,
        }
    };
    // The direct one-step target of each trampoline (only when it lands on a real block).
    let mut direct: HashMap<BlockId, BlockId> = HashMap::new();
    for (idx, b) in cfg.blocks.iter().enumerate() {
        if let Some(t) = tramp_target(b) {
            if let Some(&tb) = cfg.by_offset.get(&t) {
                direct.insert(BlockId(idx as u32), tb);
            }
        }
    }
    // Resolve each trampoline to the first non-trampoline block its chain reaches; drop it
    // from the map (leave it unthreaded) if the chain cycles.
    let mut thread: HashMap<BlockId, BlockId> = HashMap::new();
    for (&start, &first) in &direct {
        let mut seen = HashSet::new();
        seen.insert(start);
        let mut cur = first;
        let mut cyclic = false;
        while let Some(&next) = direct.get(&cur) {
            if !seen.insert(cur) {
                cyclic = true;
                break;
            }
            cur = next;
        }
        if !cyclic {
            thread.insert(start, cur);
        }
    }
    thread
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
        let mut cfg = cfg_of(
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

        let body = structure(&mut cfg).expect("should structure and verify");
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

    fn count_continues(stmts: &[Stmt]) -> usize {
        stmts
            .iter()
            .map(|s| match s {
                Stmt::Continue => 1,
                Stmt::If { then, els, .. } => count_continues(then) + count_continues(els),
                Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::For { body, .. } => {
                    count_continues(body)
                }
                _ => 0,
            })
            .sum()
    }

    /// A pure-`Jump` continue-trampoline (an empty block whose only terminator is an
    /// unconditional jump back to the loop header) reached from two *different* branch
    /// arms. It is not the unique post-dominator of either branch, so the region walk
    /// visits it in both arms and duplicates it -- which the verifier rejects. Threading
    /// the trampoline (resolving its in-edges straight to the header = `continue`) removes
    /// the duplication so the loop structures and verifies.
    #[test]
    fn shared_continue_trampoline() {
        use crate::ir::expr::ConstId;
        let mut arena = ExprArena::new();
        let cond = arena.alloc(Expr::Const(ConstId(0)));
        let c2 = arena.alloc(Expr::Const(ConstId(1)));
        let c3 = arena.alloc(Expr::Const(ConstId(2)));
        let s3 = arena.alloc(Expr::Const(ConstId(3)));
        let s5 = arena.alloc(Expr::Const(ConstId(4)));
        let ret = arena.alloc(Expr::Const(ConstId(5)));
        // B0 -> B1; B1 while cond (body=B2 else exit=B7); B2 if c2 -> B3 else B4;
        // B3: stmt; Jump B6 (trampoline); B4 if c3 -> B5 else B6 (trampoline);
        // B5: stmt; Jump B1 (continue); B6: empty; Jump B1 (continue trampoline); B7 return.
        // B6 is reached from B3 (a then-arm) and B4 (a false-arm) -- two arms, not a merge.
        let mut cfg = cfg_of(
            vec![
                (vec![], Terminator::Fallthrough(off(1))),
                (vec![], Terminator::CondBranch { cond, if_true: off(2), if_false: off(7) }),
                (vec![], Terminator::CondBranch { cond: c2, if_true: off(3), if_false: off(4) }),
                (vec![Stmt::Expr(s3)], Terminator::Jump(off(6))),
                (vec![], Terminator::CondBranch { cond: c3, if_true: off(5), if_false: off(6) }),
                (vec![Stmt::Expr(s5)], Terminator::Jump(off(1))),
                (vec![], Terminator::Jump(off(1))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&mut cfg).expect("shared continue-trampoline should structure and verify");
        let wbody = body
            .iter()
            .find_map(|s| match s {
                Stmt::While { body, .. } => Some(body),
                _ => None,
            })
            .expect("expected a while loop");
        // The trampoline is threaded away, so each arm's body appears exactly once (the
        // pre-fix walk emitted the trampoline in two arms and the verifier rejected it).
        // The jumps back to the header are redundant tail `continue`s, faithfully dropped.
        assert_eq!(count_expr(wbody, s3), 1, "s3 should appear once, got: {:?}", wbody);
        assert_eq!(count_expr(wbody, s5), 1, "s5 should appear once, got: {:?}", wbody);
        assert_eq!(count_continues(wbody), 0, "tail continues are redundant: {:?}", wbody);
    }

    /// Counts the `Expr(target)` statements anywhere within `stmts`.
    fn count_expr(stmts: &[Stmt], target: crate::ir::expr::ValueId) -> usize {
        stmts
            .iter()
            .map(|s| match s {
                Stmt::Expr(v) if *v == target => 1,
                Stmt::If { then, els, .. } => count_expr(then, target) + count_expr(els, target),
                Stmt::While { body, .. } | Stmt::Loop { body } | Stmt::For { body, .. } => {
                    count_expr(body, target)
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
        let mut cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond: c, if_true: off(1), if_false: off(2) }),
                (vec![], Terminator::Jump(off(2))),
                (vec![], Terminator::Jump(off(1))),
            ],
            arena,
        );
        assert!(structure(&mut cfg).is_none(), "irreducible CFG must not be structured");
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

        let body = structure(&mut cfg).expect("for-else with break should structure and verify");
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
        let mut cfg = cfg_of(
            vec![
                (
                    vec![],
                    Terminator::Try {
                        body: off(1),
                        handlers: vec![HandlerArm { exc_type: Some(exc), name: None, body: off(2) }],
                        end: Some(off(3)),
                        els: None,
                    },
                ),
                (vec![Stmt::Expr(body_v)], Terminator::Fallthrough(off(3))),
                (vec![Stmt::Expr(hand_v)], Terminator::Fallthrough(off(3))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&mut cfg).expect("try/except should structure and verify");
        let Some(Stmt::Try { handlers, .. }) = body.iter().find(|s| matches!(s, Stmt::Try { .. }))
        else {
            panic!("expected a Try, got: {:?}", body);
        };
        assert_eq!(handlers.len(), 1, "expected one except handler");
        assert!(matches!(body.last(), Some(Stmt::Return(_))), "tail return after try");
    }

    /// A merge-less `try` (`end` None) whose body is a bare `return` -- the lazy-init
    /// `try: return self.cached except E: <compute>; return result` shape. The body always
    /// exits via the return, so the merge-less try is well-formed and must structure.
    #[test]
    fn merge_less_try_with_returning_body() {
        use crate::ir::cfg::HandlerArm;
        use crate::ir::expr::ConstId;
        let mut arena = ExprArena::new();
        let exc = arena.alloc(Expr::Const(ConstId(0)));
        let ret_a = arena.alloc(Expr::Const(ConstId(1)));
        let hand = arena.alloc(Expr::Const(ConstId(2)));
        let ret_b = arena.alloc(Expr::Const(ConstId(3)));
        // B0 try(body=B1, except->B2, end=None); B1: return a; B2: stmt; return b.
        let mut cfg = cfg_of(
            vec![
                (
                    vec![],
                    Terminator::Try {
                        body: off(1),
                        handlers: vec![HandlerArm { exc_type: Some(exc), name: None, body: off(2) }],
                        end: None,
                        els: None,
                    },
                ),
                (vec![], Terminator::Return(Some(ret_a))),
                (vec![Stmt::Expr(hand)], Terminator::Return(Some(ret_b))),
            ],
            arena,
        );
        let body = structure(&mut cfg).expect("merge-less try with returning body should structure");
        let Some(Stmt::Try { body: tbody, handlers, .. }) =
            body.iter().find(|s| matches!(s, Stmt::Try { .. }))
        else {
            panic!("expected a Try, got: {:?}", body);
        };
        assert_eq!(handlers.len(), 1, "expected one except handler");
        assert!(matches!(tbody.last(), Some(Stmt::Return(_))), "try body returns");
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
        let mut cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond, if_true: off(1), if_false: off(3) }),
                (vec![], Terminator::CondBranch { cond: d, if_true: off(2), if_false: off(0) }),
                (vec![], Terminator::Jump(off(4))),
                (vec![Stmt::Expr(else_v)], Terminator::Fallthrough(off(4))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&mut cfg).expect("while/else+break should structure and verify");
        let Some(Stmt::WhileElse { body: wbody, els, .. }) =
            body.iter().find(|s| matches!(s, Stmt::WhileElse { .. }))
        else {
            panic!("expected a WhileElse, got: {:?}", body);
        };
        assert!(!els.is_empty(), "else clause should be recovered");
        assert_eq!(count_breaks(wbody), 1, "break should be inside the while body");
    }

    /// `if A and B: X else: Y` -- two `CondBranch`es sharing a false target. The plain
    /// region walk emits the shared `else` (B2) in both arms, which the verifier rejects;
    /// the short-circuit fold recovers it as one `if (A and B):` with `Y` emitted once.
    #[test]
    fn short_circuit_and_shared_else() {
        use crate::ir::expr::{BoolKind, ConstId};
        let mut arena = ExprArena::new();
        let a = arena.alloc(Expr::Const(ConstId(0)));
        let b = arena.alloc(Expr::Const(ConstId(1)));
        let x = arena.alloc(Expr::Const(ConstId(2)));
        let y = arena.alloc(Expr::Const(ConstId(3)));
        let ret = arena.alloc(Expr::Const(ConstId(4)));
        // B0: if A -> B1 else B2; B1: if B -> B3 else B2 (shared false);
        // B2: Y -> B4; B3: X -> B4; B4: return.
        let mut cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond: a, if_true: off(1), if_false: off(2) }),
                (vec![], Terminator::CondBranch { cond: b, if_true: off(3), if_false: off(2) }),
                (vec![Stmt::Expr(y)], Terminator::Fallthrough(off(4))),
                (vec![Stmt::Expr(x)], Terminator::Fallthrough(off(4))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let body = structure(&mut cfg).expect("short-circuit `and` should structure and verify");
        let Some(Stmt::If { cond, then, els }) = body.iter().find(|s| matches!(s, Stmt::If { .. }))
        else {
            panic!("expected an If, got: {:?}", body);
        };
        match cfg.arena.get(*cond) {
            Expr::BoolOp(BoolKind::And, ops) => assert_eq!(ops, &vec![a, b], "folded `A and B`"),
            other => panic!("expected folded `A and B`, got: {:?}", other),
        }
        assert_eq!(count_expr(then, x), 1, "then has X once");
        assert_eq!(count_expr(els, y), 1, "els has Y once, not duplicated");
    }

    /// A shared `continue` tail (`B3`: stmt; jump to the loop header) reached from two
    /// distinct branch arms that do NOT form a short-circuit chain (the intermediate `B2`
    /// carries a statement). The plain walk emits `B3` in both arms; the verifier's exact-
    /// once rule rejected it. A tail block (control leaves via continue, never falling
    /// through to a following block) may be faithfully duplicated -- each copy runs only on
    /// its own path -- so the duplication-aware verifier accepts it.
    #[test]
    fn shared_continue_tail_duplicated() {
        use crate::ir::expr::ConstId;
        let mut arena = ExprArena::new();
        let cond = arena.alloc(Expr::Const(ConstId(0)));
        let a = arena.alloc(Expr::Const(ConstId(1)));
        let bb = arena.alloc(Expr::Const(ConstId(2)));
        let s2 = arena.alloc(Expr::Const(ConstId(3)));
        let s3 = arena.alloc(Expr::Const(ConstId(4)));
        let s4 = arena.alloc(Expr::Const(ConstId(5)));
        let ret = arena.alloc(Expr::Const(ConstId(6)));
        // B0 while cond (body=B1 else exit=B5); B1 if a -> B2 else B3; B2 stmt; if bb -> B4
        // else B3; B3 stmt; continue; B4 stmt; continue; B5 return. B3 reached from B1.false
        // and B2.false (not a short-circuit chain: B2 carries a statement).
        let cfg = cfg_of(
            vec![
                (vec![], Terminator::CondBranch { cond, if_true: off(1), if_false: off(5) }),
                (vec![], Terminator::CondBranch { cond: a, if_true: off(2), if_false: off(3) }),
                (vec![Stmt::Expr(s2)], Terminator::CondBranch { cond: bb, if_true: off(4), if_false: off(3) }),
                (vec![Stmt::Expr(s3)], Terminator::Jump(off(0))),
                (vec![Stmt::Expr(s4)], Terminator::Jump(off(0))),
                (vec![], Terminator::Return(Some(ret))),
            ],
            arena,
        );
        let mut cfg = cfg;
        let body = structure(&mut cfg).expect("shared continue tail should structure and verify");
        let wbody = body
            .iter()
            .find_map(|s| match s {
                Stmt::While { body, .. } => Some(body),
                _ => None,
            })
            .expect("expected a while loop");
        // The tail B3 is faithfully duplicated (once per arm that reaches it); the others
        // appear once.
        assert_eq!(count_expr(wbody, s3), 2, "shared tail s3 emitted on both arms: {:?}", wbody);
        assert_eq!(count_expr(wbody, s2), 1, "s2 once");
        assert_eq!(count_expr(wbody, s4), 1, "s4 once");
    }
}
