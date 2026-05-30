//! Recovers nested `if`/`else` from the control-flow graph.
//!
//! For a reducible, loop-free graph the merge point of a two-way branch is its
//! immediate post-dominator. Structuring is then a recursive walk: emit a
//! branch's two arms up to that merge, then continue from the merge. Post-domi
//! nators come from running petgraph's dominator analysis on the reversed graph
//! rooted at a virtual exit.

use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Reversed;

use super::cfg::{BlockId, Cfg, Terminator};
use super::expr::Stmt;
use super::IrError;

/// Guards against runaway recursion if the graph violates the loop-free,
/// reducible assumptions the structurer relies on.
const MAX_DEPTH: usize = 4096;

/// A point control reaches: either a block or the function exit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Point {
    Block(BlockId),
    Exit,
}

/// Structures a control-flow graph into a nested statement list.
pub fn structure(cfg: &Cfg) -> Result<Vec<Stmt>, IrError> {
    let post = PostDominators::compute(cfg);
    let mut structurer = Structurer { cfg, post };
    structurer.region(cfg.entry, Point::Exit, 0)
}

struct Structurer<'a> {
    cfg: &'a Cfg,
    post: PostDominators,
}

impl Structurer<'_> {
    /// Emits the region from `start` up to (but excluding) `stop`.
    fn region(&self, start: BlockId, stop: Point, depth: usize) -> Result<Vec<Stmt>, IrError> {
        if depth > MAX_DEPTH {
            return Err(IrError::Unstructurable);
        }

        let mut out = Vec::new();
        let mut cursor = Some(start);
        while let Some(current) = cursor {
            if stop == Point::Block(current) {
                break;
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
                    cursor = Some(self.cfg.target(*target)?);
                }
                Terminator::CondBranch {
                    cond,
                    if_true,
                    if_false,
                } => {
                    let follow = self.post.immediate(current);
                    let true_block = self.cfg.target(*if_true)?;
                    let false_block = self.cfg.target(*if_false)?;

                    let then = self.arm(true_block, follow, depth)?;
                    let els = self.arm(false_block, follow, depth)?;
                    out.push(Stmt::If {
                        cond: *cond,
                        then,
                        els,
                    });

                    cursor = match follow {
                        Point::Block(block) => Some(block),
                        Point::Exit => None,
                    };
                }
            }
        }
        Ok(out)
    }

    /// Structures one branch arm: empty if the arm is the merge itself.
    fn arm(&self, entry: BlockId, follow: Point, depth: usize) -> Result<Vec<Stmt>, IrError> {
        if follow == Point::Block(entry) {
            Ok(Vec::new())
        } else {
            self.region(entry, follow, depth + 1)
        }
    }
}

/// Immediate post-dominators for every block.
struct PostDominators {
    graph: DiGraph<(), ()>,
    exit: NodeIndex,
    doms: Dominators<NodeIndex>,
}

impl PostDominators {
    fn compute(cfg: &Cfg) -> PostDominators {
        let mut graph = DiGraph::<(), ()>::new();
        let block_nodes: Vec<NodeIndex> = (0..cfg.blocks.len()).map(|_| graph.add_node(())).collect();
        let exit = graph.add_node(());

        for (idx, block) in cfg.blocks.iter().enumerate() {
            let from = block_nodes[idx];
            match &block.terminator {
                Terminator::Return(_) | Terminator::Raise(_) => {
                    graph.add_edge(from, exit, ());
                }
                Terminator::Jump(target) | Terminator::Fallthrough(target) => {
                    if let Some(to) = cfg.by_offset.get(target) {
                        graph.add_edge(from, block_nodes[to.0 as usize], ());
                    } else {
                        graph.add_edge(from, exit, ());
                    }
                }
                Terminator::CondBranch {
                    if_true, if_false, ..
                } => {
                    for target in [if_true, if_false] {
                        if let Some(to) = cfg.by_offset.get(target) {
                            graph.add_edge(from, block_nodes[to.0 as usize], ());
                        }
                    }
                }
            }
        }

        let doms = simple_fast(Reversed(&graph), exit);
        PostDominators { graph, exit, doms }
    }

    /// The immediate post-dominator of a block as a [`Point`].
    fn immediate(&self, block: BlockId) -> Point {
        let node = NodeIndex::new(block.0 as usize);
        match self.doms.immediate_dominator(node) {
            Some(idom) if idom != self.exit && idom.index() < self.graph.node_count() => {
                Point::Block(BlockId(idom.index() as u32))
            }
            _ => Point::Exit,
        }
    }
}
