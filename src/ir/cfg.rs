//! Control-flow graph over the statement IR.
//!
//! The function is split into basic blocks at jump targets and after every
//! branch or return. Each block carries its straight-line statements and a typed
//! [`Terminator`] whose conditions reference the shared [`ExprArena`]. Loops are
//! recovered from back edges by the structurer; exception and short-circuit setup
//! are still rejected so the supported surface stays explicit.

use std::collections::{BTreeSet, HashMap, HashSet};

use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use super::expr::{DerefId, ExprArena, LValue, NameId, Offset, Stmt, ValueId, VarId};
use super::unstack::Unstacker;
use super::IrError;

/// Index of a block within a [`Cfg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(pub u32);

/// How a block hands control to its successors.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Falls through to the next block in layout order.
    Fallthrough(Offset),
    /// Unconditional jump.
    Jump(Offset),
    /// Two-way branch. `if_true` is taken when `cond` is truthy.
    CondBranch {
        cond: ValueId,
        if_true: Offset,
        if_false: Offset,
    },
    /// Returns `value` (or `None` for a bare return).
    Return(Option<ValueId>),
    /// Raises an exception. Carries 0..=3 arguments (type, value, traceback).
    /// Control leaves the function (no normal successor).
    Raise(Vec<ValueId>),
    /// `FOR_ITER`: a loop header. Falls through to `body` for the next item, or
    /// jumps to `exit` when the iterator is exhausted. The iterator and loop
    /// target are recovered by the structurer, not stored here.
    ForIter { body: Offset, exit: Offset },
    /// `SETUP_EXCEPT`: a `try`/`except` region. `body` is the protected suite;
    /// each handler is one `except` clause. Both the body and every handler
    /// converge at `end` (the merge after the whole construct). The handler
    /// dispatch instructions are recovered into [`HandlerArm`]s and do not appear
    /// as blocks.
    Try {
        body: Offset,
        handlers: Vec<HandlerArm>,
        end: Offset,
    },
}

/// One recovered `except` clause: the matched type, the optional `as name`
/// binding, and the offset where the clause body begins.
#[derive(Debug, Clone)]
pub struct HandlerArm {
    pub exc_type: Option<ValueId>,
    pub name: Option<LValue>,
    pub body: Offset,
}

/// A basic block: straight-line statements plus a terminator.
#[derive(Debug, Clone)]
pub struct Block {
    pub start: Offset,
    pub stmts: Vec<Stmt>,
    pub terminator: Terminator,
    /// Values left on the symbolic stack after the block. Empty except where a
    /// value lives across a block boundary, e.g. a `for` loop iterator.
    pub stack_out: Vec<ValueId>,
    /// Set when the block could not be lowered (an unsupported opcode or stack
    /// error). The block is kept so opaque-predicate folding can prove it
    /// unreachable; if the structurer ever reaches it, this error surfaces.
    pub poison: Option<IrError>,
}

impl Block {
    /// The target offsets this block can transfer control to.
    pub fn successors(&self) -> Vec<Offset> {
        match &self.terminator {
            Terminator::Fallthrough(target) | Terminator::Jump(target) => vec![*target],
            Terminator::CondBranch {
                if_true, if_false, ..
            } => vec![*if_true, *if_false],
            Terminator::ForIter { body, exit } => vec![*body, *exit],
            Terminator::Try { body, handlers, .. } => {
                let mut targets = vec![*body];
                targets.extend(handlers.iter().map(|arm| arm.body));
                targets
            }
            Terminator::Return(_) | Terminator::Raise(_) => Vec::new(),
        }
    }
}

/// A function lowered to a control-flow graph of statement blocks.
pub struct Cfg {
    pub blocks: Vec<Block>,
    pub entry: BlockId,
    pub by_offset: HashMap<Offset, BlockId>,
    pub arena: ExprArena,
    /// For each `ForIter` header block, the loop target assigned from the next
    /// item (the `STORE` that follows `FOR_ITER`).
    pub for_targets: HashMap<BlockId, LValue>,
}

impl Cfg {
    pub fn block(&self, id: BlockId) -> &Block {
        &self.blocks[id.0 as usize]
    }

    /// Resolves a terminator target offset to its block.
    pub fn target(&self, offset: Offset) -> Result<BlockId, IrError> {
        self.by_offset.get(&offset).copied().ok_or(IrError::BadOperand)
    }

    /// Builds the graph from a decoded instruction stream.
    pub fn build(instrs: &[OffsetInstr]) -> Result<Cfg, IrError> {
        Cfg::build_with(instrs, false)
    }

    /// Builds the graph for a comprehension code object, lowering its accumulator
    /// and `SET_ADD`/`MAP_ADD` instructions into comprehension element statements.
    pub fn build_comp(instrs: &[OffsetInstr]) -> Result<Cfg, IrError> {
        Cfg::build_with(instrs, true)
    }

    fn build_with(instrs: &[OffsetInstr], comp: bool) -> Result<Cfg, IrError> {
        let mut ternaries = find_ternaries(instrs);
        let (tries, mut excluded) = recover_tries(instrs)?;
        // A chained comparison's short-circuit lands past its cleanup; record the
        // merge override and drop the cleanup/forward-jump instructions.
        let (merge_overrides, chained_excluded) = find_chained_comparisons(instrs);
        excluded.extend(chained_excluded);
        // A reordered ternary's else arm is excluded from block formation and fed at
        // the merge instead, so the existing in-block ternary folding applies.
        let (reordered_marks, reordered_excluded, else_feed_ranges) =
            find_reordered_ternaries(instrs);
        ternaries.extend(reordered_marks);
        excluded.extend(reordered_excluded);
        let else_feeds: HashMap<Offset, Vec<&OffsetInstr>> = else_feed_ranges
            .into_iter()
            .map(|(merge, (start, end))| (merge, instrs[start..end].iter().collect()))
            .collect();
        // Inline list comprehensions are folded whole; their interior instructions
        // stay inside one block and never become block leaders or for-loops.
        let (list_comps, list_interior) = find_list_comps(instrs);
        let breaks = break_targets(instrs);
        let leaders = block_leaders(instrs, &ternaries, &tries, &excluded, &list_interior, &breaks)?;
        let mut by_offset = HashMap::new();
        for (idx, leader) in leaders.iter().enumerate() {
            by_offset.insert(*leader, BlockId(idx as u32));
        }

        // The instruction after a FOR_ITER begins the loop body with the loop
        // target's store; map that body leader back to its header offset. A list
        // comprehension's FOR_ITER is folded inline, so it is skipped here.
        let mut for_body_header: HashMap<Offset, Offset> = HashMap::new();
        for (idx, item) in instrs.iter().enumerate() {
            if item.instr.opcode.mnemonic() == Mnemonic::FOR_ITER
                && !list_interior.contains(&item.offset)
            {
                if let Some(next) = instrs.get(idx + 1) {
                    for_body_header.insert(next.offset, item.offset);
                }
            }
        }

        let mut unstacker = if comp {
            Unstacker::new_comp()
        } else {
            Unstacker::new()
        };
        unstacker.set_merge_overrides(merge_overrides);

        // Build each try's terminator up front: the exception-type expressions are
        // lowered through the shared unstacker so they enter the same arena the
        // block bodies use.
        let try_terminators = build_try_terminators(&mut unstacker, instrs, &tries)?;

        let mut blocks = Vec::with_capacity(leaders.len());
        let mut for_targets = HashMap::new();

        for (idx, &leader) in leaders.iter().enumerate() {
            let end = leaders.get(idx + 1).copied().unwrap_or(Offset(u32::MAX));
            // The handler dispatch and binding instructions are recovered into the
            // try terminator; drop them so they never lower as ordinary statements.
            let body: Vec<&OffsetInstr> = instrs
                .iter()
                .filter(|i| i.offset >= leader && i.offset < end && !excluded.contains(&i.offset))
                .collect();
            let for_header = for_body_header
                .get(&leader)
                .and_then(|header| by_offset.get(header).copied());
            let block = lower_block(
                &mut unstacker,
                leader,
                end,
                &body,
                for_header,
                &mut for_targets,
                &try_terminators,
                &list_comps,
                &breaks,
                &else_feeds,
            )
            // A block that does not lower (an unsupported opcode, a stack error) is
            // kept as a poison dead-end rather than failing the whole function, so
            // opaque-predicate folding can prove it unreachable and drop it. Partial
            // statements from the failed attempt are discarded.
            .unwrap_or_else(|error| {
                let _ = unstacker.take_stmts();
                Block {
                    start: leader,
                    stmts: Vec::new(),
                    terminator: Terminator::Return(None),
                    stack_out: Vec::new(),
                    poison: Some(error),
                }
            });
            blocks.push(block);
        }

        Ok(Cfg {
            blocks,
            entry: BlockId(0),
            by_offset,
            arena: unstacker.into_arena(),
            for_targets,
        })
    }
}

/// A decoded instruction tagged with its byte offset.
pub struct OffsetInstr {
    pub offset: Offset,
    pub instr: Instruction<Standard>,
}

/// Decodes a code object's bytecode into offset-tagged instructions.
pub fn decode(code: &[u8]) -> Result<Vec<OffsetInstr>, IrError> {
    let mut reader = std::io::Cursor::new(code);
    let mut instrs = Vec::new();
    while (reader.position() as usize) < code.len() {
        let offset = Offset(reader.position() as u32);
        match decode_py27::<Standard, _>(&mut reader) {
            Ok(instr) => instrs.push(OffsetInstr { offset, instr }),
            Err(_) => return Err(IrError::Decode),
        }
    }
    Ok(instrs)
}

/// Computes the set of block-leader offsets: offset 0, every branch target, and
/// the instruction following every branch or return.
fn block_leaders(
    instrs: &[OffsetInstr],
    ternaries: &HashSet<Offset>,
    tries: &[TryShape],
    excluded: &HashSet<Offset>,
    list_interior: &HashSet<Offset>,
    breaks: &HashMap<Offset, Offset>,
) -> Result<Vec<Offset>, IrError> {
    let mut leaders = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.offset);
    }
    // A try's body and every handler clause begin a block; the dispatch between
    // them is excluded, so these leaders are added explicitly rather than falling
    // out of the terminator scan.
    for shape in tries {
        leaders.insert(shape.body_entry);
        leaders.insert(shape.end);
        for clause in &shape.clauses {
            leaders.insert(clause.body_entry);
        }
    }
    for (idx, item) in instrs.iter().enumerate() {
        let mnemonic = item.instr.opcode.mnemonic();
        let next = instrs.get(idx + 1).map(|i| i.offset);
        // A ternary's jumps stay inside their block; do not split there. Handler
        // dispatch instructions and list-comprehension interiors are folded inline
        // and never form blocks, so they do not split either.
        if ternaries.contains(&item.offset)
            || excluded.contains(&item.offset)
            || list_interior.contains(&item.offset)
        {
            continue;
        }
        match terminator_kind(mnemonic)? {
            TerminatorKind::Branch | TerminatorKind::Jump | TerminatorKind::ForIter => {
                // Backward targets are loop back edges; the structurer recovers the
                // loop, so they are allowed here.
                leaders.insert(branch_target(item)?);
                if let Some(next) = next {
                    leaders.insert(next);
                }
            }
            // A break jumps to its loop's follow block (resolved via SETUP_LOOP).
            TerminatorKind::BreakLoop => {
                if let Some(&target) = breaks.get(&item.offset) {
                    leaders.insert(target);
                }
                if let Some(next) = next {
                    leaders.insert(next);
                }
            }
            // SETUP_EXCEPT only falls through to its protected body; its handler is
            // reached by the recovered terminator, not a layout edge.
            TerminatorKind::Try | TerminatorKind::Return | TerminatorKind::Raise => {
                if let Some(next) = next {
                    leaders.insert(next);
                }
            }
            TerminatorKind::None => {}
        }
    }
    // A handler-dispatch offset, or an instruction inside a folded list
    // comprehension, must not start a block.
    leaders.retain(|offset| !excluded.contains(offset) && !list_interior.contains(offset));
    Ok(leaders.into_iter().collect())
}

/// Lowers one block: unstack its body, then read its terminator.
fn lower_block(
    unstacker: &mut Unstacker,
    leader: Offset,
    end: Offset,
    body: &[&OffsetInstr],
    for_header: Option<BlockId>,
    for_targets: &mut HashMap<BlockId, LValue>,
    try_terminators: &HashMap<Offset, Terminator>,
    list_comps: &HashMap<Offset, Offset>,
    breaks: &HashMap<Offset, Offset>,
    else_feeds: &HashMap<Offset, Vec<&OffsetInstr>>,
) -> Result<Block, IrError> {
    unstacker.start_block();

    let last = body.last().ok_or(IrError::Decode)?;
    let mnemonic = last.instr.opcode.mnemonic();
    let kind = terminator_kind(mnemonic)?;

    // A for-loop body begins with the loop target: a single store, or
    // `UNPACK_SEQUENCE` followed by one store per element for a tuple target.
    // Record it and skip it so the remaining body unstacks with a balanced stack.
    let mut start = 0;
    if let Some(header) = for_header {
        let first = body.first().ok_or(IrError::Decode)?;
        if first.instr.opcode.mnemonic() == Mnemonic::UNPACK_SEQUENCE {
            let arity = first.instr.arg.ok_or(IrError::MissingOperand)? as usize;
            let mut targets = Vec::with_capacity(arity);
            for item in body.get(1..1 + arity).ok_or(IrError::Decode)? {
                targets.push(store_target(&item.instr)?);
            }
            for_targets.insert(header, LValue::Tuple(targets));
            start = 1 + arity;
        } else {
            for_targets.insert(header, store_target(&first.instr)?);
            start = 1;
        }
    }

    let feed_end = match kind {
        TerminatorKind::None => body.len(),
        _ => body.len() - 1,
    };
    let feed = &body[start.min(feed_end)..feed_end];
    let mut i = 0;
    while i < feed.len() {
        let item = feed[i];
        // An inline list comprehension is folded as one expression; skip over its
        // whole region once parsed.
        if let Some(&comp_end) = list_comps.get(&item.offset) {
            let span = feed[i..]
                .iter()
                .position(|it| it.offset >= comp_end)
                .map_or(feed.len(), |pos| i + pos);
            unstacker.parse_list_comp(&feed[i..span])?;
            i = span;
            continue;
        }
        // A reordered ternary's else arm is fed here, at the merge, so the otherwise
        // operand is on the stack when the pending ternary resolves.
        if let Some(else_arm) = else_feeds.get(&item.offset) {
            for arm in else_arm {
                unstacker.step(&arm.instr, arm.offset)?;
            }
        }
        unstacker.resolve_pending(item.offset)?;
        unstacker.step(&item.instr, item.offset)?;
        i += 1;
    }
    // Resolve any short-circuit or ternary that merges at the terminator before the
    // terminator consumes its operands. One that merges outside this block is
    // unsupported.
    unstacker.resolve_pending(last.offset)?;
    if !unstacker.pending_resolved() {
        return Err(IrError::Unsupported(Mnemonic::JUMP_IF_FALSE_OR_POP));
    }

    let terminator = match kind {
        TerminatorKind::None => Terminator::Fallthrough(end),
        TerminatorKind::Try => try_terminators
            .get(&last.offset)
            .cloned()
            .ok_or(IrError::Unstructurable)?,
        TerminatorKind::Jump => Terminator::Jump(branch_target(last)?),
        TerminatorKind::BreakLoop => {
            Terminator::Jump(breaks.get(&last.offset).copied().ok_or(IrError::Unstructurable)?)
        }
        TerminatorKind::ForIter => Terminator::ForIter {
            body: end,
            exit: branch_target(last)?,
        },
        TerminatorKind::Return => {
            // A comprehension's final `RETURN_VALUE` returns its accumulator, which
            // is folded away, so there is no value on the stack to pop.
            if unstacker.is_comp() && unstacker.stack_is_empty() {
                Terminator::Return(None)
            } else {
                let value = unstacker.pop_value()?;
                Terminator::Return(Some(value))
            }
        }
        TerminatorKind::Raise => {
            let argc = last.instr.arg.ok_or(IrError::MissingOperand)? as usize;
            if argc > 3 {
                return Err(IrError::BadOperand);
            }
            let mut args = Vec::with_capacity(argc);
            for _ in 0..argc {
                args.push(unstacker.pop_value()?);
            }
            args.reverse();
            Terminator::Raise(args)
        }
        TerminatorKind::Branch => {
            let cond = unstacker.pop_value()?;
            let target = branch_target(last)?;
            let next = end;
            match mnemonic {
                Mnemonic::POP_JUMP_IF_FALSE => Terminator::CondBranch {
                    cond,
                    if_true: next,
                    if_false: target,
                },
                Mnemonic::POP_JUMP_IF_TRUE => Terminator::CondBranch {
                    cond,
                    if_true: target,
                    if_false: next,
                },
                _ => return Err(IrError::HasControlFlow(mnemonic)),
            }
        }
    };

    let stack_out = unstacker.stack_snapshot();
    Ok(Block {
        start: leader,
        stmts: unstacker.take_stmts(),
        terminator,
        stack_out,
        poison: None,
    })
}

/// Extracts the assignment target of a `STORE_*` instruction, used for the loop
/// variable that follows `FOR_ITER`.
fn store_target(instr: &Instruction<Standard>) -> Result<LValue, IrError> {
    let arg = instr.arg.ok_or(IrError::MissingOperand)?;
    Ok(match instr.opcode.mnemonic() {
        Mnemonic::STORE_FAST => LValue::Local(VarId(arg)),
        Mnemonic::STORE_NAME => LValue::Name(NameId(arg)),
        Mnemonic::STORE_GLOBAL => LValue::Global(NameId(arg)),
        Mnemonic::STORE_DEREF => LValue::Deref(DerefId(arg)),
        // Tuple targets (UNPACK_SEQUENCE) are not handled yet.
        other => return Err(IrError::Unsupported(other)),
    })
}

enum TerminatorKind {
    None,
    Jump,
    Branch,
    ForIter,
    Return,
    Raise,
    Try,
    /// `BREAK_LOOP`: an implicit jump out of the enclosing loop, resolved to the
    /// loop's follow block via the `SETUP_LOOP` table.
    BreakLoop,
}

/// Classifies an opcode's effect on control flow, rejecting constructs the
/// structurer does not handle.
fn terminator_kind(mnemonic: Mnemonic) -> Result<TerminatorKind, IrError> {
    Ok(match mnemonic {
        Mnemonic::RETURN_VALUE => TerminatorKind::Return,
        Mnemonic::RAISE_VARARGS => TerminatorKind::Raise,
        // CONTINUE_LOOP has an explicit (absolute) target, so it is an ordinary
        // jump; the structurer recognises a jump to the loop header as `continue`.
        Mnemonic::JUMP_ABSOLUTE | Mnemonic::JUMP_FORWARD | Mnemonic::CONTINUE_LOOP => {
            TerminatorKind::Jump
        }
        Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE => TerminatorKind::Branch,
        Mnemonic::FOR_ITER => TerminatorKind::ForIter,
        Mnemonic::SETUP_EXCEPT => TerminatorKind::Try,
        Mnemonic::BREAK_LOOP => TerminatorKind::BreakLoop,
        Mnemonic::SETUP_FINALLY | Mnemonic::SETUP_WITH | Mnemonic::END_FINALLY => {
            return Err(IrError::HasControlFlow(mnemonic))
        }
        // JUMP_IF_*_OR_POP is a short-circuit operator handled inside a block by the
        // unstacker, not a control-flow terminator.
        _ => TerminatorKind::None,
    })
}

/// Identifies the jump offsets of ternary (`then if cond else otherwise`) diamonds
/// so they can be kept inside one block and rebuilt as an expression. A ternary is
/// a `POP_JUMP_IF_FALSE` whose else target is immediately preceded by a
/// `JUMP_FORWARD` to a later merge, with both arms made only of value-producing
/// opcodes. Anything more complex (statements, nested branches) fails the check and
/// is left to structure as an ordinary `if`.
fn find_ternaries(instrs: &[OffsetInstr]) -> HashSet<Offset> {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut ternaries = HashSet::new();
    for (idx, item) in instrs.iter().enumerate() {
        // A ternary diamond branches on either POP_JUMP form; the unstacker negates
        // the condition for the true form so both render `then if cond else other`.
        if !matches!(
            item.instr.opcode.mnemonic(),
            Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE
        ) {
            continue;
        }
        let Ok(else_target) = branch_target(item) else {
            continue;
        };
        let Some(&else_idx) = index.get(&else_target) else {
            continue;
        };
        if else_idx == 0 {
            continue;
        }
        let jump = &instrs[else_idx - 1];
        if jump.instr.opcode.mnemonic() != Mnemonic::JUMP_FORWARD {
            continue;
        }
        let Ok(merge) = branch_target(jump) else {
            continue;
        };
        if merge <= else_target {
            continue;
        }
        let then_start = Offset(item.offset.0 + item.instr.len() as u32);
        if pure_expression(instrs, then_start, jump.offset)
            && pure_expression(instrs, else_target, merge)
        {
            ternaries.insert(item.offset);
            ternaries.insert(jump.offset);
            // Extend backward over an `and`-chain condition: preceding
            // POP_JUMP_IF_FALSE that also branch to the else, with only
            // value-producing code between, are the earlier `a and b and ...`
            // conditions of a compound test. Marking them keeps the whole diamond
            // (and its merge) in one block so the unstacker can fold it.
            if item.instr.opcode.mnemonic() == Mnemonic::POP_JUMP_IF_FALSE {
                let mut k = idx;
                while k > 0 {
                    k -= 1;
                    let prev = &instrs[k];
                    let prev_mnemonic = prev.instr.opcode.mnemonic();
                    if prev_mnemonic == Mnemonic::POP_JUMP_IF_FALSE
                        && branch_target(prev).ok() == Some(else_target)
                    {
                        ternaries.insert(prev.offset);
                    } else if is_statement_or_control(prev_mnemonic) {
                        break;
                    }
                }
            }
        }
    }
    ternaries
}

/// Whether every instruction in `[start, end)` only produces a value (no stores,
/// control flow, or other statement effects).
fn pure_expression(instrs: &[OffsetInstr], start: Offset, end: Offset) -> bool {
    instrs
        .iter()
        .filter(|item| item.offset >= start && item.offset < end)
        .all(|item| !is_statement_or_control(item.instr.opcode.mnemonic()))
}

/// Whether a mnemonic has a statement-level or control-flow effect, as opposed to
/// just pushing a value.
fn is_statement_or_control(mnemonic: Mnemonic) -> bool {
    let name = format!("{:?}", mnemonic);
    name.starts_with("STORE_")
        || name.starts_with("DELETE_")
        || name.starts_with("PRINT_")
        || name.starts_with("IMPORT_")
        || name.starts_with("SETUP_")
        || name.starts_with("JUMP")
        || name.starts_with("POP_JUMP")
        || name.starts_with("FOR_")
        || name.starts_with("MAKE_")
        || matches!(
            mnemonic,
            Mnemonic::POP_TOP
                | Mnemonic::RETURN_VALUE
                | Mnemonic::RAISE_VARARGS
                | Mnemonic::YIELD_VALUE
                | Mnemonic::END_FINALLY
                | Mnemonic::EXEC_STMT
                | Mnemonic::BREAK_LOOP
                | Mnemonic::CONTINUE_LOOP
                | Mnemonic::POP_BLOCK
                | Mnemonic::LOAD_LOCALS
        )
}

/// Detects ternaries the relinearizer laid out non-contiguously: the then arm
/// jumps forward to a merge placed immediately after it, while the else arm sits
/// elsewhere (after the merge) and jumps back to that same merge. The contiguous
/// [`find_ternaries`] cannot fold these because the else value is not on the stack
/// when the merge is reached.
///
/// Returns the diamond jump offsets to treat as ternary (so the cond block absorbs
/// the merge), the else-arm offsets to exclude from block formation, and a map from
/// each merge offset to the index range of the else arm's value instructions (the
/// trailing jump excluded), to be fed at the merge so the otherwise operand lands on
/// the stack before resolution.
fn find_reordered_ternaries(
    instrs: &[OffsetInstr],
) -> (HashSet<Offset>, HashSet<Offset>, HashMap<Offset, (usize, usize)>) {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut marks = HashSet::new();
    let mut excluded = HashSet::new();
    let mut else_feeds = HashMap::new();
    let is_jump = |idx: usize| instrs[idx].instr.opcode.is_jump();
    for (idx, item) in instrs.iter().enumerate() {
        if !matches!(
            item.instr.opcode.mnemonic(),
            Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE
        ) {
            continue;
        }
        let Ok(else_off) = branch_target(item) else {
            continue;
        };
        let Some(&else_idx) = index.get(&else_off) else {
            continue;
        };
        // The then arm runs from just after the test to its terminating jump.
        let then_start = idx + 1;
        let mut then_jump = then_start;
        while then_jump < instrs.len() && !is_jump(then_jump) {
            then_jump += 1;
        }
        if then_jump >= instrs.len()
            || then_jump < then_start
            || instrs[then_jump].instr.opcode.mnemonic() != Mnemonic::JUMP_FORWARD
        {
            continue;
        }
        let Ok(merge_off) = branch_target(&instrs[then_jump]) else {
            continue;
        };
        // The signature of the reordered diamond: the then arm jumps to a merge that
        // is the immediately following instruction, and the else arm is laid out
        // after that merge (a contiguous ternary has its else before the merge).
        let next_off =
            Offset(instrs[then_jump].offset.0 + instrs[then_jump].instr.len() as u32);
        if merge_off != next_off || else_off <= merge_off {
            continue;
        }
        // The else arm runs from the test's target to its terminating jump, which
        // must rejoin the same merge.
        let mut else_jump = else_idx;
        while else_jump < instrs.len() && !is_jump(else_jump) {
            else_jump += 1;
        }
        if else_jump >= instrs.len() || branch_target(&instrs[else_jump]).ok() != Some(merge_off) {
            continue;
        }
        // Both arms must be pure value expressions.
        if !pure_expression(instrs, instrs[then_start].offset, instrs[then_jump].offset)
            || !pure_expression(instrs, else_off, instrs[else_jump].offset)
        {
            continue;
        }
        marks.insert(item.offset);
        marks.insert(instrs[then_jump].offset);
        for item in &instrs[else_idx..=else_jump] {
            excluded.insert(item.offset);
        }
        else_feeds.insert(merge_off, (else_idx, else_jump));
    }
    (marks, excluded, else_feeds)
}

/// A recovered `try`/`except` region over the raw instruction stream.
struct TryShape {
    /// Offset of the `SETUP_EXCEPT` (the block whose terminator becomes `Try`).
    setup: Offset,
    /// First instruction of the protected body.
    body_entry: Offset,
    /// Merge point reached after the body and every handler.
    end: Offset,
    clauses: Vec<ClauseShape>,
}

/// One recovered `except` clause over the raw instruction stream.
struct ClauseShape {
    /// Index range `[start, end)` of the instructions that load the matched
    /// exception type, or `None` for a bare `except:`.
    type_load: Option<(usize, usize)>,
    name: Option<LValue>,
    /// First instruction of the clause body (after the dispatch and binding).
    body_entry: Offset,
}

/// Recovers every `try`/`except` region and the set of handler-dispatch
/// instruction offsets to drop from blocks. Any `SETUP_EXCEPT` whose surrounding
/// bytecode does not match the regular CPython 2.7 shape rejects the function so
/// it is never decompiled to wrong source.
fn recover_tries(instrs: &[OffsetInstr]) -> Result<(Vec<TryShape>, HashSet<Offset>), IrError> {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut shapes = Vec::new();
    let mut excluded = HashSet::new();
    for (idx, item) in instrs.iter().enumerate() {
        if item.instr.opcode.mnemonic() != Mnemonic::SETUP_EXCEPT {
            continue;
        }
        let shape = recover_try(instrs, &index, idx, &mut excluded)?;
        shapes.push(shape);
    }
    Ok((shapes, excluded))
}

/// Returns the mnemonic at an instruction index, or `Unstructurable` past the end.
fn mnemonic_at(instrs: &[OffsetInstr], idx: usize) -> Result<Mnemonic, IrError> {
    instrs
        .get(idx)
        .map(|item| item.instr.opcode.mnemonic())
        .ok_or(IrError::Unstructurable)
}

/// Recovers a single `try`/`except` rooted at the `SETUP_EXCEPT` at `setup_idx`.
fn recover_try(
    instrs: &[OffsetInstr],
    index: &HashMap<Offset, usize>,
    setup_idx: usize,
    excluded: &mut HashSet<Offset>,
) -> Result<TryShape, IrError> {
    let setup = &instrs[setup_idx];
    let handler_off = branch_target(setup)?;
    let body_entry = instrs.get(setup_idx + 1).ok_or(IrError::Unstructurable)?.offset;
    let handler_idx = *index.get(&handler_off).ok_or(IrError::BadOperand)?;
    // The protected body exits through `POP_BLOCK; JUMP_FORWARD end` immediately
    // before the handler.
    if handler_idx < 2 {
        return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
    }
    let jump = &instrs[handler_idx - 1];
    let end = match jump.instr.opcode.mnemonic() {
        Mnemonic::JUMP_FORWARD | Mnemonic::JUMP_ABSOLUTE => branch_target(jump)?,
        _ => return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT)),
    };
    if mnemonic_at(instrs, handler_idx - 2)? != Mnemonic::POP_BLOCK {
        return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
    }

    let mut clauses = Vec::new();
    let mut clause_idx = handler_idx;
    loop {
        match mnemonic_at(instrs, clause_idx)? {
            // Bare `except:`: discard the exception triple, then run the body. A
            // bare clause matches everything, so it is always the last clause.
            Mnemonic::POP_TOP => {
                if mnemonic_at(instrs, clause_idx + 1)? != Mnemonic::POP_TOP
                    || mnemonic_at(instrs, clause_idx + 2)? != Mnemonic::POP_TOP
                {
                    return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
                }
                let body = instrs.get(clause_idx + 3).ok_or(IrError::Unstructurable)?.offset;
                exclude_range(instrs, clause_idx, clause_idx + 3, excluded);
                clauses.push(ClauseShape { type_load: None, name: None, body_entry: body });
                break;
            }
            // Typed `except T [as name]:`: match the duplicated exception type,
            // and on a match bind the value before the body.
            Mnemonic::DUP_TOP => {
                let mut compare = clause_idx + 1;
                while mnemonic_at(instrs, compare)? != Mnemonic::COMPARE_OP {
                    compare += 1;
                }
                // COMPARE_OP operand 10 is the exception-match comparison.
                if instrs[compare].instr.arg != Some(10) || compare == clause_idx + 1 {
                    return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
                }
                let type_load = (clause_idx + 1, compare);
                if mnemonic_at(instrs, compare + 1)? != Mnemonic::POP_JUMP_IF_FALSE {
                    return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
                }
                let next_off = branch_target(&instrs[compare + 1])?;
                // Matched branch: pop the type, bind or discard the value, pop the
                // traceback.
                let bind = compare + 2;
                if mnemonic_at(instrs, bind)? != Mnemonic::POP_TOP {
                    return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
                }
                let name = match mnemonic_at(instrs, bind + 1)? {
                    Mnemonic::POP_TOP => None,
                    Mnemonic::STORE_FAST
                    | Mnemonic::STORE_NAME
                    | Mnemonic::STORE_GLOBAL
                    | Mnemonic::STORE_DEREF => Some(store_target(&instrs[bind + 1].instr)?),
                    _ => return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT)),
                };
                if mnemonic_at(instrs, bind + 2)? != Mnemonic::POP_TOP {
                    return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
                }
                let body = instrs.get(bind + 3).ok_or(IrError::Unstructurable)?.offset;
                exclude_range(instrs, clause_idx, bind + 3, excluded);
                clauses.push(ClauseShape { type_load: Some(type_load), name, body_entry: body });

                let next_idx = *index.get(&next_off).ok_or(IrError::BadOperand)?;
                // An unmatched typed chain re-raises through END_FINALLY; that is
                // the absence of a catch-all, not another clause.
                if mnemonic_at(instrs, next_idx)? == Mnemonic::END_FINALLY {
                    break;
                }
                clause_idx = next_idx;
            }
            _ => return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT)),
        }
    }

    // The compiler closes a handler chain with an END_FINALLY that re-raises an
    // unmatched exception. A bare `except:` leaves it unreachable rather than
    // removing it. END_FINALLY has no source form, so drop every one in the
    // handler span.
    let end_idx = *index.get(&end).ok_or(IrError::BadOperand)?;
    for item in &instrs[handler_idx..end_idx] {
        if item.instr.opcode.mnemonic() == Mnemonic::END_FINALLY {
            excluded.insert(item.offset);
        }
    }

    Ok(TryShape { setup: setup.offset, body_entry, end, clauses })
}

/// Marks the instruction offsets in `[start, end)` as handler dispatch to drop.
fn exclude_range(instrs: &[OffsetInstr], start: usize, end: usize, excluded: &mut HashSet<Offset>) {
    for item in &instrs[start..end] {
        excluded.insert(item.offset);
    }
}

/// Lowers each try's exception-type expressions through the shared unstacker and
/// assembles the `Try` terminator keyed by its `SETUP_EXCEPT` offset.
fn build_try_terminators(
    unstacker: &mut Unstacker,
    instrs: &[OffsetInstr],
    tries: &[TryShape],
) -> Result<HashMap<Offset, Terminator>, IrError> {
    let mut terminators = HashMap::new();
    for shape in tries {
        let mut handlers = Vec::with_capacity(shape.clauses.len());
        for clause in &shape.clauses {
            let exc_type = match clause.type_load {
                Some((start, end)) => {
                    unstacker.start_block();
                    for item in &instrs[start..end] {
                        unstacker.step(&item.instr, item.offset)?;
                    }
                    let value = unstacker.pop_value()?;
                    // The type loads are pure, but discard any stray statements so
                    // they never leak into the first real block.
                    let _ = unstacker.take_stmts();
                    Some(value)
                }
                None => None,
            };
            handlers.push(HandlerArm {
                exc_type,
                name: clause.name.clone(),
                body: clause.body_entry,
            });
        }
        terminators.insert(
            shape.setup,
            Terminator::Try {
                body: shape.body_entry,
                handlers,
                end: shape.end,
            },
        );
    }
    Ok(terminators)
}

/// Finds inline list comprehensions and the instruction offsets inside them.
/// Each entry maps the `BUILD_LIST 0` offset to the comprehension's end (the
/// `FOR_ITER` exit, where the built list is consumed). Interior offsets, excluding
/// the `BUILD_LIST` itself, must not start blocks so the whole region folds inline.
fn find_list_comps(instrs: &[OffsetInstr]) -> (HashMap<Offset, Offset>, HashSet<Offset>) {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut comps = HashMap::new();
    let mut interior = HashSet::new();
    for (idx, item) in instrs.iter().enumerate() {
        if item.instr.opcode.mnemonic() != Mnemonic::BUILD_LIST || item.instr.arg != Some(0) {
            continue;
        }
        if let Some(end_idx) = recognize_list_comp(instrs, &index, idx) {
            comps.insert(item.offset, instrs[end_idx].offset);
            for inner in &instrs[idx + 1..end_idx] {
                interior.insert(inner.offset);
            }
        }
    }
    (comps, interior)
}

/// Validates that the `BUILD_LIST 0` at `build_idx` begins a single-`for` list
/// comprehension and returns the index of its end (the `FOR_ITER` exit). Anything
/// else (a list literal, a nested or filtered shape the folder cannot parse)
/// returns `None`, leaving the `LIST_APPEND` unsupported so the function is
/// rejected rather than mis-recovered.
fn recognize_list_comp(
    instrs: &[OffsetInstr],
    index: &HashMap<Offset, usize>,
    build_idx: usize,
) -> Option<usize> {
    // The iterable must lead straight into GET_ITER then FOR_ITER.
    let mut for_idx = build_idx + 1;
    loop {
        let mnemonic = instrs.get(for_idx)?.instr.opcode.mnemonic();
        if mnemonic == Mnemonic::FOR_ITER {
            break;
        }
        if disqualifies_list_comp(mnemonic) {
            return None;
        }
        for_idx += 1;
    }
    if instrs.get(for_idx - 1)?.instr.opcode.mnemonic() != Mnemonic::GET_ITER {
        return None;
    }
    let for_iter = &instrs[for_idx];
    let loop_top = for_iter.offset;
    let end = branch_target(for_iter).ok()?;
    let end_idx = *index.get(&end)?;
    if end_idx <= for_idx {
        return None;
    }
    // The loop closes with a back edge to FOR_ITER, and appends exactly once with
    // no nested loop of its own.
    let back = &instrs[end_idx - 1];
    if back.instr.opcode.mnemonic() != Mnemonic::JUMP_ABSOLUTE
        || branch_target(back).ok()? != loop_top
    {
        return None;
    }
    let mut appends = 0;
    for inner in &instrs[for_idx + 1..end_idx] {
        match inner.instr.opcode.mnemonic() {
            Mnemonic::LIST_APPEND => appends += 1,
            Mnemonic::FOR_ITER => return None,
            _ => {}
        }
    }
    if appends != 1 {
        return None;
    }
    Some(end_idx)
}

/// Whether an opcode between `BUILD_LIST 0` and the comprehension's `FOR_ITER`
/// rules out a list comprehension (so the build is an ordinary list literal).
fn disqualifies_list_comp(mnemonic: Mnemonic) -> bool {
    let name = format!("{:?}", mnemonic);
    name.starts_with("STORE_")
        || name.starts_with("DELETE_")
        || name.starts_with("JUMP")
        || name.starts_with("POP_JUMP")
        || name.starts_with("SETUP_")
        || name.starts_with("PRINT_")
        || name.starts_with("IMPORT_")
        || matches!(
            mnemonic,
            Mnemonic::RETURN_VALUE
                | Mnemonic::YIELD_VALUE
                | Mnemonic::POP_TOP
                | Mnemonic::POP_BLOCK
                | Mnemonic::BREAK_LOOP
                | Mnemonic::CONTINUE_LOOP
                | Mnemonic::END_FINALLY
                | Mnemonic::LIST_APPEND
                | Mnemonic::SET_ADD
                | Mnemonic::MAP_ADD
        )
}

/// Recognises chained comparisons (`a < b < c`). The compiler emits each as
/// `DUP_TOP; ROT_THREE; COMPARE; JUMP_IF_FALSE_OR_POP L`, ending with a final
/// `COMPARE; JUMP_FORWARD L2; L: ROT_TWO; POP_TOP`. The `DUP_TOP` makes the middle
/// operand a shared value, so the short-circuit recovers `cmp1 and cmp2 ...`
/// (rendered chained in emit). This returns: the merge offset each
/// `JUMP_IF_FALSE_OR_POP` should use (the value lands after the cleanup at L2, not
/// at its literal target L), and the cleanup/forward-jump offsets to drop.
fn find_chained_comparisons(
    instrs: &[OffsetInstr],
) -> (HashMap<Offset, Offset>, HashSet<Offset>) {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut overrides = HashMap::new();
    let mut excluded = HashSet::new();
    for item in instrs {
        if item.instr.opcode.mnemonic() != Mnemonic::JUMP_IF_FALSE_OR_POP {
            continue;
        }
        let Ok(cleanup) = branch_target(item) else {
            continue;
        };
        let Some(&l_idx) = index.get(&cleanup) else {
            continue;
        };
        // The cleanup at the jump target is exactly ROT_TWO; POP_TOP, preceded by
        // the final comparison's JUMP_FORWARD to the real merge.
        if l_idx == 0
            || instrs[l_idx].instr.opcode.mnemonic() != Mnemonic::ROT_TWO
            || instrs.get(l_idx + 1).map(|i| i.instr.opcode.mnemonic()) != Some(Mnemonic::POP_TOP)
        {
            continue;
        }
        let forward = &instrs[l_idx - 1];
        if forward.instr.opcode.mnemonic() != Mnemonic::JUMP_FORWARD {
            continue;
        }
        let Ok(merge) = branch_target(forward) else {
            continue;
        };
        overrides.insert(item.offset, merge);
        excluded.insert(forward.offset);
        excluded.insert(instrs[l_idx].offset);
        excluded.insert(instrs[l_idx + 1].offset);
    }
    (overrides, excluded)
}

/// Resolves each `BREAK_LOOP` to the offset it jumps to: the block right before
/// the enclosing `SETUP_LOOP`'s follow, which is the loop's follow as the
/// structurer computes it (a `for` loop's `FOR_ITER` exit, a `while` loop's
/// condition-false target). A `break` to that block becomes a `break` statement.
fn break_targets(instrs: &[OffsetInstr]) -> HashMap<Offset, Offset> {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut targets = HashMap::new();
    let mut loops: Vec<Offset> = Vec::new();
    for item in instrs {
        while loops.last().is_some_and(|&follow| item.offset >= follow) {
            loops.pop();
        }
        match item.instr.opcode.mnemonic() {
            Mnemonic::SETUP_LOOP => {
                if let Ok(follow) = branch_target(item) {
                    loops.push(follow);
                }
            }
            Mnemonic::BREAK_LOOP => {
                if let Some(&follow) = loops.last() {
                    if let Some(&idx) = index.get(&follow) {
                        if idx > 0 {
                            targets.insert(item.offset, instrs[idx - 1].offset);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    targets
}

/// Computes the absolute target offset of a branch instruction.
fn branch_target(item: &OffsetInstr) -> Result<Offset, IrError> {
    let arg = item.instr.arg.ok_or(IrError::MissingOperand)? as u32;
    Ok(match item.instr.opcode.mnemonic() {
        Mnemonic::JUMP_ABSOLUTE
        | Mnemonic::POP_JUMP_IF_FALSE
        | Mnemonic::POP_JUMP_IF_TRUE
        | Mnemonic::JUMP_IF_FALSE_OR_POP
        | Mnemonic::JUMP_IF_TRUE_OR_POP
        | Mnemonic::CONTINUE_LOOP => Offset(arg),
        Mnemonic::JUMP_FORWARD
        | Mnemonic::FOR_ITER
        | Mnemonic::SETUP_EXCEPT
        | Mnemonic::SETUP_LOOP => Offset(item.offset.0 + item.instr.len() as u32 + arg),
        other => return Err(IrError::HasControlFlow(other)),
    })
}
