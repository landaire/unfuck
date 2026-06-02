//! Control-flow graph over the statement IR.
//!
//! The function is split into basic blocks at jump targets and after every
//! branch or return. Each block carries its straight-line statements and a typed
//! [`Terminator`] whose conditions reference the shared [`ExprArena`]. Loops are
//! recovered from back edges by the structurer; exception and short-circuit setup
//! are still rejected so the supported surface stays explicit.

use std::collections::{BTreeSet, HashMap, HashSet};

use num_traits::ToPrimitive;
use py27_marshal::{Code, Obj};
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
    /// as blocks. `end` is `None` when the body always raises or returns: the deob
    /// then drops the body's `POP_BLOCK; JUMP merge` exit, so the merge is reachable
    /// only through a handler that falls through and is absorbed into that arm.
    Try {
        body: Offset,
        handlers: Vec<HandlerArm>,
        end: Option<Offset>,
    },
    /// `SETUP_WITH`: a `with` region. `body` is the managed suite; `end` is the
    /// merge after the construct. `target` is the `as` binding, if any. The context
    /// manager expression is the value left on this block's `stack_out`.
    With {
        body: Offset,
        end: Offset,
        target: Option<LValue>,
    },
    /// `SETUP_FINALLY`: a `try`/`finally` region. `body` is the protected suite,
    /// `finalbody` the cleanup that always runs, and `end` the merge after it.
    Finally {
        body: Offset,
        finalbody: Offset,
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
            Terminator::With { body, end, .. } => vec![*body, *end],
            Terminator::Finally { body, finalbody, end } => vec![*body, *finalbody, *end],
            Terminator::Return(_) | Terminator::Raise(_) => Vec::new(),
        }
    }

    /// Successors along normal (non-exceptional) control flow. A `Try` reaches its
    /// protected body; its handlers run only on an exception. Post-dominance over
    /// these edges reflects where ordinary flow converges -- the try's merge point --
    /// even when a handler returns or raises and so never reaches that merge.
    pub fn normal_successors(&self) -> Vec<Offset> {
        match &self.terminator {
            Terminator::Try { body, .. } => vec![*body],
            // The body always reaches `end` through the cleanup; that is the normal
            // convergence point even though the implicit edge runs via WITH_CLEANUP.
            Terminator::With { body, end, .. } => vec![*body, *end],
            // The body falls into the finally, which converges at `end`.
            Terminator::Finally { body, finalbody, .. } => vec![*body, *finalbody],
            _ => self.successors(),
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
        let (withs, with_excluded) = recover_withs(instrs)?;
        excluded.extend(with_excluded);
        let (finallys, finally_excluded) = recover_finallys(instrs)?;
        excluded.extend(finally_excluded);
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
        // stay inside one block and never become block leaders or for-loops. A
        // comprehension used as a ternary then-arm also marks its condition as a
        // ternary diamond, and records the merge where the unstacker completes it.
        let (list_comps, list_interior, comp_ternaries) = find_list_comps(instrs);
        let mut comp_then_merges: HashMap<Offset, Offset> = HashMap::new();
        for (build, (cond, merge)) in &comp_ternaries {
            ternaries.insert(*cond);
            comp_then_merges.insert(*build, *merge);
        }
        let breaks = break_targets(instrs);
        let leaders = block_leaders(
            instrs,
            &ternaries,
            &tries,
            &withs,
            &finallys,
            &excluded,
            &list_interior,
            &breaks,
        )?;
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
        let with_terminators = build_with_terminators(&mut unstacker, instrs, &withs)?;
        let finally_terminators = build_finally_terminators(&finallys);

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
                &with_terminators,
                &finally_terminators,
                &list_comps,
                &breaks,
                &else_feeds,
                &comp_then_merges,
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

/// Replaces the obfuscator's no-op `JUMP_FORWARD 0` instructions with `NOP`s. A
/// forward jump of zero lands on the very next instruction, so it does nothing but
/// fragment a basic block and break the straight-line pattern matching the list
/// comprehension and ternary recognizers rely on. Real 2.7 bytecode never emits a
/// zero forward jump, so this is unambiguous and offset-preserving.
pub fn strip_noop_jumps(instrs: &mut [OffsetInstr]) {
    for item in instrs {
        if item.instr.opcode.mnemonic() == Mnemonic::JUMP_FORWARD && item.instr.arg == Some(0) {
            item.instr.opcode = Standard::NOP;
            item.instr.arg = None;
        }
    }
}

/// Neutralizes the obfuscator's opaque-predicate stack injections.
///
/// The obfuscator splices a block of the shape `LOAD_CONST <5-int tuple ending in
/// 255>; UNPACK_SEQUENCE 5; STORE_NAME x5` followed by pure set/comparison
/// arithmetic over those temps in between a producer (an `IMPORT_NAME`, a
/// `LOAD_CONST <code>`, a `BUILD_CLASS`) and its consumer (`IMPORT_FROM`,
/// `MAKE_FUNCTION`, `STORE_NAME`, ...). The block leaves junk on the stack that
/// buries the consumer's real operand, so the bytecode cannot run in CPython -- it
/// is pure dead injection meant to defeat decompilation.
///
/// Each matched block is overwritten with `NOP`s, which preserves every byte offset
/// and jump target (so the surrounding control flow is untouched). A block is only
/// neutralized when a stack simulation proves it self-contained: measured from the
/// block's entry, the simulated depth never drops below zero, so the block only ever
/// manipulates values it itself pushed and removing it cannot disturb the real
/// operand sitting beneath it. The very specific head (a random-looking 5-int tuple
/// ending in 255 unpacked straight into set arithmetic) does not occur in real code.
pub fn strip_opaque_predicates(instrs: &mut [OffsetInstr], code: &Code) {
    let mut i = 0;
    while i < instrs.len() {
        if let Some(end) = opaque_block_end(instrs, i, code) {
            for slot in &mut instrs[i..end] {
                slot.instr.opcode = Standard::NOP;
                slot.instr.arg = None;
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

/// Returns the exclusive end index of an opaque-predicate block starting at `start`,
/// or `None` if `start` is not the head of one or it is not provably safe to remove.
fn opaque_block_end(instrs: &[OffsetInstr], start: usize, code: &Code) -> Option<usize> {
    if instrs[start].instr.opcode.mnemonic() != Mnemonic::LOAD_CONST {
        return None;
    }
    let const_idx = instrs[start].instr.arg? as usize;
    if !is_obfuscation_tuple(code.consts.get(const_idx)?) {
        return None;
    }
    if instrs.get(start + 1)?.instr.opcode.mnemonic() != Mnemonic::UNPACK_SEQUENCE {
        return None;
    }

    let mut junk_temps: HashSet<u16> = HashSet::new();
    let mut pending_unpack: u16 = 0;
    let mut depth: isize = 0;
    let mut saw_op = false;
    let mut end = start;
    // How the scan terminated: a below-entry consumer (an instruction reaching down
    // past the block into the buried operand) is always a safe boundary; otherwise
    // the boundary is safe only if the stopping opcode is a recognized non-arithmetic
    // consumer (see `is_safe_consumer`). Stopping at an unrecognized arithmetic op
    // would mean an incomplete junk block, so it is rejected rather than half-removed.
    let mut stopped_below_entry = false;
    for (idx, item) in instrs.iter().enumerate().skip(start) {
        let mnemonic = item.instr.opcode.mnemonic();
        // `pops` is how many stack values the instruction consumes, or `None` if it is
        // not a junk-block opcode (so it terminates the block).
        let pops: Option<isize> = if let Some(p) = pure_value_pops(&item.instr) {
            saw_op |= mnemonic != Mnemonic::LOAD_CONST;
            Some(p)
        } else {
            match mnemonic {
                Mnemonic::UNPACK_SEQUENCE => {
                    pending_unpack = item.instr.arg.unwrap_or(0);
                    Some(1)
                }
                // The unpack targets become known junk temps; later stores are part
                // of the block only when they re-store one of those temps.
                Mnemonic::STORE_NAME => match item.instr.arg {
                    Some(name) if pending_unpack > 0 => {
                        junk_temps.insert(name);
                        pending_unpack -= 1;
                        Some(1)
                    }
                    Some(name) if junk_temps.contains(&name) => Some(1),
                    _ => None,
                },
                Mnemonic::LOAD_NAME if item.instr.arg.is_some_and(|n| junk_temps.contains(&n)) => {
                    Some(0)
                }
                _ => None,
            }
        };
        match pops {
            // A junk opcode that stays within the block's own pushed values.
            Some(pops) if depth >= pops => {
                depth += item.instr.stack_adjustment_after();
                end = idx + 1;
            }
            // A junk-class opcode that reaches below the block entry: this is the real
            // consumer of the buried operand (e.g. a `BUILD_TUPLE` combining the junk
            // with a value pushed before the block). A safe place to end.
            Some(_) => {
                stopped_below_entry = true;
                end = idx;
                break;
            }
            None => {
                end = idx;
                break;
            }
        }
    }

    // The block must leave junk behind (the buried operand sits below it), and that
    // junk must come from real opaque work: either arithmetic/set grinding over the
    // temps, or an incomplete unpack (more values produced than stored -- a shape
    // real code never emits). This rejects an ordinary `a, b, c, d, e = (..., 255)`
    // unpack whose values are then used, which leaves no junk and stores every one.
    if depth < 1 || !(saw_op || pending_unpack > 0) {
        return None;
    }
    // The boundary must be trustworthy: either a below-entry consumer, or a known
    // non-arithmetic consumer opcode. If the scan stopped at some opcode we do not
    // model (an arithmetic op missing from `pure_value_pops`), the block would be
    // only partially recognized and removing it could corrupt the stack, so bail.
    let safe_boundary =
        stopped_below_entry || (end < instrs.len() && is_safe_consumer(instrs[end].instr.opcode.mnemonic()));
    if !safe_boundary {
        return None;
    }
    // Trailing constant loads belong to the consumer that follows the block, not to
    // the junk: when the obfuscator splices its block into the middle of an operand
    // setup (e.g. between an import's level and its fromlist), the trailing
    // `LOAD_CONST` is the next real operand. A constant load pushes without consuming,
    // so leaving it in place is always safe; removing it would underflow the consumer.
    while end > start && instrs[end - 1].instr.opcode.mnemonic() == Mnemonic::LOAD_CONST {
        end -= 1;
        depth -= 1;
    }
    // After trimming, the block must still leave junk behind (depth >= 1) and end on a
    // junk-consuming op, not have collapsed to bare setup.
    if depth < 1 {
        return None;
    }
    // The temps it computes must be dead: if any is read outside the block, it is a
    // real variable and removing its stores would change behavior. Together with the
    // self-containment proof above, a block read by nothing outside itself is dead
    // code that only ever left junk on the stack, so neutralizing it is sound.
    let read_outside = instrs.iter().enumerate().any(|(idx, item)| {
        (idx < start || idx >= end)
            && item.instr.opcode.mnemonic() == Mnemonic::LOAD_NAME
            && item.instr.arg.is_some_and(|n| junk_temps.contains(&n))
    });
    if read_outside {
        return None;
    }
    Some(end)
}

/// The number of stack values a pure value-producing opcode consumes, or `None` if
/// the opcode is not one of these. "Pure" here means it computes a value purely from
/// the stack and constants -- the building blocks of an opaque-predicate block.
/// Constants and loads pop nothing; unary ops and `DUP_TOP` pop one; binary,
/// in-place, and comparison ops pop two; `BUILD_*` pops its operand count.
fn pure_value_pops(instr: &Instruction<Standard>) -> Option<isize> {
    use Mnemonic::*;
    Some(match instr.opcode.mnemonic() {
        LOAD_CONST => 0,
        UNARY_POSITIVE | UNARY_NEGATIVE | UNARY_NOT | UNARY_INVERT | UNARY_CONVERT | DUP_TOP => 1,
        BINARY_POWER | BINARY_MULTIPLY | BINARY_DIVIDE | BINARY_MODULO | BINARY_ADD
        | BINARY_SUBTRACT | BINARY_SUBSC | BINARY_FLOOR_DIVIDE | BINARY_TRUE_DIVIDE
        | BINARY_LSHIFT | BINARY_RSHIFT | BINARY_AND | BINARY_XOR | BINARY_OR | INPLACE_POWER
        | INPLACE_MULTIPLY | INPLACE_DIVIDE | INPLACE_MODULO | INPLACE_ADD | INPLACE_SUBTRACT
        | INPLACE_FLOOR_DIVIDE | INPLACE_TRUE_DIVIDE | INPLACE_LSHIFT | INPLACE_RSHIFT
        | INPLACE_AND | INPLACE_XOR | INPLACE_OR | COMPARE_OP | ROT_TWO => 2,
        ROT_THREE => 3,
        BUILD_TUPLE | BUILD_LIST | BUILD_SET => instr.arg.unwrap_or(0) as isize,
        _ => return None,
    })
}

/// Whether `mnemonic` is a non-arithmetic opcode that may legitimately consume an
/// opaque block's junk (or follow it). These are the operand-burial victims and
/// plain terminators; crucially none of them is a pure value op, so if the block
/// scan stops here it has not been cut short in the middle of junk arithmetic.
fn is_safe_consumer(mnemonic: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        mnemonic,
        IMPORT_NAME
            | IMPORT_FROM
            | IMPORT_STAR
            | MAKE_FUNCTION
            | MAKE_CLOSURE
            | BUILD_CLASS
            | CALL_FUNCTION
            | CALL_FUNCTION_VAR
            | CALL_FUNCTION_KW
            | CALL_FUNCTION_VAR_KW
            | STORE_NAME
            | STORE_FAST
            | STORE_GLOBAL
            | STORE_DEREF
            | POP_TOP
            | RETURN_VALUE
            | PRINT_ITEM
            | PRINT_NEWLINE
            | YIELD_VALUE
    )
}

/// Whether `obj` is the obfuscator's marker constant: a 5-element tuple of integers
/// ending in 255. Real code essentially never feeds such a tuple straight into the
/// `UNPACK_SEQUENCE`/set-arithmetic shape these blocks take.
fn is_obfuscation_tuple(obj: &Obj) -> bool {
    let Obj::Tuple(items) = obj else {
        return false;
    };
    let items = items.read().unwrap();
    items.len() == 5
        && items.iter().all(|o| matches!(o, Obj::Long(_)))
        && matches!(items.last(), Some(Obj::Long(v)) if v.read().unwrap().to_i64() == Some(255))
}

/// Computes the set of block-leader offsets: offset 0, every branch target, and
/// the instruction following every branch or return.
fn block_leaders(
    instrs: &[OffsetInstr],
    ternaries: &HashSet<Offset>,
    tries: &[TryShape],
    withs: &[WithShape],
    finallys: &[FinallyShape],
    excluded: &HashSet<Offset>,
    list_interior: &HashSet<Offset>,
    breaks: &HashMap<Offset, Offset>,
) -> Result<Vec<Offset>, IrError> {
    let mut leaders = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.offset);
    }
    // A with's managed body and its merge begin blocks; the binding and cleanup
    // between them are excluded, so add these leaders explicitly.
    for shape in withs {
        leaders.insert(shape.body_entry);
        leaders.insert(shape.end);
    }
    // A try/finally's body, its finally clause, and its merge each begin a block.
    for shape in finallys {
        leaders.insert(shape.body_entry);
        leaders.insert(shape.finalbody);
        leaders.insert(shape.end);
    }
    // A try's body and every handler clause begin a block; the dispatch between
    // them is excluded, so these leaders are added explicitly rather than falling
    // out of the terminator scan.
    for shape in tries {
        leaders.insert(shape.body_entry);
        // A merge-less try has no explicit merge leader; when a handler falls
        // through, the terminator scan adds its jump target as a leader.
        if let Some(end) = shape.end {
            leaders.insert(end);
        }
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
            // SETUP_EXCEPT/SETUP_WITH/SETUP_FINALLY only fall through to their managed
            // body; the recovered terminator supplies the other edges.
            TerminatorKind::Try
            | TerminatorKind::With
            | TerminatorKind::Finally
            | TerminatorKind::Return
            | TerminatorKind::Raise => {
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
    with_terminators: &HashMap<Offset, Terminator>,
    finally_terminators: &HashMap<Offset, Terminator>,
    list_comps: &HashMap<Offset, Offset>,
    breaks: &HashMap<Offset, Offset>,
    else_feeds: &HashMap<Offset, Vec<&OffsetInstr>>,
    comp_then_merges: &HashMap<Offset, Offset>,
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
            // When the comprehension is a ternary then-arm, its value becomes the
            // pending diamond's then, completed at the FOR_ITER exit (the merge).
            if let Some(&merge) = comp_then_merges.get(&item.offset) {
                unstacker.set_comp_ternary_then(merge)?;
            }
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
    // Flush a `print a,` whose suppressed newline left no PRINT_NEWLINE before the
    // block's terminator runs.
    unstacker.flush_print();

    // Resolve any short-circuit or ternary that merges at the terminator before the
    // terminator consumes its operands. One that merges outside this block is
    // unsupported.
    unstacker.resolve_pending(last.offset)?;
    if !unstacker.pending_resolved() {
        // A returned short-circuit expression (`return X and Y`) whose arm is itself
        // a chained comparison returns from the arm directly, so the operators never
        // reach a merge and their false exits are dead blocks. Fold the pending
        // operators into the value being returned; the dead exits are pruned.
        if matches!(kind, TerminatorKind::Return) {
            unstacker.force_resolve_shortcircuits()?;
        }
        if !unstacker.pending_resolved() {
            return Err(IrError::Unsupported(Mnemonic::JUMP_IF_FALSE_OR_POP));
        }
    }

    let terminator = match kind {
        TerminatorKind::None => Terminator::Fallthrough(end),
        TerminatorKind::Try => try_terminators
            .get(&last.offset)
            .cloned()
            .ok_or(IrError::Unstructurable)?,
        // The context manager expression stays on the stack (it is not consumed by
        // the terminator), so it reaches the structurer through `stack_out`.
        TerminatorKind::With => {
            with_terminators.get(&last.offset).cloned().ok_or(IrError::Unstructurable)?
        }
        TerminatorKind::Finally => {
            finally_terminators.get(&last.offset).cloned().ok_or(IrError::Unstructurable)?
        }
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
    With,
    Finally,
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
        Mnemonic::SETUP_WITH => TerminatorKind::With,
        Mnemonic::SETUP_FINALLY => TerminatorKind::Finally,
        Mnemonic::BREAK_LOOP => TerminatorKind::BreakLoop,
        Mnemonic::END_FINALLY => return Err(IrError::HasControlFlow(mnemonic)),
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
        if pure_ternary_arm(instrs, then_start, jump.offset, merge)
            && pure_ternary_arm(instrs, else_target, merge, merge)
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

/// Whether `[start, end)` is a value-producing ternary arm. Like `pure_expression`,
/// but a short-circuit `JUMP_IF_FALSE_OR_POP`/`JUMP_IF_TRUE_OR_POP` is allowed when it
/// jumps to `merge` (the ternary's merge): such a jump is part of an `and`/`or` value
/// that short-circuits straight to the arm's result, e.g. the `a or b and c` of
/// `(a or b and c) if cond else d`. The unstacker folds these into the arm value at
/// the closing JUMP_FORWARD (see its handler). A short-circuit to any other target is
/// a nested boolean with its own internal merge that this in-block folding does not
/// model, so it is treated as impure and the diamond structures as an ordinary `if`.
fn pure_ternary_arm(instrs: &[OffsetInstr], start: Offset, end: Offset, merge: Offset) -> bool {
    instrs
        .iter()
        .filter(|item| item.offset >= start && item.offset < end)
        .all(|item| {
            let mnemonic = item.instr.opcode.mnemonic();
            if matches!(
                mnemonic,
                Mnemonic::JUMP_IF_FALSE_OR_POP | Mnemonic::JUMP_IF_TRUE_OR_POP
            ) {
                return branch_target(item).ok() == Some(merge);
            }
            !is_statement_or_control(mnemonic)
        })
}

/// Whether a mnemonic has a statement-level or control-flow effect, as opposed to
/// just pushing a value.
pub(crate) fn is_statement_or_control(mnemonic: Mnemonic) -> bool {
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
    /// Merge point reached after the body and every handler, or `None` when the
    /// body has no normal exit (always raises or returns) and the deob dropped the
    /// `POP_BLOCK; JUMP merge` body exit.
    end: Option<Offset>,
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

/// A recovered `with` region over the raw instruction stream.
struct WithShape {
    /// Offset of the `SETUP_WITH` (the block whose terminator becomes `With`).
    setup: Offset,
    /// First instruction of the managed body, after the `as` binding.
    body_entry: Offset,
    /// Merge point reached after the construct (past `END_FINALLY`).
    end: Offset,
    /// The `as` target for a discard (`None`) or a simple-name store. An attribute
    /// target (`with x as obj.attr:`) is carried by `attr_bind` instead, since its
    /// object expression must be lowered through the unstacker.
    target: Option<LValue>,
    /// An attribute `as` target: the `[start, end)` instruction range of the pure
    /// attribute-chain load that produces the object, and the stored attribute name.
    attr_bind: Option<(usize, usize, NameId)>,
}

/// Recovers every `with` region and the structural instruction offsets to drop from
/// blocks. A `SETUP_WITH` whose surrounding bytecode is not the regular CPython 2.7
/// shape rejects the function rather than risk wrong source.
fn recover_withs(instrs: &[OffsetInstr]) -> Result<(Vec<WithShape>, HashSet<Offset>), IrError> {
    let index: HashMap<Offset, usize> =
        instrs.iter().enumerate().map(|(i, it)| (it.offset, i)).collect();
    let mut shapes = Vec::new();
    let mut excluded = HashSet::new();
    for (idx, item) in instrs.iter().enumerate() {
        if item.instr.opcode.mnemonic() == Mnemonic::SETUP_WITH {
            shapes.push(recover_with(instrs, &index, idx, &mut excluded)?);
        }
    }
    Ok((shapes, excluded))
}

/// Recovers a single `with` rooted at the `SETUP_WITH` at `setup_idx`. The shape is
/// `<ctx>; SETUP_WITH cleanup; STORE/POP_TOP; <body>; POP_BLOCK; LOAD_CONST None;
/// cleanup: WITH_CLEANUP; END_FINALLY`.
fn recover_with(
    instrs: &[OffsetInstr],
    index: &HashMap<Offset, usize>,
    setup_idx: usize,
    excluded: &mut HashSet<Offset>,
) -> Result<WithShape, IrError> {
    let setup = &instrs[setup_idx];
    let cleanup_off = branch_target(setup)?;
    // The SETUP_WITH target is the cleanup, but the relinearizer can interpose
    // NOP trampolines (former `JUMP_FORWARD 0`s) before the real WITH_CLEANUP, so
    // skip them.
    let cleanup_target_idx = *index.get(&cleanup_off).ok_or(IrError::BadOperand)?;
    let cleanup_idx = skip_nops(instrs, cleanup_target_idx);
    // The `as` binding (or a discarding POP_TOP) immediately follows SETUP_WITH.
    let bind_idx = setup_idx + 1;
    // The last instruction of the `as` binding; `body_entry` is the one after it.
    let mut bind_end = bind_idx;
    let mut attr_bind = None;
    let target = match mnemonic_at(instrs, bind_idx)? {
        Mnemonic::POP_TOP => None,
        Mnemonic::STORE_FAST
        | Mnemonic::STORE_NAME
        | Mnemonic::STORE_GLOBAL
        | Mnemonic::STORE_DEREF => Some(store_target(&instrs[bind_idx].instr)?),
        // `with x as obj.attr:` stores into an attribute: a pure attribute-chain
        // load of the object, then STORE_ATTR. Lower the object later (it needs the
        // unstacker); reject anything that is not a clean load chain.
        _ => {
            let mut i = bind_idx;
            while is_attr_chain_load(mnemonic_at(instrs, i)?) {
                i += 1;
            }
            if i == bind_idx || mnemonic_at(instrs, i)? != Mnemonic::STORE_ATTR {
                return Err(IrError::HasControlFlow(Mnemonic::SETUP_WITH));
            }
            let name = NameId(instrs[i].instr.arg.ok_or(IrError::MissingOperand)?);
            attr_bind = Some((bind_idx, i, name));
            bind_end = i;
            None
        }
    };
    let body_entry = instrs.get(bind_end + 1).ok_or(IrError::Unstructurable)?.offset;
    // The body exits through POP_BLOCK; find it at block-nesting depth 0 so a nested
    // try/with inside the body does not steal it.
    let mut depth = 0i32;
    let mut pop_idx = None;
    for i in (bind_idx + 1)..cleanup_idx {
        let mnemonic = instrs[i].instr.opcode.mnemonic();
        if format!("{:?}", mnemonic).starts_with("SETUP_") {
            depth += 1;
        } else if mnemonic == Mnemonic::POP_BLOCK {
            if depth == 0 {
                // Skip an orphan POP_BLOCK from a loop whose SETUP_LOOP the deob
                // dropped (it sits right before the with's own POP_BLOCK); see
                // recover_finally.
                if mnemonic_at(instrs, i + 1)? == Mnemonic::POP_BLOCK {
                    continue;
                }
                pop_idx = Some(i);
                break;
            }
            depth -= 1;
        }
    }
    // The cleanup (WITH_CLEANUP; END_FINALLY) runs on every exit, so it is present
    // and the merge always follows it. The normal-exit `POP_BLOCK; LOAD_CONST None`
    // precedes it, but the deob drops that as unreachable when the body always raises
    // or returns, leaving no body POP_BLOCK. The merge stays reachable because
    // `__exit__` may suppress the exception, so it is kept (not `None` as for `try`).
    if mnemonic_at(instrs, cleanup_idx)? != Mnemonic::WITH_CLEANUP
        || mnemonic_at(instrs, cleanup_idx + 1)? != Mnemonic::END_FINALLY
    {
        return Err(IrError::HasControlFlow(Mnemonic::SETUP_WITH));
    }
    // The normal exit is `POP_BLOCK; LOAD_CONST None; <filler>` where <filler> is the
    // relinearizer's trampoline jumps/NOPs to the cleanup (possibly empty in the
    // contiguous CPython layout). Drop POP_BLOCK and everything up to the cleanup so
    // the body falls through to the merge; require that span to be only filler so an
    // unexpected layout rejects rather than mis-structures.
    if let Some(pop_idx) = pop_idx {
        if mnemonic_at(instrs, pop_idx + 1)? != Mnemonic::LOAD_CONST {
            return Err(IrError::HasControlFlow(Mnemonic::SETUP_WITH));
        }
        for i in (pop_idx + 1)..cleanup_idx {
            if !is_exit_filler(mnemonic_at(instrs, i)?) {
                return Err(IrError::HasControlFlow(Mnemonic::SETUP_WITH));
            }
        }
        // Keep the POP_BLOCK itself: the relinearizer can make it a join point that
        // body branches jump to, so dropping it would orphan those jumps. As a no-op
        // it forms an empty block that falls through to the merge. Drop everything
        // after it up to the cleanup (the LOAD_CONST None and trampoline jumps).
        for i in (pop_idx + 1)..cleanup_idx {
            excluded.insert(instrs[i].offset);
        }
    } else {
        // No normal POP_BLOCK exit (the body always raises/returns): only the target
        // trampoline NOPs precede the cleanup. Drop them.
        for i in cleanup_target_idx..cleanup_idx {
            excluded.insert(instrs[i].offset);
        }
    }
    // The merge follows END_FINALLY, again possibly past trampoline NOPs.
    let end = instrs
        .get(skip_nops(instrs, cleanup_idx + 2))
        .ok_or(IrError::Unstructurable)?
        .offset;
    // Drop the binding (all of it, for an attribute target) and the cleanup
    // machinery so they never form blocks.
    for i in bind_idx..=bind_end {
        excluded.insert(instrs[i].offset);
    }
    for off in [instrs[cleanup_idx].offset, instrs[cleanup_idx + 1].offset] {
        excluded.insert(off);
    }
    Ok(WithShape { setup: setup.offset, body_entry, end, target, attr_bind })
}

/// Whether an opcode is a pure load that can build a `with`-target attribute chain
/// (`obj.a.b` in `with x as obj.a.b.c:`): a name/const load or an attribute access.
fn is_attr_chain_load(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::LOAD_FAST
            | Mnemonic::LOAD_DEREF
            | Mnemonic::LOAD_NAME
            | Mnemonic::LOAD_GLOBAL
            | Mnemonic::LOAD_CONST
            | Mnemonic::LOAD_ATTR
    )
}

/// Builds each `with` block's `With` terminator from its recovered shape. An
/// attribute `as` target has its object expression lowered through the shared
/// unstacker here (the pre-pass has no arena), mirroring `build_try_terminators`.
fn build_with_terminators(
    unstacker: &mut Unstacker,
    instrs: &[OffsetInstr],
    withs: &[WithShape],
) -> Result<HashMap<Offset, Terminator>, IrError> {
    let mut terminators = HashMap::new();
    for w in withs {
        let target = match w.attr_bind {
            Some((start, end, name)) => {
                unstacker.start_block();
                for item in &instrs[start..end] {
                    unstacker.step(&item.instr, item.offset)?;
                }
                let obj = unstacker.pop_value()?;
                // The loads are pure; drop any stray statements so they never leak.
                let _ = unstacker.take_stmts();
                Some(LValue::Attr(obj, name))
            }
            None => w.target.clone(),
        };
        terminators.insert(w.setup, Terminator::With { body: w.body_entry, end: w.end, target });
    }
    Ok(terminators)
}

/// A recovered `try`/`finally` region over the raw instruction stream.
struct FinallyShape {
    /// Offset of the `SETUP_FINALLY` (the block whose terminator becomes `Finally`).
    setup: Offset,
    /// First instruction of the protected body.
    body_entry: Offset,
    /// First instruction of the finally clause.
    finalbody: Offset,
    /// Merge point reached after the construct (past the finally's `END_FINALLY`).
    end: Offset,
}

/// Recovers every `try`/`finally` region and the `END_FINALLY` offsets to drop. A
/// `SETUP_FINALLY` whose surrounding bytecode is not the regular CPython 2.7 shape
/// rejects the function rather than risk wrong source.
fn recover_finallys(
    instrs: &[OffsetInstr],
) -> Result<(Vec<FinallyShape>, HashSet<Offset>), IrError> {
    let index: HashMap<Offset, usize> =
        instrs.iter().enumerate().map(|(i, it)| (it.offset, i)).collect();
    let mut shapes = Vec::new();
    let mut excluded = HashSet::new();
    for (idx, item) in instrs.iter().enumerate() {
        if item.instr.opcode.mnemonic() == Mnemonic::SETUP_FINALLY {
            shapes.push(recover_finally(instrs, &index, idx, &mut excluded)?);
        }
    }
    Ok((shapes, excluded))
}

/// Recovers a single `try`/`finally` rooted at the `SETUP_FINALLY` at `setup_idx`.
/// The shape is `SETUP_FINALLY fin; <body>; POP_BLOCK; LOAD_CONST None; fin:
/// <finalbody>; END_FINALLY`. The `POP_BLOCK`/`LOAD_CONST None` stay in the body
/// (a no-op and a discarded sentinel) so a nested try/except whose merge is that
/// `POP_BLOCK` still forms its block; only the finally's `END_FINALLY` is dropped.
fn recover_finally(
    instrs: &[OffsetInstr],
    index: &HashMap<Offset, usize>,
    setup_idx: usize,
    excluded: &mut HashSet<Offset>,
) -> Result<FinallyShape, IrError> {
    let setup = &instrs[setup_idx];
    let finalbody_off = branch_target(setup)?;
    // The SETUP_FINALLY target can land on a relinearizer trampoline before the real
    // finally body, so skip NOPs/no-op jumps.
    let finalbody_target_idx = *index.get(&finalbody_off).ok_or(IrError::BadOperand)?;
    let finalbody_idx = skip_nops(instrs, finalbody_target_idx);
    let finalbody_off = instrs[finalbody_idx].offset;
    let body_entry = instrs.get(setup_idx + 1).ok_or(IrError::Unstructurable)?.offset;
    // The body exits through its `POP_BLOCK` at block-nesting depth 0.
    let mut depth = 0i32;
    let mut pop_idx = None;
    for i in (setup_idx + 1)..finalbody_idx {
        let mnemonic = instrs[i].instr.opcode.mnemonic();
        if format!("{:?}", mnemonic).starts_with("SETUP_") {
            depth += 1;
        } else if mnemonic == Mnemonic::POP_BLOCK {
            if depth == 0 {
                // A `for` loop ending the try body has its own POP_BLOCK; the deob can
                // drop that loop's SETUP_LOOP while keeping the POP_BLOCK, leaving an
                // orphan at depth 0 right before the finally's own POP_BLOCK. The
                // finally's is followed by `LOAD_CONST None`, never by another
                // POP_BLOCK, so skip an orphan (POP_BLOCK followed by POP_BLOCK).
                if mnemonic_at(instrs, i + 1)? == Mnemonic::POP_BLOCK {
                    continue;
                }
                pop_idx = Some(i);
                break;
            }
            depth -= 1;
        }
    }
    // The normal-exit `POP_BLOCK; LOAD_CONST None;` precedes the finally body, but the
    // deob drops it as unreachable when the body always raises or returns, leaving no
    // body POP_BLOCK. The finally body and merge are derived from the SETUP_FINALLY
    // target and its END_FINALLY, not from this POP_BLOCK, and structuring the body to
    // the finally is the correct flow whether the body falls through or exits
    // abnormally, so a missing POP_BLOCK is sound without further checks.
    if let Some(pop_idx) = pop_idx {
        if mnemonic_at(instrs, pop_idx + 1)? != Mnemonic::LOAD_CONST {
            return Err(IrError::HasControlFlow(Mnemonic::SETUP_FINALLY));
        }
        // The span between the LOAD_CONST sentinel and the finally body is the
        // relinearizer's trampoline filler (jumps/NOPs); require it and drop it so it
        // forms no spurious block. POP_BLOCK and LOAD_CONST stay (a nested try merge
        // may target the POP_BLOCK).
        for i in (pop_idx + 2)..finalbody_idx {
            if !is_exit_filler(mnemonic_at(instrs, i)?) {
                return Err(IrError::HasControlFlow(Mnemonic::SETUP_FINALLY));
            }
            excluded.insert(instrs[i].offset);
        }
    }
    // The finally clause ends at its own `END_FINALLY` at depth 0.
    let mut depth = 0i32;
    let mut end_idx = None;
    for i in finalbody_idx..instrs.len() {
        let mnemonic = instrs[i].instr.opcode.mnemonic();
        if format!("{:?}", mnemonic).starts_with("SETUP_") {
            depth += 1;
        } else if mnemonic == Mnemonic::END_FINALLY {
            if depth == 0 {
                end_idx = Some(i);
                break;
            }
            depth -= 1;
        }
    }
    let end_idx = end_idx.ok_or(IrError::HasControlFlow(Mnemonic::SETUP_FINALLY))?;
    let end = instrs
        .get(skip_nops(instrs, end_idx + 1))
        .ok_or(IrError::Unstructurable)?
        .offset;
    excluded.insert(instrs[end_idx].offset);
    Ok(FinallyShape { setup: setup.offset, body_entry, finalbody: finalbody_off, end })
}

/// Builds each `try`/`finally` block's `Finally` terminator from its shape.
fn build_finally_terminators(finallys: &[FinallyShape]) -> HashMap<Offset, Terminator> {
    finallys
        .iter()
        .map(|f| {
            (
                f.setup,
                Terminator::Finally { body: f.body_entry, finalbody: f.finalbody, end: f.end },
            )
        })
        .collect()
}

/// Returns the mnemonic at an instruction index, or `Unstructurable` past the end.
fn mnemonic_at(instrs: &[OffsetInstr], idx: usize) -> Result<Mnemonic, IrError> {
    instrs
        .get(idx)
        .map(|item| item.instr.opcode.mnemonic())
        .ok_or(IrError::Unstructurable)
}

/// Advances `idx` past no-op trampolines: a `NOP` (a `JUMP_FORWARD 0` that
/// `strip_noop_jumps` rewrote) or a still-raw `JUMP_FORWARD 0`. The relinearizer
/// leaves these so a region's cleanup/merge target can land on one instead of the
/// real instruction; both fall straight through to the next instruction.
fn skip_nops(instrs: &[OffsetInstr], mut idx: usize) -> usize {
    while let Some(item) = instrs.get(idx) {
        let mnemonic = item.instr.opcode.mnemonic();
        let is_noop_jump = mnemonic == Mnemonic::JUMP_FORWARD && item.instr.arg == Some(0);
        if mnemonic == Mnemonic::NOP || is_noop_jump {
            idx += 1;
        } else {
            break;
        }
    }
    idx
}

/// Whether `mnemonic` is the kind of instruction the relinearizer leaves between a
/// `with`/`try` body's exit and its cleanup: the `LOAD_CONST None` pushed for the
/// normal exit, a `NOP` trampoline, or an unconditional jump to the cleanup. Such a
/// span is dropped (excluded) so the body falls through to the merge.
fn is_exit_filler(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::LOAD_CONST | Mnemonic::NOP | Mnemonic::JUMP_FORWARD | Mnemonic::JUMP_ABSOLUTE
    )
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
    // The SETUP_EXCEPT target can land on a relinearizer trampoline before the real
    // handler dispatch, so skip NOPs/no-op jumps to reach it.
    let handler_idx = skip_nops(instrs, *index.get(&handler_off).ok_or(IrError::BadOperand)?);
    // The protected body exits through `POP_BLOCK; JUMP end`. The relinearizer does
    // not always place this immediately before the handler -- post-try code, or a
    // folded ternary's else arm, can sit between the body exit and the handler -- so
    // locate the body's own `POP_BLOCK` by scanning from the body with block-nesting
    // depth rather than assuming adjacency. The first `POP_BLOCK` reached at depth 0
    // pops this try's block.
    let mut depth = 0i32;
    let mut pop_idx = None;
    for i in (setup_idx + 1)..handler_idx {
        let mnemonic = instrs[i].instr.opcode.mnemonic();
        if format!("{:?}", mnemonic).starts_with("SETUP_") {
            depth += 1;
        } else if mnemonic == Mnemonic::POP_BLOCK {
            if depth == 0 {
                // Skip an orphan POP_BLOCK from a loop whose SETUP_LOOP the deob
                // dropped (it precedes the try's own POP_BLOCK); see recover_finally.
                if mnemonic_at(instrs, i + 1)? == Mnemonic::POP_BLOCK {
                    continue;
                }
                pop_idx = Some(i);
                break;
            }
            depth -= 1;
        }
    }
    // A SETUP_EXCEPT pushes a block that any normal exit from the body must pop, so
    // valid CPython 2.7 bytecode always reaches a `POP_BLOCK` before leaving the body
    // normally. The deob preserves that validity and only ever removes the
    // `POP_BLOCK; JUMP merge` exit when it is unreachable, i.e. the body always raises
    // or returns. So a missing POP_BLOCK means the body has no normal exit and the
    // construct has no merge of its own (`end` is `None`); the merge, if any, is
    // reached only through a handler and absorbed into that arm. The structurer's
    // `Point::Exit` guard rejects (rather than mis-emits) any body whose region does
    // not terminate, e.g. a nested merge-less try miscounted into this one.
    let end = match pop_idx {
        Some(pop_idx) => {
            let jump = instrs.get(pop_idx + 1).ok_or(IrError::Unstructurable)?;
            match jump.instr.opcode.mnemonic() {
                Mnemonic::JUMP_FORWARD | Mnemonic::JUMP_ABSOLUTE => {
                    // The merge target may go through a relinearizer trampoline.
                    let merge = branch_target(jump)?;
                    let merge_idx =
                        skip_nops(instrs, *index.get(&merge).ok_or(IrError::BadOperand)?);
                    Some(instrs.get(merge_idx).ok_or(IrError::Unstructurable)?.offset)
                }
                // The deob drops the body's `JUMP merge` when the merge is physically
                // the next instruction -- the body falls straight through POP_BLOCK
                // into the post-try code (often the function epilogue, `LOAD_CONST
                // None; RETURN_VALUE`). The merge is then that instruction itself.
                _ => Some(jump.offset),
            }
        }
        // Merge-less: the body always raises or returns. A handler that falls through
        // then reaches whatever follows the construct, which the structurer absorbs
        // into that arm. That is wrong when the fall-through path is shared with the
        // cleanup of an enclosing try/finally or with, which its own structurer also
        // emits (double execution). The relinearizer scatters the protected region, so
        // the block-at-a-time recoverer cannot reliably tell an enclosed merge-less try
        // from a standalone one; when the code object contains any SETUP_FINALLY or
        // SETUP_WITH, reject rather than risk it. Objects with neither cannot enclose.
        None => {
            if instrs.iter().any(|item| {
                matches!(
                    item.instr.opcode.mnemonic(),
                    Mnemonic::SETUP_FINALLY | Mnemonic::SETUP_WITH
                )
            }) {
                return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT));
            }
            None
        }
    };

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
                // the absence of a catch-all, not another clause. Exclude that
                // END_FINALLY directly: the relinearizer can place it past the merge
                // (when the handlers continue an enclosing loop), where the merge-
                // clamped scan below would miss it.
                if mnemonic_at(instrs, next_idx)? == Mnemonic::END_FINALLY {
                    exclude_end_finally_tail(instrs, next_idx, excluded);
                    break;
                }
                clause_idx = next_idx;
            }
            _ => return Err(IrError::HasControlFlow(Mnemonic::SETUP_EXCEPT)),
        }
    }

    // The compiler closes a handler chain with an END_FINALLY that re-raises an
    // unmatched exception. A bare `except:` leaves it unreachable rather than
    // removing it. END_FINALLY has no source form, so drop every one in the handler
    // span. The handler's END_FINALLY follows the handler dispatch, so normally
    // [handler_idx, merge) covers it. But when the body and every handler `continue`
    // an enclosing loop, the merge is the loop header -- placed before the handler --
    // and that span is empty, leaving the handler's own END_FINALLY behind. Scan to
    // the end of the stream whenever the merge does not sit after the handler (the
    // merge-less case has no merge at all); END_FINALLY is always structural, so
    // excluding one that belongs to a later sibling is idempotent with that sibling's
    // own recovery.
    let scan_end = match end {
        Some(end) => {
            let end_idx = *index.get(&end).ok_or(IrError::BadOperand)?;
            if end_idx >= handler_idx {
                end_idx
            } else {
                instrs.len()
            }
        }
        None => instrs.len(),
    };
    for i in handler_idx..scan_end {
        if instrs[i].instr.opcode.mnemonic() == Mnemonic::END_FINALLY {
            exclude_end_finally_tail(instrs, i, excluded);
        }
    }

    Ok(TryShape { setup: setup.offset, body_entry, end, clauses })
}

/// Excludes the `END_FINALLY` at `idx` and, when present, the dead jump right after
/// it. An `END_FINALLY` re-raises an unmatched exception and never falls through, so
/// a jump immediately after it -- the re-raise path's tail the compiler emits when
/// the handlers continue an enclosing loop or return to a merge -- is unreachable
/// (unless some other instruction jumps to it). Excluding the END_FINALLY removes the
/// block boundary the preceding block's jump relied on, so leaving that dead jump
/// would fold it into the preceding block as a mid-block terminator; drop it too.
fn exclude_end_finally_tail(instrs: &[OffsetInstr], idx: usize, excluded: &mut HashSet<Offset>) {
    excluded.insert(instrs[idx].offset);
    let Some(next) = instrs.get(idx + 1) else {
        return;
    };
    if !matches!(
        next.instr.opcode.mnemonic(),
        Mnemonic::JUMP_ABSOLUTE | Mnemonic::JUMP_FORWARD
    ) {
        return;
    }
    let tail = next.offset;
    let is_target = instrs
        .iter()
        .any(|item| branch_target(item).ok() == Some(tail));
    if !is_target {
        excluded.insert(tail);
    }
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
/// Detects inline list comprehensions. Returns the comprehension regions
/// (`BUILD_LIST` offset -> end offset), the interior offsets to keep out of block
/// formation, and, for any comprehension used as a ternary then-arm, a map from its
/// `BUILD_LIST` offset to `(cond offset, merge offset)`: the preceding
/// `POP_JUMP_IF_FALSE` to mark as a ternary diamond and the `FOR_ITER` exit where the
/// comprehension value and the else arm converge.
fn find_list_comps(
    instrs: &[OffsetInstr],
) -> (HashMap<Offset, Offset>, HashSet<Offset>, HashMap<Offset, (Offset, Offset)>) {
    let index: HashMap<Offset, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, item)| (item.offset, idx))
        .collect();
    let mut comps = HashMap::new();
    let mut interior = HashSet::new();
    let mut comp_ternaries = HashMap::new();
    for (idx, item) in instrs.iter().enumerate() {
        if item.instr.opcode.mnemonic() != Mnemonic::BUILD_LIST || item.instr.arg != Some(0) {
            continue;
        }
        if let Some((end_idx, for_exit_idx)) = recognize_list_comp(instrs, &index, idx) {
            comps.insert(item.offset, instrs[end_idx].offset);
            for inner in &instrs[idx + 1..end_idx] {
                interior.insert(inner.offset);
            }
            // A comprehension whose loop exit lies past its end is a ternary then-arm:
            // the else arm sits between. Recognise the diamond when a POP_JUMP_IF_FALSE
            // immediately before the build branches to the comprehension's end (the
            // else arm), with the FOR_ITER exit as the shared merge.
            if end_idx != for_exit_idx && idx > 0 {
                let cond = &instrs[idx - 1];
                if cond.instr.opcode.mnemonic() == Mnemonic::POP_JUMP_IF_FALSE
                    && branch_target(cond).ok() == Some(instrs[end_idx].offset)
                {
                    comp_ternaries
                        .insert(item.offset, (cond.offset, instrs[for_exit_idx].offset));
                }
            }
        }
    }
    (comps, interior, comp_ternaries)
}

/// Validates that the `BUILD_LIST 0` at `build_idx` begins a single-`for` list
/// comprehension. Returns `(comp_end_idx, for_exit_idx)`: the index just past the
/// loop's back edge (where the folded comprehension ends), and the index of the
/// `FOR_ITER` exit (where the comprehension's result is used). These differ only
/// when the comprehension is the then-arm of a ternary -- the else arm sits between
/// the back edge and the exit. Anything else (a list literal, a nested or filtered
/// shape the folder cannot parse) returns `None`, leaving the `LIST_APPEND`
/// unsupported so the function is rejected rather than mis-recovered.
fn recognize_list_comp(
    instrs: &[OffsetInstr],
    index: &HashMap<Offset, usize>,
    build_idx: usize,
) -> Option<(usize, usize)> {
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
    // GET_ITER is the last real instruction before FOR_ITER; NOPs left by the no-op
    // jump removal may sit between them.
    let mut giter_idx = for_idx;
    loop {
        giter_idx = giter_idx.checked_sub(1).filter(|i| *i > build_idx)?;
        if instrs[giter_idx].instr.opcode.mnemonic() != Mnemonic::NOP {
            break;
        }
    }
    if instrs[giter_idx].instr.opcode.mnemonic() != Mnemonic::GET_ITER {
        return None;
    }
    let for_iter = &instrs[for_idx];
    let loop_top = for_iter.offset;
    let for_exit_idx = *index.get(&branch_target(for_iter).ok()?)?;
    if for_exit_idx <= for_idx {
        return None;
    }
    // Find the back edge that closes the outer loop body: a JUMP_ABSOLUTE to this
    // FOR_ITER. It is at the FOR_ITER exit for a plain comprehension, earlier (with
    // the ternary else arm following) for a comprehension used as a ternary then-arm.
    // A multi-`for` comprehension nests inner FOR_ITERs whose own back edges target
    // their inner loop tops, not this one, so they are passed over here and the
    // outer back edge is still found.
    let mut back_idx = None;
    for i in (for_idx + 1)..for_exit_idx {
        let mnemonic = instrs[i].instr.opcode.mnemonic();
        if mnemonic == Mnemonic::JUMP_ABSOLUTE && branch_target(&instrs[i]).ok() == Some(loop_top) {
            back_idx = Some(i);
            break;
        }
    }
    let back_idx = back_idx?;
    // Exactly one append builds the result list, whether the comprehension has one
    // `for` clause or several (a nested element comprehension has its own append and
    // is left to fail rather than be mis-folded).
    let appends = instrs[for_idx + 1..=back_idx]
        .iter()
        .filter(|item| item.instr.opcode.mnemonic() == Mnemonic::LIST_APPEND)
        .count();
    if appends != 1 {
        return None;
    }
    Some((back_idx + 1, for_exit_idx))
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
        | Mnemonic::SETUP_WITH
        | Mnemonic::SETUP_FINALLY
        | Mnemonic::SETUP_LOOP => Offset(item.offset.0 + item.instr.len() as u32 + arg),
        other => return Err(IrError::HasControlFlow(other)),
    })
}
