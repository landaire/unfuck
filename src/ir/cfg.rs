//! Control-flow graph over the statement IR.
//!
//! The function is split into basic blocks at jump targets and after every
//! branch or return. Each block carries its straight-line statements and a typed
//! [`Terminator`] whose conditions reference the shared [`ExprArena`]. Loops are
//! recovered from back edges by the structurer; exception and short-circuit setup
//! are still rejected so the supported surface stays explicit.

use std::collections::{BTreeSet, HashMap};

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
        let leaders = block_leaders(instrs)?;
        let mut by_offset = HashMap::new();
        for (idx, leader) in leaders.iter().enumerate() {
            by_offset.insert(*leader, BlockId(idx as u32));
        }

        // The instruction after a FOR_ITER begins the loop body with the loop
        // target's store; map that body leader back to its header offset.
        let mut for_body_header: HashMap<Offset, Offset> = HashMap::new();
        for (idx, item) in instrs.iter().enumerate() {
            if item.instr.opcode.mnemonic() == Mnemonic::FOR_ITER {
                if let Some(next) = instrs.get(idx + 1) {
                    for_body_header.insert(next.offset, item.offset);
                }
            }
        }

        let mut unstacker = Unstacker::new();
        let mut blocks = Vec::with_capacity(leaders.len());
        let mut for_targets = HashMap::new();

        for (idx, &leader) in leaders.iter().enumerate() {
            let end = leaders.get(idx + 1).copied().unwrap_or(Offset(u32::MAX));
            let body: Vec<&OffsetInstr> = instrs
                .iter()
                .filter(|i| i.offset >= leader && i.offset < end)
                .collect();
            let for_header = for_body_header
                .get(&leader)
                .and_then(|header| by_offset.get(header).copied());
            let block = lower_block(&mut unstacker, leader, end, &body, for_header, &mut for_targets)?;
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
fn block_leaders(instrs: &[OffsetInstr]) -> Result<Vec<Offset>, IrError> {
    let mut leaders = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.offset);
    }
    for (idx, item) in instrs.iter().enumerate() {
        let mnemonic = item.instr.opcode.mnemonic();
        let next = instrs.get(idx + 1).map(|i| i.offset);
        match terminator_kind(mnemonic)? {
            TerminatorKind::Branch | TerminatorKind::Jump | TerminatorKind::ForIter => {
                // Backward targets are loop back edges; the structurer recovers the
                // loop, so they are allowed here.
                leaders.insert(branch_target(item)?);
                if let Some(next) = next {
                    leaders.insert(next);
                }
            }
            TerminatorKind::Return | TerminatorKind::Raise => {
                if let Some(next) = next {
                    leaders.insert(next);
                }
            }
            TerminatorKind::None => {}
        }
    }
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
) -> Result<Block, IrError> {
    unstacker.start_block();

    let last = body.last().ok_or(IrError::Decode)?;
    let mnemonic = last.instr.opcode.mnemonic();
    let kind = terminator_kind(mnemonic)?;

    // A for-loop body begins with the store of the loop target. Record it and skip
    // it so the remaining body unstacks with a balanced stack (the body refers to
    // the target through ordinary loads).
    let mut start = 0;
    if let Some(header) = for_header {
        let first = body.first().ok_or(IrError::Decode)?;
        for_targets.insert(header, store_target(&first.instr)?);
        start = 1;
    }

    let feed_end = match kind {
        TerminatorKind::None => body.len(),
        _ => body.len() - 1,
    };
    for item in &body[start.min(feed_end)..feed_end] {
        unstacker.step(&item.instr)?;
    }

    let terminator = match kind {
        TerminatorKind::None => Terminator::Fallthrough(end),
        TerminatorKind::Jump => Terminator::Jump(branch_target(last)?),
        TerminatorKind::ForIter => Terminator::ForIter {
            body: end,
            exit: branch_target(last)?,
        },
        TerminatorKind::Return => {
            let value = unstacker.pop_value()?;
            Terminator::Return(Some(value))
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
}

/// Classifies an opcode's effect on control flow, rejecting constructs the
/// structurer does not handle.
fn terminator_kind(mnemonic: Mnemonic) -> Result<TerminatorKind, IrError> {
    Ok(match mnemonic {
        Mnemonic::RETURN_VALUE => TerminatorKind::Return,
        Mnemonic::RAISE_VARARGS => TerminatorKind::Raise,
        Mnemonic::JUMP_ABSOLUTE | Mnemonic::JUMP_FORWARD => TerminatorKind::Jump,
        Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE => TerminatorKind::Branch,
        Mnemonic::FOR_ITER => TerminatorKind::ForIter,
        Mnemonic::SETUP_EXCEPT
        | Mnemonic::SETUP_FINALLY
        | Mnemonic::SETUP_WITH
        | Mnemonic::BREAK_LOOP
        | Mnemonic::CONTINUE_LOOP
        | Mnemonic::END_FINALLY
        | Mnemonic::YIELD_VALUE
        | Mnemonic::JUMP_IF_FALSE_OR_POP
        | Mnemonic::JUMP_IF_TRUE_OR_POP => return Err(IrError::HasControlFlow(mnemonic)),
        _ => TerminatorKind::None,
    })
}

/// Computes the absolute target offset of a branch instruction.
fn branch_target(item: &OffsetInstr) -> Result<Offset, IrError> {
    let arg = item.instr.arg.ok_or(IrError::MissingOperand)? as u32;
    Ok(match item.instr.opcode.mnemonic() {
        Mnemonic::JUMP_ABSOLUTE | Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE => {
            Offset(arg)
        }
        Mnemonic::JUMP_FORWARD | Mnemonic::FOR_ITER => {
            Offset(item.offset.0 + item.instr.len() as u32 + arg)
        }
        other => return Err(IrError::HasControlFlow(other)),
    })
}
