//! The bytecode optimizer run on every assembled code object. It folds
//! constant expressions, threads jumps, and drops some redundant
//! instruction pairs, producing the same bytes as the reference compiler.
//!
//! Rewrites overwrite instructions in place and pad the freed bytes with
//! `NOP`. A final pass removes the padding, moves jump arguments, and
//! adjusts `co_lnotab` to the new offsets.

use crate::interp::code::op;
use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::fold;
use crate::interp::compiler::fold::BinaryFold;
use crate::interp::compiler::fold::MAX_FOLDED_SIZE;
use crate::interp::compiler::fold::UnaryFold;
use crate::interp::compiler::object::Object;

/// How a jump instruction encodes its destination.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JumpKind {
    /// The argument is a code offset.
    Absolute,
    /// The argument counts from the end of the jump instruction.
    Relative,
}

impl JumpKind {
    fn of(opcode: u8) -> Option<Self> {
        match opcode {
            op::JUMP_ABSOLUTE | op::POP_JUMP_IF_FALSE | op::POP_JUMP_IF_TRUE | op::JUMP_IF_FALSE_OR_POP | op::JUMP_IF_TRUE_OR_POP | op::CONTINUE_LOOP => Some(Self::Absolute),
            op::JUMP_FORWARD | op::FOR_ITER | op::SETUP_LOOP | op::SETUP_EXCEPT | op::SETUP_FINALLY | op::SETUP_WITH => Some(Self::Relative),
            _ => None,
        }
    }

    fn destination(self, offset: usize, arg: u16) -> usize {
        match self {
            Self::Absolute => usize::from(arg),
            Self::Relative => offset + 3 + usize::from(arg),
        }
    }
}

/// For each byte offset of the unmodified code, how many jump destinations
/// lie at or before it. Two offsets with the same label are in the same
/// basic block. The labels are not updated as rewrites move jumps.
struct BlockLabels(Vec<u32>);

impl BlockLabels {
    fn new(code: &[u8]) -> Self {
        let mut is_destination = vec![false; code.len()];
        for (offset, instruction) in Instructions::new(code) {
            let (Some(kind), Some(arg)) = (JumpKind::of(instruction.opcode), instruction.arg) else {
                continue;
            };
            if let Some(flag) = is_destination.get_mut(kind.destination(offset, arg)) {
                *flag = true;
            }
        }

        let labels = is_destination
            .iter()
            .scan(0u32, |count, &flag| {
                *count += u32::from(flag);
                Some(*count)
            })
            .collect();

        Self(labels)
    }

    /// Whether `len` bytes from `start` contain no jump destination other
    /// than possibly `start` itself.
    fn is_straight_line(&self, start: usize, len: usize) -> bool {
        let Some(last) = (start + len).checked_sub(1) else {
            return false;
        };
        let (Some(first), Some(last)) = (self.0.get(start), self.0.get(last)) else {
            return false;
        };

        first == last
    }
}

/// One decoded instruction.
#[derive(Clone, Copy)]
struct Instruction {
    opcode: u8,
    /// `None` for opcodes that take no argument.
    arg: Option<u16>,
}

impl Instruction {
    fn has_arg(opcode: u8) -> bool {
        opcode >= op::HAVE_ARGUMENT
    }

    fn width(opcode: u8) -> usize {
        if Self::has_arg(opcode) { 3 } else { 1 }
    }

    fn decode(code: &[u8], offset: usize) -> Option<Self> {
        let opcode = *code.get(offset)?;
        if !Self::has_arg(opcode) {
            return Some(Self { opcode, arg: None });
        }

        let low = *code.get(offset + 1)?;
        let high = *code.get(offset + 2)?;

        Some(Self { opcode, arg: Some(u16::from_le_bytes([low, high])) })
    }
}

/// Walks instruction boundaries, stopping at a truncated final instruction.
struct Instructions<'a> {
    code: &'a [u8],
    offset: usize,
}

impl<'a> Instructions<'a> {
    fn new(code: &'a [u8]) -> Self {
        Self { code, offset: 0 }
    }
}

impl Iterator for Instructions<'_> {
    type Item = (usize, Instruction);

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        let instruction = Instruction::decode(self.code, offset)?;
        self.offset += Instruction::width(instruction.opcode);

        Some((offset, instruction))
    }
}

/// Where the scan continues after visiting an instruction.
enum Next {
    /// Resume at `offset`, after `loads` consecutive `LOAD_CONST`
    /// instructions that end there.
    Resume { offset: usize, loads: usize },
    /// The instruction at the same offset was replaced; visit it again.
    Revisit,
}

impl Next {
    fn after(offset: usize, len: usize) -> Self {
        Self::Resume { offset: offset + len, loads: 0 }
    }
}

struct Rewriter<'a> {
    code: Vec<u8>,
    blocks: BlockLabels,
    consts: &'a mut Vec<Object>,
    names: &'a [Vec<u8>],
    context: &'a mut dyn CompileContext,
}

impl Rewriter<'_> {
    /// Visits every instruction once in order, plus revisits of rewritten
    /// jumps. `None` abandons the optimization.
    fn run(&mut self) -> Option<()> {
        let mut offset = 0;
        let mut loads = 0;
        let mut revisits = 0;

        while offset < self.code.len() {
            match self.visit(offset, loads)? {
                Next::Resume { offset: next, loads: next_loads } => {
                    offset = next;
                    loads = next_loads;
                    revisits = 0;
                }
                Next::Revisit => {
                    // Conditional jumps that lead to each other in a cycle
                    // would be rewritten forever; give up on the jump instead.
                    revisits += 1;
                    if revisits > self.code.len() {
                        let opcode = self.code.get(offset)?;
                        offset += Instruction::width(*opcode);
                        loads = 0;
                        revisits = 0;
                    }
                }
            }
        }

        Some(())
    }

    fn visit(&mut self, offset: usize, loads: usize) -> Option<Next> {
        let Instruction { opcode, arg } = Instruction::decode(&self.code, offset)?;

        match opcode {
            op::LOAD_NAME | op::LOAD_GLOBAL => self.load_none(offset, arg?, loads),
            op::LOAD_CONST => self.skip_true_test(offset, arg?, loads),
            op::BUILD_TUPLE | op::BUILD_LIST => self.build_sequence(offset, opcode, arg?, loads),
            op::UNARY_NEGATIVE | op::UNARY_CONVERT | op::UNARY_INVERT => self.fold_unary(offset, opcode, loads),
            op::UNARY_NOT => self.invert_jump(offset),
            op::COMPARE_OP => self.invert_comparison(offset, arg?),
            op::JUMP_IF_FALSE_OR_POP | op::JUMP_IF_TRUE_OR_POP => self.merge_conditions(offset, opcode, arg?),
            op::RETURN_VALUE => self.drop_after_return(offset),
            op::EXTENDED_ARG => None,
            opcode if JumpKind::of(opcode).is_some() => self.thread_jump(offset, opcode, arg?),
            opcode => match binary_fold(opcode) {
                Some(operation) => self.fold_binary(offset, operation, loads),
                None => Some(Next::after(offset, Instruction::width(opcode))),
            },
        }
    }

    fn opcode(&self, offset: usize) -> Option<u8> {
        self.code.get(offset).copied()
    }

    fn write(&mut self, offset: usize, opcode: u8, arg: u16) -> Option<()> {
        let [low, high] = arg.to_le_bytes();
        self.code.get_mut(offset..offset + 3)?.copy_from_slice(&[opcode, low, high]);

        Some(())
    }

    fn pad(&mut self, start: usize, len: usize) -> Option<()> {
        self.code.get_mut(start..start + len)?.fill(op::NOP);

        Some(())
    }

    fn add_constant(&mut self, object: Object) -> Option<u16> {
        let index = u16::try_from(self.consts.len()).ok()?;
        self.consts.push(object);

        Some(index)
    }

    /// Loading the name `None` becomes loading the `None` constant.
    fn load_none(&mut self, offset: usize, name: u16, loads: usize) -> Option<Next> {
        let name = self.names.get(usize::from(name))?;
        // The name is compared as a NUL-terminated string.
        let visible = name.split(|&byte| byte == 0).next().unwrap_or_default();
        if visible != b"None" {
            return Some(Next::after(offset, 3));
        }

        let index = match self.consts.iter().position(|object| matches!(object, Object::None)) {
            Some(index) => u16::try_from(index).ok()?,
            None => self.add_constant(Object::None)?,
        };
        self.write(offset, op::LOAD_CONST, index)?;

        Some(Next::Resume { offset: offset + 3, loads: loads + 1 })
    }

    /// A true constant followed by `POP_JUMP_IF_FALSE` never jumps, as in
    /// `while 1:`; both instructions go.
    fn skip_true_test(&mut self, offset: usize, index: u16, loads: usize) -> Option<Next> {
        let constant = self.consts.get(usize::from(index))?;
        if self.opcode(offset + 3) != Some(op::POP_JUMP_IF_FALSE) || !self.blocks.is_straight_line(offset, 6) || !fold::is_true(constant) {
            return Some(Next::Resume { offset: offset + 3, loads: loads + 1 });
        }

        self.pad(offset, 6)?;

        Some(Next::after(offset, 6))
    }

    /// A tuple of constants becomes one constant, as does a list of
    /// constants tested with `in` or `not in`. A sequence built only to be
    /// unpacked again into one to three targets becomes stack rotations.
    fn build_sequence(&mut self, offset: usize, opcode: u8, size: u16, loads: usize) -> Option<Next> {
        let count = usize::from(size);
        let next = Instruction::decode(&self.code, offset + 3);

        let start = offset.checked_sub(3 * count).filter(|_| loads >= count);
        if let Some(start) = start {
            let span = offset + 3 - start;
            let foldable = match opcode {
                op::BUILD_TUPLE => self.blocks.is_straight_line(start, span),
                _ => next.is_some_and(|next| next.opcode == op::COMPARE_OP && matches!(next.arg, Some(6 | 7))) && self.blocks.is_straight_line(start, span + 3),
            };
            if foldable {
                let items = (0..count).map(|position| loaded_constant(&self.code, self.consts, start + 3 * position).cloned()).collect::<Option<Vec<_>>>()?;
                let index = self.add_constant(Object::Tuple(items.into()))?;
                self.pad(start, offset - start)?;
                self.write(offset, op::LOAD_CONST, index)?;

                return Some(Next::Resume { offset: offset + 3, loads: 1 });
            }
        }

        let unpacks_same = next.is_some_and(|next| next.opcode == op::UNPACK_SEQUENCE && next.arg == Some(size));
        if !unpacks_same || !self.blocks.is_straight_line(offset, 6) {
            return Some(Next::after(offset, 3));
        }

        let rotations: &[u8] = match count {
            1 => &[],
            2 => &[op::ROT_TWO],
            3 => &[op::ROT_THREE, op::ROT_TWO],
            _ => return Some(Next::after(offset, 3)),
        };
        self.pad(offset, 6)?;
        self.code.get_mut(offset..offset + rotations.len())?.copy_from_slice(rotations);

        Some(Next::after(offset, 6))
    }

    /// Two constants and a binary operation become the result, unless the
    /// operation raises or makes a long sequence.
    fn fold_binary(&mut self, offset: usize, operation: BinaryFold, loads: usize) -> Option<Next> {
        let Some(start) = offset.checked_sub(6).filter(|&start| loads >= 2 && self.blocks.is_straight_line(start, 7)) else {
            return Some(Next::after(offset, 1));
        };

        let left = loaded_constant(&self.code, self.consts, start)?;
        let right = loaded_constant(&self.code, self.consts, start + 3)?;
        let Some(result) = fold::binary(operation, left, right, &mut *self.context) else {
            return Some(Next::after(offset, 1));
        };
        if fold::size(&result).is_some_and(|size| size > MAX_FOLDED_SIZE) {
            return Some(Next::after(offset, 1));
        }

        let index = self.add_constant(result)?;
        self.pad(start, 4)?;
        self.write(offset - 2, op::LOAD_CONST, index)?;

        Some(Next::Resume { offset: offset + 1, loads: 1 })
    }

    /// A constant and a unary operation become the result. Negation applies
    /// only to true operands, so that `-0.0` keeps its sign at run time.
    fn fold_unary(&mut self, offset: usize, opcode: u8, loads: usize) -> Option<Next> {
        let Some(start) = offset.checked_sub(3).filter(|&start| loads >= 1 && self.blocks.is_straight_line(start, 4)) else {
            return Some(Next::after(offset, 1));
        };

        let operand = loaded_constant(&self.code, self.consts, start)?;
        let result = match opcode {
            op::UNARY_NEGATIVE if fold::is_true(operand) => fold::unary(UnaryFold::Negative, operand, &mut *self.context),
            op::UNARY_CONVERT => fold::unary(UnaryFold::Convert, operand, &mut *self.context),
            op::UNARY_INVERT => fold::unary(UnaryFold::Invert, operand, &mut *self.context),
            _ => None,
        };
        let Some(result) = result else {
            return Some(Next::after(offset, 1));
        };

        let index = self.add_constant(result)?;
        self.pad(start, 1)?;
        self.write(offset - 2, op::LOAD_CONST, index)?;

        Some(Next::Resume { offset: offset + 1, loads: 1 })
    }

    /// `not x` tested by `POP_JUMP_IF_FALSE` becomes a `POP_JUMP_IF_TRUE`
    /// on `x`.
    fn invert_jump(&mut self, offset: usize) -> Option<Next> {
        let next = Instruction::decode(&self.code, offset + 1);
        let Some(next) = next.filter(|next| next.opcode == op::POP_JUMP_IF_FALSE && self.blocks.is_straight_line(offset, 4)) else {
            return Some(Next::after(offset, 1));
        };

        self.write(offset, op::POP_JUMP_IF_TRUE, next.arg?)?;
        self.pad(offset + 3, 1)?;

        Some(Next::Revisit)
    }

    /// `not` applied to `in`, `not in`, `is`, or `is not` becomes the
    /// opposite comparison.
    fn invert_comparison(&mut self, offset: usize, comparison: u16) -> Option<Next> {
        const IN: u16 = 6;
        const IS_NOT: u16 = 9;

        if !(IN..=IS_NOT).contains(&comparison) || self.opcode(offset + 3) != Some(op::UNARY_NOT) || !self.blocks.is_straight_line(offset, 4) {
            return Some(Next::after(offset, 3));
        }

        // The pairs are (6, 7) and (8, 9).
        self.write(offset, op::COMPARE_OP, comparison ^ 1)?;
        self.pad(offset + 3, 1)?;

        Some(Next::after(offset, 4))
    }

    /// A `JUMP_IF_*_OR_POP` that lands on another conditional jump decides
    /// that jump too. Testing the same truth, it jumps where that jump goes;
    /// testing the opposite truth, it pops and continues after it.
    fn merge_conditions(&mut self, offset: usize, opcode: u8, arg: u16) -> Option<Next> {
        let landing = usize::from(arg);
        let Some(second) = Instruction::decode(&self.code, landing).filter(|second| is_conditional(second.opcode)) else {
            return self.thread_jump(offset, opcode, arg);
        };

        if jumps_when_true(second.opcode) == jumps_when_true(opcode) {
            self.write(offset, second.opcode, second.arg?)?;
        } else {
            let popping = if jumps_when_true(opcode) { op::POP_JUMP_IF_TRUE } else { op::POP_JUMP_IF_FALSE };
            self.write(offset, popping, u16::try_from(landing + 3).ok()?)?;
        }

        Some(Next::Revisit)
    }

    /// A jump to an unconditional jump goes straight to its destination,
    /// and an unconditional jump to `RETURN_VALUE` becomes `RETURN_VALUE`.
    fn thread_jump(&mut self, offset: usize, opcode: u8, arg: u16) -> Option<Next> {
        let kind = JumpKind::of(opcode)?;
        let landing = kind.destination(offset, arg);
        let target = Instruction::decode(&self.code, landing)?;

        if is_unconditional(opcode) && target.opcode == op::RETURN_VALUE {
            self.pad(offset, 3)?;
            *self.code.get_mut(offset)? = op::RETURN_VALUE;

            return Some(Next::after(offset, 3));
        }
        if !is_unconditional(target.opcode) {
            return Some(Next::after(offset, 3));
        }

        let final_destination = JumpKind::of(target.opcode)?.destination(landing, target.arg?);
        let opcode = if opcode == op::JUMP_FORWARD { op::JUMP_ABSOLUTE } else { opcode };
        let arg = match JumpKind::of(opcode)? {
            JumpKind::Absolute => final_destination,
            JumpKind::Relative => {
                let Some(distance) = final_destination.checked_sub(offset + 3) else {
                    return Some(Next::after(offset, 3));
                };
                distance
            }
        };
        self.write(offset, opcode, u16::try_from(arg).ok()?)?;

        Some(Next::after(offset, 3))
    }

    /// Unreachable code directly after `RETURN_VALUE` goes when it is a
    /// single three-byte instruction and another `RETURN_VALUE`, or a lone
    /// unconditional jump. The test reads raw bytes, not instructions.
    fn drop_after_return(&mut self, offset: usize) -> Option<Next> {
        let Some(&fifth) = self.code.get(offset + 4) else {
            return Some(Next::after(offset, 1));
        };

        if fifth == op::RETURN_VALUE && self.blocks.is_straight_line(offset, 5) {
            self.pad(offset + 1, 4)?;
        } else if self.opcode(offset + 1).is_some_and(is_unconditional) && self.blocks.is_straight_line(offset, 4) {
            self.pad(offset + 1, 3)?;
        }

        Some(Next::after(offset, 1))
    }
}

/// New offsets of the rewritten code once its `NOP`s are removed.
struct Layout {
    /// Indexed by old offset, plus one entry for the end of the code. A
    /// byte inside an instruction maps to where that instruction moves.
    /// Such offsets occur only in malformed input, where the reference
    /// produces unpredictable results.
    new_offsets: Vec<usize>,
}

impl Layout {
    fn new(code: &[u8]) -> Option<Self> {
        let mut new_offsets = Vec::with_capacity(code.len() + 1);
        let mut removed = 0;

        for (offset, instruction) in Instructions::new(code) {
            let width = Instruction::width(instruction.opcode);
            new_offsets.extend(std::iter::repeat_n(offset - removed, width));
            if instruction.opcode == op::NOP {
                removed += 1;
            }
        }

        // A truncated final instruction cannot be relocated.
        if new_offsets.len() != code.len() {
            return None;
        }
        new_offsets.push(code.len() - removed);

        Some(Self { new_offsets })
    }

    fn relocate(&self, offset: usize) -> Option<usize> {
        self.new_offsets.get(offset).copied()
    }

    /// The code without `NOP`s, with jump arguments moved.
    fn compact(&self, code: &[u8]) -> Option<Vec<u8>> {
        let mut compacted = Vec::with_capacity(code.len());

        for (offset, instruction) in Instructions::new(code) {
            if instruction.opcode == op::NOP {
                continue;
            }
            let Some(arg) = instruction.arg else {
                compacted.push(instruction.opcode);
                continue;
            };

            let arg = match JumpKind::of(instruction.opcode) {
                None => usize::from(arg),
                Some(kind) => {
                    let destination = self.relocate(kind.destination(offset, arg))?;
                    match kind {
                        JumpKind::Absolute => destination,
                        JumpKind::Relative => destination.checked_sub(self.relocate(offset)? + 3)?,
                    }
                }
            };
            let [low, high] = u16::try_from(arg).ok()?.to_le_bytes();
            compacted.extend_from_slice(&[instruction.opcode, low, high]);
        }

        Some(compacted)
    }

    /// `lnotab` with each address increment recomputed for the new offsets.
    fn relocate_lnotab(&self, lnotab: &[u8]) -> Option<Vec<u8>> {
        let mut relocated = lnotab.to_vec();
        let mut old_address = 0;
        let mut previous = 0;

        for increment in relocated.iter_mut().step_by(2) {
            old_address += usize::from(*increment);
            let address = self.relocate(old_address)?;
            *increment = u8::try_from(address.checked_sub(previous)?).ok()?;
            previous = address;
        }

        Some(relocated)
    }
}

/// Optimizes `code` and returns the new bytecode, appending folded
/// constants to `consts` and rewriting `lnotab` to match.
///
/// Code that is too long, does not end in `RETURN_VALUE`, or has an
/// `lnotab` byte of 255 is returned unchanged. So is code containing
/// `EXTENDED_ARG`, but constants appended before it was reached stay.
pub fn optimize(code: Vec<u8>, consts: &mut Vec<Object>, names: &[Vec<u8>], lnotab: &mut Vec<u8>, context: &mut dyn CompileContext) -> Vec<u8> {
    // Longer code is skipped so that rewritten jump arguments cannot
    // overflow 16 bits.
    const MAX_CODE_LEN: usize = 32700;

    if code.len() > MAX_CODE_LEN || code.last() != Some(&op::RETURN_VALUE) || lnotab.contains(&255) {
        return code;
    }

    let mut rewriter = Rewriter { code: code.clone(), blocks: BlockLabels::new(&code), consts, names, context };
    if rewriter.run().is_none() {
        return code;
    }

    let Some(layout) = Layout::new(&rewriter.code) else {
        return code;
    };
    let Some(compacted) = layout.compact(&rewriter.code) else {
        return code;
    };
    let Some(new_lnotab) = layout.relocate_lnotab(lnotab) else {
        return code;
    };
    *lnotab = new_lnotab;

    compacted
}

/// The constant loaded by the `LOAD_CONST` at `offset`.
fn loaded_constant<'c>(code: &[u8], consts: &'c [Object], offset: usize) -> Option<&'c Object> {
    let instruction = Instruction::decode(code, offset)?;

    consts.get(usize::from(instruction.arg?))
}

fn binary_fold(opcode: u8) -> Option<BinaryFold> {
    let operation = match opcode {
        op::BINARY_POWER => BinaryFold::Power,
        op::BINARY_MULTIPLY => BinaryFold::Multiply,
        op::BINARY_TRUE_DIVIDE => BinaryFold::TrueDivide,
        op::BINARY_FLOOR_DIVIDE => BinaryFold::FloorDivide,
        op::BINARY_MODULO => BinaryFold::Modulo,
        op::BINARY_ADD => BinaryFold::Add,
        op::BINARY_SUBTRACT => BinaryFold::Subtract,
        op::BINARY_SUBSCR => BinaryFold::Subscript,
        op::BINARY_LSHIFT => BinaryFold::LShift,
        op::BINARY_RSHIFT => BinaryFold::RShift,
        op::BINARY_AND => BinaryFold::And,
        op::BINARY_XOR => BinaryFold::Xor,
        op::BINARY_OR => BinaryFold::Or,
        _ => return None,
    };

    Some(operation)
}

fn is_unconditional(opcode: u8) -> bool {
    matches!(opcode, op::JUMP_FORWARD | op::JUMP_ABSOLUTE)
}

fn is_conditional(opcode: u8) -> bool {
    matches!(opcode, op::POP_JUMP_IF_FALSE | op::POP_JUMP_IF_TRUE | op::JUMP_IF_FALSE_OR_POP | op::JUMP_IF_TRUE_OR_POP)
}

fn jumps_when_true(opcode: u8) -> bool {
    matches!(opcode, op::POP_JUMP_IF_TRUE | op::JUMP_IF_TRUE_OR_POP)
}

/// Expected results come from the reference CPython 2.7.18, calling its
/// optimizer on the same input through ctypes:
///
/// ```python
/// import ctypes, opcode
/// optimize = ctypes.pythonapi.PyCode_Optimize
/// optimize.restype = ctypes.py_object
/// optimize.argtypes = [ctypes.py_object] * 4
///
/// def run(instructions, consts, names, lnotab):
///     code = ''.join(chr(opcode.opmap[op]) + ('' if arg is None else chr(arg & 255) + chr(arg >> 8))
///                    for op, arg in instructions)
///     consts = list(consts)
///     lnotab = (''.join(map(chr, lnotab)) + 'x')[:-1]  # a fresh, modifiable str
///     return optimize(code, consts, tuple(names), lnotab), consts, map(ord, lnotab)
/// ```
#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::compiler::context::TestContext;
    use crate::interp::compiler::unit::Constant;

    fn encode(instructions: &[(u8, u16)]) -> Vec<u8> {
        let mut code = Vec::new();
        for &(opcode, arg) in instructions {
            code.push(opcode);
            if opcode >= op::HAVE_ARGUMENT {
                code.extend_from_slice(&arg.to_le_bytes());
            }
        }

        code
    }

    struct Optimized {
        code: Vec<u8>,
        consts: Vec<Constant>,
        lnotab: Vec<u8>,
    }

    fn run(instructions: &[(u8, u16)], consts: Vec<Object>, names: &[&str], lnotab: &[u8]) -> Optimized {
        let mut consts = consts;
        let names: Vec<Vec<u8>> = names.iter().map(|name| name.as_bytes().to_vec()).collect();
        let mut lnotab = lnotab.to_vec();
        let mut context = TestContext::new();

        let code = optimize(encode(instructions), &mut consts, &names, &mut lnotab, &mut context);

        Optimized { code, consts: consts.into_iter().map(Object::into_constant).collect(), lnotab }
    }

    fn interned(value: &str) -> Object {
        Object::str(value.as_bytes().to_vec(), true)
    }

    #[test]
    fn conditional_jump_to_jump_absolute_takes_its_target() {
        let result = run(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 9), (op::JUMP_FORWARD, 3), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)], vec![Object::None], &["x"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 0), (op::JUMP_FORWARD, 3), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    /// A threaded `JUMP_FORWARD` becomes `JUMP_ABSOLUTE`, which can reach
    /// any offset.
    #[test]
    fn jump_forward_to_jump_becomes_absolute() {
        let result = run(
            &[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 13), (op::JUMP_FORWARD, 4), (op::LOAD_NAME, 0), (op::POP_TOP, 0), (op::JUMP_FORWARD, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["x"],
            &[],
        );

        assert_eq!(
            result.code,
            encode(&[
                (op::LOAD_NAME, 0),
                (op::POP_JUMP_IF_FALSE, 16),
                (op::JUMP_ABSOLUTE, 16),
                (op::LOAD_NAME, 0),
                (op::POP_TOP, 0),
                (op::JUMP_FORWARD, 0),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ])
        );
    }

    /// Each jump is threaded through one unconditional jump only; the
    /// second jump in the chain was not yet rewritten when the first was.
    #[test]
    fn threads_one_level_per_jump() {
        let result = run(
            &[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 6), (op::JUMP_ABSOLUTE, 9), (op::JUMP_ABSOLUTE, 12), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["x"],
            &[],
        );

        assert_eq!(
            result.code,
            encode(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 9), (op::JUMP_ABSOLUTE, 12), (op::JUMP_ABSOLUTE, 0), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)])
        );
    }

    /// A relative jump is not threaded backwards.
    #[test]
    fn relative_jump_is_not_threaded_backwards() {
        let result = run(
            &[(op::SETUP_LOOP, 0), (op::JUMP_FORWARD, 3), (op::JUMP_ABSOLUTE, 0), (op::FOR_ITER, 0), (op::JUMP_ABSOLUTE, 3), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &[],
            &[],
        );

        assert_eq!(result.code, encode(&[(op::SETUP_LOOP, 6), (op::JUMP_FORWARD, 3), (op::JUMP_ABSOLUTE, 0), (op::FOR_ITER, 0), (op::JUMP_ABSOLUTE, 9), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn or_pop_jump_to_same_test_jumps_to_its_target() {
        let result = run(
            &[
                (op::LOAD_NAME, 0),
                (op::JUMP_IF_FALSE_OR_POP, 9),
                (op::LOAD_NAME, 1),
                (op::JUMP_IF_FALSE_OR_POP, 15),
                (op::LOAD_NAME, 2),
                (op::STORE_NAME, 3),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ],
            vec![Object::None],
            &["a", "b", "c", "d"],
            &[],
        );

        assert_eq!(
            result.code,
            encode(&[
                (op::LOAD_NAME, 0),
                (op::JUMP_IF_FALSE_OR_POP, 15),
                (op::LOAD_NAME, 1),
                (op::JUMP_IF_FALSE_OR_POP, 15),
                (op::LOAD_NAME, 2),
                (op::STORE_NAME, 3),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ])
        );
    }

    #[test]
    fn or_pop_jump_to_opposite_test_pops_and_skips_it() {
        let result = run(
            &[
                (op::LOAD_NAME, 0),
                (op::JUMP_IF_TRUE_OR_POP, 9),
                (op::LOAD_NAME, 1),
                (op::JUMP_IF_FALSE_OR_POP, 15),
                (op::LOAD_NAME, 2),
                (op::STORE_NAME, 3),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ],
            vec![Object::None],
            &["a", "b", "c", "d"],
            &[],
        );

        assert_eq!(
            result.code,
            encode(&[
                (op::LOAD_NAME, 0),
                (op::POP_JUMP_IF_TRUE, 12),
                (op::LOAD_NAME, 1),
                (op::JUMP_IF_FALSE_OR_POP, 15),
                (op::LOAD_NAME, 2),
                (op::STORE_NAME, 3),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ])
        );
    }

    /// A merged conditional jump is examined again: it follows a chain of
    /// conditional jumps and then an unconditional one.
    #[test]
    fn merged_condition_is_threaded_again() {
        let result =
            run(&[(op::LOAD_NAME, 0), (op::JUMP_IF_FALSE_OR_POP, 6), (op::POP_JUMP_IF_FALSE, 9), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)], vec![Object::None], &["x"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 0), (op::POP_JUMP_IF_FALSE, 0), (op::JUMP_ABSOLUTE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    /// Two conditional jumps that lead to each other are left alone instead
    /// of being rewritten forever.
    #[test]
    fn conditional_jump_cycle_terminates() {
        let instructions = [(op::LOAD_NAME, 0), (op::JUMP_IF_FALSE_OR_POP, 6), (op::JUMP_IF_FALSE_OR_POP, 3), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)];
        let result = run(&instructions, vec![Object::None], &["x"], &[]);

        assert_eq!(result.code.len(), encode(&instructions).len());
    }

    /// An unconditional jump to `RETURN_VALUE` returns directly; the freed
    /// bytes go and the later jump target and `lnotab` address move back.
    #[test]
    fn jump_to_return_becomes_return() {
        let result = run(
            &[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 12), (op::LOAD_CONST, 0), (op::JUMP_FORWARD, 3), (op::LOAD_CONST, 1), (op::RETURN_VALUE, 0)],
            vec![Object::Int(1), Object::None],
            &["x"],
            &[0, 1, 6, 1, 6, 1],
        );

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_FALSE, 10), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0), (op::LOAD_CONST, 1), (op::RETURN_VALUE, 0)]));
        assert_eq!(result.lnotab, [0, 1, 6, 1, 4, 1]);
    }

    #[test]
    fn load_global_none_appends_none_constant() {
        let result = run(&[(op::LOAD_GLOBAL, 0), (op::RETURN_VALUE, 0)], vec![Object::Int(1)], &["None"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_CONST, 1), (op::RETURN_VALUE, 0)]));
        assert_eq!(result.consts, [Constant::Int(1), Constant::None]);
    }

    /// The existing `None` constant is reused. The other name loaded first
    /// interrupts the run of constants, so no tuple is folded.
    #[test]
    fn load_name_none_reuses_none_constant() {
        let result = run(&[(op::LOAD_NAME, 1), (op::LOAD_NAME, 0), (op::BUILD_TUPLE, 2), (op::RETURN_VALUE, 0)], vec![Object::Int(1), Object::None], &["None", "x"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 1), (op::LOAD_CONST, 1), (op::BUILD_TUPLE, 2), (op::RETURN_VALUE, 0)]));
        assert_eq!(result.consts, [Constant::Int(1), Constant::None]);
    }

    /// Names are compared up to their first NUL byte.
    #[test]
    fn none_name_ends_at_nul() {
        let result = run(&[(op::LOAD_GLOBAL, 0), (op::RETURN_VALUE, 0)], vec![Object::None], &["None\0y"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    /// The `None` loaded by name counts as a constant of the tuple.
    #[test]
    fn folds_tuple_of_constants() {
        let result = run(
            &[
                (op::LOAD_NAME, 1),
                (op::POP_TOP, 0),
                (op::LOAD_CONST, 0),
                (op::LOAD_CONST, 1),
                (op::LOAD_NAME, 0),
                (op::BUILD_TUPLE, 3),
                (op::STORE_NAME, 1),
                (op::LOAD_CONST, 2),
                (op::RETURN_VALUE, 0),
            ],
            vec![Object::Int(1), interned("a"), Object::None],
            &["None", "x"],
            &[0, 1, 4, 1, 12, 1],
        );

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 1), (op::POP_TOP, 0), (op::LOAD_CONST, 3), (op::STORE_NAME, 1), (op::LOAD_CONST, 2), (op::RETURN_VALUE, 0)]));
        let tuple = Constant::Tuple(vec![Constant::Int(1), Constant::Str { value: b"a".to_vec(), interned: true }, Constant::None]);
        assert_eq!(result.consts, [Constant::Int(1), Constant::Str { value: b"a".to_vec(), interned: true }, Constant::None, tuple]);
        assert_eq!(result.lnotab, [0, 1, 4, 1, 3, 1]);
    }

    /// A folded tuple counts as one constant for an enclosing tuple, but a
    /// folded binary operation leaves padding that ends the run.
    #[test]
    fn folded_results_join_only_later_runs() {
        let nested =
            run(&[(op::LOAD_CONST, 0), (op::LOAD_CONST, 1), (op::BUILD_TUPLE, 2), (op::LOAD_CONST, 0), (op::BUILD_TUPLE, 2), (op::RETURN_VALUE, 0)], vec![Object::Int(1), Object::Int(2)], &[], &[]);
        let after_binary = run(
            &[(op::LOAD_CONST, 0), (op::LOAD_CONST, 1), (op::LOAD_CONST, 1), (op::BINARY_MULTIPLY, 0), (op::BUILD_TUPLE, 2), (op::RETURN_VALUE, 0)],
            vec![Object::Int(1), Object::Int(2)],
            &[],
            &[],
        );

        assert_eq!(nested.code, encode(&[(op::LOAD_CONST, 3), (op::RETURN_VALUE, 0)]));
        assert_eq!(after_binary.code, encode(&[(op::LOAD_CONST, 0), (op::LOAD_CONST, 2), (op::BUILD_TUPLE, 2), (op::RETURN_VALUE, 0)]));
        assert_eq!(after_binary.consts, [Constant::Int(1), Constant::Int(2), Constant::Int(4)]);
    }

    #[test]
    fn folds_list_of_constants_tested_with_in() {
        let result =
            run(&[(op::LOAD_NAME, 0), (op::LOAD_CONST, 0), (op::LOAD_CONST, 1), (op::BUILD_LIST, 2), (op::COMPARE_OP, 6), (op::RETURN_VALUE, 0)], vec![Object::Int(1), Object::Int(2)], &["x"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::LOAD_CONST, 2), (op::COMPARE_OP, 6), (op::RETURN_VALUE, 0)]));
        assert_eq!(result.consts, [Constant::Int(1), Constant::Int(2), Constant::Tuple(vec![Constant::Int(1), Constant::Int(2)])]);
    }

    #[test]
    fn keeps_list_of_constants_tested_for_equality() {
        let instructions = [(op::LOAD_CONST, 0), (op::LOAD_CONST, 1), (op::BUILD_LIST, 2), (op::COMPARE_OP, 2), (op::RETURN_VALUE, 0)];
        let result = run(&instructions, vec![Object::Int(1), Object::Int(2)], &[], &[]);

        assert_eq!(result.code, encode(&instructions));
        assert_eq!(result.consts, [Constant::Int(1), Constant::Int(2)]);
    }

    #[test]
    fn negation_folds_only_true_operands() {
        let one = run(&[(op::LOAD_CONST, 0), (op::UNARY_NEGATIVE, 0), (op::RETURN_VALUE, 0)], vec![Object::Int(1)], &[], &[]);
        let zero = run(&[(op::LOAD_CONST, 0), (op::UNARY_NEGATIVE, 0), (op::RETURN_VALUE, 0)], vec![Object::Float(0.0)], &[], &[]);

        assert_eq!(one.code, encode(&[(op::LOAD_CONST, 1), (op::RETURN_VALUE, 0)]));
        assert_eq!(one.consts, [Constant::Int(1), Constant::Int(-1)]);
        assert_eq!(zero.code, encode(&[(op::LOAD_CONST, 0), (op::UNARY_NEGATIVE, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn true_constant_test_is_removed() {
        let result = run(&[(op::LOAD_CONST, 0), (op::POP_JUMP_IF_FALSE, 7), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)], vec![Object::Int(1)], &[], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn build_and_unpack_one_is_removed() {
        let result = run(&[(op::LOAD_NAME, 0), (op::BUILD_TUPLE, 1), (op::UNPACK_SEQUENCE, 1), (op::STORE_NAME, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)], vec![Object::None], &["a"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::STORE_NAME, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn build_and_unpack_two_becomes_rot_two() {
        let result = run(
            &[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::BUILD_TUPLE, 2), (op::UNPACK_SEQUENCE, 2), (op::STORE_NAME, 0), (op::STORE_NAME, 1), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["a", "b"],
            &[],
        );

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::ROT_TWO, 0), (op::STORE_NAME, 0), (op::STORE_NAME, 1), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn build_list_and_unpack_three_becomes_rotations() {
        let result = run(
            &[
                (op::LOAD_NAME, 0),
                (op::LOAD_NAME, 1),
                (op::LOAD_NAME, 2),
                (op::BUILD_LIST, 3),
                (op::UNPACK_SEQUENCE, 3),
                (op::STORE_NAME, 0),
                (op::STORE_NAME, 1),
                (op::STORE_NAME, 2),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ],
            vec![Object::None],
            &["a", "b", "c"],
            &[],
        );

        assert_eq!(
            result.code,
            encode(&[
                (op::LOAD_NAME, 0),
                (op::LOAD_NAME, 1),
                (op::LOAD_NAME, 2),
                (op::ROT_THREE, 0),
                (op::ROT_TWO, 0),
                (op::STORE_NAME, 0),
                (op::STORE_NAME, 1),
                (op::STORE_NAME, 2),
                (op::LOAD_CONST, 0),
                (op::RETURN_VALUE, 0),
            ])
        );
    }

    #[test]
    fn return_after_return_is_removed() {
        let result = run(&[(op::LOAD_NAME, 0), (op::RETURN_VALUE, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)], vec![Object::None], &["x"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::RETURN_VALUE, 0)]));
    }

    /// The unreachable jump goes and `SETUP_LOOP` moves its target back.
    #[test]
    fn jump_after_return_is_removed() {
        let result = run(
            &[(op::SETUP_LOOP, 8), (op::LOAD_NAME, 0), (op::RETURN_VALUE, 0), (op::JUMP_ABSOLUTE, 3), (op::POP_BLOCK, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["x"],
            &[],
        );

        assert_eq!(result.code, encode(&[(op::SETUP_LOOP, 5), (op::LOAD_NAME, 0), (op::RETURN_VALUE, 0), (op::POP_BLOCK, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
    }

    /// The test for a second return looks four bytes ahead, even when that
    /// byte is an argument; the padding then cuts an instruction in two.
    #[test]
    fn return_test_reads_raw_bytes() {
        let result = run(
            &[(op::LOAD_GLOBAL, 0), (op::RETURN_VALUE, 0), (op::POP_TOP, 0), (op::POP_TOP, 0), (op::LOAD_FAST, 0x0053), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["None"],
            &[],
        );

        assert_eq!(result.code, [op::LOAD_CONST, 0, 0, op::RETURN_VALUE, op::STOP_CODE, op::LOAD_CONST, 0, 0, op::RETURN_VALUE]);
    }

    #[test]
    fn not_before_pop_jump_if_false_inverts_the_jump() {
        let result = run(
            &[(op::LOAD_NAME, 0), (op::UNARY_NOT, 0), (op::POP_JUMP_IF_FALSE, 11), (op::LOAD_NAME, 0), (op::POP_TOP, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)],
            vec![Object::None],
            &["x"],
            &[0, 1, 7, 1],
        );

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::POP_JUMP_IF_TRUE, 10), (op::LOAD_NAME, 0), (op::POP_TOP, 0), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)]));
        assert_eq!(result.lnotab, [0, 1, 6, 1]);
    }

    #[test]
    fn not_after_identity_or_membership_test_inverts_it() {
        let is = run(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 8), (op::UNARY_NOT, 0), (op::RETURN_VALUE, 0)], Vec::new(), &["a", "b"], &[]);
        let not_in = run(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 7), (op::UNARY_NOT, 0), (op::RETURN_VALUE, 0)], Vec::new(), &["a", "b"], &[]);

        assert_eq!(is.code, encode(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 9), (op::RETURN_VALUE, 0)]));
        assert_eq!(not_in.code, encode(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 6), (op::RETURN_VALUE, 0)]));
    }

    /// A jump destination between the comparison and `not` keeps both. The
    /// unreachable jump after the first return still goes.
    #[test]
    fn jump_destination_blocks_inverting_comparison() {
        let result =
            run(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 8), (op::UNARY_NOT, 0), (op::RETURN_VALUE, 0), (op::JUMP_ABSOLUTE, 9), (op::RETURN_VALUE, 0)], Vec::new(), &["a", "b"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_NAME, 0), (op::LOAD_NAME, 1), (op::COMPARE_OP, 8), (op::UNARY_NOT, 0), (op::RETURN_VALUE, 0)]));
    }

    #[test]
    fn lnotab_byte_255_leaves_code_unchanged() {
        let instructions = [(op::LOAD_NAME, 0), (op::BUILD_TUPLE, 1), (op::UNPACK_SEQUENCE, 1), (op::RETURN_VALUE, 0)];
        let result = run(&instructions, Vec::new(), &["None"], &[255, 0, 10, 1]);

        assert_eq!(result.code, encode(&instructions));
        assert!(result.consts.is_empty());
        assert_eq!(result.lnotab, [255, 0, 10, 1]);
    }

    /// `EXTENDED_ARG` stops the optimization, but the `None` appended for
    /// an earlier `LOAD_GLOBAL None` stays.
    #[test]
    fn extended_arg_leaves_code_unchanged_after_appending() {
        let instructions = [(op::LOAD_GLOBAL, 0), (op::POP_TOP, 0), (op::EXTENDED_ARG, 0), (op::LOAD_NAME, 1), (op::LOAD_CONST, 0), (op::RETURN_VALUE, 0)];
        let result = run(&instructions, vec![Object::Int(1)], &["None"], &[]);

        assert_eq!(result.code, encode(&instructions));
        assert_eq!(result.consts, [Constant::Int(1), Constant::None]);
    }

    #[test]
    fn code_without_final_return_is_unchanged() {
        let instructions = [(op::LOAD_GLOBAL, 0), (op::RETURN_VALUE, 0), (op::POP_TOP, 0)];
        let result = run(&instructions, vec![Object::Int(1)], &["None"], &[]);

        assert_eq!(result.code, encode(&instructions));
        assert_eq!(result.consts, [Constant::Int(1)]);
    }

    /// The final byte is tested, not the final instruction.
    #[test]
    fn final_return_byte_may_be_an_argument() {
        let result = run(&[(op::LOAD_GLOBAL, 0), (op::LOAD_FAST, 0x5300)], vec![Object::None], &["None"], &[]);

        assert_eq!(result.code, encode(&[(op::LOAD_CONST, 0), (op::LOAD_FAST, 0x5300)]));
    }

    #[test]
    fn code_above_32700_bytes_is_unchanged() {
        let instructions = |pops: usize| {
            let mut instructions = vec![(op::LOAD_GLOBAL, 0)];
            instructions.extend(std::iter::repeat_n((op::POP_TOP, 0), pops));
            instructions.push((op::RETURN_VALUE, 0));
            instructions
        };

        let too_long = run(&instructions(32697), vec![Object::Int(1)], &["None"], &[]);
        assert_eq!(too_long.code.len(), 32701);
        assert_eq!(too_long.code, encode(&instructions(32697)));
        assert_eq!(too_long.consts, [Constant::Int(1)]);

        let at_limit = run(&instructions(32696), vec![Object::Int(1)], &["None"], &[]);
        assert_eq!(at_limit.code.get(..3), Some(&[op::LOAD_CONST, 1, 0][..]));
        assert_eq!(at_limit.consts, [Constant::Int(1), Constant::None]);
    }
}
