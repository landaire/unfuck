//! Turns a unit's basic blocks into bytecode: orders the reachable blocks,
//! resolves jump arguments, writes `co_lnotab`, and computes the maximum
//! stack depth.

use crate::interp::code::op;
use crate::interp::compiler::context::CompileError;

/// An index into a unit's basic blocks, in allocation order.
pub type BlockIndex = usize;

/// How an instruction refers to its target block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jump {
    /// The argument is the target's code offset.
    Absolute(BlockIndex),
    /// The argument counts from the end of the jump instruction.
    Relative(BlockIndex),
}

impl Jump {
    fn target(self) -> BlockIndex {
        match self {
            Self::Absolute(target) | Self::Relative(target) => target,
        }
    }
}

/// One instruction before layout. Jump arguments are filled in by
/// `assemble`.
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    pub opcode: u8,
    /// `None` for opcodes that take no argument.
    pub arg: Option<i32>,
    pub jump: Option<Jump>,
    /// The source line this instruction starts, if it starts one. Line 0,
    /// which only trees built through `_ast` carry, adds no `lnotab` entry.
    pub line: Option<i32>,
}

impl Instruction {
    /// Encoded size in bytes: arguments above 16 bits take an
    /// `EXTENDED_ARG` prefix.
    fn size(&self) -> i32 {
        match self.arg {
            None => 1,
            Some(arg) if arg > 0xffff => 6,
            Some(_) => 3,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BasicBlock {
    pub instructions: Vec<Instruction>,
    /// The block reached by falling off the end of this one.
    pub next: Option<BlockIndex>,
    /// A `RETURN_VALUE` was added to the block.
    pub returns: bool,
}

/// Bytecode and line table of a unit, before optimization.
pub struct Assembly {
    pub code: Vec<u8>,
    pub lnotab: Vec<u8>,
}

struct Writer {
    code: Vec<u8>,
    lines: LineTable,
}

impl Writer {
    fn write(&mut self, instruction: &Instruction) {
        if let Some(line) = instruction.line.filter(|&line| line != 0) {
            self.lines.record(self.code.len(), line);
        }

        let Some(arg) = instruction.arg else {
            self.code.push(instruction.opcode);
            return;
        };

        // Arguments are C ints; only the low 32 bits are encoded.
        let [low, high, extended_low, extended_high] = arg.to_le_bytes();
        if instruction.size() == 6 {
            self.code.extend_from_slice(&[op::EXTENDED_ARG, extended_low, extended_high]);
        }
        self.code.extend_from_slice(&[instruction.opcode, low, high]);
    }
}

/// The `co_lnotab` encoding: pairs of (bytecode offset increment, line
/// increment) bytes, written each time an instruction starts a line.
struct LineTable {
    table: Vec<u8>,
    offset: usize,
    line: i32,
}

impl LineTable {
    fn new(first_line: i32) -> Self {
        Self { table: Vec::new(), offset: 0, line: first_line }
    }

    fn record(&mut self, offset: usize, line: i32) {
        const STEP: u8 = 255;

        let mut offset_step = offset - self.offset;
        let mut line_step = line.wrapping_sub(self.line);
        if offset_step == 0 && line_step == 0 {
            return;
        }

        // Increments above 255 are spread over several pairs, the offset
        // first. A line that goes backwards wraps around in the byte.
        if offset_step > usize::from(STEP) {
            let pairs = offset_step / usize::from(STEP);
            self.table.extend(std::iter::repeat_n([STEP, 0], pairs).flatten());
            offset_step %= usize::from(STEP);
        }
        if line_step > i32::from(STEP) {
            let pairs = line_step / i32::from(STEP);
            self.table.extend_from_slice(&[offset_step as u8, STEP]);
            self.table.extend(std::iter::repeat_n([0, STEP], (pairs - 1) as usize).flatten());
            offset_step = 0;
            line_step %= i32::from(STEP);
        }
        self.table.extend_from_slice(&[offset_step as u8, line_step as u8]);

        self.offset = offset;
        self.line = line;
    }
}

/// Lays out the blocks reachable from the entry block (index 0) and emits
/// their bytecode. Line numbers in `lnotab` count from `first_line`.
pub fn assemble(blocks: &mut [BasicBlock], first_line: i32) -> Assembly {
    let order = layout_order(blocks);
    resolve_jumps(blocks, &order);

    let mut writer = Writer { code: Vec::new(), lines: LineTable::new(first_line) };
    for &block in &order {
        for instruction in &blocks[block].instructions {
            writer.write(instruction);
        }
    }

    Assembly { code: writer.code, lnotab: writer.lines.table }
}

/// The reachable blocks in layout order: the reverse of a depth-first
/// post-order that explores a block's fall-through successor first and
/// then its jump targets in instruction order.
fn layout_order(blocks: &[BasicBlock]) -> Vec<BlockIndex> {
    /// A block on the current search path.
    struct Visit {
        block: BlockIndex,
        fell_through: bool,
        /// Where to look for the next jump.
        position: usize,
    }

    let mut finished = Vec::new();
    if blocks.is_empty() {
        return finished;
    }

    let mut visited = vec![false; blocks.len()];
    visited[0] = true;
    let mut path = vec![Visit { block: 0, fell_through: false, position: 0 }];

    while let Some(visit) = path.last_mut() {
        let block = &blocks[visit.block];
        let successor = if visit.fell_through {
            let rest = block.instructions.get(visit.position..).unwrap_or_default();
            let Some((skipped, jump)) = rest.iter().enumerate().find_map(|(skipped, instruction)| Some((skipped, instruction.jump?))) else {
                finished.push(visit.block);
                path.pop();
                continue;
            };
            visit.position += skipped + 1;
            Some(jump.target())
        } else {
            visit.fell_through = true;
            block.next
        };

        if let Some(successor) = successor
            && !visited[successor]
        {
            visited[successor] = true;
            path.push(Visit { block: successor, fell_through: false, position: 0 });
        }
    }

    finished.reverse();

    finished
}

/// Assigns block offsets and jump arguments. A jump argument above 16 bits
/// grows its instruction, which moves later blocks, so this repeats until
/// the number of such jumps stops changing. Blocks outside the layout
/// keep offset 0 but are still counted.
fn resolve_jumps(blocks: &mut [BasicBlock], order: &[BlockIndex]) {
    let mut offsets = vec![0i32; blocks.len()];
    let mut wide_jumps = None;

    loop {
        let mut offset = 0;
        for &block in order {
            offsets[block] = offset;
            offset += blocks[block].instructions.iter().map(Instruction::size).sum::<i32>();
        }

        let mut count = 0;
        for (block, start) in blocks.iter_mut().zip(offsets.iter().copied()).rev() {
            let mut end = start;
            for instruction in &mut block.instructions {
                end += instruction.size();
                let Some(jump) = instruction.jump else {
                    continue;
                };

                let arg = match jump {
                    Jump::Absolute(target) => offsets[target],
                    Jump::Relative(target) => offsets[target] - end,
                };
                instruction.arg = Some(arg);
                if arg > 0xffff {
                    count += 1;
                }
            }
        }

        if wide_jumps == Some(count) {
            return;
        }
        wide_jumps = Some(count);
    }
}

/// The deepest value stack any path from the entry block reaches.
///
/// Each block is explored depth-first from every jump or fall-through that
/// reaches it with a deeper stack than seen before, and is not re-entered
/// while it is on the current path.
pub fn stack_depth(blocks: &[BasicBlock]) -> Result<i32, CompileError> {
    /// A block on the current path.
    struct Visit {
        block: BlockIndex,
        depth: i32,
        position: usize,
        /// Set once the rest of the block is unreachable or its successor
        /// has been entered; the visit ends when control returns to it.
        exhausted: bool,
    }

    struct Explorer {
        on_path: Vec<bool>,
        entry_depth: Vec<Option<i32>>,
        path: Vec<Visit>,
    }

    impl Explorer {
        fn enter(&mut self, block: BlockIndex, depth: i32) {
            if self.on_path[block] || self.entry_depth[block].is_some_and(|entry| entry >= depth) {
                return;
            }

            self.on_path[block] = true;
            self.entry_depth[block] = Some(depth);
            self.path.push(Visit { block, depth, position: 0, exhausted: false });
        }
    }

    if blocks.is_empty() {
        return Ok(0);
    }

    let mut explorer = Explorer { on_path: vec![false; blocks.len()], entry_depth: vec![None; blocks.len()], path: Vec::new() };
    let mut deepest = 0;
    explorer.enter(0, 0);

    while let Some(visit) = explorer.path.last_mut() {
        if visit.exhausted {
            let block = visit.block;
            explorer.path.pop();
            explorer.on_path[block] = false;
            continue;
        }

        let block = &blocks[visit.block];
        let mut branch = None;
        while let Some(instruction) = block.instructions.get(visit.position) {
            visit.position += 1;
            visit.depth += stack_effect(instruction.opcode, instruction.arg.unwrap_or(0))?;
            deepest = deepest.max(visit.depth);

            let Some(jump) = instruction.jump else {
                continue;
            };

            let target_depth = match instruction.opcode {
                // The target runs after the iterator is exhausted and popped.
                op::FOR_ITER => visit.depth - 2,
                // The handler starts with the exception triple pushed.
                op::SETUP_FINALLY | op::SETUP_EXCEPT => {
                    deepest = deepest.max(visit.depth + 3);
                    visit.depth + 3
                }
                // The value stays on the stack only when the jump is taken.
                op::JUMP_IF_TRUE_OR_POP | op::JUMP_IF_FALSE_OR_POP => {
                    visit.depth -= 1;
                    visit.depth + 1
                }
                _ => visit.depth,
            };
            if matches!(instruction.opcode, op::JUMP_ABSOLUTE | op::JUMP_FORWARD) {
                visit.exhausted = true;
            }
            branch = Some((jump.target(), target_depth));
            break;
        }

        if let Some((target, depth)) = branch {
            explorer.enter(target, depth);
            continue;
        }

        visit.exhausted = true;
        let depth = visit.depth;
        if let Some(next) = block.next {
            explorer.enter(next, depth);
        }
    }

    Ok(deepest)
}

/// How many values an instruction leaves on the stack, minus how many it
/// takes, as the stack size computation counts them.
fn stack_effect(opcode: u8, arg: i32) -> Result<i32, CompileError> {
    // The low byte counts positional arguments, the high byte keyword
    // pairs.
    let call_operands = |arg: i32| (arg % 256) + 2 * (arg / 256);

    let effect = match opcode {
        op::ROT_TWO | op::ROT_THREE | op::ROT_FOUR => 0,
        op::UNARY_POSITIVE | op::UNARY_NEGATIVE | op::UNARY_NOT | op::UNARY_CONVERT | op::UNARY_INVERT | op::GET_ITER => 0,
        op::LOAD_ATTR | op::DELETE_NAME | op::DELETE_GLOBAL | op::DELETE_FAST => 0,
        op::PRINT_NEWLINE | op::BREAK_LOOP | op::YIELD_VALUE | op::POP_BLOCK => 0,
        op::JUMP_FORWARD | op::JUMP_ABSOLUTE | op::CONTINUE_LOOP | op::JUMP_IF_TRUE_OR_POP | op::JUMP_IF_FALSE_OR_POP => 0,
        op::SETUP_LOOP | op::SETUP_EXCEPT | op::SETUP_FINALLY => 0,

        op::DUP_TOP | op::LOAD_LOCALS | op::FOR_ITER | op::IMPORT_FROM | op::BUILD_MAP => 1,
        op::LOAD_CONST | op::LOAD_NAME | op::LOAD_GLOBAL | op::LOAD_FAST | op::LOAD_CLOSURE | op::LOAD_DEREF => 1,
        op::SETUP_WITH => 4,

        op::BINARY_POWER | op::BINARY_MULTIPLY | op::BINARY_DIVIDE | op::BINARY_MODULO | op::BINARY_ADD | op::BINARY_SUBTRACT => -1,
        op::BINARY_SUBSCR | op::BINARY_FLOOR_DIVIDE | op::BINARY_TRUE_DIVIDE => -1,
        op::BINARY_LSHIFT | op::BINARY_RSHIFT | op::BINARY_AND | op::BINARY_XOR | op::BINARY_OR => -1,
        op::INPLACE_ADD | op::INPLACE_SUBTRACT | op::INPLACE_MULTIPLY | op::INPLACE_DIVIDE | op::INPLACE_MODULO | op::INPLACE_POWER => -1,
        op::INPLACE_FLOOR_DIVIDE | op::INPLACE_TRUE_DIVIDE => -1,
        op::INPLACE_LSHIFT | op::INPLACE_RSHIFT | op::INPLACE_AND | op::INPLACE_XOR | op::INPLACE_OR => -1,
        op::POP_TOP | op::LIST_APPEND | op::SET_ADD | op::COMPARE_OP | op::IMPORT_NAME | op::IMPORT_STAR => -1,
        op::STORE_NAME | op::STORE_GLOBAL | op::STORE_FAST | op::STORE_DEREF | op::DELETE_ATTR => -1,
        op::PRINT_EXPR | op::PRINT_ITEM | op::PRINT_NEWLINE_TO | op::RETURN_VALUE | op::WITH_CLEANUP => -1,
        op::POP_JUMP_IF_FALSE | op::POP_JUMP_IF_TRUE => -1,
        op::MAP_ADD | op::STORE_MAP | op::DELETE_SUBSCR | op::STORE_ATTR | op::PRINT_ITEM_TO | op::BUILD_CLASS => -2,
        op::STORE_SUBSCR | op::EXEC_STMT | op::END_FINALLY => -3,

        // `SLICE+n`, `STORE_SLICE+n`, and `DELETE_SLICE+n`: bit 0 of `n`
        // means a lower bound is on the stack, bit 1 an upper bound.
        opcode if (op::SLICE..op::SLICE + 4).contains(&opcode) => -slice_bounds(opcode - op::SLICE),
        opcode if (op::STORE_SLICE..op::STORE_SLICE + 4).contains(&opcode) => -2 - slice_bounds(opcode - op::STORE_SLICE),
        opcode if (op::DELETE_SLICE..op::DELETE_SLICE + 4).contains(&opcode) => -1 - slice_bounds(opcode - op::DELETE_SLICE),

        op::UNPACK_SEQUENCE => arg - 1,
        op::DUP_TOPX => arg,
        op::BUILD_TUPLE | op::BUILD_LIST | op::BUILD_SET => 1 - arg,
        op::RAISE_VARARGS | op::MAKE_FUNCTION => -arg,
        op::MAKE_CLOSURE => -arg - 1,
        op::BUILD_SLICE if arg == 3 => -2,
        op::BUILD_SLICE => -1,
        op::CALL_FUNCTION => -call_operands(arg),
        op::CALL_FUNCTION_VAR | op::CALL_FUNCTION_KW => -call_operands(arg) - 1,
        op::CALL_FUNCTION_VAR_KW => -call_operands(arg) - 2,

        _ => return Err(CompileError::System { message: format!("no stack effect known for opcode {opcode}") }),
    };

    Ok(effect)
}

/// The number of slice bounds selected by the low two bits of a slice
/// opcode's offset.
fn slice_bounds(variant: u8) -> i32 {
    i32::from(variant & 1) + i32::from(variant >> 1 & 1)
}
