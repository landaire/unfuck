use crate::interp::value::PyBytes;
use crate::interp::value::Value;

/// `co_flags` bits of a Python 2.7 code object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeFlags(pub u32);

impl CodeFlags {
    pub const OPTIMIZED: u32 = 0x1;
    pub const NEWLOCALS: u32 = 0x2;
    pub const VARARGS: u32 = 0x4;
    pub const VARKEYWORDS: u32 = 0x8;
    pub const NESTED: u32 = 0x10;
    pub const GENERATOR: u32 = 0x20;
    pub const NOFREE: u32 = 0x40;
    pub const FUTURE_DIVISION: u32 = 0x2000;
    pub const FUTURE_ABSOLUTE_IMPORT: u32 = 0x4000;
    pub const FUTURE_UNICODE_LITERALS: u32 = 0x20000;

    pub fn contains(self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

#[derive(Debug)]
pub struct CodeObject {
    pub argcount: u32,
    pub nlocals: u32,
    pub stacksize: u32,
    pub flags: CodeFlags,
    pub code: Box<[u8]>,
    pub consts: Vec<Value>,
    pub names: Vec<PyBytes>,
    pub varnames: Vec<PyBytes>,
    pub freevars: Vec<PyBytes>,
    pub cellvars: Vec<PyBytes>,
    pub filename: PyBytes,
    pub name: PyBytes,
    pub firstlineno: u32,
    pub lnotab: PyBytes,
}

impl CodeObject {
    /// Source line of the instruction at `offset`, from `co_lnotab`.
    pub fn line_at(&self, offset: usize) -> u32 {
        let table = self.lnotab.as_bytes();
        let mut line = self.firstlineno;
        let mut address = 0usize;

        for pair in table.chunks_exact(2) {
            address += usize::from(pair[0]);
            if address > offset {
                break;
            }
            line += u32::from(pair[1]);
        }

        line
    }
}

/// Python 2.7 opcode numbers (`Lib/opcode.py`).
pub mod op {
    pub const STOP_CODE: u8 = 0;
    pub const POP_TOP: u8 = 1;
    pub const ROT_TWO: u8 = 2;
    pub const ROT_THREE: u8 = 3;
    pub const DUP_TOP: u8 = 4;
    pub const ROT_FOUR: u8 = 5;
    pub const NOP: u8 = 9;
    pub const UNARY_POSITIVE: u8 = 10;
    pub const UNARY_NEGATIVE: u8 = 11;
    pub const UNARY_NOT: u8 = 12;
    pub const UNARY_CONVERT: u8 = 13;
    pub const UNARY_INVERT: u8 = 15;
    pub const BINARY_POWER: u8 = 19;
    pub const BINARY_MULTIPLY: u8 = 20;
    pub const BINARY_DIVIDE: u8 = 21;
    pub const BINARY_MODULO: u8 = 22;
    pub const BINARY_ADD: u8 = 23;
    pub const BINARY_SUBTRACT: u8 = 24;
    pub const BINARY_SUBSCR: u8 = 25;
    pub const BINARY_FLOOR_DIVIDE: u8 = 26;
    pub const BINARY_TRUE_DIVIDE: u8 = 27;
    pub const INPLACE_FLOOR_DIVIDE: u8 = 28;
    pub const INPLACE_TRUE_DIVIDE: u8 = 29;
    pub const SLICE: u8 = 30;
    pub const STORE_SLICE: u8 = 40;
    pub const DELETE_SLICE: u8 = 50;
    pub const STORE_MAP: u8 = 54;
    pub const INPLACE_ADD: u8 = 55;
    pub const INPLACE_SUBTRACT: u8 = 56;
    pub const INPLACE_MULTIPLY: u8 = 57;
    pub const INPLACE_DIVIDE: u8 = 58;
    pub const INPLACE_MODULO: u8 = 59;
    pub const STORE_SUBSCR: u8 = 60;
    pub const DELETE_SUBSCR: u8 = 61;
    pub const BINARY_LSHIFT: u8 = 62;
    pub const BINARY_RSHIFT: u8 = 63;
    pub const BINARY_AND: u8 = 64;
    pub const BINARY_XOR: u8 = 65;
    pub const BINARY_OR: u8 = 66;
    pub const INPLACE_POWER: u8 = 67;
    pub const GET_ITER: u8 = 68;
    pub const PRINT_EXPR: u8 = 70;
    pub const PRINT_ITEM: u8 = 71;
    pub const PRINT_NEWLINE: u8 = 72;
    pub const PRINT_ITEM_TO: u8 = 73;
    pub const PRINT_NEWLINE_TO: u8 = 74;
    pub const INPLACE_LSHIFT: u8 = 75;
    pub const INPLACE_RSHIFT: u8 = 76;
    pub const INPLACE_AND: u8 = 77;
    pub const INPLACE_XOR: u8 = 78;
    pub const INPLACE_OR: u8 = 79;
    pub const BREAK_LOOP: u8 = 80;
    pub const WITH_CLEANUP: u8 = 81;
    pub const LOAD_LOCALS: u8 = 82;
    pub const RETURN_VALUE: u8 = 83;
    pub const IMPORT_STAR: u8 = 84;
    pub const EXEC_STMT: u8 = 85;
    pub const YIELD_VALUE: u8 = 86;
    pub const POP_BLOCK: u8 = 87;
    pub const END_FINALLY: u8 = 88;
    pub const BUILD_CLASS: u8 = 89;
    pub const HAVE_ARGUMENT: u8 = 90;
    pub const STORE_NAME: u8 = 90;
    pub const DELETE_NAME: u8 = 91;
    pub const UNPACK_SEQUENCE: u8 = 92;
    pub const FOR_ITER: u8 = 93;
    pub const LIST_APPEND: u8 = 94;
    pub const STORE_ATTR: u8 = 95;
    pub const DELETE_ATTR: u8 = 96;
    pub const STORE_GLOBAL: u8 = 97;
    pub const DELETE_GLOBAL: u8 = 98;
    pub const DUP_TOPX: u8 = 99;
    pub const LOAD_CONST: u8 = 100;
    pub const LOAD_NAME: u8 = 101;
    pub const BUILD_TUPLE: u8 = 102;
    pub const BUILD_LIST: u8 = 103;
    pub const BUILD_SET: u8 = 104;
    pub const BUILD_MAP: u8 = 105;
    pub const LOAD_ATTR: u8 = 106;
    pub const COMPARE_OP: u8 = 107;
    pub const IMPORT_NAME: u8 = 108;
    pub const IMPORT_FROM: u8 = 109;
    pub const JUMP_FORWARD: u8 = 110;
    pub const JUMP_IF_FALSE_OR_POP: u8 = 111;
    pub const JUMP_IF_TRUE_OR_POP: u8 = 112;
    pub const JUMP_ABSOLUTE: u8 = 113;
    pub const POP_JUMP_IF_FALSE: u8 = 114;
    pub const POP_JUMP_IF_TRUE: u8 = 115;
    pub const LOAD_GLOBAL: u8 = 116;
    pub const CONTINUE_LOOP: u8 = 119;
    pub const SETUP_LOOP: u8 = 120;
    pub const SETUP_EXCEPT: u8 = 121;
    pub const SETUP_FINALLY: u8 = 122;
    pub const LOAD_FAST: u8 = 124;
    pub const STORE_FAST: u8 = 125;
    pub const DELETE_FAST: u8 = 126;
    pub const RAISE_VARARGS: u8 = 130;
    pub const CALL_FUNCTION: u8 = 131;
    pub const MAKE_FUNCTION: u8 = 132;
    pub const BUILD_SLICE: u8 = 133;
    pub const MAKE_CLOSURE: u8 = 134;
    pub const LOAD_CLOSURE: u8 = 135;
    pub const LOAD_DEREF: u8 = 136;
    pub const STORE_DEREF: u8 = 137;
    pub const CALL_FUNCTION_VAR: u8 = 140;
    pub const CALL_FUNCTION_KW: u8 = 141;
    pub const CALL_FUNCTION_VAR_KW: u8 = 142;
    pub const SETUP_WITH: u8 = 143;
    pub const EXTENDED_ARG: u8 = 145;
    pub const SET_ADD: u8 = 146;
    pub const MAP_ADD: u8 = 147;
}
