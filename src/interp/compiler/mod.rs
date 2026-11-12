//! A Python 2.7.12 source compiler. `tokenizer` and `parser` build an
//! `ast` tree with the node classes of the `_ast` module, and `symtable`,
//! `codegen`, and `assemble` turn it into code objects with the bytecode
//! that `compile` emits. `marshal` writes them as `marshal.dumps` does.

pub mod assemble;
pub mod ast;
pub mod codegen;
pub mod context;
mod cst_to_ast;
pub mod fold;
pub mod future;
mod literals;
pub mod marshal;
pub mod object;
pub mod parser;
pub mod peephole;
pub mod source;
pub(crate) mod symbol;
pub mod symtable;
pub mod tokenizer;
pub mod unit;

pub use codegen::compile_ast;
pub use context::CompileContext;
pub use context::CompileError;
pub use parser::ParseError;
pub use parser::Parsed;
pub use parser::parse;
pub use parser::parse_with_codecs;
pub use parser::parse_with_flags;
pub use unit::CodeUnit;
pub use unit::Constant;

/// The `mode` argument of `compile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Exec,
    Eval,
    Single,
}

/// `co_flags` and `compile` flag bits accepted by `compile` and set by `__future__`
/// imports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompilerFlags(pub u32);

impl CompilerFlags {
    pub const SOURCE_IS_UTF8: u32 = 0x0100;
    pub const DONT_IMPLY_DEDENT: u32 = 0x0200;
    pub const ONLY_AST: u32 = 0x0400;
    pub const FUTURE_DIVISION: u32 = 0x2000;
    pub const FUTURE_ABSOLUTE_IMPORT: u32 = 0x4000;
    pub const FUTURE_WITH_STATEMENT: u32 = 0x8000;
    pub const FUTURE_PRINT_FUNCTION: u32 = 0x1_0000;
    pub const FUTURE_UNICODE_LITERALS: u32 = 0x2_0000;

    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }
}

/// Which `SyntaxError` subclass CPython raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxErrorKind {
    SyntaxError,
    IndentationError,
    TabError,
}

/// A compile-time error with the fields of CPython's `SyntaxError`:
/// `(msg, (filename, lineno, offset, text))`. `offset` and `text` are
/// absent where CPython leaves them `None`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message} ({filename}, line {lineno})", filename = String::from_utf8_lossy(filename))]
pub struct SyntaxError {
    pub kind: SyntaxErrorKind,
    pub message: String,
    pub filename: Vec<u8>,
    /// A C `int`: trees built through `_ast` may carry negative lines.
    pub lineno: i32,
    pub offset: Option<u32>,
    pub text: Option<Vec<u8>>,
}
