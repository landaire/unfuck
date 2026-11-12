//! What the compiler needs from its host: the C `long` width, the warnings
//! machinery, and the default encoding.

use crate::interp::compiler::SyntaxError;
use crate::interp::hash::LongWidth;

/// The host interpreter state a compilation reads.
pub trait CompileContext {
    /// Width of C `long`, which bounds `int` objects.
    fn long_width(&self) -> LongWidth;

    /// Issues a warning at the given location, or attributed to the calling
    /// frame without one. `Err` means
    /// the warnings filter raised it; the context keeps the exception.
    fn warn(&mut self, warning: &CompileWarning) -> Result<(), WarningRaised>;

    /// Decodes a `str` with the default encoding, as implicit `str` to
    /// `unicode` coercion does. `None` when decoding fails.
    fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarningCategory {
    SyntaxWarning,
    DeprecationWarning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileWarning {
    pub category: WarningCategory,
    pub message: String,
    /// `(filename, lineno)` of the warning; absent when it is attributed
    /// to the calling frame.
    pub location: Option<WarningLocation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarningLocation {
    pub filename: Vec<u8>,
    pub lineno: i32,
}

/// The warnings filter turned a warning into an exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WarningRaised {
    /// The exception is an instance of `SyntaxWarning`, which the symbol table pass
    /// replaces with a `SyntaxError`.
    pub is_syntax_warning: bool,
}

/// Why `compile_ast` failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// A compiler error: `args` is `(msg, (filename, lineno, offset, text))`.
    #[error(transparent)]
    Syntax(SyntaxError),
    /// An error located after the fact: `args` is
    /// `(msg,)` and the location is only in the attributes.
    #[error(transparent)]
    SyntaxLocated(SyntaxError),
    /// A `SyntaxError` with no location: `args`
    /// is `(msg,)` and `filename`, `lineno`, `offset`, and `text` are None.
    #[error("SyntaxError: {message}")]
    SyntaxUnlocated { message: String },
    /// A `SystemError`, raised for malformed ASTs built from `_ast` objects.
    #[error("SystemError: {message}")]
    System { message: String },
    /// A warning hook raised; the context holds the exception.
    #[error("a compile-time warning was raised as an exception")]
    WarningRaised,
}

/// A context for unit tests: Linux x64 CPython with the default `ascii`
/// encoding, warnings recorded and never raised.
#[cfg(test)]
pub(crate) struct TestContext {
    pub long_width: LongWidth,
    pub warnings: Vec<CompileWarning>,
}

#[cfg(test)]
impl TestContext {
    pub fn new() -> Self {
        Self { long_width: LongWidth::Bits64, warnings: Vec::new() }
    }
}

#[cfg(test)]
impl CompileContext for TestContext {
    fn long_width(&self) -> LongWidth {
        self.long_width
    }

    fn warn(&mut self, warning: &CompileWarning) -> Result<(), WarningRaised> {
        self.warnings.push(warning.clone());

        Ok(())
    }

    fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>> {
        bytes.iter().map(|&byte| if byte < 0x80 { Some(u16::from(byte)) } else { None }).collect()
    }
}
