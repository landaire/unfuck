//! The `marshal` object serialization of CPython 2.7: one writer
//! for interpreter values and compiler output, and one reader.

mod reader;
mod values;
pub mod writer;

pub use reader::load_code;
pub use reader::loads;
pub use values::DumpStop;
pub use values::dumps;

/// The nesting limit of a release build.
pub const MAX_DEPTH: usize = 2000;

/// The current marshal format version.
pub const VERSION: i64 = 2;

/// The type codes of the marshal format.
pub mod types {
    pub const NULL: u8 = b'0';
    pub const NONE: u8 = b'N';
    pub const FALSE: u8 = b'F';
    pub const TRUE: u8 = b'T';
    pub const STOPITER: u8 = b'S';
    pub const ELLIPSIS: u8 = b'.';
    pub const INT: u8 = b'i';
    pub const INT64: u8 = b'I';
    pub const FLOAT: u8 = b'f';
    pub const BINARY_FLOAT: u8 = b'g';
    pub const COMPLEX: u8 = b'x';
    pub const BINARY_COMPLEX: u8 = b'y';
    pub const LONG: u8 = b'l';
    pub const STRING: u8 = b's';
    pub const INTERNED: u8 = b't';
    pub const STRINGREF: u8 = b'R';
    pub const TUPLE: u8 = b'(';
    pub const LIST: u8 = b'[';
    pub const DICT: u8 = b'{';
    pub const CODE: u8 = b'c';
    pub const UNICODE: u8 = b'u';
    pub const UNKNOWN: u8 = b'?';
    pub const SET: u8 = b'<';
    pub const FROZENSET: u8 = b'>';
}

#[cfg(test)]
mod tests;
