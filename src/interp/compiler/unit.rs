//! The code objects the compiler produces, as plain data. `marshal::dump`
//! writes them in the format of `marshal.dumps`.

use num_bigint::BigInt;

/// A CPython 2.7 code object.
#[derive(Clone, Debug, PartialEq)]
pub struct CodeUnit {
    pub argcount: u32,
    pub nlocals: u32,
    pub stacksize: u32,
    pub flags: u32,
    pub code: Vec<u8>,
    pub consts: Vec<Constant>,

    /// `co_names`, `co_varnames`, `co_freevars`, and `co_cellvars`, which
    /// code object creation interns.
    pub names: Vec<Vec<u8>>,
    pub varnames: Vec<Vec<u8>>,
    pub freevars: Vec<Vec<u8>>,
    pub cellvars: Vec<Vec<u8>>,

    /// `co_filename`, a fresh string per code object: interned only when it
    /// is at most one byte long.
    pub filename: Vec<u8>,
    pub name: Vec<u8>,
    /// Whether the `co_name` object is interned. Identifiers and the names
    /// the compiler interns are; `<genexpr>`, `<setcomp>`, and `<dictcomp>`
    /// are not.
    pub name_interned: bool,
    pub firstlineno: i32,
    pub lnotab: Vec<u8>,
}

/// An element of `co_consts`, or of a constant tuple.
#[derive(Clone, Debug, PartialEq)]
pub enum Constant {
    None,
    Ellipsis,
    /// An `int`, within the target's C `long`.
    Int(i64),
    Long(BigInt),
    Float(f64),
    Complex { real: f64, imag: f64 },
    /// A `str`. Marshal writes interned strings as `t`/`R` and others as
    /// `s`.
    Str { value: Vec<u8>, interned: bool },
    /// A `unicode` of UTF-16 code units.
    Unicode(Vec<u16>),
    Tuple(Vec<Constant>),
    Code(Box<CodeUnit>),
}
