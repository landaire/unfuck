//! Constants while a code object is being compiled. `str` objects keep their
//! identity, because whether marshal writes a string as interned depends
//! on which object a constant tuple holds, not on its value.

use std::cell::Cell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::compiler::unit::CodeUnit;
use crate::interp::compiler::unit::Constant;
use crate::interp::complex::Complex;

/// A Python object that can appear in `co_consts`.
#[derive(Clone, Debug)]
pub enum Object {
    None,
    Ellipsis,
    /// An `int`, within the target's C `long`.
    Int(i64),
    Long(Rc<BigInt>),
    Float(f64),
    Complex(Complex),
    Str(Rc<StrObject>),
    /// A `unicode` of UTF-16 code units.
    Unicode(Rc<[u16]>),
    Tuple(Rc<[Object]>),
    Code(Rc<CodeUnit>),
}

/// A `str` object. Two constants share an `Rc` exactly when CPython would
/// hand out the same object.
#[derive(Debug)]
pub struct StrObject {
    pub value: Vec<u8>,
    /// Whether the string is interned.
    pub interned: Cell<bool>,
}

impl StrObject {
    pub fn new(value: Vec<u8>, interned: bool) -> Rc<Self> {
        Rc::new(Self { value, interned: Cell::new(interned) })
    }
}

impl Object {
    pub fn str(value: Vec<u8>, interned: bool) -> Self {
        Self::Str(StrObject::new(value, interned))
    }

    /// The constant as it ends up in the code object.
    pub fn into_constant(self) -> Constant {
        match self {
            Self::None => Constant::None,
            Self::Ellipsis => Constant::Ellipsis,
            Self::Int(value) => Constant::Int(value),
            Self::Long(value) => Constant::Long(Rc::unwrap_or_clone(value)),
            Self::Float(value) => Constant::Float(value),
            Self::Complex(value) => Constant::Complex { real: value.real, imag: value.imag },
            Self::Str(object) => Constant::Str { value: object.value.clone(), interned: object.interned.get() },
            Self::Unicode(units) => Constant::Unicode(units.to_vec()),
            Self::Tuple(items) => Constant::Tuple(items.iter().cloned().map(Self::into_constant).collect()),
            Self::Code(code) => Constant::Code(Box::new(Rc::unwrap_or_clone(code))),
        }
    }
}
