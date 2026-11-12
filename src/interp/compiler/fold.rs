//! Constant folding: arithmetic, indexing, `%` formatting, truth values,
//! lengths, and backquote `repr` of the object types that occur in
//! `co_consts`, with the results these operations give at run time.

mod complex;
mod number;
mod percent;
mod sequence;
mod text;

use num_bigint::BigInt;
use num_traits::Zero;

use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::object::Object;
use crate::interp::complex::Complex;

/// The optimizer discards folded `str`, `unicode`, and `tuple` results
/// longer than this.
pub(crate) const MAX_FOLDED_SIZE: usize = 20;

/// The binary operations the optimizer folds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryFold {
    Power,
    Multiply,
    TrueDivide,
    FloorDivide,
    Modulo,
    Add,
    Subtract,
    Subscript,
    LShift,
    RShift,
    And,
    Xor,
    Or,
}

/// The unary operations the optimizer folds. `Convert` is backquote
/// `repr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryFold {
    Negative,
    Convert,
    Invert,
}

/// A numeric operand. Mixed operands are converted to the wider kind, in
/// declaration order.
#[derive(Clone, Copy)]
enum Number<'a> {
    Int(i64),
    Long(&'a BigInt),
    Float(f64),
    Complex(Complex),
}

impl<'a> Number<'a> {
    fn from_object(object: &'a Object) -> Option<Self> {
        match object {
            Object::Int(value) => Some(Self::Int(*value)),
            Object::Long(value) => Some(Self::Long(value)),
            Object::Float(value) => Some(Self::Float(*value)),
            Object::Complex(value) => Some(Self::Complex(*value)),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Int(_) => 0,
            Self::Long(_) => 1,
            Self::Float(_) => 2,
            Self::Complex(_) => 3,
        }
    }

    fn to_long(self) -> Option<BigInt> {
        match self {
            Self::Int(value) => Some(BigInt::from(value)),
            Self::Long(value) => Some(value.clone()),
            Self::Float(_) | Self::Complex(_) => None,
        }
    }

    /// `None` when a `long` is too large for a float.
    fn to_double(self) -> Option<f64> {
        match self {
            Self::Int(value) => Some(value as f64),
            Self::Long(value) => number::long_to_float(value),
            Self::Float(value) => Some(value),
            Self::Complex(_) => None,
        }
    }

    fn to_complex(self) -> Option<Complex> {
        match self {
            Self::Complex(value) => Some(value),
            other => Some(Complex { real: other.to_double()?, imag: 0.0 }),
        }
    }
}

/// The result of the operation, or `None` where it raises.
///
/// Also `None` for `str`, `unicode`, and `tuple` results longer than
/// `MAX_FOLDED_SIZE`, which the optimizer would discard; they are never
/// built. `long` results above 2**24 bits are treated as the `MemoryError`
/// computing them would eventually cause. `unicode` subscripts are never
/// folded.
///
/// A `str` result has the identity it has at run time: an operand returned
/// unchanged is the same `Rc`, single characters from indexing are
/// interned, and new strings are not.
pub fn binary(op: BinaryFold, left: &Object, right: &Object, context: &mut dyn CompileContext) -> Option<Object> {
    if let (Some(left), Some(right)) = (Number::from_object(left), Number::from_object(right)) {
        return numeric(op, left, right, context);
    }

    match op {
        BinaryFold::Add => sequence::concat(left, right, &*context),
        BinaryFold::Multiply => {
            if is_sequence(left) {
                return sequence::repeat(left, right);
            }

            if is_sequence(right) {
                return sequence::repeat(right, left);
            }

            None
        }
        BinaryFold::Modulo => match left {
            Object::Str(format) => percent::format_str(format, right, context),
            Object::Unicode(format) => percent::format_unicode(format, right, context),
            _ => None,
        },
        BinaryFold::Subscript => sequence::subscript(left, right),
        BinaryFold::Power
        | BinaryFold::TrueDivide
        | BinaryFold::FloorDivide
        | BinaryFold::Subtract
        | BinaryFold::LShift
        | BinaryFold::RShift
        | BinaryFold::And
        | BinaryFold::Xor
        | BinaryFold::Or => None,
    }
}

/// The result of the operation, or `None` where it raises.
///
/// The optimizer only negates true operands, which keeps the sign of
/// `-0.0`. A `Convert` result is new and uninterned unless it is a single
/// character (the repr of a one-digit `int`), and `None` for code objects,
/// whose repr contains their address.
pub fn unary(op: UnaryFold, operand: &Object, context: &mut dyn CompileContext) -> Option<Object> {
    let width = context.long_width();

    match (op, operand) {
        (UnaryFold::Negative, Object::Int(value)) => Some(number::int_result(width, -i128::from(*value))),
        (UnaryFold::Negative, Object::Long(value)) => number::long_result(-&**value),
        (UnaryFold::Negative, Object::Float(value)) => Some(Object::Float(-value)),
        (UnaryFold::Negative, Object::Complex(value)) => Some(Object::Complex(-*value)),
        (UnaryFold::Invert, Object::Int(value)) => Some(Object::Int(!value)),
        (UnaryFold::Invert, Object::Long(value)) => number::long_result(-(&**value + 1u32)),
        (UnaryFold::Convert, operand) => {
            let text = text::repr(operand)?;
            let interned = text.len() == 1;
            Some(Object::str(text, interned))
        }
        (UnaryFold::Negative | UnaryFold::Invert, _) => None,
    }
}

/// The truth value of the object.
pub fn is_true(object: &Object) -> bool {
    match object {
        Object::None => false,
        Object::Ellipsis | Object::Code(_) => true,
        Object::Int(value) => *value != 0,
        Object::Long(value) => !value.is_zero(),
        Object::Float(value) => *value != 0.0,
        Object::Complex(value) => value.real != 0.0 || value.imag != 0.0,
        Object::Str(object) => !object.value.is_empty(),
        Object::Unicode(units) => !units.is_empty(),
        Object::Tuple(items) => !items.is_empty(),
    }
}

/// `len()` of a `str`, `unicode` (in UTF-16 code units), or `tuple`, and
/// `None` for objects without a length.
pub fn size(object: &Object) -> Option<usize> {
    match object {
        Object::Str(object) => Some(object.value.len()),
        Object::Unicode(units) => Some(units.len()),
        Object::Tuple(items) => Some(items.len()),
        Object::None | Object::Ellipsis | Object::Int(_) | Object::Long(_) | Object::Float(_) | Object::Complex(_) | Object::Code(_) => None,
    }
}

fn is_sequence(object: &Object) -> bool {
    matches!(object, Object::Str(_) | Object::Unicode(_) | Object::Tuple(_))
}

/// Arithmetic on two numbers, done in the wider of the two kinds.
fn numeric(op: BinaryFold, left: Number<'_>, right: Number<'_>, context: &mut dyn CompileContext) -> Option<Object> {
    let width = context.long_width();

    match left.rank().max(right.rank()) {
        0 => {
            let (Number::Int(left), Number::Int(right)) = (left, right) else {
                return None;
            };

            number::int_binary(op, left, right, width)
        }
        1 => number::long_binary(op, &left.to_long()?, &right.to_long()?),
        2 => number::float_binary(op, left.to_double()?, right.to_double()?),
        _ => complex::binary(op, left.to_complex()?, right.to_complex()?, context),
    }
}

#[cfg(test)]
mod tests;
