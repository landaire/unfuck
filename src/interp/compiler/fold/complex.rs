//! Folding of `complex` operations, with the arithmetic of
//! `crate::interp::complex`. A fold that would raise is not done.

use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::context::CompileWarning;
use crate::interp::compiler::context::WarningCategory;
use crate::interp::compiler::fold::BinaryFold;
use crate::interp::compiler::object::Object;
use crate::interp::complex::Complex;
use crate::interp::complex::Errno;

/// An operation where either operand is complex.
pub(super) fn binary(op: BinaryFold, left: Complex, right: Complex, context: &mut dyn CompileContext) -> Option<Object> {
    let value = match op {
        BinaryFold::Add => left.sum(right),
        BinaryFold::Subtract => left.diff(right),
        BinaryFold::Multiply => left.prod(right),
        BinaryFold::TrueDivide => {
            let quotient = left.quot(right);
            if quotient.errno == Errno::Domain {
                return None;
            }
            quotient.value
        }
        BinaryFold::FloorDivide => {
            // Floor division of complex numbers warns twice.
            warn_divmod(context)?;
            warn_divmod(context)?;
            left.divmod(right)?.0
        }
        BinaryFold::Modulo => {
            warn_divmod(context)?;
            left.divmod(right)?.1
        }
        BinaryFold::Power => {
            let power = left.power(right);
            if power.errno != Errno::Ok {
                return None;
            }
            power.value
        }
        BinaryFold::Subscript | BinaryFold::LShift | BinaryFold::RShift | BinaryFold::And | BinaryFold::Xor | BinaryFold::Or => return None,
    };

    Some(Object::Complex(value))
}

fn warn_divmod(context: &mut dyn CompileContext) -> Option<()> {
    let warning = CompileWarning { category: WarningCategory::DeprecationWarning, message: "complex divmod(), // and % are deprecated".to_owned(), location: None };

    context.warn(&warning).ok()
}
