//! `int`, `long`, `bool`, `float`, and `complex`. Constructors convert as
//! the reference interpreter does; the methods serve explicit calls such as
//! `int.__add__(a, b)` and delegate to the interpreter's numeric
//! operations on plain values, so a subclass that overrides an operator
//! and calls the base method does not recurse.

pub mod complex;
pub mod float;
mod integer;
pub(crate) mod parse;

use crate::interp::builtins::modules::codecs::errors::EncodeFault;
use crate::interp::builtins::modules::codecs::errors::encode_error;
use crate::interp::error::PyResult;
use crate::interp::value::PyText;
use crate::interp::vm::Vm;

pub fn install(vm: &Vm) -> PyResult<()> {
    integer::register(vm)?;
    float::register(vm)?;
    complex::register(vm)
}

/// The bytes numeric parsers see for a unicode argument. Whitespace
/// becomes a space and Latin-1 passes through; other code points need the
/// Unicode database, which is not emulated.
fn decimal_bytes(vm: &Vm, text: &PyText) -> PyResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.units().len());

    for (position, unit) in text.units().iter().enumerate() {
        let byte = match *unit {
            0 => {
                let fault = EncodeFault { encoding: "decimal", reason: "invalid decimal Unicode string", input: text.units(), start: position, end: position + 1 };
                return Err(encode_error(vm, &fault));
            }
            0x1c..=0x1f | 0x85 | 0xa0 => b' ',
            unit if unit < 0x100 => unit as u8,
            _ => return Err(vm.halt_unsupported("numeric conversion of non-Latin-1 unicode text")),
        };
        bytes.push(byte);
    }

    Ok(bytes)
}

/// `repr` of at most the first 200 bytes, as conversion errors quote it.
fn quoted(bytes: &[u8]) -> String {
    crate::interp::builtins::functions::repr_bytes(&bytes[..bytes.len().min(200)])
}

