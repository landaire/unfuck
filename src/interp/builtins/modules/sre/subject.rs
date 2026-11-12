//! The code units a pattern runs over, taken from a `unicode` object or
//! from any object with a single-segment read buffer.

use crate::interp::buffer::Segment;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The units of a subject.
pub enum Subject {
    /// One byte per character: a `str` or a byte buffer.
    Narrow(PyBytes),
    /// A `unicode` object.
    Text(PyText),
    /// A buffer whose size is twice its length, read as UTF-16 units.
    Wide(Box<[u16]>),
}

/// A borrowed view of a subject's units.
#[derive(Clone, Copy)]
pub enum Units<'a> {
    Narrow(&'a [u8]),
    Wide(&'a [u16]),
}

impl Subject {
    /// The units of `value`, or `None` when it is unknown.
    pub fn from_value(vm: &Vm, value: &Value) -> PyResult<Option<Self>> {
        if value.is_unknown() {
            return Ok(None);
        }
        if let Some(text) = vm.as_text(value) {
            return Ok(Some(Subject::Text(text)));
        }
        if let Some(bytes) = vm.as_str_bytes(value) {
            return Ok(Some(Subject::Narrow(bytes)));
        }

        let not_a_buffer = || vm.type_error("expected string or buffer");
        if !vm.has_segment(value, Segment::Read) {
            return Err(not_a_buffer());
        }
        let bytes = match vm.segment(value, Segment::Read) {
            Ok(Some(bytes)) => bytes,
            Ok(None) | Err(Signal::Raise(_)) => return Err(not_a_buffer()),
            Err(halt) => return Err(halt),
        };

        // The length decides whether the buffer holds bytes or UTF-16
        // units.
        let Some(length) = vm.len(value)? else {
            return Ok(None);
        };
        let size = bytes.as_bytes().len();
        if size == length {
            return Ok(Some(Subject::Narrow(bytes)));
        }
        if Some(size) == length.checked_mul(2) {
            let units = bytes.as_bytes().chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            return Ok(Some(Subject::Wide(units)));
        }

        Err(vm.type_error("buffer size mismatch"))
    }

    pub fn units(&self) -> Units<'_> {
        match self {
            Subject::Narrow(bytes) => Units::Narrow(bytes.as_bytes()),
            Subject::Text(text) => Units::Wide(text.units()),
            Subject::Wide(units) => Units::Wide(units),
        }
    }

    pub fn len(&self) -> usize {
        match self.units() {
            Units::Narrow(units) => units.len(),
            Units::Wide(units) => units.len(),
        }
    }
}

impl Units<'_> {
    /// Whether the units hold no backslash, so a replacement template
    /// needs no expansion.
    pub fn is_literal_template(self) -> bool {
        match self {
            Units::Narrow(units) => !units.contains(&b'\\'),
            Units::Wide(units) => !units.contains(&u16::from(b'\\')),
        }
    }
}
