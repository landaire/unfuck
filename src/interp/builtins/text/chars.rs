//! Character classes, case mappings, and numeric values of `str` bytes (the
//! C locale) and `unicode` UTF-16 code units (the Unicode 5.2 database of
//! CPython 2.7).

use std::ops::Deref;

use crate::interp::builtins::text::unicode_db::LOWER_MAP;
use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::text::unicode_db::NUMERIC_VALUES;
use crate::interp::builtins::text::unicode_db::PROPERTY_RUNS;
use crate::interp::builtins::text::unicode_db::Properties;
use crate::interp::builtins::text::unicode_db::TITLE_MAP;
use crate::interp::builtins::text::unicode_db::UPPER_MAP;
use crate::interp::error::PyResult;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// One element of a `str` (a byte) or of a `unicode` (a UTF-16 code unit).
/// String algorithms are written once over this trait.
pub trait CodeUnit: Copy + Eq + Ord + Into<u32> + 'static {
    const UNICODE: bool;

    fn from_ascii(byte: u8) -> Self;

    /// Truncates a code point the way a C cast to the unit type does.
    fn truncate(code: u32) -> Self;

    /// The string a method copies its result into from the source bytes.
    fn new_value(units: Vec<Self>) -> Value;

    /// The string a method allocates at its final length before filling it in.
    fn new_unshared_value(units: Vec<Self>) -> Value;

    /// The string a method allocates directly or shrinks afterwards.
    fn allocated_value(units: Vec<Self>) -> Value;

    /// Units of a string argument, shared with its storage when no
    /// conversion is needed.
    type Shared: Deref<Target = [Self]>;

    /// Content of a string argument converted to this kind, or `None` when
    /// the value is not a string. A `str` converts to `unicode` with the
    /// default (ASCII) encoding.
    fn coerce(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>>;

    /// A string argument of the search and split methods, which `str` reads
    /// as a character buffer (accepting a `bytearray`) and `unicode` through
    /// unicode coercion (which refuses one).
    fn coerce_buffer(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>>;

    fn is_space(self) -> bool;
    fn is_linebreak(self) -> bool;
    fn is_alpha(self) -> bool;
    fn is_decimal(self) -> bool;
    fn is_digit(self) -> bool;
    fn is_numeric(self) -> bool;
    fn is_alnum(self) -> bool;
    fn is_lower(self) -> bool;
    fn is_upper(self) -> bool;
    fn is_title(self) -> bool;
    fn to_lower(self) -> Self;
    fn to_upper(self) -> Self;
    fn to_title(self) -> Self;
}

impl CodeUnit for u8 {
    const UNICODE: bool = false;

    fn from_ascii(byte: u8) -> Self {
        byte
    }

    fn truncate(code: u32) -> Self {
        code as u8
    }

    fn new_value(units: Vec<Self>) -> Value {
        Value::Str(PyBytes::new(units))
    }

    fn new_unshared_value(units: Vec<Self>) -> Value {
        Value::Str(PyBytes::new_unshared(units))
    }

    fn allocated_value(units: Vec<Self>) -> Value {
        Value::Str(PyBytes::allocate(units))
    }

    type Shared = SharedBytes;

    fn coerce(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>> {
        Ok(vm.as_str_bytes(value).map(SharedBytes))
    }

    fn coerce_buffer(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>> {
        Ok(vm.buffer(value, BufferInterface::Character)?.map(SharedBytes))
    }

    fn is_space(self) -> bool {
        matches!(self, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
    }

    fn is_linebreak(self) -> bool {
        matches!(self, b'\n' | b'\r')
    }

    fn is_alpha(self) -> bool {
        self.is_ascii_alphabetic()
    }

    fn is_decimal(self) -> bool {
        self.is_ascii_digit()
    }

    fn is_digit(self) -> bool {
        self.is_ascii_digit()
    }

    fn is_numeric(self) -> bool {
        self.is_ascii_digit()
    }

    fn is_alnum(self) -> bool {
        self.is_ascii_alphanumeric()
    }

    fn is_lower(self) -> bool {
        self.is_ascii_lowercase()
    }

    fn is_upper(self) -> bool {
        self.is_ascii_uppercase()
    }

    fn is_title(self) -> bool {
        false
    }

    fn to_lower(self) -> Self {
        self.to_ascii_lowercase()
    }

    fn to_upper(self) -> Self {
        self.to_ascii_uppercase()
    }

    fn to_title(self) -> Self {
        self.to_ascii_uppercase()
    }
}

impl CodeUnit for u16 {
    const UNICODE: bool = true;

    fn from_ascii(byte: u8) -> Self {
        u16::from(byte)
    }

    fn truncate(code: u32) -> Self {
        code as u16
    }

    fn new_value(units: Vec<Self>) -> Value {
        Value::Unicode(PyText::new(units))
    }

    fn new_unshared_value(units: Vec<Self>) -> Value {
        Value::Unicode(PyText::new_unshared(units))
    }

    fn allocated_value(units: Vec<Self>) -> Value {
        Value::Unicode(PyText::allocate(units))
    }

    type Shared = SharedText;

    fn coerce(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>> {
        Ok(vm.coerce_text(value)?.map(SharedText))
    }

    fn coerce_buffer(vm: &Vm, value: &Value) -> PyResult<Option<Self::Shared>> {
        if vm.as_bytearray(value).is_some() {
            return Err(vm.type_error("decoding bytearray is not supported"));
        }

        Ok(vm.unicode_from_object(value)?.map(SharedText))
    }

    fn is_space(self) -> bool {
        properties(self).contains(Properties::SPACE)
    }

    fn is_linebreak(self) -> bool {
        properties(self).contains(Properties::LINEBREAK)
    }

    fn is_alpha(self) -> bool {
        properties(self).contains(Properties::ALPHA)
    }

    fn is_decimal(self) -> bool {
        properties(self).contains(Properties::DECIMAL)
    }

    fn is_digit(self) -> bool {
        properties(self).contains(Properties::DIGIT)
    }

    fn is_numeric(self) -> bool {
        properties(self).contains(Properties::NUMERIC)
    }

    fn is_alnum(self) -> bool {
        properties(self).intersects(Properties::ALPHA | Properties::DECIMAL | Properties::DIGIT | Properties::NUMERIC)
    }

    fn is_lower(self) -> bool {
        properties(self).contains(Properties::LOWER)
    }

    fn is_upper(self) -> bool {
        properties(self).contains(Properties::UPPER)
    }

    fn is_title(self) -> bool {
        properties(self).contains(Properties::TITLE)
    }

    fn to_lower(self) -> Self {
        mapped(LOWER_MAP, self).unwrap_or(self)
    }

    fn to_upper(self) -> Self {
        mapped(UPPER_MAP, self).unwrap_or(self)
    }

    fn to_title(self) -> Self {
        mapped(TITLE_MAP, self).unwrap_or_else(|| self.to_upper())
    }
}

/// The bytes of a `str` argument.
pub struct SharedBytes(PyBytes);

impl Deref for SharedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The code units of a `unicode` argument.
pub struct SharedText(PyText);

impl Deref for SharedText {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        self.0.units()
    }
}

/// The decimal digit value of a unit, as `unicodedata.decimal` reports it.
pub fn decimal_value(unit: u16) -> Option<u8> {
    if !unit.is_decimal() {
        return None;
    }

    digit_of(unit)
}

/// The digit value of a unit, as `unicodedata.digit` reports it.
pub fn digit_value(unit: u16) -> Option<u8> {
    if !unit.is_digit() {
        return None;
    }

    digit_of(unit)
}

/// The numeric value of a unit, as `unicodedata.numeric` reports it.
pub fn numeric_value(unit: u16) -> Option<f64> {
    let index = NUMERIC_VALUES.binary_search_by_key(&unit, |(source, _)| *source).ok()?;

    NUMERIC_VALUES.get(index).map(|(_, value)| *value)
}

/// The value of a decimal or digit unit, whose numeric value is a digit.
fn digit_of(unit: u16) -> Option<u8> {
    numeric_value(unit).map(|value| value as u8)
}

fn properties(unit: u16) -> Properties {
    let run = PROPERTY_RUNS.partition_point(|(start, _)| *start <= unit);
    let bits = run.checked_sub(1).and_then(|index| PROPERTY_RUNS.get(index)).map_or(0, |(_, bits)| *bits);

    Properties::from_bits_truncate(bits)
}

fn mapped(table: &[(u16, u16)], unit: u16) -> Option<u16> {
    table.binary_search_by_key(&unit, |(source, _)| *source).ok().map(|index| table[index].1)
}
