//! The charmap codec: bytes decode through a 256-character table or any
//! mapping, and text encodes through a mapping or the `EncodingMap` that
//! `charmap_build` makes from a decoding table.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args::index_value;
use crate::interp::builtins::modules::codecs::args::plain_int;
use crate::interp::builtins::modules::codecs::errors::Builtin;
use crate::interp::builtins::modules::codecs::errors::DecodeFault;
use crate::interp::builtins::modules::codecs::errors::EncodeFault;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::errors::encode_error;
use crate::interp::builtins::modules::codecs::errors::new_encode_exception;
use crate::interp::builtins::modules::codecs::errors::xml_character_references;
use crate::interp::builtins::modules::codecs::unicode::push_code_point;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const ENCODING: &str = "charmap";
const UNDEFINED: &str = "character maps to <undefined>";
const TYPE_NAME: &str = "EncodingMap";

/// The table entry that marks a byte as undefined.
const UNDEFINED_UNIT: u16 = 0xfffe;

/// An encoding table built from a decoding table: the byte of each
/// mapped BMP code unit.
pub struct EncodingMap {
    /// Mapped units in ascending order.
    units: Box<[u16]>,
    /// The byte of each unit in `units`.
    bytes: Box<[u8]>,
    /// The size `size()` reports.
    reported_size: usize,
}

impl_native_data!(EncodingMap, "EncodingMap");

impl EncodingMap {
    fn byte(&self, unit: u16) -> Option<u8> {
        let index = self.units.binary_search(&unit).ok()?;

        self.bytes.get(index).copied()
    }
}

fn create_encoding_map_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[method("size", encoding_map_size)];

    new_final_type(vm, TypeSpec { name: TYPE_NAME, module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })
}

fn encoding_map_size(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let map = this::<EncodingMap>(vm, &args, TYPE_NAME, "size")?;
    method_no_arguments(vm, &args, "size")?;

    Ok(Value::Int(i64::try_from(map.reported_size).unwrap_or(i64::MAX)))
}

/// The encoding map of a 256-unit decoding table: an `EncodingMap` when
/// the table starts with NUL, holds no other NUL, and its units fall in
/// fewer than 255 blocks of 128; otherwise a dict from unit to byte.
pub fn build(vm: &Vm, table: &[u16]) -> PyResult<Value> {
    // `size()` reports 63, plus 16 per distinct 2048-unit block and 128 per
    // distinct 128-unit block among the defined units after the first.
    const BASE_SIZE: usize = 63;
    const WIDE_BLOCK_SIZE: usize = 16;
    const NARROW_BLOCK_SIZE: usize = 128;
    const NARROW_BLOCK_LIMIT: usize = 255;

    if table.len() != 256 {
        return Err(vm.type_error("bad argument type for built-in operation"));
    }

    let defined = || table.iter().skip(1).filter(|unit| **unit != UNDEFINED_UNIT);
    let wide_blocks: BTreeSet<u16> = defined().map(|unit| unit >> 11).collect();
    let narrow_blocks: BTreeSet<u16> = defined().map(|unit| unit >> 7).collect();
    let fits = table[0] == 0 && !table[1..].contains(&0) && narrow_blocks.len() < NARROW_BLOCK_LIMIT;

    if !fits {
        let dict = vm.new_dict();
        for (byte, unit) in table.iter().enumerate() {
            vm.dict_set(&dict, Value::Int(i64::from(*unit)), Value::Int(byte as i64))?;
        }
        return Ok(Value::Object(dict));
    }

    // A unit listed twice encodes to its last byte.
    let entries: BTreeMap<u16, u8> = table.iter().enumerate().filter(|(_, unit)| **unit != UNDEFINED_UNIT).map(|(byte, unit)| (*unit, byte as u8)).collect();
    let units = entries.keys().copied().collect();
    let bytes = entries.values().copied().collect();
    let reported_size = BASE_SIZE + WIDE_BLOCK_SIZE * wide_blocks.len() + NARROW_BLOCK_SIZE * narrow_blocks.len();
    let class = native_type(vm, TYPE_NAME, create_encoding_map_type)?;

    Ok(new_native_object(vm, &class, EncodingMap { units, bytes, reported_size }))
}

/// `mapping[key]`, with a `LookupError` reading as no entry.
fn lookup(vm: &Vm, mapping: &Value, key: u32) -> PyResult<Option<Value>> {
    match vm.getitem(mapping, &Value::Int(i64::from(key))) {
        Ok(value) => {
            halt_on_unknown(&value, "charmap mapping result")?;
            Ok(Some(value))
        }
        Err(Signal::Raise(exception)) if vm.is_exception(&exception, ExceptionKind::LookupError) => Ok(None),
        Err(signal) => Err(signal),
    }
}

/// Decodes `input` through `mapping`. An exact `unicode` is a table indexed
/// by byte; other mappings are indexed through `__getitem__`. A missing
/// entry, `None`, and U+FFFE are undefined.
pub fn decode(vm: &Vm, input: &[u8], mapping: &Value, errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    let table = match mapping {
        Value::Unicode(text) => Some(text.units()),
        _ => None,
    };

    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while let Some(&byte) = input.get(position) {
        let defined = match table {
            Some(units) => match units.get(usize::from(byte)) {
                Some(&unit) if unit != UNDEFINED_UNIT => {
                    output.push(unit);
                    true
                }
                _ => false,
            },
            None => decode_through_mapping(vm, mapping, byte, &mut output)?,
        };
        if defined {
            position += 1;
            continue;
        }

        let fault = DecodeFault { encoding: ENCODING, reason: UNDEFINED, input, start: position, end: position + 1 };
        let replacement = errors.decode(&fault)?;
        output.extend_from_slice(&replacement.units);
        position = replacement.resume;
    }

    Ok(output)
}

/// Appends what `mapping[byte]` decodes to; false when it is undefined.
fn decode_through_mapping(vm: &Vm, mapping: &Value, byte: u8, output: &mut Vec<u16>) -> PyResult<bool> {
    const CODE_POINT_LIMIT: i64 = 0x11_0000;

    let Some(value) = lookup(vm, mapping, u32::from(byte))? else {
        return Ok(false);
    };
    if value.is_none() {
        return Ok(false);
    }

    if let Some(code) = plain_int(&value) {
        if !(0..CODE_POINT_LIMIT).contains(&code) {
            return Err(vm.type_error("character mapping must be in range(0x110000)"));
        }
        if code == i64::from(UNDEFINED_UNIT) {
            return Ok(false);
        }
        push_code_point(output, code as u32);
        return Ok(true);
    }

    let Some(text) = vm.as_text(&value) else {
        return Err(vm.type_error("character mapping must return integer, None or unicode"));
    };
    if text.units() == [UNDEFINED_UNIT] {
        return Ok(false);
    }
    output.extend_from_slice(text.units());

    Ok(true)
}

/// Appends the encoding of `unit` through `mapping`; false when the
/// mapping leaves it undefined.
fn encode_unit(vm: &Vm, mapping: &Value, unit: u16, output: &mut Vec<u8>) -> PyResult<bool> {
    if let Some(map) = native_data::<EncodingMap>(mapping) {
        let Some(byte) = map.byte(unit) else {
            return Ok(false);
        };
        output.push(byte);
        return Ok(true);
    }

    let Some(value) = lookup(vm, mapping, u32::from(unit))? else {
        return Ok(false);
    };
    if value.is_none() {
        return Ok(false);
    }

    if let Some(code) = plain_int(&value) {
        let Ok(byte) = u8::try_from(code) else {
            return Err(vm.type_error("character mapping must be in range(256)"));
        };
        output.push(byte);
        return Ok(true);
    }
    let Some(bytes) = vm.as_str_bytes(&value) else {
        return Err(vm.type_error("character mapping must return integer, None or str"));
    };
    output.extend_from_slice(bytes.as_bytes());

    Ok(true)
}

/// Encodes the units an error handler substituted; false when the mapping
/// leaves one undefined.
fn encode_substitute(vm: &Vm, mapping: &Value, units: &[u16], output: &mut Vec<u8>) -> PyResult<bool> {
    for &unit in units {
        if !encode_unit(vm, mapping, unit, output)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// The error a substitution that cannot be encoded raises. Handlers from
/// the registry share one exception per call: its arguments describe the
/// first range they were given, its `start` and `end` the current one.
fn substitution_error(vm: &Vm, fault: &EncodeFault<'_>, first_handled: Range<usize>) -> Signal {
    let first = EncodeFault { start: first_handled.start, end: first_handled.end, ..*fault };
    let exception = match new_encode_exception(vm, &first) {
        Ok(exception) => exception,
        Err(signal) => return signal,
    };
    for (name, value) in [("start", fault.start), ("end", fault.end)] {
        if let Err(signal) = vm.setattr_str(&exception, name, index_value(value)) {
            return signal;
        }
    }

    Signal::Raise(exception)
}

/// Encodes `input` through `mapping`. Each run of undefined units goes to
/// the error handler as one range; the strict, ignore, replace, and
/// xmlcharrefreplace handlers are chosen by name.
pub fn encode(vm: &Vm, input: &[u16], mapping: &Value, errors: &mut Errors<'_>) -> PyResult<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut probe = Vec::new();
    let mut first_handled = None;
    let mut position = 0;
    while let Some(&unit) = input.get(position) {
        if encode_unit(vm, mapping, unit, &mut output)? {
            position += 1;
            continue;
        }

        let mut end = position + 1;
        while let Some(&next) = input.get(end) {
            probe.clear();
            if encode_unit(vm, mapping, next, &mut probe)? {
                break;
            }
            end += 1;
        }
        let fault = EncodeFault { encoding: ENCODING, reason: UNDEFINED, input, start: position, end };

        match errors.named() {
            Some(Builtin::Strict) => return Err(encode_error(vm, &fault)),
            Some(Builtin::Ignore) => {}
            Some(Builtin::Replace) => {
                let marks = vec![u16::from(b'?'); end - position];
                if !encode_substitute(vm, mapping, &marks, &mut output)? {
                    return Err(encode_error(vm, &fault));
                }
            }
            Some(Builtin::XmlCharRefReplace) => {
                let references: Vec<u16> = xml_character_references(&input[position..end]).bytes().map(u16::from).collect();
                if !encode_substitute(vm, mapping, &references, &mut output)? {
                    return Err(encode_error(vm, &fault));
                }
            }
            Some(Builtin::BackslashReplace) | None => {
                let first = first_handled.get_or_insert(position..end).clone();
                let replacement = errors.encode(&fault)?;
                if !encode_substitute(vm, mapping, &replacement.units, &mut output)? {
                    return Err(substitution_error(vm, &fault, first));
                }
                position = replacement.resume;
                continue;
            }
        }
        position = end;
    }

    Ok(output)
}
