//! Argument conversions that the codec, `cStringIO`, `strop`, and
//! `_locale` natives share.

use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::text::codecs;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The first unknown argument: a native whose result depends on it
/// returns it unchanged.
pub fn first_unknown(values: &[Value]) -> Option<Value> {
    values.iter().find(|value| value.is_unknown()).cloned()
}

/// Positional arguments of a varargs function, with the argument count
/// errors of format parsing.
pub fn varargs(vm: &Vm, args: CallArgs, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let given = args.positional.len();
    if given < minimum || given > maximum {
        let (bound, count) = if minimum == maximum {
            ("exactly", minimum)
        } else if given < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if count == 1 { "" } else { "s" };
        return Err(vm.type_error(&format!("{function}() takes {bound} {count} argument{plural} ({given} given)")));
    }

    Ok(args.positional)
}

/// Positional arguments for unpacking by count, whose errors name the
/// function without parentheses.
pub fn unpack(vm: &Vm, args: CallArgs, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let given = args.positional.len();
    if given < minimum || given > maximum {
        let (bound, count) = if minimum == maximum {
            ("", minimum)
        } else if given < minimum {
            ("at least ", minimum)
        } else {
            ("at most ", maximum)
        };
        return Err(vm.type_error(&format!("{function} expected {bound}{count} arguments, got {given}")));
    }

    Ok(args.positional)
}

/// The argument of a single-argument function.
pub fn single(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let given = args.positional.len();
    let mut positional = args.positional.into_iter();
    match (positional.next(), given) {
        (Some(value), 1) => Ok(value),
        _ => Err(vm.type_error(&format!("{function}() takes exactly one argument ({given} given)"))),
    }
}

/// Checks the call of a no-argument callable whose first `receivers`
/// positional arguments are its bound receiver.
pub fn no_arguments(vm: &Vm, args: &CallArgs, receivers: usize, function: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let given = args.positional.len().saturating_sub(receivers);
    if given != 0 {
        return Err(vm.type_error(&format!("{function}() takes no arguments ({given} given)")));
    }

    Ok(())
}

/// The type name of a value's type.
pub fn type_name(vm: &Vm, value: &Value) -> String {
    vm.type_name(value)
}

/// The argument conversion error, which names `None` rather than its type.
fn conversion_error(vm: &Vm, function: &str, position: usize, expected: &str, value: &Value) -> Signal {
    let shown = if value.is_none() { "None".to_owned() } else { type_name(vm, value) };

    vm.type_error(&format!("{function}() argument {position} must be {expected}, not {shown}"))
}

/// The bytes of a `str`, or of a `unicode` encoded with the default
/// encoding; other values fail naming `expected`.
fn string_bytes(vm: &Vm, function: &str, position: usize, value: &Value, expected: &str) -> PyResult<PyBytes> {
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(bytes);
    }
    if let Some(text) = vm.as_text(value) {
        return encode_default(vm, &text);
    }

    Err(conversion_error(vm, function, position, expected, value))
}

/// A buffer read through `interface`, or a `unicode` encoded with the
/// default encoding; other values fail naming `expected`.
fn buffer_bytes(vm: &Vm, function: &str, position: usize, value: &Value, interface: BufferInterface, expected: &str) -> PyResult<PyBytes> {
    if let Some(text) = vm.as_text(value) {
        return encode_default(vm, &text);
    }

    vm.buffer(value, interface)?.ok_or_else(|| conversion_error(vm, function, position, expected, value))
}

/// `s*`.
pub fn string_or_buffer(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyBytes> {
    buffer_bytes(vm, function, position, value, BufferInterface::Any, "string or buffer")
}

/// `s#`.
pub fn read_buffer(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyBytes> {
    buffer_bytes(vm, function, position, value, BufferInterface::Pinned, "string or read-only buffer")
}

/// `t#`, which names a character buffer that needs releasing a pinned
/// buffer.
pub fn character_buffer(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyBytes> {
    let releasing = vm.buffer_slots(value).is_some_and(|slots| slots.character && slots.release);
    let expected = if releasing { "string or pinned buffer" } else { "string or read-only character buffer" };

    buffer_bytes(vm, function, position, value, BufferInterface::PinnedCharacter, expected)
}

/// `s`: a string usable as a C string.
pub fn c_string(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyBytes> {
    let bytes = string_bytes(vm, function, position, value, "string")?;
    if bytes.as_bytes().contains(&0) {
        return Err(conversion_error(vm, function, position, "string without null bytes", value));
    }

    Ok(bytes)
}

/// `S`: a `str` object.
pub fn exact_string(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyBytes> {
    vm.as_str_bytes(value).ok_or_else(|| conversion_error(vm, function, position, "string", value))
}

/// `z`: `None` or a string usable as a C string.
pub fn optional_string(vm: &Vm, function: &str, position: usize, value: Option<&Value>) -> PyResult<Option<PyBytes>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };

    let bytes = string_bytes(vm, function, position, value, "string or None")?;
    if bytes.as_bytes().contains(&0) {
        return Err(conversion_error(vm, function, position, "string without null bytes or None", value));
    }

    Ok(Some(bytes))
}

/// `z#`: `None` or a buffer.
pub fn optional_read_buffer(vm: &Vm, function: &str, position: usize, value: Option<&Value>) -> PyResult<Option<PyBytes>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };

    read_buffer(vm, function, position, value).map(Some)
}

/// `i`: a C `int`, read through the C `long` conversion.
pub fn c_int(vm: &Vm, value: &Value) -> PyResult<i32> {
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }
    let Some(integral) = vm.as_integral(value) else {
        return Err(vm.type_error("an integer is required"));
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    let Some(number) = number.filter(|number| numbers::fits_int(vm.config.long_width, *number)) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
    };

    i32::try_from(number).map_err(|_| {
        let message = if number > 0 { "signed integer is greater than maximum" } else { "signed integer is less than minimum" };
        vm.raise(ExceptionKind::OverflowError, message)
    })
}

/// `n`: a `ssize_t`.
pub fn ssize(vm: &Vm, value: &Value) -> PyResult<i64> {
    arguments::ssize_argument(vm, value)
}

/// Unicode coercion: `unicode` as is, `str` decoded with the default
/// encoding.
pub fn to_unicode(vm: &Vm, value: &Value) -> PyResult<PyText> {
    if let Some(text) = vm.as_text(value) {
        return Ok(text);
    }
    if let Some(bytes) = vm.as_str_bytes(value) {
        return decode_default(vm, &bytes);
    }

    Err(vm.type_error(&format!("coercing to Unicode: need string or buffer, {} found", type_name(vm, value))))
}

/// String data: a `str`, or a `unicode` encoded with the default encoding.
pub fn string_or_unicode(vm: &Vm, value: &Value) -> PyResult<PyBytes> {
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(bytes);
    }
    if let Some(text) = vm.as_text(value) {
        return encode_default(vm, &text);
    }

    Err(vm.type_error(&format!("expected string or Unicode object, {} found", type_name(vm, value))))
}

/// Encoding with the default encoding, with `UnicodeEncodeError` carrying
/// the encoding, object, and positions.
pub fn encode_default(vm: &Vm, text: &PyText) -> PyResult<PyBytes> {
    let mut errors = Errors::new(vm, None);
    let codec = vm.default_codec();
    let bytes = codecs::encode_units(vm, codec, text.units(), &mut errors)?;

    Ok(codecs::encoded_string(codec, text.units().len(), bytes))
}

/// Decoding with the default encoding and `errors` 'strict'.
pub fn decode_default(vm: &Vm, bytes: &PyBytes) -> PyResult<PyText> {
    let mut errors = Errors::new(vm, Some(PyBytes::from("strict")));
    let codec = vm.default_codec();
    let units = codecs::decode_units(vm, codec, bytes.as_bytes(), &mut errors)?;

    Ok(codecs::decoded_text(codec, bytes.as_bytes(), units))
}

/// An `int` value or a subclass such as `bool`, not `long`.
pub fn plain_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Int(number) => Some(*number),
        Value::Object(object) => match &object.payload {
            Payload::Int(number) => Some(*number),
            _ => None,
        },
        _ => None,
    }
}

/// A length or position as a Python `int`. Buffer lengths and positions
/// stay below `i64::MAX`, so the conversion never saturates.
pub fn index_value(value: usize) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(i64::MAX))
}
