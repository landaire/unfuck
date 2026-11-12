//! Codec error handling: the builtin handlers, the calls of registered
//! handlers during decoding and encoding, and the exceptions codecs raise.

use std::rc::Rc;

use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::codecs::registry;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeFn;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The error handlers the codec registry starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    Strict,
    Ignore,
    Replace,
    XmlCharRefReplace,
    BackslashReplace,
}

impl Builtin {
    pub const ALL: [Self; 5] = [Self::Strict, Self::Ignore, Self::Replace, Self::XmlCharRefReplace, Self::BackslashReplace];

    /// The name the handler is registered under.
    pub fn name(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Ignore => "ignore",
            Self::Replace => "replace",
            Self::XmlCharRefReplace => "xmlcharrefreplace",
            Self::BackslashReplace => "backslashreplace",
        }
    }

    /// The `__name__` of the handler function.
    pub fn function_name(self) -> &'static str {
        match self {
            Self::Strict => "strict_errors",
            Self::Ignore => "ignore_errors",
            Self::Replace => "replace_errors",
            Self::XmlCharRefReplace => "xmlcharrefreplace_errors",
            Self::BackslashReplace => "backslashreplace_errors",
        }
    }

    pub fn function(self) -> NativeFn {
        match self {
            Self::Strict => strict_errors,
            Self::Ignore => ignore_errors,
            Self::Replace => replace_errors,
            Self::XmlCharRefReplace => xmlcharrefreplace_errors,
            Self::BackslashReplace => backslashreplace_errors,
        }
    }
}

#[derive(Clone)]
enum Handler {
    Builtin(Builtin),
    Python(Value),
}

/// An undecodable range of the input.
pub struct DecodeFault<'a> {
    pub encoding: &'static str,
    pub reason: &'static str,
    pub input: &'a [u8],
    pub start: usize,
    pub end: usize,
}

/// An unencodable range of the input.
pub struct EncodeFault<'a> {
    pub encoding: &'static str,
    pub reason: &'static str,
    pub input: &'a [u16],
    pub start: usize,
    pub end: usize,
}

/// What an error handler substitutes, and where coding resumes.
pub struct Replacement {
    pub units: Vec<u16>,
    pub resume: usize,
}

/// The `errors` argument of a codec, resolving its handler through the
/// registry on the first error.
pub struct Errors<'a> {
    vm: &'a Vm,
    /// `None` is a NULL `errors`, which means 'strict'.
    name: Option<PyBytes>,
    handler: Option<Handler>,
}

impl<'a> Errors<'a> {
    pub fn new(vm: &'a Vm, name: Option<PyBytes>) -> Self {
        Self { vm, name, handler: None }
    }

    pub fn vm(&self) -> &'a Vm {
        self.vm
    }

    /// The raw `errors` string; `None` when NULL.
    pub fn name(&self) -> Option<&[u8]> {
        self.name.as_ref().map(PyBytes::as_bytes)
    }

    /// The handler the ASCII, Latin-1, and charmap encoders select by
    /// name alone, without consulting the registry.
    pub fn named(&self) -> Option<Builtin> {
        match self.name() {
            None | Some(b"strict") => Some(Builtin::Strict),
            Some(b"replace") => Some(Builtin::Replace),
            Some(b"ignore") => Some(Builtin::Ignore),
            Some(b"xmlcharrefreplace") => Some(Builtin::XmlCharRefReplace),
            Some(_) => None,
        }
    }

    fn handler(&mut self) -> PyResult<Handler> {
        if let Some(handler) = &self.handler {
            return Ok(handler.clone());
        }

        let name = self.name().unwrap_or(b"strict").to_vec();
        let function = registry::lookup_error(self.vm, &name)?;
        let handler = match registry::builtin_handler(self.vm, &function) {
            Some(builtin) => Handler::Builtin(builtin),
            None => Handler::Python(function),
        };
        self.handler = Some(handler.clone());

        Ok(handler)
    }

    /// Calls the error handler for a decode fault.
    pub fn decode(&mut self, fault: &DecodeFault<'_>) -> PyResult<Replacement> {
        match self.handler()? {
            Handler::Builtin(Builtin::Strict) => Err(decode_error(self.vm, fault)),
            Handler::Builtin(Builtin::Ignore) => Ok(Replacement { units: Vec::new(), resume: fault.end }),
            Handler::Builtin(Builtin::Replace) => Ok(Replacement { units: vec![0xfffd], resume: fault.end }),
            Handler::Builtin(Builtin::XmlCharRefReplace | Builtin::BackslashReplace) => Err(self.vm.type_error("don't know how to handle UnicodeDecodeError in error callback")),
            Handler::Python(function) => {
                let exception = new_decode_exception(self.vm, fault)?;
                let result = self.vm.call(&function, CallArgs::new(vec![exception]))?;
                handler_result(self.vm, &result, fault.input.len(), "decoding error handler must return (unicode, int) tuple")
            }
        }
    }

    /// Calls the error handler for an encode fault.
    pub fn encode(&mut self, fault: &EncodeFault<'_>) -> PyResult<Replacement> {
        match self.handler()? {
            Handler::Builtin(Builtin::Strict) => Err(encode_error(self.vm, fault)),
            Handler::Builtin(builtin) => Ok(Replacement { units: encode_replacement(builtin, fault.input, fault.start, fault.end), resume: fault.end }),
            Handler::Python(function) => {
                let exception = new_encode_exception(self.vm, fault)?;
                let result = self.vm.call(&function, CallArgs::new(vec![exception]))?;
                handler_result(self.vm, &result, fault.input.len(), "encoding error handler must return (unicode, int) tuple")
            }
        }
    }
}

/// Checks the `(replacement, position)` a Python error handler returned.
fn handler_result(vm: &Vm, result: &Value, length: usize, message: &str) -> PyResult<Replacement> {
    if result.is_unknown() {
        return Err(Signal::Halt(Halt::UnknownCondition { context: "codec error handler result".to_owned(), origin: format!("{result:?}") }));
    }
    let Some(items) = vm.as_tuple(result) else {
        return Err(vm.type_error(message));
    };
    let [replacement, position] = &items[..] else {
        return Err(vm.type_error(message));
    };
    let (Some(replacement), Some(position), None) = (vm.as_text(replacement), vm.as_index(position), vm.as_float(position)) else {
        return Err(vm.type_error(message));
    };

    let length = i64::try_from(length).unwrap_or(i64::MAX);
    let resume = if position < 0 { position + length } else { position };
    let Some(resume) = usize::try_from(resume).ok().filter(|resume| i64::try_from(*resume).is_ok_and(|resume| resume <= length)) else {
        return Err(vm.raise(ExceptionKind::IndexError, &format!("position {resume} from error handler out of bounds")));
    };

    Ok(Replacement { units: replacement.units().to_vec(), resume })
}

/// The replacement of a builtin non-strict handler for an encoding error.
fn encode_replacement(builtin: Builtin, input: &[u16], start: usize, end: usize) -> Vec<u16> {
    let range = input.get(start..end).unwrap_or_default();

    match builtin {
        Builtin::Strict | Builtin::Ignore => Vec::new(),
        Builtin::Replace => vec![u16::from(b'?'); range.len()],
        Builtin::XmlCharRefReplace => xml_character_references(range).encode_utf16().collect(),
        Builtin::BackslashReplace => backslash_escapes(range).encode_utf16().collect(),
    }
}

/// `&#N;` for each character; surrogate pairs combine, as in the narrow
/// build.
pub fn xml_character_references(units: &[u16]) -> String {
    let mut output = String::new();

    for code in code_points(units) {
        output.push_str(&format!("&#{code};"));
    }

    output
}

/// `\xNN` or `\uNNNN` for each code unit.
fn backslash_escapes(units: &[u16]) -> String {
    let mut output = String::new();

    for &unit in units {
        if unit >= 0x100 {
            output.push_str(&format!("\\u{unit:04x}"));
        } else {
            output.push_str(&format!("\\x{unit:02x}"));
        }
    }

    output
}

/// Code points of UTF-16 units, combining surrogate pairs.
pub fn code_points(units: &[u16]) -> Vec<u32> {
    let mut points = Vec::with_capacity(units.len());
    let mut index = 0;

    while let Some(&unit) = units.get(index) {
        index += 1;
        let low = units.get(index).copied().filter(|low| (0xd800..=0xdbff).contains(&unit) && (0xdc00..=0xdfff).contains(low));
        let code = match low {
            Some(low) => {
                index += 1;
                (((u32::from(unit) & 0x3ff) << 10) | (u32::from(low) & 0x3ff)) + 0x10000
            }
            None => u32::from(unit),
        };
        points.push(code);
    }

    points
}

/// Builds a `UnicodeDecodeError`.
pub fn new_decode_exception(vm: &Vm, fault: &DecodeFault<'_>) -> PyResult<Value> {
    let class = Rc::clone(vm.types().exception(ExceptionKind::UnicodeDecodeError));
    let arguments = vec![Value::str(fault.encoding), Value::Str(PyBytes::new(fault.input)), args::index_value(fault.start), args::index_value(fault.end), Value::str(fault.reason)];

    vm.instantiate_exception(&class, arguments)
}

/// Builds a `UnicodeEncodeError`.
pub fn new_encode_exception(vm: &Vm, fault: &EncodeFault<'_>) -> PyResult<Value> {
    let class = Rc::clone(vm.types().exception(ExceptionKind::UnicodeEncodeError));
    let arguments = vec![Value::str(fault.encoding), Value::Unicode(PyText::new(fault.input)), args::index_value(fault.start), args::index_value(fault.end), Value::str(fault.reason)];

    vm.instantiate_exception(&class, arguments)
}

/// A `UnicodeDecodeError` ready to propagate.
pub fn decode_error(vm: &Vm, fault: &DecodeFault<'_>) -> Signal {
    match new_decode_exception(vm, fault) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// A `UnicodeEncodeError` ready to propagate.
pub fn encode_error(vm: &Vm, fault: &EncodeFault<'_>) -> Signal {
    match new_encode_exception(vm, fault) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// Which `UnicodeError` a handler received.
enum ErrorKind {
    Encode,
    Decode,
    Translate,
}

/// Classifies the exception a builtin handler received, raising
/// a `TypeError` for anything else.
fn error_kind(vm: &Vm, exception: &Value) -> PyResult<ErrorKind> {
    if vm.is_exception(exception, ExceptionKind::UnicodeEncodeError) {
        return Ok(ErrorKind::Encode);
    }
    if vm.is_exception(exception, ExceptionKind::UnicodeDecodeError) {
        return Ok(ErrorKind::Decode);
    }
    if vm.is_exception(exception, ExceptionKind::UnicodeTranslateError) {
        return Ok(ErrorKind::Translate);
    }

    Err(wrong_exception_type(vm, exception))
}

/// The `TypeError` for an unsupported exception, which names the class by its `__name__`.
fn wrong_exception_type(vm: &Vm, exception: &Value) -> Signal {
    let class = vm.class_of(exception);
    let name = class.as_class().map_or_else(|| "?".to_owned(), |data| data.name().to_string_lossy());

    vm.type_error(&format!("don't know how to handle {name} in error callback"))
}

/// The `object` of a `UnicodeError` with `start` and `end` clamped into it.
struct ErrorFields {
    /// The units of a unicode `object`; empty for a decoding error.
    units: Vec<u16>,
    start: usize,
    end: usize,
}

fn error_fields(vm: &Vm, exception: &Value, kind: &ErrorKind) -> PyResult<ErrorFields> {
    let object = vm.getattr_str(exception, "object")?;
    let (units, length) = match kind {
        ErrorKind::Decode => match vm.as_str_bytes(&object) {
            Some(bytes) => (Vec::new(), bytes.as_bytes().len()),
            None => return Err(vm.type_error("object attribute must be str")),
        },
        ErrorKind::Encode | ErrorKind::Translate => match vm.as_text(&object) {
            Some(text) => (text.units().to_vec(), text.units().len()),
            None => return Err(vm.type_error("object attribute must be unicode")),
        },
    };

    let start = args::ssize(vm, &vm.getattr_str(exception, "start")?)?;
    let end = args::ssize(vm, &vm.getattr_str(exception, "end")?)?;

    // Lengths never exceed `i64::MAX`, so the clamped values convert.
    let length = i64::try_from(length).unwrap_or(i64::MAX);
    let start = start.max(0).min(length - 1).max(0);
    let end = end.max(1).min(length).max(0);

    Ok(ErrorFields { units, start: usize::try_from(start).unwrap_or(0), end: usize::try_from(end).unwrap_or(0) })
}

fn handler_tuple(units: Vec<u16>, end: usize) -> Value {
    Value::tuple(vec![Value::Unicode(PyText::new_unshared(units)), args::index_value(end)])
}

/// The 'strict' error handler.
fn strict_errors(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let exception = args::single(vm, args, "strict_errors")?;
    if exception.is_unknown() {
        return Ok(exception);
    }

    if vm.is_exception_class(&Value::Object(vm.class_of(&exception))) {
        return Err(Signal::Raise(exception));
    }

    Err(vm.type_error("codec must pass exception instance"))
}

/// The 'ignore' error handler.
fn ignore_errors(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let exception = args::single(vm, args, "ignore_errors")?;
    if exception.is_unknown() {
        return Ok(exception);
    }

    let kind = error_kind(vm, &exception)?;
    let fields = error_fields(vm, &exception, &kind)?;

    Ok(handler_tuple(Vec::new(), fields.end))
}

/// The 'replace' error handler.
fn replace_errors(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let exception = args::single(vm, args, "replace_errors")?;
    if exception.is_unknown() {
        return Ok(exception);
    }

    let kind = error_kind(vm, &exception)?;
    let fields = error_fields(vm, &exception, &kind)?;
    let count = fields.end.saturating_sub(fields.start);
    let units = match kind {
        ErrorKind::Decode => vec![0xfffd],
        ErrorKind::Encode => vec![u16::from(b'?'); count],
        ErrorKind::Translate => vec![0xfffd; count],
    };

    Ok(handler_tuple(units, fields.end))
}

/// The unencodable units and `end` of a `UnicodeEncodeError`, for the
/// handlers that only handle encoding.
fn encode_error_range(vm: &Vm, exception: &Value) -> PyResult<(Vec<u16>, usize)> {
    let kind = error_kind(vm, exception)?;
    if !matches!(kind, ErrorKind::Encode) {
        return Err(wrong_exception_type(vm, exception));
    }

    let fields = error_fields(vm, exception, &kind)?;
    let units = fields.units.get(fields.start..fields.end).unwrap_or_default().to_vec();

    Ok((units, fields.end))
}

/// The 'xmlcharrefreplace' error handler.
fn xmlcharrefreplace_errors(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let exception = args::single(vm, args, "xmlcharrefreplace_errors")?;
    if exception.is_unknown() {
        return Ok(exception);
    }

    let (units, end) = encode_error_range(vm, &exception)?;

    Ok(handler_tuple(xml_character_references(&units).encode_utf16().collect(), end))
}

/// The 'backslashreplace' error handler.
fn backslashreplace_errors(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let exception = args::single(vm, args, "backslashreplace_errors")?;
    if exception.is_unknown() {
        return Ok(exception);
    }

    let (units, end) = encode_error_range(vm, &exception)?;

    Ok(handler_tuple(backslash_escapes(&units).encode_utf16().collect(), end))
}
