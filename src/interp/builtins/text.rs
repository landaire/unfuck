//! `str`, `unicode`, and `basestring`: constructors, methods, `%`
//! formatting, `str.format`, the format-spec mini-language, and codecs.

pub(crate) mod chars;
pub mod codecs;
mod format;
mod formatter;
mod methods;
mod percent;
mod spec;
mod unicode_db;
mod unicode_name_table;
pub mod unicode_names;

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::install as install_methods;
use crate::interp::builtins::modules::codecs::Direction;
use crate::interp::builtins::modules::codecs::code_with_registry;
use crate::interp::builtins::modules::codecs::errors::code_points;
use crate::interp::builtins::parse;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::receiver;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub(crate) use methods::str_method_body;

pub fn install(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install_methods(vm, &types.basestring, &[static_method("__new__", basestring_new)])?;
    install_methods(vm, &types.str, &[static_method("__new__", str_new)])?;
    install_methods(vm, &types.unicode, &[static_method("__new__", unicode_new)])?;
    methods::install(vm)?;

    format::install(vm)
}

/// `repr` of a byte string.
pub fn repr_bytes(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') { '"' } else { '\'' };
    let mut output = String::with_capacity(bytes.len() + 2);
    output.push(quote);

    for &byte in bytes {
        match byte {
            b'\\' => output.push_str("\\\\"),
            b'\t' => output.push_str("\\t"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            _ if char::from(byte) == quote => {
                output.push('\\');
                output.push(quote);
            }
            0x20..=0x7e => output.push(char::from(byte)),
            _ => output.push_str(&format!("\\x{byte:02x}")),
        }
    }

    output.push(quote);
    output
}

/// `repr` of a unicode string. The narrow build shows a surrogate pair as
/// one `\U` escape.
pub fn repr_unicode(units: &[u16]) -> String {
    let quote = if units.contains(&u16::from(b'\'')) && !units.contains(&u16::from(b'"')) { '"' } else { '\'' };
    let mut output = String::with_capacity(units.len() + 3);
    output.push('u');
    output.push(quote);

    for code in code_points(units) {
        match code {
            0x5c => output.push_str("\\\\"),
            0x09 => output.push_str("\\t"),
            0x0a => output.push_str("\\n"),
            0x0d => output.push_str("\\r"),
            _ if code == u32::from(quote) => {
                output.push('\\');
                output.push(quote);
            }
            0x20..=0x7e => output.push(char::from(code as u8)),
            0..=0xff => output.push_str(&format!("\\x{code:02x}")),
            0x100..=0xffff => output.push_str(&format!("\\u{code:04x}")),
            _ => output.push_str(&format!("\\U{code:08x}")),
        }
    }

    output.push(quote);
    output
}

fn basestring_new(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.type_error("The basestring type cannot be instantiated"))
}

/// The class argument of a builtin `__new__`, checked to derive from
/// `base`.
fn subtype_argument(vm: &Vm, args: CallArgs, base: &ObjectRef, name: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (class, rest) = receiver(vm, args, "__new__")?;
    let Value::Object(class) = class else {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(&class))));
    };
    if class.as_class().is_none() {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.class_name(&class.class()))));
    }
    if !vm.is_subclass(&class, base)? {
        return Err(vm.type_error(&format!("{name}.__new__({}): {} is not a subtype of {name}", vm.class_name(&class), vm.class_name(&class))));
    }

    Ok((class, rest))
}

/// Instance of `class` (a subclass of a builtin immutable type) holding
/// `payload`.
fn subtype_instance(vm: &Vm, class: &ObjectRef, payload: Payload) -> Value {
    let dict = class.as_class().is_some_and(|data| data.instance_dict).then(|| vm.new_dict());

    Value::Object(vm.alloc(class, payload, dict))
}

/// `str(object='')`.
fn str_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().str);
    let (class, rest) = subtype_argument(vm, args, &base, "str")?;
    let slots = parse(vm, rest, "str", &["object"], 0)?;

    let value = match &slots[0] {
        Some(object) => vm.to_str(object)?,
        None => Value::str(""),
    };
    if Rc::ptr_eq(&class, &base) || value.is_unknown() {
        return Ok(value);
    }

    let Some(bytes) = vm.as_str_bytes(&value) else {
        return Err(vm.type_error("str() did not return a string"));
    };

    Ok(subtype_instance(vm, &class, Payload::Str(bytes)))
}

/// `unicode(string=u''[, encoding[, errors]])`.
fn unicode_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().unicode);
    let (class, rest) = subtype_argument(vm, args, &base, "unicode")?;
    let slots = parse_with(vm, rest, "unicode", &["string", "encoding", "errors"], 0, |vm, index, value| match index {
        _ if value.is_unknown() => Ok(value),
        0 => Ok(value),
        _ => string_argument(vm, &value, "unicode", index + 1).map(|bytes| Value::Str(PyBytes::new(bytes))),
    })?;
    if let Some(unknown) = slots.iter().flatten().find(|value| value.is_unknown()) {
        return Ok(unknown.clone());
    }

    let text_of = |slot: &Option<Value>| match slot {
        Some(Value::Str(bytes)) => Some(bytes.as_bytes().to_vec()),
        _ => None,
    };
    let value = match &slots[..] {
        [None, ..] => Value::Unicode(PyText::new(Vec::new())),
        [Some(object), None, None] => vm.to_unicode(object)?,
        [Some(object), encoding, errors] => vm.decode_object(object, text_of(encoding).as_deref(), text_of(errors).as_deref())?,
        _ => return Err(vm.type_error("unicode() takes at most 3 arguments")),
    };
    if value.is_unknown() {
        return Ok(value);
    }

    let Some(text) = vm.as_text(&value) else {
        return Err(vm.type_error(&format!("decoder did not return an unicode object (type={})", vm.type_name(&value))));
    };
    if Rc::ptr_eq(&class, &base) {
        return Ok(Value::Unicode(text));
    }

    Ok(subtype_instance(vm, &class, Payload::Unicode(text)))
}

/// A `char *` argument (`s` format): a `str`, or a `unicode` encoded with
/// the default encoding.
fn string_argument(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<Vec<u8>> {
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(bytes.as_bytes().to_vec());
    }
    if let Some(text) = vm.as_text(value) {
        return Ok(codecs::encode_default(vm, text.units())?.as_bytes().to_vec());
    }

    Err(vm.type_error(&format!("{function}() argument {position} must be string, not {}", vm.type_name(value))))
}

/// The result of an `__index__` call. An unknown index decides the shape of
/// the result, so it halts like any branch on an unknown value.
fn index_result(result: Value) -> PyResult<Value> {
    let Value::Unknown(unknown) = &result else {
        return Ok(result);
    };

    Err(Signal::Halt(Halt::UnknownCondition { context: "__index__".to_owned(), origin: unknown.origin.clone() }))
}

/// A C `int` argument (`i` format).
fn int_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let number = match vm.as_integral(value) {
        Some(Integral::Int(number)) => number,
        Some(Integral::Long(number)) => number.to_i64().ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))?,
        None => return Err(vm.type_error("an integer is required")),
    };

    if number > i64::from(i32::MAX) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum"));
    }
    if number < i64::from(i32::MIN) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum"));
    }

    Ok(number)
}

/// The first unknown among call arguments. A method whose result depends
/// on an unknown argument is itself unknown.
fn unknown_argument(args: &CallArgs) -> Option<Value> {
    args.positional.iter().chain(args.keywords.iter().map(|(_, value)| value)).find(|value| value.is_unknown()).cloned()
}

/// Rejects a string result of `size` units with `MemoryError`, as the
/// client's allocation would fail, instead of exhausting the host.
pub(crate) fn check_size(vm: &Vm, size: i64) -> PyResult<()> {
    if size <= i64::from(i32::MAX) {
        return Ok(());
    }

    let class = Rc::clone(vm.types().exception(ExceptionKind::MemoryError));

    Err(Signal::Raise(vm.instantiate_exception(&class, Vec::new())?))
}

/// An exception of `kind` whose message is a `str` holding `message`
/// as is, including bytes outside ASCII.
pub(crate) fn raise_bytes(vm: &Vm, kind: ExceptionKind, message: Vec<u8>) -> Signal {
    let class = Rc::clone(vm.types().exception(kind));

    vm.raise_string(&class, Value::Str(PyBytes::new(message)))
}

impl Vm {
    /// `unicode(value)`: `__unicode__`, then `str()` decoded with the default
    /// encoding.
    pub fn to_unicode(&self, value: &Value) -> PyResult<Value> {
        if value.is_unknown() || matches!(value, Value::Unicode(_)) {
            return Ok(value.clone());
        }

        let result = if let Some(method) = self.user_override(value, "__unicode__")? {
            self.call0(&method)?
        } else if let Some(text) = self.as_text(value) {
            // A subclass instance is copied into an exact `unicode`.
            return Ok(Value::Unicode(PyText::new(text.units())));
        } else if let Some(exception) = self.exception_unicode(value)? {
            return Ok(exception);
        } else {
            self.object_str(value)?
        };

        if result.is_unknown() {
            return Ok(result);
        }
        if let Some(text) = self.as_text(&result) {
            return Ok(Value::Unicode(text));
        }
        if let Some(bytes) = self.as_str_bytes(&result) {
            return Ok(Value::Unicode(codecs::decode_default(self, bytes.as_bytes())?));
        }

        Err(self.type_error(&format!("coercing to Unicode: need string or buffer, {} found", self.type_name(&result))))
    }

    /// `BaseException.__unicode__` for an exception value; `None` when
    /// `value` is not an exception.
    pub(crate) fn exception_unicode(&self, value: &Value) -> PyResult<Option<Value>> {
        if !matches!(value.as_object().map(|object| &object.payload), Some(Payload::Exception(..))) {
            return Ok(None);
        }

        crate::interp::builtins::exception_types::exception_unicode(self, value).map(Some)
    }

    /// `str(value)` except that a `__str__` returning `unicode` keeps it.
    pub(crate) fn object_str(&self, value: &Value) -> PyResult<Value> {
        let Some(method) = self.user_override(value, "__str__")? else {
            return self.to_str(value);
        };

        let result = self.call0(&method)?;
        if result.is_unknown() || self.as_str_bytes(&result).is_some() || self.as_text(&result).is_some() {
            return Ok(result);
        }

        Err(self.type_error(&format!("__str__ returned non-string (type {})", self.type_name(&result))))
    }

    /// Decodes a byte string; `None` encoding means the default encoding.
    pub fn decode_object(&self, object: &Value, encoding: Option<&[u8]>, errors: Option<&[u8]>) -> PyResult<Value> {
        if object.is_unknown() {
            return Ok(object.clone());
        }
        if self.as_text(object).is_some() {
            return Err(self.type_error("decoding Unicode is not supported"));
        }
        if self.as_bytearray(object).is_some() {
            return Err(self.type_error("decoding bytearray is not supported"));
        }
        let Some(bytes) = self.coercible_char_buffer(object)? else {
            return Err(self.type_error(&format!("coercing to Unicode: need string or buffer, {} found", self.type_name(object))));
        };

        let name = encoding.unwrap_or(b"ascii");
        let Some(codec) = codecs::Codec::lookup(name) else {
            let decoded = code_with_registry(self, name, Value::Str(bytes), errors, Direction::Decode)?;
            if decoded.is_unknown() || self.as_text(&decoded).is_some() {
                return Ok(decoded);
            }
            return Err(self.type_error(&format!("decoder did not return an unicode object (type={})", self.type_name(&decoded))));
        };

        codecs::decode(self, codec, bytes.as_bytes(), errors)
    }

    /// The character buffer of a value as decoding reads it, which reports a
    /// `TypeError` as a failed coercion; `None` then.
    pub(crate) fn coercible_char_buffer(&self, value: &Value) -> PyResult<Option<PyBytes>> {
        match self.buffer(value, BufferInterface::Character) {
            Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::TypeError) => Ok(None),
            result => result,
        }
    }

    /// Unicode coercion of a value other than a `bytearray`: text, a `str`,
    /// or another character buffer, decoded with the default encoding; `None`
    /// when it is none of these.
    pub(crate) fn unicode_from_object(&self, value: &Value) -> PyResult<Option<PyText>> {
        if let Some(text) = self.coerce_text(value)? {
            return Ok(Some(text));
        }
        let Some(bytes) = self.coercible_char_buffer(value)? else {
            return Ok(None);
        };

        codecs::decode_default(self, bytes.as_bytes()).map(Some)
    }

    /// `str.decode`: the codec's result for a byte string, which must be a
    /// `str` or `unicode`.
    pub fn decode_bytes(&self, bytes: &[u8], encoding: Option<&[u8]>, errors: Option<&[u8]>) -> PyResult<Value> {
        let name = encoding.unwrap_or(b"ascii");
        let Some(codec) = codecs::Codec::lookup(name) else {
            let decoded = code_with_registry(self, name, Value::Str(PyBytes::new(bytes)), errors, Direction::Decode)?;
            return self.require_string_result(decoded, "decoder");
        };

        codecs::decode(self, codec, bytes, errors)
    }

    /// The native codec for `encoding` (the default encoding when `None`);
    /// `None` for codecs only the registry provides.
    pub(crate) fn native_codec(&self, encoding: Option<&[u8]>) -> Option<codecs::Codec> {
        codecs::Codec::lookup(encoding.unwrap_or(b"ascii"))
    }

    /// The check `str.encode`, `str.decode`, and `unicode.encode` apply to
    /// a registry codec's result.
    pub(crate) fn require_string_result(&self, result: Value, role: &str) -> PyResult<Value> {
        if result.is_unknown() || self.as_str_bytes(&result).is_some() || self.as_text(&result).is_some() {
            return Ok(result);
        }

        Err(self.type_error(&format!("{role} did not return a string/unicode object (type={})", self.type_name(&result))))
    }
}

/// Raised Python exception of the given kind, as opposed to halts and
/// other exceptions.
fn is_raised(vm: &Vm, signal: &Signal, kind: ExceptionKind) -> bool {
    matches!(signal, Signal::Raise(exception) if vm.is_exception(exception, kind))
}
