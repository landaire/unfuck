//! The builtin exception classes: the `__new__` and `__init__` of each
//! class, the `__str__` forms, pickling support, and the native fields
//! (`message`, `errno`, `code`, ...) exposed as member descriptors.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::core::object_delattr;
use crate::interp::builtins::core::object_getattribute;
use crate::interp::builtins::core::object_repr;
use crate::interp::builtins::core::object_setattr;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::static_method;
use crate::interp::builtins::winerror_map::winerror_to_errno;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeFn;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The names of the C fields beyond `args`.
const FIELDS: [&str; 17] = [
    "message",
    "code",
    "errno",
    "strerror",
    "filename",
    "winerror",
    "msg",
    "lineno",
    "offset",
    "text",
    "print_file_and_line",
    "encoding",
    "object",
    "start",
    "end",
    "reason",
    "__dict__",
];

fn static_field(name: &str) -> Option<&'static str> {
    FIELDS.iter().copied().find(|field| *field == name)
}

/// A C field of `object`; `None` when NULL.
pub fn field(object: &ObjectRef, name: &str) -> Option<Value> {
    let Payload::Exception(data) = &object.payload else {
        return None;
    };
    let fields = data.fields.borrow();
    let stored = fields.values.iter().find(|(key, _)| *key == name).map(|(_, value)| value.clone());

    match name {
        "message" if fields.message_deleted => None,
        "message" => Some(stored.unwrap_or_else(|| Value::str(""))),
        _ => stored,
    }
}

/// Stores a C field of `object`; `None` makes it NULL.
pub fn set_field(object: &ObjectRef, name: &'static str, value: Option<Value>) {
    let Payload::Exception(data) = &object.payload else {
        return;
    };
    let mut fields = data.fields.borrow_mut();

    if name == "message" {
        fields.message_deleted = value.is_none();
    }
    fields.values.retain(|(key, _)| *key != name);
    if let Some(value) = value {
        fields.values.push((name, value));
    }
}

/// An index field (`start`, `end`), zero until set.
fn size_field(vm: &Vm, object: &ObjectRef, name: &str) -> i64 {
    field(object, name).and_then(|value| vm.as_index(&value)).unwrap_or(0)
}

fn stored_args(object: &ObjectRef) -> Value {
    match &object.payload {
        Payload::Exception(data) => data.args.borrow().clone(),
        _ => Value::tuple(Vec::new()),
    }
}

fn set_args(object: &ObjectRef, args: Value) {
    if let Payload::Exception(data) = &object.payload {
        *data.args.borrow_mut() = args;
    }
}

/// The class of a builtin exception kind.
fn kind_class(vm: &Vm, kind: ExceptionKind) -> ObjectRef {
    Rc::clone(vm.types().exception(kind))
}

/// The type name of a builtin exception class.
fn kind_name(kind: ExceptionKind) -> String {
    format!("exceptions.{}", kind.name())
}

fn kind_at(index: usize) -> ExceptionKind {
    ExceptionKind::ALL.get(index).copied().unwrap_or(ExceptionKind::BaseException)
}

/// The kinds whose class defines its own string conversion.
const STR_KINDS: [ExceptionKind; 8] = [
    ExceptionKind::WindowsError,
    ExceptionKind::EnvironmentError,
    ExceptionKind::SyntaxError,
    ExceptionKind::KeyError,
    ExceptionKind::UnicodeEncodeError,
    ExceptionKind::UnicodeDecodeError,
    ExceptionKind::UnicodeTranslateError,
    ExceptionKind::BaseException,
];

/// The builtin kind whose string conversion instances of `class` inherit.
fn str_kind(vm: &Vm, class: &ObjectRef) -> ExceptionKind {
    let Some(data) = class.as_class() else {
        return ExceptionKind::BaseException;
    };

    for entry in data.mro() {
        let crate::interp::object::MroEntry::Class(ancestor) = entry else {
            continue;
        };
        if let Some(kind) = STR_KINDS.iter().copied().find(|kind| Rc::ptr_eq(&ancestor, vm.types().exception(*kind))) {
            return kind;
        }
    }

    ExceptionKind::BaseException
}

/// The `__init__` behavior of a builtin exception kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Init {
    Base,
    SystemExit,
    Environment,
    Windows,
    Syntax,
    UnicodeEncode,
    UnicodeDecode,
    UnicodeTranslate,
}

fn init_of(kind: ExceptionKind) -> Init {
    match kind {
        ExceptionKind::SystemExit => Init::SystemExit,
        ExceptionKind::EnvironmentError | ExceptionKind::IOError | ExceptionKind::OSError => Init::Environment,
        ExceptionKind::WindowsError => Init::Windows,
        ExceptionKind::SyntaxError | ExceptionKind::IndentationError | ExceptionKind::TabError => Init::Syntax,
        ExceptionKind::UnicodeEncodeError => Init::UnicodeEncode,
        ExceptionKind::UnicodeDecodeError => Init::UnicodeDecode,
        ExceptionKind::UnicodeTranslateError => Init::UnicodeTranslate,
        _ => Init::Base,
    }
}

/// The type names of the kinds that define members.
fn member_owner_name(kind: ExceptionKind) -> &'static str {
    match kind {
        ExceptionKind::SystemExit => "exceptions.SystemExit",
        ExceptionKind::EnvironmentError => "exceptions.EnvironmentError",
        ExceptionKind::WindowsError => "exceptions.WindowsError",
        ExceptionKind::SyntaxError => "exceptions.SyntaxError",
        ExceptionKind::UnicodeEncodeError => "exceptions.UnicodeEncodeError",
        ExceptionKind::UnicodeDecodeError => "exceptions.UnicodeDecodeError",
        ExceptionKind::UnicodeTranslateError => "exceptions.UnicodeTranslateError",
        _ => "exceptions.BaseException",
    }
}

/// The C member fields a kind adds.
fn members_of(kind: ExceptionKind) -> &'static [&'static str] {
    match kind {
        ExceptionKind::SystemExit => &["code"],
        ExceptionKind::EnvironmentError => &["errno", "strerror", "filename"],
        ExceptionKind::WindowsError => &["errno", "strerror", "filename", "winerror"],
        ExceptionKind::SyntaxError => &["msg", "filename", "lineno", "offset", "text", "print_file_and_line"],
        ExceptionKind::UnicodeEncodeError | ExceptionKind::UnicodeDecodeError | ExceptionKind::UnicodeTranslateError => &["encoding", "object", "start", "end", "reason"],
        _ => &[],
    }
}

macro_rules! per_kind {
    ($function:ident, $($index:literal)*) => {
        [$($function::<$index> as NativeFn,)*]
    };
}

const NEW: [NativeFn; 51] = per_kind!(kind_new, 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50);

const INIT: [NativeFn; 51] = per_kind!(kind_init, 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50);

/// Installs the methods, members, and getsets of every builtin exception
/// class, and records their module for the type name.
pub fn install_exception_types(vm: &Vm) -> PyResult<()> {
    for (index, kind) in ExceptionKind::ALL.iter().copied().enumerate() {
        let class = kind_class(vm, kind);
        vm.set_static_module(&class, "exceptions");

        let (Some(new), Some(init)) = (NEW.get(index), INIT.get(index)) else {
            return Err(vm.halt_unsupported("an exception kind beyond the per-kind tables"));
        };
        install(vm, &class, &[static_method("__new__", *new), method("__init__", *init)])?;

        let str_method: Option<NativeFn> = match kind {
            ExceptionKind::BaseException => Some(base_str_method),
            ExceptionKind::EnvironmentError => Some(environment_str_method),
            ExceptionKind::WindowsError => Some(windows_str_method),
            ExceptionKind::SyntaxError => Some(syntax_str_method),
            ExceptionKind::KeyError => Some(key_str_method),
            ExceptionKind::UnicodeEncodeError => Some(unicode_encode_str_method),
            ExceptionKind::UnicodeDecodeError => Some(unicode_decode_str_method),
            ExceptionKind::UnicodeTranslateError => Some(unicode_translate_str_method),
            _ => None,
        };
        if let Some(str_method) = str_method {
            install(vm, &class, &[method("__str__", str_method)])?;
        }

        let owner = member_owner_name(kind);
        for &name in members_of(kind) {
            add_member(vm, &class, GetSet { name, owner, get: member_get, set: Some(member_set) })?;
        }
    }

    let base = kind_class(vm, ExceptionKind::BaseException);
    install(
        vm,
        &base,
        &[
            method("__repr__", object_repr),
            method("__getitem__", exception_getitem),
            method("__getslice__", exception_getslice),
            method("__getattribute__", object_getattribute),
            method("__setattr__", object_setattr),
            method("__delattr__", object_delattr),
            method("__reduce__", base_reduce),
            method("__setstate__", base_setstate),
            method("__unicode__", base_unicode),
        ],
    )?;
    let owner = "exceptions.BaseException";
    add_getset(vm, &base, GetSet { name: "__dict__", owner, get: dict_get, set: Some(dict_set) })?;
    add_getset(vm, &base, GetSet { name: "args", owner, get: args_get, set: Some(args_set) })?;
    add_getset(vm, &base, GetSet { name: "message", owner, get: message_get, set: Some(message_set) })?;

    let environment = kind_class(vm, ExceptionKind::EnvironmentError);
    install(vm, &environment, &[method("__reduce__", environment_reduce)])
}

/// The receiver of a method of `kind`'s class, checked as a slot wrapper
/// or method descriptor checks it.
fn bound(vm: &Vm, args: &CallArgs, kind: ExceptionKind, method: &str) -> PyResult<ObjectRef> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{}' object needs an argument", kind_name(kind))));
    };
    let class = kind_class(vm, kind);
    match receiver {
        Value::Object(object) if vm.is_instance_of(receiver, &class)? && matches!(object.payload, Payload::Exception(..)) => Ok(Rc::clone(object)),
        _ => Err(vm.type_error(&format!("descriptor '{method}' requires a '{}' object but received a '{}'", kind_name(kind), vm.type_name(receiver)))),
    }
}

/// The `__new__` of `kind`'s class.
fn kind_new<const KIND: usize>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let kind = kind_at(KIND);
    let owner = kind_name(kind);
    let Some(first) = args.positional.first() else {
        return Err(vm.type_error(&format!("{owner}.__new__(): not enough arguments")));
    };
    let Value::Object(class) = first else {
        return Err(vm.type_error(&format!("{owner}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    };
    if class.as_class().is_none() {
        return Err(vm.type_error(&format!("{owner}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    }
    if !vm.is_subclass(class, &kind_class(vm, kind))? {
        let name = vm.class_name(class);
        return Err(vm.type_error(&format!("{owner}.__new__({name}): {name} is not a subtype of {owner}")));
    }

    vm.instantiate_layout(class)
}

/// The `__init__` of `kind`'s class as its slot wrapper.
fn kind_init<const KIND: usize>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let kind = kind_at(KIND);
    let object = bound(vm, &args, kind, "__init__")?;
    let (_, rest) = receiver(vm, args, "__init__")?;
    if rest.has_keywords() {
        return Err(vm.type_error(&format!("{} does not take keyword arguments", vm.type_name(&Value::Object(Rc::clone(&object))))));
    }

    initialize(vm, &object, init_of(kind), rest.positional)?;

    Ok(Value::None)
}

fn initialize(vm: &Vm, object: &ObjectRef, init: Init, args: Vec<Value>) -> PyResult<()> {
    base_init(object, &args);

    match init {
        Init::Base => Ok(()),
        Init::SystemExit => {
            match args.as_slice() {
                [] => {}
                [code] => set_field(object, "code", Some(code.clone())),
                _ => set_field(object, "code", Some(Value::tuple(args.clone()))),
            }
            Ok(())
        }
        Init::Environment => environment_init(object, &args),
        Init::Windows => windows_init(vm, object, &args),
        Init::Syntax => syntax_init(vm, object, &args),
        Init::UnicodeEncode => unicode_init(vm, object, &args, true, false),
        Init::UnicodeDecode => unicode_init(vm, object, &args, false, false),
        Init::UnicodeTranslate => unicode_init(vm, object, &args, true, true),
    }
}

/// `BaseException.__init__`.
fn base_init(object: &ObjectRef, args: &[Value]) {
    set_args(object, Value::tuple(args.to_vec()));
    if let [only] = args {
        set_field(object, "message", Some(only.clone()));
    }
}

/// `EnvironmentError.__init__`.
fn environment_init(object: &ObjectRef, args: &[Value]) -> PyResult<()> {
    if args.len() <= 1 || args.len() > 3 {
        return Ok(());
    }

    set_field(object, "errno", Some(args[0].clone()));
    set_field(object, "strerror", Some(args[1].clone()));
    if let Some(filename) = args.get(2) {
        set_field(object, "filename", Some(filename.clone()));
        set_args(object, Value::tuple(args[..2].to_vec()));
    }

    Ok(())
}

/// `WindowsError.__init__`: `errno` becomes the POSIX code and `winerror` the
/// Win32 code given.
fn windows_init(vm: &Vm, object: &ObjectRef, args: &[Value]) -> PyResult<()> {
    environment_init(object, args)?;

    let Some(code) = field(object, "errno") else {
        return Ok(());
    };
    let Some(number) = c_long(vm, &code)? else {
        return Err(vm.halt_unsupported("WindowsError with an unknown error code"));
    };

    set_field(object, "winerror", Some(code));
    set_field(object, "errno", Some(Value::Int(i64::from(winerror_to_errno(number)))));

    Ok(())
}

/// Conversion to a C `long` for the Windows build, where `long` has 32
/// bits. `None` for unknown values.
fn c_long(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let number = if let Some(integral) = vm.as_integral(value) {
        integral
    } else if let Some(number) = vm.as_float(value) {
        if !number.is_finite() {
            let what = if number.is_nan() { "cannot convert float NaN to integer" } else { "cannot convert float infinity to integer" };
            return Err(vm.raise(if number.is_nan() { ExceptionKind::ValueError } else { ExceptionKind::OverflowError }, what));
        }
        match number.trunc().to_i64() {
            Some(number) => Integral::Int(number),
            None => return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
        }
    } else if let Some(method) = vm.user_override(value, "__int__")? {
        let result = vm.call0(&method)?;
        if result.is_unknown() {
            return Ok(None);
        }
        vm.as_integral(&result).ok_or_else(|| vm.type_error("nb_int should return int object"))?
    } else {
        return Err(vm.type_error("an integer is required"));
    };

    let number = match number {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    number.and_then(|number| i32::try_from(number).ok()).map(Some).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))
}

/// `SyntaxError.__init__`.
fn syntax_init(vm: &Vm, object: &ObjectRef, args: &[Value]) -> PyResult<()> {
    if let Some(message) = args.first() {
        set_field(object, "msg", Some(message.clone()));
    }

    let [_, info] = args else {
        return Ok(());
    };
    let Ok(fields) = <[Value; 4]>::try_from(vm.collect(info)?) else {
        return Err(vm.raise(ExceptionKind::IndexError, "tuple index out of range"));
    };
    for (name, value) in ["filename", "lineno", "offset", "text"].into_iter().zip(fields) {
        set_field(object, name, Some(value));
    }

    Ok(())
}

/// The `n` argument format: a signed size after the float check, with
/// the failures argument parsing reports.
fn ssize(vm: &Vm, value: &Value) -> PyResult<i64> {
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    int_as_ssize(vm, value)
}

/// Conversion to a signed size on the Windows x64 build, where the size
/// type is wider than `long`: integers directly, other numbers through
/// `__long__` when they have it, else `__int__`.
fn int_as_ssize(vm: &Vm, value: &Value) -> PyResult<i64> {
    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            if let Some(number) = vm.as_float(value) {
                if !number.is_finite() {
                    let (kind, message) = if number.is_nan() { (ExceptionKind::ValueError, "cannot convert float NaN to integer") } else { (ExceptionKind::OverflowError, "cannot convert float infinity to integer") };
                    return Err(vm.raise(kind, message));
                }
                return number.trunc().to_i64().ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to int"));
            }
            let method = match vm.user_override(value, "__long__")? {
                Some(method) => method,
                None => vm.user_override(value, "__int__")?.ok_or_else(|| vm.type_error("an integer is required"))?,
            };
            let result = vm.call0(&method)?;
            vm.as_integral(&result).ok_or_else(|| vm.type_error("nb_int should return int object"))?
        }
    };

    match integral {
        Integral::Int(number) => Ok(number),
        Integral::Long(number) => number.to_i64().ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to int")),
    }
}

/// `UnicodeError.__init__` and `UnicodeTranslateError.__init__`: the `O!O!nnO!`
/// (or `O!nnO!`) parse into the fields. The object fields are cleared
/// first and stay NULL when parsing fails; `start` and `end` keep what
/// was parsed before a failure.
fn unicode_init(vm: &Vm, object: &ObjectRef, args: &[Value], unicode_object: bool, translate: bool) -> PyResult<()> {
    if !translate {
        set_field(object, "encoding", None);
    }
    set_field(object, "object", None);
    set_field(object, "reason", None);

    let expected = if translate { 4 } else { 5 };
    if args.len() != expected {
        return Err(vm.type_error(&format!("function takes exactly {expected} arguments ({} given)", args.len())));
    }

    let mut position = 0;
    let mut encoding = None;
    if !translate {
        if vm.as_str_bytes(&args[0]).is_none() {
            return Err(vm.type_error(&format!("argument 1 must be str, not {}", vm.type_name(&args[0]))));
        }
        encoding = Some(args[0].clone());
        position = 1;
    }

    let text = &args[position];
    let valid = if unicode_object { vm.as_text(text).is_some() } else { vm.as_str_bytes(text).is_some() };
    if !valid {
        let expected = if unicode_object { "unicode" } else { "str" };
        return Err(vm.type_error(&format!("argument {} must be {expected}, not {}", position + 1, vm.type_name(text))));
    }

    let start = ssize(vm, &args[position + 1])?;
    set_field(object, "start", Some(Value::Int(start)));
    let end = ssize(vm, &args[position + 2])?;
    set_field(object, "end", Some(Value::Int(end)));

    let reason = &args[position + 3];
    if vm.as_str_bytes(reason).is_none() {
        return Err(vm.type_error(&format!("argument {} must be str, not {}", position + 4, vm.type_name(reason))));
    }

    if let Some(encoding) = encoding {
        set_field(object, "encoding", Some(encoding));
    }
    set_field(object, "object", Some(text.clone()));
    set_field(object, "reason", Some(reason.clone()));

    Ok(())
}

/// `str(exception)` for a builtin exception without a Python `__str__`:
/// the string conversion its class inherits.
pub fn exception_str(vm: &Vm, exception: &Value) -> PyResult<Value> {
    let Value::Object(object) = exception else {
        return vm.to_str(exception);
    };

    // `_ssl` replaces the string conversion of its `SSLError` classes.
    if let Some(text) = crate::interp::builtins::modules::ssl::error_text(vm, object, &stored_args(object)) {
        return text;
    }

    match str_kind(vm, &object.class()) {
        ExceptionKind::WindowsError => windows_str(vm, object),
        ExceptionKind::EnvironmentError => environment_str(vm, object),
        ExceptionKind::SyntaxError => syntax_str(vm, object),
        ExceptionKind::KeyError => key_str(vm, object),
        ExceptionKind::UnicodeEncodeError => unicode_str(vm, object, UnicodeForm::Encode),
        ExceptionKind::UnicodeDecodeError => unicode_str(vm, object, UnicodeForm::Decode),
        ExceptionKind::UnicodeTranslateError => unicode_str(vm, object, UnicodeForm::Translate),
        _ => base_str(vm, object),
    }
}

/// Whether `str` of instances of `class` is `BaseException.__str__`.
pub fn uses_base_str(vm: &Vm, class: &ObjectRef) -> bool {
    str_kind(vm, class) == ExceptionKind::BaseException
}

/// `BaseException.__str__`.
fn base_str(vm: &Vm, object: &ObjectRef) -> PyResult<Value> {
    let args = stored_args(object);
    let items = vm.as_tuple(&args).map(|items| items.to_vec()).unwrap_or_default();

    match items.as_slice() {
        [] => Ok(Value::str("")),
        [only] => vm.to_str(only),
        _ => vm.to_str(&args),
    }
}

/// `unicode()` of the string conversion result when the class overrides
/// it, else of `args`.
pub fn exception_unicode(vm: &Vm, exception: &Value) -> PyResult<Value> {
    let Value::Object(object) = exception else {
        return vm.to_unicode(exception);
    };

    if let Some(method) = vm.user_override(exception, "__str__")? {
        let text = vm.call0(&method)?;
        return vm.to_unicode(&text);
    }
    if !uses_base_str(vm, &object.class()) {
        let text = exception_str(vm, exception)?;
        return vm.to_unicode(&text);
    }

    let args = stored_args(object);
    let items = vm.as_tuple(&args).map(|items| items.to_vec()).unwrap_or_default();
    match items.as_slice() {
        [] => Ok(Value::Unicode(PyText::new(Vec::new()))),
        [only] => vm.to_unicode(only),
        _ => vm.to_unicode(&args),
    }
}

/// `"[Errno %s] %s: %s"`-style text of the environment error fields.
fn environment_text(vm: &Vm, label: &str, code: Option<Value>, strerror: Option<Value>, filename: Option<Value>) -> PyResult<Option<Value>> {
    if let Some(filename) = filename {
        let format = Value::str(&format!("[{label} %s] %s: %s"));
        let items = vec![code.unwrap_or(Value::None), strerror.unwrap_or(Value::None), vm.repr(&filename)?];
        return vm.format_percent(&format, &Value::tuple(items)).map(Some);
    }
    if let (Some(code), Some(strerror)) = (code, strerror) {
        let format = Value::str(&format!("[{label} %s] %s"));
        return vm.format_percent(&format, &Value::tuple(vec![code, strerror])).map(Some);
    }

    Ok(None)
}

/// `EnvironmentError.__str__`.
fn environment_str(vm: &Vm, object: &ObjectRef) -> PyResult<Value> {
    match environment_text(vm, "Errno", field(object, "errno"), field(object, "strerror"), field(object, "filename"))? {
        Some(text) => Ok(text),
        None => base_str(vm, object),
    }
}

/// `WindowsError.__str__`.
fn windows_str(vm: &Vm, object: &ObjectRef) -> PyResult<Value> {
    match environment_text(vm, "Error", field(object, "winerror"), field(object, "strerror"), field(object, "filename"))? {
        Some(text) => Ok(text),
        None => environment_str(vm, object),
    }
}

/// The bytes a C `%s` reads: up to the first NUL.
fn c_string(bytes: &[u8]) -> &[u8] {
    bytes.split(|&byte| byte == 0).next().unwrap_or_default()
}

/// `SyntaxError.__str__`.
fn syntax_str(vm: &Vm, object: &ObjectRef) -> PyResult<Value> {
    let message = vm.to_str(&field(object, "msg").unwrap_or(Value::None))?;
    let Some(text) = vm.as_str_bytes(&message) else {
        return Ok(message);
    };

    let filename = field(object, "filename").and_then(|filename| vm.as_str_bytes(&filename));
    let lineno = match field(object, "lineno") {
        Some(Value::Int(number)) => Some(number),
        Some(Value::Bool(flag)) => Some(i64::from(flag)),
        Some(Value::Object(lineno)) => match &lineno.payload {
            Payload::Int(number) => Some(*number),
            _ => None,
        },
        _ => None,
    };
    if filename.is_none() && lineno.is_none() {
        return Ok(message);
    }

    // The base name splits at the path separator, a backslash on Windows.
    let base_name = filename.map(|filename| {
        let bytes = c_string(filename.as_bytes());
        let start = bytes.iter().rposition(|byte| *byte == b'\\').map_or(0, |index| index + 1);
        bytes[start..].to_vec()
    });

    let mut rendered = c_string(text.as_bytes()).to_vec();
    match (base_name, lineno) {
        (Some(name), Some(lineno)) => {
            rendered.extend_from_slice(b" (");
            rendered.extend_from_slice(&name);
            rendered.extend_from_slice(format!(", line {lineno})").as_bytes());
        }
        (Some(name), None) => {
            rendered.extend_from_slice(b" (");
            rendered.extend_from_slice(&name);
            rendered.push(b')');
        }
        (None, Some(lineno)) => rendered.extend_from_slice(format!(" (line {lineno})").as_bytes()),
        (None, None) => return Ok(message),
    }

    Ok(Value::Str(PyBytes::new(rendered)))
}

/// `KeyError.__str__`.
fn key_str(vm: &Vm, object: &ObjectRef) -> PyResult<Value> {
    let args = stored_args(object);
    if let Some([only]) = vm.as_tuple(&args).as_deref() {
        return vm.repr(only);
    }

    base_str(vm, object)
}

#[derive(Clone, Copy)]
enum UnicodeForm {
    Encode,
    Decode,
    Translate,
}

/// A `%.400s` argument: `str()` of the field (`<NULL>` when unset), cut
/// at a NUL and at 400 bytes.
fn limited_text(vm: &Vm, value: Option<Value>) -> PyResult<Vec<u8>> {
    let Some(value) = value else {
        return Ok(b"<NULL>".to_vec());
    };
    let text = vm.to_str(&value)?;
    let Some(bytes) = vm.as_str_bytes(&text) else {
        return Err(vm.halt_unsupported("str() of a UnicodeError field returned a non-str"));
    };
    let bytes = c_string(bytes.as_bytes());

    Ok(bytes[..bytes.len().min(400)].to_vec())
}

/// `__str__` of `UnicodeEncodeError`, `UnicodeDecodeError`, and
/// `UnicodeTranslateError`.
fn unicode_str(vm: &Vm, object: &ObjectRef, form: UnicodeForm) -> PyResult<Value> {
    let Some(subject) = field(object, "object") else {
        return Ok(Value::Unicode(PyText::new(Vec::new())));
    };

    let reason = limited_text(vm, field(object, "reason"))?;
    let encoding = match form {
        UnicodeForm::Translate => Vec::new(),
        UnicodeForm::Encode | UnicodeForm::Decode => limited_text(vm, field(object, "encoding"))?,
    };
    let start = size_field(vm, object, "start");
    let end = size_field(vm, object, "end");

    let length = match form {
        UnicodeForm::Decode => vm.as_str_bytes(&subject).map(|bytes| bytes.as_bytes().len()),
        UnicodeForm::Encode | UnicodeForm::Translate => vm.as_text(&subject).map(|text| text.units().len()),
    };
    let Some(length) = length else {
        return Err(vm.halt_unsupported("str() of a UnicodeError whose object has the wrong type"));
    };
    let length = i64::try_from(length).unwrap_or(i64::MAX);

    let single = start < length && end == start.wrapping_add(1);
    let quoted = |prefix: &[u8]| -> Vec<u8> { [b"'".as_slice(), &encoding, b"' codec can't ", prefix].concat() };

    let mut rendered = if single {
        let Ok(index) = usize::try_from(start) else {
            return Err(vm.halt_unsupported("str() of a UnicodeError with a negative start"));
        };
        match form {
            UnicodeForm::Decode => {
                let byte = vm.as_str_bytes(&subject).and_then(|bytes| bytes.as_bytes().get(index).copied()).unwrap_or(0);
                quoted(format!("decode byte 0x{byte:02x} in position {start}: ").as_bytes())
            }
            UnicodeForm::Encode | UnicodeForm::Translate => {
                let character = vm.as_text(&subject).and_then(|text| text.units().get(index).copied()).unwrap_or(0);
                let escape = if character <= 0xff { format!("x{character:02x}") } else { format!("u{character:04x}") };
                let text = format!("character u'\\{escape}' in position {start}: ");
                match form {
                    UnicodeForm::Translate => format!("can't translate {text}").into_bytes(),
                    _ => quoted(format!("encode {text}").as_bytes()),
                }
            }
        }
    } else {
        let last = end.wrapping_sub(1);
        match form {
            UnicodeForm::Encode => quoted(format!("encode characters in position {start}-{last}: ").as_bytes()),
            UnicodeForm::Decode => quoted(format!("decode bytes in position {start}-{last}: ").as_bytes()),
            UnicodeForm::Translate => format!("can't translate characters in position {start}-{last}: ").into_bytes(),
        }
    };
    rendered.extend_from_slice(&reason);

    Ok(Value::Str(PyBytes::new(rendered)))
}

macro_rules! str_methods {
    ($($name:ident => $kind:ident, $render:expr;)*) => {
        $(
            fn $name(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let object = bound(vm, &args, ExceptionKind::$kind, "__str__")?;
                positional(vm, CallArgs { positional: args.positional.into_iter().skip(1).collect(), keywords: args.keywords, keyword_dict: args.keyword_dict }, "__str__", 0, 0)?;
                let render: fn(&Vm, &ObjectRef) -> PyResult<Value> = $render;
                render(vm, &object)
            }
        )*
    };
}

str_methods! {
    base_str_method => BaseException, base_str;
    environment_str_method => EnvironmentError, environment_str;
    windows_str_method => WindowsError, windows_str;
    syntax_str_method => SyntaxError, syntax_str;
    key_str_method => KeyError, key_str;
    unicode_encode_str_method => UnicodeEncodeError, |vm, object| unicode_str(vm, object, UnicodeForm::Encode);
    unicode_decode_str_method => UnicodeDecodeError, |vm, object| unicode_str(vm, object, UnicodeForm::Decode);
    unicode_translate_str_method => UnicodeTranslateError, |vm, object| unicode_str(vm, object, UnicodeForm::Translate);
}

/// `BaseException.__getitem__`: `args[index]`.
fn exception_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::BaseException, "__getitem__")?;
    let args = positional(vm, args, "__getitem__", 2, 2)?;
    let index = ssize(vm, &args[1])?;

    vm.getitem(&stored_args(&object), &Value::Int(index))
}

/// `BaseException.__getslice__`: `args[i:j]`.
fn exception_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::BaseException, "__getslice__")?;
    let args = positional(vm, args, "__getslice__", 3, 3)?;
    let (start, stop) = (ssize(vm, &args[1])?, ssize(vm, &args[2])?);

    let stored = stored_args(&object);
    let items = vm.as_tuple(&stored).map(|items| items.to_vec()).unwrap_or_default();
    let length = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let adjust = |index: i64| if index < 0 { index + length } else { index };
    let start = usize::try_from(adjust(start).clamp(0, length)).unwrap_or(0);
    let stop = usize::try_from(adjust(stop).clamp(0, length)).unwrap_or(0).max(start);

    Ok(Value::tuple(items[start..stop].to_vec()))
}

/// `(type, args)`, or `(type, args, __dict__)` once the dict exists.
fn reduce_with(object: &ObjectRef, args: Value) -> Value {
    let class = Value::Object(object.class());
    match object.dict() {
        Some(dict) => Value::tuple(vec![class, args, Value::Object(dict)]),
        None => Value::tuple(vec![class, args]),
    }
}

/// `BaseException.__reduce__`.
fn base_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::BaseException, "__reduce__")?;
    crate::interp::builtins::modules::method_no_arguments(vm, &args, "__reduce__")?;

    Ok(reduce_with(&object, stored_args(&object)))
}

/// `EnvironmentError.__reduce__`: the filename rejoins the two `args`.
fn environment_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::EnvironmentError, "__reduce__")?;
    crate::interp::builtins::modules::method_no_arguments(vm, &args, "__reduce__")?;

    let stored = stored_args(&object);
    let reduced = match (vm.as_tuple(&stored).as_deref(), field(&object, "filename")) {
        (Some([first, second]), Some(filename)) => Value::tuple(vec![first.clone(), second.clone(), filename]),
        _ => stored,
    };

    Ok(reduce_with(&object, reduced))
}

/// `BaseException.__setstate__`.
fn base_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::BaseException, "__setstate__")?;
    let state = crate::interp::builtins::modules::method_one_argument(vm, &args, "__setstate__")?;
    if state.is_none() {
        return Ok(Value::None);
    }
    let dict = match &state {
        Value::Object(dict) if dict.as_dict().is_some() => Rc::clone(dict),
        _ => return Err(vm.type_error("state is not a dictionary")),
    };
    let items = vm.dict_items(&dict)?;

    let target = Value::Object(object);
    for (key, value) in items {
        // Attribute assignment takes a `unicode` name in the default encoding.
        let name = match (vm.as_str_bytes(&key), vm.as_text(&key)) {
            (Some(name), _) => name,
            (None, Some(text)) => match vm.encode_default(&text)? {
                Value::Str(name) => name,
                _ => return Err(vm.type_error("attribute name must be string")),
            },
            (None, None) => return Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(&key)))),
        };
        vm.setattr(&target, &name, value)?;
    }

    Ok(Value::None)
}

fn base_unicode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let object = bound(vm, &args, ExceptionKind::BaseException, "__unicode__")?;
    crate::interp::builtins::modules::method_no_arguments(vm, &args, "__unicode__")?;

    exception_unicode(vm, &Value::Object(object))
}

/// The exception a getset or member applies to.
fn exception_object<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a ObjectRef> {
    match instance {
        Value::Object(object) if matches!(object.payload, Payload::Exception(..)) => Ok(object),
        _ => Err(descriptor_mismatch(vm, getset, instance)),
    }
}

fn dict_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let object = exception_object(vm, getset, instance)?;

    Ok(Value::Object(vm.instance_dict(object)?))
}

fn dict_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let object = exception_object(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("__dict__ may not be deleted"));
    };
    let Value::Object(dict) = &value else {
        return Err(vm.type_error("__dict__ must be a dictionary"));
    };
    if !matches!(dict.payload, Payload::Dict(_)) {
        return Err(vm.type_error("__dict__ must be a dictionary"));
    }

    *object.dict.borrow_mut() = Some(Rc::clone(dict));

    Ok(())
}

fn args_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(stored_args(exception_object(vm, getset, instance)?))
}

fn args_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let object = exception_object(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("args may not be deleted"));
    };

    set_args(object, Value::tuple(vm.collect(&value)?));

    Ok(())
}

/// The `BaseException.message` getter.
fn message_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let object = exception_object(vm, getset, instance)?;
    if let Some(dict) = object.dict() {
        if let Some(message) = vm.dict_get_str(&dict, "message")? {
            return Ok(message);
        }
    }
    let Some(message) = field(object, "message") else {
        return Err(vm.raise(ExceptionKind::AttributeError, "message attribute was deleted"));
    };

    let warnings = vm.import_module("_warnings")?;
    let warn = vm.getattr_str(&warnings, "warn")?;
    let category = Value::Object(kind_class(vm, ExceptionKind::DeprecationWarning));
    vm.call(&warn, CallArgs::new(vec![Value::str("BaseException.message has been deprecated as of Python 2.6"), category, Value::Int(1)]))?;

    Ok(message)
}

/// The `BaseException.message` setter: assignments go to `__dict__`.
fn message_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let object = exception_object(vm, getset, instance)?;
    match value {
        Some(value) => {
            let dict = vm.instance_dict(object)?;
            vm.dict_set_str(&dict, "message", value)
        }
        None => {
            if let Some(dict) = object.dict() {
                vm.dict_delete(&dict, &Value::str("message"))?;
            }
            set_field(object, "message", None);
            Ok(())
        }
    }
}

/// An object or index member.
fn member_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let object = member_owner(vm, getset, instance)?;
    if matches!(getset.name, "start" | "end") {
        return Ok(Value::Int(size_field(vm, object, getset.name)));
    }

    Ok(field(object, getset.name).unwrap_or(Value::None))
}

fn member_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let object = member_owner(vm, getset, instance)?;
    let Some(name) = static_field(getset.name) else {
        return Err(vm.halt_unsupported("an exception member without a field"));
    };

    if matches!(name, "start" | "end") {
        let Some(value) = value else {
            return Err(vm.type_error("can't delete numeric/char attribute"));
        };
        // The -1 failure value is stored before raising.
        let number = match int_as_ssize(vm, &value) {
            Ok(number) => number,
            Err(signal) => {
                set_field(object, name, Some(Value::Int(-1)));
                return Err(signal);
            }
        };
        set_field(object, name, Some(Value::Int(number)));
        return Ok(());
    }

    set_field(object, name, value);

    Ok(())
}

/// The exception a member applies to: an instance of the member's class.
fn member_owner<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a ObjectRef> {
    let name = getset.owner.strip_prefix("exceptions.").unwrap_or(getset.owner);
    let kind = ExceptionKind::ALL.iter().copied().find(|kind| kind.name() == name).unwrap_or(ExceptionKind::BaseException);
    match instance {
        Value::Object(object) if matches!(object.payload, Payload::Exception(..)) && vm.is_instance_of(instance, &kind_class(vm, kind))? => Ok(object),
        _ => Err(descriptor_mismatch(vm, getset, instance)),
    }
}
