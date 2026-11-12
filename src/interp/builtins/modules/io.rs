//! `_io`. The abstract bases, `BytesIO`, `StringIO`, and
//! `IncrementalNewlineDecoder` work in memory. Streams over files exist as
//! classes; opening one depends on the host, so it yields an unknown value.

mod bytesio;
mod buffered;
mod fileio;
mod iobase;
mod newline;
mod stringio;
mod textio;

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::containers::memoryview::WritableBuffer;
use crate::interp::builtins::containers::memoryview::writable_buffer;
use crate::interp::builtins::function;
use crate::interp::builtins::install;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::codecs::args::c_int;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::args::first_unknown;
use crate::interp::builtins::modules::codecs::args::optional_string;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::parse;
use crate::interp::builtins::set_attribute;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `DEFAULT_BUFFER_SIZE`.
const DEFAULT_BUFFER_SIZE: i64 = 8192;

/// Classes `_io` creates at import that its methods raise.
#[derive(Default)]
struct IoState {
    unsupported_operation: RefCell<Option<ObjectRef>>,
    blocking_io_error: RefCell<Option<ObjectRef>>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("open", open)])?;
    set_attribute(vm, module, "DEFAULT_BUFFER_SIZE", Value::Int(DEFAULT_BUFFER_SIZE))?;

    // A heap type built at import, so its `__module__` names the importer.
    let bases = Value::tuple(vec![Value::Object(Rc::clone(vm.types().exception(ExceptionKind::ValueError))), Value::Object(Rc::clone(vm.types().exception(ExceptionKind::IOError)))]);
    let unsupported = vm.type_new(&vm.types().type_, &Value::str("UnsupportedOperation"), &bases, &Value::Object(vm.new_dict()))?;
    let Value::Object(unsupported_class) = &unsupported else {
        return Err(vm.type_error("UnsupportedOperation creation failed"));
    };
    *vm.native_state::<IoState>().unsupported_operation.borrow_mut() = Some(Rc::clone(unsupported_class));
    set_attribute(vm, module, "UnsupportedOperation", unsupported)?;

    let blocking = new_exception_class(vm, "__builtin__", "BlockingIOError", vm.types().exception(ExceptionKind::IOError))?;
    install(vm, &blocking, &[method("__init__", blocking_io_error_init)])?;
    *vm.native_state::<IoState>().blocking_io_error.borrow_mut() = Some(Rc::clone(&blocking));
    set_attribute(vm, module, "BlockingIOError", Value::Object(blocking))?;

    iobase::init(vm, module)?;
    fileio::init(vm, module)?;
    buffered::init(vm, module)?;
    textio::init(vm, module)?;
    set_attribute(vm, module, "BytesIO", Value::Object(bytesio::bytes_io_type(vm)?))?;
    set_attribute(vm, module, "StringIO", Value::Object(stringio::string_io_type(vm)?))?;

    set_attribute(vm, module, "IncrementalNewlineDecoder", Value::Object(newline::decoder_type(vm)?))
}

/// `BlockingIOError.__init__`: `IOError` arguments plus the count of characters
/// written before blocking.
fn blocking_io_error_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(receiver) = args.positional.first().cloned() else {
        return Err(vm.type_error("descriptor '__init__' of 'BlockingIOError' object needs an argument"));
    };
    let rest: Vec<Value> = args.positional[1..].to_vec();
    if rest.len() < 2 || rest.len() > 3 {
        let (bound, count) = if rest.len() < 2 { ("at least", 2) } else { ("at most", 3) };
        return Err(vm.type_error(&format!("BlockingIOError() takes {bound} {count} arguments ({} given)", rest.len())));
    }

    let written = match rest.get(2) {
        Some(value) => ssize_argument(vm, value)?,
        None => 0,
    };

    let base_init = vm.getattr_str(&Value::Object(Rc::clone(vm.types().exception(ExceptionKind::IOError))), "__init__")?;
    vm.call(&base_init, CallArgs { positional: vec![receiver.clone(), rest[0].clone(), rest[1].clone()], keywords: args.keywords, keyword_dict: args.keyword_dict })?;
    vm.setattr_str(&receiver, "characters_written", Value::Int(written))?;

    Ok(Value::None)
}

/// `io.open`. The arguments are checked as CPython checks them before it
/// opens the file; the stream itself depends on the host.
fn open(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse(vm, args, "open", &["file", "mode", "buffering", "encoding", "errors", "newline", "closefd"], 0)?;
    let given: Vec<Value> = slots.iter().flatten().cloned().collect();
    if first_unknown(&given).is_some() {
        return vm.host_operation_on(HostCapability::FileSystem, "_io.open", Denial::Crt, None);
    }

    let Some(file) = &slots[0] else {
        return Err(missing_argument(vm, "file", 1));
    };
    let mode = match &slots[1] {
        Some(mode) => c_string(vm, "open", 2, mode)?,
        None => PyBytes::from("r"),
    };
    if let Some(buffering) = &slots[2] {
        c_int(vm, buffering)?;
    }
    let encoding = optional_string(vm, "open", 4, slots[3].as_ref())?;
    let errors = optional_string(vm, "open", 5, slots[4].as_ref())?;
    let newline = optional_string(vm, "open", 6, slots[5].as_ref())?;
    let closefd = match &slots[6] {
        Some(closefd) => c_int(vm, closefd)? != 0,
        None => true,
    };

    let is_file = vm.as_text(file).is_some() || vm.as_str_bytes(file).is_some() || is_number(vm, file)?;
    if !is_file {
        let repr = vm.repr_text(file)?;
        return Err(vm.type_error(&format!("invalid file: {repr}")));
    }

    let mode = OpenMode::parse(vm, mode.as_bytes())?;
    if mode.binary && encoding.is_some() {
        return Err(vm.raise(ExceptionKind::ValueError, "binary mode doesn't take an encoding argument"));
    }
    if mode.binary && errors.is_some() {
        return Err(vm.raise(ExceptionKind::ValueError, "binary mode doesn't take an errors argument"));
    }
    if mode.binary && newline.is_some() {
        return Err(vm.raise(ExceptionKind::ValueError, "binary mode doesn't take a newline argument"));
    }
    fileio::check_file_arguments(vm, file, &mode.raw, closefd)?;

    let filename = (!is_number(vm, file)?).then_some(file);
    vm.host_operation_on(HostCapability::FileSystem, "_io.open", Denial::Crt, filename)
}

/// The mode letters of `io.open` after validation.
struct OpenMode {
    binary: bool,
    /// The mode of the underlying `FileIO`.
    raw: Vec<u8>,
}

impl OpenMode {
    fn parse(vm: &Vm, mode: &[u8]) -> PyResult<Self> {
        let invalid = || vm.raise(ExceptionKind::ValueError, &format!("invalid mode: '{}'", String::from_utf8_lossy(mode)));

        let mut reading = false;
        let mut writing = false;
        let mut appending = false;
        let mut updating = false;
        let mut text = false;
        let mut binary = false;
        let mut universal = false;
        for (index, letter) in mode.iter().enumerate() {
            match letter {
                b'r' => reading = true,
                b'w' => writing = true,
                b'a' => appending = true,
                b't' => text = true,
                b'+' => updating = true,
                b'b' => binary = true,
                b'U' => {
                    universal = true;
                    reading = true;
                }
                _ => return Err(invalid()),
            }
            if mode[index + 1..].contains(letter) {
                return Err(invalid());
            }
        }

        if universal && (writing || appending) {
            return Err(vm.raise(ExceptionKind::ValueError, "can't use U and writing mode at once"));
        }
        if text && binary {
            return Err(vm.raise(ExceptionKind::ValueError, "can't have text and binary mode at once"));
        }
        if u8::from(reading) + u8::from(writing) + u8::from(appending) > 1 {
            return Err(vm.raise(ExceptionKind::ValueError, "must have exactly one of read/write/append mode"));
        }

        let raw = [(reading, b'r'), (writing, b'w'), (appending, b'a'), (updating, b'+')].into_iter().filter(|(present, _)| *present).map(|(_, letter)| letter).collect();

        Ok(Self { binary, raw })
    }
}

/// `UnsupportedOperation(message)`.
fn unsupported(vm: &Vm, message: &str) -> Signal {
    let class = vm.native_state::<IoState>().unsupported_operation.borrow().clone();
    let Some(class) = class else {
        return vm.raise(ExceptionKind::ValueError, message);
    };

    vm.raise_string(&class, Value::str(message))
}

/// The argument parsing error for a missing required argument.
fn missing_argument(vm: &Vm, name: &str, position: usize) -> Signal {
    vm.type_error(&format!("Required argument '{name}' (pos {position}) not found"))
}

/// Halts when `value` is unknown: the result would depend on it.
fn require_known(value: &Value, context: &str) -> PyResult<()> {
    let Value::Unknown(unknown) = value else {
        return Ok(());
    };

    Err(Signal::Halt(Halt::UnknownCondition { context: context.to_owned(), origin: unknown.origin.clone() }))
}

/// Whether a value is a number or an object that converts to one.
fn is_number(vm: &Vm, value: &Value) -> PyResult<bool> {
    if value.is_unknown() || vm.is_number(value) {
        return Ok(true);
    }

    Ok(vm.user_override(value, "__int__")?.is_some() || vm.user_override(value, "__float__")?.is_some())
}

/// Whether a value supports `__index__`; an unknown value passes so its
/// conversion halts.
fn is_index(vm: &Vm, value: &Value) -> PyResult<bool> {
    Ok(value.is_unknown() || vm.is_index(value)?)
}

/// A size or limit argument as the `_io` size parsers read it: `None` when
/// absent or `None`.
fn size_argument(vm: &Vm, value: Option<&Value>) -> PyResult<Option<i64>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };
    if !is_number(vm, value)? {
        return Err(vm.type_error(&format!("integer argument expected, got '{}'", vm.type_name(value))));
    }

    index_value(vm, value).map(Some)
}

/// The `n` format unit.
fn ssize_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    crate::interp::builtins::arguments::ssize_argument(vm, value)
}

/// The `i` format unit.
fn int_argument(vm: &Vm, value: &Value, context: &str) -> PyResult<i32> {
    require_known(value, context)?;

    c_int(vm, value)
}

/// A `ssize_t` result, which is a `long` in Python 2.
fn long_value(value: usize) -> Value {
    Value::Long(Rc::new(value.into()))
}

/// The `w*` conversion of a `readinto` argument: a `bytearray` or a view
/// over one. `function` is `None` when the format names no function.
fn readinto_target(vm: &Vm, args: &CallArgs, function: Option<&str>) -> PyResult<WritableBuffer> {
    if args.has_keywords() {
        let name = function.unwrap_or("readinto");
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let given = args.positional.len().saturating_sub(1);
    let Some(buffer) = args.positional.get(1).filter(|_| given == 1) else {
        return Err(match function {
            Some(name) => vm.type_error(&format!("{name}() takes exactly 1 argument ({given} given)")),
            None => vm.type_error(&format!("function takes exactly 1 argument ({given} given)")),
        });
    };

    require_known(buffer, "readinto buffer")?;
    if let Some(target) = writable_buffer(buffer) {
        return Ok(target);
    }

    let prefix = function.map_or(String::new(), |name| format!("{name}() "));

    Err(vm.type_error(&format!("{prefix}argument 1 must be read-write buffer, not {}", vm.type_name(buffer))))
}

/// A contiguous read-only buffer as `BytesIO.write` and the buffered
/// writers request it.
fn buffer_argument(vm: &Vm, value: &Value) -> PyResult<PyBytes> {
    require_known(value, "buffer")?;
    if let Some(bytes) = vm.buffer(value, BufferInterface::New)? {
        return Ok(bytes);
    }

    Err(vm.type_error(&format!("'{}' does not have the buffer interface", vm.type_name(value))))
}

/// The arguments of a method call without its receiver, for keyword
/// parsing.
fn after_receiver(args: &CallArgs) -> CallArgs {
    CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() }
}

/// Rejects arguments to a method that stands for a type slot (`__iter__`,
/// `next`), with the messages of a slot wrapper.
fn slot_no_arguments(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("wrapper {name} doesn't take keyword arguments")));
    }
    let given = args.positional.len().saturating_sub(1);
    if given > 0 {
        return Err(vm.type_error(&format!("expected 0 arguments, got {given}")));
    }

    Ok(())
}

/// The class argument of a native `__new__`, which must derive from
/// `native`.
pub(super) fn allocation_class(vm: &Vm, args: &CallArgs, native: &ObjectRef) -> PyResult<ObjectRef> {
    let name = vm.class_name(native);
    let Some(first) = args.positional.first() else {
        return Err(vm.type_error(&format!("{name}.__new__(): not enough arguments")));
    };
    let Value::Object(class) = first.clone() else {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    };
    if class.as_class().is_none() {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    }
    if !vm.is_subclass(&class, native)? {
        let given = vm.class_name(&class);
        return Err(vm.type_error(&format!("{name}.__new__({given}): {given} is not a subtype of {name}")));
    }

    Ok(class)
}
