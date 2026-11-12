//! The concrete bases of the I/O ABCs, including the base parts of the
//! buffered and text layers. Their default methods work through the
//! methods a subclass provides.

use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::DEFAULT_BUFFER_SIZE;
use super::long_value;
use super::readinto_target;
use super::require_known;
use super::size_argument;
use super::slot_no_arguments;
use super::ssize_argument;
use super::unsupported;

/// The attribute `close` sets; its presence marks the stream closed.
const CLOSED_MARKER: &str = "__IOBase_closed";

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "_IOBase", Value::Object(iobase_type(vm)?))?;
    set_attribute(vm, module, "_RawIOBase", Value::Object(raw_base_type(vm)?))?;
    set_attribute(vm, module, "_BufferedIOBase", Value::Object(buffered_base_type(vm)?))?;
    set_attribute(vm, module, "_TextIOBase", Value::Object(text_base_type(vm)?))
}

pub fn iobase_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io._IOBase", create_iobase_type)
}

pub fn raw_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io._RawIOBase", create_raw_base_type)
}

pub fn buffered_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io._BufferedIOBase", create_buffered_base_type)
}

pub fn text_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io._TextIOBase", create_text_base_type)
}

fn create_iobase_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "_IOBase",
            module: "_io",
            base: None,
            layout: Layout::Object,
            instance_dict: true,
            methods: &[
                method("seek", iobase_seek),
                method("tell", iobase_tell),
                method("truncate", iobase_truncate),
                method("flush", iobase_flush),
                method("close", iobase_close),
                method("seekable", iobase_seekable),
                method("readable", iobase_readable),
                method("writable", iobase_writable),
                method("_checkClosed", iobase_check_closed),
                method("_checkSeekable", iobase_check_seekable),
                method("_checkReadable", iobase_check_readable),
                method("_checkWritable", iobase_check_writable),
                method("fileno", iobase_fileno),
                method("isatty", iobase_isatty),
                method("__enter__", iobase_enter),
                method("__exit__", iobase_exit),
                method("readline", iobase_readline),
                method("readlines", iobase_readlines),
                method("writelines", iobase_writelines),
                method("__iter__", iobase_iter),
                method("next", iobase_next),
            ],
        },
    )?;
    add_getset(vm, &class, GetSet { name: "closed", owner: "_io._IOBase", get: iobase_closed_get, set: None })?;

    Ok(class)
}

fn create_raw_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = iobase_type(vm)?;

    new_type(
        vm,
        TypeSpec {
            name: "_RawIOBase",
            module: "_io",
            base: Some(base),
            layout: Layout::Object,
            instance_dict: true,
            methods: &[method("read", raw_read), method("readall", raw_readall)],
        },
    )
}

fn create_buffered_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = iobase_type(vm)?;

    new_type(
        vm,
        TypeSpec {
            name: "_BufferedIOBase",
            module: "_io",
            base: Some(base),
            layout: Layout::Object,
            instance_dict: true,
            methods: &[
                method("detach", buffered_detach),
                method("read", |vm, args| varargs_unsupported(vm, &args, "read")),
                method("read1", |vm, args| varargs_unsupported(vm, &args, "read1")),
                method("readinto", buffered_readinto),
                method("write", |vm, args| varargs_unsupported(vm, &args, "write")),
            ],
        },
    )
}

fn create_text_base_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = iobase_type(vm)?;
    let class = new_type(
        vm,
        TypeSpec {
            name: "_TextIOBase",
            module: "_io",
            base: Some(base),
            layout: Layout::Object,
            instance_dict: true,
            methods: &[
                method("detach", text_detach),
                method("read", |vm, args| varargs_unsupported(vm, &args, "read")),
                method("readline", |vm, args| varargs_unsupported(vm, &args, "readline")),
                method("write", |vm, args| varargs_unsupported(vm, &args, "write")),
            ],
        },
    )?;

    for name in ["encoding", "newlines", "errors"] {
        add_getset(vm, &class, GetSet { name, owner: "_io._TextIOBase", get: text_attribute_get, set: None })?;
    }

    Ok(class)
}

/// The receiver of a method of the I/O bases.
fn receiver(vm: &Vm, args: &CallArgs, owner: &str, method: &str) -> PyResult<Value> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{owner}' object needs an argument")));
    };
    require_known(receiver, method)?;

    Ok(receiver.clone())
}

/// An attribute presence check that treats any exception as absence.
fn has_attribute(vm: &Vm, target: &Value, name: &str) -> PyResult<bool> {
    match vm.getattr_opt(target, &PyBytes::from(name)) {
        Ok(found) => Ok(found.is_some()),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt),
    }
}

/// The `__IOBase_closed` attribute: the internal state `close` keeps, which subclasses may
/// report differently through `closed`.
fn is_marked_closed(vm: &Vm, target: &Value) -> PyResult<bool> {
    has_attribute(vm, target, CLOSED_MARKER)
}

fn closed_file(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on closed file.")
}

/// Consults the `closed` attribute.
fn check_closed(vm: &Vm, target: &Value) -> PyResult<()> {
    let closed = vm.getattr_str(target, "closed")?;
    require_known(&closed, "closed")?;
    if vm.truthy(&closed, "closed")? {
        return Err(closed_file(vm));
    }

    Ok(())
}

/// Rejects keywords as a varargs method does.
fn varargs_only(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    Ok(())
}

fn varargs_unsupported(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    varargs_only(vm, args, name)?;

    Err(unsupported(vm, name))
}

fn iobase_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    varargs_unsupported(vm, &args, "seek")
}

fn iobase_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "tell")?;
    method_no_arguments(vm, &args, "tell")?;

    vm.call_method(&target, "seek", vec![Value::Int(0), Value::Int(1)])
}

fn iobase_truncate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    varargs_unsupported(vm, &args, "truncate")
}

fn iobase_flush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "flush")?;
    method_no_arguments(vm, &args, "flush")?;

    if is_marked_closed(vm, &target)? {
        return Err(closed_file(vm));
    }

    Ok(Value::None)
}

/// `IOBase.close`: flushes, then marks the stream closed even when the
/// flush fails.
fn iobase_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "close")?;
    method_no_arguments(vm, &args, "close")?;

    if is_marked_closed(vm, &target)? {
        return Ok(Value::None);
    }

    let flushed = vm.call_method(&target, "flush", Vec::new());
    let marked = vm.setattr_str(&target, CLOSED_MARKER, Value::Bool(true));
    flushed?;
    marked?;

    Ok(Value::None)
}

fn iobase_seekable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._IOBase", "seekable")?;
    method_no_arguments(vm, &args, "seekable")?;

    Ok(Value::Bool(false))
}

fn iobase_readable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._IOBase", "readable")?;
    method_no_arguments(vm, &args, "readable")?;

    Ok(Value::Bool(false))
}

fn iobase_writable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._IOBase", "writable")?;
    method_no_arguments(vm, &args, "writable")?;

    Ok(Value::Bool(false))
}

fn iobase_check_closed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "_checkClosed")?;
    method_no_arguments(vm, &args, "_checkClosed")?;
    check_closed(vm, &target)?;

    Ok(Value::None)
}

/// The capability checks: the capability method must return `True`
/// itself.
fn check_capability(vm: &Vm, args: &CallArgs, method: &str, capability: &str, message: &str) -> PyResult<Value> {
    let target = receiver(vm, args, "_io._IOBase", method)?;
    method_no_arguments(vm, args, method)?;

    let result = vm.call_method(&target, capability, Vec::new())?;
    require_known(&result, capability)?;
    if !matches!(result, Value::Bool(true)) {
        return Err(vm.raise(ExceptionKind::IOError, message));
    }

    Ok(result)
}

fn iobase_check_seekable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    check_capability(vm, &args, "_checkSeekable", "seekable", "File or stream is not seekable.")
}

fn iobase_check_readable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    check_capability(vm, &args, "_checkReadable", "readable", "File or stream is not readable.")
}

fn iobase_check_writable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    check_capability(vm, &args, "_checkWritable", "writable", "File or stream is not writable.")
}

fn iobase_fileno(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._IOBase", "fileno")?;
    method_no_arguments(vm, &args, "fileno")?;

    Err(unsupported(vm, "fileno"))
}

fn iobase_isatty(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "isatty")?;
    method_no_arguments(vm, &args, "isatty")?;
    check_closed(vm, &target)?;

    Ok(Value::Bool(false))
}

fn iobase_enter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "__enter__")?;
    method_no_arguments(vm, &args, "__enter__")?;
    check_closed(vm, &target)?;

    Ok(target)
}

fn iobase_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "__exit__")?;
    varargs_only(vm, &args, "__exit__")?;

    vm.call_method(&target, "close", Vec::new())
}

/// `IOBase.readline`: reads one byte at a time, or up to the newline that
/// `peek` reveals.
fn iobase_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "readline")?;
    let rest = method_arguments(vm, &args, "readline", 0, 1)?;
    let limit = size_argument(vm, rest.first())?.filter(|limit| *limit >= 0);

    let has_peek = has_attribute(vm, &target, "peek")?;
    let mut buffer: Vec<u8> = Vec::new();
    while limit.is_none_or(|limit| i64::try_from(buffer.len()).is_ok_and(|length| length < limit)) {
        let mut read_ahead = 1;
        if has_peek {
            let peeked = vm.call_method(&target, "peek", vec![Value::Int(1)])?;
            require_known(&peeked, "peek result")?;
            let Some(peeked) = vm.as_str_bytes(&peeked) else {
                return Err(vm.raise(ExceptionKind::IOError, &format!("peek() should have returned a bytes object, not '{}'", vm.type_name(&peeked))));
            };
            let peeked = peeked.as_bytes();
            if !peeked.is_empty() {
                let window = match limit {
                    Some(limit) => &peeked[..peeked.len().min(usize::try_from(limit).unwrap_or(usize::MAX))],
                    None => peeked,
                };
                read_ahead = window.iter().position(|byte| *byte == b'\n').map_or(window.len(), |index| index + 1);
            }
        }

        let chunk = vm.call_method(&target, "read", vec![Value::Int(i64::try_from(read_ahead).unwrap_or(i64::MAX))])?;
        require_known(&chunk, "read result")?;
        let Some(chunk) = vm.as_str_bytes(&chunk) else {
            return Err(vm.raise(ExceptionKind::IOError, &format!("read() should have returned a bytes object, not '{}'", vm.type_name(&chunk))));
        };
        if chunk.as_bytes().is_empty() {
            break;
        }
        buffer.extend_from_slice(chunk.as_bytes());
        if buffer.last() == Some(&b'\n') {
            break;
        }
    }

    Ok(Value::Str(PyBytes::new(buffer)))
}

/// The length of a line.
fn line_length(vm: &Vm, line: &Value) -> PyResult<usize> {
    require_known(line, "line length")?;

    match vm.len(line)? {
        Some(length) => Ok(length),
        None => Err(vm.type_error(&format!("object of type '{}' has no len()", vm.type_name(line)))),
    }
}

fn iobase_readlines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "readlines")?;
    let rest = method_arguments(vm, &args, "readlines", 0, 1)?;
    let hint = size_argument(vm, rest.first())?.filter(|hint| *hint > 0);

    let Some(hint) = hint else {
        return Ok(vm.new_list(vm.collect(&target)?));
    };

    let iterator = vm.iter(&target)?;
    let mut lines = Vec::new();
    let mut total: i64 = 0;
    while let Some(line) = vm.next(&iterator)? {
        let length = line_length(vm, &line)?;
        lines.push(line);
        let length = i64::try_from(length).unwrap_or(i64::MAX);
        if length > hint - total {
            break;
        }
        total += length;
    }

    Ok(vm.new_list(lines))
}

fn iobase_writelines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "writelines")?;
    let rest = method_arguments(vm, &args, "writelines", 1, 1)?;
    check_closed(vm, &target)?;

    let iterator = vm.iter(&rest[0])?;
    while let Some(line) = vm.next(&iterator)? {
        vm.call_method(&target, "write", vec![line])?;
    }

    Ok(Value::None)
}

fn iobase_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "__iter__")?;
    slot_no_arguments(vm, &args, "__iter__")?;
    check_closed(vm, &target)?;

    Ok(target)
}

fn iobase_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._IOBase", "next")?;
    slot_no_arguments(vm, &args, "next")?;

    let line = vm.call_method(&target, "readline", Vec::new())?;
    if line_length(vm, &line)? == 0 {
        return Err(stop_iteration(vm));
    }

    Ok(line)
}

/// Checks that a computed attribute of an I/O base applies to `instance`.
fn getset_receiver(vm: &Vm, getset: &GetSet, instance: &Value, class: &ObjectRef) -> PyResult<()> {
    require_known(instance, getset.name)?;
    if vm.is_instance_of(instance, class)? {
        return Ok(());
    }

    Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

fn iobase_closed_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    getset_receiver(vm, getset, instance, &iobase_type(vm)?)?;

    Ok(Value::Bool(is_marked_closed(vm, instance)?))
}

/// `encoding`, `newlines`, and `errors` of `_TextIOBase`, which subclasses
/// override.
fn text_attribute_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    getset_receiver(vm, getset, instance, &text_base_type(vm)?)?;

    Ok(Value::None)
}

/// `RawIOBase.read`: a negative size reads everything; other sizes read
/// into a `bytearray`, which the interpreter does not model.
fn raw_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._RawIOBase", "read")?;
    let rest = method_arguments(vm, &args, "read", 0, 1)?;
    let size = match rest.first() {
        Some(size) => ssize_argument(vm, size)?,
        None => -1,
    };

    if size < 0 {
        return vm.call_method(&target, "readall", Vec::new());
    }

    let size = usize::try_from(size).unwrap_or(0);
    let buffer = vm.new_bytearray(vec![0; size]);
    let result = vm.call_method(&target, "readinto", vec![buffer.clone()])?;
    require_known(&result, "readinto result")?;
    if result.is_none() {
        return Ok(Value::None);
    }

    let count = index_or_value_error(vm, &result)?;
    let Ok(count) = usize::try_from(count) else {
        return Err(vm.raise(ExceptionKind::SystemError, "Negative size passed to PyString_FromStringAndSize"));
    };
    let mut bytes = vm.as_bytearray(&buffer).unwrap_or_default();
    bytes.truncate(count);

    Ok(Value::Str(PyBytes::new(bytes)))
}

/// A `ssize_t` conversion that reports overflow as ValueError.
fn index_or_value_error(vm: &Vm, value: &Value) -> PyResult<i64> {
    match index_value(vm, value) {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::OverflowError) => {
            Err(vm.raise(ExceptionKind::ValueError, &format!("cannot fit '{}' into an index-sized integer", vm.type_name(value))))
        }
        result => result,
    }
}

fn raw_readall(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._RawIOBase", "readall")?;
    method_no_arguments(vm, &args, "readall")?;

    let mut chunks: Vec<u8> = Vec::new();
    let mut any = false;
    loop {
        let data = vm.call_method(&target, "read", vec![Value::Int(DEFAULT_BUFFER_SIZE)])?;
        require_known(&data, "read result")?;
        if data.is_none() {
            if !any {
                return Ok(Value::None);
            }
            break;
        }
        let Some(bytes) = vm.as_str_bytes(&data) else {
            return Err(vm.type_error("read() should return bytes"));
        };
        if bytes.as_bytes().is_empty() {
            break;
        }
        chunks.extend_from_slice(bytes.as_bytes());
        any = true;
    }

    Ok(Value::Str(PyBytes::new(chunks)))
}

fn buffered_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._BufferedIOBase", "detach")?;
    method_no_arguments(vm, &args, "detach")?;

    Err(unsupported(vm, "detach"))
}

/// `BufferedIOBase.readinto`: `read` the buffer's length and copy it in.
fn buffered_readinto(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let target = receiver(vm, &args, "_io._BufferedIOBase", "readinto")?;
    let buffer = readinto_target(vm, &args, Some("readinto"))?;

    let data = vm.call_method(&target, "read", vec![Value::Int(i64::try_from(buffer.len()).unwrap_or(i64::MAX))])?;
    require_known(&data, "read result")?;
    let Some(data) = vm.as_str_bytes(&data) else {
        return Err(vm.type_error("read() should return bytes"));
    };
    buffer.write(0, data.as_bytes());

    Ok(long_value(data.as_bytes().len()))
}

fn text_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_io._TextIOBase", "detach")?;
    method_no_arguments(vm, &args, "detach")?;

    Err(unsupported(vm, "detach"))
}
