//! `_io.BytesIO`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::after_receiver;
use super::allocation_class;
use super::buffer_argument;
use super::int_argument;
use super::iobase::buffered_base_type;
use super::is_index;
use super::long_value;
use super::readinto_target;
use super::require_known;
use super::size_argument;

/// `sizeof(bytesio)` on 64-bit builds.
const BASIC_SIZE: usize = 64;

/// The largest buffer the interpreter builds. CPython would allocate more;
/// whether that succeeds depends on host memory.
const MAX_BUFFER: usize = 1 << 31;

struct BytesIo {
    state: RefCell<State>,
}

impl_native_data!(BytesIo, "_io.BytesIO");

struct State {
    /// `None` once closed.
    content: Option<Vec<u8>>,
    /// May lie past the end after a seek.
    position: usize,
    /// The tracked allocation size, which `__sizeof__`
    /// reports.
    allocated: usize,
}

impl State {
    fn content(&self, vm: &Vm) -> PyResult<&Vec<u8>> {
        self.content.as_ref().ok_or_else(|| closed_file(vm))
    }

    /// The growth policy CPython applies to the allocation.
    fn resize(&mut self, size: usize) {
        let allocated = self.allocated;
        self.allocated = if size < allocated / 2 {
            size + 1
        } else if size < allocated {
            allocated
        } else if size as f64 <= allocated as f64 * 1.125 {
            size + (size >> 3) + if size < 9 { 3 } else { 6 }
        } else {
            size + 1
        };
    }

    /// Writes at the position, padding an overseek with NULs.
    fn write(&mut self, vm: &Vm, data: &[u8]) -> PyResult<()> {
        let Some(end) = self.position.checked_add(data.len()).filter(|end| *end <= MAX_BUFFER) else {
            return Err(vm.halt_unsupported("BytesIO write past 2 GiB"));
        };
        if end > self.allocated {
            self.resize(end);
        }

        let position = self.position;
        let content = self.content.as_mut().ok_or_else(|| closed_file(vm))?;
        if content.len() < end {
            content.resize(end, 0);
        }
        content[position..end].copy_from_slice(data);
        self.position = end;

        Ok(())
    }

    /// One line: the bytes through the next newline, advancing past them.
    fn line(&mut self, vm: &Vm) -> PyResult<Vec<u8>> {
        let position = self.position;
        let rest = self.content(vm)?.get(position..).unwrap_or_default();
        let length = rest.iter().position(|byte| *byte == b'\n').map_or(rest.len(), |index| index + 1);
        let line = rest[..length].to_vec();
        self.position += length;

        Ok(line)
    }
}

pub fn bytes_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io.BytesIO", create_bytes_io_type)
}

fn create_bytes_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = buffered_base_type(vm)?;
    let class = new_type(
        vm,
        TypeSpec {
            name: "BytesIO",
            module: "_io",
            base: Some(base),
            layout: Layout::Native,
            instance_dict: true,
            methods: &[
                static_method("__new__", bytes_io_new),
                method("__init__", bytes_io_init),
                method("readable", bytes_io_readable),
                method("seekable", bytes_io_seekable),
                method("writable", bytes_io_writable),
                method("close", bytes_io_close),
                method("flush", bytes_io_flush),
                method("isatty", bytes_io_isatty),
                method("tell", bytes_io_tell),
                method("write", bytes_io_write),
                method("writelines", bytes_io_writelines),
                method("read1", bytes_io_read1),
                method("readinto", bytes_io_readinto),
                method("readline", bytes_io_readline),
                method("readlines", bytes_io_readlines),
                method("read", bytes_io_read),
                method("getvalue", bytes_io_getvalue),
                method("seek", bytes_io_seek),
                method("truncate", bytes_io_truncate),
                method("__getstate__", bytes_io_getstate),
                method("__setstate__", bytes_io_setstate),
                method("__sizeof__", bytes_io_sizeof),
                method("__iter__", bytes_io_iter),
                method("next", bytes_io_next),
            ],
        },
    )?;
    add_getset(vm, &class, GetSet { name: "closed", owner: "_io.BytesIO", get: bytes_io_closed, set: None })?;

    Ok(class)
}

fn closed_file(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on closed file.")
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a BytesIo> {
    this::<BytesIo>(vm, args, "_io.BytesIO", method)
}

/// The receiver of a method that first checks the stream is open
/// (raising `ValueError` when closed).
fn open_receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a BytesIo> {
    let stream = receiver(vm, args, method)?;
    stream.state.borrow().content(vm)?;

    Ok(stream)
}

/// The receiver of a no-argument method that checks the stream is open.
fn open_noargs<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a BytesIo> {
    let stream = receiver(vm, args, method)?;
    method_no_arguments(vm, args, method)?;
    stream.state.borrow().content(vm)?;

    Ok(stream)
}

fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Str(PyBytes::new(bytes))
}

/// `BytesIO.write` once the stream is known to be open.
fn write_value(vm: &Vm, stream: &BytesIo, value: &Value) -> PyResult<usize> {
    stream.state.borrow().content(vm)?;

    let data = buffer_argument(vm, value)?;
    let data = data.as_bytes();
    if !data.is_empty() {
        stream.state.borrow_mut().write(vm, data)?;
    }

    Ok(data.len())
}

fn bytes_io_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &bytes_io_type(vm)?)?;

    Ok(new_native_object(vm, &class, BytesIo { state: RefCell::new(State { content: Some(Vec::new()), position: 0, allocated: 0 }) }))
}

fn bytes_io_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__init__")?;
    let slots = parse(vm, after_receiver(&args), "BytesIO", &["initial_bytes"], 0)?;

    {
        let mut state = stream.state.borrow_mut();
        state.position = 0;
        if let Some(content) = state.content.as_mut() {
            content.clear();
        }
    }

    let Some(initial) = slots[0].as_ref().filter(|initial| !initial.is_none()) else {
        return Ok(Value::None);
    };
    write_value(vm, stream, initial)?;
    stream.state.borrow_mut().position = 0;

    Ok(Value::None)
}

/// The check shared by `readable`, `seekable`, and `writable`.
fn capable(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<Value> {
    open_noargs(vm, args, method)?;

    Ok(Value::Bool(true))
}

fn bytes_io_readable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capable(vm, &args, "readable")
}

fn bytes_io_seekable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capable(vm, &args, "seekable")
}

fn bytes_io_writable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capable(vm, &args, "writable")
}

fn bytes_io_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "close")?;
    method_no_arguments(vm, &args, "close")?;

    stream.state.borrow_mut().content = None;

    Ok(Value::None)
}

fn bytes_io_flush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    open_noargs(vm, &args, "flush")?;

    Ok(Value::None)
}

fn bytes_io_isatty(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    open_noargs(vm, &args, "isatty")?;

    Ok(Value::Bool(false))
}

fn bytes_io_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_noargs(vm, &args, "tell")?;

    Ok(long_value(stream.state.borrow().position))
}

/// `BytesIO.read`: up to `size` bytes, all remaining when negative.
fn read_bytes(vm: &Vm, stream: &BytesIo, size: Option<i64>) -> PyResult<Value> {
    let mut state = stream.state.borrow_mut();
    let position = state.position;
    let rest = state.content(vm)?.get(position..).unwrap_or_default();
    let count = match size.and_then(|size| usize::try_from(size).ok()) {
        Some(size) => size.min(rest.len()),
        None => rest.len(),
    };
    let bytes = rest[..count].to_vec();
    state.position += count;

    Ok(bytes_value(bytes))
}

fn bytes_io_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "read")?;
    let rest = method_arguments(vm, &args, "read", 0, 1)?;
    let size = size_argument(vm, rest.first())?;

    read_bytes(vm, stream, size)
}

fn bytes_io_read1(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "read1")?;
    let size = method_one_argument(vm, &args, "read1")?;
    stream.state.borrow().content(vm)?;
    let size = size_argument(vm, Some(&size))?;

    read_bytes(vm, stream, size)
}

fn bytes_io_readinto(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "readinto")?;
    let target = readinto_target(vm, &args, None)?;

    let mut state = stream.state.borrow_mut();
    let position = state.position;
    let rest = state.content(vm)?.get(position..).unwrap_or_default();
    let count = target.len().min(rest.len());
    target.write(0, &rest[..count]);
    state.position += count;

    Ok(long_value(count))
}

fn bytes_io_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "readline")?;
    let rest = method_arguments(vm, &args, "readline", 0, 1)?;
    let size = size_argument(vm, rest.first())?;

    let mut state = stream.state.borrow_mut();
    let mut line = state.line(vm)?;
    if let Some(size) = size.and_then(|size| usize::try_from(size).ok()).filter(|size| *size < line.len()) {
        state.position -= line.len() - size;
        line.truncate(size);
    }

    Ok(bytes_value(line))
}

fn bytes_io_readlines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "readlines")?;
    let rest = method_arguments(vm, &args, "readlines", 0, 1)?;
    let hint = size_argument(vm, rest.first())?.and_then(|hint| usize::try_from(hint).ok()).filter(|hint| *hint > 0);

    let mut state = stream.state.borrow_mut();
    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let line = state.line(vm)?;
        if line.is_empty() {
            break;
        }
        total += line.len();
        lines.push(bytes_value(line));
        if hint.is_some_and(|hint| total >= hint) {
            break;
        }
    }
    drop(state);

    Ok(vm.new_list(lines))
}

fn bytes_io_getvalue(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_noargs(vm, &args, "getvalue")?;

    Ok(bytes_value(stream.state.borrow().content(vm)?.clone()))
}

fn bytes_io_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "seek")?;
    let rest = method_arguments(vm, &args, "seek", 1, 2)?;
    let whence = match rest.get(1) {
        Some(whence) => int_argument(vm, whence, "BytesIO.seek whence")?,
        None => 0,
    };
    let offset = index_value(vm, &rest[0])?;

    if offset < 0 && whence == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("negative seek value {offset}")));
    }

    let mut state = stream.state.borrow_mut();
    let base = match whence {
        0 => 0,
        1 => state.position,
        2 => state.content(vm)?.len(),
        _ => return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid whence ({whence}, should be 0, 1 or 2)"))),
    };
    let base = i64::try_from(base).unwrap_or(i64::MAX);
    let Some(target) = base.checked_add(offset) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "new position too large"));
    };
    state.position = usize::try_from(target.max(0)).unwrap_or(0);

    Ok(long_value(state.position))
}

fn bytes_io_truncate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_receiver(vm, &args, "truncate")?;
    let rest = method_arguments(vm, &args, "truncate", 0, 1)?;
    let size = size_argument(vm, rest.first())?;

    let mut state = stream.state.borrow_mut();
    let size = match size {
        Some(size) if size < 0 => return Err(vm.raise(ExceptionKind::ValueError, &format!("negative size value {size}"))),
        Some(size) => usize::try_from(size).unwrap_or(usize::MAX),
        None => state.position,
    };
    if size < state.content(vm)?.len() {
        if let Some(content) = state.content.as_mut() {
            content.truncate(size);
        }
        state.resize(size);
    }

    Ok(long_value(size))
}

fn bytes_io_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "write")?;
    let data = method_one_argument(vm, &args, "write")?;

    Ok(long_value(write_value(vm, stream, &data)?))
}

fn bytes_io_writelines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "writelines")?;
    let lines = method_one_argument(vm, &args, "writelines")?;
    stream.state.borrow().content(vm)?;

    let iterator = vm.iter(&lines)?;
    while let Some(line) = vm.next(&iterator)? {
        write_value(vm, stream, &line)?;
    }

    Ok(Value::None)
}

fn bytes_io_getstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_noargs(vm, &args, "__getstate__")?;

    let (content, position) = {
        let state = stream.state.borrow();
        (state.content(vm)?.clone(), state.position)
    };
    let dict = match args.positional[0].as_object().and_then(|object| object.dict()) {
        Some(dict) => Value::Object(vm.dict_copy(&dict)?),
        None => Value::None,
    };

    Ok(Value::tuple(vec![bytes_value(content), Value::Int(i64::try_from(position).unwrap_or(i64::MAX)), dict]))
}

fn bytes_io_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__setstate__")?;
    let state = method_one_argument(vm, &args, "__setstate__")?;
    let target = &args.positional[0];

    require_known(&state, "BytesIO state")?;
    let Some(items) = vm.as_tuple(&state).filter(|items| items.len() >= 3) else {
        return Err(vm.type_error(&format!("{}.__setstate__ argument should be 3-tuple, got {}", vm.type_name(target), vm.type_name(&state))));
    };

    {
        let mut current = stream.state.borrow_mut();
        current.position = 0;
        if let Some(content) = current.content.as_mut() {
            content.clear();
        }
    }
    write_value(vm, stream, &items[0])?;

    let position = &items[1];
    if !is_index(vm, position)? {
        return Err(vm.type_error(&format!("second item of state must be an integer, not {}", vm.type_name(position))));
    }
    let position = index_value(vm, position)?;
    let Ok(position) = usize::try_from(position) else {
        return Err(vm.raise(ExceptionKind::ValueError, "position value cannot be negative"));
    };
    stream.state.borrow_mut().position = position;

    let dict = &items[2];
    if dict.is_none() {
        return Ok(Value::None);
    }
    require_known(dict, "BytesIO state dict")?;
    let is_dict = matches!(dict, Value::Object(object) if object.as_dict().is_some());
    if !is_dict {
        return Err(vm.type_error(&format!("third item of state should be a dict, got a {}", vm.type_name(dict))));
    }
    let Some(object) = target.as_object() else {
        return Err(vm.type_error("BytesIO.__setstate__ requires an object"));
    };
    let instance_dict = vm.instance_dict(object)?;
    vm.dict_merge(&instance_dict, dict, true)?;

    Ok(Value::None)
}

fn bytes_io_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__sizeof__")?;
    method_no_arguments(vm, &args, "__sizeof__")?;

    let basic = instance_size(vm, &vm.class_of(&args.positional[0]))?;
    let state = stream.state.borrow();
    let buffer = if state.content.is_some() { state.allocated } else { 0 };

    Ok(long_value(basic + buffer))
}

/// The instance size of `class`: the `BytesIO` struct plus one pointer per
/// `__slots__` entry its subclasses add. `__dict__` and `__weakref__` add
/// nothing, since `BytesIO` already has both.
fn instance_size(vm: &Vm, class: &ObjectRef) -> PyResult<usize> {
    let native = bytes_io_type(vm)?;
    let Some(data) = class.as_class() else {
        return Ok(BASIC_SIZE);
    };

    let mut slots = 0;
    for entry in data.mro() {
        let MroEntry::Class(ancestor) = entry else {
            continue;
        };
        if Rc::ptr_eq(&ancestor, &native) {
            break;
        }
        let Some(ancestor_data) = ancestor.as_class() else {
            continue;
        };
        let Some(declared) = vm.dict_get_str(&ancestor_data.dict, "__slots__")? else {
            continue;
        };
        let names = if vm.as_str_bytes(&declared).is_some() || vm.as_text(&declared).is_some() { vec![declared] } else { vm.collect(&declared)? };
        slots += names.iter().filter(|name| !matches!(vm.text_of(name).as_deref(), Some("__dict__" | "__weakref__"))).count();
    }

    Ok(BASIC_SIZE + 8 * slots)
}

fn bytes_io_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "__iter__")?;
    method_no_arguments(vm, &args, "__iter__")?;

    Ok(args.positional[0].clone())
}

fn bytes_io_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = open_noargs(vm, &args, "next")?;

    let line = stream.state.borrow_mut().line(vm)?;
    if line.is_empty() {
        return Err(stop_iteration(vm));
    }

    Ok(bytes_value(line))
}

fn bytes_io_closed(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(stream) = native_data::<BytesIo>(instance) else {
        return Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))));
    };

    Ok(Value::Bool(stream.state.borrow().content.is_none()))
}
