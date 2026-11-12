//! `_io.StringIO`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args::optional_string;
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
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::after_receiver;
use super::allocation_class;
use super::int_argument;
use super::iobase::text_base_type;
use super::is_index;
use super::long_value;
use super::newline::LineEnding;
use super::newline::NewlineState;
use super::require_known;
use super::size_argument;

const LF: u16 = b'\n' as u16;

/// The largest buffer the interpreter builds, in code units. CPython would
/// allocate more; whether that succeeds depends on host memory.
const MAX_BUFFER: usize = 1 << 30;

struct StringIo {
    state: RefCell<State>,
}

impl_native_data!(StringIo, "_io.StringIO");

/// The stream before `__init__` ran (`ok == 0`) or after. `close` marks
/// even an uninitialized stream closed.
enum State {
    Uninitialized { closed: bool },
    Ready(Stream),
}

struct Stream {
    closed: bool,
    content: Vec<u16>,
    /// May lie past the end after a seek.
    position: usize,
    /// The `newline` argument; `None` for universal newlines with
    /// translation.
    newline: Option<PyBytes>,
    /// Translates and records line endings on write in universal mode.
    decoder: Option<NewlineState>,
    /// Replaces `\n` on write when `newline` starts with `\r`.
    write_newline: Option<Vec<u16>>,
}

impl Stream {
    fn line_ending(&self) -> LineEnding {
        match &self.newline {
            None => LineEnding::Translated,
            Some(newline) if newline.as_bytes().is_empty() => LineEnding::Universal,
            Some(newline) => LineEnding::Fixed(newline.as_bytes().iter().map(|byte| u16::from(*byte)).collect()),
        }
    }

    /// Translates line endings and writes at the position,
    /// padding an overseek with NULs.
    fn write(&mut self, vm: &Vm, text: &[u16]) -> PyResult<()> {
        let mut units = match self.decoder.as_mut() {
            Some(decoder) => decoder.decode(text.to_vec(), true),
            None => text.to_vec(),
        };
        if let Some(separator) = &self.write_newline {
            units = units.iter().flat_map(|unit| if *unit == LF { separator.clone() } else { vec![*unit] }).collect();
        }

        let Some(end) = self.position.checked_add(units.len()).filter(|end| *end <= MAX_BUFFER) else {
            return Err(vm.halt_unsupported("StringIO write past 1 Gi code units"));
        };
        if self.content.len() < end {
            self.content.resize(end, 0);
        }
        self.content[self.position..end].copy_from_slice(&units);
        self.position = end;

        Ok(())
    }

    /// Up to `limit` units through the next line
    /// ending.
    fn read_line(&mut self, limit: Option<usize>) -> Vec<u16> {
        let rest = self.content.get(self.position..).unwrap_or_default();
        let window = match limit {
            Some(limit) => &rest[..limit.min(rest.len())],
            None => rest,
        };
        let length = self.line_ending().line_length(window).unwrap_or(window.len());
        let line = window[..length].to_vec();
        self.position += length;

        line
    }
}

pub fn string_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io.StringIO", create_string_io_type)
}

fn create_string_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = text_base_type(vm)?;
    let class = new_type(
        vm,
        TypeSpec {
            name: "StringIO",
            module: "_io",
            base: Some(base),
            layout: Layout::Native,
            instance_dict: true,
            methods: &[
                static_method("__new__", string_io_new),
                method("__init__", string_io_init),
                method("close", string_io_close),
                method("getvalue", string_io_getvalue),
                method("read", string_io_read),
                method("readline", string_io_readline),
                method("tell", string_io_tell),
                method("truncate", string_io_truncate),
                method("seek", string_io_seek),
                method("write", string_io_write),
                method("seekable", string_io_seekable),
                method("readable", string_io_readable),
                method("writable", string_io_writable),
                method("__getstate__", string_io_getstate),
                method("__setstate__", string_io_setstate),
                method("next", string_io_next),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "closed", owner: "_io.StringIO", get: string_io_closed, set: None })?;
    add_getset(vm, &class, GetSet { name: "newlines", owner: "_io.StringIO", get: string_io_newlines, set: None })?;
    add_getset(vm, &class, GetSet { name: "line_buffering", owner: "_io.StringIO", get: string_io_line_buffering, set: None })?;

    Ok(class)
}

fn uninitialized(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on uninitialized object")
}

fn closed_file(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on closed file")
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a StringIo> {
    this::<StringIo>(vm, args, "_io.StringIO", method)
}

impl StringIo {
    /// `body` with the stream after the initialization check.
    fn initialized<R>(&self, vm: &Vm, body: impl FnOnce(&mut Stream) -> PyResult<R>) -> PyResult<R> {
        let mut state = self.state.borrow_mut();
        let State::Ready(stream) = &mut *state else {
            return Err(uninitialized(vm));
        };

        body(stream)
    }

    /// `body` with the stream after the initialization and closed checks.
    fn open<R>(&self, vm: &Vm, body: impl FnOnce(&mut Stream) -> PyResult<R>) -> PyResult<R> {
        self.initialized(vm, |stream| {
            if stream.closed {
                return Err(closed_file(vm));
            }

            body(stream)
        })
    }

    fn check_initialized(&self, vm: &Vm) -> PyResult<()> {
        self.initialized(vm, |_| Ok(()))
    }

    fn check_open(&self, vm: &Vm) -> PyResult<()> {
        self.open(vm, |_| Ok(()))
    }
}

fn text_value(units: Vec<u16>) -> Value {
    Value::Unicode(PyText::new(units))
}

fn string_io_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &string_io_type(vm)?)?;

    Ok(new_native_object(vm, &class, StringIo { state: RefCell::new(State::Uninitialized { closed: false }) }))
}

/// `StringIO.__init__` with its `initial_value` and `newline` arguments.
fn initialize(vm: &Vm, stream: &StringIo, value: Option<&Value>, newline: Option<&Value>) -> PyResult<()> {
    let newline = match newline {
        Some(newline) => {
            require_known(newline, "StringIO newline")?;
            optional_string(vm, "__init__", 2, Some(newline))?
        }
        None => Some(PyBytes::from("\n")),
    };
    if let Some(newline) = newline.as_ref().filter(|newline| !matches!(newline.as_bytes(), b"" | b"\n" | b"\r" | b"\r\n")) {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("illegal newline value: {}", newline.to_string_lossy())));
    }

    let value = value.filter(|value| !value.is_none());
    let initial = match value {
        Some(value) => {
            require_known(value, "StringIO initial value")?;
            let Some(text) = vm.as_text(value) else {
                return Err(vm.type_error(&format!("initial_value must be unicode or None, not {}", vm.type_name(value))));
            };
            Some(text)
        }
        None => None,
    };

    let universal = newline.as_ref().is_none_or(|newline| newline.as_bytes().is_empty());
    let translate = newline.is_none();
    let write_newline = newline.as_ref().filter(|newline| newline.as_bytes().first() == Some(&b'\r')).map(|newline| newline.as_bytes().iter().map(|byte| u16::from(*byte)).collect());
    let decoder = universal.then(|| NewlineState::new(translate));

    let mut ready = Stream { closed: false, content: Vec::new(), position: 0, newline, decoder, write_newline };
    if let Some(initial) = initial {
        ready.write(vm, initial.units())?;
    }
    ready.position = 0;
    *stream.state.borrow_mut() = State::Ready(ready);

    Ok(())
}

fn string_io_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__init__")?;
    let slots = parse(vm, after_receiver(&args), "__init__", &["initial_value", "newline"], 0)?;

    initialize(vm, stream, slots[0].as_ref(), slots[1].as_ref())?;

    Ok(Value::None)
}

fn string_io_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "close")?;
    method_no_arguments(vm, &args, "close")?;

    match &mut *stream.state.borrow_mut() {
        State::Uninitialized { closed } => *closed = true,
        State::Ready(ready) => {
            ready.closed = true;
            ready.content = Vec::new();
            ready.newline = None;
            ready.decoder = None;
            ready.write_newline = None;
        }
    }

    Ok(Value::None)
}

fn string_io_getvalue(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "getvalue")?;
    method_no_arguments(vm, &args, "getvalue")?;

    stream.open(vm, |ready| Ok(text_value(ready.content.clone())))
}

fn string_io_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "tell")?;
    method_no_arguments(vm, &args, "tell")?;

    stream.open(vm, |ready| Ok(long_value(ready.position)))
}

fn string_io_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "read")?;
    stream.check_initialized(vm)?;
    let rest = method_arguments(vm, &args, "read", 0, 1)?;
    stream.check_open(vm)?;
    let size = size_argument(vm, rest.first())?;

    stream.open(vm, |ready| {
        let rest = ready.content.get(ready.position..).unwrap_or_default();
        let count = match size.and_then(|size| usize::try_from(size).ok()) {
            Some(size) => size.min(rest.len()),
            None => rest.len(),
        };
        let units = rest[..count].to_vec();
        ready.position += count;

        Ok(text_value(units))
    })
}

fn string_io_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "readline")?;
    stream.check_initialized(vm)?;
    let rest = method_arguments(vm, &args, "readline", 0, 1)?;
    stream.check_open(vm)?;
    let limit = size_argument(vm, rest.first())?.and_then(|limit| usize::try_from(limit).ok());

    stream.open(vm, |ready| Ok(text_value(ready.read_line(limit))))
}

fn string_io_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "next")?;
    method_no_arguments(vm, &args, "next")?;
    stream.check_open(vm)?;

    let target = &args.positional[0];
    let exact = Rc::ptr_eq(&vm.class_of(target), &string_io_type(vm)?);
    let line = if exact {
        stream.open(vm, |ready| Ok(ready.read_line(None)))?
    } else {
        let line = vm.call_method(target, "readline", Vec::new())?;
        require_known(&line, "StringIO readline result")?;
        let Some(text) = vm.as_text(&line) else {
            return Err(vm.raise(ExceptionKind::IOError, &format!("readline() should have returned an str object, not '{}'", vm.type_name(&line))));
        };
        text.units().to_vec()
    };

    if line.is_empty() {
        return Err(stop_iteration(vm));
    }

    Ok(text_value(line))
}

fn string_io_truncate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "truncate")?;
    stream.check_initialized(vm)?;
    let rest = method_arguments(vm, &args, "truncate", 0, 1)?;
    stream.check_open(vm)?;
    let size = size_argument(vm, rest.first())?;

    stream.open(vm, |ready| {
        let size = match size {
            Some(size) if size < 0 => return Err(vm.raise(ExceptionKind::ValueError, &format!("Negative size value {size}"))),
            Some(size) => usize::try_from(size).unwrap_or(usize::MAX),
            None => ready.position,
        };
        ready.content.truncate(size);

        Ok(long_value(size))
    })
}

fn string_io_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "seek")?;
    stream.check_initialized(vm)?;
    let rest = method_arguments(vm, &args, "seek", 1, 2)?;
    let whence = match rest.get(1) {
        Some(whence) => int_argument(vm, whence, "StringIO.seek whence")?,
        None => 0,
    };
    let offset = index_value(vm, &rest[0])?;
    stream.check_open(vm)?;

    if !(0..=2).contains(&whence) {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("Invalid whence ({whence}, should be 0, 1 or 2)")));
    }
    if offset < 0 && whence == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("Negative seek position {offset}")));
    }
    if whence != 0 && offset != 0 {
        return Err(vm.raise(ExceptionKind::IOError, "Can't do nonzero cur-relative seeks"));
    }

    stream.open(vm, |ready| {
        ready.position = match whence {
            0 => usize::try_from(offset).unwrap_or(usize::MAX),
            1 => ready.position,
            _ => ready.content.len(),
        };

        Ok(long_value(ready.position))
    })
}

fn string_io_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "write")?;
    let text = method_one_argument(vm, &args, "write")?;
    stream.check_initialized(vm)?;

    require_known(&text, "StringIO data")?;
    let Some(text) = vm.as_text(&text) else {
        return Err(vm.type_error(&format!("unicode argument expected, got '{}'", vm.type_name(&text))));
    };

    stream.open(vm, |ready| {
        let units = text.units();
        if !units.is_empty() {
            ready.write(vm, units)?;
        }

        Ok(long_value(units.len()))
    })
}

fn capability(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<Value> {
    let stream = receiver(vm, args, method)?;
    method_no_arguments(vm, args, method)?;
    stream.check_open(vm)?;

    Ok(Value::Bool(true))
}

fn string_io_seekable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capability(vm, &args, "seekable")
}

fn string_io_readable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capability(vm, &args, "readable")
}

fn string_io_writable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    capability(vm, &args, "writable")
}

fn string_io_getstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__getstate__")?;
    method_no_arguments(vm, &args, "__getstate__")?;

    let (content, newline, position) = stream.open(vm, |ready| Ok((ready.content.clone(), ready.newline.clone(), ready.position)))?;
    let dict = match args.positional[0].as_object().and_then(|object| object.dict()) {
        Some(dict) => Value::Object(vm.dict_copy(&dict)?),
        None => Value::None,
    };
    let newline = newline.map_or(Value::None, Value::Str);

    Ok(Value::tuple(vec![text_value(content), newline, Value::Int(i64::try_from(position).unwrap_or(i64::MAX)), dict]))
}

fn string_io_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver(vm, &args, "__setstate__")?;
    let state = method_one_argument(vm, &args, "__setstate__")?;
    let target = &args.positional[0];

    let closed = match &*stream.state.borrow() {
        State::Uninitialized { closed } => *closed,
        State::Ready(ready) => ready.closed,
    };
    if closed {
        return Err(closed_file(vm));
    }

    require_known(&state, "StringIO state")?;
    let Some(items) = vm.as_tuple(&state).filter(|items| items.len() >= 4) else {
        return Err(vm.type_error(&format!("{}.__setstate__ argument should be 4-tuple, got {}", vm.type_name(target), vm.type_name(&state))));
    };

    initialize(vm, stream, Some(&items[0]), Some(&items[1]))?;

    // The value in the state is already translated; restore it unchanged.
    let Some(content) = vm.as_text(&items[0]) else {
        return Err(vm.halt_unsupported("StringIO.__setstate__ without an initial value"));
    };
    stream.initialized(vm, |ready| {
        ready.content = content.units().to_vec();
        Ok(())
    })?;

    let position = &items[2];
    if !is_index(vm, position)? {
        return Err(vm.type_error(&format!("third item of state must be an integer, got {}", vm.type_name(position))));
    }
    let position = index_value(vm, position)?;
    let Ok(position) = usize::try_from(position) else {
        return Err(vm.raise(ExceptionKind::ValueError, "position value cannot be negative"));
    };
    stream.initialized(vm, |ready| {
        ready.position = position;
        Ok(())
    })?;

    let dict = &items[3];
    if dict.is_none() {
        return Ok(Value::None);
    }
    require_known(dict, "StringIO state dict")?;
    let is_dict = matches!(dict, Value::Object(object) if object.as_dict().is_some());
    if !is_dict {
        return Err(vm.type_error(&format!("fourth item of state should be a dict, got a {}", vm.type_name(dict))));
    }
    let Some(object) = target.as_object() else {
        return Err(vm.type_error("StringIO.__setstate__ requires an object"));
    };
    let instance_dict = vm.instance_dict(object)?;
    vm.dict_merge(&instance_dict, dict, true)?;

    Ok(Value::None)
}

/// The stream behind a computed attribute of `StringIO`.
fn getset_stream<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a StringIo> {
    native_data::<StringIo>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

fn string_io_closed(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let stream = getset_stream(vm, getset, instance)?;

    stream.initialized(vm, |ready| Ok(Value::Bool(ready.closed)))
}

fn string_io_line_buffering(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let stream = getset_stream(vm, getset, instance)?;
    stream.check_open(vm)?;

    Ok(Value::Bool(false))
}

fn string_io_newlines(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let stream = getset_stream(vm, getset, instance)?;

    stream.open(vm, |ready| Ok(ready.decoder.map_or(Value::None, |decoder| decoder.seen.value())))
}
