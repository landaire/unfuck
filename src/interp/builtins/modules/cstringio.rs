//! `cStringIO`: `StringO` output streams and read-only `StringI` input
//! streams over byte strings.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::iterator_result;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
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

const OUTPUT_TYPE: &str = "cStringIO.StringO";
const INPUT_TYPE: &str = "cStringIO.StringI";

/// The bytes of an open stream.
enum Buffer {
    /// `StringI`: the initial string, of which the first `size` bytes
    /// remain after truncation.
    Input { data: PyBytes, size: usize },
    /// `StringO`: the written bytes.
    Output(Vec<u8>),
}

impl Buffer {
    fn content(&self) -> &[u8] {
        match self {
            Self::Input { data, size } => data.as_bytes().get(..*size).unwrap_or_default(),
            Self::Output(bytes) => bytes,
        }
    }

    fn truncate(&mut self, length: usize) {
        match self {
            Self::Input { size, .. } => *size = (*size).min(length),
            Self::Output(bytes) => bytes.truncate(length),
        }
    }
}

/// A `StringO` or `StringI` object.
pub(crate) struct StringIo {
    /// Whether this is a `StringO`.
    pub(crate) output: bool,
    /// `None` once closed.
    buffer: RefCell<Option<Buffer>>,
    /// May lie past the end after a seek.
    position: Cell<usize>,
    /// The `softspace` member of `StringO`.
    softspace: Cell<i32>,
}

impl_native_data!(StringIo, "cStringIO.StringIO");

impl StringIo {
    /// The open check, then `body` with the open buffer.
    fn with_buffer<R>(&self, vm: &Vm, body: impl FnOnce(&mut Buffer) -> R) -> PyResult<R> {
        let mut buffer = self.buffer.borrow_mut();
        let Some(buffer) = buffer.as_mut() else {
            return Err(vm.raise(ExceptionKind::ValueError, "I/O operation on closed file"));
        };

        Ok(body(buffer))
    }

    /// `read`: up to `count` bytes (all remaining when `None`).
    pub(crate) fn read(&self, vm: &Vm, count: Option<usize>) -> PyResult<Vec<u8>> {
        let position = self.position.get();
        let bytes = self.with_buffer(vm, |buffer| {
            let remaining = buffer.content().get(position..).unwrap_or_default();
            let count = count.map_or(remaining.len(), |count| count.min(remaining.len()));
            remaining[..count].to_vec()
        })?;
        self.position.set(position + bytes.len());

        Ok(bytes)
    }

    /// `readline`: through the next newline or to the end.
    pub(crate) fn read_line(&self, vm: &Vm) -> PyResult<Vec<u8>> {
        let position = self.position.get();
        let line = self.with_buffer(vm, |buffer| {
            let remaining = buffer.content().get(position..).unwrap_or_default();
            let length = remaining.iter().position(|&byte| byte == b'\n').map_or(remaining.len(), |newline| newline + 1);
            remaining[..length].to_vec()
        })?;
        self.position.set(position + line.len());

        Ok(line)
    }

    /// `write`: writes at the position, padding an overseek with NULs.
    pub(crate) fn write(&self, vm: &Vm, data: &[u8]) -> PyResult<()> {
        let position = self.position.get();
        if i32::try_from(data.len()).is_err() {
            return Err(vm.raise(ExceptionKind::OverflowError, "length too large"));
        }
        // CPython would allocate the padding of a far overseek; past 2 GiB the
        // outcome depends on host memory.
        if i32::try_from(position).is_err() {
            return Err(vm.halt_unsupported("cStringIO write past 2 GiB"));
        }

        self.with_buffer(vm, |buffer| {
            let Buffer::Output(bytes) = buffer else {
                return;
            };
            if bytes.len() < position {
                bytes.resize(position, 0);
            }
            let end = position + data.len();
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[position..end].copy_from_slice(data);
        })?;
        self.position.set(position + data.len());

        Ok(())
    }
}

/// The receiver of a method of `StringO` (`OUTPUT`) or `StringI`, checked
/// as the method descriptor of that type checks it.
fn receiver<'a, const OUTPUT: bool>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a StringIo> {
    let type_name = if OUTPUT { OUTPUT_TYPE } else { INPUT_TYPE };
    let Some(value) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{type_name}' object needs an argument")));
    };

    match native_data::<StringIo>(value).filter(|stream| stream.output == OUTPUT) {
        Some(stream) => Ok(stream),
        None => Err(vm.type_error(&format!("descriptor '{method}' requires a '{type_name}' object but received a '{}'", args::type_name(vm, value)))),
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("StringIO", string_io)])?;

    let input = native_type(vm, INPUT_TYPE, create_input_type)?;
    let output = native_type(vm, OUTPUT_TYPE, create_output_type)?;
    set_attribute(vm, module, "InputType", Value::Object(input))?;
    set_attribute(vm, module, "OutputType", Value::Object(output))
}

fn create_output_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[
        method("flush", flush::<true>),
        method("getvalue", getvalue::<true>),
        method("isatty", isatty::<true>),
        method("read", read::<true>),
        method("readline", readline::<true>),
        method("readlines", readlines::<true>),
        method("reset", reset::<true>),
        method("seek", seek::<true>),
        method("tell", tell::<true>),
        method("truncate", truncate::<true>),
        method("close", close::<true>),
        method("write", write),
        method("writelines", writelines),
        method("__iter__", iter::<true>),
        method("next", next::<true>),
    ];

    let class = new_final_type(vm, TypeSpec { name: "StringO", module: "cStringIO", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    add_member(vm, &class, GetSet { name: "softspace", owner: OUTPUT_TYPE, get: get_softspace, set: Some(set_softspace) })?;
    add_getset(vm, &class, GetSet { name: "closed", owner: OUTPUT_TYPE, get: closed::<true>, set: None })?;

    Ok(class)
}

fn create_input_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[
        method("flush", flush::<false>),
        method("getvalue", getvalue::<false>),
        method("isatty", isatty::<false>),
        method("read", read::<false>),
        method("readline", readline::<false>),
        method("readlines", readlines::<false>),
        method("reset", reset::<false>),
        method("seek", seek::<false>),
        method("tell", tell::<false>),
        method("truncate", truncate::<false>),
        method("close", close::<false>),
        method("__iter__", iter::<false>),
        method("next", next::<false>),
    ];

    let class = new_final_type(vm, TypeSpec { name: "StringI", module: "cStringIO", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    add_getset(vm, &class, GetSet { name: "closed", owner: INPUT_TYPE, get: closed::<false>, set: None })?;

    Ok(class)
}

/// `StringIO([s])`: a `StringI` reading `s`, or an empty `StringO`.
fn string_io(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::unpack(vm, args, "StringIO", 0, 1)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let Some(initial) = args.first() else {
        let class = native_type(vm, OUTPUT_TYPE, create_output_type)?;
        let stream = StringIo { output: true, buffer: RefCell::new(Some(Buffer::Output(Vec::new()))), position: Cell::new(0), softspace: Cell::new(0) };
        return Ok(new_native_object(vm, &class, stream));
    };

    let data = args::string_or_buffer(vm, "StringIO", 1, initial)?;
    let size = data.as_bytes().len();
    let class = native_type(vm, INPUT_TYPE, create_input_type)?;
    let stream = StringIo { output: false, buffer: RefCell::new(Some(Buffer::Input { data, size })), position: Cell::new(0), softspace: Cell::new(0) };

    Ok(new_native_object(vm, &class, stream))
}

fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Str(PyBytes::new(bytes))
}

/// The receiver of a no-argument method.
fn no_argument_receiver<'a, const OUTPUT: bool>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a StringIo> {
    let stream = receiver::<OUTPUT>(vm, args, method)?;
    args::no_arguments(vm, args, 1, method)?;

    Ok(stream)
}

/// The receiver and remaining arguments of a varargs method, which
/// rejects keywords before it runs.
fn varargs_receiver<'a, const OUTPUT: bool>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a StringIo, Vec<Value>)> {
    let stream = receiver::<OUTPUT>(vm, args, method)?;
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method}() takes no keyword arguments")));
    }

    Ok((stream, args.positional.get(1..).unwrap_or_default().to_vec()))
}

/// The argument count check of format parsing.
fn check_count(vm: &Vm, rest: Vec<Value>, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    args::varargs(vm, CallArgs::new(rest), function, minimum, maximum)
}

/// The check that the stream is open.
fn check_open(vm: &Vm, stream: &StringIo) -> PyResult<()> {
    stream.with_buffer(vm, |_| ())
}

fn flush<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "flush")?;
    check_open(vm, stream)?;

    Ok(Value::None)
}

/// `getvalue([use_pos])`: the whole string, or up to the position.
fn getvalue<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "getvalue")?;
    check_open(vm, stream)?;
    let rest = args::unpack(vm, CallArgs::new(rest), "getval", 0, 1)?;

    let use_position = match rest.first() {
        Some(flag) => vm.truthy(flag, "getvalue use_pos")?,
        None => false,
    };
    let position = stream.position.get();
    let value = stream.with_buffer(vm, |buffer| {
        let content = buffer.content();
        let end = if use_position { position.min(content.len()) } else { content.len() };
        content[..end].to_vec()
    })?;

    Ok(bytes_value(value))
}

fn isatty<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "isatty")?;
    check_open(vm, stream)?;

    Ok(Value::Bool(false))
}

/// `read([n])`: `n` bytes, or the rest when `n` is negative or absent.
fn read<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "read")?;
    let rest = check_count(vm, rest, "read", 0, 1)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let count = rest.first().map(|value| args::ssize(vm, value)).transpose()?;
    let count = count.and_then(|count| usize::try_from(count).ok());

    Ok(bytes_value(stream.read(vm, count)?))
}

/// `readline([size])`: a line, cut to `size` bytes when shorter.
fn readline<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "readline")?;
    let rest = check_count(vm, rest, "readline", 0, 1)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let limit = rest.first().map(|value| args::c_int(vm, value)).transpose()?;
    let mut line = stream.read_line(vm)?;
    if let Some(limit) = limit.and_then(|limit| usize::try_from(limit).ok()).filter(|limit| *limit < line.len()) {
        stream.position.set(stream.position.get() - (line.len() - limit));
        line.truncate(limit);
    }

    Ok(bytes_value(line))
}

/// `readlines([hint])`: lines until the end, or until `hint` bytes.
fn readlines<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "readlines")?;
    let rest = check_count(vm, rest, "readlines", 0, 1)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let hint = rest.first().map(|value| args::ssize(vm, value)).transpose()?.unwrap_or(0);
    let mut lines = Vec::new();
    let mut length = 0i64;
    loop {
        let line = stream.read_line(vm)?;
        if line.is_empty() {
            break;
        }
        length = length.saturating_add(i64::try_from(line.len()).unwrap_or(i64::MAX));
        lines.push(bytes_value(line));
        if hint > 0 && length >= hint {
            break;
        }
    }

    Ok(vm.new_list(lines))
}

fn reset<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "reset")?;
    check_open(vm, stream)?;
    stream.position.set(0);

    Ok(Value::None)
}

/// `seek(position[, mode])`: mode 1 is relative to the position, 2 to the
/// end, anything else absolute; a negative result clamps to 0.
fn seek<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "seek")?;
    check_open(vm, stream)?;
    let rest = check_count(vm, rest, "seek", 1, 2)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let offset = args::ssize(vm, &rest[0])?;
    let mode = rest.get(1).map(|value| args::c_int(vm, value)).transpose()?.unwrap_or(0);
    let base = match mode {
        2 => stream.with_buffer(vm, |buffer| buffer.content().len())?,
        1 => stream.position.get(),
        _ => 0,
    };

    // Positions and lengths stay far below `i64::MAX`.
    let base = i64::try_from(base).unwrap_or(i64::MAX);
    let position = usize::try_from(offset.saturating_add(base).max(0)).unwrap_or(usize::MAX);
    stream.position.set(position);

    Ok(Value::None)
}

fn tell<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "tell")?;
    check_open(vm, stream)?;

    Ok(args::index_value(stream.position.get()))
}

/// `truncate([size])`: cuts at `size` (the position by default) and moves
/// the position to the new end.
fn truncate<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<OUTPUT>(vm, &args, "truncate")?;
    check_open(vm, stream)?;
    let rest = check_count(vm, rest, "truncate", 0, 1)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let size = match rest.first() {
        Some(value) => usize::try_from(args::ssize(vm, value)?).ok(),
        None => Some(stream.position.get()),
    };
    let Some(size) = size else {
        let class = Rc::clone(vm.types().exception(ExceptionKind::IOError));
        let error = vm.instantiate_exception(&class, vec![Value::Int(22), Value::str("Invalid argument")])?;
        return Err(Signal::Raise(error));
    };

    let end = stream.with_buffer(vm, |buffer| {
        buffer.truncate(size);
        buffer.content().len()
    })?;
    stream.position.set(end);

    Ok(Value::None)
}

fn close<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "close")?;
    *stream.buffer.borrow_mut() = None;
    stream.position.set(0);

    Ok(Value::None)
}

/// `write(s)`: a string, or unicode encoded with the default encoding.
fn write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (stream, rest) = varargs_receiver::<true>(vm, &args, "write")?;
    let rest = check_count(vm, rest, "write", 1, 1)?;
    if let Some(unknown) = args::first_unknown(&rest) {
        return Ok(unknown);
    }

    let data = args::string_or_buffer(vm, "write", 1, &rest[0])?;
    stream.write(vm, data.as_bytes())?;

    Ok(Value::None)
}

/// `writelines(iterable)`: writes each string.
fn writelines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = receiver::<true>(vm, &args, "writelines")?;
    let rest = CallArgs { positional: args.positional.get(1..).unwrap_or_default().to_vec(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    let lines = args::single(vm, rest, "writelines")?;
    if lines.is_unknown() {
        return Ok(lines);
    }

    let iterator = vm.iter(&lines)?;
    while let Some(line) = vm.next(&iterator)? {
        if line.is_unknown() {
            return Ok(line);
        }
        let data = args::string_or_unicode(vm, &line)?;
        stream.write(vm, data.as_bytes())?;
    }

    Ok(Value::None)
}

fn iter<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_argument_receiver::<OUTPUT>(vm, &args, "__iter__")?;

    Ok(args.positional[0].clone())
}

/// `next`: the next line; an empty line ends the iteration.
fn next<const OUTPUT: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = no_argument_receiver::<OUTPUT>(vm, &args, "next")?;
    let line = stream.read_line(vm)?;

    iterator_result(vm, (!line.is_empty()).then(|| bytes_value(line)))
}

/// The stream behind a descriptor of `getset`, after the instance type check.
fn descriptor_stream<'a, const OUTPUT: bool>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a StringIo> {
    native_data::<StringIo>(instance)
        .filter(|stream| stream.output == OUTPUT)
        .ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

fn closed<const OUTPUT: bool>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let stream = descriptor_stream::<OUTPUT>(vm, getset, instance)?;

    Ok(Value::Bool(stream.buffer.borrow().is_none()))
}

fn get_softspace(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let stream = descriptor_stream::<true>(vm, getset, instance)?;

    Ok(Value::Int(i64::from(stream.softspace.get())))
}

/// Sets the `int` `softspace` member; `None` on deletion.
fn set_softspace(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let stream = descriptor_stream::<true>(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("can't delete numeric/char attribute"));
    };
    if value.is_unknown() {
        return Err(vm.halt_unsupported("unknown softspace value"));
    }

    stream.softspace.set(args::c_int(vm, &value)?);

    Ok(())
}
