//! `_io.TextIOWrapper`: a character stream over a buffered binary stream.
//! Text passes through the incremental codecs of the encoding, line endings
//! are translated as the `newline` argument asks, and `tell` reports an
//! opaque cookie from which `seek` rebuilds the decoder state.

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_bigint::Sign;
use num_traits::ToPrimitive;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args::c_int;
use crate::interp::builtins::modules::codecs::args::optional_string;
use crate::interp::builtins::modules::codecs::registry;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::operator::is_sequence;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::after_receiver;
use super::allocation_class;
use super::int_argument;
use super::iobase::text_base_type;
use super::long_value;
use super::missing_argument;
use super::newline::LineEnding;
use super::newline::decoder_type;
use super::require_known;
use super::size_argument;

const LF: u16 = b'\n' as u16;
const CR: u16 = b'\r' as u16;

/// The qualified type name used in descriptor messages.
const TYPE_NAME: &str = "_io.TextIOWrapper";

/// The `newline` argument.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Newline {
    /// `None`: any line ending reads as `\n`; `\n` writes as the host
    /// separator.
    Translate,
    /// `''`: any line ending ends a line and is kept as is.
    Universal,
    Lf,
    Cr,
    CrLf,
}

impl Newline {
    /// `None` for a value the constructor rejects.
    fn parse(value: Option<&[u8]>) -> Option<Self> {
        match value {
            None => Some(Self::Translate),
            Some(b"") => Some(Self::Universal),
            Some(b"\n") => Some(Self::Lf),
            Some(b"\r") => Some(Self::Cr),
            Some(b"\r\n") => Some(Self::CrLf),
            Some(_) => None,
        }
    }

    fn line_ending(self) -> LineEnding {
        match self {
            Self::Translate | Self::Lf => LineEnding::Translated,
            Self::Universal => LineEnding::Universal,
            Self::Cr => LineEnding::Fixed(vec![CR]),
            Self::CrLf => LineEnding::Fixed(vec![CR, LF]),
        }
    }

    /// Whether decoded text passes through an `IncrementalNewlineDecoder`,
    /// and if so whether it translates.
    fn newline_decoder(self) -> Option<bool> {
        match self {
            Self::Translate => Some(true),
            Self::Universal => Some(false),
            Self::Lf | Self::Cr | Self::CrLf => None,
        }
    }

    /// What `\n` becomes on write. The interpreter models Windows, whose
    /// line separator is `\r\n`.
    fn write_separator(self) -> Option<&'static [u16]> {
        match self {
            Self::Translate | Self::CrLf => Some(&[CR, LF]),
            Self::Cr => Some(&[CR]),
            Self::Universal | Self::Lf => None,
        }
    }
}

/// The struct members of the object. They are not reset by a failing
/// `__init__` until the codec lookup, so they outlive the stream state.
struct Members {
    encoding: Value,
    buffer: Value,
    line_buffering: bool,
}

/// The decoder state before the last chunk was read, and the bytes fed to
/// the decoder since then. `tell` replays them to find a position.
#[derive(Clone)]
struct Snapshot {
    /// The flag word of `decoder.getstate()`, converted only when used.
    flags: Value,
    input: Vec<u8>,
}

/// The state `__init__` builds.
struct Stream {
    detached: bool,
    errors: PyBytes,
    newline: Newline,
    decoder: Option<Value>,
    encoder: Option<Value>,
    seekable: bool,
    /// Off while iterating with `next`, which takes no snapshots.
    telling: bool,
    chunk_size: usize,

    /// The text of the last chunk and how much of it was returned.
    decoded: Vec<u16>,
    used: usize,
    snapshot: Option<Snapshot>,

    /// Encoded writes not yet passed to the buffer.
    pending: Option<Vec<Value>>,
    pending_size: usize,
}

impl Stream {
    fn remaining(&self) -> &[u16] {
        self.decoded.get(self.used..).unwrap_or_default()
    }

    fn take(&mut self, limit: usize) -> Vec<u16> {
        let count = limit.min(self.remaining().len());
        let taken = self.remaining()[..count].to_vec();
        self.used += count;

        taken
    }

    fn forget_decoded(&mut self) {
        self.decoded.clear();
        self.used = 0;
        self.snapshot = None;
    }
}

struct TextIo {
    members: RefCell<Members>,
    /// `None` until `__init__` succeeds.
    stream: RefCell<Option<Stream>>,
}

impl_native_data!(TextIo, "_io.TextIOWrapper");

impl TextIo {
    /// Runs `body` on the stream state; no Python code may run inside.
    fn with<R>(&self, vm: &Vm, body: impl FnOnce(&mut Stream) -> R) -> PyResult<R> {
        let mut stream = self.stream.borrow_mut();
        let Some(stream) = stream.as_mut() else {
            return Err(uninitialized(vm));
        };

        Ok(body(stream))
    }

    /// The wrapped buffer of an initialized, attached stream.
    fn attached(&self, vm: &Vm) -> PyResult<Value> {
        if self.with(vm, |stream| stream.detached)? {
            return Err(vm.raise(ExceptionKind::ValueError, "underlying buffer has been detached"));
        }

        Ok(self.members.borrow().buffer.clone())
    }
}

/// The position cookie of `tell`: a 21-byte little-endian unsigned number
/// of a 64-bit start position, then 32-bit decoder flags, bytes to feed,
/// and characters to skip, then one byte asking for a final decode.
#[derive(Clone, Copy)]
struct Cookie {
    start: i64,
    decoder_flags: i32,
    bytes_to_feed: i32,
    chars_to_skip: i32,
    need_eof: u8,
}

impl Cookie {
    const BYTES: usize = 21;

    fn at(start: i64, decoder_flags: i32) -> Self {
        Self { start, decoder_flags, bytes_to_feed: 0, chars_to_skip: 0, need_eof: 0 }
    }

    /// Whether the cookie names the start of the stream with a fresh
    /// decoder.
    fn is_origin(&self) -> bool {
        self.start == 0 && self.decoder_flags == 0
    }

    fn to_value(self) -> Value {
        let mut bytes = Vec::with_capacity(Self::BYTES);
        bytes.extend_from_slice(&self.start.to_le_bytes());
        bytes.extend_from_slice(&self.decoder_flags.to_le_bytes());
        bytes.extend_from_slice(&self.bytes_to_feed.to_le_bytes());
        bytes.extend_from_slice(&self.chars_to_skip.to_le_bytes());
        bytes.push(self.need_eof);

        Value::long(BigInt::from_bytes_le(Sign::Plus, &bytes))
    }

    /// Reads a cookie through `long(value)`.
    fn from_value(vm: &Vm, value: &Value) -> PyResult<Self> {
        let number = vm.call(&Value::Object(Rc::clone(&vm.types().long)), CallArgs::new(vec![value.clone()]))?;
        require_known(&number, "TextIOWrapper cookie")?;
        let Some(number) = vm.as_integral(&number) else {
            return Err(vm.type_error("an integer is required"));
        };

        let (sign, magnitude) = number.to_bigint().to_bytes_le();
        if sign == Sign::Minus {
            return Err(vm.raise(ExceptionKind::OverflowError, "can't convert negative long to unsigned"));
        }
        if magnitude.len() > Self::BYTES {
            return Err(vm.raise(ExceptionKind::OverflowError, "long too big to convert"));
        }
        let mut bytes = [0u8; Self::BYTES];
        bytes[..magnitude.len()].copy_from_slice(&magnitude);

        let word = |offset: usize| i32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
        let mut start = [0u8; 8];
        start.copy_from_slice(&bytes[..8]);

        Ok(Self { start: i64::from_le_bytes(start), decoder_flags: word(8), bytes_to_feed: word(12), chars_to_skip: word(16), need_eof: bytes[20] })
    }
}

/// An argument of `__init__` after its conversion.
enum InitArgument {
    Object(Value),
    Text(Option<PyBytes>),
    Flag(i32),
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "TextIOWrapper", Value::Object(text_io_type(vm)?))
}

fn text_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, TYPE_NAME, create_text_io_type)
}

fn create_text_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = text_base_type(vm)?;
    let class = new_type(
        vm,
        TypeSpec {
            name: "TextIOWrapper",
            module: "_io",
            base: Some(base),
            layout: Layout::Native,
            instance_dict: true,
            methods: &[
                static_method("__new__", text_io_new),
                method("__init__", text_io_init),
                method("__repr__", text_io_repr),
                method("detach", text_io_detach),
                method("write", text_io_write),
                method("read", text_io_read),
                method("readline", text_io_readline),
                method("flush", text_io_flush),
                method("close", text_io_close),
                method("fileno", |vm, args| forward(vm, &args, "fileno")),
                method("seekable", |vm, args| forward(vm, &args, "seekable")),
                method("readable", |vm, args| forward(vm, &args, "readable")),
                method("writable", |vm, args| forward(vm, &args, "writable")),
                method("isatty", |vm, args| forward(vm, &args, "isatty")),
                method("seek", text_io_seek),
                method("tell", text_io_tell),
                method("truncate", text_io_truncate),
                method("next", text_io_next),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "encoding", owner: TYPE_NAME, get: encoding_get, set: None })?;
    add_member(vm, &class, GetSet { name: "buffer", owner: TYPE_NAME, get: buffer_get, set: None })?;
    add_member(vm, &class, GetSet { name: "line_buffering", owner: TYPE_NAME, get: line_buffering_get, set: None })?;
    add_getset(vm, &class, GetSet { name: "name", owner: TYPE_NAME, get: name_get, set: None })?;
    add_getset(vm, &class, GetSet { name: "closed", owner: TYPE_NAME, get: closed_get, set: None })?;
    add_getset(vm, &class, GetSet { name: "newlines", owner: TYPE_NAME, get: newlines_get, set: None })?;
    add_getset(vm, &class, GetSet { name: "errors", owner: TYPE_NAME, get: errors_get, set: None })?;
    add_getset(vm, &class, GetSet { name: "_CHUNK_SIZE", owner: TYPE_NAME, get: chunk_size_get, set: Some(chunk_size_set) })?;

    Ok(class)
}

fn uninitialized(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on uninitialized object")
}

fn io_error(vm: &Vm, message: &str) -> Signal {
    vm.raise(ExceptionKind::IOError, message)
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a TextIo, &'a Value)> {
    let io = this::<TextIo>(vm, args, TYPE_NAME, method)?;

    Ok((io, &args.positional[0]))
}

/// Raises when the `closed` attribute of the wrapper is true.
fn check_closed(vm: &Vm, target: &Value) -> PyResult<()> {
    let closed = vm.getattr_str(target, "closed")?;
    require_known(&closed, "TextIOWrapper closed")?;
    if vm.truthy(&closed, "TextIOWrapper closed")? {
        return Err(vm.raise(ExceptionKind::ValueError, "I/O operation on closed file."));
    }

    Ok(())
}

fn is_zero(vm: &Vm, value: &Value) -> PyResult<bool> {
    let equal = vm.compare(value, &Value::long(BigInt::from(0)), CompareOp::Equal)?;

    vm.truthy(&equal, "TextIOWrapper zero comparison")
}

/// Calls `decoder.decode` and checks that it produced text.
fn decode(vm: &Vm, decoder: &Value, arguments: Vec<Value>) -> PyResult<PyText> {
    let decoded = vm.call_method(decoder, "decode", arguments)?;
    require_known(&decoded, "decoded text")?;

    vm.as_text(&decoded).ok_or_else(|| vm.type_error(&format!("decoder should return a string result, not '{}'", vm.type_name(&decoded))))
}

/// The two items of a decoder state, which may be any sequence other than
/// a `str`.
fn state_items(vm: &Vm, state: &Value) -> PyResult<(Value, Value)> {
    require_known(state, "decoder state")?;

    if vm.as_str_bytes(state).is_some() || !is_sequence(vm, state)? {
        return Err(vm.type_error(&format!("argument must be 2-item sequence, not {}", vm.type_name(state))));
    }
    let Some(length) = vm.len(state)? else {
        return Err(vm.halt_unsupported("decoder state of unknown length"));
    };
    if length != 2 {
        return Err(vm.type_error(&format!("argument must be sequence of length 2, not {length}")));
    }

    Ok((vm.getitem(state, &Value::Int(0))?, vm.getitem(state, &Value::Int(1))?))
}

/// The decoder state while replaying bytes: whether bytes are buffered,
/// and the flag word.
fn replay_state(vm: &Vm, state: &Value) -> PyResult<(bool, i32)> {
    let (buffered, flags) = state_items(vm, state)?;
    require_known(&buffered, "decoder state buffer")?;

    let empty = match (vm.as_str_bytes(&buffered), vm.as_text(&buffered)) {
        (Some(bytes), _) => bytes.as_bytes().is_empty(),
        (None, Some(text)) => text.units().is_empty(),
        (None, None) => return Err(vm.type_error(&format!("argument 1 must be string or read-only buffer, not {}", vm.type_name(&buffered)))),
    };

    Ok((empty, int_argument(vm, &flags, "decoder state flags")?))
}

/// A file position as a 64-bit integer, converting through `__int__`.
fn offset_value(vm: &Vm, value: &Value) -> PyResult<i64> {
    require_known(value, "file position")?;

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            if vm.as_float(value).is_none() && vm.user_override(value, "__int__")?.is_none() {
                return Err(vm.type_error("an integer is required"));
            }
            let converted = vm.call(&Value::Object(Rc::clone(&vm.types().int)), CallArgs::new(vec![value.clone()]))?;
            require_known(&converted, "file position")?;
            vm.as_integral(&converted).ok_or_else(|| vm.type_error("an integer is required"))?
        }
    };

    match integral {
        Integral::Int(number) => Ok(number),
        Integral::Long(number) => number.to_i64().ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long too big to convert")),
    }
}

/// Saturates a count into a cookie field; real counts are far smaller.
fn cookie_field(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// Puts the decoder in the state the cookie records before its bytes.
fn rewind_decoder(vm: &Vm, decoder: &Value, cookie: &Cookie) -> PyResult<()> {
    if cookie.is_origin() {
        vm.call_method(decoder, "reset", Vec::new())?;
    } else {
        vm.call_method(decoder, "setstate", vec![Value::tuple(vec![Value::str(""), Value::Int(i64::from(cookie.decoder_flags))])])?;
    }

    Ok(())
}

/// Passes the encoded writes held back so far to the buffer.
fn write_pending(vm: &Vm, io: &TextIo, buffer: &Value) -> PyResult<()> {
    let pending = io.with(vm, |stream| {
        stream.pending_size = 0;
        stream.pending.take()
    })?;
    let Some(pending) = pending else {
        return Ok(());
    };

    let joined = vm.call_method(&Value::str(""), "join", vec![vm.new_list(pending)])?;
    vm.call_method(buffer, "write", vec![joined])?;

    Ok(())
}

/// Reads and decodes one chunk, replacing the decoded text. Returns false
/// once the stream is at its end and the decoder had nothing left to give.
fn read_chunk(vm: &Vm, io: &TextIo, buffer: &Value) -> PyResult<bool> {
    let (decoder, telling, chunk_size) = io.with(vm, |stream| (stream.decoder.clone(), stream.telling, stream.chunk_size))?;
    let Some(decoder) = decoder else {
        return Err(io_error(vm, "not readable"));
    };

    let state = match telling {
        true => Some(state_items(vm, &vm.call_method(&decoder, "getstate", Vec::new())?)?),
        false => None,
    };

    let input = vm.call_method(buffer, "read1", vec![long_value(chunk_size)])?;
    require_known(&input, "read1 result")?;
    let Some(bytes) = vm.as_str_bytes(&input) else {
        return Err(vm.type_error(&format!("underlying read1() should have returned a bytes object, not '{}'", vm.type_name(&input))));
    };
    let at_end = bytes.as_bytes().is_empty();

    let decoded = decode(vm, &decoder, vec![input, Value::Bool(at_end)])?;

    let snapshot = match state {
        Some((buffered, flags)) => {
            require_known(&buffered, "decoder state buffer")?;
            let Some(buffered) = vm.as_str_bytes(&buffered) else {
                return Err(vm.type_error(&format!("decoder getstate() should have returned a bytes object, not '{}'", vm.type_name(&buffered))));
            };
            Some(Snapshot { flags, input: [buffered.as_bytes(), bytes.as_bytes()].concat() })
        }
        None => None,
    };

    let produced = !decoded.units().is_empty();
    io.with(vm, |stream| {
        stream.decoded = decoded.units().to_vec();
        stream.used = 0;
        if telling {
            stream.snapshot = snapshot;
        }
    })?;

    Ok(!at_end || produced)
}

/// `read(size)` after the argument and state checks.
fn read_text(vm: &Vm, io: &TextIo, buffer: &Value, size: Option<usize>) -> PyResult<Vec<u16>> {
    let Some(decoder) = io.with(vm, |stream| stream.decoder.clone())? else {
        return Err(io_error(vm, "not readable"));
    };
    write_pending(vm, io, buffer)?;

    let Some(size) = size else {
        let input = vm.call_method(buffer, "read", Vec::new())?;
        let decoded = decode(vm, &decoder, vec![input, Value::Bool(true)])?;

        // The used-up chunk stays; a later `readline(0)` sees it and reads
        // nothing.
        return io.with(vm, |stream| {
            let mut text = stream.remaining().to_vec();
            text.extend_from_slice(decoded.units());
            stream.used = stream.decoded.len();
            stream.snapshot = None;
            text
        });
    };

    let mut text = io.with(vm, |stream| stream.take(size))?;
    while text.len() < size {
        let more = read_chunk(vm, io, buffer)?;
        let wanted = size - text.len();
        text.extend(io.with(vm, |stream| stream.take(wanted))?);
        if !more {
            break;
        }
    }

    Ok(text)
}

/// `readline(limit)` after the argument and state checks.
fn read_line(vm: &Vm, io: &TextIo, buffer: &Value, limit: Option<usize>) -> PyResult<Vec<u16>> {
    write_pending(vm, io, buffer)?;
    let (readable, newline) = io.with(vm, |stream| (stream.decoder.is_some(), stream.newline))?;
    if !readable {
        return Err(io_error(vm, "not readable"));
    }
    let ending = newline.line_ending();

    let mut line: Vec<u16> = Vec::new();
    // Text before this index holds no line ending.
    let mut searched = 0;
    let end = loop {
        // A chunk already decoded, even when used up, is searched before
        // anything more is read.
        while io.with(vm, |stream| stream.decoded.is_empty())? {
            let more = read_chunk(vm, io, buffer)?;
            if !more {
                io.with(vm, Stream::forget_decoded)?;
                return Ok(line);
            }
        }

        io.with(vm, |stream| {
            line.extend_from_slice(stream.remaining());
            stream.used = stream.decoded.len();
        })?;

        let window = &line[searched..];
        if let Some(length) = ending.line_length(window) {
            break searched + length;
        }
        searched += ending.consumed(window);
        if let Some(limit) = limit.filter(|limit| searched >= *limit) {
            break limit;
        }

        io.with(vm, |stream| {
            stream.decoded.clear();
            stream.used = 0;
        })?;
    };

    let end = limit.map_or(end, |limit| end.min(limit)).min(line.len());
    let returned = line.len() - end;
    line.truncate(end);
    io.with(vm, |stream| stream.used = stream.used.saturating_sub(returned))?;

    Ok(line)
}

/// Replays the bytes of the snapshot to find the last point at which the
/// decoder held no bytes, and the characters to skip after it.
fn replay(vm: &Vm, decoder: &Value, cookie: &mut Cookie, input: &[u8], used: usize) -> PyResult<()> {
    rewind_decoder(vm, decoder, cookie)?;

    let mut skip = used;
    let mut fed = 0;
    let mut produced = 0;
    let mut reached = false;
    for byte in input {
        fed += 1;
        produced += decode(vm, decoder, vec![Value::Str(PyBytes::new(vec![*byte]))])?.units().len();
        let state = vm.call_method(decoder, "getstate", Vec::new())?;
        let (empty, flags) = replay_state(vm, &state)?;

        if empty && produced <= skip {
            cookie.start = cookie.start.wrapping_add(i64::from(cookie_field(fed)));
            cookie.decoder_flags = flags;
            skip -= produced;
            fed = 0;
            produced = 0;
        }
        if produced >= skip {
            reached = true;
            break;
        }
    }

    if !reached {
        produced += decode(vm, decoder, vec![Value::str(""), Value::Int(1)])?.units().len();
        cookie.need_eof = 1;
        if produced < skip {
            return Err(io_error(vm, "can't reconstruct logical file position"));
        }
    }

    cookie.bytes_to_feed = cookie_field(fed);
    cookie.chars_to_skip = cookie_field(skip);

    Ok(())
}

fn text_io_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &text_io_type(vm)?)?;
    let members = Members { encoding: Value::None, buffer: Value::None, line_buffering: false };

    Ok(new_native_object(vm, &class, TextIo { members: RefCell::new(members), stream: RefCell::new(None) }))
}

/// `locale.getpreferredencoding()`, or ASCII without the module.
fn default_encoding(vm: &Vm) -> PyResult<PyBytes> {
    let locale = match vm.import_module("locale") {
        Ok(locale) => locale,
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::ImportError) => return Ok(PyBytes::from("ascii")),
        Err(error) => return Err(error),
    };

    let encoding = vm.call_method(&locale, "getpreferredencoding", Vec::new())?;
    require_known(&encoding, "preferred encoding")?;

    vm.as_str_bytes(&encoding).ok_or_else(|| vm.type_error("bad argument type for built-in operation"))
}

fn text_io_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, _) = receiver(vm, &args, "__init__")?;
    *io.stream.borrow_mut() = None;

    let names = ["buffer", "encoding", "errors", "newline", "line_buffering"];
    let mut slots = parse_with(vm, after_receiver(&args), "fileio", &names, 1, |vm, index, value| match index {
        0 => Ok(InitArgument::Object(value)),
        4 => {
            require_known(&value, "TextIOWrapper line_buffering")?;
            Ok(InitArgument::Flag(c_int(vm, &value)?))
        }
        _ => {
            require_known(&value, "TextIOWrapper text argument")?;
            Ok(InitArgument::Text(optional_string(vm, "fileio", index + 1, Some(&value))?))
        }
    })?
    .into_iter();

    let Some(InitArgument::Object(buffer)) = slots.next().flatten() else {
        return Err(missing_argument(vm, "buffer", 1));
    };
    let mut text = || match slots.next().flatten() {
        Some(InitArgument::Text(text)) => text,
        _ => None,
    };
    let encoding = text();
    let errors = text().unwrap_or_else(|| PyBytes::from("strict"));
    let newline_argument = text();
    let line_buffering = matches!(slots.next().flatten(), Some(InitArgument::Flag(flag)) if flag != 0);

    let Some(newline) = Newline::parse(newline_argument.as_ref().map(PyBytes::as_bytes)) else {
        let shown = newline_argument.map(|value| value.to_string_lossy()).unwrap_or_default();
        return Err(vm.raise(ExceptionKind::ValueError, &format!("illegal newline value: {shown}")));
    };

    {
        let mut members = io.members.borrow_mut();
        members.buffer = Value::None;
        members.encoding = Value::None;
    }

    let encoding = match encoding {
        Some(encoding) => encoding,
        None => default_encoding(vm)?,
    };
    let codec = registry::lookup(vm, encoding.as_bytes())?;
    require_known(&codec, "codec")?;

    *io.members.borrow_mut() = Members { encoding: Value::Str(encoding), buffer: buffer.clone(), line_buffering };

    let readable = vm.call_method(&buffer, "readable", Vec::new())?;
    let decoder = if vm.truthy(&readable, "TextIOWrapper readable")? {
        let factory = vm.getattr_str(&codec, "incrementaldecoder")?;
        let decoder = vm.call(&factory, CallArgs::new(vec![Value::Str(errors.clone())]))?;
        match newline.newline_decoder() {
            Some(translate) => Some(vm.call(&Value::Object(decoder_type(vm)?), CallArgs::new(vec![decoder, Value::Bool(translate)]))?),
            None => Some(decoder),
        }
    } else {
        None
    };

    let writable = vm.call_method(&buffer, "writable", Vec::new())?;
    let encoder = if vm.truthy(&writable, "TextIOWrapper writable")? {
        let factory = vm.getattr_str(&codec, "incrementalencoder")?;
        Some(vm.call(&factory, CallArgs::new(vec![Value::Str(errors.clone())]))?)
    } else {
        None
    };

    let seekable = vm.call_method(&buffer, "seekable", Vec::new())?;
    let seekable = vm.truthy(&seekable, "TextIOWrapper seekable")?;

    // Writing into the middle of a stream must not start with a BOM.
    if let (true, Some(encoder)) = (seekable, &encoder) {
        let position = vm.call_method(&buffer, "tell", Vec::new())?;
        if !is_zero(vm, &position)? {
            vm.call_method(encoder, "setstate", vec![Value::long(BigInt::from(0))])?;
        }
    }

    *io.stream.borrow_mut() = Some(Stream {
        detached: false,
        errors,
        newline,
        decoder,
        encoder,
        seekable,
        telling: seekable,
        chunk_size: 8192,
        decoded: Vec::new(),
        used: 0,
        snapshot: None,
        pending: None,
        pending_size: 0,
    });

    Ok(Value::None)
}

fn text_io_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "__repr__")?;
    method_no_arguments(vm, &args, "__repr__")?;
    io.with(vm, |_| ())?;

    let mut text = String::from("<_io.TextIOWrapper");
    match vm.getattr_str(target, "name") {
        Ok(name) => {
            text.push_str(" name=");
            text.push_str(&vm.repr_text(&name)?);
        }
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::Exception) => {
            // A stream without a usable name shows only its encoding.
        }
        Err(error) => return Err(error),
    }
    let encoding = io.members.borrow().encoding.clone();
    text.push_str(" encoding=");
    text.push_str(&vm.repr_text(&encoding)?);
    text.push('>');

    Ok(Value::str(&text))
}

fn text_io_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "detach")?;
    method_no_arguments(vm, &args, "detach")?;
    io.attached(vm)?;

    vm.call_method(target, "flush", Vec::new())?;

    let buffer = std::mem::replace(&mut io.members.borrow_mut().buffer, Value::None);
    io.with(vm, |stream| stream.detached = true)?;

    Ok(buffer)
}

fn text_io_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "write")?;
    let buffer = io.attached(vm)?;
    let rest = method_arguments(vm, &args, "write", 1, 1)?;
    let original = rest[0].clone();
    require_known(&original, "TextIOWrapper write argument")?;
    let Some(text) = vm.as_text(&original) else {
        return Err(vm.type_error(&format!("write() argument 1 must be unicode, not {}", vm.type_name(&original))));
    };
    check_closed(vm, target)?;

    let (encoder, newline) = io.with(vm, |stream| (stream.encoder.clone(), stream.newline))?;
    let Some(encoder) = encoder else {
        return Err(io_error(vm, "not writable"));
    };
    let line_buffering = io.members.borrow().line_buffering;

    let units = text.units();
    let has_lf = units.contains(&LF);
    let must_flush = line_buffering && (has_lf || units.contains(&CR));
    let translated = match newline.write_separator().filter(|_| has_lf) {
        Some(separator) => Value::Unicode(PyText::new(units.iter().flat_map(|unit| if *unit == LF { separator } else { std::slice::from_ref(unit) }).copied().collect::<Vec<u16>>())),
        None => original,
    };

    let encoded = vm.call_method(&encoder, "encode", vec![translated])?;
    require_known(&encoded, "encoded text")?;
    let encoded_size = vm.as_str_bytes(&encoded).map_or(0, |bytes| bytes.as_bytes().len());
    let over_chunk = io.with(vm, |stream| {
        stream.pending.get_or_insert_with(Vec::new).push(encoded);
        stream.pending_size += encoded_size;
        stream.pending_size > stream.chunk_size
    })?;

    if over_chunk || must_flush {
        write_pending(vm, io, &buffer)?;
    }
    if must_flush {
        vm.call_method(&buffer, "flush", Vec::new())?;
    }

    let decoder = io.with(vm, |stream| {
        stream.snapshot = None;
        stream.decoder.clone()
    })?;
    if let Some(decoder) = decoder {
        vm.call_method(&decoder, "reset", Vec::new())?;
    }

    Ok(long_value(units.len()))
}

fn text_io_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "read")?;
    let buffer = io.attached(vm)?;
    let rest = method_arguments(vm, &args, "read", 0, 1)?;
    let size = size_argument(vm, rest.first())?;
    check_closed(vm, target)?;

    let size = size.and_then(|size| usize::try_from(size).ok());

    Ok(Value::Unicode(PyText::new(read_text(vm, io, &buffer, size)?)))
}

fn text_io_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "readline")?;
    let buffer = io.attached(vm)?;
    let rest = method_arguments(vm, &args, "readline", 0, 1)?;
    let limit = match rest.first() {
        Some(Value::None) => return Err(vm.type_error("integer argument expected, got 'NoneType'")),
        argument => size_argument(vm, argument)?,
    };
    check_closed(vm, target)?;

    let limit = limit.and_then(|limit| usize::try_from(limit).ok());

    Ok(Value::Unicode(PyText::new(read_line(vm, io, &buffer, limit)?)))
}

fn text_io_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "next")?;
    method_no_arguments(vm, &args, "next")?;
    let buffer = io.attached(vm)?;
    io.with(vm, |stream| stream.telling = false)?;

    let exact = Rc::ptr_eq(&vm.class_of(target), &text_io_type(vm)?);
    let line = if exact {
        check_closed(vm, target)?;
        read_line(vm, io, &buffer, None)?
    } else {
        let line = vm.call_method(target, "readline", Vec::new())?;
        require_known(&line, "readline result")?;
        let Some(line) = vm.as_text(&line) else {
            return Err(io_error(vm, &format!("readline() should have returned an str object, not '{}'", vm.type_name(&line))));
        };
        line.units().to_vec()
    };

    if line.is_empty() {
        io.with(vm, |stream| {
            stream.snapshot = None;
            stream.telling = stream.seekable;
        })?;
        return Err(stop_iteration(vm));
    }

    Ok(Value::Unicode(PyText::new(line)))
}

fn text_io_flush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "flush")?;
    method_no_arguments(vm, &args, "flush")?;
    let buffer = io.attached(vm)?;
    check_closed(vm, target)?;

    io.with(vm, |stream| stream.telling = stream.seekable)?;
    write_pending(vm, io, &buffer)?;

    vm.call_method(&buffer, "flush", Vec::new())
}

fn text_io_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "close")?;
    method_no_arguments(vm, &args, "close")?;
    let buffer = io.attached(vm)?;

    let closed = vm.getattr_str(&buffer, "closed")?;
    require_known(&closed, "buffer closed")?;
    if vm.truthy(&closed, "buffer closed")? {
        return Ok(Value::None);
    }

    // The buffer closes even when the flush fails. An error from closing
    // takes precedence over one from flushing.
    let flushed = vm.call_method(target, "flush", Vec::new());
    let result = vm.call_method(&buffer, "close", Vec::new())?;
    flushed?;

    Ok(result)
}

/// A method answered by the same method of the buffer.
fn forward(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    let (io, _) = receiver(vm, args, name)?;
    method_no_arguments(vm, args, name)?;
    let buffer = io.attached(vm)?;

    vm.call_method(&buffer, name, Vec::new())
}

fn text_io_truncate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "truncate")?;
    let buffer = io.attached(vm)?;
    let rest = method_arguments(vm, &args, "truncate", 0, 1)?;
    let position = rest.first().cloned().unwrap_or(Value::None);

    vm.call_method(target, "flush", Vec::new())?;

    vm.call_method(&buffer, "truncate", vec![position])
}

fn text_io_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "tell")?;
    method_no_arguments(vm, &args, "tell")?;
    let buffer = io.attached(vm)?;
    check_closed(vm, target)?;

    let (seekable, telling) = io.with(vm, |stream| (stream.seekable, stream.telling))?;
    if !seekable {
        return Err(io_error(vm, "underlying stream is not seekable"));
    }
    if !telling {
        return Err(io_error(vm, "telling position disabled by next() call"));
    }

    write_pending(vm, io, &buffer)?;
    vm.call_method(target, "flush", Vec::new())?;
    let position = vm.call_method(&buffer, "tell", Vec::new())?;

    let (decoder, snapshot, used) = io.with(vm, |stream| (stream.decoder.clone(), stream.snapshot.clone(), stream.used))?;
    let (Some(decoder), Some(snapshot)) = (decoder, snapshot) else {
        return Ok(position);
    };

    let position = offset_value(vm, &position)?;
    let flags = int_argument(vm, &snapshot.flags, "decoder state flags")?;
    let consumed = i64::try_from(snapshot.input.len()).unwrap_or(i64::MAX);
    let mut cookie = Cookie::at(position.wrapping_sub(consumed), flags);
    if used == 0 {
        return Ok(cookie.to_value());
    }

    // Replaying changes the decoder; put back the state it had.
    let saved = vm.call_method(&decoder, "getstate", Vec::new())?;
    let replayed = replay(vm, &decoder, &mut cookie, &snapshot.input, used);
    let restored = vm.call_method(&decoder, "setstate", vec![saved]);
    replayed?;
    restored?;

    Ok(cookie.to_value())
}

fn text_io_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (io, target) = receiver(vm, &args, "seek")?;
    let buffer = io.attached(vm)?;
    let rest = method_arguments(vm, &args, "seek", 1, 2)?;
    let mut position = rest[0].clone();
    let whence = match rest.get(1) {
        Some(whence) => int_argument(vm, whence, "TextIOWrapper.seek whence")?,
        None => 0,
    };
    check_closed(vm, target)?;

    if !io.with(vm, |stream| stream.seekable)? {
        return Err(io_error(vm, "underlying stream is not seekable"));
    }

    match whence {
        0 => {}
        1 => {
            if !is_zero(vm, &position)? {
                return Err(io_error(vm, "can't do nonzero cur-relative seeks"));
            }
            position = vm.call_method(target, "tell", Vec::new())?;
        }
        2 => {
            if !is_zero(vm, &position)? {
                return Err(io_error(vm, "can't do nonzero end-relative seeks"));
            }
            vm.call_method(target, "flush", Vec::new())?;
            let decoder = io.with(vm, |stream| {
                stream.forget_decoded();
                stream.decoder.clone()
            })?;
            if let Some(decoder) = decoder {
                vm.call_method(&decoder, "reset", Vec::new())?;
            }
            return vm.call_method(&buffer, "seek", vec![Value::Int(0), Value::Int(2)]);
        }
        _ => return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid whence ({whence}, should be 0, 1 or 2)"))),
    }

    let negative = vm.compare(&position, &Value::long(BigInt::from(0)), CompareOp::Less)?;
    if vm.truthy(&negative, "TextIOWrapper seek position")? {
        let shown = vm.repr_text(&position)?;
        return Err(vm.raise(ExceptionKind::ValueError, &format!("negative seek position {shown}")));
    }

    vm.call_method(target, "flush", Vec::new())?;
    let cookie = Cookie::from_value(vm, &position)?;
    vm.call_method(&buffer, "seek", vec![Value::long(BigInt::from(cookie.start))])?;

    let (decoder, encoder) = io.with(vm, |stream| {
        stream.forget_decoded();
        (stream.decoder.clone(), stream.encoder.clone())
    })?;
    if let Some(decoder) = &decoder {
        rewind_decoder(vm, decoder, &cookie)?;
    }

    // The position is now the cookie's start, with nothing fed since.
    io.with(vm, |stream| stream.snapshot = Some(Snapshot { flags: Value::Int(i64::from(cookie.decoder_flags)), input: Vec::new() }))?;

    if cookie.chars_to_skip != 0 {
        let input = vm.call_method(&buffer, "read", vec![Value::Int(i64::from(cookie.bytes_to_feed))])?;
        require_known(&input, "read result")?;
        let Some(bytes) = vm.as_str_bytes(&input) else {
            return Err(vm.type_error(&format!("underlying read() should have returned a bytes object, not '{}'", vm.type_name(&input))));
        };
        io.with(vm, |stream| stream.snapshot = Some(Snapshot { flags: Value::Int(i64::from(cookie.decoder_flags)), input: bytes.as_bytes().to_vec() }))?;
        let decoded = match &decoder {
            Some(decoder) => decode(vm, decoder, vec![input, Value::Int(i64::from(cookie.need_eof))])?.units().to_vec(),
            None => Vec::new(),
        };

        let available = decoded.len();
        io.with(vm, |stream| stream.decoded = decoded)?;
        // A forged cookie may hold a negative count; nothing is skipped then.
        let skip = usize::try_from(cookie.chars_to_skip).unwrap_or(0);
        if available < skip {
            return Err(io_error(vm, "can't restore logical file position"));
        }
        io.with(vm, |stream| stream.used = skip)?;
    }

    if let Some(encoder) = encoder {
        if cookie.is_origin() {
            vm.call_method(&encoder, "reset", Vec::new())?;
        } else {
            vm.call_method(&encoder, "setstate", vec![Value::long(BigInt::from(0))])?;
        }
    }

    Ok(position)
}

/// The object behind a descriptor of `TextIOWrapper`.
fn descriptor_target<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a TextIo> {
    native_data::<TextIo>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

fn encoding_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(descriptor_target(vm, getset, instance)?.members.borrow().encoding.clone())
}

fn buffer_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(descriptor_target(vm, getset, instance)?.members.borrow().buffer.clone())
}

fn line_buffering_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(Value::Bool(descriptor_target(vm, getset, instance)?.members.borrow().line_buffering))
}

fn name_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let buffer = descriptor_target(vm, getset, instance)?.attached(vm)?;

    vm.getattr_str(&buffer, "name")
}

fn closed_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let buffer = descriptor_target(vm, getset, instance)?.attached(vm)?;

    vm.getattr_str(&buffer, "closed")
}

fn newlines_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let io = descriptor_target(vm, getset, instance)?;
    io.attached(vm)?;

    let Some(decoder) = io.with(vm, |stream| stream.decoder.clone())? else {
        return Ok(Value::None);
    };
    match vm.getattr_str(&decoder, "newlines") {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::AttributeError) => Ok(Value::None),
        result => result,
    }
}

fn errors_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let io = descriptor_target(vm, getset, instance)?;

    io.with(vm, |stream| Value::Str(stream.errors.clone()))
}

fn chunk_size_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let io = descriptor_target(vm, getset, instance)?;
    io.attached(vm)?;

    io.with(vm, |stream| long_value(stream.chunk_size))
}

fn chunk_size_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let io = descriptor_target(vm, getset, instance)?;
    io.attached(vm)?;

    let Some(value) = value else {
        return Err(vm.raise(ExceptionKind::SystemError, "null argument to internal routine"));
    };
    require_known(&value, "_CHUNK_SIZE")?;
    let size = vm.index_as_ssize(&value, Some(ExceptionKind::TypeError))?;
    let Some(size) = usize::try_from(size).ok().filter(|size| *size > 0) else {
        return Err(vm.raise(ExceptionKind::ValueError, "a strictly positive integer is required"));
    };

    io.with(vm, |stream| stream.chunk_size = size)
}
