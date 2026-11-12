//! `_io.BufferedReader`, `_io.BufferedWriter`, `_io.BufferedRandom`, and
//! `_io.BufferedRWPair`.
//!
//! One array holds both the read-ahead and the pending writes, and the
//! positions inside it are kept as signed offsets. Every call made on the
//! raw stream, with its sizes and order, follows from that arithmetic, so it
//! is reproduced exactly, including the stale offsets the reference leaves
//! behind after some rewinds, failed seeks, and non-blocking writes.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::containers::memoryview::hold_buffer;
use crate::interp::builtins::containers::memoryview::new_memoryview;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args::string_or_buffer;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::parse;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
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
use super::IoState;
use super::after_receiver;
use super::allocation_class;
use super::int_argument;
use super::iobase::buffered_base_type;
use super::missing_argument;
use super::readinto_target;
use super::require_known;
use super::size_argument;
use super::slot_no_arguments;
use super::ssize_argument;

/// `__sizeof__` of a buffered object before its buffer is counted.
const BASIC_SIZE: i64 = 152;

/// The `max_buffer_size` default; any other value draws a warning.
const MAX_BUFFER_SIZE_DEFAULT: i64 = -234;

const BLOCKED_MESSAGE: &str = "write could not complete without blocking";

/// The largest buffer or read size reproduced. Whether a larger allocation
/// succeeds depends on the memory of the client machine.
const MAX_ALLOCATION: usize = 1 << 31;

/// Which of the three buffered classes an object belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Reader,
    Writer,
    Random,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Reader => "BufferedReader",
            Kind::Writer => "BufferedWriter",
            Kind::Random => "BufferedRandom",
        }
    }

    fn qualified(self) -> &'static str {
        match self {
            Kind::Reader => "_io.BufferedReader",
            Kind::Writer => "_io.BufferedWriter",
            Kind::Random => "_io.BufferedRandom",
        }
    }

    fn readable(self) -> bool {
        matches!(self, Kind::Reader | Kind::Random)
    }

    fn writable(self) -> bool {
        matches!(self, Kind::Writer | Kind::Random)
    }
}

/// Whether a buffered object can be used.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Uninitialized,
    Ready,
    Detached,
}

struct Buffered {
    kind: Kind,
    status: Cell<Status>,
    /// The raw stream. A failed re-initialization leaves the object
    /// unusable but keeps a stream here, which the `raw` member reports.
    raw: RefCell<Option<Value>>,
    core: RefCell<Core>,
    /// Set while a method talks to the raw stream; a nested call from the
    /// raw stream back into this object is refused.
    busy: Cell<bool>,
}

impl_native_data!(Buffered, "_io.Buffered");

/// The buffer and the positions within it. Offsets are signed: a rewind can
/// leave the raw offset behind the logical position, and a negative raw
/// offset means the raw position is not known relative to the buffer.
struct Core {
    buffer: Vec<u8>,
    readable: bool,
    writable: bool,

    /// The logical position.
    pos: i64,
    /// Where the raw stream is.
    raw_pos: i64,
    /// The end of the read-ahead, when there is read-ahead.
    read_end: Option<i64>,
    /// Pending writes span `write_start..write_end` when `write_end` is set;
    /// an empty span still counts as pending for position arithmetic.
    write_start: i64,
    write_end: Option<i64>,

    /// The absolute position of the raw stream as last observed.
    abs_pos: i64,
}

impl Core {
    fn new(size: usize, kind: Kind) -> Self {
        Self {
            buffer: vec![0; size],
            readable: kind.readable(),
            writable: kind.writable(),
            pos: 0,
            raw_pos: 0,
            read_end: None,
            write_start: 0,
            write_end: None,
            abs_pos: 0,
        }
    }

    fn size(&self) -> i64 {
        i64::try_from(self.buffer.len()).unwrap_or(i64::MAX)
    }

    fn read_valid(&self) -> bool {
        self.readable && self.read_end.is_some()
    }

    fn write_valid(&self) -> bool {
        self.writable && self.write_end.is_some()
    }

    /// Bytes of read-ahead after the logical position. It can be negative
    /// after pending writes moved the position past the read data.
    fn readahead(&self) -> i64 {
        match self.read_end {
            Some(end) if self.readable => end - self.pos,
            _ => 0,
        }
    }

    /// How far the raw stream is ahead of the logical position, when either
    /// buffer is in use and the raw position is known.
    fn raw_offset(&self) -> i64 {
        if (self.read_valid() || self.write_valid()) && self.raw_pos >= 0 {
            self.raw_pos - self.pos
        } else {
            0
        }
    }

    /// Moves the logical position; written bytes past the read-ahead extend
    /// it.
    fn advance_to(&mut self, position: i64) {
        self.pos = position;
        if self.read_valid() && self.read_end.is_some_and(|end| end < position) {
            self.read_end = Some(position);
        }
    }

    fn reset_read(&mut self) {
        self.read_end = None;
    }

    fn reset_write(&mut self) {
        self.write_start = 0;
        self.write_end = None;
    }

    fn clamp(&self, offset: i64) -> usize {
        usize::try_from(offset.clamp(0, self.size())).unwrap_or(0)
    }

    fn slice(&self, start: i64, end: i64) -> Vec<u8> {
        let start = self.clamp(start);
        let end = self.clamp(end).max(start);

        self.buffer[start..end].to_vec()
    }

    fn store(&mut self, start: i64, data: &[u8]) {
        let start = self.clamp(start);
        let end = (start + data.len()).min(self.buffer.len());
        self.buffer[start..end].copy_from_slice(&data[..end - start]);
    }
}

/// Clears the busy flag when a raw-stream section ends.
struct Entered<'a>(&'a Cell<bool>);

impl Drop for Entered<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    for kind in [Kind::Reader, Kind::Writer, Kind::Random] {
        set_attribute(vm, module, kind.name(), Value::Object(buffered_type(vm, kind)?))?;
    }

    set_attribute(vm, module, "BufferedRWPair", Value::Object(pair_type(vm)?))
}

pub fn buffered_type(vm: &Vm, kind: Kind) -> PyResult<ObjectRef> {
    match kind {
        Kind::Reader => native_type(vm, "_io.BufferedReader", |vm| create_type(vm, Kind::Reader)),
        Kind::Writer => native_type(vm, "_io.BufferedWriter", |vm| create_type(vm, Kind::Writer)),
        Kind::Random => native_type(vm, "_io.BufferedRandom", |vm| create_type(vm, Kind::Random)),
    }
}

fn create_type(vm: &Vm, kind: Kind) -> PyResult<ObjectRef> {
    let mut methods: Vec<MethodSpec> = vec![
        method("__repr__", buffered_repr),
        method("__sizeof__", buffered_sizeof),
        method("close", buffered_close),
        method("detach", buffered_detach),
        method("fileno", |vm, args| forward_no_arguments(vm, args, "fileno")),
        method("flush", buffered_flush),
        method("isatty", |vm, args| forward_no_arguments(vm, args, "isatty")),
        method("readable", |vm, args| forward_no_arguments(vm, args, "readable")),
        method("seek", buffered_seek),
        method("seekable", |vm, args| forward_no_arguments(vm, args, "seekable")),
        method("tell", buffered_tell),
        method("truncate", buffered_truncate),
        method("writable", |vm, args| forward_no_arguments(vm, args, "writable")),
    ];
    let constructor = match kind {
        Kind::Reader => [static_method("__new__", |vm, args| buffered_new(vm, args, Kind::Reader)), method("__init__", |vm, args| buffered_init(vm, args, Kind::Reader))],
        Kind::Writer => [static_method("__new__", |vm, args| buffered_new(vm, args, Kind::Writer)), method("__init__", |vm, args| buffered_init(vm, args, Kind::Writer))],
        Kind::Random => [static_method("__new__", |vm, args| buffered_new(vm, args, Kind::Random)), method("__init__", |vm, args| buffered_init(vm, args, Kind::Random))],
    };
    methods.extend(constructor);
    if kind.readable() {
        methods.extend([
            method("next", buffered_next),
            method("peek", buffered_peek),
            method("read", buffered_read),
            method("read1", buffered_read1),
            method("readline", buffered_readline),
        ]);
    }
    if kind.writable() {
        methods.push(method("write", buffered_write));
    }
    if kind == Kind::Random {
        methods.push(method("readinto", buffered_readinto));
    }

    let class = new_type(
        vm,
        TypeSpec {
            name: kind.name(),
            module: "_io",
            base: Some(buffered_base_type(vm)?),
            layout: Layout::Native,
            instance_dict: true,
            methods: &methods,
        },
    )?;
    let owner = kind.qualified();
    add_getset(vm, &class, GetSet { name: "closed", owner, get: buffered_closed, set: None })?;
    add_getset(vm, &class, GetSet { name: "name", owner, get: |vm, getset, instance| raw_attribute(vm, getset, instance, "name"), set: None })?;
    add_getset(vm, &class, GetSet { name: "mode", owner, get: |vm, getset, instance| raw_attribute(vm, getset, instance, "mode"), set: None })?;
    add_member(vm, &class, GetSet { name: "raw", owner, get: buffered_raw, set: None })?;

    Ok(class)
}

fn long(value: i64) -> Value {
    Value::long(BigInt::from(value))
}

fn bytes_value(data: Vec<u8>) -> Value {
    Value::Str(PyBytes::new(data))
}

fn uninitialized(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "I/O operation on uninitialized object")
}

fn detached(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "raw stream has been detached")
}

fn io_error(vm: &Vm, message: &str) -> Signal {
    vm.raise(ExceptionKind::IOError, message)
}

/// The `BlockingIOError` of a write that could only partly complete.
fn blocked(vm: &Vm, written: i64) -> Signal {
    let class = vm.native_state::<IoState>().blocking_io_error.borrow().clone();
    let Some(class) = class else {
        return io_error(vm, BLOCKED_MESSAGE);
    };

    match vm.instantiate_exception(&class, vec![Value::Int(0), Value::str(BLOCKED_MESSAGE), Value::Int(written)]) {
        Ok(error) => Signal::Raise(error),
        Err(signal) => signal,
    }
}

impl Buffered {
    fn new(kind: Kind) -> Self {
        Self { kind, status: Cell::new(Status::Uninitialized), raw: RefCell::new(None), core: RefCell::new(Core::new(0, kind)), busy: Cell::new(false) }
    }

    /// The raw stream, or the error of an object that cannot be used.
    fn raw(&self, vm: &Vm) -> PyResult<Value> {
        match self.status.get() {
            Status::Ready => self.raw.borrow().clone().ok_or_else(|| uninitialized(vm)),
            Status::Uninitialized => Err(uninitialized(vm)),
            Status::Detached => Err(detached(vm)),
        }
    }

    /// Marks the start of a section that calls the raw stream.
    fn enter(&self, vm: &Vm, this: &Value) -> PyResult<Entered<'_>> {
        if self.busy.get() {
            let repr = vm.repr_text(this)?;
            return Err(vm.raise(ExceptionKind::RuntimeError, &format!("reentrant call inside {repr}")));
        }
        self.busy.set(true);

        Ok(Entered(&self.busy))
    }
}

/// The receiver of a method of `kind`'s class.
fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str, kind: Option<Kind>) -> PyResult<(&'a Value, &'a Buffered)> {
    let Some(this) = args.positional.first() else {
        let owner = kind.map_or("_io._BufferedIOBase", Kind::qualified);
        return Err(vm.type_error(&format!("descriptor '{method}' of '{owner}' object needs an argument")));
    };
    require_known(this, method)?;

    match native_data::<Buffered>(this) {
        Some(buffered) if kind.is_none_or(|kind| kind == buffered.kind) => Ok((this, buffered)),
        _ => {
            let owner = kind.map_or("_io._BufferedIOBase", Kind::qualified);
            Err(vm.type_error(&format!("descriptor '{method}' requires a '{owner}' object but received a '{}'", vm.type_name(this))))
        }
    }
}

fn getset_receiver<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Buffered> {
    native_data::<Buffered>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

fn buffered_new(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &buffered_type(vm, kind)?)?;

    Ok(new_native_object(vm, &class, Buffered::new(kind)))
}

/// Issues a `DeprecationWarning` attributed to the caller.
fn deprecation_warning(vm: &Vm, message: &str) -> PyResult<()> {
    let module = vm.import_module("_warnings")?;
    let warn = vm.getattr_str(&module, "warn")?;
    let category = Value::Object(Rc::clone(vm.types().exception(ExceptionKind::DeprecationWarning)));
    vm.call(&warn, CallArgs::new(vec![Value::str(message), category, Value::Int(1)]))?;

    Ok(())
}

/// Requires `raw.<capability>()` to return `True`.
fn require_capability(vm: &Vm, raw: &Value, capability: &str) -> PyResult<()> {
    let result = vm.call_method(raw, capability, Vec::new())?;
    require_known(&result, capability)?;
    if matches!(result, Value::Bool(true)) {
        return Ok(());
    }

    Err(io_error(vm, &format!("File or stream is not {capability}.")))
}

fn buffered_init(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (_, buffered) = receiver(vm, &args, "__init__", Some(kind))?;
    buffered.status.set(Status::Uninitialized);
    let names: &[&str] = if kind == Kind::Reader { &["raw", "buffer_size"] } else { &["raw", "buffer_size", "max_buffer_size"] };
    let slots = parse(vm, after_receiver(&args), kind.name(), names, 0)?;

    let Some(raw) = slots[0].clone() else {
        return Err(missing_argument(vm, "raw", 1));
    };
    let size = match &slots[1] {
        Some(value) => ssize_argument(vm, value)?,
        None => DEFAULT_BUFFER_SIZE,
    };
    let max_size = match slots.get(2).and_then(Option::as_ref) {
        Some(value) => ssize_argument(vm, value)?,
        None => MAX_BUFFER_SIZE_DEFAULT,
    };

    if max_size != MAX_BUFFER_SIZE_DEFAULT {
        deprecation_warning(vm, "max_buffer_size is deprecated")?;
    }
    if kind == Kind::Random {
        require_capability(vm, &raw, "seekable")?;
    }
    if kind.readable() {
        require_capability(vm, &raw, "readable")?;
    }
    if kind.writable() {
        require_capability(vm, &raw, "writable")?;
    }

    *buffered.raw.borrow_mut() = Some(raw.clone());
    if size <= 0 {
        *buffered.core.borrow_mut() = Core::new(0, kind);
        return Err(vm.raise(ExceptionKind::ValueError, "buffer size must be strictly positive"));
    }
    // Whether a larger allocation succeeds depends on the client machine's
    // memory, so such sizes are not reproduced.
    let Some(size) = usize::try_from(size).ok().filter(|size| *size <= MAX_ALLOCATION) else {
        return Err(vm.halt_unsupported("buffered stream buffer above 2 GiB"));
    };

    *buffered.core.borrow_mut() = Core::new(size, kind);
    // A raw stream that cannot tell its position leaves the cached position
    // at zero.
    match raw_tell(vm, &raw, &buffered.core) {
        Ok(_) | Err(Signal::Raise(_)) => {}
        Err(halt) => return Err(halt),
    }
    buffered.status.set(Status::Ready);

    Ok(Value::None)
}

/// A byte count returned by `raw.readinto` or `raw.write`. A result that is
/// not an index counts as -1, which the caller then reports as an invalid
/// length in place of the conversion error.
fn raw_count(vm: &Vm, value: &Value, context: &str) -> PyResult<i64> {
    require_known(value, context)?;

    match vm.index_as_ssize(value, Some(ExceptionKind::ValueError)) {
        Ok(count) => Ok(count),
        Err(Signal::Raise(_)) => Ok(-1),
        Err(halt) => Err(halt),
    }
}

/// A file offset: an index that must fit in a signed 64-bit integer.
fn offset_value(vm: &Vm, value: &Value, context: &str) -> PyResult<i64> {
    require_known(value, context)?;
    let index = vm.number_index(value)?;

    vm.as_integral(&index).and_then(|integral| integral.to_i64()).ok_or_else(|| vm.raise(ExceptionKind::ValueError, &format!("cannot fit '{}' into an offset-sized integer", vm.type_name(value))))
}

/// `raw.readinto` of a fresh `length`-byte view. `None` when the raw stream
/// would block.
fn raw_readinto(vm: &Vm, raw: &Value, length: i64) -> PyResult<Option<Vec<u8>>> {
    let length_bytes = usize::try_from(length).unwrap_or(0);
    let array = vm.new_bytearray(vec![0; length_bytes]);
    let view = new_memoryview(vm, &array)?;

    let result = vm.call_method(raw, "readinto", vec![view])?;
    if result.is_none() {
        return Ok(None);
    }
    let count = raw_count(vm, &result, "readinto result")?;
    if count < 0 || count > length {
        return Err(io_error(vm, &format!("raw readinto() returned invalid length {count} (should have been between 0 and {length})")));
    }

    let Some(mut data) = vm.as_bytearray(&array) else {
        return Err(vm.type_error("readinto buffer is not a bytearray"));
    };
    data.truncate(usize::try_from(count).unwrap_or(0));

    Ok(Some(data))
}

/// `raw.write` of a read-only view of `data`. `None` when the raw stream
/// would block.
fn raw_write(vm: &Vm, raw: &Value, data: &[u8]) -> PyResult<Option<i64>> {
    let view = new_memoryview(vm, &bytes_value(data.to_vec()))?;
    let result = vm.call_method(raw, "write", vec![view])?;
    if result.is_none() {
        return Ok(None);
    }

    let length = i64::try_from(data.len()).unwrap_or(i64::MAX);
    let count = raw_count(vm, &result, "write result")?;
    if count < 0 || count > length {
        return Err(io_error(vm, &format!("raw write() returned invalid length {count} (should have been between 0 and {length})")));
    }

    Ok(Some(count))
}

fn checked_position(vm: &Vm, result: &Value, core: &RefCell<Core>) -> PyResult<i64> {
    let position = offset_value(vm, result, "raw position")?;
    if position < 0 {
        return Err(io_error(vm, &format!("Raw stream returned invalid position {position}")));
    }
    core.borrow_mut().abs_pos = position;

    Ok(position)
}

fn raw_seek(vm: &Vm, raw: &Value, core: &RefCell<Core>, target: i64, whence: i64) -> PyResult<i64> {
    let result = vm.call_method(raw, "seek", vec![long(target), long(whence)])?;

    checked_position(vm, &result, core)
}

fn raw_tell(vm: &Vm, raw: &Value, core: &RefCell<Core>) -> PyResult<i64> {
    let result = vm.call_method(raw, "tell", Vec::new())?;

    checked_position(vm, &result, core)
}

fn check_closed(vm: &Vm, raw: &Value, message: &str) -> PyResult<()> {
    let closed = vm.getattr_str(raw, "closed")?;
    require_known(&closed, "closed")?;
    if vm.truthy(&closed, "closed")? {
        return Err(vm.raise(ExceptionKind::ValueError, message));
    }

    Ok(())
}

/// The operations on one buffered object and its raw stream.
struct Stream<'a> {
    vm: &'a Vm,
    raw: Value,
    core: &'a RefCell<Core>,
}

impl Stream<'_> {
    fn seek_relative(&self, offset: i64) -> PyResult<i64> {
        raw_seek(self.vm, &self.raw, self.core, offset, 1)
    }

    /// Positions near the limits of a signed 64-bit integer wrap around, as
    /// in the reference.
    fn add_to_position(&self, count: i64) {
        let mut core = self.core.borrow_mut();
        core.abs_pos = core.abs_pos.wrapping_add(count);
    }

    /// Reads into the buffer after the read-ahead (or at its start), as
    /// much as fits. `None` when the raw stream would block.
    fn fill_buffer(&self) -> PyResult<Option<i64>> {
        let (start, length) = {
            let core = self.core.borrow();
            let start = if core.read_valid() { core.read_end.unwrap_or(0) } else { 0 };
            (start, core.size() - start)
        };

        let Some(data) = raw_readinto(self.vm, &self.raw, length)? else {
            return Ok(None);
        };
        let count = i64::try_from(data.len()).unwrap_or(0);
        if count > 0 {
            self.add_to_position(count);
            let mut core = self.core.borrow_mut();
            core.store(start, &data);
            core.read_end = Some(start + count);
            core.raw_pos = start + count;
        }

        Ok(Some(count))
    }

    /// Writes the pending bytes, first moving the raw stream back to them.
    fn flush_pending(&self) -> PyResult<()> {
        let rewind = {
            let core = self.core.borrow();
            if !core.write_valid() || core.write_end == Some(core.write_start) {
                return Ok(());
            }
            core.raw_offset() + (core.pos - core.write_start)
        };
        if rewind != 0 {
            self.seek_relative(-rewind)?;
            self.core.borrow_mut().raw_pos -= rewind;
        }

        loop {
            let (start, pending) = {
                let core = self.core.borrow();
                let end = core.write_end.unwrap_or(core.write_start);
                if core.write_start >= end {
                    break;
                }
                (core.write_start, core.slice(core.write_start, end))
            };
            let Some(count) = raw_write(self.vm, &self.raw, &pending)? else {
                return Err(blocked(self.vm, 0));
            };
            self.add_to_position(count);
            let mut core = self.core.borrow_mut();
            core.write_start = start + count;
            core.raw_pos = core.write_start;
        }

        self.core.borrow_mut().reset_write();

        Ok(())
    }

    /// Writes the pending bytes, then for readable streams moves the raw
    /// stream to the logical position and drops the read-ahead.
    fn flush_and_rewind(&self) -> PyResult<()> {
        self.flush_pending()?;
        if !self.core.borrow().readable {
            return Ok(());
        }

        let rewind = self.core.borrow().raw_offset();
        let moved = self.seek_relative(-rewind);
        self.core.borrow_mut().reset_read();
        moved?;

        Ok(())
    }

    fn take(&self, count: i64) -> Vec<u8> {
        let mut core = self.core.borrow_mut();
        let data = core.slice(core.pos, core.pos + count);
        core.pos += count;

        data
    }

    fn read(&self, size: i64) -> PyResult<Value> {
        let available = self.core.borrow().readahead();
        if size <= available {
            return Ok(bytes_value(self.take(size)));
        }

        self.read_generic(size)
    }

    fn read_all(&self) -> PyResult<Value> {
        let mut data = {
            let mut core = self.core.borrow_mut();
            match core.read_end {
                Some(end) if core.readable => {
                    let data = core.slice(core.pos, end);
                    core.pos = end;
                    data
                }
                _ => Vec::new(),
            }
        };
        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }
        self.core.borrow_mut().reset_read();

        loop {
            let chunk = self.vm.call_method(&self.raw, "read", Vec::new())?;
            require_known(&chunk, "raw read result")?;
            if chunk.is_none() {
                if data.is_empty() {
                    return Ok(Value::None);
                }
                break;
            }
            let Some(chunk) = self.vm.as_str_bytes(&chunk) else {
                return Err(self.vm.type_error("read() should return bytes"));
            };
            if chunk.as_bytes().is_empty() {
                break;
            }
            self.add_to_position(i64::try_from(chunk.as_bytes().len()).unwrap_or(0));
            data.extend_from_slice(chunk.as_bytes());
        }

        Ok(bytes_value(data))
    }

    /// A read the read-ahead cannot satisfy: whole multiples of the buffer
    /// size go straight to the result, the rest through the buffer.
    fn read_generic(&self, size: i64) -> PyResult<Value> {
        let mut data = {
            let available = self.core.borrow().readahead().max(0);
            self.take(available)
        };
        let mut remaining = size - i64::try_from(data.len()).unwrap_or(0);

        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }
        self.core.borrow_mut().reset_read();

        let buffer_size = self.core.borrow().size();
        while remaining > 0 {
            let direct = remaining - remaining % buffer_size;
            if direct == 0 {
                break;
            }
            match raw_readinto(self.vm, &self.raw, direct)? {
                None => return Ok(if data.is_empty() { Value::None } else { bytes_value(data) }),
                Some(chunk) if chunk.is_empty() => return Ok(bytes_value(data)),
                Some(chunk) => {
                    let count = i64::try_from(chunk.len()).unwrap_or(0);
                    self.add_to_position(count);
                    remaining -= count;
                    data.extend_from_slice(&chunk);
                }
            }
        }

        {
            let mut core = self.core.borrow_mut();
            core.pos = 0;
            core.raw_pos = 0;
            core.read_end = Some(0);
        }
        while remaining > 0 && self.core.borrow().read_end.is_some_and(|end| end < buffer_size) {
            match self.fill_buffer()? {
                None => return Ok(if data.is_empty() { Value::None } else { bytes_value(data) }),
                Some(0) => return Ok(bytes_value(data)),
                Some(count) => {
                    let taken = count.min(remaining);
                    data.extend(self.take(taken));
                    remaining -= taken;
                }
            }
        }

        Ok(bytes_value(data))
    }

    fn read1(&self, size: i64) -> PyResult<Value> {
        let available = self.core.borrow().readahead();
        if available > 0 {
            return Ok(bytes_value(self.take(size.min(available))));
        }

        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }
        self.core.borrow_mut().reset_read();
        let count = self.fill_buffer()?.unwrap_or(0);

        let taken = size.min(count);
        let mut core = self.core.borrow_mut();
        let data = core.slice(0, taken);
        core.pos = taken;

        Ok(bytes_value(data))
    }

    fn peek(&self) -> PyResult<Value> {
        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }

        {
            let core = self.core.borrow();
            let available = core.readahead();
            if available > 0 {
                return Ok(bytes_value(core.slice(core.pos, core.pos + available)));
            }
        }

        self.core.borrow_mut().reset_read();
        let count = self.fill_buffer()?.unwrap_or(0);
        let mut core = self.core.borrow_mut();
        core.pos = 0;

        Ok(bytes_value(core.slice(0, count)))
    }

    /// A line of at most `limit` bytes (unlimited when negative). Lines
    /// spanning several buffer loads are read into the start of the buffer
    /// each time; the logical position only moves where the line ends.
    fn readline(&self, mut limit: i64) -> PyResult<Vec<u8>> {
        let mut line = {
            let mut core = self.core.borrow_mut();
            let available = core.readahead();
            let window = if limit >= 0 { available.min(limit) } else { available };
            let chunk = core.slice(core.pos, core.pos + window);
            if let Some(index) = chunk.iter().position(|byte| *byte == b'\n') {
                core.pos += i64::try_from(index).unwrap_or(0) + 1;
                return Ok(chunk[..=index].to_vec());
            }
            core.pos += window;
            if limit >= 0 {
                limit -= window;
            }
            chunk
        };
        if limit == 0 {
            return Ok(line);
        }

        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }

        loop {
            self.core.borrow_mut().reset_read();
            let count = match self.fill_buffer()? {
                Some(count) if count > 0 => count,
                _ => break,
            };
            let window = if limit >= 0 { count.min(limit) } else { count };
            let chunk = self.core.borrow().slice(0, window);
            if let Some(index) = chunk.iter().position(|byte| *byte == b'\n') {
                line.extend_from_slice(&chunk[..=index]);
                self.core.borrow_mut().pos = i64::try_from(index).unwrap_or(0) + 1;
                break;
            }
            line.extend_from_slice(&chunk);
            if window == limit {
                self.core.borrow_mut().pos = window;
                break;
            }
            if limit >= 0 {
                limit -= window;
            }
        }

        Ok(line)
    }

    fn write(&self, data: &[u8]) -> PyResult<i64> {
        let length = i64::try_from(data.len()).unwrap_or(i64::MAX);

        // Data that fits after the position goes into the buffer.
        {
            let mut core = self.core.borrow_mut();
            if !core.read_valid() && !core.write_valid() {
                core.pos = 0;
                core.raw_pos = 0;
            }
            if length <= core.size() - core.pos {
                let start = core.pos;
                core.store(start, data);
                if !core.write_valid() || core.write_start > start {
                    core.write_start = start;
                }
                core.advance_to(start + length);
                if core.write_end.is_none_or(|end| core.pos > end) {
                    core.write_end = Some(core.pos);
                }
                return Ok(length);
            }
        }

        if let Err(signal) = self.flush_pending() {
            if !self.is_blocked(&signal) {
                return Err(signal);
            }
            return self.buffer_after_blocked_flush(data);
        }

        let offset = self.core.borrow().raw_offset();
        if offset != 0 {
            self.seek_relative(-offset)?;
            self.core.borrow_mut().raw_pos -= offset;
        }

        let buffer_size = self.core.borrow().size();
        let mut written = 0usize;
        let mut remaining = length;
        while remaining > buffer_size {
            let Some(count) = raw_write(self.vm, &self.raw, &data[written..])? else {
                // Keep one buffer's worth; the rest is reported unwritten.
                let mut core = self.core.borrow_mut();
                let end = (written + core.buffer.len()).min(data.len());
                core.store(0, &data[written..end]);
                core.raw_pos = 0;
                let full = core.size();
                core.advance_to(full);
                core.write_end = Some(full);
                drop(core);
                return Err(blocked(self.vm, i64::try_from(written).unwrap_or(0) + buffer_size));
            };
            self.add_to_position(count);
            written += usize::try_from(count).unwrap_or(0);
            remaining -= count;
        }

        let mut core = self.core.borrow_mut();
        if core.readable {
            core.reset_read();
        }
        core.reset_write();
        core.store(0, &data[written..]);
        core.write_start = 0;
        core.write_end = Some(remaining);
        core.advance_to(remaining);
        core.raw_pos = 0;

        Ok(length)
    }

    fn is_blocked(&self, signal: &Signal) -> bool {
        let Signal::Raise(error) = signal else {
            return false;
        };
        let class = self.vm.native_state::<IoState>().blocking_io_error.borrow().clone();

        class.is_some_and(|class| self.vm.is_instance_of(error, &class).unwrap_or(false))
    }

    /// After the pending bytes could not be flushed: move them to the front
    /// and buffer as much of `data` as then fits.
    fn buffer_after_blocked_flush(&self, data: &[u8]) -> PyResult<i64> {
        let mut core = self.core.borrow_mut();
        let start = core.write_start;
        let end = core.write_end.unwrap_or(start);
        let pending = core.slice(start, end);
        core.store(0, &pending);
        core.write_end = Some(end - start);
        core.raw_pos -= start;
        core.pos -= start;
        core.write_start = 0;
        if core.readable {
            core.reset_read();
        }

        let filled = core.write_end.unwrap_or(0);
        let room = core.size() - filled;
        let length = i64::try_from(data.len()).unwrap_or(i64::MAX);
        let taken = length.min(room);
        let taken_bytes = usize::try_from(taken).unwrap_or(0);
        core.store(filled, &data[..taken_bytes]);
        core.write_end = Some(filled + taken);
        core.pos += taken;
        drop(core);

        if length <= room {
            return Ok(length);
        }

        Err(blocked(self.vm, taken))
    }

    fn tell(&self) -> PyResult<i64> {
        let position = raw_tell(self.vm, &self.raw, self.core)?;

        Ok(position.wrapping_sub(self.core.borrow().raw_offset()))
    }

    fn seek(&self, target: i64, whence: i64) -> PyResult<i64> {
        // A target inside the read-ahead only moves the position.
        if whence != 2 && self.core.borrow().readable {
            let current = self.core.borrow().abs_pos;
            let mut core = self.core.borrow_mut();
            let available = core.readahead();
            if available > 0 {
                let offset = if whence == 0 { target.wrapping_sub(current.wrapping_sub(core.raw_offset())) } else { target };
                if offset >= -core.pos && offset <= available {
                    core.pos += offset;
                    return Ok(current.wrapping_sub(available).wrapping_add(offset));
                }
            }
        }

        if self.core.borrow().writable {
            self.flush_pending()?;
            self.core.borrow_mut().reset_write();
        }

        let mut target = target;
        if whence == 1 {
            let core = self.core.borrow();
            if core.read_valid() && core.raw_pos >= 0 {
                target = target.wrapping_sub(core.raw_pos - core.pos);
            }
        }

        let position = raw_seek(self.vm, &self.raw, self.core, target, whence)?;
        let mut core = self.core.borrow_mut();
        core.raw_pos = -1;
        if core.readable {
            core.reset_read();
        }

        Ok(position)
    }

    fn truncate(&self, position: Value) -> PyResult<Value> {
        if self.core.borrow().writable {
            self.flush_and_rewind()?;
        }

        let result = self.vm.call_method(&self.raw, "truncate", vec![position])?;
        match raw_tell(self.vm, &self.raw, self.core) {
            Ok(_) | Err(Signal::Raise(_)) => {}
            Err(halt) => return Err(halt),
        }

        Ok(result)
    }
}

/// Methods taking positional arguments only refuse keywords before
/// anything else is checked.
fn reject_keywords(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    Ok(())
}

/// The receiver, its raw stream, and the operations on them.
fn stream<'a>(vm: &'a Vm, buffered: &'a Buffered) -> PyResult<Stream<'a>> {
    Ok(Stream { vm, raw: buffered.raw(vm)?, core: &buffered.core })
}

fn buffered_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    // The largest size whose result string is not refused outright; the
    // limit leaves room for the string header.
    const LARGEST_RESULT: i64 = i64::MAX - 33;

    let (this, buffered) = receiver(vm, &args, "read", None)?;
    reject_keywords(vm, &args, "read")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "read", 0, 1)?;
    let size = size_argument(vm, rest.first())?.unwrap_or(-1);
    if size < -1 {
        return Err(vm.raise(ExceptionKind::ValueError, "read length must be positive or -1"));
    }
    check_closed(vm, &stream.raw, "read of closed file")?;

    if size == -1 {
        let _entered = buffered.enter(vm, this)?;
        return stream.read_all();
    }

    let available = buffered.core.borrow().readahead();
    if size <= available {
        return Ok(bytes_value(stream.take(size)));
    }

    // The result is allocated whole before the raw stream is called.
    if size > LARGEST_RESULT {
        return Err(vm.raise(ExceptionKind::OverflowError, "string is too large"));
    }
    if usize::try_from(size).is_ok_and(|size| size > MAX_ALLOCATION) {
        return Err(vm.halt_unsupported("buffered read above 2 GiB"));
    }

    let _entered = buffered.enter(vm, this)?;
    stream.read(size)
}

fn buffered_read1(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "read1", None)?;
    reject_keywords(vm, &args, "read1")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "read1", 1, 1)?;
    let size = ssize_argument(vm, &rest[0])?;
    if size < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "read length must be positive"));
    }
    if size == 0 {
        return Ok(bytes_value(Vec::new()));
    }

    let _entered = buffered.enter(vm, this)?;
    stream.read1(size)
}

fn buffered_peek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "peek", None)?;
    reject_keywords(vm, &args, "peek")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "peek", 0, 1)?;
    if let Some(size) = rest.first() {
        ssize_argument(vm, size)?;
    }

    let _entered = buffered.enter(vm, this)?;
    stream.peek()
}

fn buffered_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "readline", None)?;
    reject_keywords(vm, &args, "readline")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "readline", 0, 1)?;
    let limit = size_argument(vm, rest.first())?.unwrap_or(-1);
    check_closed(vm, &stream.raw, "readline of closed file")?;

    let _entered = buffered.enter(vm, this)?;
    Ok(bytes_value(stream.readline(limit)?))
}

fn buffered_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "next", None)?;
    slot_no_arguments(vm, &args, "next")?;
    let stream = stream(vm, buffered)?;
    check_closed(vm, &stream.raw, "readline of closed file")?;

    let line = {
        let _entered = buffered.enter(vm, this)?;
        stream.readline(-1)?
    };
    if line.is_empty() {
        return Err(stop_iteration(vm));
    }

    Ok(bytes_value(line))
}

/// `readinto` of `BufferedRandom`: reads through the `read` method.
fn buffered_readinto(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "readinto", Some(Kind::Random))?;
    reject_keywords(vm, &args, "readinto")?;
    buffered.raw(vm)?;
    let target = readinto_target(vm, &args, Some("readinto"))?;

    let length = i64::try_from(target.len()).unwrap_or(i64::MAX);
    let data = vm.call_method(this, "read", vec![Value::Int(length)])?;
    require_known(&data, "read result")?;
    let Some(data) = vm.as_str_bytes(&data) else {
        return Err(vm.type_error("read() should return bytes"));
    };
    target.write(0, data.as_bytes());

    Ok(long(i64::try_from(data.as_bytes().len()).unwrap_or(i64::MAX)))
}

fn buffered_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "write", None)?;
    reject_keywords(vm, &args, "write")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "write", 1, 1)?;
    let _hold = hold_buffer(&rest[0]);
    let data = string_or_buffer(vm, "write", 1, &rest[0])?;

    let _entered = buffered.enter(vm, this)?;
    check_closed(vm, &stream.raw, "write to closed file")?;
    let written = stream.write(data.as_bytes())?;

    Ok(long(written))
}

fn buffered_flush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "flush", None)?;
    method_no_arguments(vm, &args, "flush")?;
    let stream = stream(vm, buffered)?;
    if buffered.kind == Kind::Reader {
        return vm.call_method(&stream.raw, "flush", Vec::new());
    }
    check_closed(vm, &stream.raw, "flush of closed file")?;

    let _entered = buffered.enter(vm, this)?;
    stream.flush_and_rewind()?;

    Ok(Value::None)
}

fn buffered_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, buffered) = receiver(vm, &args, "tell", None)?;
    method_no_arguments(vm, &args, "tell")?;
    let stream = stream(vm, buffered)?;

    Ok(long(stream.tell()?))
}

fn buffered_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "seek", None)?;
    reject_keywords(vm, &args, "seek")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "seek", 1, 2)?;
    let whence = match rest.get(1) {
        Some(value) => i64::from(int_argument(vm, value, "seek whence")?),
        None => 0,
    };
    if !(0..=2).contains(&whence) {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("whence must be between 0 and 2, not {whence}")));
    }
    check_closed(vm, &stream.raw, "seek of closed file")?;
    let target = offset_value(vm, &rest[0], "seek target")?;

    let _entered = buffered.enter(vm, this)?;
    Ok(long(stream.seek(target, whence)?))
}

fn buffered_truncate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "truncate", None)?;
    reject_keywords(vm, &args, "truncate")?;
    let stream = stream(vm, buffered)?;
    let rest = method_arguments(vm, &args, "truncate", 0, 1)?;
    let position = rest.into_iter().next().unwrap_or(Value::None);

    let _entered = buffered.enter(vm, this)?;
    stream.truncate(position)
}

/// `close`: flushes through the `flush` method, then closes the raw stream
/// even when the flush failed. A failure to close wins over the flush's.
fn buffered_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "close", None)?;
    method_no_arguments(vm, &args, "close")?;
    let raw = buffered.raw(vm)?;

    let closed = {
        let _entered = buffered.enter(vm, this)?;
        let closed = vm.getattr_str(&raw, "closed")?;
        require_known(&closed, "closed")?;
        vm.truthy(&closed, "closed")?
    };
    if closed {
        return Ok(Value::None);
    }

    let flushed = vm.call_method(this, "flush", Vec::new());
    if let Err(Signal::Halt(halt)) = flushed {
        return Err(Signal::Halt(halt));
    }
    vm.call_method(&raw, "close", Vec::new())?;
    flushed?;

    Ok(Value::None)
}

fn buffered_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, buffered) = receiver(vm, &args, "detach", None)?;
    method_no_arguments(vm, &args, "detach")?;
    let raw = buffered.raw(vm)?;

    vm.call_method(this, "flush", Vec::new())?;
    buffered.status.set(Status::Detached);
    *buffered.raw.borrow_mut() = None;

    Ok(raw)
}

/// A method answered by the raw stream's method of the same name.
fn forward_no_arguments(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (_, buffered) = receiver(vm, &args, name, None)?;
    method_no_arguments(vm, &args, name)?;
    let raw = buffered.raw(vm)?;

    vm.call_method(&raw, name, Vec::new())
}

fn buffered_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, buffered) = receiver(vm, &args, "__sizeof__", None)?;
    method_no_arguments(vm, &args, "__sizeof__")?;
    let buffer = buffered.core.borrow().buffer.len();

    Ok(long(BASIC_SIZE + i64::try_from(buffer).unwrap_or(0)))
}

/// `repr`: the type name, with the `name` attribute when it can be read.
fn buffered_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (this, _) = receiver(vm, &args, "__repr__", None)?;
    method_no_arguments(vm, &args, "__repr__")?;
    let type_name = vm.type_name(this);

    match vm.getattr_str(this, "name") {
        Ok(name) => {
            let name = vm.repr_text(&name)?;
            Ok(Value::str(&format!("<{type_name} name={name}>")))
        }
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::Exception) => Ok(Value::str(&format!("<{type_name}>"))),
        Err(signal) => Err(signal),
    }
}

fn buffered_closed(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let buffered = getset_receiver(vm, getset, instance)?;
    let raw = buffered.raw(vm)?;

    vm.getattr_str(&raw, "closed")
}

fn raw_attribute(vm: &Vm, getset: &GetSet, instance: &Value, name: &str) -> PyResult<Value> {
    let buffered = getset_receiver(vm, getset, instance)?;
    let raw = buffered.raw(vm)?;

    vm.getattr_str(&raw, name)
}

fn buffered_raw(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let buffered = getset_receiver(vm, getset, instance)?;

    Ok(buffered.raw.borrow().clone().unwrap_or(Value::None))
}

/// A `BufferedRWPair`: a reader and a writer over two raw streams.
struct Pair {
    sides: RefCell<Option<(Value, Value)>>,
}

impl_native_data!(Pair, "_io.BufferedRWPair");

pub fn pair_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io.BufferedRWPair", create_pair_type)
}

fn create_pair_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "BufferedRWPair",
            module: "_io",
            base: Some(buffered_base_type(vm)?),
            layout: Layout::Native,
            instance_dict: true,
            methods: &[
                static_method("__new__", pair_new),
                method("__init__", pair_init),
                method("close", pair_close),
                method("flush", |vm, args| pair_forward(vm, args, Side::Writer, "flush")),
                method("isatty", pair_isatty),
                method("peek", |vm, args| pair_forward(vm, args, Side::Reader, "peek")),
                method("read", |vm, args| pair_forward(vm, args, Side::Reader, "read")),
                method("read1", |vm, args| pair_forward(vm, args, Side::Reader, "read1")),
                method("readable", |vm, args| pair_forward(vm, args, Side::Reader, "readable")),
                method("readinto", |vm, args| pair_forward(vm, args, Side::Reader, "readinto")),
                method("writable", |vm, args| pair_forward(vm, args, Side::Writer, "writable")),
                method("write", |vm, args| pair_forward(vm, args, Side::Writer, "write")),
            ],
        },
    )?;
    add_getset(vm, &class, GetSet { name: "closed", owner: "_io.BufferedRWPair", get: pair_closed, set: None })?;

    Ok(class)
}

#[derive(Clone, Copy)]
enum Side {
    Reader,
    Writer,
}

fn pair_receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a Value, &'a Pair)> {
    let Some(this) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '_io.BufferedRWPair' object needs an argument")));
    };
    require_known(this, method)?;

    match native_data::<Pair>(this) {
        Some(pair) => Ok((this, pair)),
        None => Err(vm.type_error(&format!("descriptor '{method}' requires a '_io.BufferedRWPair' object but received a '{}'", vm.type_name(this)))),
    }
}

fn pair_sides(vm: &Vm, pair: &Pair) -> PyResult<(Value, Value)> {
    pair.sides.borrow().clone().ok_or_else(|| uninitialized(vm))
}

fn pair_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &pair_type(vm)?)?;

    Ok(new_native_object(vm, &class, Pair { sides: RefCell::new(None) }))
}

fn pair_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, pair) = pair_receiver(vm, &args, "__init__")?;
    // Keyword arguments are accepted and ignored.
    let rest = &args.positional[1..];
    if rest.len() < 2 {
        return Err(vm.type_error(&format!("BufferedRWPair() takes at least 2 arguments ({} given)", rest.len())));
    }
    if rest.len() > 4 {
        return Err(vm.type_error(&format!("BufferedRWPair() takes at most 4 arguments ({} given)", rest.len())));
    }

    let size = match rest.get(2) {
        Some(value) => ssize_argument(vm, value)?,
        None => DEFAULT_BUFFER_SIZE,
    };
    let max_size = match rest.get(3) {
        Some(value) => ssize_argument(vm, value)?,
        None => MAX_BUFFER_SIZE_DEFAULT,
    };
    if max_size != MAX_BUFFER_SIZE_DEFAULT {
        deprecation_warning(vm, "max_buffer_size is deprecated")?;
    }

    require_capability(vm, &rest[0], "readable")?;
    require_capability(vm, &rest[1], "writable")?;

    let reader_class = Value::Object(buffered_type(vm, Kind::Reader)?);
    let reader = vm.call(&reader_class, CallArgs::new(vec![rest[0].clone(), Value::Int(size)]))?;
    let writer_class = Value::Object(buffered_type(vm, Kind::Writer)?);
    let writer = vm.call(&writer_class, CallArgs::new(vec![rest[1].clone(), Value::Int(size)]))?;
    *pair.sides.borrow_mut() = Some((reader, writer));

    Ok(Value::None)
}

fn pair_forward(vm: &Vm, args: CallArgs, side: Side, name: &str) -> PyResult<Value> {
    let (_, pair) = pair_receiver(vm, &args, name)?;
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    let (reader, writer) = pair_sides(vm, pair)?;
    let target = match side {
        Side::Reader => reader,
        Side::Writer => writer,
    };

    vm.call_method(&target, name, args.positional[1..].to_vec())
}

/// `isatty`: the writer's answer unless it is `False`, then the reader's.
fn pair_isatty(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, pair) = pair_receiver(vm, &args, "isatty")?;
    method_no_arguments(vm, &args, "isatty")?;
    let (reader, writer) = pair_sides(vm, pair)?;

    let answer = vm.call_method(&writer, "isatty", Vec::new())?;
    if !matches!(answer, Value::Bool(false)) {
        return Ok(answer);
    }

    vm.call_method(&reader, "isatty", Vec::new())
}

/// `close`: closes the writer, then the reader even when that failed. The
/// reader's failure wins over the writer's.
fn pair_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, pair) = pair_receiver(vm, &args, "close")?;
    method_no_arguments(vm, &args, "close")?;
    let (reader, writer) = pair_sides(vm, pair)?;

    let written = vm.call_method(&writer, "close", Vec::new());
    if let Err(Signal::Halt(halt)) = written {
        return Err(Signal::Halt(halt));
    }
    vm.call_method(&reader, "close", Vec::new())?;
    written?;

    Ok(Value::None)
}

fn pair_closed(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(pair) = native_data::<Pair>(instance) else {
        return Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))));
    };
    let Some((_, writer)) = pair.sides.borrow().clone() else {
        return Err(vm.raise(ExceptionKind::RuntimeError, "the BufferedRWPair object is being garbage-collected"));
    };

    vm.getattr_str(&writer, "closed")
}
