//! `Connection` and `PipeConnection`, which share one implementation. The
//! handle and the read and write flags live in the object; transfers go
//! through the host.

use std::any::Any;
use std::cell::Cell;
use std::marker::PhantomData;

use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args::encode_default;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::static_method;
use crate::interp::buffer::BufferInterface;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::numbers::bigint_to_f64;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::handle_argument;
use super::int_value;
use super::long_bits;
use super::pickler;
use super::ssize_value;
use super::unnamed_arguments;

/// `INVALID_HANDLE_VALUE`.
const INVALID_HANDLE: u64 = u64::MAX;

/// Which of the two connection types an implementation serves.
trait Flavor: 'static {
    /// The class name.
    const NAME: &'static str;
    const TYPE_NAME: &'static str;
}

struct Socket;

impl Flavor for Socket {
    const NAME: &'static str = "Connection";
    const TYPE_NAME: &'static str = "_multiprocessing.Connection";
}

struct Pipe;

impl Flavor for Pipe {
    const NAME: &'static str = "PipeConnection";
    const TYPE_NAME: &'static str = "_multiprocessing.PipeConnection";
}

/// A `ConnectionObject`.
struct Connection<F> {
    /// `None` once a failed receive may have closed the handle.
    handle: Cell<Option<u64>>,
    /// `None` once a failed receive may have cleared the flag.
    readable: Cell<Option<bool>>,
    writable: bool,

    flavor: PhantomData<F>,
}

impl<F: Flavor> NativeData for Connection<F> {
    fn type_name(&self) -> &'static str {
        F::TYPE_NAME
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<F: Flavor> Connection<F> {
    /// The check that the connection is readable; `None` when the flag is unknown.
    fn check_readable(&self, vm: &Vm) -> PyResult<Option<()>> {
        match self.readable.get() {
            Some(true) => Ok(Some(())),
            Some(false) => Err(vm.raise(ExceptionKind::IOError, "connection is write-only")),
            None => Ok(None),
        }
    }

    /// The check that the connection is writable.
    fn check_writable(&self, vm: &Vm) -> PyResult<()> {
        if self.writable {
            return Ok(());
        }

        Err(vm.raise(ExceptionKind::IOError, "connection is read-only"))
    }

    /// The state a receive leaves behind. On a bad message length a
    /// read-only connection closes its handle and a read-write one becomes
    /// write-only; whether that happened is unknown.
    fn after_receive(&self) {
        if self.writable {
            self.readable.set(None);
        } else {
            self.handle.set(None);
        }
    }
}

/// A converted argument of the constructor.
enum NewArgument {
    Handle(Option<u64>),
    Flag(Option<i32>),
}

pub(super) fn connection_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, Socket::TYPE_NAME, create_type::<Socket>)
}

pub(super) fn pipe_connection_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, Pipe::TYPE_NAME, create_type::<Pipe>)
}

fn create_type<F: Flavor>(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: F::NAME,
            module: "_multiprocessing",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", connection_new::<F>),
                method("__repr__", connection_repr::<F>),
                method("send_bytes", connection_send_bytes::<F>),
                method("recv_bytes", connection_recv_bytes::<F>),
                method("recv_bytes_into", connection_recv_bytes_into::<F>),
                method("send", connection_send::<F>),
                method("recv", connection_recv::<F>),
                method("poll", connection_poll::<F>),
                method("fileno", connection_fileno::<F>),
                method("close", connection_close::<F>),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "closed", owner: F::TYPE_NAME, get: connection_closed::<F>, set: None })?;
    add_getset(vm, &class, GetSet { name: "readable", owner: F::TYPE_NAME, get: connection_readable::<F>, set: None })?;
    add_getset(vm, &class, GetSet { name: "writable", owner: F::TYPE_NAME, get: connection_writable::<F>, set: None })?;

    Ok(class)
}

fn receiver<'a, F: Flavor>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a Connection<F>> {
    this::<Connection<F>>(vm, args, F::TYPE_NAME, method)
}

/// `Connection.__new__`: `"K|ii"` over `handle`, `readable`,
/// `writable`.
fn connection_new<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = native_type(vm, F::TYPE_NAME, create_type::<F>)?;
    let (class, args) = new_class(vm, args, &base)?;

    let arguments = parse_with(vm, args, "", &["handle", "readable", "writable"], 1, |vm, index, value| match index {
        0 => handle_argument(vm, &value, 1).map(NewArgument::Handle),
        _ => int_value(vm, &value).map(NewArgument::Flag),
    })?;
    let flag = |argument: Option<&Option<NewArgument>>| match argument {
        Some(Some(NewArgument::Flag(flag))) => *flag,
        _ => Some(1),
    };
    let (Some(Some(NewArgument::Handle(handle))), readable, writable) = (arguments.first(), flag(arguments.get(1)), flag(arguments.get(2))) else {
        return Err(vm.type_error("Required argument 'handle' (pos 1) not found"));
    };
    let (Some(handle), Some(readable), Some(writable)) = (*handle, readable, writable) else {
        return Ok(Value::unknown("_multiprocessing connection of unknown arguments"));
    };

    // `%zd` of the handle as a signed `ssize_t`.
    let signed = handle as i64;
    if handle == INVALID_HANDLE || signed < 0 {
        return Err(vm.raise(ExceptionKind::IOError, &format!("invalid handle {signed}")));
    }
    if readable == 0 && writable == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "either readable or writable must be true"));
    }

    let connection = Connection::<F> { handle: Cell::new(Some(handle)), readable: Cell::new(Some(readable != 0)), writable: writable != 0, flavor: PhantomData };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(connection))))
}

/// `Connection.__repr__`.
fn connection_repr<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "__repr__")?;
    method_no_arguments(vm, &args, "__repr__")?;

    let (Some(handle), Some(readable)) = (connection.handle.get(), connection.readable.get()) else {
        return Ok(Value::unknown("_multiprocessing connection repr after a host receive"));
    };
    let kind = match (readable, connection.writable) {
        (true, true) => "read-write",
        (true, false) => "read-only",
        _ => "write-only",
    };

    Ok(Value::str(&format!("<{kind} {}, handle {}>", F::NAME, handle as i64)))
}

/// `Connection.send_bytes`: `"s#|nn"`, then the flag and range checks before
/// the host write.
fn connection_send_bytes<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "send_bytes")?;
    let arguments = unnamed_arguments(vm, &args, 1, "send_bytes", 1, 3)?;

    let length = read_buffer_length(vm, &arguments[0])?;
    let offset = match arguments.get(1) {
        Some(offset) => ssize_value(vm, offset)?,
        None => Some(0),
    };
    // The minimum signed size stands for an absent size, even when passed.
    let size = match arguments.get(2) {
        Some(size) => Some(ssize_value(vm, size)?).filter(|size| *size != Some(i64::MIN)),
        None => None,
    };

    connection.check_writable(vm)?;

    let Some(offset) = offset else {
        return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing send_bytes() of unknown arguments");
    };
    if offset < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "offset is negative"));
    }
    let Some(length) = length else {
        return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing send_bytes() of unknown arguments");
    };
    if length < offset {
        return Err(vm.raise(ExceptionKind::ValueError, "buffer length < offset"));
    }
    if let Some(size) = size {
        let Some(size) = size else {
            return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing send_bytes() of unknown arguments");
        };
        if size < 0 {
            return Err(vm.raise(ExceptionKind::ValueError, "size is negative"));
        }
        if offset.checked_add(size).is_none_or(|end| end > length) {
            return Err(vm.raise(ExceptionKind::ValueError, "buffer length < offset + size"));
        }
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing send_bytes() (host connection)")
}

/// The length of the `s#` format: a string, unicode in the default
/// encoding, or a read buffer that needs no release. `None` when unknown.
fn read_buffer_length(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let length = if let Some(bytes) = vm.as_str_bytes(value) {
        bytes.as_bytes().len()
    } else if let Some(text) = vm.as_text(value) {
        encode_default(vm, &text)?.as_bytes().len()
    } else if let Some(contents) = vm.buffer(value, BufferInterface::Pinned)? {
        contents.as_bytes().len()
    } else {
        return Err(vm.type_error(&format!("argument 1 must be string or read-only buffer, not {}", converted_type_name(vm, value))));
    };

    i64::try_from(length).map(Some).map_err(|_| vm.halt_unsupported("buffer longer than Py_ssize_t"))
}

/// `Connection.recv_bytes`: `"|n"`, then the flag and length checks before
/// the host read.
fn connection_recv_bytes<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "recv_bytes")?;
    let arguments = unnamed_arguments(vm, &args, 1, "recv_bytes", 0, 1)?;
    let maximum = match arguments.first() {
        Some(maximum) => ssize_value(vm, maximum)?,
        None => Some(i64::MAX),
    };

    let readable = connection.check_readable(vm)?;
    let Some(maximum) = maximum else {
        return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing recv_bytes() of unknown arguments");
    };
    if maximum < 0 {
        // With an unknown flag the call raises either `IOError` or this.
        if readable.is_none() {
            return Err(vm.halt_unsupported("recv_bytes() with a negative length on a connection whose readability is unknown"));
        }
        return Err(vm.raise(ExceptionKind::ValueError, "maxlength < 0"));
    }
    let result = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing recv_bytes() (host connection)")?;
    connection.after_receive();

    Ok(result)
}

/// `Connection.recv_bytes_into`: the flag check precedes `"w*|n"`. The host
/// data would be written into the buffer, so a call that gets that far
/// halts.
fn connection_recv_bytes_into<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "recv_bytes_into")?;
    reject_keywords(vm, &args, "recv_bytes_into")?;
    if connection.check_readable(vm)?.is_none() {
        return Err(vm.halt_unsupported("recv_bytes_into() on a connection whose readability is unknown"));
    }

    let arguments = unnamed_arguments(vm, &args, 1, "recv_bytes_into", 1, 2)?;
    let length = write_buffer_length(vm, &arguments[0])?;
    let offset = match arguments.get(1) {
        Some(offset) => ssize_value(vm, offset)?,
        None => Some(0),
    };

    if let (Some(length), Some(offset)) = (length, offset) {
        if offset < 0 {
            return Err(vm.raise(ExceptionKind::ValueError, "negative offset"));
        }
        if offset > length {
            return Err(vm.raise(ExceptionKind::ValueError, "offset too large"));
        }
    }

    vm.host_permit(HostCapability::SharedMemory, Denial::Native, None)?;
    Err(vm.halt_unsupported("recv_bytes_into() writes host data into a buffer"))
}

/// The keyword check of a varargs method, which precedes its body.
fn reject_keywords(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method}() takes no keyword arguments")));
    }

    Ok(())
}

/// The length of the writable `w*` format; `None` when unknown.
fn write_buffer_length(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let is_view = vm.is_instance_of(value, &vm.types().memoryview)?;
    let writable = if is_view {
        let readonly = vm.getattr_str(value, "readonly")?;
        if readonly.is_unknown() {
            return Ok(None);
        }
        !vm.truthy(&readonly, "memoryview.readonly")?
    } else {
        vm.buffer_slots(value).is_some_and(|slots| slots.new && slots.write)
    };
    let contents = if writable { vm.buffer(value, BufferInterface::New)? } else { None };
    let Some(contents) = contents else {
        return Err(vm.type_error(&format!("argument 1 must be read-write buffer, not {}", converted_type_name(vm, value))));
    };

    i64::try_from(contents.as_bytes().len()).map(Some).map_err(|_| vm.halt_unsupported("buffer longer than Py_ssize_t"))
}

/// `send`: the object is pickled before the host write.
fn connection_send<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "send")?;
    let object = method_one_argument(vm, &args, "send")?;
    connection.check_writable(vm)?;

    let pickler = pickler(vm)?;
    let pickled = vm.call(&pickler.dumps, CallArgs::new(vec![object, pickler.protocol.clone()]))?;

    // Unicode goes through the default encoding.
    if !pickled.is_unknown() && vm.as_str_bytes(&pickled).is_none() {
        let Some(text) = vm.as_text(&pickled) else {
            return Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(&pickled))));
        };
        encode_default(vm, &text)?;
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing send() (host connection)")
}

/// `recv`. Unpickling host data runs code the interpreter cannot predict,
/// so a readable connection halts.
fn connection_recv<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "recv")?;
    method_no_arguments(vm, &args, "recv")?;
    connection.check_readable(vm)?;

    vm.host_permit(HostCapability::SharedMemory, Denial::Native, None)?;
    Err(vm.halt_unsupported("recv() unpickles host data"))
}

/// `Connection.poll`: the flag check precedes `"|O"`.
fn connection_poll<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "poll")?;
    reject_keywords(vm, &args, "poll")?;
    if connection.check_readable(vm)?.is_none() {
        // The argument checks run only on a readable connection, and when
        // they would fail the call raises whichever way the flag is.
        let rest = &args.positional[1..];
        let plain = match rest {
            [] => true,
            [timeout] => {
                let converts = match vm.as_integral(timeout) {
                    Some(Integral::Int(_)) => true,
                    Some(Integral::Long(number)) => bigint_to_f64(&number).is_some(),
                    None => false,
                };
                timeout.is_none() || timeout.is_unknown() || vm.as_float(timeout).is_some() || converts
            }
            _ => false,
        };
        if !plain {
            return Err(vm.halt_unsupported("poll() arguments on a connection whose readability is unknown"));
        }
        return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing poll() on a connection whose readability is unknown");
    }

    let arguments = unnamed_arguments(vm, &args, 1, "poll", 0, 1)?;
    if let Some(timeout) = arguments.first().filter(|timeout| !timeout.is_none()) {
        c_double(vm, timeout)?;
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing poll() (host connection)")
}

/// `Connection.fileno`: the handle cast to a C `long`.
fn connection_fileno<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "fileno")?;
    method_no_arguments(vm, &args, "fileno")?;

    match connection.handle.get() {
        None => Ok(Value::unknown("_multiprocessing fileno() after a host receive")),
        Some(INVALID_HANDLE) => Err(vm.raise(ExceptionKind::IOError, "handle is invalid")),
        Some(handle) => Ok(Value::Int(match long_bits(vm) {
            32 => i64::from(handle as u32 as i32),
            _ => handle as i64,
        })),
    }
}

/// `Connection.close`. Closing the host handle has no effect on interpreter
/// state beyond the invalidated handle.
fn connection_close<F: Flavor>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let connection = receiver::<F>(vm, &args, "close")?;
    method_no_arguments(vm, &args, "close")?;

    if connection.handle.get() != Some(INVALID_HANDLE) {
        vm.host_permit(HostCapability::SharedMemory, Denial::Native, None)?;
    }
    connection.handle.set(Some(INVALID_HANDLE));

    Ok(Value::None)
}

/// The connection behind a getter's `instance`; `None` when it is unknown.
fn getter_receiver<'a, F: Flavor>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<Option<&'a Connection<F>>> {
    if instance.is_unknown() {
        return Ok(None);
    }

    native_data::<Connection<F>>(instance).map(Some).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

fn connection_closed<F: Flavor>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(connection) = getter_receiver::<F>(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(match connection.handle.get() {
        Some(handle) => Value::Bool(handle == INVALID_HANDLE),
        None => Value::unknown("_multiprocessing connection closed state after a host receive"),
    })
}

fn connection_readable<F: Flavor>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(connection) = getter_receiver::<F>(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(match connection.readable.get() {
        Some(readable) => Value::Bool(readable),
        None => Value::unknown("_multiprocessing connection readability after a host receive"),
    })
}

fn connection_writable<F: Flavor>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(connection) = getter_receiver::<F>(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(Value::Bool(connection.writable))
}
