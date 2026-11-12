//! `FileIO`. Opening a file depends on the host, so construction checks
//! its arguments and yields an unknown value. No instance is ever built, so
//! every method rejects its receiver.

use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::args::first_unknown;
use crate::interp::builtins::modules::codecs::args::to_unicode;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::parse;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::after_receiver;
use super::allocation_class;
use super::int_argument;
use super::iobase::raw_base_type;
use super::missing_argument;

/// A method of `FileIO` that rejects its receiver.
macro_rules! file_methods {
    ($($name:literal),* $(,)?) => {
        [static_method("__new__", file_io_new), $(method($name, |vm, args| file_method(vm, &args, $name))),*]
    };
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "FileIO", Value::Object(file_io_type(vm)?))
}

pub fn file_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io.FileIO", create_file_io_type)
}

fn create_file_io_type(vm: &Vm) -> PyResult<ObjectRef> {
    let base = raw_base_type(vm)?;
    let methods = file_methods!("__repr__", "close", "fileno", "isatty", "read", "readable", "readall", "readinto", "seek", "seekable", "tell", "truncate", "writable", "write");
    let class = new_type(vm, TypeSpec { name: "FileIO", module: "_io", base: Some(base), layout: Layout::Native, instance_dict: true, methods: &methods })?;

    for name in ["closed", "closefd", "mode"] {
        add_getset(vm, &class, GetSet { name, owner: "_io.FileIO", get: file_attribute, set: None })?;
    }

    Ok(class)
}

/// A method called on a value that is not a `FileIO`.
fn file_method(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{name}' of '_io.FileIO' object needs an argument")));
    };

    Err(vm.type_error(&format!("descriptor '{name}' requires a '_io.FileIO' object but received a '{}'", vm.type_name(receiver))))
}

fn file_attribute(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

/// The checks CPython makes before it opens the file.
fn file_io_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    allocation_class(vm, &args, &file_io_type(vm)?)?;
    let slots = parse(vm, after_receiver(&args), "fileio", &["file", "mode", "closefd"], 0)?;
    let given: Vec<Value> = slots.iter().flatten().cloned().collect();
    if first_unknown(&given).is_some() {
        return vm.host_operation_on(HostCapability::FileSystem, "_io.FileIO", Denial::Crt, None);
    }

    let Some(file) = &slots[0] else {
        return Err(missing_argument(vm, "file", 1));
    };
    let mode = match &slots[1] {
        Some(mode) => Some(c_string(vm, "fileio", 2, mode)?),
        None => None,
    };
    let closefd = match &slots[2] {
        Some(closefd) => int_argument(vm, closefd, "FileIO closefd")? != 0,
        None => true,
    };

    check_file_arguments(vm, file, mode.as_ref().map_or(b"r".as_slice(), |mode| mode.as_bytes()), closefd)?;

    let filename = vm.as_integral(file).is_none().then_some(file);
    vm.host_operation_on(HostCapability::FileSystem, "_io.FileIO", Denial::Crt, filename)
}

/// The checks `FileIO.__init__` makes before it opens the file.
pub fn check_file_arguments(vm: &Vm, file: &Value, mode: &[u8], closefd: bool) -> PyResult<()> {
    if vm.as_float(file).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }
    let descriptor = match vm.as_integral(file) {
        Some(Integral::Int(number)) => i32::try_from(number).ok(),
        Some(Integral::Long(number)) => number.to_i32(),
        None => None,
    };
    if descriptor.is_some_and(|descriptor| descriptor < 0) {
        return Err(vm.raise(ExceptionKind::ValueError, "negative file descriptor"));
    }

    if descriptor.is_none() {
        file_name(vm, file)?;
    }

    check_file_mode(vm, mode)?;
    if descriptor.is_none() && !closefd {
        return Err(vm.raise(ExceptionKind::ValueError, "Cannot use closefd=False with file name"));
    }

    Ok(())
}

/// The name check of `FileIO.__init__`: a string or a character buffer.
/// The name may hold NUL characters; the open then sees the name up to the
/// first one.
fn file_name(vm: &Vm, file: &Value) -> PyResult<()> {
    if vm.as_text(file).is_some() {
        return Ok(());
    }
    // `et` reads a `str` or another character buffer as bytes, through a
    // decode that reports a `TypeError` from the buffer as its own.
    let bytes = match vm.buffer(file, BufferInterface::Character) {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => {
            return Err(vm.type_error(&format!("coercing to Unicode: need string or buffer, {} found", vm.type_name(file))));
        }
        bytes => bytes?,
    };
    if bytes.is_some() {
        return Ok(());
    }

    to_unicode(vm, file)?;

    Ok(())
}

/// The mode letters `FileIO.__init__` accepts.
fn check_file_mode(vm: &Vm, mode: &[u8]) -> PyResult<()> {
    let bad_mode = || vm.raise(ExceptionKind::ValueError, "Must have exactly one of read/write/append mode and at most one plus");

    let mut access = false;
    let mut plus = false;
    for letter in mode {
        match letter {
            b'r' | b'w' | b'a' if access => return Err(bad_mode()),
            b'r' | b'w' | b'a' => access = true,
            b'b' => {}
            b'+' if plus => return Err(bad_mode()),
            b'+' => plus = true,
            _ => return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid mode: {}", String::from_utf8_lossy(mode)))),
        }
    }
    if !access {
        return Err(bad_mode());
    }

    Ok(())
}
