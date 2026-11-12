//! The `_multiprocessing.win32` namespace class: static functions over
//! host handles, checked as the Win64 build parses their arguments.

use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::check_unsigned_long_mask;
use super::dword_argument;
use super::handle_argument;
use super::int_value;
use super::unnamed_arguments;
use super::unsigned_value;

/// The `win32` constants in namespace creation order, with the values of
/// `winerror.h`, `winnt.h`, and `winbase.h`. `NULL` is built as an `int`.
const CONSTANTS: [(&str, u64); 18] = [
    ("ERROR_ALREADY_EXISTS", 183),
    ("ERROR_NO_DATA", 232),
    ("ERROR_PIPE_BUSY", 231),
    ("ERROR_PIPE_CONNECTED", 535),
    ("ERROR_SEM_TIMEOUT", 121),
    ("GENERIC_READ", 0x8000_0000),
    ("GENERIC_WRITE", 0x4000_0000),
    ("INFINITE", 0xFFFF_FFFF),
    ("NMPWAIT_WAIT_FOREVER", 0xFFFF_FFFF),
    ("OPEN_EXISTING", 3),
    ("PIPE_ACCESS_DUPLEX", 3),
    ("PIPE_ACCESS_INBOUND", 1),
    ("PIPE_READMODE_MESSAGE", 2),
    ("PIPE_TYPE_MESSAGE", 4),
    ("PIPE_UNLIMITED_INSTANCES", 255),
    ("PIPE_WAIT", 0),
    ("PROCESS_ALL_ACCESS", 0x001F_0FFF),
    ("NULL", 0),
];

/// A unit of an argument format of the `win32` functions.
#[derive(Clone, Copy)]
enum Unit {
    /// Handles and pointers (`K`).
    Handle,
    /// `DWORD` (`k`).
    Dword,
    /// `i`
    Int,
    /// `s`
    Text,
    /// `O`
    Object,
}

pub(super) fn win32_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_multiprocessing.win32", create_win32_type)
}

/// `Win32Type` has no constructor and cannot be subclassed.
fn create_win32_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "win32",
            module: "_multiprocessing",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("CloseHandle", win32_close_handle),
                static_method("GetLastError", win32_get_last_error),
                static_method("OpenProcess", win32_open_process),
                static_method("ExitProcess", win32_exit_process),
                static_method("ConnectNamedPipe", win32_connect_named_pipe),
                static_method("CreateFile", win32_create_file),
                static_method("CreateNamedPipe", win32_create_named_pipe),
                static_method("SetNamedPipeHandleState", win32_set_named_pipe_handle_state),
                static_method("WaitNamedPipe", win32_wait_named_pipe),
            ],
        },
    )?;

    let Some(data) = class.as_class() else {
        return Err(vm.type_error("win32 is not a class"));
    };
    for (name, value) in CONSTANTS {
        vm.dict_set_str(&data.dict, name, unsigned_value(vm, value))?;
    }

    Ok(class)
}

/// Argument parsing of a nameless format made of `units`.
fn parse_units(vm: &Vm, args: &CallArgs, function: &str, units: &[Unit]) -> PyResult<Vec<Value>> {
    let arguments = unnamed_arguments(vm, args, 0, function, units.len(), units.len())?;

    for (index, (argument, unit)) in arguments.iter().zip(units).enumerate() {
        let position = index + 1;
        match unit {
            Unit::Handle => {
                handle_argument(vm, argument, position)?;
            }
            Unit::Dword => dword_argument(vm, argument, position)?,
            Unit::Int => {
                int_value(vm, argument)?;
            }
            Unit::Text => {
                c_string(vm, argument, None, position)?;
            }
            Unit::Object => {}
        }
    }

    Ok(arguments)
}

/// A `path` function's refusal reports its first argument as the filename.
macro_rules! host_functions {
    ($($rust:ident => $name:literal, $capability:ident, $path:literal, [$($unit:ident),*];)*) => {
        $(
            fn $rust(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let arguments = parse_units(vm, &args, $name, &[$(Unit::$unit),*])?;
                let filename = if $path { arguments.first() } else { None };

                vm.host_operation_on(
                    HostCapability::$capability,
                    concat!("_multiprocessing.win32.", $name, "() (host operating system)"),
                    Denial::Native,
                    filename,
                )
            }
        )*
    };
}

host_functions! {
    win32_close_handle => "CloseHandle", SharedMemory, false, [Handle];
    win32_connect_named_pipe => "ConnectNamedPipe", SharedMemory, false, [Handle, Handle];
    win32_create_file => "CreateFile", FileSystem, true, [Text, Dword, Dword, Handle, Dword, Dword, Handle];
    win32_create_named_pipe => "CreateNamedPipe", SharedMemory, false, [Text, Dword, Dword, Dword, Dword, Dword, Dword, Handle];
    win32_open_process => "OpenProcess", Process, false, [Dword, Int, Dword];
    win32_wait_named_pipe => "WaitNamedPipe", SharedMemory, false, [Text, Dword];
}

/// `win32.GetLastError` ignores its arguments.
fn win32_get_last_error(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("GetLastError() takes no keyword arguments"));
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.win32.GetLastError() (host operating system)")
}

/// `win32.ExitProcess`: `"I"`, then the process ends.
fn win32_exit_process(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = unnamed_arguments(vm, &args, 0, "ExitProcess", 1, 1)?;
    if vm.as_float(&arguments[0]).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }
    check_unsigned_long_mask(vm, &arguments[0])?;

    vm.host_permit(HostCapability::Process, Denial::Native, None)?;
    Err(vm.halt_unsupported("_multiprocessing.win32.ExitProcess ends the process"))
}

/// `win32.SetNamedPipeHandleState`: a handle and three objects, then each
/// argument other than `None` goes through unsigned masked conversion.
fn win32_set_named_pipe_handle_state(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_units(vm, &args, "SetNamedPipeHandleState", &[Unit::Handle, Unit::Object, Unit::Object, Unit::Object])?;
    for argument in arguments.iter().skip(1).filter(|argument| !argument.is_none()) {
        check_unsigned_long_mask(vm, argument)?;
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.win32.SetNamedPipeHandleState() (host operating system)")
}
