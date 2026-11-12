//! The `_subprocess` module. Arguments, the startup information attributes,
//! and the environment block are checked as the Windows build does;
//! process, pipe, and handle results come from the host and are unknown.

use std::cell::Cell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::host_arguments::c_long;
use crate::interp::builtins::modules::host_arguments::exact;
use crate::interp::builtins::modules::host_arguments::float_int;
use crate::interp::builtins::modules::host_arguments::long_long;
use crate::interp::builtins::modules::host_arguments::number_int;
use crate::interp::builtins::modules::host_arguments::optional_string;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::host::HostCapability;
use crate::interp::error::Signal;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const HANDLE_TYPE: &str = "_subprocess_handle";

/// `INVALID_HANDLE_VALUE` of `winbase.h`, which is also the pseudo handle
/// `GetCurrentProcess` returns.
const INVALID_HANDLE_VALUE: i64 = -1;

/// Module constants in insertion order, with the values of the
/// Windows SDK `winbase.h`, `winnt.h`, and `winuser.h`. `INFINITE` is the
/// `DWORD` 0xFFFFFFFF passed through `int`.
const CONSTANTS: [(&str, i64); 12] = [
    ("STD_INPUT_HANDLE", -10),
    ("STD_OUTPUT_HANDLE", -11),
    ("STD_ERROR_HANDLE", -12),
    ("DUPLICATE_SAME_ACCESS", 0x2),
    ("STARTF_USESTDHANDLES", 0x100),
    ("STARTF_USESHOWWINDOW", 0x1),
    ("SW_HIDE", 0),
    ("INFINITE", -1),
    ("WAIT_OBJECT_0", 0),
    ("CREATE_NEW_CONSOLE", 0x10),
    ("CREATE_NEW_PROCESS_GROUP", 0x200),
    ("STILL_ACTIVE", 259),
];

/// A `_subprocess_handle`. Only `GetCurrentProcess` creates one without
/// the host, so its value is always known.
struct ProcessHandle {
    handle: Cell<i64>,
}

impl_native_data!(ProcessHandle, "_subprocess_handle");

/// Functions whose results come from the host.
macro_rules! host_functions {
    ($($rust:ident => $name:literal, |$vm:ident, $args:ident| $check:block;)*) => {
        $(
            fn $rust($vm: &Vm, $args: CallArgs) -> PyResult<Value> {
                $check

                $vm.host_operation(HostCapability::Process, concat!("_subprocess.", $name, "() (host process)"))
            }
        )*
    };
}

host_functions! {
    get_std_handle => "GetStdHandle", |vm, args| {
        let [which] = exact(vm, args, "GetStdHandle")?;
        c_int(vm, &which)?;
    };
    terminate_process => "TerminateProcess", |vm, args| {
        let [process, exit_code] = exact(vm, args, "TerminateProcess")?;
        long_long(vm, &process)?;
        c_int(vm, &exit_code)?;
    };
    get_exit_code_process => "GetExitCodeProcess", |vm, args| {
        let [process] = exact(vm, args, "GetExitCodeProcess")?;
        long_long(vm, &process)?;
    };
    wait_for_single_object => "WaitForSingleObject", |vm, args| {
        let [handle, milliseconds] = exact(vm, args, "WaitForSingleObject")?;
        long_long(vm, &handle)?;
        c_int(vm, &milliseconds)?;
    };
    get_version => "GetVersion", |vm, args| {
        let [] = exact(vm, args, "GetVersion")?;
    };
    get_module_file_name => "GetModuleFileName", |vm, args| {
        let [module] = exact(vm, args, "GetModuleFileName")?;
        long_long(vm, &module)?;
    };
}

/// `_subprocess` functions in table order.
const FUNCTIONS: [MethodSpec; 10] = [
    function("GetStdHandle", get_std_handle),
    function("GetCurrentProcess", get_current_process),
    function("DuplicateHandle", duplicate_handle),
    function("CreatePipe", create_pipe),
    function("CreateProcess", create_process),
    function("TerminateProcess", terminate_process),
    function("GetExitCodeProcess", get_exit_code_process),
    function("WaitForSingleObject", wait_for_single_object),
    function("GetVersion", get_version),
    function("GetModuleFileName", get_module_file_name),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    Ok(())
}

fn handle_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_subprocess._subprocess_handle", create_handle_type)
}

fn create_handle_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name: HANDLE_TYPE,
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("Detach", handle_detach), method("Close", handle_close), method("__int__", handle_int)],
        },
    )
}

fn new_handle(vm: &Vm, value: i64) -> PyResult<Value> {
    let class = handle_type(vm)?;

    Ok(new_native_object(vm, &class, ProcessHandle { handle: Cell::new(value) }))
}

/// A handle as a Python integer on the 64-bit build: a signed 64-bit value.
fn handle_number(value: i64) -> Value {
    Value::Long(Rc::new(BigInt::from(value)))
}

fn handle_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let handle = this::<ProcessHandle>(vm, &args, HANDLE_TYPE, "Detach")?;
    method_arguments(vm, &args, "Detach", 0, 0)?;

    let previous = handle.handle.replace(INVALID_HANDLE_VALUE);

    Ok(handle_number(previous))
}

/// `Close` ignores the result of `CloseHandle`.
fn handle_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let handle = this::<ProcessHandle>(vm, &args, HANDLE_TYPE, "Close")?;
    method_arguments(vm, &args, "Close", 0, 0)?;

    handle.handle.set(INVALID_HANDLE_VALUE);

    Ok(Value::None)
}

fn handle_int(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = bind(vm, args, "__int__", HANDLE_TYPE)?;
    wrapper_arguments(vm, rest, 0)?;
    let Some(handle) = native_data::<ProcessHandle>(&receiver) else {
        return Err(wrong_receiver(vm, "__int__", HANDLE_TYPE, &receiver));
    };

    Ok(handle_number(handle.handle.get()))
}

/// `GetCurrentProcess` returns a constant pseudo handle.
fn get_current_process(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [] = exact(vm, args, "GetCurrentProcess")?;

    new_handle(vm, INVALID_HANDLE_VALUE)
}

fn duplicate_handle(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "DuplicateHandle", 5, 6)?;
    let [source_process, source, target_process, access, inherit, options @ ..] = args.as_slice() else {
        return Err(vm.type_error(&format!("DuplicateHandle() takes at least 5 arguments ({} given)", args.len())));
    };
    long_long(vm, source_process)?;
    long_long(vm, source)?;
    long_long(vm, target_process)?;
    c_int(vm, access)?;
    c_int(vm, inherit)?;
    for option in options {
        c_int(vm, option)?;
    }

    vm.host_operation(HostCapability::Process, "_subprocess.DuplicateHandle() (host process)")
}

fn create_pipe(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [_attributes, size] = exact(vm, args, "CreatePipe")?;
    c_int(vm, &size)?;

    vm.host_operation(HostCapability::Process, "_subprocess.CreatePipe() (host process)")
}

/// `CreateProcess`. The startup information and environment are read
/// before the process is created.
fn create_process(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [application, command_line, _process_attributes, _thread_attributes, inherit, flags, environment, directory, startup_info] = exact(vm, args, "CreateProcess")?;
    optional_string(vm, &application, "CreateProcess", 1)?;
    optional_string(vm, &command_line, "CreateProcess", 2)?;
    c_int(vm, &inherit)?;
    c_int(vm, &flags)?;
    optional_string(vm, &directory, "CreateProcess", 8)?;

    read_startup_info(vm, &startup_info)?;
    if !environment.is_none() {
        check_environment(vm, &environment)?;
    }

    vm.host_operation(HostCapability::Process, "_subprocess.CreateProcess() (host process)")
}

/// The integer and handle attribute reads of `CreateProcess`. A missing
/// attribute clears every pending error, so only an integer conversion
/// error after the last failed lookup is raised.
fn read_startup_info(vm: &Vm, startup_info: &Value) -> PyResult<()> {
    const FIELDS: [(&str, bool); 5] = [("dwFlags", true), ("wShowWindow", true), ("hStdInput", false), ("hStdOutput", false), ("hStdError", false)];

    let mut pending = None;
    for (name, is_int) in FIELDS {
        let value = match vm.getattr_str(startup_info, name) {
            Ok(value) => value,
            Err(Signal::Raise(_)) => {
                pending = None;
                continue;
            }
            Err(halt) => return Err(halt),
        };
        if !is_int {
            continue;
        }
        match int_as_long(vm, &value) {
            Ok(()) => {}
            Err(Signal::Raise(error)) => pending = Some(Signal::Raise(error)),
            Err(halt) => return Err(halt),
        }
    }

    match pending {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// C `long` conversion, keeping only errors. A float converts through
/// truncation, and the result must fit a C `long`.
fn int_as_long(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() {
        return Ok(());
    }
    if vm.as_integral(value).is_some() {
        c_long(vm, value)?;
        return Ok(());
    }
    if let Some(number) = vm.as_float(value) {
        if vm.user_override(value, "__int__")?.is_none() {
            let truncated = float_int(vm, number)?.to_bigint();
            c_long(vm, &Value::Long(Rc::new(truncated)))?;
            return Ok(());
        }
    }

    let Some(result) = number_int(vm, value)? else {
        return Ok(());
    };
    if vm.as_integral(&result).is_none() {
        return Err(vm.type_error("nb_int should return int object"));
    }

    c_long(vm, &result).map(|_| ())
}

/// The environment check of 2.7.12: a mapping whose keys and values are all
/// `str`.
fn check_environment(vm: &Vm, environment: &Value) -> PyResult<()> {
    if environment.is_unknown() {
        return Ok(());
    }
    if !is_mapping(vm, environment)? {
        return Err(vm.type_error("environment must be dictionary or None"));
    }

    let Some(size) = vm.len(environment)? else {
        return Ok(());
    };
    let keys = vm.call_method(environment, "keys", Vec::new())?;
    let values = vm.call_method(environment, "values", Vec::new())?;
    if keys.is_unknown() || values.is_unknown() {
        return Ok(());
    }
    let (Some(keys), Some(values)) = (vm.as_list(&keys), vm.as_list(&values)) else {
        return Err(vm.halt_unsupported("_subprocess.CreateProcess with an environment whose keys() or values() is not a list"));
    };
    if keys.len() < size || values.len() < size {
        return Err(vm.halt_unsupported("_subprocess.CreateProcess with an environment shorter than its len()"));
    }

    for (key, value) in keys.iter().zip(values.iter()).take(size) {
        let is_text = |item: &Value| item.is_unknown() || vm.as_str_bytes(item).is_some();
        if !is_text(key) || !is_text(value) {
            return Err(vm.type_error("environment can only contain strings"));
        }
    }

    Ok(())
}

/// Whether a value is a mapping: item access without slicing.
fn is_mapping(vm: &Vm, value: &Value) -> PyResult<bool> {
    let Value::Object(_) = value else {
        return Ok(false);
    };
    if vm.as_list(value).is_some() || vm.as_tuple(value).is_some() {
        return Ok(false);
    }

    Ok(vm.lookup_special(value, "__getitem__")?.is_some() && vm.lookup_special(value, "__getslice__")?.is_none())
}
