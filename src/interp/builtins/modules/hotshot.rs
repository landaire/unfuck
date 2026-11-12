//! The `_hotshot` module. Its profiler and log reader objects are only
//! made by opening a host file, so the factory functions return unknown
//! values after checking their arguments, and the two types never have
//! instances the interpreter can inspect.

use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const PROFILER_TYPE: &str = "_hotshot.ProfilerType";
const LOG_READER_TYPE: &str = "_hotshot.LogReaderType";

/// `WHAT_*` record tags, in module initialization order.
const CONSTANTS: [(&str, i64); 8] = [
    ("WHAT_ENTER", 0x00),
    ("WHAT_EXIT", 0x01),
    ("WHAT_LINENO", 0x02),
    ("WHAT_OTHER", 0x03),
    ("WHAT_ADD_INFO", 0x13),
    ("WHAT_DEFINE_FILE", 0x23),
    ("WHAT_DEFINE_FUNC", 0x43),
    ("WHAT_LINE_TIMES", 0x33),
];

const FUNCTIONS: [MethodSpec; 4] = [
    function("coverage", hotshot_coverage),
    function("profiler", hotshot_profiler),
    function("logreader", hotshot_logreader),
    function("resolution", hotshot_resolution),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    // The version taken from "$Revision$", which has no digits.
    set_attribute(vm, module, "__version__", Value::str(""))?;
    set_attribute(vm, module, "LogReaderType", Value::Object(native_type(vm, LOG_READER_TYPE, create_log_reader_type)?))?;
    set_attribute(vm, module, "ProfilerType", Value::Object(native_type(vm, PROFILER_TYPE, create_profiler_type)?))?;

    let error = native_type(vm, "hotshot.ProfilerError", |vm| {
        let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
        new_exception_class(vm, "hotshot", "ProfilerError", &base)
    })?;
    set_attribute(vm, module, "ProfilerError", Value::Object(error))?;

    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    Ok(())
}

fn create_profiler_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "ProfilerType",
            module: "_hotshot",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("addinfo", profiler_addinfo),
                method("close", profiler_close),
                method("fileno", profiler_fileno),
                method("runcall", profiler_runcall),
                method("runcode", profiler_runcode),
                method("start", profiler_start),
                method("stop", profiler_stop),
            ],
        },
    )?;

    for name in ["frametimings", "lineevents", "linetimings"] {
        add_member(vm, &class, GetSet { name, owner: PROFILER_TYPE, get: host_object_attribute, set: None })?;
    }
    add_getset(vm, &class, GetSet { name: "closed", owner: PROFILER_TYPE, get: host_object_attribute, set: None })?;

    Ok(class)
}

fn create_log_reader_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "LogReaderType",
            module: "_hotshot",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("close", log_reader_close),
                method("fileno", log_reader_fileno),
                method("__iter__", log_reader_iter),
                method("next", log_reader_next),
                method("__getitem__", log_reader_getitem),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "info", owner: LOG_READER_TYPE, get: host_object_attribute, set: None })?;
    add_getset(vm, &class, GetSet { name: "closed", owner: LOG_READER_TYPE, get: host_object_attribute, set: None })?;

    Ok(class)
}

/// An attribute of a profiler or log reader. Every instance comes from a
/// host file and is unknown, so any other receiver is of the wrong type.
fn host_object_attribute(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    if instance.is_unknown() {
        return Ok(instance.clone());
    }

    Err(descriptor_mismatch(vm, getset, instance))
}

/// The receiver check of a profiler or log reader method, which CPython
/// performs before any argument check. Every instance comes from a host
/// file and is unknown, and dispatching on an unknown receiver halts, so
/// the methods' own argument checks are never reached.
fn host_object_method(vm: &Vm, args: CallArgs, owner: &str, method: &str) -> PyResult<Value> {
    let (receiver, _) = bind(vm, args, method, owner)?;

    Err(wrong_receiver(vm, method, owner, &receiver))
}

macro_rules! host_object_methods {
    ($($rust:ident => $owner:expr, $name:literal;)*) => {
        $(
            fn $rust(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                host_object_method(vm, args, $owner, $name)
            }
        )*
    };
}

host_object_methods! {
    profiler_addinfo => PROFILER_TYPE, "addinfo";
    profiler_close => PROFILER_TYPE, "close";
    profiler_fileno => PROFILER_TYPE, "fileno";
    profiler_runcall => PROFILER_TYPE, "runcall";
    profiler_runcode => PROFILER_TYPE, "runcode";
    profiler_start => PROFILER_TYPE, "start";
    profiler_stop => PROFILER_TYPE, "stop";
    log_reader_close => LOG_READER_TYPE, "close";
    log_reader_fileno => LOG_READER_TYPE, "fileno";
    log_reader_iter => LOG_READER_TYPE, "__iter__";
    log_reader_next => LOG_READER_TYPE, "next";
    log_reader_getitem => LOG_READER_TYPE, "__getitem__";
}

/// The `s` format of a function whose format names it.
fn file_name_argument(vm: &Vm, value: &Value, function: &str) -> PyResult<()> {
    c_string(vm, value, Some(function), 1)?;

    Ok(())
}

/// `_hotshot.profiler`: `"s|ii:profiler"`; the log file is created on the
/// host.
fn hotshot_profiler(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "profiler", 1, 3)?;
    file_name_argument(vm, &arguments[0], "profiler")?;
    for flag in arguments.iter().skip(1) {
        if !flag.is_unknown() {
            int_argument(vm, flag)?;
        }
    }

    vm.host_operation_on(HostCapability::FileSystem, "_hotshot.profiler() (host file)", Denial::Crt, Some(&arguments[0]))
}

/// `_hotshot.coverage`: `"s:coverage"`; the log file is created on the host.
fn hotshot_coverage(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "coverage", 1, 1)?;
    file_name_argument(vm, &arguments[0], "coverage")?;

    vm.host_operation_on(HostCapability::FileSystem, "_hotshot.coverage() (host file)", Denial::Crt, Some(&arguments[0]))
}

/// `_hotshot.logreader`: `"s:logreader"`; the log is read from the host.
fn hotshot_logreader(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "logreader", 1, 1)?;
    file_name_argument(vm, &arguments[0], "logreader")?;

    vm.host_operation_on(HostCapability::FileSystem, "_hotshot.logreader() (host file)", Denial::Crt, Some(&arguments[0]))
}

/// `_hotshot.resolution`: two C `int`s measured from the host timer.
fn hotshot_resolution(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "resolution")?;
    vm.host_permit(HostCapability::Clock, Denial::Native, None)?;

    Ok(Value::tuple(vec![Value::unknown("_hotshot.resolution() (host timer)"), Value::unknown("_hotshot.resolution() (host timer)")]))
}
