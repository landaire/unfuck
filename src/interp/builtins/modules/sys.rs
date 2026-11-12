//! `sys` as CPython 2.7.12 for Windows x64 reports it.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;
use std::rc::Weak;

use num_bigint::BigInt;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::forbid_instances;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_struct_sequence_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_struct_sequence;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::hash::LongWidth;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The builtin modules of the Windows build, in sorted order.
const BUILTIN_MODULE_NAMES: [&str; 62] = [
    "__builtin__",
    "__main__",
    "_ast",
    "_bisect",
    "_codecs",
    "_codecs_cn",
    "_codecs_hk",
    "_codecs_iso2022",
    "_codecs_jp",
    "_codecs_kr",
    "_codecs_tw",
    "_collections",
    "_csv",
    "_functools",
    "_heapq",
    "_hotshot",
    "_io",
    "_json",
    "_locale",
    "_lsprof",
    "_md5",
    "_multibytecodec",
    "_random",
    "_sha",
    "_sha256",
    "_sha512",
    "_sre",
    "_struct",
    "_subprocess",
    "_symtable",
    "_warnings",
    "_weakref",
    "_winreg",
    "array",
    "audioop",
    "binascii",
    "cPickle",
    "cStringIO",
    "cmath",
    "datetime",
    "errno",
    "exceptions",
    "future_builtins",
    "gc",
    "imageop",
    "imp",
    "itertools",
    "marshal",
    "math",
    "mmap",
    "msvcrt",
    "nt",
    "operator",
    "parser",
    "signal",
    "strop",
    "sys",
    "thread",
    "time",
    "xxsubtype",
    "zipimport",
    "zlib",
];

const FLAGS: [&str; 16] = [
    "debug",
    "py3k_warning",
    "division_warning",
    "division_new",
    "inspect",
    "interactive",
    "optimize",
    "dont_write_bytecode",
    "no_user_site",
    "no_site",
    "ignore_environment",
    "tabcheck",
    "verbose",
    "unicode",
    "bytes_warning",
    "hash_randomization",
];

/// `PY_VERSION` of the emulated interpreter.
pub(super) const PY_VERSION: &str = "2.7.12";

const FLOAT_INFO: [&str; 11] = ["max", "max_exp", "max_10_exp", "min", "min_exp", "min_10_exp", "dig", "mant_dig", "epsilon", "radix", "rounds"];

const VERSION_INFO: [&str; 5] = ["major", "minor", "micro", "releaselevel", "serial"];

const WINDOWS_VERSION: [&str; 5] = ["major", "minor", "build", "platform", "service_pack"];

/// Interpreter settings `sys` reports back.
struct SysState {
    check_interval: Cell<i64>,
}

impl Default for SysState {
    /// The check interval starts at 100.
    fn default() -> Self {
        Self { check_interval: Cell::new(100) }
    }
}

/// The standard streams. Output written to them is discarded.
struct StandardStream {
    name: &'static str,
}

impl_native_data!(StandardStream, "sys.StandardStream");

/// Whether `value` is one of the standard streams, whose output Python code
/// cannot observe.
pub fn is_standard_stream(value: &Value) -> bool {
    crate::interp::builtins::modules::native_data::<StandardStream>(value).is_some()
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("_clear_type_cache", none_result),
            function("_current_frames", unknown_frames),
            function("_getframe", sys_getframe),
            function("call_tracing", sys_call_tracing),
            function("displayhook", sys_displayhook),
            function("exc_clear", sys_exc_clear),
            function("exc_info", sys_exc_info),
            function("excepthook", none_result),
            function("exit", sys_exit),
            function("getcheckinterval", sys_getcheckinterval),
            function("getdefaultencoding", sys_getdefaultencoding),
            function("getfilesystemencoding", sys_getfilesystemencoding),
            function("getprofile", sys_getprofile),
            function("getrecursionlimit", sys_getrecursionlimit),
            function("getrefcount", sys_getrefcount),
            function("getsizeof", sys_getsizeof),
            function("gettrace", none_result),
            function("getwindowsversion", sys_getwindowsversion),
            function("setcheckinterval", sys_setcheckinterval),
            function("setprofile", sys_setprofile),
            function("setdefaultencoding", sys_setdefaultencoding),
            function("setrecursionlimit", sys_setrecursionlimit),
            function("settrace", sys_settrace),
        ],
    )?;

    let dict = vm.instance_dict(module)?;
    for (hook, original) in [("displayhook", "__displayhook__"), ("excepthook", "__excepthook__")] {
        if let Some(function) = vm.dict_get_str(&dict, hook)? {
            set_attribute(vm, module, original, function)?;
        }
    }

    let maxint = match vm.config.long_width {
        LongWidth::Bits32 => i64::from(i32::MAX),
        LongWidth::Bits64 => i64::MAX,
    };
    set_attribute(vm, module, "maxint", Value::Int(maxint))?;
    set_attribute(vm, module, "exc_type", Value::None)?;
    set_attribute(vm, module, "maxsize", vm.new_int(BigInt::from(i64::MAX)))?;
    set_attribute(vm, module, "maxunicode", Value::Int(0xFFFF))?;
    set_attribute(vm, module, "byteorder", Value::str("little"))?;
    set_attribute(vm, module, "platform", Value::str("win32"))?;
    // The version string embeds the build date and compiler of the executable.
    let version = match &vm.config.host.sys_version {
        Some(version) => Value::str(version),
        None => Value::unknown("sys.version (build date and compiler of the executable)"),
    };
    set_attribute(vm, module, "version", version)?;
    set_attribute(vm, module, "hexversion", Value::Int(0x0207_0CF0))?;
    set_attribute(vm, module, "api_version", Value::Int(1013))?;
    set_attribute(vm, module, "subversion", Value::tuple(vec![Value::str("CPython"), Value::str(""), Value::str("")]))?;
    // The client's build string reads `default`: it was built without
    // Mercurial identifiers, so both are empty.
    set_attribute(vm, module, "_mercurial", Value::tuple(vec![Value::str("CPython"), Value::str(""), Value::str("")]))?;
    set_attribute(vm, module, "winver", Value::str("2.7"))?;
    set_attribute(vm, module, "float_repr_style", Value::str("short"))?;
    set_attribute(vm, module, "py3kwarning", Value::Bool(false))?;
    set_attribute(vm, module, "dont_write_bytecode", Value::Bool(false))?;
    set_attribute(vm, module, "copyright", Value::unknown("sys.copyright text"))?;

    let names = match &vm.config.host.builtin_module_names {
        Some(names) => {
            // The builtin module names are reported sorted.
            let mut names = names.clone();
            names.sort_unstable();
            names.iter().map(|name| Value::str(name)).collect()
        }
        None => BUILTIN_MODULE_NAMES.iter().map(|name| Value::str(name)).collect(),
    };
    set_attribute(vm, module, "builtin_module_names", Value::tuple(names))?;

    set_attribute(vm, module, "modules", Value::Object(Rc::clone(vm.modules())))?;
    // The embedding host sets these; the interpreter resolves imports
    // through its module source instead, so the lists start empty.
    set_attribute(vm, module, "path", vm.new_list(Vec::new()))?;
    set_attribute(vm, module, "meta_path", vm.new_list(Vec::new()))?;
    set_attribute(vm, module, "path_hooks", vm.new_list(Vec::new()))?;
    set_attribute(vm, module, "path_importer_cache", Value::Object(vm.new_dict()))?;
    set_attribute(vm, module, "warnoptions", vm.new_list(Vec::new()))?;
    set_attribute(vm, module, "argv", vm.new_list(vec![Value::str("")]))?;
    set_attribute(vm, module, "executable", Value::unknown("sys.executable"))?;
    set_attribute(vm, module, "prefix", Value::unknown("sys.prefix"))?;
    set_attribute(vm, module, "exec_prefix", Value::unknown("sys.exec_prefix"))?;
    set_attribute(vm, module, "dllhandle", Value::unknown("sys.dllhandle"))?;

    let version_info = new_struct_sequence_type(vm, "sys", "version_info", &VERSION_INFO)?;
    forbid_instances(vm, &version_info)?;
    let version = vec![Value::Int(2), Value::Int(7), Value::Int(12), Value::str("final"), Value::Int(0)];
    set_attribute(vm, module, "version_info", new_struct_sequence(vm, &version_info, version))?;

    let flags = new_struct_sequence_type(vm, "sys", "flags", &FLAGS)?;
    forbid_instances(vm, &flags)?;
    set_attribute(vm, module, "flags", new_struct_sequence(vm, &flags, vec![Value::Int(0); FLAGS.len()]))?;

    let float_info = new_struct_sequence_type(vm, "sys", "float_info", &FLOAT_INFO)?;
    let float_values = vec![
        Value::Float(f64::MAX),
        Value::Int(i64::from(f64::MAX_EXP)),
        Value::Int(i64::from(f64::MAX_10_EXP)),
        Value::Float(f64::MIN_POSITIVE),
        Value::Int(i64::from(f64::MIN_EXP)),
        Value::Int(i64::from(f64::MIN_10_EXP)),
        Value::Int(i64::from(f64::DIGITS)),
        Value::Int(i64::from(f64::MANTISSA_DIGITS)),
        Value::Float(f64::EPSILON),
        Value::Int(i64::from(f64::RADIX)),
        Value::Int(1),
    ];
    set_attribute(vm, module, "float_info", new_struct_sequence(vm, &float_info, float_values))?;

    let stream_class = native_type(vm, "sys.StandardStream", create_stream_type)?;
    for (name, file_name) in [("stdin", "<stdin>"), ("stdout", "<stdout>"), ("stderr", "<stderr>")] {
        let stream = new_native_object(vm, &stream_class, StandardStream { name: file_name });
        set_attribute(vm, module, name, stream.clone())?;
        set_attribute(vm, module, &format!("__{name}__"), stream)?;
    }

    crate::interp::traceback::install(vm)
}

/// The argument installed with a native profile function, such as an
/// enabled `_lsprof.Profiler`.
pub(super) type ProfileSlot = RefCell<Option<Value>>;

#[derive(Default)]
struct ProfileHook {
    object: Rc<ProfileSlot>,
}

/// Installs a native profile function and its argument; `None` removes the
/// hook. The previous argument is released after the slot is, since its
/// deallocation may clear the slot again.
pub(super) fn set_profile_object(vm: &Vm, object: Option<Value>) {
    let slot = Rc::clone(&vm.native_state::<ProfileHook>().object);
    let previous = slot.try_borrow_mut().map(|mut current| std::mem::replace(&mut *current, object));
    drop(previous);
}

/// The slot, for objects whose deallocation removes the hook without
/// access to the interpreter.
pub(super) fn profile_slot(vm: &Vm) -> Weak<ProfileSlot> {
    Rc::downgrade(&vm.native_state::<ProfileHook>().object)
}

/// The argument of the installed C profile function, if any.
pub(super) fn profile_object(vm: &Vm) -> Option<Value> {
    vm.native_state::<ProfileHook>().object.try_borrow().ok().and_then(|object| object.clone())
}

fn sys_getprofile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getprofile")?;

    Ok(profile_object(vm).unwrap_or(Value::None))
}

fn none_result(_vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Ok(Value::None)
}

/// `sys._getframe([depth])`.
fn sys_getframe(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "_getframe", 0, 1)?;
    let depth = match args.first() {
        None => 0,
        Some(depth) if depth.is_unknown() => return Ok(depth.clone()),
        Some(depth) => vm.as_index(depth).ok_or_else(|| vm.type_error("an integer is required"))?,
    };
    let Ok(depth) = usize::try_from(depth) else {
        return Err(vm.raise(ExceptionKind::ValueError, "call stack is not deep enough"));
    };

    vm.frame_object(depth)
}

/// `sys.setdefaultencoding(name)`, which embedded clients keep and call at
/// startup.
fn sys_setdefaultencoding(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "setdefaultencoding", 1, 1)?;
    let Some(name) = vm.text_of(&args[0]) else {
        return Err(vm.type_error("setdefaultencoding() argument 1 must be string"));
    };

    vm.set_default_encoding(&name)?;

    Ok(Value::None)
}

fn unknown_frames(_vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Ok(Value::unknown("sys._current_frames()"))
}

fn sys_call_tracing(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "call_tracing", 2, 2)?;
    let Some(arguments) = vm.as_tuple(&args[1]) else {
        return Err(vm.type_error(&format!("call_tracing() argument 2 must be tuple, not {}", vm.type_name(&args[1]))));
    };

    vm.call(&args[0], CallArgs::new(arguments.to_vec()))
}

/// `sys.displayhook`: binds `__builtin__._` to the value. Printing is
/// discarded, but `repr` still runs for its side effects and errors.
fn sys_displayhook(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "displayhook", 1, 1)?;
    if args[0].is_none() {
        return Ok(Value::None);
    }

    let builtins = vm.builtins_dict();
    vm.dict_set_str(&builtins, "_", Value::None)?;
    vm.repr(&args[0])?;
    vm.dict_set_str(&builtins, "_", args[0].clone())?;

    Ok(Value::None)
}

fn sys_exc_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "exc_clear")?;
    vm.clear_handled_exceptions();

    Ok(Value::None)
}

/// `sys.exc_info`.
fn sys_exc_info(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "exc_info")?;

    let Some(handled) = vm.handled_exception() else {
        return Ok(Value::tuple(vec![Value::None, Value::None, Value::None]));
    };

    let class = Value::Object(vm.class_of(&handled.exception));

    Ok(Value::tuple(vec![class, handled.exception, handled.traceback]))
}

fn sys_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "exit", 0, 1)?;
    let class = Rc::clone(vm.types().exception(ExceptionKind::SystemExit));

    let exception = vm.instantiate_exception(&class, args)?;

    Err(Signal::Raise(exception))
}

fn sys_getcheckinterval(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getcheckinterval")?;

    Ok(vm.new_int_from_i64(vm.native_state::<SysState>().check_interval.get()))
}

/// `sys.setcheckinterval`: stored for `getcheckinterval`; the interpreter
/// has no thread switching for it to pace.
fn sys_setcheckinterval(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "setcheckinterval", 1, 1)?;
    if args[0].is_unknown() {
        return Err(vm.halt_unsupported("sys.setcheckinterval with an unknown interval"));
    }
    if vm.as_float(&args[0]).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }
    let Some(interval) = vm.as_index(&args[0]) else {
        return Err(vm.type_error("an integer is required"));
    };
    let Ok(interval) = i32::try_from(interval) else {
        let message = if interval > 0 { "signed integer is greater than maximum" } else { "signed integer is less than minimum" };
        return Err(vm.raise(ExceptionKind::OverflowError, message));
    };

    vm.native_state::<SysState>().check_interval.set(i64::from(interval));

    Ok(Value::None)
}

fn sys_getdefaultencoding(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getdefaultencoding")?;

    Ok(Value::str(&vm.default_encoding_name()))
}

fn sys_getfilesystemencoding(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getfilesystemencoding")?;

    Ok(Value::str("mbcs"))
}

fn sys_getrecursionlimit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getrecursionlimit")?;

    Ok(vm.new_int_from_i64(vm.recursion_limit() as i64))
}

fn sys_setrecursionlimit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "setrecursionlimit", 1, 1)?;
    if args[0].is_unknown() {
        return Err(vm.halt_unsupported("sys.setrecursionlimit with an unknown limit"));
    }
    if vm.as_float(&args[0]).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }
    let Some(limit) = vm.as_index(&args[0]) else {
        return Err(vm.type_error("an integer is required"));
    };
    if limit <= 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "recursion limit must be positive"));
    }

    vm.set_recursion_limit(usize::try_from(limit).unwrap_or(usize::MAX));

    Ok(Value::None)
}

/// Reference counts are not modelled.
fn sys_getrefcount(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    positional(vm, args, "getrefcount", 1, 1)?;

    Ok(Value::unknown("sys.getrefcount()"))
}

/// Object sizes depend on the native object layout, which is not modelled.
fn sys_getsizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    positional(vm, args, "getsizeof", 1, 2)?;

    Ok(Value::unknown("sys.getsizeof()"))
}

/// The host's version is unknown, except that the game only runs on the NT
/// platform (`VER_PLATFORM_WIN32_NT`).
fn sys_getwindowsversion(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getwindowsversion")?;

    let class = windows_version_type(vm)?;
    let values = vec![
        Value::unknown("sys.getwindowsversion().major"),
        Value::unknown("sys.getwindowsversion().minor"),
        Value::unknown("sys.getwindowsversion().build"),
        Value::Int(2),
        Value::unknown("sys.getwindowsversion().service_pack"),
    ];

    Ok(new_struct_sequence(vm, &class, values))
}

fn windows_version_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "sys.getwindowsversion", |vm| new_struct_sequence_type(vm, "sys", "getwindowsversion", &WINDOWS_VERSION))
}

/// Tracing and profiling only observe execution; installing a hook would
/// run Python code the interpreter cannot schedule as CPython does.
fn install_hook(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    let [hook] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!("{name}() takes exactly one argument ({} given)", args.positional.len())));
    };
    if !hook.is_none() {
        return Err(vm.halt_unsupported(format!("sys.{name} hooks")));
    }

    Ok(Value::None)
}

fn sys_settrace(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    install_hook(vm, &args, "settrace")
}

/// `sys.setprofile(None)` removes any C profile function as well.
fn sys_setprofile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    install_hook(vm, &args, "setprofile")?;
    set_profile_object(vm, None);

    Ok(Value::None)
}

fn create_stream_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_type(
        vm,
        TypeSpec {
            name: "StandardStream",
            module: "sys",
            base: None,
            layout: Layout::Native,
            instance_dict: true,
            methods: &[
                method("write", stream_write),
                method("writelines", stream_writelines),
                method("flush", stream_none),
                method("close", stream_none),
                method("isatty", stream_unknown),
                method("fileno", stream_unknown),
                method("read", stream_unknown),
                method("readline", stream_unknown),
                method("readlines", stream_unknown),
                method("__repr__", stream_repr),
            ],
        },
    )
}

fn stream_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<StandardStream>(vm, &args, "sys.StandardStream", "write")?;
    let args = positional(vm, args, "write", 2, 2)?;

    let text = &args[1];
    if !text.is_unknown() && vm.as_str_bytes(text).is_none() && vm.as_text(text).is_none() {
        return Err(vm.type_error(&format!("expected a string or other character buffer object, not {}", vm.type_name(text))));
    }

    Ok(Value::None)
}

fn stream_writelines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<StandardStream>(vm, &args, "sys.StandardStream", "writelines")?;
    let args = positional(vm, args, "writelines", 2, 2)?;

    let iterator = vm.iter(&args[1])?;
    while let Some(line) = vm.next(&iterator)? {
        if !line.is_unknown() && vm.as_str_bytes(&line).is_none() && vm.as_text(&line).is_none() {
            return Err(vm.type_error("writelines() argument must be a sequence of strings"));
        }
    }

    Ok(Value::None)
}

fn stream_none(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<StandardStream>(vm, &args, "sys.StandardStream", "flush")?;

    Ok(Value::None)
}

/// Console state and input come from the host.
fn stream_unknown(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = this::<StandardStream>(vm, &args, "sys.StandardStream", "read")?;

    vm.host_operation(HostCapability::Console, format!("{} stream state", stream.name))
}

/// `file.__repr__`.
fn stream_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let stream = this::<StandardStream>(vm, &args, "sys.StandardStream", "__repr__")?;
    let mode = if stream.name == "<stdin>" { "r" } else { "w" };
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error("descriptor '__repr__' of 'file' object needs an argument"));
    };

    Ok(Value::str(&format!("<open file '{}', mode '{mode}' at {}>", stream.name, vm.pointer_text(vm.value_address(receiver)))))
}

