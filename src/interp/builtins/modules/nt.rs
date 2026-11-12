//! The `nt` module of the Windows build. Every name the Windows build
//! defines exists, since `os` re-exports them. Results of host operating
//! system calls are unknown values; calls that end or replace the process
//! halt.

use std::cell::Cell;
use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_struct_sequence_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::time::argument_prefix;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Visible fields of `stat_result`. CPython also stores float times in
/// hidden fields behind `st_atime`, `st_mtime`, and `st_ctime`; these
/// names read the integer times here.
const STAT_RESULT_FIELDS: [&str; 10] = [
    "st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime",
    "st_mtime", "st_ctime",
];

const STATVFS_RESULT_FIELDS: [&str; 10] = [
    "f_bsize",
    "f_frsize",
    "f_blocks",
    "f_bfree",
    "f_bavail",
    "f_files",
    "f_ffree",
    "f_favail",
    "f_flag",
    "f_namemax",
];

/// Module constants in insertion order, with the Visual C++ `fcntl.h`,
/// `stdio.h`, and `process.h` values.
const CONSTANTS: [(&str, i64); 24] = [
    ("F_OK", 0),
    ("R_OK", 4),
    ("W_OK", 2),
    ("X_OK", 1),
    ("TMP_MAX", 32767),
    ("O_RDONLY", 0x0000),
    ("O_WRONLY", 0x0001),
    ("O_RDWR", 0x0002),
    ("O_APPEND", 0x0008),
    ("O_CREAT", 0x0100),
    ("O_EXCL", 0x0400),
    ("O_TRUNC", 0x0200),
    ("O_BINARY", 0x8000),
    ("O_TEXT", 0x4000),
    ("O_NOINHERIT", 0x0080),
    ("O_SHORT_LIVED", 0x1000),
    ("O_TEMPORARY", 0x0040),
    ("O_RANDOM", 0x0010),
    ("O_SEQUENTIAL", 0x0020),
    ("P_WAIT", 0),
    ("P_NOWAIT", 1),
    ("P_OVERLAY", 2),
    ("P_NOWAITO", 3),
    ("P_DETACH", 4),
];

/// `_sys_errlist` of the Visual C++ CRT, indexed by `errno`.
const ERROR_MESSAGES: [&str; 43] = [
    "No error",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted function call",
    "Input/output error",
    "No such device or address",
    "Arg list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Not enough space",
    "Permission denied",
    "Bad address",
    "Unknown error",
    "Resource device",
    "File exists",
    "Improper link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate I/O control operation",
    "Unknown error",
    "File too large",
    "No space left on device",
    "Invalid seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Domain error",
    "Result too large",
    "Unknown error",
    "Resource deadlock avoided",
    "Unknown error",
    "Filename too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Illegal byte sequence",
];

struct NtState {
    /// `os.stat_float_times()`; `None` once set from an unknown value.
    stat_float_times: Cell<Option<bool>>,
}

impl Default for NtState {
    fn default() -> Self {
        Self {
            stat_float_times: Cell::new(Some(true)),
        }
    }
}

/// Functions without arguments whose results come from the host.
macro_rules! host_queries {
    ($($rust:ident => $name:literal, $capability:ident),* $(,)?) => {
        $(
            fn $rust(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                no_arguments(vm, &args, $name)?;

                vm.host_operation(HostCapability::$capability, concat!("nt.", $name, "() (host operating system)"))
            }
        )*
    };
}

host_queries! {
    nt_getcwd => "getcwd", FileSystem,
    nt_getcwdu => "getcwdu", FileSystem,
    nt_times => "times", Clock,
    nt_getpid => "getpid", Randomness,
    nt_pipe => "pipe", Process,
    nt_tmpfile => "tmpfile", FileSystem,
    nt_tmpnam => "tmpnam", FileSystem,
}

/// Functions whose arguments are checked as the Windows build parses them
/// and whose results come from the host. A `path` function's refusal
/// reports its first argument as the filename.
macro_rules! host_functions {
    ($($rust:ident => $name:literal, $capability:ident, $path:literal, $format:expr;)*) => {
        $(
            fn $rust(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let arguments = parse_arguments(vm, &args, $name, &$format)?;
                let filename = if $path { arguments.first() } else { None };

                vm.host_operation_on(
                    HostCapability::$capability,
                    concat!("nt.", $name, "() (host operating system)"),
                    Denial::Native,
                    filename,
                )
            }
        )*
    };
}

host_functions! {
    nt_access => "access", FileSystem, true, named("access", &[PATH, Unit::Int], &[]);
    nt_chdir => "chdir", FileSystem, true, named("chdir", &[Unit::WideText], &[]);
    nt_chmod => "chmod", FileSystem, true, named("chmod", &[PATH, Unit::Int], &[]);
    nt_listdir => "listdir", FileSystem, true, named("listdir", &[PATH_WITH_NULLS], &[]);
    nt_lstat => "lstat", FileSystem, true, named("lstat", &[PATH], &[]);
    nt_mkdir => "mkdir", FileSystem, true, named("mkdir", &[PATH], &[Unit::Int]);
    nt_rmdir => "rmdir", FileSystem, true, named("rmdir", &[Unit::WideText], &[]);
    nt_stat => "stat", FileSystem, true, named("stat", &[PATH], &[]);
    nt_system => "system", Process, false, named("system", &[Unit::Text], &[]);
    nt_umask => "umask", FileSystem, false, named("umask", &[Unit::Int], &[]);
    nt_unlink => "unlink", FileSystem, true, named("remove", &[Unit::WideText], &[]);
    nt_remove => "remove", FileSystem, true, named("remove", &[Unit::WideText], &[]);
    nt_utime => "utime", FileSystem, true, named("utime", &[PATH, Unit::Object], &[]);
    nt_popen => "popen", Process, false, named("popen", &[Unit::Text], &[Unit::Text, Unit::Int]);
    nt_popen2 => "popen2", Process, false, named("popen2", &[Unit::Text], &[Unit::Text, Unit::Int]);
    nt_popen3 => "popen3", Process, false, named("popen3", &[Unit::Text], &[Unit::Text, Unit::Int]);
    nt_popen4 => "popen4", Process, false, named("popen4", &[Unit::Text], &[Unit::Text, Unit::Int]);
    nt_startfile => "startfile", Process, true, named("startfile", &[PATH], &[Unit::Text]);
    nt_kill => "kill", Process, false, named("kill", &[Unit::UnsignedLong, Unit::UnsignedLong], &[]);
    nt_waitpid => "waitpid", Process, false, named("waitpid", &[Unit::Int, Unit::Int], &[]);
    nt_open => "open", FileSystem, true, Format { name: None, required: &[PATH, Unit::Int], optional: &[Unit::Int] };
    nt_close => "close", FileSystem, false, named("close", &[Unit::Int], &[]);
    nt_closerange => "closerange", FileSystem, false, named("closerange", &[Unit::Int, Unit::Int], &[]);
    nt_dup => "dup", FileSystem, false, named("dup", &[Unit::Int], &[]);
    nt_dup2 => "dup2", FileSystem, false, named("dup2", &[Unit::Int, Unit::Int], &[]);
    nt_write => "write", FileSystem, false, named("write", &[Unit::Int, Unit::Buffer], &[]);
    nt_fstat => "fstat", FileSystem, false, named("fstat", &[Unit::Int], &[]);
    nt_isatty => "isatty", FileSystem, false, named("isatty", &[Unit::Int], &[]);
    nt_tempnam => "tempnam", FileSystem, false, named("tempnam", &[], &[Unit::OptionalText, Unit::OptionalText]);
    nt_getfullpathname => "_getfullpathname", FileSystem, true, named("_getfullpathname", &[PATH_WITH_NULLS], &[]);
    nt_isdir => "_isdir", FileSystem, true, named("_isdir", &[PATH], &[]);
}

/// `nt` functions in table order for the Windows build.
const FUNCTIONS: [MethodSpec; 53] = [
    function("access", nt_access),
    function("chdir", nt_chdir),
    function("chmod", nt_chmod),
    function("getcwd", nt_getcwd),
    function("getcwdu", nt_getcwdu),
    function("listdir", nt_listdir),
    function("lstat", nt_lstat),
    function("mkdir", nt_mkdir),
    function("rename", nt_rename),
    function("rmdir", nt_rmdir),
    function("stat", nt_stat),
    function("stat_float_times", nt_stat_float_times),
    function("system", nt_system),
    function("umask", nt_umask),
    function("unlink", nt_unlink),
    function("remove", nt_remove),
    function("utime", nt_utime),
    function("times", nt_times),
    function("_exit", nt_exit),
    function("execv", nt_execv),
    function("execve", nt_execve),
    function("spawnv", nt_spawnv),
    function("spawnve", nt_spawnve),
    function("getpid", nt_getpid),
    function("popen", nt_popen),
    function("popen2", nt_popen2),
    function("popen3", nt_popen3),
    function("popen4", nt_popen4),
    function("startfile", nt_startfile),
    function("kill", nt_kill),
    function("waitpid", nt_waitpid),
    function("open", nt_open),
    function("close", nt_close),
    function("closerange", nt_closerange),
    function("dup", nt_dup),
    function("dup2", nt_dup2),
    function("lseek", nt_lseek),
    function("read", nt_read),
    function("write", nt_write),
    function("fstat", nt_fstat),
    function("fdopen", nt_fdopen),
    function("isatty", nt_isatty),
    function("pipe", nt_pipe),
    function("putenv", nt_putenv),
    function("strerror", nt_strerror),
    function("fsync", nt_fsync),
    function("tmpfile", nt_tmpfile),
    function("tempnam", nt_tempnam),
    function("tmpnam", nt_tmpnam),
    function("abort", nt_abort),
    function("_getfullpathname", nt_getfullpathname),
    function("_isdir", nt_isdir),
    function("urandom", nt_urandom),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    // The host environment is not emulated: client code sees an empty
    // environment, as if the process had been started without one.
    set_attribute(vm, module, "environ", Value::Object(vm.new_dict()))?;

    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    set_attribute(
        vm,
        module,
        "error",
        Value::Object(Rc::clone(vm.types().exception(ExceptionKind::OSError))),
    )?;
    set_attribute(
        vm,
        module,
        "stat_result",
        Value::Object(native_type(vm, "nt.stat_result", |vm| {
            new_struct_sequence_type(vm, "nt", "stat_result", &STAT_RESULT_FIELDS)
        })?),
    )?;
    set_attribute(
        vm,
        module,
        "statvfs_result",
        Value::Object(native_type(vm, "nt.statvfs_result", |vm| {
            new_struct_sequence_type(vm, "nt", "statvfs_result", &STATVFS_RESULT_FIELDS)
        })?),
    )?;

    Ok(())
}

/// `stat_float_times([newval])`: with no argument (or -1) reports the
/// setting, otherwise stores it.
fn nt_stat_float_times(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "stat_float_times", 0, 1)?;
    let state = vm.native_state::<NtState>();

    let new_value = match args.first() {
        Some(argument) => match c_int(vm, argument)? {
            Some(number) => Some(number),
            None => {
                state.stat_float_times.set(None);
                return Ok(Value::unknown(
                    "nt.stat_float_times() set from an unknown value",
                ));
            }
        },
        None => None,
    };

    match new_value {
        None | Some(-1) => Ok(state.stat_float_times.get().map_or_else(
            || Value::unknown("nt.stat_float_times() set from an unknown value"),
            Value::Bool,
        )),
        Some(number) => {
            state.stat_float_times.set(Some(number != 0));
            Ok(Value::None)
        }
    }
}

/// `os.strerror` with the CRT `strerror`, which reports codes outside
/// its table as "Unknown error".
fn nt_strerror(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "strerror", 1, 1)?;
    let Some(code) = c_int(vm, &args[0])? else {
        return Ok(Value::unknown("nt.strerror() of an unknown code"));
    };

    let message = usize::try_from(code)
        .ok()
        .and_then(|index| ERROR_MESSAGES.get(index))
        .copied()
        .unwrap_or("Unknown error");

    Ok(Value::str(message))
}

/// `os._exit`: validated, then halts since it ends the process.
fn nt_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    parse_arguments(vm, &args, "_exit", &named("_exit", &[Unit::Int], &[]))?;

    vm.host_permit(HostCapability::Process, Denial::Native, None)?;
    Err(vm.halt_unsupported("nt._exit ends the process"))
}

fn nt_abort(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "abort")?;

    vm.host_permit(HostCapability::Process, Denial::Native, None)?;
    Err(vm.halt_unsupported("nt.abort ends the process"))
}

/// `os.execv`: validated, then halts since it replaces the process.
fn nt_execv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "execv",
        &named("execv", &[NARROW_PATH, Unit::Object], &[]),
    )?;
    check_argv(vm, &arguments[1], "execv", true)?;

    vm.host_permit(HostCapability::Process, Denial::Native, None)?;
    Err(vm.halt_unsupported("nt.execv replaces the process"))
}

/// `os.execve`: validated, then halts since it replaces the process.
fn nt_execve(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "execve",
        &named("execve", &[NARROW_PATH, Unit::Object, Unit::Object], &[]),
    )?;
    check_argv(vm, &arguments[1], "execve", false)?;
    check_environment(vm, &arguments[2], "execve")?;

    vm.host_permit(HostCapability::Process, Denial::Native, None)?;
    Err(vm.halt_unsupported("nt.execve replaces the process"))
}

fn nt_spawnv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "spawnv",
        &named("spawnv", &[Unit::Int, NARROW_PATH, Unit::Object], &[]),
    )?;
    check_argv(vm, &arguments[2], "spawnv", false)?;

    vm.host_operation(HostCapability::Process, "nt.spawnv() (host operating system)")
}

fn nt_spawnve(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "spawnve",
        &named(
            "spawnve",
            &[Unit::Int, NARROW_PATH, Unit::Object, Unit::Object],
            &[],
        ),
    )?;
    check_argv(vm, &arguments[2], "spawnve", false)?;
    check_environment(vm, &arguments[3], "spawnve")?;

    vm.host_operation(HostCapability::Process, "nt.spawnve() (host operating system)")
}

/// The argument vector of the exec and spawn functions: a list or tuple
/// of strings, nonempty for `execv`.
fn check_argv(vm: &Vm, argv: &Value, function: &str, nonempty: bool) -> PyResult<()> {
    if argv.is_unknown() {
        return Ok(());
    }
    let Some(items) = vm
        .as_list(argv)
        .or_else(|| vm.as_tuple(argv).map(|items| items.to_vec()))
    else {
        return Err(vm.type_error(&format!("{function}() arg 2 must be a tuple or list")));
    };
    if nonempty && items.is_empty() {
        return Err(vm.raise(
            ExceptionKind::ValueError,
            &format!("{function}() arg 2 must not be empty"),
        ));
    }

    let is_text = |item: &Value| {
        item.is_unknown() || vm.as_str_bytes(item).is_some() || vm.as_text(item).is_some()
    };
    if !items.iter().all(is_text) {
        return Err(vm.type_error(&format!("{function}() arg 2 must contain only strings")));
    }

    Ok(())
}

/// The environment of `execve` and `spawnve`, which must be a mapping.
fn check_environment(vm: &Vm, environment: &Value, function: &str) -> PyResult<()> {
    let is_mapping = match environment {
        Value::Unknown(_) => true,
        Value::Object(_) => {
            vm.lookup_special(environment, "__getitem__")?.is_some()
                && vm.as_list(environment).is_none()
                && vm.as_tuple(environment).is_none()
        }
        _ => false,
    };
    if !is_mapping {
        return Err(vm.type_error(&format!("{function}() arg 3 must be a mapping object")));
    }

    Ok(())
}

/// `os.read`: a negative size fails before the descriptor is used.
fn nt_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "read",
        &named("read", &[Unit::Int, Unit::Int], &[]),
    )?;
    if let Some(size) = c_int(vm, &arguments[1])?
        && size < 0
    {
        return Err(os_error(vm, EINVAL));
    }

    vm.host_operation(HostCapability::FileSystem, "nt.read() (host operating system)")
}

/// `os.lseek`: the position converts as a C `long` or, for a `long`, as a
/// C `long long`.
fn nt_lseek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "lseek",
        &named("lseek", &[Unit::Int, Unit::Object, Unit::Int], &[]),
    )?;
    let position = &arguments[1];

    match vm.as_integral(position) {
        Some(Integral::Long(number)) if number.to_i64().is_none() => {
            return Err(vm.raise(ExceptionKind::OverflowError, "long too big to convert"));
        }
        Some(_) => {}
        None if position.is_unknown() || vm.as_float(position).is_some() => {}
        None if vm.lookup_special(position, "__int__")?.is_some() => {}
        None => return Err(vm.type_error("an integer is required")),
    }

    vm.host_operation(HostCapability::FileSystem, "nt.lseek() (host operating system)")
}

/// `os.fdopen`: the mode is checked before the descriptor is used.
fn nt_fdopen(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "fdopen",
        &Format {
            name: None,
            required: &[Unit::Int],
            optional: &[Unit::Text, Unit::Int],
        },
    )?;
    if let Some(mode) = arguments.get(1)
        && let Some(mode) = c_string(vm, mode, None, 2)?
    {
        sanitize_mode(vm, mode.as_bytes())?;
    }

    vm.host_operation(HostCapability::FileSystem, "nt.fdopen() (host operating system)")
}

/// File mode normalization with the Windows mode check.
fn sanitize_mode(vm: &Vm, original: &[u8]) -> PyResult<()> {
    if original.is_empty() {
        return Err(vm.raise(ExceptionKind::ValueError, "empty mode string"));
    }

    let mut mode = original.to_vec();
    if let Some(position) = mode.iter().position(|byte| *byte == b'U') {
        mode.remove(position);
        if matches!(mode.first(), Some(b'w' | b'a')) {
            return Err(vm.raise(
                ExceptionKind::ValueError,
                "universal newline mode can only be used with modes starting with 'r'",
            ));
        }
        if mode.first() != Some(&b'r') {
            mode.insert(0, b'r');
        }
        if !mode.contains(&b'b') {
            mode.insert(1, b'b');
        }
    } else if !matches!(mode.first(), Some(b'r' | b'w' | b'a')) {
        let shown = String::from_utf8_lossy(original.get(..200).unwrap_or(original));
        return Err(vm.raise(
            ExceptionKind::ValueError,
            &format!("mode string must begin with one of 'r', 'w', 'a' or 'U', not '{shown}'"),
        ));
    }

    if !is_valid_crt_mode(&mode) {
        let shown = String::from_utf8_lossy(mode.get(..50).unwrap_or(&mode));
        return Err(vm.raise(
            ExceptionKind::ValueError,
            &format!("Invalid mode ('{shown}')"),
        ));
    }

    Ok(())
}

/// The Windows mode check. Its `,ccs=` branch compares from the comma, so
/// every mode with an encoding is rejected; letters of the pairs `bt`,
/// `cn`, and `SR` share one slot.
fn is_valid_crt_mode(mode: &[u8]) -> bool {
    let mode: Vec<u8> = mode
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ')
        .collect();
    let Some((first, rest)) = mode.split_first() else {
        return false;
    };
    if !b"rwa".contains(first) {
        return false;
    }

    let mut singles = [false; 3];
    let mut pairs = [false; 3];
    for byte in rest {
        let slot = if let Some(index) = b"+TD".iter().position(|single| single == byte) {
            &mut singles[index]
        } else if let Some(index) = b"btcnSR".iter().position(|pair| pair == byte) {
            &mut pairs[index / 2]
        } else if *byte == b' ' || *byte == b'N' {
            continue;
        } else {
            return false;
        };
        if *slot {
            return false;
        }
        *slot = true;
    }

    true
}

/// `os.putenv`: `_putenv("name=value")`, which takes the name up to the
/// first `=` and fails when it is empty.
fn nt_putenv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const MAX_ENV: usize = 32767;

    let arguments = parse_arguments(
        vm,
        &args,
        "putenv",
        &named("putenv", &[Unit::Text, Unit::Text], &[]),
    )?;
    let (Some(name), Some(value)) = (
        c_string(vm, &arguments[0], Some("putenv"), 1)?,
        c_string(vm, &arguments[1], Some("putenv"), 2)?,
    ) else {
        return vm.host_operation(HostCapability::Environment, "nt.putenv() (host operating system)");
    };

    if name.as_bytes().len() + value.as_bytes().len() + 1 > MAX_ENV {
        return Err(vm.raise(
            ExceptionKind::ValueError,
            &format!("the environment variable is longer than {MAX_ENV} bytes"),
        ));
    }
    if name.as_bytes().first().is_none_or(|first| *first == b'=') {
        return Err(os_error(vm, EINVAL));
    }

    vm.host_operation(HostCapability::Environment, "nt.putenv() (host operating system)")
}

/// `os.rename`: two strings, tried as unicode and then as `ss`.
fn nt_rename(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(
        vm,
        &args,
        "rename",
        &named("rename", &[Unit::Object, Unit::Object], &[]),
    )?;

    let is_text = |item: &Value| {
        item.is_unknown() || vm.as_str_bytes(item).is_some() || vm.as_text(item).is_some()
    };
    if !arguments.iter().all(is_text) {
        for (index, argument) in arguments.iter().enumerate() {
            c_string(vm, argument, Some("rename"), index + 1)?;
        }
    }

    vm.host_operation_on(HostCapability::FileSystem, "nt.rename() (host operating system)", Denial::Native, arguments.first())
}

/// `os.urandom`.
fn nt_urandom(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = parse_arguments(vm, &args, "urandom", &named("urandom", &[Unit::Size], &[]))?;
    if vm.as_index(&arguments[0]).is_some_and(|size| size < 0) {
        return Err(vm.raise(ExceptionKind::ValueError, "negative argument not allowed"));
    }

    vm.host_operation_on(HostCapability::Randomness, "nt.urandom() (host random source)", Denial::Unavailable, None)
}

/// `os.fsync` of a descriptor or an object with `fileno`.
fn nt_fsync(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("fsync() takes no keyword arguments"));
    }
    let [descriptor] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!(
            "fsync() takes exactly one argument ({} given)",
            args.positional.len()
        )));
    };

    file_descriptor(vm, descriptor)?;

    vm.host_operation(HostCapability::FileSystem, "nt.fsync() (host operating system)")
}

/// A descriptor from an integer or `fileno()`; `None` when the descriptor is
/// unknown.
fn file_descriptor(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let number = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let Some(fileno) = vm.getattr_opt(value, &vm.name("fileno"))? else {
                return Err(vm.type_error("argument must be an int, or have a fileno() method."));
            };
            let result = vm.call0(&fileno)?;
            if result.is_unknown() {
                return Ok(None);
            }
            let Some(integral) = vm.as_integral(&result) else {
                return Err(vm.type_error("fileno() returned a non-integer"));
            };
            integral
        }
    };

    let descriptor = match number {
        Integral::Int(number) => i32::try_from(number).ok(),
        Integral::Long(number) => number.to_i32(),
    };
    let Some(descriptor) = descriptor else {
        return Err(vm.raise(
            ExceptionKind::OverflowError,
            "Python int too large to convert to C int",
        ));
    };
    if descriptor < 0 {
        return Err(vm.raise(
            ExceptionKind::ValueError,
            &format!("file descriptor cannot be a negative integer ({descriptor})"),
        ));
    }

    Ok(Some(descriptor))
}

/// `EINVAL` of the CRT.
const EINVAL: i32 = 22;

/// The `OSError(code, strerror(code))` for `code`.
fn os_error(vm: &Vm, code: i32) -> Signal {
    let message = usize::try_from(code)
        .ok()
        .and_then(|index| ERROR_MESSAGES.get(index))
        .copied()
        .unwrap_or("Unknown error");
    let class = Rc::clone(vm.types().exception(ExceptionKind::OSError));

    match vm.instantiate_exception(
        &class,
        vec![Value::Int(i64::from(code)), Value::str(message)],
    ) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// One unit of an argument format.
#[derive(Clone, Copy)]
enum Unit {
    /// `i`
    Int,
    /// `k`: any integer, without range checking.
    UnsignedLong,
    /// `n`
    Size,
    /// `s`
    Text,
    /// `z`
    OptionalText,
    /// `s*`
    Buffer,
    /// `et`, or `et#` when `null_bytes` is set. When `wide` is set the
    /// function first tries `u`, which accepts any unicode string.
    Path { wide: bool, null_bytes: bool },
    /// `s` after a `U` attempt: unicode is accepted as is.
    WideText,
    /// `O`
    Object,
}

/// A path tried as unicode first, then as `et`.
const PATH: Unit = Unit::Path {
    wide: true,
    null_bytes: false,
};
/// A path tried as unicode first, then as `et#`.
const PATH_WITH_NULLS: Unit = Unit::Path {
    wide: true,
    null_bytes: true,
};
/// A path parsed only as `et`.
const NARROW_PATH: Unit = Unit::Path {
    wide: false,
    null_bytes: false,
};

/// An argument format. `name` follows the `:` of the format and prefixes
/// its messages; nameless formats report "function".
struct Format {
    name: Option<&'static str>,
    required: &'static [Unit],
    optional: &'static [Unit],
}

const fn named(name: &'static str, required: &'static [Unit], optional: &'static [Unit]) -> Format {
    Format {
        name: Some(name),
        required,
        optional,
    }
}

/// Argument parsing of a varargs function named `function`.
fn parse_arguments(
    vm: &Vm,
    args: &CallArgs,
    function: &str,
    format: &Format,
) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let given = args.positional.len();
    let minimum = format.required.len();
    let maximum = minimum + format.optional.len();
    if !(minimum..=maximum).contains(&given) {
        let (bound, limit) = if minimum == maximum {
            ("exactly", minimum)
        } else if given < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if limit == 1 { "" } else { "s" };
        let subject = format
            .name
            .map_or_else(|| "function".to_owned(), |name| format!("{name}()"));
        return Err(vm.type_error(&format!(
            "{subject} takes {bound} {limit} argument{plural} ({given} given)"
        )));
    }

    let units = format.required.iter().chain(format.optional);
    for (index, (argument, unit)) in args.positional.iter().zip(units).enumerate() {
        check_unit(vm, argument, *unit, format.name, index + 1)?;
    }

    Ok(args.positional.clone())
}

/// Converts one argument as its format unit would, keeping only errors.
fn check_unit(
    vm: &Vm,
    value: &Value,
    unit: Unit,
    name: Option<&str>,
    position: usize,
) -> PyResult<()> {
    if value.is_unknown() {
        return Ok(());
    }

    let prefix = argument_prefix(name);
    let is_text = vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some();
    match unit {
        Unit::Int => {
            c_int(vm, value)?;
        }
        Unit::UnsignedLong => {
            if vm.as_integral(value).is_none() {
                return Err(vm.type_error(&format!(
                    "{prefix}argument {position} must be integer<k>, not {}",
                    converted_type_name(vm, value)
                )));
            }
        }
        Unit::Size => {
            if vm.as_float(value).is_some() {
                return Err(vm.type_error("integer argument expected, got float"));
            }
            match vm.as_integral(value) {
                None => return Err(vm.type_error("an integer is required")),
                Some(Integral::Long(number)) if number.to_i64().is_none() => {
                    return Err(vm.raise(
                        ExceptionKind::OverflowError,
                        "cannot fit 'long' into an index-sized integer",
                    ));
                }
                Some(_) => {}
            }
        }
        Unit::Text => {
            c_string(vm, value, name, position)?;
        }
        Unit::OptionalText => {
            if !value.is_none() && !is_text {
                return Err(vm.type_error(&format!(
                    "{prefix}argument {position} must be string or None, not {}",
                    converted_type_name(vm, value)
                )));
            }
            if !value.is_none() {
                c_string(vm, value, name, position)?;
            }
        }
        Unit::Buffer => {
            let types = vm.types();
            let is_buffer = [&types.bytearray, &types.buffer, &types.memoryview]
                .into_iter()
                .any(|class| vm.is_instance_of(value, class).unwrap_or(false));
            if !is_text && !is_buffer {
                return Err(vm.type_error(&format!(
                    "{prefix}argument {position} must be string or buffer, not {}",
                    converted_type_name(vm, value)
                )));
            }
        }
        Unit::Path { wide, null_bytes } => {
            let (units_contain_null, kind) = match (vm.as_str_bytes(value), vm.as_text(value)) {
                (Some(bytes), _) => (bytes.as_bytes().contains(&0), "str"),
                (None, Some(_)) if wide => (false, "unicode"),
                (None, Some(text)) => (text.units().contains(&0), "unicode"),
                (None, None) => {
                    return Err(vm.type_error(&format!(
                        "coercing to Unicode: need string or buffer, {} found",
                        vm.type_name(value)
                    )));
                }
            };
            if units_contain_null && !null_bytes {
                return Err(vm.type_error(&format!("{prefix}argument {position} must be encoded string without null bytes, not {kind}")));
            }
        }
        Unit::WideText => {
            if vm.as_text(value).is_none() {
                c_string(vm, value, name, position)?;
            }
        }
        Unit::Object => {}
    }

    Ok(())
}
