//! The `msvcrt` module. Arguments are checked as the Windows build parses
//! them; console, locking, heap, and descriptor results come from the host
//! and are unknown.

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::host_arguments::bad_descriptor;
use crate::interp::builtins::modules::host_arguments::c_long;
use crate::interp::builtins::modules::host_arguments::character;
use crate::interp::builtins::modules::host_arguments::exact;
use crate::interp::builtins::modules::host_arguments::is_unverifiable_descriptor;
use crate::interp::builtins::modules::host_arguments::unicode;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The `_LK_*` modes of the Visual C++ `sys/locking.h`, in module
/// initialization order.
const LOCKING_MODES: [(&str, i64); 5] = [("LK_LOCK", 1), ("LK_NBLCK", 2), ("LK_NBRLCK", 4), ("LK_RLCK", 3), ("LK_UNLCK", 0)];

/// The assembly constants of the Visual C++ 2008 `crtassem.h`.
const ASSEMBLY_STRINGS: [(&str, &str); 3] = [
    ("VC_ASSEMBLY_PUBLICKEYTOKEN", "1fc8b3b9a1e18e3b"),
    ("CRT_ASSEMBLY_VERSION", "9.0.21022.8"),
    ("LIBRARIES_ASSEMBLY_NAME_PREFIX", "Microsoft.VC90"),
];

/// Console functions without arguments whose results come from the host.
macro_rules! console_queries {
    ($($rust:ident => $name:literal),* $(,)?) => {
        $(
            fn $rust(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let [] = exact(vm, args, $name)?;

                vm.host_operation(HostCapability::Console, concat!("msvcrt.", $name, "() (host console)"))
            }
        )*
    };
}

console_queries! {
    msvcrt_kbhit => "kbhit",
    msvcrt_getch => "getch",
    msvcrt_getche => "getche",
    msvcrt_getwch => "getwch",
    msvcrt_getwche => "getwche",
}

/// `msvcrt` functions in table order.
const FUNCTIONS: [MethodSpec; 14] = [
    function("heapmin", msvcrt_heapmin),
    function("locking", msvcrt_locking),
    function("setmode", msvcrt_setmode),
    function("open_osfhandle", msvcrt_open_osfhandle),
    function("get_osfhandle", msvcrt_get_osfhandle),
    function("kbhit", msvcrt_kbhit),
    function("getch", msvcrt_getch),
    function("getche", msvcrt_getche),
    function("putch", msvcrt_putch),
    function("ungetch", msvcrt_ungetch),
    function("getwch", msvcrt_getwch),
    function("getwche", msvcrt_getwche),
    function("putwch", msvcrt_putwch),
    function("ungetwch", msvcrt_ungetwch),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    for (name, value) in LOCKING_MODES {
        set_attribute(vm, module, name, Value::Int(value))?;
    }
    for (name, value) in ASSEMBLY_STRINGS {
        set_attribute(vm, module, name, Value::str(value))?;
    }

    Ok(())
}

fn msvcrt_heapmin(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [] = exact(vm, args, "heapmin")?;

    vm.host_operation(HostCapability::Process, "msvcrt.heapmin() (host heap)")
}

fn msvcrt_locking(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [descriptor, mode, length] = exact(vm, args, "locking")?;
    c_int(vm, &descriptor)?;
    c_int(vm, &mode)?;
    c_long(vm, &length)?;

    vm.host_operation(HostCapability::FileSystem, "msvcrt.locking() (host file locks)")
}

fn msvcrt_setmode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [descriptor, flags] = exact(vm, args, "setmode")?;
    c_int(vm, &descriptor)?;
    c_int(vm, &flags)?;

    vm.host_operation(HostCapability::FileSystem, "msvcrt.setmode() (host file descriptor table)")
}

fn msvcrt_open_osfhandle(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [handle, flags] = exact(vm, args, "open_osfhandle")?;
    c_long(vm, &handle)?;
    c_int(vm, &flags)?;

    vm.host_operation(HostCapability::FileSystem, "msvcrt.open_osfhandle() (host file descriptor table)")
}

/// `msvcrt.get_osfhandle`: descriptors the descriptor check rejects
/// without consulting the CRT tables fail exactly.
fn msvcrt_get_osfhandle(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [descriptor] = exact(vm, args, "get_osfhandle")?;
    let descriptor = c_int(vm, &descriptor)?;

    if descriptor.is_some_and(|descriptor| is_unverifiable_descriptor(i64::from(descriptor))) {
        return Err(bad_descriptor(vm));
    }

    vm.host_operation(HostCapability::FileSystem, "msvcrt.get_osfhandle() (host file descriptor table)")
}

fn msvcrt_putch(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [character_argument] = exact(vm, args, "putch")?;
    character(vm, &character_argument, "putch", 1)?;

    vm.host_operation(HostCapability::Console, "msvcrt.putch() (host console)")
}

fn msvcrt_ungetch(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [character_argument] = exact(vm, args, "ungetch")?;
    character(vm, &character_argument, "ungetch", 1)?;

    vm.host_operation(HostCapability::Console, "msvcrt.ungetch() (host console)")
}

/// `msvcrt.putwch` parses `u#`, which rejects every non-unicode argument
/// as a raw buffer.
fn msvcrt_putwch(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [text] = exact(vm, args, "putwch")?;
    let length = unicode(vm, &text, "putwch", 1, "cannot convert raw buffers")?;

    if length == Some(0) {
        return Err(vm.raise(ExceptionKind::ValueError, "Expected unicode string of length 1"));
    }

    vm.host_operation(HostCapability::Console, "msvcrt.putwch() (host console)")
}

fn msvcrt_ungetwch(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [text] = exact(vm, args, "ungetwch")?;
    unicode(vm, &text, "ungetwch", 1, "unicode")?;

    vm.host_operation(HostCapability::Console, "msvcrt.ungetwch() (host console)")
}
