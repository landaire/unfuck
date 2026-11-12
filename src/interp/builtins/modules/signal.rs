//! The `signal` module of the Windows build. No signal ever arrives, so
//! installed handlers never run; the module keeps the handler table
//! `signal` and `getsignal` report.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::host_arguments::exact;
use crate::interp::builtins::modules::host_arguments::is_unverifiable_descriptor;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `NSIG` of the Visual C++ `signal.h`.
const NSIG: i32 = 23;

/// Slots of the handler tables, one per signal number below `NSIG`.
const SLOTS: usize = 23;

/// Signal numbers of the Visual C++ `signal.h`, in module initialization
/// order.
const SIGNALS: [(&str, i32); 7] = [
    ("SIGINT", SIGINT),
    ("SIGBREAK", 21),
    ("SIGILL", 4),
    ("SIGABRT", 22),
    ("SIGFPE", 8),
    ("SIGSEGV", 11),
    ("SIGTERM", 15),
];

const SIGINT: i32 = 2;
const SIGINT_SLOT: usize = 2;

/// `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` of `wincon.h`.
const CONSOLE_EVENTS: [(&str, i64); 2] = [("CTRL_C_EVENT", 0), ("CTRL_BREAK_EVENT", 1)];

/// The C runtime disposition of a signal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Default,
    Ignore,
    /// The interpreter's handler, which runs the Python handler.
    Python,
    /// Set from a handler of unknown kind.
    Unknown,
}

/// The C runtime handler table and the Python one (`Handlers`), which outlive
/// reinitialization of the module.
struct SignalState {
    dispositions: RefCell<Vec<Disposition>>,
    handlers: RefCell<Vec<Value>>,
    /// `IgnoreHandler`: `SIG_IGN` is compared by identity.
    ignore_handler: RefCell<Value>,
    /// The `set_wakeup_fd` descriptor; `None` once set to a descriptor only the host can check.
    wakeup_fd: Cell<Option<i32>>,
}

impl Default for SignalState {
    fn default() -> Self {
        Self {
            dispositions: RefCell::new(vec![Disposition::Default; SLOTS]),
            handlers: RefCell::new(vec![Value::None; SLOTS]),
            ignore_handler: RefCell::new(Value::None),
            wakeup_fd: Cell::new(Some(-1)),
        }
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("signal", signal_signal),
            function("getsignal", signal_getsignal),
            function("set_wakeup_fd", signal_set_wakeup_fd),
            function("default_int_handler", signal_default_int_handler),
        ],
    )?;

    // The null `SIG_DFL` is the int 0, `SIG_IGN` a long.
    let default_handler = Value::Int(0);
    let ignore_handler = Value::Long(Rc::new(BigInt::from(1)));
    set_attribute(vm, module, "SIG_DFL", default_handler.clone())?;
    set_attribute(vm, module, "SIG_IGN", ignore_handler.clone())?;
    set_attribute(vm, module, "NSIG", Value::Int(i64::from(NSIG)))?;
    let int_handler = vm.getattr_str(&Value::Object(Rc::clone(module)), "default_int_handler")?;

    let state = vm.native_state::<SignalState>();
    {
        let mut dispositions = state.dispositions.borrow_mut();
        let mut handlers = state.handlers.borrow_mut();
        for (number, (disposition, handler)) in dispositions.iter_mut().zip(handlers.iter_mut()).enumerate() {
            // Signals the CRT rejects report `SIG_ERR`.
            let supported = i32::try_from(number).is_ok_and(is_crt_signal);
            *handler = match (supported, *disposition) {
                (true, Disposition::Default) => default_handler.clone(),
                (true, Disposition::Ignore) => ignore_handler.clone(),
                (true, Disposition::Unknown) => unknown_handler(),
                _ => Value::None,
            };
        }

        if let (Some(disposition), Some(handler)) = (dispositions.get_mut(SIGINT_SLOT), handlers.get_mut(SIGINT_SLOT)) {
            if *disposition == Disposition::Default {
                *handler = int_handler;
                *disposition = Disposition::Python;
            }
        }
    }
    *state.ignore_handler.borrow_mut() = ignore_handler;

    for (name, number) in SIGNALS {
        set_attribute(vm, module, name, Value::Int(i64::from(number)))?;
    }
    for (name, value) in CONSOLE_EVENTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    Ok(())
}

/// The signals the Visual C++ `signal` accepts.
fn is_crt_signal(number: i32) -> bool {
    SIGNALS.iter().any(|(_, signal)| *signal == number)
}

/// The `i` signal number argument. Branching on an unknown number halts.
fn signal_number(vm: &Vm, value: &Value, function: &str) -> PyResult<i32> {
    match c_int(vm, value)? {
        Some(number) => Ok(number),
        None => Err(vm.halt_unsupported(format!("signal.{function} with an unknown signal number"))),
    }
}

/// The handler table slot of a signal number; `None` outside `1..NSIG`.
fn slot(number: i32) -> Option<usize> {
    if !(1..NSIG).contains(&number) {
        return None;
    }

    usize::try_from(number).ok()
}

fn signal_signal(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [number, handler] = exact(vm, args, "signal")?;

    let number = signal_number(vm, &number, "signal")?;
    if !is_crt_signal(number) {
        return Err(vm.raise(ExceptionKind::ValueError, "invalid signal value"));
    }

    let state = vm.native_state::<SignalState>();
    let disposition = if handler.is_unknown() {
        Disposition::Unknown
    } else if vm.is_same(&handler, &state.ignore_handler.borrow()) {
        Disposition::Ignore
    } else if vm.is_same(&handler, &Value::Int(0)) {
        Disposition::Default
    } else if is_callable(vm, &handler)? {
        Disposition::Python
    } else {
        return Err(vm.type_error("signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object"));
    };

    let mut dispositions = state.dispositions.borrow_mut();
    let mut handlers = state.handlers.borrow_mut();
    let Some((stored_disposition, stored_handler)) = slot(number).and_then(|index| dispositions.get_mut(index).zip(handlers.get_mut(index))) else {
        return Err(vm.raise(ExceptionKind::ValueError, "signal number out of range"));
    };
    *stored_disposition = disposition;

    // An unknown handler may be rejected as not callable, which leaves the
    // previous one installed; both the result and the slot are unknown.
    if disposition == Disposition::Unknown {
        *stored_handler = unknown_handler();
        return Ok(Value::unknown("signal.signal() with an unknown handler"));
    }

    Ok(std::mem::replace(stored_handler, handler))
}

fn unknown_handler() -> Value {
    Value::unknown("signal handler set from an unknown value")
}

fn signal_getsignal(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [number] = exact(vm, args, "getsignal")?;

    let number = signal_number(vm, &number, "getsignal")?;
    let state = vm.native_state::<SignalState>();
    let handler = slot(number).and_then(|index| state.handlers.borrow().get(index).cloned());
    let Some(handler) = handler else {
        return Err(vm.raise(ExceptionKind::ValueError, "signal number out of range"));
    };

    Ok(handler)
}

/// `signal.set_wakeup_fd`. Descriptors the descriptor check rejects
/// without consulting the CRT fail exactly; whether another descriptor is
/// open is host state, so the call returns an unknown value and the stored
/// descriptor becomes unknown.
fn signal_set_wakeup_fd(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [descriptor] = exact(vm, args, "set_wakeup_fd")?;

    let state = vm.native_state::<SignalState>();
    let Some(descriptor) = c_int(vm, &descriptor)? else {
        let result = vm.host_operation(HostCapability::FileSystem, "signal.set_wakeup_fd() (unknown descriptor)")?;
        state.wakeup_fd.set(None);
        return Ok(result);
    };
    if descriptor != -1 && is_unverifiable_descriptor(i64::from(descriptor)) {
        return Err(vm.raise(ExceptionKind::ValueError, "invalid fd"));
    }

    let previous = state.wakeup_fd.get();
    if descriptor != -1 {
        let result = vm.host_operation(HostCapability::FileSystem, "signal.set_wakeup_fd() (host file descriptor table)")?;
        state.wakeup_fd.set(None);
        return Ok(result);
    }
    state.wakeup_fd.set(Some(descriptor));

    match previous {
        Some(previous) => Ok(Value::Long(Rc::new(BigInt::from(previous)))),
        None => Ok(Value::unknown("signal.set_wakeup_fd() (host file descriptor table)")),
    }
}

/// `signal.default_int_handler`: any positional arguments, then
/// `KeyboardInterrupt` without arguments.
fn signal_default_int_handler(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("default_int_handler() takes no keyword arguments"));
    }

    let class = Rc::clone(vm.types().exception(ExceptionKind::KeyboardInterrupt));
    let exception = vm.instantiate_exception(&class, Vec::new())?;

    Err(Signal::Raise(exception))
}
