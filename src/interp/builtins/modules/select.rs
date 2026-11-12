//! The `select` module of the Windows build, which has neither `poll`,
//! `epoll`, nor `kqueue`. Arguments are checked as the Windows build checks
//! them; the readiness Winsock reports is unknown.

use num_traits::ToPrimitive;

use crate::interp::attr::MroLookup;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::numeric::float::float_as_double;
use crate::interp::builtins::set_attribute;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `WSAEINVAL` of `winerror.h`: Winsock `select` rejects three empty sets.
const WSAEINVAL: i64 = 10022;

/// `LONG_MAX` of the 32-bit C `long` the timeout's seconds convert to.
const LONG_MAX: f64 = 2_147_483_647.0;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("select", select_select)])?;
    set_attribute(vm, module, "error", Value::Object(select_error(vm)?))?;

    Ok(())
}

/// `select.error`, an `Exception` subclass.
fn select_error(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "select.error", |vm| new_exception_class(vm, "select", "error", vm.types().exception(ExceptionKind::Exception)))
}

/// `select(rlist, wlist, xlist[, timeout])`.
fn select_select(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = unpack(vm, args, "select", 3, 4)?;

    if let Some(timeout) = arguments.get(3) {
        check_timeout(vm, timeout)?;
    }

    let mut all_empty = true;
    for sequence in &arguments[..3] {
        match descriptor_count(vm, sequence)? {
            Some(0) => {}
            _ => all_empty = false,
        }
    }

    if all_empty {
        // The message is the system's text for the error, which depends on
        // the host's language.
        let exception = vm.instantiate_exception(&select_error(vm)?, vec![Value::Int(WSAEINVAL), Value::unknown("select.error message (host operating system)")])?;
        return Err(Signal::Raise(exception));
    }

    vm.host_operation(HostCapability::Network, "select.select() (host operating system)")
}

/// The timeout conversion: a number of seconds whose integer part fits a
/// C `long`, or `None`.
fn check_timeout(vm: &Vm, timeout: &Value) -> PyResult<()> {
    if timeout.is_none() || timeout.is_unknown() {
        return Ok(());
    }
    if !is_number(vm, timeout)? {
        return Err(vm.type_error("timeout must be a float or None"));
    }

    let seconds = float_as_double(vm, timeout)?;
    if seconds > LONG_MAX {
        return Err(vm.raise(ExceptionKind::OverflowError, "timeout period too long"));
    }

    Ok(())
}

/// Whether a value is a number: the type converts with `__int__` or
/// `__float__`, which a class does when its MRO defines either. Classic
/// instances support every number operation.
fn is_number(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.is_number(value) {
        return Ok(true);
    }
    let Value::Object(object) = value else {
        return Ok(false);
    };
    let class = object.class();
    if vm.is_classic_class(&class) {
        return Ok(true);
    }

    for name in ["__int__", "__float__"] {
        match vm.lookup_mro(&class, name)? {
            MroLookup::Found { .. } => return Ok(true),
            MroLookup::Unknown(unknown) => return Err(Signal::Halt(Halt::UnknownCondition { context: "select() timeout number check".to_owned(), origin: unknown.origin.clone() })),
            MroLookup::Missing => {}
        }
    }

    Ok(false)
}

/// Converts each item to a file descriptor; an item past `FD_SETSIZE` (512
/// on Windows) is rejected after its conversion. The item count, or `None`
/// when the sequence is unknown.
fn descriptor_count(vm: &Vm, sequence: &Value) -> PyResult<Option<usize>> {
    const FD_SETSIZE: usize = 512;

    if sequence.is_unknown() {
        return Ok(None);
    }

    let items = fast_sequence(vm, sequence)?;
    for (index, item) in items.iter().enumerate() {
        file_descriptor(vm, item)?;
        if index >= FD_SETSIZE {
            return Err(vm.raise(ExceptionKind::ValueError, "too many file descriptors in select()"));
        }
    }

    Ok(Some(items.len()))
}

/// A list or tuple of the sequence, with the error "arguments 1-3 must be
/// sequences".
fn fast_sequence(vm: &Vm, sequence: &Value) -> PyResult<Vec<Value>> {
    let is_exact = match sequence {
        Value::Tuple(_) => true,
        Value::Object(object) => matches!(object.payload, Payload::List(_) | Payload::Tuple(_)) && vm.is_builtin_type(&object.class()),
        _ => false,
    };
    if is_exact {
        return vm.collect(sequence);
    }

    let iterator = match vm.iter(sequence) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(exception)) if vm.is_exception(&exception, ExceptionKind::TypeError) => {
            return Err(vm.type_error("arguments 1-3 must be sequences"));
        }
        Err(signal) => return Err(signal),
    };

    let mut items = Vec::new();
    while let Some(item) = vm.next(&iterator)? {
        items.push(item);
    }

    Ok(items)
}

/// A descriptor from an integer or `fileno()`. An out-of-range number
/// becomes -1 with its `OverflowError` replaced by the negative descriptor
/// error.
fn file_descriptor(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() {
        return Ok(());
    }

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let fileno = match vm.getattr_str(value, "fileno") {
                Ok(fileno) => fileno,
                Err(Signal::Raise(_)) => return Err(vm.type_error("argument must be an int, or have a fileno() method.")),
                Err(halt) => return Err(halt),
            };
            let result = vm.call0(&fileno)?;
            if result.is_unknown() {
                return Ok(());
            }
            let Some(integral) = vm.as_integral(&result) else {
                return Err(vm.type_error("fileno() returned a non-integer"));
            };
            integral
        }
    };

    let descriptor = match integral {
        Integral::Int(number) => i32::try_from(number).unwrap_or(-1),
        Integral::Long(number) => number.to_i32().unwrap_or(-1),
    };
    if descriptor < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("file descriptor cannot be a negative integer ({descriptor})")));
    }

    Ok(())
}
