//! Argument format units and C API conversions the Windows host modules
//! (`signal`, `_winreg`, `msvcrt`, `_subprocess`) share. Conversions of
//! unknown arguments succeed with `None`.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;

use crate::interp::builtins::modules::math::classic_int;
use crate::interp::builtins::modules::time::argument_prefix;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::positional;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `EBADF` of the CRT `errno.h`.
pub(super) const EBADF: i64 = 9;

/// `_NHANDLE_` of the CRT (`IOINFO_ARRAYS * IOINFO_ARRAY_ELTS`).
const CRT_HANDLE_LIMIT: i64 = 2048;

/// Whether the descriptor check rejects `descriptor` without consulting
/// the CRT tables: negative descriptors and those past `_NHANDLE_`.
pub(super) fn is_unverifiable_descriptor(descriptor: i64) -> bool {
    !(0..CRT_HANDLE_LIMIT).contains(&descriptor)
}

/// The IOError for `EBADF`.
pub(super) fn bad_descriptor(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::IOError));

    match vm.instantiate_exception(&class, vec![Value::Int(EBADF), Value::str("Bad file descriptor")]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// The arguments of a varargs function whose format takes exactly `N`
/// arguments.
pub(super) fn exact<const N: usize>(vm: &Vm, args: CallArgs, function: &str) -> PyResult<[Value; N]> {
    let given = positional(vm, args, function, N, N)?;
    let count = given.len();

    given.try_into().map_err(|_| vm.type_error(&format!("{function}() takes exactly {N} arguments ({count} given)")))
}

/// The `l` unit: a C `long`.
pub(super) fn c_long(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let Some(integral) = vm.as_integral(value) else {
        return Err(vm.type_error("an integer is required"));
    };
    let (low, high) = numbers::int_bounds(vm.config.long_width);
    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    let Some(number) = number.filter(|number| (low..=high).contains(number)) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
    };

    Ok(Some(number))
}

/// The truncated value of a float.
pub(super) fn float_int(vm: &Vm, number: f64) -> PyResult<Integral> {
    if number.is_nan() {
        return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
    }
    let Some(truncated) = BigInt::from_f64(number.trunc()) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
    };

    Ok(Integral::Long(truncated))
}

/// The `L` unit, a C `long long`. A float is truncated after a
/// `DeprecationWarning`; other objects convert through `__int__`.
pub(super) fn long_long(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let integral = match (vm.as_integral(value), vm.as_float(value)) {
        (Some(integral), _) => integral,
        (None, Some(number)) => {
            deprecation_warning(vm, "integer argument expected, got float")?;
            float_int(vm, number)?
        }
        (None, None) => {
            let Some(converted) = number_int(vm, value)? else {
                return Ok(None);
            };
            let Some(integral) = vm.as_integral(&converted) else {
                return Err(vm.type_error("integer conversion failed"));
            };
            integral
        }
    };
    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    let Some(number) = number else {
        return Err(vm.raise(ExceptionKind::OverflowError, "long too big to convert"));
    };

    Ok(Some(number))
}

/// The integer conversion of a value that is not an int, long, or float:
/// a classic instance's or a type's `__int__` method. `None` when the
/// result is unknown.
pub(super) fn number_int(vm: &Vm, value: &Value) -> PyResult<Option<Value>> {
    let result = match value {
        Value::Object(object) if vm.is_classic_class(&object.class()) => classic_int(vm, value)?,
        _ => {
            let Some(method) = vm.user_override(value, "__int__")? else {
                return Err(vm.type_error("an integer is required"));
            };
            vm.call0(&method)?
        }
    };
    if result.is_unknown() {
        return Ok(None);
    }

    Ok(Some(result))
}

/// Issues a `DeprecationWarning` with `message`.
fn deprecation_warning(vm: &Vm, message: &str) -> PyResult<()> {
    let module = vm.import_module("_warnings")?;
    let warn = vm.getattr_str(&module, "warn")?;
    let category = Value::Object(Rc::clone(vm.types().exception(ExceptionKind::DeprecationWarning)));
    vm.call(&warn, CallArgs::new(vec![Value::str(message), category, Value::Int(1)]))?;

    Ok(())
}

/// The `s` unit.
pub(super) fn string(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<()> {
    c_string(vm, value, Some(function), position)?;

    Ok(())
}

/// The `z` unit: a string or `None`.
pub(super) fn optional_string(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() || value.is_none() {
        return Ok(());
    }

    let prefix = argument_prefix(Some(function));
    let Some(bytes) = vm.as_str_bytes(value) else {
        if vm.as_text(value).is_some() {
            c_string(vm, value, Some(function), position)?;
            return Ok(());
        }
        return Err(vm.type_error(&format!("{prefix}argument {position} must be string or None, not {}", converted_type_name(vm, value))));
    };
    if bytes.as_bytes().contains(&0) {
        return Err(vm.type_error(&format!("{prefix}argument {position} must be string without null bytes or None, not {}", vm.type_name(value))));
    }

    Ok(())
}

/// The `c` unit: a `str` of length one.
pub(super) fn character(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() {
        return Ok(());
    }

    match vm.as_str_bytes(value) {
        Some(bytes) if bytes.as_bytes().len() == 1 => Ok(()),
        _ => Err(vm.type_error(&format!("{function}() argument {position} must be char, not {}", converted_type_name(vm, value)))),
    }
}

/// The `u` unit and, with `expected` "cannot convert raw buffers", the
/// `u#` unit; both accept only unicode. The result is the length in code
/// units, `None` when unknown.
pub(super) fn unicode(vm: &Vm, value: &Value, function: &str, position: usize, expected: &str) -> PyResult<Option<usize>> {
    if value.is_unknown() {
        return Ok(None);
    }

    match vm.as_text(value) {
        Some(text) => Ok(Some(text.units().len())),
        None => Err(vm.type_error(&format!("{function}() argument {position} must be {expected}, not {}", converted_type_name(vm, value)))),
    }
}

/// Pointer conversion for the 64-bit pointers of the Windows build: ints
/// and negative longs as signed 64-bit, other longs as unsigned 64-bit.
/// `value` must be an int or long.
pub(super) fn void_pointer(vm: &Vm, value: &Value) -> PyResult<Option<u64>> {
    let Some(integral) = vm.as_integral(value) else {
        return Ok(None);
    };

    let pointer = match integral {
        Integral::Int(number) => Some(number as u64),
        Integral::Long(number) if number < BigInt::from(0) => number.to_i64().map(|number| number as u64),
        Integral::Long(number) => number.to_u64(),
    };
    let Some(pointer) = pointer else {
        return Err(vm.raise(ExceptionKind::OverflowError, "long too big to convert"));
    };

    Ok(Some(pointer))
}

/// A 64-bit pointer as a Python integer: null is the int 0, any other
/// pointer an unsigned long.
pub(super) fn from_void_pointer(pointer: u64) -> Value {
    if pointer == 0 {
        return Value::Int(0);
    }

    Value::Long(Rc::new(BigInt::from(pointer)))
}
