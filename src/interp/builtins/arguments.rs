//! Argument handling shared by the methods of builtin types, with the
//! messages the reference interpreter's method wrappers and argument
//! converters report.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Splits off the receiver of method `method` of builtin type `owner`.
/// Dispatching on an unknown receiver halts.
pub fn bind(vm: &Vm, mut args: CallArgs, method: &str, owner: &str) -> PyResult<(Value, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{owner}' object needs an argument")));
    }

    let receiver = args.positional.remove(0);
    if let Value::Unknown(unknown) = &receiver {
        return Err(Signal::Halt(Halt::UnknownCondition { context: format!("{owner}.{method} receiver"), origin: unknown.origin.clone() }));
    }

    Ok((receiver, args))
}

pub fn wrong_receiver(vm: &Vm, method: &str, owner: &str, got: &Value) -> Signal {
    vm.type_error(&format!("descriptor '{method}' requires a '{owner}' object but received a '{}'", vm.type_name(got)))
}

fn reject_keywords(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<()> {
    if !args.has_keywords() {
        return Ok(());
    }

    Err(vm.type_error(&format!("{method}() takes no keyword arguments")))
}

/// A method that takes no arguments.
pub fn no_arguments(vm: &Vm, args: CallArgs, method: &str) -> PyResult<()> {
    reject_keywords(vm, &args, method)?;

    let count = args.positional.len();
    if count != 0 {
        return Err(vm.type_error(&format!("{method}() takes no arguments ({count} given)")));
    }

    Ok(())
}

/// A method that takes exactly one positional argument.
pub fn one_argument(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    reject_keywords(vm, &args, method)?;

    let count = args.positional.len();
    let Ok([argument]) = <[Value; 1]>::try_from(args.positional) else {
        return Err(vm.type_error(&format!("{method}() takes exactly one argument ({count} given)")));
    };

    Ok(argument)
}

/// Unpacks a positional argument tuple whose length lies within a range.
pub fn unpack(vm: &Vm, args: CallArgs, name: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    reject_keywords(vm, &args, name)?;

    let count = args.positional.len();
    let qualifier = |bound: &str| if minimum == maximum { String::new() } else { format!("{bound} ") };
    if count < minimum {
        return Err(vm.type_error(&format!("{name} expected {}{minimum} arguments, got {count}", qualifier("at least"))));
    }
    if count > maximum {
        return Err(vm.type_error(&format!("{name} expected {}{maximum} arguments, got {count}", qualifier("at most"))));
    }

    Ok(args.positional)
}

/// Arguments of a slot wrapper such as `list.__len__`.
pub fn wrapper_arguments(vm: &Vm, args: CallArgs, count: usize) -> PyResult<Vec<Value>> {
    let given = args.positional.len();
    if given != count {
        return Err(vm.type_error(&format!("expected {count} arguments, got {given}")));
    }

    Ok(args.positional)
}

/// The single argument of a binary slot wrapper.
pub fn wrapper_operand(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let given = args.positional.len();
    let Ok([operand]) = <[Value; 1]>::try_from(args.positional) else {
        return Err(vm.type_error(&format!("expected 1 arguments, got {given}")));
    };

    Ok(operand)
}

/// The two arguments of a slot wrapper such as `__setitem__`.
pub fn wrapper_pair(vm: &Vm, args: CallArgs) -> PyResult<(Value, Value)> {
    let given = args.positional.len();
    let Ok([first, second]) = <[Value; 2]>::try_from(args.positional) else {
        return Err(vm.type_error(&format!("expected 2 arguments, got {given}")));
    };

    Ok((first, second))
}

/// The type check of the `__cmp__` slot wrapper: the operand must share
/// the receiver's builtin comparison or be an instance of the receiver's
/// type.
pub fn cmp_operand_check(vm: &Vm, receiver: &Value, other: &Value, same_comparison: bool) -> PyResult<()> {
    let class = vm.type_of(receiver);
    if same_comparison && vm.user_override(other, "__cmp__")?.is_none() {
        return Ok(());
    }
    if vm.is_instance_of(other, &class)? {
        return Ok(());
    }

    let name = vm.class_name(&class);

    Err(vm.type_error(&format!("{name}.__cmp__(x,y) requires y to be a '{name}', not a '{}'", vm.type_name(other))))
}

/// Stores an attribute in a class's namespace.
pub fn set_class_attribute(vm: &Vm, class: &ObjectRef, name: &str, value: Value) -> PyResult<()> {
    let Some(data) = class.as_class() else {
        return Err(vm.type_error(&format!("cannot set '{name}' on a non-class")));
    };

    vm.dict_set_str(&data.dict, name, value)
}

/// A MemoryError without arguments.
pub fn memory_error(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::MemoryError));

    match vm.instantiate_exception(&class, Vec::new()) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

pub fn halt_on_unknown(value: &Value, context: &str) -> PyResult<()> {
    let Value::Unknown(unknown) = value else {
        return Ok(());
    };

    Err(Signal::Halt(Halt::UnknownCondition { context: context.to_owned(), origin: unknown.origin.clone() }))
}

/// The `n` argument format (a signed size). `__index__` plays no part.
/// Where the size type is wider than a C `long` (Windows x64), other
/// objects convert through `__long__`, else `__int__`; with a 64-bit C
/// `long` only `__int__` counts, and a `long` subclass also goes through it.
pub fn ssize_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    halt_on_unknown(value, "integer argument")?;
    let wide = vm.config.long_width == LongWidth::Bits32;

    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let long_subclass = matches!(value, Value::Object(object) if matches!(object.payload, Payload::Long(_)));
    let integral = match vm.as_integral(value) {
        Some(integral) if wide || !long_subclass => integral,
        _ => ssize_conversion(vm, value, wide)?,
    };

    integral.to_i64().ok_or_else(|| {
        let message = if wide { "long int too large to convert to int" } else { "Python int too large to convert to C long" };
        vm.raise(ExceptionKind::OverflowError, message)
    })
}

/// The integer an `n` argument converts to through its conversion methods.
fn ssize_conversion(vm: &Vm, value: &Value, wide: bool) -> PyResult<Integral> {
    let result = if is_classic_instance(vm, value) {
        if wide { classic_instance_long(vm, value)? } else { classic_instance_int(vm, value)? }
    } else {
        let method = match vm.user_override(value, if wide { "__long__" } else { "__int__" })? {
            Some(method) => Some(method),
            None if wide => vm.user_override(value, "__int__")?,
            None => None,
        };
        let Some(method) = method else {
            if vm.as_complex(value).is_some() {
                let target = if wide { "long" } else { "int" };
                return Err(vm.type_error(&format!("can't convert complex to {target}")));
            }
            if let Some(integral) = vm.as_integral(value) {
                return Ok(integral);
            }
            return Err(vm.type_error("an integer is required"));
        };
        vm.call0(&method)?
    };
    halt_on_unknown(&result, "__int__ result")?;

    vm.as_integral(&result).ok_or_else(|| vm.type_error("__int__ method should return an integer"))
}

/// Conversion to a signed size, raising OverflowError when out of range.
pub fn index_value(vm: &Vm, value: &Value) -> PyResult<i64> {
    vm.index_as_ssize(value, Some(ExceptionKind::OverflowError))
}

/// A start or stop bound of `index()`, with out-of-range longs clamped.
pub fn slice_index(vm: &Vm, value: &Value) -> PyResult<i64> {
    halt_on_unknown(value, "slice index")?;
    if !vm.is_index(value)? {
        return Err(vm.type_error("slice indices must be integers or None or have an __index__ method"));
    }

    vm.index_as_ssize(value, None)
}

/// Whether `value` is an instance of a classic class.
pub fn is_classic_instance(vm: &Vm, value: &Value) -> bool {
    match value {
        Value::Object(object) => matches!(object.payload, Payload::Instance) && vm.is_classic_class(&object.class()),
        _ => false,
    }
}

/// Integer conversion of a classic instance: `__int__`, else `__trunc__`
/// with its result converted to an int.
pub fn classic_instance_int(vm: &Vm, value: &Value) -> PyResult<Value> {
    if classic_has_attribute(vm, value, "__int__")? {
        return vm.call0(&vm.getattr_str(value, "__int__")?);
    }

    let truncated = vm.call0(&vm.getattr_str(value, "__trunc__")?)?;

    integral_to_int(vm, truncated, "__trunc__")
}

/// Long conversion of a classic instance: `__long__`, else the integer
/// conversion.
pub fn classic_instance_long(vm: &Vm, value: &Value) -> PyResult<Value> {
    if classic_has_attribute(vm, value, "__long__")? {
        return vm.call0(&vm.getattr_str(value, "__long__")?);
    }

    classic_instance_int(vm, value)
}

/// `hasattr` semantics that swallow any exception of the lookup.
fn classic_has_attribute(vm: &Vm, value: &Value, name: &str) -> PyResult<bool> {
    match vm.getattr_opt(value, &PyBytes::from(name)) {
        Ok(found) => Ok(found.is_some()),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt),
    }
}

/// An int or long, or the result of the value's `__int__`.
fn integral_to_int(vm: &Vm, integral: Value, method: &str) -> PyResult<Value> {
    halt_on_unknown(&integral, "__trunc__ result")?;
    if vm.as_integral(&integral).is_some() {
        return Ok(integral);
    }

    let converted = match vm.getattr_opt(&integral, &PyBytes::from("__int__")) {
        Ok(Some(function)) => Some(vm.call0(&function)?),
        Ok(None) | Err(Signal::Raise(_)) => None,
        Err(halt) => return Err(halt),
    };
    let offender = match converted {
        Some(result) if vm.as_integral(&result).is_some() => return Ok(result),
        Some(result) => result,
        None => integral,
    };
    halt_on_unknown(&offender, "__int__ result")?;

    // A classic instance is named by its class.
    let type_name = match &offender {
        Value::Object(object) if is_classic_instance(vm, &offender) => vm.class_name(&object.class()),
        _ => vm.type_name(&offender),
    };

    Err(vm.type_error(&format!("{method} returned non-Integral (type {type_name})")))
}

/// The `l` argument format (a C `long`, through `__int__`).
pub fn long_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    halt_on_unknown(value, "integer argument")?;

    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let result = if is_classic_instance(vm, value) {
                classic_instance_int(vm, value)?
            } else {
                let Some(method) = vm.user_override(value, "__int__")? else {
                    if vm.as_complex(value).is_some() {
                        return Err(vm.type_error("can't convert complex to int"));
                    }
                    return Err(vm.type_error("an integer is required"));
                };
                vm.call0(&method)?
            };
            halt_on_unknown(&result, "__int__ result")?;
            vm.as_integral(&result).ok_or_else(|| vm.type_error("nb_int should return int object"))?
        }
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };

    match number {
        Some(number) if crate::interp::numbers::fits_int(vm.config.long_width, number) => Ok(number),
        _ => Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
    }
}

/// The `i` argument format (a C `int`, through `__int__`).
pub fn int_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    let number = long_argument(vm, value)?;
    if number > i64::from(i32::MAX) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum"));
    }
    if number < i64::from(i32::MIN) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum"));
    }

    Ok(number)
}

/// Splits off and checks the class argument of `base.__new__(cls, ...)`.
pub fn new_class(vm: &Vm, mut args: CallArgs, base: &ObjectRef) -> PyResult<(ObjectRef, CallArgs)> {
    let name = vm.class_name(base);
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("{name}.__new__(): not enough arguments")));
    }

    let first = args.positional.remove(0);
    let class = match &first {
        Value::Object(class) if class.as_class().is_some() => Rc::clone(class),
        _ => return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(&first)))),
    };
    if !vm.is_subclass(&class, base)? {
        let class_name = vm.class_name(&class);
        return Err(vm.type_error(&format!("{name}.__new__({class_name}): {class_name} is not a subtype of {name}")));
    }

    Ok((class, args))
}

/// An instance of a subclass of a builtin type with the given storage.
pub fn new_instance(vm: &Vm, class: &ObjectRef, payload: Payload) -> Value {
    let instance_dict = class.as_class().is_some_and(|data| data.instance_dict);
    let dict = if instance_dict { Some(vm.new_dict()) } else { None };

    Value::Object(vm.alloc(class, payload, dict))
}

pub fn stop_iteration(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::StopIteration));

    match vm.instantiate_exception(&class, Vec::new()) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}
