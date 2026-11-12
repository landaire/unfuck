//! `tzinfo`: the abstract base of time zones written in Python, with the
//! default `fromutc` conversion.

use super::Outcome;
use super::TZINFO_TYPE;
use super::US_PER_SECOND;
use super::datetime_data;
use super::finish;
use super::known;
use super::new_datetime;
use super::no_arguments;
use super::tzinfo_type;
use super::zone::OffsetMethod;
use super::zone::OffsetMinutes;
use super::zone::is_tzinfo;
use super::zone::offset_minutes;
use super::zone::same_tzinfo;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub(super) fn create_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_type(
        vm,
        TypeSpec {
            name: "tzinfo",
            module: "datetime",
            base: None,
            layout: Layout::Object,
            instance_dict: false,
            methods: &[
                static_method("__new__", tzinfo_new),
                method("tzname", |vm, args| finish(not_implemented(vm, args, "tzname"))),
                method("utcoffset", |vm, args| finish(not_implemented(vm, args, "utcoffset"))),
                method("dst", |vm, args| finish(not_implemented(vm, args, "dst"))),
                method("fromutc", |vm, args| finish(tzinfo_fromutc(vm, args))),
                method("__reduce__", |vm, args| finish(tzinfo_reduce(vm, args))),
            ],
        },
    )
}

/// The receiver of a `tzinfo` method and the remaining arguments.
fn receiver(vm: &Vm, mut args: CallArgs, method: &str) -> Outcome<(Value, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{TZINFO_TYPE}' object needs an argument")).into());
    }

    let receiver = known(args.positional.remove(0))?;
    if !is_tzinfo(vm, &receiver)? {
        return Err(mismatch(vm, method, &receiver).into());
    }

    Ok((receiver, args))
}

fn mismatch(vm: &Vm, method: &str, value: &Value) -> Signal {
    vm.type_error(&format!("descriptor '{method}' requires a '{TZINFO_TYPE}' object but received a '{}'", vm.type_name(value)))
}

/// `tzinfo.__new__(cls, ...)`: an instance of `cls`, whatever the other
/// arguments.
fn tzinfo_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, _) = new_class(vm, args, &tzinfo_type(vm)?)?;

    Ok(new_instance(vm, &class, Payload::Instance))
}

/// The abstract `tzname`, `utcoffset`, and `dst`.
fn not_implemented(vm: &Vm, args: CallArgs, name: &str) -> Outcome<Value> {
    let (receiver, args) = receiver(vm, args, name)?;
    let mut with_receiver = args;
    with_receiver.positional.insert(0, receiver);
    method_one_argument(vm, &with_receiver, name)?;

    Err(vm.raise(ExceptionKind::NotImplementedError, &format!("a tzinfo subclass must implement {name}()")).into())
}

/// The default `fromutc`: from UTC to standard local time through
/// `utcoffset() - dst()`, then to local time through `dst()` at that time.
fn tzinfo_fromutc(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = receiver(vm, args, "fromutc")?;
    let mut with_receiver = args;
    with_receiver.positional.insert(0, receiver.clone());
    let datetime = known(method_one_argument(vm, &with_receiver, "fromutc")?)?;

    let Some(data) = datetime_data(&datetime) else {
        return Err(vm.type_error("fromutc: argument must be a datetime").into());
    };
    if !same_tzinfo(data.tzinfo.as_ref(), Some(&receiver)) {
        return Err(vm.raise(ExceptionKind::ValueError, "fromutc: dt.tzinfo is not self").into());
    }

    let Some(OffsetMinutes(offset)) = offset_minutes(vm, &receiver, OffsetMethod::UtcOffset, &datetime)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "fromutc: non-None utcoffset() result required").into());
    };
    let Some(OffsetMinutes(mut dst)) = offset_minutes(vm, &receiver, OffsetMethod::Dst, &datetime)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "fromutc: non-None dst() result required").into());
    };

    let mut moment = data.moment.get()?;
    let standard = offset - dst;
    if standard != 0 {
        moment = shift(vm, moment, standard)?;
        let shifted = new_datetime(vm, moment, Some(receiver.clone()))?;
        let Some(OffsetMinutes(local_dst)) = offset_minutes(vm, &receiver, OffsetMethod::Dst, &shifted)? else {
            return Err(vm.raise(ExceptionKind::ValueError, "fromutc: tz.dst() gaveinconsistent results; cannot convert").into());
        };
        dst = local_dst;
    }

    let local = shift(vm, moment, dst)?;

    Ok(new_datetime(vm, local, Some(receiver))?)
}

/// The moment `minutes` after `moment`; out of range is an error.
fn shift(vm: &Vm, moment: super::Moment, minutes: i64) -> PyResult<super::Moment> {
    super::Moment::from_microseconds(moment.microseconds() + i128::from(minutes) * 60 * i128::from(US_PER_SECOND)).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "date value out of range"))
}

/// `(type(self), self.__getinitargs__() or (), state)` where the state is
/// `self.__getstate__()`, else a nonempty `__dict__`; without a state the
/// tuple has two items.
fn tzinfo_reduce(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = receiver(vm, args, "__reduce__")?;
    no_arguments(vm, &args, "__reduce__")?;

    let initargs = match optional_attribute(vm, &receiver, "__getinitargs__")? {
        Some(method) => known(vm.call0(&method)?)?,
        None => Value::tuple(Vec::new()),
    };
    let state = match optional_attribute(vm, &receiver, "__getstate__")? {
        Some(method) => known(vm.call0(&method)?)?,
        None => match optional_attribute(vm, &receiver, "__dict__")? {
            Some(dict) if dict_has_items(vm, &dict)? => dict,
            _ => Value::None,
        },
    };

    let mut reduced = vec![Value::Object(vm.type_of(&receiver)), initargs];
    if !state.is_none() {
        reduced.push(state);
    }

    Ok(Value::tuple(reduced))
}

/// Attribute `name` of `value`; `None` when the lookup raises
/// `AttributeError`.
fn optional_attribute(vm: &Vm, value: &Value, name: &str) -> Outcome<Option<Value>> {
    match vm.getattr_opt(value, &PyBytes::from(name)) {
        Ok(found) => Ok(found),
        Err(Signal::Raise(error)) => {
            let attribute_error = vm.types().exception(ExceptionKind::AttributeError);
            if vm.is_instance_of(&error, attribute_error)? {
                return Ok(None);
            }
            Err(Signal::Raise(error).into())
        }
        Err(halt) => Err(halt.into()),
    }
}

/// Whether `value` is a dict with at least one item.
fn dict_has_items(vm: &Vm, value: &Value) -> PyResult<bool> {
    let Value::Object(object) = value else {
        return Ok(false);
    };
    if object.as_dict().is_none() {
        return Ok(false);
    }

    Ok(vm.dict_len(object)? > 0)
}
