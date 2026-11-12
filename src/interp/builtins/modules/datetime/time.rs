//! `time`: a time of day with an optional `tzinfo`. Its zone methods get
//! `None` as their argument.

use super::ClockTime;
use super::Fields;
use super::Outcome;
use super::TIME_TYPE;
use super::compare_error;
use super::comparison_methods;
use super::date::format_spec;
use super::date::strftime_format;
use super::fields::FieldArguments;
use super::fields::check_clock;
use super::fields::pickle_state;
use super::finish;
use super::format;
use super::hash_value;
use super::is_time;
use super::known;
use super::new_time_of;
use super::no_arguments;
use super::no_operands;
use super::operand;
use super::split_receiver;
use super::time_data;
use super::time_type;
use super::zone::OffsetMethod;
use super::zone::OffsetMinutes;
use super::zone::OffsetPair;
use super::zone::ZoneContext;
use super::zone::is_tzinfo;
use super::zone::offset_pair;
use super::zone::offset_value;
use super::zone::tzinfo_argument;
use super::zone::utc_offset;
use super::zone::zone_name;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::hash::PyHash;
use crate::interp::hash::hash_bytes;
use crate::interp::hash::hash_int;
use crate::interp::hash::hash_tuple;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const NAMES: [&str; 5] = ["hour", "minute", "second", "microsecond", "tzinfo"];

/// A method call: the receiver's known fields, the receiver itself, and
/// the remaining arguments.
struct TimeCall {
    clock: ClockTime,
    tzinfo: Option<Value>,
    receiver: Value,
    args: CallArgs,
}

pub(super) fn create_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "time",
            module: "datetime",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", |vm, args| finish(time_new(vm, args))),
                method("__repr__", |vm, args| finish(time_repr(vm, args))),
                method("__str__", |vm, args| finish(time_str(vm, args))),
                method("__hash__", |vm, args| finish(time_hash(vm, args))),
                method("__nonzero__", |vm, args| finish(time_nonzero(vm, args))),
                method("isoformat", |vm, args| finish(time_isoformat(vm, args))),
                method("strftime", |vm, args| finish(time_strftime(vm, args))),
                method("__format__", |vm, args| finish(time_format(vm, args))),
                method("utcoffset", |vm, args| finish(time_offset(vm, args, OffsetMethod::UtcOffset, "utcoffset"))),
                method("tzname", |vm, args| finish(time_tzname(vm, args))),
                method("dst", |vm, args| finish(time_offset(vm, args, OffsetMethod::Dst, "dst"))),
                method("replace", |vm, args| finish(time_replace(vm, args))),
                method("__reduce__", |vm, args| finish(time_reduce(vm, args))),
            ],
        },
    )?;

    install(vm, &class, &comparison_methods!(time_compare))?;
    for name in NAMES {
        add_getset(vm, &class, GetSet { name, owner: TIME_TYPE, get: field, set: None })?;
    }

    Ok(class)
}

/// The receiver of a `time` method, its known fields and `tzinfo`, and the
/// remaining arguments.
fn receiver(vm: &Vm, args: CallArgs, method: &str) -> Outcome<TimeCall> {
    let (receiver, args) = split_receiver(vm, args, TIME_TYPE, method, is_time)?;
    let Some(data) = time_data(&receiver) else {
        return Err(vm.type_error("time receiver lost its payload").into());
    };
    let clock = data.clock.get()?;
    let tzinfo = data.tzinfo.clone();

    Ok(TimeCall { clock, tzinfo, receiver, args })
}

fn field(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = time_data(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    if getset.name == "tzinfo" {
        return Ok(data.tzinfo.clone().unwrap_or(Value::None));
    }
    let clock = match &data.clock {
        Fields::Known(clock) => *clock,
        Fields::Unknown(value) => return Ok(value.clone()),
    };

    let value = match getset.name {
        "hour" => clock.hour,
        "minute" => clock.minute,
        "second" => clock.second,
        _ => clock.microsecond,
    };

    Ok(Value::Int(value))
}

/// `time(hour, minute, second, microsecond, tzinfo)`, or a time restored
/// from its pickle state.
fn time_new(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = new_class(vm, args, &time_type(vm)?)?;

    if let Some((state, tzinfo)) = pickle_state(vm, &args, 2, 6, |bytes| bytes[0] < 24) {
        let tzinfo = state_tzinfo(vm, tzinfo)?;
        let Ok(state) = <[u8; 6]>::try_from(state) else {
            return Err(vm.type_error("time state has the wrong length").into());
        };
        return Ok(new_time_of(vm, &class, Fields::Known(ClockTime::from_state(&state)), tzinfo));
    }

    let arguments = FieldArguments::parse(vm, args, "", &NAMES, 0, 4)?;
    let unknown = arguments.first_unknown();
    let clock = match unknown {
        Some(unknown) => Fields::Unknown(unknown),
        None => {
            let [hour, minute, second, microsecond] = arguments.ints([0; 4])?;
            Fields::Known(check_clock(vm, hour, minute, second, microsecond)?)
        }
    };
    let tzinfo = match arguments.object(4) {
        Some(tzinfo) => tzinfo_argument(vm, &tzinfo)?,
        None => None,
    };

    Ok(new_time_of(vm, &class, clock, tzinfo))
}

/// The `tzinfo` that follows a pickle state: absent, `None`, or a `tzinfo`.
pub(super) fn state_tzinfo(vm: &Vm, tzinfo: Option<&Value>) -> Outcome<Option<Value>> {
    let Some(tzinfo) = tzinfo else {
        return Ok(None);
    };
    let tzinfo = known(tzinfo.clone())?;
    if tzinfo.is_none() {
        return Ok(None);
    }
    if !is_tzinfo(vm, &tzinfo)? {
        return Err(vm.type_error("bad tzinfo state arg").into());
    }

    Ok(Some(tzinfo))
}

fn time_repr(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, receiver, args } = receiver(vm, args, "__repr__")?;
    no_operands(vm, args, "__repr__")?;

    let prefix = format!("{}({}", vm.type_name(&receiver), format::clock_arguments(clock));

    format::close_repr(vm, prefix, tzinfo.as_ref())
}

/// `str(time)`: `self.isoformat()`.
fn time_str(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, TIME_TYPE, "__str__", is_time)?;
    no_operands(vm, args, "__str__")?;

    Ok(vm.call_method(&receiver, "isoformat", Vec::new())?)
}

fn time_isoformat(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, args, .. } = receiver(vm, args, "isoformat")?;
    no_arguments(vm, &args, "isoformat")?;

    let offset = format::iso_offset(vm, tzinfo.as_ref(), &Value::None)?;

    Ok(Value::str(&format!("{}{offset}", format::iso_clock(clock))))
}

/// `time.strftime(format)`, formatting the fields on 1900-01-01.
fn time_strftime(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, args, .. } = receiver(vm, args, "strftime")?;
    let format = strftime_format(vm, args)?;

    let fields = [1900, 1, 1, clock.hour, clock.minute, clock.second, 0, 1, -1];
    let timetuple = Value::tuple(fields.iter().map(|field| vm.new_int_from_i64(*field)).collect());
    let directives = format::Directives { zone: ZoneContext { tzinfo: tzinfo.as_ref(), argument: &Value::None }, microsecond: clock.microsecond };

    format::strftime(vm, format.as_bytes(), &timetuple, directives)
}

fn time_format(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, TIME_TYPE, "__format__", is_time)?;
    let spec = format_spec(vm, args)?;

    format::format_method(vm, &receiver, &spec)
}

fn time_offset(vm: &Vm, args: CallArgs, offset: OffsetMethod, name: &str) -> Outcome<Value> {
    let TimeCall { tzinfo, args, .. } = receiver(vm, args, name)?;
    no_arguments(vm, &args, name)?;

    offset_value(vm, tzinfo.as_ref(), offset, &Value::None)
}

fn time_tzname(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { tzinfo, args, .. } = receiver(vm, args, "tzname")?;
    no_arguments(vm, &args, "tzname")?;

    zone_name(vm, tzinfo.as_ref(), &Value::None)
}

/// A time of the receiver's type with some fields replaced, built without
/// calling the type.
fn time_replace(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, receiver, args } = receiver(vm, args, "replace")?;

    let arguments = FieldArguments::parse(vm, args, "replace", &NAMES, 0, 4)?;
    let [hour, minute, second, microsecond] = arguments.ints([clock.hour, clock.minute, clock.second, clock.microsecond])?;
    let clock = check_clock(vm, hour, minute, second, microsecond)?;
    let tzinfo = match arguments.object(4) {
        Some(tzinfo) => tzinfo_argument(vm, &tzinfo)?,
        None => tzinfo,
    };

    Ok(new_time_of(vm, &vm.type_of(&receiver), Fields::Known(clock), tzinfo))
}

fn time_reduce(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, receiver, args } = receiver(vm, args, "__reduce__")?;
    no_arguments(vm, &args, "__reduce__")?;

    let mut state = vec![Value::Str(PyBytes::new(clock.state().to_vec()))];
    state.extend(tzinfo);

    Ok(Value::tuple(vec![Value::Object(vm.type_of(&receiver)), Value::tuple(state)]))
}

/// Minutes since midnight less the UTC offset, and the rest of the fields.
fn utc_key(clock: ClockTime, offset: OffsetMinutes) -> (i64, i64, i64) {
    (clock.hour * 60 + clock.minute - offset.0, clock.second, clock.microsecond)
}

fn time_compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> PyResult<Value> {
    finish(compare(vm, args, name, operation))
}

fn compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, receiver, args } = receiver(vm, args, name)?;
    let other = known(operand(vm, args, name)?)?;

    let Some(other_data) = time_data(&other) else {
        return match operation {
            CompareOp::Equal => Ok(Value::Bool(false)),
            CompareOp::NotEqual => Ok(Value::Bool(true)),
            _ => Err(compare_error(vm, &receiver, &other).into()),
        };
    };
    let other_clock = other_data.clock.get()?;

    let ordering = match offset_pair(vm, ZoneContext { tzinfo: tzinfo.as_ref(), argument: &Value::None }, ZoneContext { tzinfo: other_data.tzinfo.as_ref(), argument: &Value::None })? {
        OffsetPair::Naive => clock.cmp(&other_clock),
        OffsetPair::Aware { left, right } => utc_key(clock, left).cmp(&utc_key(other_clock, right)),
        OffsetPair::Mixed => return Err(vm.type_error("can't compare offset-naive and offset-aware times").into()),
    };

    Ok(Value::Bool(operation.holds(ordering)))
}

/// Naive times hash as their pickle state. Aware ones hash as the naive
/// time of their UTC clock reading when it falls within the day, else as
/// the tuple of its fields.
fn time_hash(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, receiver, args } = receiver(vm, args, "__hash__")?;
    no_operands(vm, args, "__hash__")?;

    let Some(data) = time_data(&receiver) else {
        return Err(vm.type_error("time receiver lost its payload").into());
    };
    if let Some(hash) = data.hash.get() {
        return Ok(hash_value(vm, hash));
    }

    let hash = compute_hash(vm, clock, tzinfo.as_ref())?;
    data.hash.set(Some(hash));

    Ok(hash_value(vm, hash))
}

fn compute_hash(vm: &Vm, clock: ClockTime, tzinfo: Option<&Value>) -> Outcome<PyHash> {
    let width = vm.config.long_width;
    let Some(OffsetMinutes(offset)) = utc_offset(vm, tzinfo, &Value::None)? else {
        return Ok(hash_bytes(width, &clock.state()));
    };

    let minutes = clock.hour * 60 + clock.minute - offset;
    let hour = minutes.div_euclid(60);
    let minute = minutes.rem_euclid(60);
    if (0..24).contains(&hour) {
        let utc = ClockTime { hour, minute, ..clock };
        return Ok(hash_bytes(width, &utc.state()));
    }

    let fields = [hour, minute, clock.second, clock.microsecond].map(|field| hash_int(width, field));

    Ok(hash_tuple(width, fields, 4))
}

/// A time is false at midnight UTC: zero seconds and microseconds, and
/// hours and minutes equal to the UTC offset.
fn time_nonzero(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let TimeCall { clock, tzinfo, args, .. } = receiver(vm, args, "__nonzero__")?;
    no_operands(vm, args, "__nonzero__")?;

    if clock.second != 0 || clock.microsecond != 0 {
        return Ok(Value::Bool(true));
    }

    let offset = utc_offset(vm, tzinfo.as_ref(), &Value::None)?.map_or(0, |OffsetMinutes(minutes)| minutes);

    Ok(Value::Bool(clock.hour * 60 + clock.minute != offset))
}
