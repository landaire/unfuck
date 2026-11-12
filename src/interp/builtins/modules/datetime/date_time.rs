//! `datetime`: a `date` subclass with a time of day and an optional
//! `tzinfo`. Its zone methods get the datetime itself as their argument.

use std::cell::RefCell;

use super::BinarySlot;
use super::ClockTime;
use super::DATETIME_TYPE;
use super::Fields;
use super::Moment;
use super::Outcome;
use super::Side;
use super::Stop;
use super::US_PER_DAY;
use super::US_PER_SECOND;
use super::binary;
use super::calendar::CivilDate;
use super::compare_error;
use super::comparison_methods;
use super::date::LAST_LOCAL_SECOND;
use super::date::current_time;
use super::date_fields;
use super::datetime_data;
use super::datetime_type;
use super::delta::delta_from_microseconds;
use super::delta_data;
use super::fields::FieldArguments;
use super::fields::check_clock;
use super::fields::check_date;
use super::fields::pickle_state;
use super::finish;
use super::format;
use super::has_attribute;
use super::hash_value;
use super::is_date;
use super::is_datetime;
use super::known;
use super::new_date;
use super::new_datetime;
use super::new_datetime_of;
use super::new_delta;
use super::new_time;
use super::no_arguments;
use super::no_operands;
use super::operand;
use super::split_class;
use super::split_receiver;
use super::time::state_tzinfo;
use super::time_data;
use super::zone::OffsetMethod;
use super::zone::OffsetMinutes;
use super::zone::OffsetPair;
use super::zone::ZoneContext;
use super::zone::is_tzinfo;
use super::zone::offset_minutes;
use super::zone::offset_pair;
use super::zone::offset_value;
use super::zone::tzinfo_argument;
use super::zone::utc_offset;
use super::zone::zone_name;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::class_method;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::operator::is_sequence;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::modules::time::double_to_time_t;
use crate::interp::builtins::modules::time::strptime_importable;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::PyHash;
use crate::interp::hash::hash_bytes;
use crate::interp::hash::hash_int;
use crate::interp::hash::hash_tuple;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const NAMES: [&str; 8] = ["year", "month", "day", "hour", "minute", "second", "microsecond", "tzinfo"];

/// The `_strptime` module the first `strptime` call imported, kept for the
/// life of the interpreter.
#[derive(Default)]
struct StrptimeModule {
    module: RefCell<Option<Value>>,
}

/// A method call: the receiver's known fields, the receiver itself, and
/// the remaining arguments.
struct DateTimeCall {
    moment: Moment,
    tzinfo: Option<Value>,
    receiver: Value,
    args: CallArgs,
}

/// How a timestamp becomes calendar fields.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Conversion {
    /// Through the host time zone, which leaves the fields unknown.
    Local,
    Utc,
}

/// A timestamp as whole seconds since the epoch and the microseconds after
/// them.
struct TimestampParts {
    seconds: i64,
    microsecond: i64,
}

/// A converted `timestamp` argument, or the `tz` one.
enum TimestampSlot {
    Timestamp(Option<f64>),
    Zone(Value),
}

/// An argument of `combine`.
enum CombineSlot {
    Date(Fields<CivilDate>),
    Time(Fields<ClockTime>, Option<Value>),
    Unknown(Value),
}

pub(super) fn create_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "datetime",
            module: "datetime",
            base: Some(super::date_type(vm)?),
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", |vm, args| finish(datetime_new(vm, args))),
                method("__repr__", |vm, args| finish(datetime_repr(vm, args))),
                method("__str__", |vm, args| finish(datetime_str(vm, args))),
                method("__hash__", |vm, args| finish(datetime_hash(vm, args))),
                method("__add__", |vm, args| binary(vm, args, slot("__add__", Side::Left), add)),
                method("__radd__", |vm, args| binary(vm, args, slot("__radd__", Side::Right), add)),
                method("__sub__", |vm, args| binary(vm, args, slot("__sub__", Side::Left), subtract)),
                method("__rsub__", |vm, args| binary(vm, args, slot("__rsub__", Side::Right), subtract)),
                class_method("now", |vm, args| finish(datetime_now(vm, args))),
                class_method("utcnow", |vm, args| finish(datetime_utcnow(vm, args))),
                class_method("fromtimestamp", |vm, args| finish(datetime_fromtimestamp(vm, args))),
                class_method("utcfromtimestamp", |vm, args| finish(datetime_utcfromtimestamp(vm, args))),
                class_method("strptime", |vm, args| finish(datetime_strptime(vm, args))),
                class_method("combine", |vm, args| finish(datetime_combine(vm, args))),
                method("date", |vm, args| finish(datetime_date(vm, args))),
                method("time", |vm, args| finish(datetime_time(vm, args))),
                method("timetz", |vm, args| finish(datetime_timetz(vm, args))),
                method("ctime", |vm, args| finish(datetime_ctime(vm, args))),
                method("timetuple", |vm, args| finish(datetime_timetuple(vm, args))),
                method("utctimetuple", |vm, args| finish(datetime_utctimetuple(vm, args))),
                method("isoformat", |vm, args| finish(datetime_isoformat(vm, args))),
                method("utcoffset", |vm, args| finish(datetime_offset(vm, args, OffsetMethod::UtcOffset, "utcoffset"))),
                method("tzname", |vm, args| finish(datetime_tzname(vm, args))),
                method("dst", |vm, args| finish(datetime_offset(vm, args, OffsetMethod::Dst, "dst"))),
                method("replace", |vm, args| finish(datetime_replace(vm, args))),
                method("astimezone", |vm, args| finish(datetime_astimezone(vm, args))),
                method("__reduce__", |vm, args| finish(datetime_reduce(vm, args))),
            ],
        },
    )?;

    install(vm, &class, &comparison_methods!(datetime_compare))?;
    for name in ["hour", "minute", "second", "microsecond", "tzinfo"] {
        add_getset(vm, &class, GetSet { name, owner: DATETIME_TYPE, get: field, set: None })?;
    }

    Ok(class)
}

/// A binary slot wrapper of this type.
const fn slot(name: &'static str, side: Side) -> BinarySlot {
    BinarySlot { owner: DATETIME_TYPE, accepts: is_datetime, name, side }
}

/// The receiver of a `datetime` method, its known fields and `tzinfo`, and
/// the remaining arguments.
fn receiver(vm: &Vm, args: CallArgs, method: &str) -> Outcome<DateTimeCall> {
    let (receiver, args) = split_receiver(vm, args, DATETIME_TYPE, method, is_datetime)?;
    let (moment, tzinfo) = moment_of(vm, &receiver)?;

    Ok(DateTimeCall { moment, tzinfo, receiver, args })
}

/// The known fields and `tzinfo` of a datetime.
fn moment_of(vm: &Vm, value: &Value) -> Outcome<(Moment, Option<Value>)> {
    let Some(data) = datetime_data(value) else {
        return Err(vm.type_error("datetime receiver lost its payload").into());
    };

    Ok((data.moment.get()?, data.tzinfo.clone()))
}

fn field(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = datetime_data(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    if getset.name == "tzinfo" {
        return Ok(data.tzinfo.clone().unwrap_or(Value::None));
    }
    let clock = match &data.moment {
        Fields::Known(moment) => moment.clock,
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

/// `datetime(year, month, day[, hour[, minute[, second[, microsecond[,
/// tzinfo]]]]])`, or a datetime restored from its pickle state.
fn datetime_new(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = new_class(vm, args, &datetime_type(vm)?)?;

    if let Some((state, tzinfo)) = pickle_state(vm, &args, 2, 10, |bytes| (1..=12).contains(&bytes[2])) {
        let tzinfo = state_tzinfo(vm, tzinfo)?;
        let Ok(state) = <[u8; 10]>::try_from(state) else {
            return Err(vm.type_error("datetime state has the wrong length").into());
        };
        let date = super::date_from_state(&[state[0], state[1], state[2], state[3]]);
        let clock = ClockTime::from_state(&[state[4], state[5], state[6], state[7], state[8], state[9]]);
        return Ok(new_datetime_of(vm, &class, Fields::Known(Moment { date, clock }), tzinfo));
    }

    let arguments = FieldArguments::parse(vm, args, "", &NAMES, 3, 7)?;
    let moment = match arguments.first_unknown() {
        Some(unknown) => Fields::Unknown(unknown),
        None => {
            let [year, month, day, hour, minute, second, microsecond] = arguments.ints([0; 7])?;
            let date = check_date(vm, year, month, day)?;
            let clock = check_clock(vm, hour, minute, second, microsecond)?;
            Fields::Known(Moment { date, clock })
        }
    };
    let tzinfo = match arguments.object(7) {
        Some(tzinfo) => tzinfo_argument(vm, &tzinfo)?,
        None => None,
    };

    Ok(new_datetime_of(vm, &class, moment, tzinfo))
}

/// `cls(year, month, day, hour, minute, second, microsecond, tzinfo)`.
fn call_class(vm: &Vm, class: &ObjectRef, moment: Moment, tzinfo: Value) -> PyResult<Value> {
    let Moment { date, clock } = moment;
    let mut fields: Vec<Value> = [date.year, date.month, date.day, clock.hour, clock.minute, clock.second, clock.microsecond].iter().map(|field| vm.new_int_from_i64(*field)).collect();
    fields.push(tzinfo);

    vm.call(&Value::Object(ObjectRef::clone(class)), CallArgs::new(fields))
}

/// `cls(...)` with each field an unknown value from `origin`.
fn call_class_unknown(vm: &Vm, class: &ObjectRef, origin: &str, tzinfo: Value) -> PyResult<Value> {
    let mut fields: Vec<Value> = (0..7).map(|_| Value::unknown(origin)).collect();
    fields.push(tzinfo);

    vm.call(&Value::Object(ObjectRef::clone(class)), CallArgs::new(fields))
}

/// Splits a timestamp, its fraction rounded to the nearest microsecond with
/// halves away from zero.
fn split_timestamp(vm: &Vm, timestamp: f64) -> PyResult<TimestampParts> {
    let seconds = double_to_time_t(vm, timestamp)?;
    let fraction = timestamp - seconds as f64;
    let scaled = fraction * US_PER_SECOND as f64;
    let rounded = if scaled >= 0.0 { (scaled + 0.5).floor() } else { (scaled - 0.5).ceil() };

    // The fraction is below one second, so the rounding fits.
    let mut microsecond = rounded as i64;
    let mut seconds = seconds;
    if microsecond < 0 {
        seconds = seconds.saturating_sub(1);
        microsecond += US_PER_SECOND;
    }
    if microsecond >= US_PER_SECOND {
        seconds = seconds.saturating_add(1);
        microsecond -= US_PER_SECOND;
    }

    Ok(TimestampParts { seconds, microsecond })
}

/// `cls(*fields, tzinfo)` of a timestamp; `None` stands for an unknown one.
fn from_timestamp(vm: &Vm, class: &ObjectRef, timestamp: Option<f64>, conversion: Conversion, tzinfo: Value) -> Outcome<Value> {
    /// Day ordinal of 1970-01-01, the epoch of timestamps.
    const EPOCH_ORDINAL: i64 = 719_163;

    /// The span of timestamps the host C runtime converts to UTC: 12 hours
    /// before the epoch through 13 hours past 3000-12-31 23:59:59.
    const FIRST_UTC_SECOND: i64 = -43_200;
    const LAST_UTC_SECOND: i64 = 32_535_291_599;

    let Some(timestamp) = timestamp else {
        return Ok(call_class_unknown(vm, class, "datetime from the host clock", tzinfo)?);
    };

    let TimestampParts { seconds, microsecond } = split_timestamp(vm, timestamp)?;
    let range = match conversion {
        Conversion::Local => 0..=LAST_LOCAL_SECOND,
        Conversion::Utc => FIRST_UTC_SECOND..=LAST_UTC_SECOND,
    };
    if !range.contains(&seconds) {
        return Err(vm.raise(ExceptionKind::ValueError, "timestamp out of range for platform localtime()/gmtime() function").into());
    }
    if conversion == Conversion::Local {
        return Ok(call_class_unknown(vm, class, "datetime.fromtimestamp() (host time zone)", tzinfo)?);
    }

    let total = (i128::from(EPOCH_ORDINAL) * i128::from(US_PER_DAY)) + i128::from(seconds) * i128::from(US_PER_SECOND) + i128::from(microsecond);
    let Some(moment) = Moment::from_microseconds(total) else {
        return Err(vm.raise(ExceptionKind::ValueError, "timestamp out of range for platform localtime()/gmtime() function").into());
    };

    Ok(call_class(vm, class, moment, tzinfo)?)
}

/// The local reading of `timestamp`, or with a zone its UTC reading
/// converted by `tz.fromutc`.
fn from_timestamp_in(vm: &Vm, class: &ObjectRef, timestamp: Option<f64>, tzinfo: Option<Value>) -> Outcome<Value> {
    let Some(tzinfo) = tzinfo else {
        return from_timestamp(vm, class, timestamp, Conversion::Local, Value::None);
    };

    let utc = from_timestamp(vm, class, timestamp, Conversion::Utc, tzinfo.clone())?;

    Ok(vm.call_method(&tzinfo, "fromutc", vec![utc])?)
}

/// The `tz` argument of `now` and `fromtimestamp`.
fn zone_argument(vm: &Vm, value: Option<Value>) -> Outcome<Option<Value>> {
    match value {
        Some(value) => tzinfo_argument(vm, &value),
        None => Ok(None),
    }
}

/// `time.time()` as a float; `None` when unknown.
fn clock_reading(vm: &Vm) -> Outcome<Option<f64>> {
    let now = current_time(vm)?;

    Ok(c_double(vm, &now)?)
}

fn datetime_now(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "now")?;
    let values = crate::interp::builtins::parse(vm, args, "now", &["tz"], 0)?;
    let tzinfo = zone_argument(vm, values.into_iter().next().flatten())?;

    let now = clock_reading(vm)?;

    from_timestamp_in(vm, &class, now, tzinfo)
}

fn datetime_utcnow(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "utcnow")?;
    no_arguments(vm, &args, "utcnow")?;

    let now = clock_reading(vm)?;

    from_timestamp(vm, &class, now, Conversion::Utc, Value::None)
}

fn datetime_fromtimestamp(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "fromtimestamp")?;
    let slots = parse_with(vm, args, "fromtimestamp", &["timestamp", "tz"], 1, |vm, index, value| {
        if index == 0 {
            return Ok(TimestampSlot::Timestamp(c_double(vm, &value)?));
        }

        Ok(TimestampSlot::Zone(value))
    })?;

    let mut timestamp = None;
    let mut zone = None;
    for slot in slots.into_iter().flatten() {
        match slot {
            TimestampSlot::Timestamp(value) => timestamp = value,
            TimestampSlot::Zone(value) => zone = Some(value),
        }
    }
    let tzinfo = zone_argument(vm, zone)?;

    from_timestamp_in(vm, &class, timestamp, tzinfo)
}

fn datetime_utcfromtimestamp(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "utcfromtimestamp")?;
    let values = positional(vm, args, "utcfromtimestamp", 1, 1)?;

    let timestamp = c_double(vm, &values[0])?;

    from_timestamp(vm, &class, timestamp, Conversion::Utc, Value::None)
}

/// `datetime.strptime(string, format)`: `cls(*fields)` of what
/// `_strptime._strptime` returns.
fn datetime_strptime(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "strptime")?;
    let values = positional(vm, args, "strptime", 2, 2)?;
    let mut texts = Vec::with_capacity(2);
    for (index, value) in values.iter().enumerate() {
        let value = known(value.clone())?;
        texts.push(Value::Str(c_string(vm, "strptime", index + 1, &value)?));
    }

    let module = strptime_module(vm)?;
    let parsed = known(vm.call_method(&module, "_strptime", texts)?)?;
    let Some(fields) = strptime_fields(vm, &parsed)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "unexpected value from _strptime._strptime").into());
    };

    let arguments = fields.iter().map(|field| vm.new_int_from_i64(*field)).collect();

    Ok(vm.call(&Value::Object(class), CallArgs::new(arguments))?)
}

/// The `_strptime` module: the one an earlier call imported, else a fresh
/// import. Its import gives unknown results unless `strptime_importable`.
fn strptime_module(vm: &Vm) -> Outcome<Value> {
    let state = vm.native_state::<StrptimeModule>();
    if let Some(module) = state.module.borrow().clone() {
        return Ok(module);
    }
    if !strptime_importable(vm)? {
        return Err(Stop::Unknown(Value::unknown("_strptime import (host locale and time zone)")));
    }

    let module = vm.import_module("_strptime")?;
    *state.module.borrow_mut() = Some(module.clone());

    Ok(module)
}

/// Year through second of the struct and the microseconds `_strptime`
/// returns, each a plain `int`; `None` for any other shape, including one
/// whose items cannot be read.
fn strptime_fields(vm: &Vm, parsed: &Value) -> Outcome<Option<Vec<i64>>> {
    if !sequence_with_length(vm, parsed, |length| length == 2)? {
        return Ok(None);
    }
    let Some(fields) = sequence_item(vm, parsed, 0)? else {
        return Ok(None);
    };
    let Some(fraction) = sequence_item(vm, parsed, 1)? else {
        return Ok(None);
    };
    if !sequence_with_length(vm, &fields, |length| length >= 6)? {
        return Ok(None);
    }

    let mut values = Vec::with_capacity(7);
    for index in 0..6 {
        let Some(item) = sequence_item(vm, &fields, index)? else {
            return Ok(None);
        };
        let Some(Integral::Int(number)) = vm.as_integral(&known(item)?) else {
            return Ok(None);
        };
        values.push(number);
    }
    let Some(Integral::Int(fraction)) = vm.as_integral(&known(fraction)?) else {
        return Ok(None);
    };
    values.push(fraction);

    Ok(Some(values))
}

/// Whether `value` is a sequence whose length `accepts`; a length that
/// raises counts as rejected.
fn sequence_with_length(vm: &Vm, value: &Value, accepts: fn(usize) -> bool) -> Outcome<bool> {
    let value = known(value.clone())?;
    if !is_sequence(vm, &value)? {
        return Ok(false);
    }

    match vm.len(&value) {
        Ok(Some(length)) => Ok(accepts(length)),
        Ok(None) => Err(Stop::Unknown(value)),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt.into()),
    }
}

/// Item `index` of a sequence; `None` when reading it raises.
fn sequence_item(vm: &Vm, value: &Value, index: i64) -> Outcome<Option<Value>> {
    match vm.getitem(value, &Value::Int(index)) {
        Ok(item) => Ok(Some(item)),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt.into()),
    }
}

/// `datetime.combine(date, time)`: `cls(*fields, time.tzinfo)`.
fn datetime_combine(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATETIME_TYPE, "combine")?;
    let slots = parse_with(vm, args, "combine", &["date", "time"], 2, |vm, index, value| {
        if value.is_unknown() {
            return Ok(CombineSlot::Unknown(value));
        }
        if index == 0
            && let Some(fields) = date_fields(&value)
        {
            return Ok(CombineSlot::Date(fields));
        }
        if index == 1
            && let Some(data) = time_data(&value)
        {
            return Ok(CombineSlot::Time(data.clock.clone(), data.tzinfo.clone()));
        }

        let expected = if index == 0 { "datetime.date" } else { "datetime.time" };
        let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(&value) };
        Err(vm.type_error(&format!("combine() argument {} must be {expected}, not {shown}", index + 1)))
    })?;

    let mut date = None;
    let mut time = None;
    for slot in slots.into_iter().flatten() {
        match slot {
            CombineSlot::Date(fields) => date = Some(fields.get()?),
            CombineSlot::Time(clock, tzinfo) => time = Some((clock.get()?, tzinfo)),
            CombineSlot::Unknown(value) => return Err(Stop::Unknown(value)),
        }
    }
    let (Some(date), Some((clock, tzinfo))) = (date, time) else {
        return Err(vm.type_error("combine() requires a date and a time").into());
    };

    Ok(call_class(vm, &class, Moment { date, clock }, tzinfo.unwrap_or(Value::None))?)
}

fn datetime_date(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, args, .. } = receiver(vm, args, "date")?;
    no_arguments(vm, &args, "date")?;

    Ok(new_date(vm, moment.date)?)
}

fn datetime_time(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, args, .. } = receiver(vm, args, "time")?;
    no_arguments(vm, &args, "time")?;

    Ok(new_time(vm, moment.clock, None)?)
}

fn datetime_timetz(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, args, .. } = receiver(vm, args, "timetz")?;
    no_arguments(vm, &args, "timetz")?;

    Ok(new_time(vm, moment.clock, tzinfo)?)
}

fn datetime_ctime(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, args, .. } = receiver(vm, args, "ctime")?;
    no_arguments(vm, &args, "ctime")?;

    Ok(Value::str(&format::ctime(moment.date, moment.clock)))
}

/// `timetuple()`, whose `tm_isdst` comes from `dst()`: -1 when it is
/// `None`, else whether it is nonzero.
fn datetime_timetuple(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "timetuple")?;
    no_arguments(vm, &args, "timetuple")?;

    let is_dst = match &tzinfo {
        Some(tzinfo) => match offset_minutes(vm, tzinfo, OffsetMethod::Dst, &receiver)? {
            Some(OffsetMinutes(minutes)) => i64::from(minutes != 0),
            None => -1,
        },
        None => -1,
    };

    Ok(format::struct_time(vm, moment.date, moment.clock, is_dst)?)
}

/// `utctimetuple()`: the fields less the UTC offset with `tm_isdst` 0. The
/// year may leave 1..=9999 by one.
fn datetime_utctimetuple(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "utctimetuple")?;
    no_arguments(vm, &args, "utctimetuple")?;

    let utc = match utc_offset(vm, tzinfo.as_ref(), &receiver)? {
        Some(OffsetMinutes(minutes)) => {
            let total = moment.microseconds() - i128::from(minutes) * 60 * i128::from(US_PER_SECOND);
            let Some(utc) = Moment::from_microseconds_unbounded(total) else {
                return Err(vm.raise(ExceptionKind::OverflowError, "date value out of range").into());
            };
            utc
        }
        None => moment,
    };

    Ok(format::struct_time(vm, utc.date, utc.clock, 0)?)
}

/// The `sep` argument of `isoformat`: one character.
fn separator(vm: &Vm, args: CallArgs) -> Outcome<u8> {
    let values = parse_with(vm, args, "isoformat", &["sep"], 0, |vm, _, value| {
        if value.is_unknown() {
            return Ok(Err(value));
        }
        if let Some(bytes) = vm.as_str_bytes(&value)
            && let [byte] = bytes.as_bytes()
        {
            return Ok(Ok(*byte));
        }

        let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(&value) };
        Err(vm.type_error(&format!("isoformat() argument 1 must be char, not {shown}")))
    })?;

    match values.into_iter().next().flatten() {
        Some(Ok(byte)) => Ok(byte),
        Some(Err(unknown)) => Err(Stop::Unknown(unknown)),
        None => Ok(b'T'),
    }
}

fn datetime_isoformat(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "isoformat")?;
    let separator = separator(vm, args)?;

    let offset = format::iso_offset(vm, tzinfo.as_ref(), &receiver)?;
    let mut text = format::iso_date(moment.date).into_bytes();
    text.push(separator);
    text.extend_from_slice(format::iso_clock(moment.clock).as_bytes());
    text.extend_from_slice(offset.as_bytes());

    Ok(Value::Str(PyBytes::new(text)))
}

fn datetime_offset(vm: &Vm, args: CallArgs, offset: OffsetMethod, name: &str) -> Outcome<Value> {
    let DateTimeCall { tzinfo, receiver, args, .. } = receiver(vm, args, name)?;
    no_arguments(vm, &args, name)?;

    offset_value(vm, tzinfo.as_ref(), offset, &receiver)
}

fn datetime_tzname(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { tzinfo, receiver, args, .. } = receiver(vm, args, "tzname")?;
    no_arguments(vm, &args, "tzname")?;

    zone_name(vm, tzinfo.as_ref(), &receiver)
}

/// A datetime of the receiver's type with some fields replaced, built
/// without calling the type.
fn datetime_replace(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "replace")?;

    let arguments = FieldArguments::parse(vm, args, "replace", &NAMES, 0, 7)?;
    let Moment { date, clock } = moment;
    let defaults = [date.year, date.month, date.day, clock.hour, clock.minute, clock.second, clock.microsecond];
    let [year, month, day, hour, minute, second, microsecond] = arguments.ints(defaults)?;
    let date = check_date(vm, year, month, day)?;
    let clock = check_clock(vm, hour, minute, second, microsecond)?;
    let tzinfo = match arguments.object(7) {
        Some(tzinfo) => tzinfo_argument(vm, &tzinfo)?,
        None => tzinfo,
    };

    Ok(new_datetime_of(vm, &vm.type_of(&receiver), Fields::Known(Moment { date, clock }), tzinfo))
}

/// The moment `microseconds` after `moment`; out of range is an error.
fn shift(vm: &Vm, moment: Moment, microseconds: i128) -> PyResult<Moment> {
    Moment::from_microseconds(moment.microseconds() + microseconds).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "date value out of range"))
}

/// `astimezone(tz)`: the same UTC moment in the zone of `tz`, through
/// `tz.fromutc`.
fn datetime_astimezone(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "astimezone")?;
    let values = parse_with(vm, args, "astimezone", &["tz"], 1, |vm, _, value| {
        if value.is_unknown() || is_tzinfo(vm, &value)? {
            return Ok(value);
        }

        let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(&value) };
        Err(vm.type_error(&format!("astimezone() argument 1 must be datetime.tzinfo, not {shown}")))
    })?;
    let Some(Some(zone)) = values.into_iter().next() else {
        return Err(vm.type_error("astimezone() requires a tz").into());
    };
    let zone = known(zone)?;

    if super::zone::same_tzinfo(tzinfo.as_ref(), Some(&zone)) {
        return Ok(receiver);
    }
    let Some(OffsetMinutes(minutes)) = utc_offset(vm, tzinfo.as_ref(), &receiver)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "astimezone() cannot be applied to a naive datetime").into());
    };

    let utc = shift(vm, moment, -i128::from(minutes) * 60 * i128::from(US_PER_SECOND))?;
    let utc = new_datetime(vm, utc, Some(zone.clone()))?;

    Ok(vm.call_method(&zone, "fromutc", vec![utc])?)
}

fn datetime_reduce(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "__reduce__")?;
    no_arguments(vm, &args, "__reduce__")?;

    let mut state = vec![Value::Str(PyBytes::new(moment.state().to_vec()))];
    state.extend(tzinfo);

    Ok(Value::tuple(vec![Value::Object(vm.type_of(&receiver)), Value::tuple(state)]))
}

fn datetime_repr(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "__repr__")?;
    no_operands(vm, args, "__repr__")?;

    let Moment { date, clock } = moment;
    let prefix = format!("{}({}, {}, {}, {}", vm.type_name(&receiver), date.year, date.month, date.day, format::clock_arguments(clock));

    format::close_repr(vm, prefix, tzinfo.as_ref())
}

/// `str(datetime)`: `self.isoformat(' ')`.
fn datetime_str(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, DATETIME_TYPE, "__str__", is_datetime)?;
    no_operands(vm, args, "__str__")?;

    Ok(vm.call_method(&receiver, "isoformat", vec![Value::str(" ")])?)
}

/// Naive datetimes hash as their pickle state; aware ones as the
/// `(days, seconds, microseconds)` of their UTC moment.
fn datetime_hash(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, "__hash__")?;
    no_operands(vm, args, "__hash__")?;

    let Some(data) = datetime_data(&receiver) else {
        return Err(vm.type_error("datetime receiver lost its payload").into());
    };
    if let Some(hash) = data.hash.get() {
        return Ok(hash_value(vm, hash));
    }

    let hash = compute_hash(vm, moment, tzinfo.as_ref(), &receiver)?;
    data.hash.set(Some(hash));

    Ok(hash_value(vm, hash))
}

fn compute_hash(vm: &Vm, moment: Moment, tzinfo: Option<&Value>, receiver: &Value) -> Outcome<PyHash> {
    let width = vm.config.long_width;
    let Some(OffsetMinutes(minutes)) = utc_offset(vm, tzinfo, receiver)? else {
        return Ok(hash_bytes(width, &moment.state()));
    };

    let total = moment.microseconds() - i128::from(minutes) * 60 * i128::from(US_PER_SECOND);
    let delta = delta_from_microseconds(vm, total)?;
    let fields = [delta.days, delta.seconds, delta.microseconds].map(|field| hash_int(width, field));

    Ok(hash_tuple(width, fields, 3))
}

/// A datetime plus a delta, in either order, keeping the `tzinfo`.
fn add(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    let (datetime, delta) = match (is_datetime(left), delta_data(left), is_datetime(right), delta_data(right)) {
        (true, _, _, Some(delta)) => (left, delta),
        (_, Some(delta), true, _) => (right, delta),
        _ => return Ok(Value::NotImplemented),
    };

    let (moment, tzinfo) = moment_of(vm, datetime)?;
    let moment = shift(vm, moment, delta.microseconds_total())?;

    Ok(new_datetime(vm, moment, tzinfo)?)
}

/// A datetime less a datetime, giving the delta between their UTC moments,
/// or less a delta.
fn subtract(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    if !is_datetime(left) {
        return Ok(Value::NotImplemented);
    }
    let (moment, tzinfo) = moment_of(vm, left)?;

    if let Some(delta) = delta_data(right) {
        let moment = shift(vm, moment, -delta.microseconds_total())?;
        return Ok(new_datetime(vm, moment, tzinfo)?);
    }
    if !is_datetime(right) {
        return Ok(Value::NotImplemented);
    }

    let (other, other_tzinfo) = moment_of(vm, right)?;
    let difference = match offset_pair(vm, ZoneContext { tzinfo: tzinfo.as_ref(), argument: left }, ZoneContext { tzinfo: other_tzinfo.as_ref(), argument: right })? {
        OffsetPair::Naive => moment.microseconds() - other.microseconds(),
        OffsetPair::Aware { left: OffsetMinutes(offset), right: OffsetMinutes(other_offset) } => moment.microseconds() - other.microseconds() - i128::from(offset - other_offset) * 60 * i128::from(US_PER_SECOND),
        OffsetPair::Mixed => return Err(vm.type_error("can't subtract offset-naive and offset-aware datetimes").into()),
    };

    Ok(new_delta(vm, delta_from_microseconds(vm, difference)?)?)
}

fn datetime_compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> PyResult<Value> {
    finish(compare(vm, args, name, operation))
}

/// Datetimes compare by their UTC moments. A plain date only tests unequal;
/// other objects with a `timetuple` get to compare themselves.
fn compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> Outcome<Value> {
    let DateTimeCall { moment, tzinfo, receiver, args } = receiver(vm, args, name)?;
    let other = known(operand(vm, args, name)?)?;

    if !is_datetime(&other) {
        if !is_date(&other) && has_attribute(vm, &other, "timetuple")? {
            return Ok(Value::NotImplemented);
        }
        return match operation {
            CompareOp::Equal => Ok(Value::Bool(false)),
            CompareOp::NotEqual => Ok(Value::Bool(true)),
            _ => Err(compare_error(vm, &receiver, &other).into()),
        };
    }

    let (other_moment, other_tzinfo) = moment_of(vm, &other)?;
    let ordering = match offset_pair(vm, ZoneContext { tzinfo: tzinfo.as_ref(), argument: &receiver }, ZoneContext { tzinfo: other_tzinfo.as_ref(), argument: &other })? {
        OffsetPair::Naive => moment.cmp(&other_moment),
        OffsetPair::Aware { left: OffsetMinutes(offset), right: OffsetMinutes(other_offset) } => {
            let shift = |minutes: i64| i128::from(minutes) * 60 * i128::from(US_PER_SECOND);
            (moment.microseconds() - shift(offset)).cmp(&(other_moment.microseconds() - shift(other_offset)))
        }
        OffsetPair::Mixed => return Err(vm.type_error("can't compare offset-naive and offset-aware datetimes").into()),
    };

    Ok(Value::Bool(operation.holds(ordering)))
}
