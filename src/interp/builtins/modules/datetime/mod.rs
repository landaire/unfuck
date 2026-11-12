//! The `datetime` extension module. Calendar arithmetic, formatting, and
//! conversions through Python `tzinfo` methods are exact. Readings of the
//! host clock and conversions through the host time zone are unknown
//! values.

mod calendar;
mod date;
mod date_time;
mod delta;
mod fields;
mod format;
mod time;
mod tzinfo;
mod zone;

use std::cell::Cell;

use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::set_class_attribute;
use crate::interp::builtins::modules::capsule::new_capsule;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::hash::PyHash;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use calendar::CivilDate;

const MINYEAR: i64 = 1;
const MAXYEAR: i64 = 9999;

/// The ordinal of 9999-12-31.
const MAX_ORDINAL: i64 = 3_652_059;

/// The largest magnitude of `timedelta.days`.
const MAX_DELTA_DAYS: i64 = 999_999_999;

const US_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
const US_PER_DAY: i64 = US_PER_SECOND * SECONDS_PER_DAY;

const DELTA_TYPE: &str = "datetime.timedelta";
const DATE_TYPE: &str = "datetime.date";
const TIME_TYPE: &str = "datetime.time";
const DATETIME_TYPE: &str = "datetime.datetime";
const TZINFO_TYPE: &str = "datetime.tzinfo";

/// Why a native stopped early: a Python-level signal, or an unknown value
/// that the result depends on and that becomes the result.
enum Stop {
    Signal(Signal),
    Unknown(Value),
}

impl From<Signal> for Stop {
    fn from(signal: Signal) -> Self {
        Self::Signal(signal)
    }
}

type Outcome<T> = Result<T, Stop>;

/// Ends a native with its result, which is the unknown value it stopped on
/// if it stopped on one.
fn finish(outcome: Outcome<Value>) -> PyResult<Value> {
    match outcome {
        Ok(value) | Err(Stop::Unknown(value)) => Ok(value),
        Err(Stop::Signal(signal)) => Err(signal),
    }
}

/// Passes `value` through unless it is unknown.
fn known(value: Value) -> Outcome<Value> {
    if value.is_unknown() {
        return Err(Stop::Unknown(value));
    }

    Ok(value)
}

/// A time of day. Fields read from a pickle state may lie outside their
/// usual ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClockTime {
    hour: i64,
    minute: i64,
    second: i64,
    microsecond: i64,
}

impl ClockTime {
    const MIDNIGHT: Self = Self { hour: 0, minute: 0, second: 0, microsecond: 0 };

    /// Whole seconds since midnight.
    fn seconds(self) -> i64 {
        (self.hour * 60 + self.minute) * 60 + self.second
    }

    /// The six bytes of a time pickle state.
    fn state(self) -> [u8; 6] {
        let [_, us_high, us_middle, us_low] = (self.microsecond as u32).to_be_bytes();

        [self.hour as u8, self.minute as u8, self.second as u8, us_high, us_middle, us_low]
    }

    fn from_state(bytes: &[u8; 6]) -> Self {
        let [hour, minute, second, us_high, us_middle, us_low] = *bytes;

        Self { hour: i64::from(hour), minute: i64::from(minute), second: i64::from(second), microsecond: i64::from(u32::from_be_bytes([0, us_high, us_middle, us_low])) }
    }
}

/// A date and a time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Moment {
    date: CivilDate,
    clock: ClockTime,
}

impl Moment {
    /// Microseconds since the start of day ordinal 0.
    fn microseconds(self) -> i128 {
        (i128::from(self.date.ordinal()) * i128::from(SECONDS_PER_DAY) + i128::from(self.clock.seconds())) * i128::from(US_PER_SECOND) + i128::from(self.clock.microsecond)
    }

    /// The moment `microseconds` after the ordinal epoch; `None` outside
    /// years 1..=9999.
    fn from_microseconds(microseconds: i128) -> Option<Self> {
        let ordinal = microseconds.div_euclid(i128::from(US_PER_DAY));
        if !(1..=i128::from(MAX_ORDINAL)).contains(&ordinal) {
            return None;
        }

        Self::from_microseconds_unbounded(microseconds)
    }

    /// `from_microseconds` without the year range; `None` only when the
    /// day count leaves `i64`.
    fn from_microseconds_unbounded(microseconds: i128) -> Option<Self> {
        let ordinal = i64::try_from(microseconds.div_euclid(i128::from(US_PER_DAY))).ok()?;
        let within = i64::try_from(microseconds.rem_euclid(i128::from(US_PER_DAY))).ok()?;

        let seconds = within / US_PER_SECOND;
        let clock = ClockTime { hour: seconds / 3600, minute: seconds / 60 % 60, second: seconds % 60, microsecond: within % US_PER_SECOND };

        Some(Self { date: CivilDate::from_ordinal(ordinal), clock })
    }

    /// The ten bytes of a datetime pickle state.
    fn state(self) -> [u8; 10] {
        let mut bytes = [0; 10];
        bytes[..4].copy_from_slice(&date_state(self.date));
        bytes[4..].copy_from_slice(&self.clock.state());

        bytes
    }
}

/// The four bytes of a date pickle state.
fn date_state(date: CivilDate) -> [u8; 4] {
    let [_, _, year_high, year_low] = (date.year as u32).to_be_bytes();

    [year_high, year_low, date.month as u8, date.day as u8]
}

fn date_from_state(bytes: &[u8; 4]) -> CivilDate {
    let [year_high, year_low, month, day] = *bytes;

    CivilDate::new(i64::from(u16::from_be_bytes([year_high, year_low])), i64::from(month), i64::from(day))
}

/// Fields of an instance, or the unknown value they were built from when a
/// constructor received one, as for the current time.
#[derive(Clone)]
enum Fields<T> {
    Known(T),
    Unknown(Value),
}

impl<T> Fields<T>
where
    T: Copy,
{
    /// The known fields; stops on unknown ones.
    fn get(&self) -> Outcome<T> {
        match self {
            Self::Known(fields) => Ok(*fields),
            Self::Unknown(value) => Err(Stop::Unknown(value.clone())),
        }
    }
}

/// A normalized `timedelta`: `0 <= seconds < 86400` and
/// `0 <= microseconds < 1000000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DeltaData {
    days: i64,
    seconds: i64,
    microseconds: i64,
}

impl DeltaData {
    fn microseconds_total(self) -> i128 {
        (i128::from(self.days) * i128::from(SECONDS_PER_DAY) + i128::from(self.seconds)) * i128::from(US_PER_SECOND) + i128::from(self.microseconds)
    }

    /// The delta of `total` microseconds; the day count instead when it
    /// exceeds the magnitude limit.
    fn from_microseconds(total: i128) -> Result<Self, i128> {
        let days = total.div_euclid(i128::from(US_PER_DAY));
        if !(-i128::from(MAX_DELTA_DAYS)..=i128::from(MAX_DELTA_DAYS)).contains(&days) {
            return Err(days);
        }

        // Both are now within a day's or a delta's range.
        let days = days as i64;
        let within = total.rem_euclid(i128::from(US_PER_DAY)) as i64;

        Ok(Self { days, seconds: within / US_PER_SECOND, microseconds: within % US_PER_SECOND })
    }
}

/// Which operand of a binary operator the receiver is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

/// A binary slot wrapper of one of the module's types.
struct BinarySlot {
    /// Qualified name of the receiver's type.
    owner: &'static str,
    accepts: fn(&Value) -> bool,
    name: &'static str,
    side: Side,
}

struct DateData {
    date: Fields<CivilDate>,
}

/// A `time`. `tzinfo` is `None` both without one and for an explicit
/// `None`, which behave alike.
struct TimeData {
    clock: Fields<ClockTime>,
    tzinfo: Option<Value>,
    hash: Cell<Option<PyHash>>,
}

struct DateTimeData {
    moment: Fields<Moment>,
    tzinfo: Option<Value>,
    hash: Cell<Option<PyHash>>,
}

crate::interp::builtins::modules::impl_native_data!(DeltaData, "datetime.timedelta");
crate::interp::builtins::modules::impl_native_data!(DateData, "datetime.date");
crate::interp::builtins::modules::impl_native_data!(TimeData, "datetime.time");
crate::interp::builtins::modules::impl_native_data!(DateTimeData, "datetime.datetime");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let delta = delta_type(vm)?;
    let date = date_type(vm)?;
    let time = time_type(vm)?;
    let datetime = datetime_type(vm)?;
    let tzinfo = tzinfo_type(vm)?;

    let last_clock = ClockTime { hour: 23, minute: 59, second: 59, microsecond: US_PER_SECOND - 1 };
    let first_date = CivilDate::new(MINYEAR, 1, 1);
    let last_date = CivilDate::new(MAXYEAR, 12, 31);
    let tick = DeltaData { days: 0, seconds: 0, microseconds: 1 };

    set_class_attribute(vm, &delta, "resolution", new_delta(vm, tick)?)?;
    set_class_attribute(vm, &delta, "min", new_delta(vm, DeltaData { days: -MAX_DELTA_DAYS, seconds: 0, microseconds: 0 })?)?;
    set_class_attribute(vm, &delta, "max", new_delta(vm, DeltaData { days: MAX_DELTA_DAYS, seconds: SECONDS_PER_DAY - 1, microseconds: US_PER_SECOND - 1 })?)?;

    set_class_attribute(vm, &date, "min", new_date(vm, first_date)?)?;
    set_class_attribute(vm, &date, "max", new_date(vm, last_date)?)?;
    set_class_attribute(vm, &date, "resolution", new_delta(vm, DeltaData { days: 1, seconds: 0, microseconds: 0 })?)?;

    set_class_attribute(vm, &time, "min", new_time(vm, ClockTime::MIDNIGHT, None)?)?;
    set_class_attribute(vm, &time, "max", new_time(vm, last_clock, None)?)?;
    set_class_attribute(vm, &time, "resolution", new_delta(vm, tick)?)?;

    set_class_attribute(vm, &datetime, "min", new_datetime(vm, Moment { date: first_date, clock: ClockTime::MIDNIGHT }, None)?)?;
    set_class_attribute(vm, &datetime, "max", new_datetime(vm, Moment { date: last_date, clock: last_clock }, None)?)?;
    set_class_attribute(vm, &datetime, "resolution", new_delta(vm, tick)?)?;

    set_attribute(vm, module, "MINYEAR", Value::Int(MINYEAR))?;
    set_attribute(vm, module, "MAXYEAR", Value::Int(MAXYEAR))?;
    set_attribute(vm, module, "date", Value::Object(date))?;
    set_attribute(vm, module, "datetime", Value::Object(datetime))?;
    set_attribute(vm, module, "time", Value::Object(time))?;
    set_attribute(vm, module, "timedelta", Value::Object(delta))?;
    set_attribute(vm, module, "tzinfo", Value::Object(tzinfo))?;
    set_attribute(vm, module, "datetime_CAPI", new_capsule(vm, "datetime.datetime_CAPI")?)?;

    Ok(())
}

fn delta_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DELTA_TYPE, delta::create_type)
}

fn date_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DATE_TYPE, date::create_type)
}

fn time_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, TIME_TYPE, time::create_type)
}

fn datetime_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DATETIME_TYPE, date_time::create_type)
}

fn tzinfo_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, TZINFO_TYPE, tzinfo::create_type)
}

fn delta_data(value: &Value) -> Option<DeltaData> {
    native_data::<DeltaData>(value).copied()
}

fn time_data(value: &Value) -> Option<&TimeData> {
    native_data::<TimeData>(value)
}

fn datetime_data(value: &Value) -> Option<&DateTimeData> {
    native_data::<DateTimeData>(value)
}

/// The date fields of a date or a datetime; `None` for anything else.
fn date_fields(value: &Value) -> Option<Fields<CivilDate>> {
    if let Some(data) = native_data::<DateData>(value) {
        return Some(data.date.clone());
    }

    let data = datetime_data(value)?;
    let fields = match &data.moment {
        Fields::Known(moment) => Fields::Known(moment.date),
        Fields::Unknown(value) => Fields::Unknown(value.clone()),
    };

    Some(fields)
}

fn is_date(value: &Value) -> bool {
    date_fields(value).is_some()
}

fn is_datetime(value: &Value) -> bool {
    datetime_data(value).is_some()
}

fn is_time(value: &Value) -> bool {
    time_data(value).is_some()
}

fn is_delta(value: &Value) -> bool {
    delta_data(value).is_some()
}

/// An exact `timedelta`.
fn new_delta(vm: &Vm, delta: DeltaData) -> PyResult<Value> {
    Ok(new_instance(vm, &delta_type(vm)?, Payload::Native(Box::new(delta))))
}

/// A `timedelta` of `class` without calling it.
fn new_delta_of(vm: &Vm, class: &ObjectRef, delta: DeltaData) -> Value {
    new_instance(vm, class, Payload::Native(Box::new(delta)))
}

/// An exact `date`.
fn new_date(vm: &Vm, date: CivilDate) -> PyResult<Value> {
    Ok(new_date_of(vm, &date_type(vm)?, Fields::Known(date)))
}

/// A `date` of `class` without calling it.
fn new_date_of(vm: &Vm, class: &ObjectRef, date: Fields<CivilDate>) -> Value {
    new_instance(vm, class, Payload::Native(Box::new(DateData { date })))
}

/// An exact `time`.
fn new_time(vm: &Vm, clock: ClockTime, tzinfo: Option<Value>) -> PyResult<Value> {
    Ok(new_time_of(vm, &time_type(vm)?, Fields::Known(clock), tzinfo))
}

/// A `time` of `class` without calling it.
fn new_time_of(vm: &Vm, class: &ObjectRef, clock: Fields<ClockTime>, tzinfo: Option<Value>) -> Value {
    new_instance(vm, class, Payload::Native(Box::new(TimeData { clock, tzinfo, hash: Cell::new(None) })))
}

/// An exact `datetime`.
fn new_datetime(vm: &Vm, moment: Moment, tzinfo: Option<Value>) -> PyResult<Value> {
    Ok(new_datetime_of(vm, &datetime_type(vm)?, Fields::Known(moment), tzinfo))
}

/// A `datetime` of `class` without calling it.
fn new_datetime_of(vm: &Vm, class: &ObjectRef, moment: Fields<Moment>, tzinfo: Option<Value>) -> Value {
    new_instance(vm, class, Payload::Native(Box::new(DateTimeData { moment, tzinfo, hash: Cell::new(None) })))
}

/// The receiver of a method of the type named `owner`, checked by `accepts`,
/// and the arguments after it.
fn split_receiver(vm: &Vm, mut args: CallArgs, owner: &str, method: &str, accepts: fn(&Value) -> bool) -> Outcome<(Value, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{owner}' object needs an argument")).into());
    }

    let receiver = args.positional.remove(0);
    if receiver.is_unknown() {
        return Err(Stop::Unknown(receiver));
    }
    if !accepts(&receiver) {
        return Err(vm.type_error(&format!("descriptor '{method}' requires a '{owner}' object but received a '{}'", vm.type_name(&receiver))).into());
    }

    Ok((receiver, args))
}

/// The class argument of a class method.
fn split_class(vm: &Vm, args: CallArgs, owner: &str, method: &str) -> Outcome<(ObjectRef, CallArgs)> {
    let (class, args) = split_receiver(vm, args, owner, method, |value| value.as_object().is_some_and(|object| object.as_class().is_some()))?;
    let Value::Object(class) = class else {
        return Err(vm.type_error("class method receiver is not a class").into());
    };

    Ok((class, args))
}

/// Runs `operator` on the operands of a call to `slot`, in source order.
fn binary(vm: &Vm, args: CallArgs, slot: BinarySlot, operator: fn(&Vm, &Value, &Value) -> Outcome<Value>) -> PyResult<Value> {
    finish(binary_outcome(vm, args, slot, operator))
}

fn binary_outcome(vm: &Vm, args: CallArgs, slot: BinarySlot, operator: fn(&Vm, &Value, &Value) -> Outcome<Value>) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, slot.owner, slot.name, slot.accepts)?;
    let other = known(operand(vm, args, slot.name)?)?;

    match slot.side {
        Side::Left => operator(vm, &receiver, &other),
        Side::Right => operator(vm, &other, &receiver),
    }
}

/// The operand of the binary slot wrapper `name`.
fn operand(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    no_wrapper_keywords(vm, &args, name)?;

    crate::interp::builtins::arguments::wrapper_operand(vm, args)
}

/// Checks the arguments of the unary slot wrapper `name`.
fn no_operands(vm: &Vm, args: CallArgs, name: &str) -> PyResult<()> {
    no_wrapper_keywords(vm, &args, name)?;

    crate::interp::builtins::arguments::wrapper_arguments(vm, args, 0).map(drop)
}

/// Slot wrappers take positional arguments only.
fn no_wrapper_keywords(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("wrapper {name} doesn't take keyword arguments")));
    }

    Ok(())
}

/// Checks that a no-argument method got no arguments.
fn no_arguments(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<()> {
    crate::interp::builtins::modules::no_arguments(vm, args, method)
}

/// The value `hash()` gives for `hash`.
fn hash_value(vm: &Vm, hash: PyHash) -> Value {
    vm.new_int_from_i64(hash.value())
}

/// Comparison failure between two operands of unrelated types.
fn compare_error(vm: &Vm, left: &Value, right: &Value) -> Signal {
    vm.type_error(&format!("can't compare {} to {}", vm.type_name(left), vm.type_name(right)))
}

/// Whether `value` has attribute `name`; any exception of the lookup counts
/// as absent.
fn has_attribute(vm: &Vm, value: &Value, name: &str) -> PyResult<bool> {
    match vm.getattr_opt(value, &crate::interp::value::PyBytes::from(name)) {
        Ok(found) => Ok(found.is_some()),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt),
    }
}

/// The six rich comparison slot wrappers, each calling `$compare(vm, args,
/// name, operation)`.
macro_rules! comparison_methods {
    ($compare:path) => {
        [
            crate::interp::builtins::method("__lt__", |vm, args| $compare(vm, args, "__lt__", crate::interp::ops::CompareOp::Less)),
            crate::interp::builtins::method("__le__", |vm, args| $compare(vm, args, "__le__", crate::interp::ops::CompareOp::LessEqual)),
            crate::interp::builtins::method("__eq__", |vm, args| $compare(vm, args, "__eq__", crate::interp::ops::CompareOp::Equal)),
            crate::interp::builtins::method("__ne__", |vm, args| $compare(vm, args, "__ne__", crate::interp::ops::CompareOp::NotEqual)),
            crate::interp::builtins::method("__gt__", |vm, args| $compare(vm, args, "__gt__", crate::interp::ops::CompareOp::Greater)),
            crate::interp::builtins::method("__ge__", |vm, args| $compare(vm, args, "__ge__", crate::interp::ops::CompareOp::GreaterEqual)),
        ]
    };
}

use comparison_methods;

#[cfg(test)]
mod tests;
