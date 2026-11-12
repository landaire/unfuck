//! `date`, whose methods also serve `datetime` receivers.

use super::BinarySlot;
use super::DATE_TYPE;
use super::DeltaData;
use super::Fields;
use super::MAX_ORDINAL;
use super::Outcome;
use super::Side;
use super::binary;
use super::calendar::CivilDate;
use super::compare_error;
use super::comparison_methods;
use super::date_fields;
use super::date_from_state;
use super::date_state;
use super::date_type;
use super::delta_data;
use super::fields::FieldArguments;
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
use super::new_date_of;
use super::new_delta;
use super::no_arguments;
use super::no_operands;
use super::operand;
use super::split_class;
use super::split_receiver;
use super::zone::ZoneContext;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::class_method;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args::read_buffer;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::modules::time::double_to_time_t;
use crate::interp::builtins::parse;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::hash_bytes;
use crate::interp::hash::hash_tuple;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const NAMES: [&str; 3] = ["year", "month", "day"];

/// The last second the host C runtime converts to local time.
pub(super) const LAST_LOCAL_SECOND: i64 = 32_535_244_799;

/// A method call: the receiver's known fields, the receiver itself, and
/// the remaining arguments.
struct DateCall {
    date: CivilDate,
    receiver: Value,
    args: CallArgs,
}

pub(super) fn create_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "date",
            module: "datetime",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", |vm, args| finish(date_new(vm, args))),
                method("__repr__", |vm, args| finish(date_repr(vm, args))),
                method("__str__", |vm, args| finish(date_str(vm, args))),
                method("__hash__", |vm, args| finish(date_hash(vm, args))),
                method("__add__", |vm, args| binary(vm, args, slot("__add__", Side::Left), add)),
                method("__radd__", |vm, args| binary(vm, args, slot("__radd__", Side::Right), add)),
                method("__sub__", |vm, args| binary(vm, args, slot("__sub__", Side::Left), subtract)),
                method("__rsub__", |vm, args| binary(vm, args, slot("__rsub__", Side::Right), subtract)),
                class_method("fromtimestamp", |vm, args| finish(date_fromtimestamp(vm, args))),
                class_method("fromordinal", |vm, args| finish(date_fromordinal(vm, args))),
                class_method("today", |vm, args| finish(date_today(vm, args))),
                method("ctime", |vm, args| finish(date_ctime(vm, args))),
                method("strftime", |vm, args| finish(date_strftime(vm, args))),
                method("__format__", |vm, args| finish(date_format(vm, args))),
                method("timetuple", |vm, args| finish(date_timetuple(vm, args))),
                method("isocalendar", |vm, args| finish(date_isocalendar(vm, args))),
                method("isoformat", |vm, args| finish(date_isoformat(vm, args))),
                method("isoweekday", |vm, args| finish(date_isoweekday(vm, args))),
                method("toordinal", |vm, args| finish(date_toordinal(vm, args))),
                method("weekday", |vm, args| finish(date_weekday(vm, args))),
                method("replace", |vm, args| finish(date_replace(vm, args))),
                method("__reduce__", |vm, args| finish(date_reduce(vm, args))),
            ],
        },
    )?;

    install(vm, &class, &comparison_methods!(date_compare))?;
    for name in NAMES {
        add_getset(vm, &class, GetSet { name, owner: DATE_TYPE, get: field, set: None })?;
    }

    Ok(class)
}

/// A binary slot wrapper of this type.
const fn slot(name: &'static str, side: Side) -> BinarySlot {
    BinarySlot { owner: DATE_TYPE, accepts: is_date, name, side }
}

/// The receiver of a `date` method, its known date fields, and the
/// remaining arguments.
fn receiver(vm: &Vm, args: CallArgs, method: &str) -> Outcome<DateCall> {
    let (receiver, args) = split_receiver(vm, args, DATE_TYPE, method, is_date)?;
    let date = receiver_date(vm, &receiver)?;

    Ok(DateCall { date, receiver, args })
}

fn receiver_date(vm: &Vm, receiver: &Value) -> Outcome<CivilDate> {
    let Some(fields) = date_fields(receiver) else {
        return Err(vm.type_error("date receiver lost its payload").into());
    };

    fields.get()
}

fn field(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(fields) = date_fields(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    let date = match fields {
        Fields::Known(date) => date,
        Fields::Unknown(value) => return Ok(value),
    };

    let value = match getset.name {
        "year" => date.year,
        "month" => date.month,
        _ => date.day,
    };

    Ok(Value::Int(value))
}

/// `date(year, month, day)`, or a date restored from its pickle state.
fn date_new(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = new_class(vm, args, &date_type(vm)?)?;

    if let Some((state, _)) = pickle_state(vm, &args, 1, 4, |bytes| (1..=12).contains(&bytes[2])) {
        let Ok(state) = <[u8; 4]>::try_from(state) else {
            return Err(vm.type_error("date state has the wrong length").into());
        };
        return Ok(new_date_of(vm, &class, Fields::Known(date_from_state(&state))));
    }

    let arguments = FieldArguments::parse(vm, args, "", &NAMES, 3, 3)?;
    if let Some(unknown) = arguments.first_unknown() {
        return Ok(new_date_of(vm, &class, Fields::Unknown(unknown)));
    }
    let [year, month, day] = arguments.ints([0; 3])?;
    let date = check_date(vm, year, month, day)?;

    Ok(new_date_of(vm, &class, Fields::Known(date)))
}

/// `cls(year, month, day)` with each field unknown, for a local date the
/// host time zone determines.
fn call_class_unknown(vm: &Vm, class: &ObjectRef, origin: &str) -> PyResult<Value> {
    let fields = (0..3).map(|_| Value::unknown(origin)).collect();

    vm.call(&Value::Object(ObjectRef::clone(class)), CallArgs::new(fields))
}

/// `date.fromtimestamp(timestamp)`: the local date, which depends on the
/// host time zone.
fn date_fromtimestamp(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATE_TYPE, "fromtimestamp")?;
    let [timestamp] = <[Value; 1]>::try_from(positional(vm, args, "fromtimestamp", 1, 1)?).map_err(|_| vm.type_error("fromtimestamp() takes exactly 1 argument"))?;

    if let Some(timestamp) = c_double(vm, &timestamp)? {
        let seconds = double_to_time_t(vm, timestamp)?;
        if !(0..=LAST_LOCAL_SECOND).contains(&seconds) {
            return Err(vm.raise(ExceptionKind::ValueError, "timestamp out of range for platform localtime() function").into());
        }
    }

    Ok(call_class_unknown(vm, &class, "date.fromtimestamp() (host time zone)")?)
}

/// `date.fromordinal(ordinal)`: `cls(year, month, day)`.
fn date_fromordinal(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATE_TYPE, "fromordinal")?;
    let [ordinal] = <[Value; 1]>::try_from(positional(vm, args, "fromordinal", 1, 1)?).map_err(|_| vm.type_error("fromordinal() takes exactly 1 argument"))?;
    if ordinal.is_unknown() {
        let fields = vec![ordinal.clone(), ordinal.clone(), ordinal];
        return Ok(vm.call(&Value::Object(class), CallArgs::new(fields))?);
    }

    let ordinal = int_argument(vm, &ordinal)?;
    if ordinal < 1 {
        return Err(vm.raise(ExceptionKind::ValueError, "ordinal must be >= 1").into());
    }

    let date = CivilDate::from_ordinal(ordinal);
    let fields = [date.year, date.month, date.day].map(Value::Int).to_vec();

    Ok(vm.call(&Value::Object(class), CallArgs::new(fields))?)
}

/// `date.today()`: `cls.fromtimestamp(time.time())`.
fn date_today(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (class, args) = split_class(vm, args, DATE_TYPE, "today")?;
    no_arguments(vm, &args, "today")?;

    let now = current_time(vm)?;

    Ok(vm.call_method(&Value::Object(class), "fromtimestamp", vec![now])?)
}

/// `time.time()` through the `time` module.
pub(super) fn current_time(vm: &Vm) -> PyResult<Value> {
    let module = vm.import_module("time")?;

    vm.call_method(&module, "time", Vec::new())
}

/// The date `days` after `date`.
fn shift(vm: &Vm, date: CivilDate, days: i64) -> Outcome<Value> {
    let ordinal = date.ordinal() + days;
    if !(1..=MAX_ORDINAL).contains(&ordinal) {
        return Err(vm.raise(ExceptionKind::OverflowError, "date value out of range").into());
    }

    Ok(new_date(vm, CivilDate::from_ordinal(ordinal))?)
}

/// A date plus the days of a delta, in either order. Datetimes take no
/// part.
fn add(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    if is_datetime(left) || is_datetime(right) {
        return Ok(Value::NotImplemented);
    }
    let (date, delta) = match (date_fields(left), delta_data(left), date_fields(right), delta_data(right)) {
        (Some(date), _, _, Some(delta)) | (_, Some(delta), Some(date), _) => (date, delta),
        _ => return Ok(Value::NotImplemented),
    };

    shift(vm, date.get()?, delta.days)
}

/// A date less a date, giving a delta of days, or less the days of a
/// delta.
fn subtract(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    if is_datetime(left) || is_datetime(right) {
        return Ok(Value::NotImplemented);
    }
    let Some(date) = date_fields(left) else {
        return Ok(Value::NotImplemented);
    };

    if let Some(other) = date_fields(right) {
        let days = date.get()?.ordinal() - other.get()?.ordinal();
        return Ok(new_delta(vm, DeltaData { days, seconds: 0, microseconds: 0 })?);
    }
    let Some(delta) = delta_data(right) else {
        return Ok(Value::NotImplemented);
    };

    shift(vm, date.get()?, -delta.days)
}

fn date_repr(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, receiver, args } = receiver(vm, args, "__repr__")?;
    no_operands(vm, args, "__repr__")?;

    Ok(Value::str(&format!("{}({}, {}, {})", vm.type_name(&receiver), date.year, date.month, date.day)))
}

/// `str(date)`: `self.isoformat()`.
fn date_str(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, DATE_TYPE, "__str__", is_date)?;
    no_operands(vm, args, "__str__")?;

    Ok(vm.call_method(&receiver, "isoformat", Vec::new())?)
}

fn date_isoformat(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "isoformat")?;
    no_arguments(vm, &args, "isoformat")?;

    Ok(Value::str(&format::iso_date(date)))
}

fn date_ctime(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "ctime")?;
    no_arguments(vm, &args, "ctime")?;

    Ok(Value::str(&format::ctime(date, super::ClockTime::MIDNIGHT)))
}

/// The `format` argument of a `strftime` method.
pub(super) fn strftime_format(vm: &Vm, args: CallArgs) -> Outcome<PyBytes> {
    let values = parse(vm, args, "strftime", &["format"], 1)?;
    let Some(Some(format)) = values.into_iter().next() else {
        return Err(vm.type_error("strftime() format is missing").into());
    };

    let format = known(format)?;

    Ok(read_buffer(vm, "strftime", 1, &format)?)
}

/// `strftime(format)` of a date or datetime, formatting `self.timetuple()`.
fn date_strftime(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, DATE_TYPE, "strftime", is_date)?;
    let format = strftime_format(vm, args)?;

    let timetuple = vm.call_method(&receiver, "timetuple", Vec::new())?;
    let data = super::datetime_data(&receiver);
    let directives = match data {
        Some(data) => format::Directives { zone: ZoneContext { tzinfo: data.tzinfo.as_ref(), argument: &receiver }, microsecond: data.moment.get()?.clock.microsecond },
        None => format::Directives { zone: ZoneContext { tzinfo: None, argument: &Value::None }, microsecond: 0 },
    };

    format::strftime(vm, format.as_bytes(), &timetuple, directives)
}

/// The spec argument of a `__format__` method.
pub(super) fn format_spec(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [spec] = <[Value; 1]>::try_from(positional(vm, args, "__format__", 1, 1)?).map_err(|_| vm.type_error("__format__() takes exactly 1 argument"))?;

    Ok(spec)
}

fn date_format(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, DATE_TYPE, "__format__", is_date)?;
    let spec = format_spec(vm, args)?;

    format::format_method(vm, &receiver, &spec)
}

fn date_timetuple(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "timetuple")?;
    no_arguments(vm, &args, "timetuple")?;

    Ok(format::struct_time(vm, date, super::ClockTime::MIDNIGHT, -1)?)
}

fn date_isocalendar(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "isocalendar")?;
    no_arguments(vm, &args, "isocalendar")?;

    let iso = date.iso_calendar();

    Ok(Value::tuple(vec![vm.new_int_from_i64(iso.year), Value::Int(iso.week), Value::Int(iso.weekday)]))
}

fn date_isoweekday(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "isoweekday")?;
    no_arguments(vm, &args, "isoweekday")?;

    Ok(Value::Int(date.weekday() + 1))
}

fn date_toordinal(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "toordinal")?;
    no_arguments(vm, &args, "toordinal")?;

    Ok(vm.new_int_from_i64(date.ordinal()))
}

fn date_weekday(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "weekday")?;
    no_arguments(vm, &args, "weekday")?;

    Ok(Value::Int(date.weekday()))
}

fn date_compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> PyResult<Value> {
    finish(compare(vm, args, name, operation))
}

/// Dates, and datetimes as their dates, compare by their fields. Other
/// objects with a `timetuple` get to compare themselves.
fn compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> Outcome<Value> {
    let (receiver, args) = split_receiver(vm, args, DATE_TYPE, name, is_date)?;
    let other = known(operand(vm, args, name)?)?;

    if let Some(other) = date_fields(&other) {
        let date = receiver_date(vm, &receiver)?;
        return Ok(Value::Bool(operation.holds(date.cmp(&other.get()?))));
    }
    if has_attribute(vm, &other, "timetuple")? {
        return Ok(Value::NotImplemented);
    }

    match operation {
        CompareOp::Equal => Ok(Value::Bool(false)),
        CompareOp::NotEqual => Ok(Value::Bool(true)),
        _ => Err(compare_error(vm, &receiver, &other).into()),
    }
}

/// A date of the receiver's type with some fields replaced, built without
/// calling the type.
fn date_replace(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, receiver, args } = receiver(vm, args, "replace")?;

    let arguments = FieldArguments::parse(vm, args, "replace", &NAMES, 0, 3)?;
    let [year, month, day] = arguments.ints([date.year, date.month, date.day])?;
    let date = check_date(vm, year, month, day)?;

    Ok(new_date_of(vm, &vm.type_of(&receiver), Fields::Known(date)))
}

/// Hashes as the 1-tuple of the pickle state.
fn date_hash(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, args, .. } = receiver(vm, args, "__hash__")?;
    no_operands(vm, args, "__hash__")?;

    let width = vm.config.long_width;
    let state = hash_bytes(width, &date_state(date));

    Ok(hash_value(vm, hash_tuple(width, [state], 1)))
}

fn date_reduce(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DateCall { date, receiver, args } = receiver(vm, args, "__reduce__")?;
    no_arguments(vm, &args, "__reduce__")?;

    let state = Value::tuple(vec![Value::Str(PyBytes::new(date_state(date).to_vec()))]);

    Ok(Value::tuple(vec![Value::Object(vm.type_of(&receiver)), state]))
}
