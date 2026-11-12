//! `timedelta`: a signed duration kept as normalized days, seconds, and
//! microseconds.

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use num_traits::Zero;

use super::BinarySlot;
use super::DELTA_TYPE;
use super::DeltaData;
use super::MAX_DELTA_DAYS;
use super::Outcome;
use super::Side;
use super::Stop;
use super::US_PER_DAY;
use super::US_PER_SECOND;
use super::binary;
use super::compare_error;
use super::comparison_methods;
use super::delta_data;
use super::delta_type;
use super::finish;
use super::hash_value;
use super::is_delta;
use super::new_delta;
use super::new_delta_of;
use super::no_arguments;
use super::no_operands;
use super::operand;
use super::split_receiver;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::numeric::float::float_to_integer;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::hash_int;
use crate::interp::hash::hash_tuple;
use crate::interp::numbers::Integral;
use crate::interp::numbers::true_divide;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A method call: the receiver's known fields, the receiver itself, and
/// the remaining arguments.
struct DeltaCall {
    delta: DeltaData,
    receiver: Value,
    args: CallArgs,
}

pub(super) fn create_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "timedelta",
            module: "datetime",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", |vm, args| finish(delta_new(vm, args))),
                method("__repr__", |vm, args| finish(delta_repr(vm, args))),
                method("__str__", |vm, args| finish(delta_str(vm, args))),
                method("__hash__", |vm, args| finish(delta_hash(vm, args))),
                method("__add__", |vm, args| binary(vm, args, slot("__add__", Side::Left), add)),
                method("__radd__", |vm, args| binary(vm, args, slot("__radd__", Side::Right), add)),
                method("__sub__", |vm, args| binary(vm, args, slot("__sub__", Side::Left), subtract)),
                method("__rsub__", |vm, args| binary(vm, args, slot("__rsub__", Side::Right), subtract)),
                method("__mul__", |vm, args| binary(vm, args, slot("__mul__", Side::Left), multiply)),
                method("__rmul__", |vm, args| binary(vm, args, slot("__rmul__", Side::Right), multiply)),
                method("__div__", |vm, args| binary(vm, args, slot("__div__", Side::Left), divide)),
                method("__rdiv__", |vm, args| binary(vm, args, slot("__rdiv__", Side::Right), divide)),
                method("__floordiv__", |vm, args| binary(vm, args, slot("__floordiv__", Side::Left), divide)),
                method("__rfloordiv__", |vm, args| binary(vm, args, slot("__rfloordiv__", Side::Right), divide)),
                method("__neg__", |vm, args| unary(vm, args, "__neg__", negate)),
                method("__pos__", |vm, args| unary(vm, args, "__pos__", Ok)),
                method("__abs__", |vm, args| unary(vm, args, "__abs__", absolute)),
                method("__nonzero__", |vm, args| finish(delta_nonzero(vm, args))),
                method("total_seconds", |vm, args| finish(delta_total_seconds(vm, args))),
                method("__reduce__", |vm, args| finish(delta_reduce(vm, args))),
            ],
        },
    )?;

    install(vm, &class, &comparison_methods!(delta_compare))?;
    for name in ["days", "seconds", "microseconds"] {
        add_member(vm, &class, GetSet { name, owner: DELTA_TYPE, get: member, set: None })?;
    }

    Ok(class)
}

/// A binary slot wrapper of this type.
const fn slot(name: &'static str, side: Side) -> BinarySlot {
    BinarySlot { owner: DELTA_TYPE, accepts: is_delta, name, side }
}

fn receiver(vm: &Vm, args: CallArgs, method: &str) -> Outcome<DeltaCall> {
    let (receiver, args) = split_receiver(vm, args, DELTA_TYPE, method, is_delta)?;
    let Some(delta) = delta_data(&receiver) else {
        return Err(vm.type_error("timedelta receiver lost its payload").into());
    };

    Ok(DeltaCall { delta, receiver, args })
}

fn member(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(delta) = delta_data(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    let field = match getset.name {
        "days" => delta.days,
        "seconds" => delta.seconds,
        _ => delta.microseconds,
    };

    Ok(Value::Int(field))
}

/// Raises the error for a result whose day count is out of range: an
/// overflow of C `long` first, then the magnitude limit.
pub(super) fn days_overflow(vm: &Vm, days: i128) -> Signal {
    let fits_long = i64::try_from(days).is_ok_and(|days| crate::interp::numbers::fits_int(vm.config.long_width, days));
    if !fits_long {
        return vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long");
    }

    vm.raise(ExceptionKind::OverflowError, &format!("days={days}; must have magnitude <= {MAX_DELTA_DAYS}"))
}

/// The delta of `total` microseconds, or the overflow error.
pub(super) fn delta_from_microseconds(vm: &Vm, total: i128) -> PyResult<DeltaData> {
    DeltaData::from_microseconds(total).map_err(|days| days_overflow(vm, days))
}

/// `delta_from_microseconds` for an arbitrarily large count.
fn delta_from_big(vm: &Vm, total: &BigInt) -> PyResult<DeltaData> {
    if let Some(total) = total.to_i128() {
        return delta_from_microseconds(vm, total);
    }

    // Far beyond the range: the day count does not fit any C long.
    Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))
}

/// `timedelta.__new__`: sums its components in microseconds. Integer parts
/// are exact; the fractional microseconds of float components accumulate
/// apart and are rounded half away from zero once.
fn delta_new(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    /// Constructor keywords in positional order.
    const KEYWORDS: [&str; 7] = ["days", "seconds", "microseconds", "milliseconds", "minutes", "hours", "weeks"];

    /// The order the constructor adds its components in, with each one's
    /// position in `KEYWORDS`, name, and length in microseconds.
    const COMPONENTS: [(usize, &str, i64); 7] = [
        (2, "microseconds", 1),
        (3, "milliseconds", 1_000),
        (1, "seconds", US_PER_SECOND),
        (4, "minutes", 60 * US_PER_SECOND),
        (5, "hours", 3_600 * US_PER_SECOND),
        (0, "days", US_PER_DAY),
        (6, "weeks", 7 * US_PER_DAY),
    ];

    let (class, args) = new_class(vm, args, &delta_type(vm)?)?;
    let values = parse(vm, args, "__new__", &KEYWORDS, 0)?;

    let mut total = BigInt::zero();
    let mut leftover = 0.0_f64;
    for (index, name, unit) in COMPONENTS {
        let Some(value) = &values[index] else {
            continue;
        };
        if value.is_unknown() {
            return Err(Stop::Unknown(value.clone()));
        }

        if let Some(integral) = vm.as_integral(value) {
            total += integral_to_big(integral) * unit;
            continue;
        }
        let Some(number) = vm.as_float(value) else {
            return Err(vm.type_error(&format!("unsupported type for timedelta {name} component: {}", vm.type_name(value))).into());
        };

        let whole = number.trunc();
        total += float_to_integer(vm, whole)? * unit;
        let fraction = number - whole;
        if fraction == 0.0 {
            continue;
        }

        let scaled = fraction * unit as f64;
        let scaled_whole = scaled.trunc();
        total += float_to_integer(vm, scaled_whole)?;
        leftover += scaled - scaled_whole;
    }
    total += BigInt::from(round_half_away(leftover));

    let delta = delta_from_big(vm, &total)?;

    Ok(new_delta_of(vm, &class, delta))
}

/// Rounds to the nearest integer, halves away from zero, as `floor(x +
/// 0.5)` for positive values and `ceil(x - 0.5)` for negative ones.
fn round_half_away(value: f64) -> i64 {
    let rounded = if value >= 0.0 { (value + 0.5).floor() } else { (value - 0.5).ceil() };

    // The leftover is the sum of at most seven fractions.
    rounded as i64
}

fn integral_to_big(integral: Integral) -> BigInt {
    match integral {
        Integral::Int(number) => BigInt::from(number),
        Integral::Long(number) => number,
    }
}

fn delta_repr(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, receiver, args } = receiver(vm, args, "__repr__")?;
    no_operands(vm, args, "__repr__")?;

    let fields = if delta.microseconds != 0 {
        format!("{}, {}, {}", delta.days, delta.seconds, delta.microseconds)
    } else if delta.seconds != 0 {
        format!("{}, {}", delta.days, delta.seconds)
    } else {
        format!("{}", delta.days)
    };

    Ok(Value::str(&format!("{}({fields})", vm.type_name(&receiver))))
}

fn delta_str(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, args, .. } = receiver(vm, args, "__str__")?;
    no_operands(vm, args, "__str__")?;

    let mut text = String::new();
    if delta.days != 0 {
        let plural = if delta.days.abs() == 1 { "" } else { "s" };
        text.push_str(&format!("{} day{plural}, ", delta.days));
    }
    text.push_str(&format!("{}:{:02}:{:02}", delta.seconds / 3600, delta.seconds / 60 % 60, delta.seconds % 60));
    if delta.microseconds != 0 {
        text.push_str(&format!(".{:06}", delta.microseconds));
    }

    Ok(Value::str(&text))
}

/// Hashes as the tuple `(days, seconds, microseconds)`.
fn delta_hash(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, args, .. } = receiver(vm, args, "__hash__")?;
    no_operands(vm, args, "__hash__")?;

    let width = vm.config.long_width;
    let hashes = [delta.days, delta.seconds, delta.microseconds].map(|field| hash_int(width, field));

    Ok(hash_value(vm, hash_tuple(width, hashes, 3)))
}

fn delta_compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> PyResult<Value> {
    finish(compare(vm, args, name, operation))
}

fn compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> Outcome<Value> {
    let DeltaCall { delta, receiver, args } = receiver(vm, args, name)?;
    let other = super::known(operand(vm, args, name)?)?;

    if let Some(other) = delta_data(&other) {
        return Ok(Value::Bool(operation.holds(delta.cmp(&other))));
    }

    match operation {
        CompareOp::Equal => Ok(Value::Bool(false)),
        CompareOp::NotEqual => Ok(Value::Bool(true)),
        _ => Err(compare_error(vm, &receiver, &other).into()),
    }
}

fn add(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    let (Some(left), Some(right)) = (delta_data(left), delta_data(right)) else {
        return Ok(Value::NotImplemented);
    };

    Ok(new_delta(vm, delta_from_microseconds(vm, left.microseconds_total() + right.microseconds_total())?)?)
}

fn subtract(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    let (Some(left), Some(right)) = (delta_data(left), delta_data(right)) else {
        return Ok(Value::NotImplemented);
    };

    Ok(new_delta(vm, delta_from_microseconds(vm, left.microseconds_total() - right.microseconds_total())?)?)
}

/// A delta times an int or long, in either order.
fn multiply(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    let (delta, factor) = match (delta_data(left), delta_data(right)) {
        (Some(delta), None) => (delta, right),
        (None, Some(delta)) => (delta, left),
        _ => return Ok(Value::NotImplemented),
    };
    let Some(factor) = vm.as_integral(factor) else {
        return Ok(Value::NotImplemented);
    };

    let total = BigInt::from(delta.microseconds_total()) * integral_to_big(factor);

    Ok(new_delta(vm, delta_from_big(vm, &total)?)?)
}

/// A delta floor-divided by an int or long. The division runs on Python
/// integers so that division by zero reports as the client's does.
fn divide(vm: &Vm, left: &Value, right: &Value) -> Outcome<Value> {
    let Some(delta) = delta_data(left) else {
        return Ok(Value::NotImplemented);
    };
    if vm.as_integral(right).is_none() {
        return Ok(Value::NotImplemented);
    }

    let total = vm.new_int(BigInt::from(delta.microseconds_total()));
    let quotient = super::known(vm.binary_op(BinaryOp::FloorDivide, &total, right)?)?;
    let Some(quotient) = vm.as_integral(&quotient) else {
        return Err(vm.type_error("timedelta division gave a non-integer").into());
    };

    Ok(new_delta(vm, delta_from_big(vm, &integral_to_big(quotient))?)?)
}

fn unary(vm: &Vm, args: CallArgs, name: &str, operator: fn(DeltaData) -> Result<DeltaData, i128>) -> PyResult<Value> {
    finish(unary_outcome(vm, args, name, operator))
}

fn unary_outcome(vm: &Vm, args: CallArgs, name: &str, operator: fn(DeltaData) -> Result<DeltaData, i128>) -> Outcome<Value> {
    let DeltaCall { delta, args, .. } = receiver(vm, args, name)?;
    no_operands(vm, args, name)?;

    let result = operator(delta).map_err(|days| days_overflow(vm, days))?;

    Ok(new_delta(vm, result)?)
}

fn negate(delta: DeltaData) -> Result<DeltaData, i128> {
    DeltaData::from_microseconds(-delta.microseconds_total())
}

fn absolute(delta: DeltaData) -> Result<DeltaData, i128> {
    if delta.days < 0 { negate(delta) } else { Ok(delta) }
}

fn delta_nonzero(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, args, .. } = receiver(vm, args, "__nonzero__")?;
    no_operands(vm, args, "__nonzero__")?;

    Ok(Value::Bool(delta != DeltaData { days: 0, seconds: 0, microseconds: 0 }))
}

/// The duration in seconds: the microsecond count divided by 10**6.
fn delta_total_seconds(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, args, .. } = receiver(vm, args, "total_seconds")?;
    no_arguments(vm, &args, "total_seconds")?;

    // The quotient of the two integers, correctly rounded.
    let total = BigInt::from(delta.microseconds_total());
    let Some(seconds) = true_divide(&total, &BigInt::from(US_PER_SECOND)) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "integer division result too large for a float").into());
    };

    Ok(Value::Float(seconds))
}

fn delta_reduce(vm: &Vm, args: CallArgs) -> Outcome<Value> {
    let DeltaCall { delta, receiver, args } = receiver(vm, args, "__reduce__")?;
    no_arguments(vm, &args, "__reduce__")?;

    let fields = Value::tuple(vec![Value::Int(delta.days), Value::Int(delta.seconds), Value::Int(delta.microseconds)]);

    Ok(Value::tuple(vec![Value::Object(vm.type_of(&receiver)), fields]))
}
