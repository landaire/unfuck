//! Calls into Python `tzinfo` objects and checks of what they return.

use std::rc::Rc;

use super::DeltaData;
use super::Outcome;
use super::delta_data;
use super::known;
use super::new_delta;
use super::tzinfo_type;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A `tzinfo` method that returns an offset from UTC.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OffsetMethod {
    UtcOffset,
    Dst,
}

impl OffsetMethod {
    fn name(self) -> &'static str {
        match self {
            Self::UtcOffset => "utcoffset",
            Self::Dst => "dst",
        }
    }
}

/// An offset from UTC in whole minutes, within -1439..=1439.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OffsetMinutes(pub(super) i64);

/// The `tzinfo` member of a time or datetime, and the argument its methods
/// get: `None` for a time, the datetime itself for a datetime.
#[derive(Clone, Copy)]
pub(super) struct ZoneContext<'a> {
    pub(super) tzinfo: Option<&'a Value>,
    pub(super) argument: &'a Value,
}

/// Offsets of two aware-or-naive operands, for comparison or subtraction.
pub(super) enum OffsetPair {
    /// Both naive, or sharing one `tzinfo` member: their fields compare
    /// directly.
    Naive,
    /// Both aware, with their offsets.
    Aware { left: OffsetMinutes, right: OffsetMinutes },
    /// One naive and one aware.
    Mixed,
}

/// Whether the type of `value` derives from `tzinfo`.
pub(super) fn is_tzinfo(vm: &Vm, value: &Value) -> PyResult<bool> {
    let Value::Object(_) = value else {
        return Ok(false);
    };

    vm.is_subclass(&vm.type_of(value), &tzinfo_type(vm)?)
}

/// A `tzinfo` constructor argument: `None`, or a `tzinfo` instance.
pub(super) fn tzinfo_argument(vm: &Vm, value: &Value) -> Outcome<Option<Value>> {
    let value = known(value.clone())?;
    if value.is_none() {
        return Ok(None);
    }
    if !is_tzinfo(vm, &value)? {
        return Err(vm.type_error(&format!("tzinfo argument must be None or of a tzinfo subclass, not type '{}'", vm.type_name(&value))).into());
    }

    Ok(Some(value))
}

/// The offset `tzinfo.<method>(argument)` returns; `None` when it returns
/// `None`.
pub(super) fn offset_minutes(vm: &Vm, tzinfo: &Value, method: OffsetMethod, argument: &Value) -> Outcome<Option<OffsetMinutes>> {
    let name = method.name();
    let result = known(vm.call_method(tzinfo, name, vec![argument.clone()])?)?;
    if result.is_none() {
        return Ok(None);
    }
    let Some(delta) = delta_data(&result) else {
        return Err(vm.type_error(&format!("tzinfo.{name}() must return None or timedelta, not '{}'", vm.type_name(&result))).into());
    };

    // Any day count other than -1 and 0 is reported as a full day.
    if delta.days != -1 && delta.days != 0 {
        return Err(out_of_range(vm, name, 1440).into());
    }
    if delta.seconds % 60 != 0 || delta.microseconds != 0 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("tzinfo.{name}() must return a whole number of minutes")).into());
    }
    let minutes = delta.days * 1440 + delta.seconds / 60;
    if minutes <= -1440 {
        return Err(out_of_range(vm, name, minutes).into());
    }

    Ok(Some(OffsetMinutes(minutes)))
}

fn out_of_range(vm: &Vm, name: &str, minutes: i64) -> crate::interp::error::Signal {
    vm.raise(ExceptionKind::ValueError, &format!("tzinfo.{name}() returned {minutes}; must be in -1439 .. 1439"))
}

/// The UTC offset of an aware value whose `tzinfo` member is `tzinfo`;
/// `None` without a member or when `utcoffset()` returns `None`.
pub(super) fn utc_offset(vm: &Vm, tzinfo: Option<&Value>, argument: &Value) -> Outcome<Option<OffsetMinutes>> {
    let Some(tzinfo) = tzinfo else {
        return Ok(None);
    };

    offset_minutes(vm, tzinfo, OffsetMethod::UtcOffset, argument)
}

/// The result of a `utcoffset()` or `dst()` method: `None`, or an exact
/// `timedelta` of the checked offset.
pub(super) fn offset_value(vm: &Vm, tzinfo: Option<&Value>, method: OffsetMethod, argument: &Value) -> Outcome<Value> {
    let Some(tzinfo) = tzinfo else {
        return Ok(Value::None);
    };
    let Some(OffsetMinutes(minutes)) = offset_minutes(vm, tzinfo, method, argument)? else {
        return Ok(Value::None);
    };

    let delta = DeltaData { days: minutes.div_euclid(1440), seconds: minutes.rem_euclid(1440) * 60, microseconds: 0 };

    Ok(new_delta(vm, delta)?)
}

/// The result of a `tzname()` method: `None` or a `str`.
pub(super) fn zone_name(vm: &Vm, tzinfo: Option<&Value>, argument: &Value) -> Outcome<Value> {
    let Some(tzinfo) = tzinfo else {
        return Ok(Value::None);
    };

    let name = known(vm.call_method(tzinfo, "tzname", vec![argument.clone()])?)?;
    if !name.is_none() && vm.as_str_bytes(&name).is_none() {
        return Err(vm.type_error(&format!("tzinfo.tzname() must return None or a string, not '{}'", vm.type_name(&name))).into());
    }

    Ok(name)
}

/// Whether two `tzinfo` members are the same object, or both absent.
pub(super) fn same_tzinfo(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(Value::Object(left)), Some(Value::Object(right))) => Rc::ptr_eq(left, right),
        _ => false,
    }
}

/// Classifies two operands by their `tzinfo` members and UTC offsets.
pub(super) fn offset_pair(vm: &Vm, left: ZoneContext<'_>, right: ZoneContext<'_>) -> Outcome<OffsetPair> {
    if same_tzinfo(left.tzinfo, right.tzinfo) {
        return Ok(OffsetPair::Naive);
    }

    let left_offset = utc_offset(vm, left.tzinfo, left.argument)?;
    let right_offset = utc_offset(vm, right.tzinfo, right.argument)?;
    let pair = match (left_offset, right_offset) {
        (None, None) => OffsetPair::Naive,
        (Some(left), Some(right)) => OffsetPair::Aware { left, right },
        _ => OffsetPair::Mixed,
    };

    Ok(pair)
}
