//! Parsing and range checks of the integer fields constructors and
//! `replace` take.

use super::ClockTime;
use super::MAXYEAR;
use super::MINYEAR;
use super::Outcome;
use super::Stop;
use super::calendar::CivilDate;
use super::calendar::days_in_month;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::parse_with;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// One parsed argument.
#[derive(Clone)]
enum Slot {
    Int(i64),
    Unknown(Value),
    Object(Value),
}

/// Arguments bound to `names`: the leading ones C `int` fields, an
/// optional last one any object.
pub(super) struct FieldArguments {
    slots: Vec<Option<Slot>>,
}

impl FieldArguments {
    /// Binds `args` to `names`, converting the first `int_count` to C `int`
    /// values as they bind and keeping the rest as objects.
    pub(super) fn parse(vm: &Vm, args: CallArgs, function: &str, names: &[&str], required: usize, int_count: usize) -> PyResult<Self> {
        let slots = parse_with(vm, args, function, names, required, |vm, index, value| {
            if index >= int_count {
                return Ok(Slot::Object(value));
            }
            if value.is_unknown() {
                return Ok(Slot::Unknown(value));
            }

            int_argument(vm, &value).map(Slot::Int)
        })?;

        Ok(Self { slots })
    }

    /// The integer fields, with absent ones taken from `defaults`; stops on
    /// the first unknown one.
    pub(super) fn ints<const N: usize>(&self, defaults: [i64; N]) -> Outcome<[i64; N]> {
        let mut values = defaults;
        for (value, slot) in values.iter_mut().zip(&self.slots) {
            match slot {
                Some(Slot::Int(number)) => *value = *number,
                Some(Slot::Unknown(unknown)) => return Err(Stop::Unknown(unknown.clone())),
                Some(Slot::Object(_)) | None => {
                    // Absent fields keep their default.
                }
            }
        }

        Ok(values)
    }

    /// The first unknown integer field, if any.
    pub(super) fn first_unknown(&self) -> Option<Value> {
        self.slots.iter().find_map(|slot| match slot {
            Some(Slot::Unknown(value)) => Some(value.clone()),
            _ => None,
        })
    }

    /// The object argument at `index`, if given.
    pub(super) fn object(&self, index: usize) -> Option<Value> {
        match self.slots.get(index) {
            Some(Some(Slot::Object(value))) => Some(value.clone()),
            _ => None,
        }
    }
}

/// Range checks of a date's fields, in the order the client applies them.
pub(super) fn check_date(vm: &Vm, year: i64, month: i64, day: i64) -> PyResult<CivilDate> {
    if !(MINYEAR..=MAXYEAR).contains(&year) {
        return Err(vm.raise(ExceptionKind::ValueError, "year is out of range"));
    }
    if !(1..=12).contains(&month) {
        return Err(vm.raise(ExceptionKind::ValueError, "month must be in 1..12"));
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(vm.raise(ExceptionKind::ValueError, "day is out of range for month"));
    }

    Ok(CivilDate::new(year, month, day))
}

/// Range checks of a time of day's fields.
pub(super) fn check_clock(vm: &Vm, hour: i64, minute: i64, second: i64, microsecond: i64) -> PyResult<ClockTime> {
    if !(0..=23).contains(&hour) {
        return Err(vm.raise(ExceptionKind::ValueError, "hour must be in 0..23"));
    }
    if !(0..=59).contains(&minute) {
        return Err(vm.raise(ExceptionKind::ValueError, "minute must be in 0..59"));
    }
    if !(0..=59).contains(&second) {
        return Err(vm.raise(ExceptionKind::ValueError, "second must be in 0..59"));
    }
    if !(0..=999_999).contains(&microsecond) {
        return Err(vm.raise(ExceptionKind::ValueError, "microsecond must be in 0..999999"));
    }

    Ok(ClockTime { hour, minute, second, microsecond })
}

/// The bytes of a pickle state passed as the only positional argument, or
/// with one more for a `tzinfo`: a `str` of `length` bytes that `accepts`.
pub(super) fn pickle_state<'a>(vm: &Vm, args: &'a CallArgs, max_positional: usize, length: usize, accepts: fn(&[u8]) -> bool) -> Option<(Vec<u8>, Option<&'a Value>)> {
    let positional = &args.positional;
    if positional.is_empty() || positional.len() > max_positional {
        return None;
    }

    let bytes = vm.as_str_bytes(&positional[0])?;
    let bytes = bytes.as_bytes();
    if bytes.len() != length || !accepts(bytes) {
        return None;
    }

    Some((bytes.to_vec(), positional.get(1)))
}
