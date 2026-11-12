//! Text forms shared by the types: reprs, ISO 8601, `ctime`, `struct_time`,
//! and `strftime` with the `%z`, `%Z`, and `%f` directives the module adds.

use super::ClockTime;
use super::Outcome;
use super::calendar::CivilDate;
use super::known;
use super::zone::OffsetMinutes;
use super::zone::ZoneContext;
use super::zone::utc_offset;
use super::zone::zone_name;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// What `strftime` expands `%z`, `%Z`, and `%f` from.
pub(super) struct Directives<'a> {
    pub(super) zone: ZoneContext<'a>,
    pub(super) microsecond: i64,
}

/// `h, m[, s[, us]]` as a repr lists them.
pub(super) fn clock_arguments(clock: ClockTime) -> String {
    let mut text = format!("{}, {}", clock.hour, clock.minute);
    if clock.second != 0 || clock.microsecond != 0 {
        text.push_str(&format!(", {}", clock.second));
    }
    if clock.microsecond != 0 {
        text.push_str(&format!(", {}", clock.microsecond));
    }

    text
}

/// `prefix` and `, tzinfo=<repr>` when there is a member, then `)`.
pub(super) fn close_repr(vm: &Vm, prefix: String, tzinfo: Option<&Value>) -> Outcome<Value> {
    let mut bytes = prefix.into_bytes();
    if let Some(tzinfo) = tzinfo {
        let repr = known(vm.repr(tzinfo)?)?;
        let Some(repr) = vm.as_str_bytes(&repr) else {
            return Err(vm.type_error("__repr__ returned non-string").into());
        };
        bytes.extend_from_slice(b", tzinfo=");
        bytes.extend_from_slice(repr.as_bytes());
    }
    bytes.push(b')');

    Ok(Value::Str(PyBytes::new(bytes)))
}

pub(super) fn iso_date(date: CivilDate) -> String {
    format!("{:04}-{:02}-{:02}", date.year, date.month, date.day)
}

pub(super) fn iso_clock(clock: ClockTime) -> String {
    let mut text = format!("{:02}:{:02}:{:02}", clock.hour, clock.minute, clock.second);
    if clock.microsecond != 0 {
        text.push_str(&format!(".{:06}", clock.microsecond));
    }

    text
}

/// A UTC offset as a sign, two digits of hours, `separator`, and two
/// digits of minutes.
pub(super) fn offset_text(offset: OffsetMinutes, separator: &str) -> String {
    let OffsetMinutes(minutes) = offset;
    let sign = if minutes < 0 { '-' } else { '+' };
    let magnitude = minutes.abs();

    format!("{sign}{:02}{separator}{:02}", magnitude / 60, magnitude % 60)
}

/// The ISO offset suffix of an aware value; empty when naive.
pub(super) fn iso_offset(vm: &Vm, tzinfo: Option<&Value>, argument: &Value) -> Outcome<String> {
    let text = match utc_offset(vm, tzinfo, argument)? {
        Some(offset) => offset_text(offset, ":"),
        None => String::new(),
    };

    Ok(text)
}

/// `Www Mmm dd hh:mm:ss yyyy`. A weekday outside the week, as a day 0 date
/// of year 0 has, prints as the C runtime prints a null string.
pub(super) fn ctime(date: CivilDate, clock: ClockTime) -> String {
    const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTH_NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    let weekday = usize::try_from(date.weekday()).ok().and_then(|index| DAY_NAMES.get(index)).copied().unwrap_or("(null)");
    let month = usize::try_from(date.month - 1).ok().and_then(|index| MONTH_NAMES.get(index)).copied().unwrap_or("(null)");

    format!("{weekday} {month} {:>2} {:02}:{:02}:{:02} {:04}", date.day, clock.hour, clock.minute, clock.second, date.year)
}

/// `time.struct_time` of the fields, through the `time` module.
pub(super) fn struct_time(vm: &Vm, date: CivilDate, clock: ClockTime, is_dst: i64) -> PyResult<Value> {
    let module = vm.import_module("time")?;
    let class = vm.getattr_str(&module, "struct_time")?;
    let fields = [date.year, date.month, date.day, clock.hour, clock.minute, clock.second, date.weekday(), date.day_of_year(), is_dst];
    let tuple = Value::tuple(fields.iter().map(|field| vm.new_int_from_i64(*field)).collect());

    vm.call(&class, crate::interp::object::CallArgs::new(vec![tuple]))
}

/// Formats `timetuple` with `time.strftime` after expanding the directives
/// this module defines. A `timetuple` whose year is before 1900 is
/// rejected first.
pub(super) fn strftime(vm: &Vm, format: &[u8], timetuple: &Value, directives: Directives<'_>) -> Outcome<Value> {
    let timetuple = known(timetuple.clone())?;
    check_year(vm, &timetuple)?;

    let expanded = expand_directives(vm, format, &directives)?;

    let module = vm.import_module("time")?;
    let function = vm.getattr_str(&module, "strftime")?;

    Ok(vm.call(&function, crate::interp::object::CallArgs::new(vec![Value::Str(PyBytes::new(expanded)), timetuple]))?)
}

/// Rejects a `timetuple` whose first item is not an int of at least 1900;
/// an item that is no int reports as year -1.
fn check_year(vm: &Vm, timetuple: &Value) -> Outcome<()> {
    let item = known(vm.getitem(timetuple, &Value::Int(0))?)?;
    let year = match int_argument(vm, &item) {
        Ok(year) => year,
        Err(Signal::Raise(_)) => -1,
        Err(halt) => return Err(halt.into()),
    };
    if year < 1900 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("year={year} is before 1900; the datetime strftime() methods require year >= 1900")).into());
    }

    Ok(())
}

/// Copies `format` up to its first NUL with `%z`, `%Z`, and `%f` replaced.
/// Each zone method is called once, at the first directive that needs it.
fn expand_directives(vm: &Vm, format: &[u8], directives: &Directives<'_>) -> Outcome<Vec<u8>> {
    let end = format.iter().position(|byte| *byte == 0).unwrap_or(format.len());
    let format = &format[..end];

    let mut offset: Option<Vec<u8>> = None;
    let mut name: Option<Vec<u8>> = None;
    let mut expanded = Vec::with_capacity(format.len());
    let mut index = 0;
    while index < format.len() {
        let byte = format[index];
        index += 1;
        if byte != b'%' {
            expanded.push(byte);
            continue;
        }

        let Some(&directive) = format.get(index) else {
            return Err(vm.raise(ExceptionKind::ValueError, "strftime format ends with raw %").into());
        };
        index += 1;
        match directive {
            b'z' => {
                if offset.is_none() {
                    offset = Some(offset_replacement(vm, directives)?);
                }
                expanded.extend_from_slice(offset.as_deref().unwrap_or_default());
            }
            b'Z' => {
                if name.is_none() {
                    name = Some(name_replacement(vm, directives)?);
                }
                expanded.extend_from_slice(name.as_deref().unwrap_or_default());
            }
            b'f' => expanded.extend_from_slice(format!("{:06}", directives.microsecond).as_bytes()),
            other => expanded.extend_from_slice(&[b'%', other]),
        }
    }

    Ok(expanded)
}

/// `%z`: `+HHMM`, or nothing for a naive value.
fn offset_replacement(vm: &Vm, directives: &Directives<'_>) -> Outcome<Vec<u8>> {
    let ZoneContext { tzinfo, argument } = directives.zone;
    let text = match utc_offset(vm, tzinfo, argument)? {
        Some(offset) => offset_text(offset, ""),
        None => String::new(),
    };

    Ok(text.into_bytes())
}

/// `%Z`: the zone name with each `%` doubled, or nothing.
fn name_replacement(vm: &Vm, directives: &Directives<'_>) -> Outcome<Vec<u8>> {
    let ZoneContext { tzinfo, argument } = directives.zone;
    let name = zone_name(vm, tzinfo, argument)?;
    let Some(bytes) = vm.as_str_bytes(&name) else {
        return Ok(Vec::new());
    };

    let mut replacement = Vec::with_capacity(bytes.as_bytes().len());
    for byte in bytes.as_bytes() {
        if *byte == b'%' {
            replacement.push(b'%');
        }
        replacement.push(*byte);
    }

    Ok(replacement)
}

/// `__format__`: `str(self)` or `unicode(self)` for an empty spec of that
/// type, else `self.strftime(spec)`.
pub(super) fn format_method(vm: &Vm, receiver: &Value, spec: &Value) -> Outcome<Value> {
    let spec = known(spec.clone())?;
    let is_empty = if let Some(bytes) = vm.as_str_bytes(&spec) {
        bytes.as_bytes().is_empty()
    } else if let Some(text) = vm.as_text(&spec) {
        if text.units().is_empty() {
            return Ok(vm.to_unicode(receiver)?);
        }
        false
    } else {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("__format__ expects str or unicode, not {}", vm.type_name(&spec))).into());
    };
    if is_empty {
        return Ok(vm.to_str(receiver)?);
    }

    Ok(vm.call_method(receiver, "strftime", vec![spec])?)
}
