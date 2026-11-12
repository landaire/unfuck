//! The `time` module of the Windows build. Clock readings and conversions
//! through the host time zone are unknown values; UTC conversions and
//! formatting of explicit tuples are exact.

use std::cell::RefCell;

use num_traits::ToPrimitive;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_struct_sequence_type;
use crate::interp::builtins::modules::new_struct_sequence;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const STRUCT_TIME_FIELDS: [&str; 9] = [
    "tm_year", "tm_mon", "tm_mday", "tm_hour", "tm_min", "tm_sec", "tm_wday", "tm_yday", "tm_isdst",
];

/// `_MAX__TIME64_T` of the CRT: 3000-12-31 23:59:59 UTC.
const MAX_TIME64: i64 = 32_535_244_799;

/// The module dict, from which `accept2dyear` is read on each call.
#[derive(Default)]
struct TimeState {
    module_dict: RefCell<Option<ObjectRef>>,
}

/// A broken-down time (`struct tm`) with C field conventions.
struct BrokenDownTime {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
    weekday: i32,
    yearday: i32,
    isdst: i32,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("time", time_time),
            function("clock", time_clock),
            function("sleep", time_sleep),
            function("gmtime", time_gmtime),
            function("localtime", time_localtime),
            function("asctime", time_asctime),
            function("ctime", time_ctime),
            function("mktime", time_mktime),
            function("strftime", time_strftime),
            function("strptime", time_strptime),
        ],
    )?;

    // PYTHONY2K is not set in the game process.
    set_attribute(vm, module, "accept2dyear", Value::Int(1))?;
    match &vm.config.host.time_zone {
        Some(zone) => {
            set_attribute(vm, module, "timezone", Value::Int(i64::from(zone.timezone)))?;
            set_attribute(vm, module, "altzone", Value::Int(i64::from(zone.timezone) - 3600))?;
            set_attribute(vm, module, "daylight", Value::Int(i64::from(zone.daylight)))?;
            let [standard, daylight] = &zone.tzname;
            let names = vec![Value::Str(PyBytes::new(standard.clone())), Value::Str(PyBytes::new(daylight.clone()))];
            set_attribute(vm, module, "tzname", Value::tuple(names))?;
        }
        None => {
            for name in ["timezone", "altzone", "daylight", "tzname"] {
                set_attribute(vm, module, name, Value::unknown(format!("time.{name} (host time zone)")))?;
            }
        }
    }
    set_attribute(
        vm,
        module,
        "struct_time",
        Value::Object(struct_time_type(vm)?),
    )?;

    *vm.native_state::<TimeState>().module_dict.borrow_mut() = Some(vm.instance_dict(module)?);

    Ok(())
}

fn struct_time_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "time.struct_time", |vm| {
        new_struct_sequence_type(vm, "time", "struct_time", &STRUCT_TIME_FIELDS)
    })
}

/// Rejects any argument to a no-argument function.
pub(super) fn no_arguments(vm: &Vm, args: &CallArgs, function: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }
    if !args.positional.is_empty() {
        return Err(vm.type_error(&format!(
            "{function}() takes no arguments ({} given)",
            args.positional.len()
        )));
    }

    Ok(())
}

/// A C `int` argument (format `i`); `None` when unknown.
pub(super) fn c_int(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let Some(integral) = vm.as_integral(value) else {
        return Err(vm.type_error("an integer is required"));
    };
    let (low, high) = numbers::int_bounds(vm.config.long_width);
    let long = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    let Some(long) = long.filter(|number| (low..=high).contains(number)) else {
        return Err(vm.raise(
            ExceptionKind::OverflowError,
            "Python int too large to convert to C long",
        ));
    };

    match i32::try_from(long) {
        Ok(number) => Ok(Some(number)),
        Err(_) if long > 0 => Err(vm.raise(
            ExceptionKind::OverflowError,
            "signed integer is greater than maximum",
        )),
        Err(_) => Err(vm.raise(
            ExceptionKind::OverflowError,
            "signed integer is less than minimum",
        )),
    }
}

/// The `"name() "` prefix argument parsing puts before argument errors;
/// empty for formats without a function name.
pub(super) fn argument_prefix(function: Option<&str>) -> String {
    function
        .map(|name| format!("{name}() "))
        .unwrap_or_default()
}

/// The type name an argument conversion error reports.
pub(super) fn converted_type_name(vm: &Vm, value: &Value) -> String {
    if value.is_none() {
        "None".to_owned()
    } else {
        vm.type_name(value)
    }
}

/// A `char*` argument (format `s`); `None` when unknown. `function` is the
/// name in the format, if it has one.
pub(super) fn c_string(
    vm: &Vm,
    value: &Value,
    function: Option<&str>,
    position: usize,
) -> PyResult<Option<PyBytes>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let prefix = argument_prefix(function);
    let bytes = match (vm.as_str_bytes(value), vm.as_text(value)) {
        (Some(bytes), _) => bytes,
        (None, Some(text)) => {
            let Some(ascii) = text
                .units()
                .iter()
                .map(|unit| u8::try_from(*unit).ok().filter(u8::is_ascii))
                .collect::<Option<Vec<u8>>>()
            else {
                return Err(vm.halt_unsupported(format!(
                    "{prefix}argument {position} as non-ASCII unicode"
                )));
            };
            PyBytes::new(ascii)
        }
        (None, None) => {
            return Err(vm.type_error(&format!(
                "{prefix}argument {position} must be string, not {}",
                converted_type_name(vm, value)
            )));
        }
    };
    if bytes.as_bytes().contains(&0) {
        return Err(vm.type_error(&format!(
            "{prefix}argument {position} must be string without null bytes, not {}",
            vm.type_name(value)
        )));
    }

    Ok(Some(bytes))
}

/// Float conversion; `None` when the argument is unknown.
pub(super) fn c_double(vm: &Vm, value: &Value) -> PyResult<Option<f64>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if let Some(number) = vm.as_float(value) {
        return Ok(Some(number));
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => return Ok(Some(number as f64)),
        Some(Integral::Long(number)) => {
            return numbers::bigint_to_f64(&number).map(Some).ok_or_else(|| {
                vm.raise(
                    ExceptionKind::OverflowError,
                    "long int too large to convert to float",
                )
            });
        }
        None => {}
    }

    let Some(convert) = vm.lookup_special(value, "__float__")? else {
        if vm.as_complex(value).is_some() {
            return Err(vm.type_error("can't convert complex to float"));
        }
        return Err(vm.type_error("a float is required"));
    };
    let result = vm.call0(&convert)?;
    if result.is_unknown() {
        return Ok(None);
    }

    vm.as_float(&result)
        .map(Some)
        .ok_or_else(|| vm.type_error("nb_float should return float object"))
}

/// Converts a float to the 64-bit `time_t` of the Windows build.
pub(super) fn double_to_time_t(vm: &Vm, when: f64) -> PyResult<i64> {
    // A NaN converts to the minimum value without tripping the range check.
    if when.is_nan() {
        return Ok(i64::MIN);
    }

    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    if !(-LIMIT..LIMIT).contains(&when) {
        return Err(vm.raise(
            ExceptionKind::ValueError,
            "timestamp out of range for platform time_t",
        ));
    }

    Ok(when.trunc() as i64)
}

/// The UTC calendar fields of a timestamp the CRT `gmtime` accepts.
fn utc_time(vm: &Vm, seconds: i64) -> PyResult<BrokenDownTime> {
    // The CRT rejects other values through its invalid parameter handler or
    // with results that were not verified against the Windows build.
    if !(0..=MAX_TIME64).contains(&seconds) {
        return Err(vm.halt_unsupported(format!("time.gmtime({seconds}) outside the CRT range")));
    }

    let days = seconds / 86_400;
    let of_day = seconds % 86_400;

    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year_march = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year_march + 2) / 153;
    let day = day_of_year_march - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let cumulative = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let month_start = cumulative.get((month - 1) as usize).copied().unwrap_or(0);
    let yearday = month_start + day - 1 + i64::from(leap && month > 2);

    Ok(BrokenDownTime {
        year: (year - 1900) as i32,
        month: (month - 1) as i32,
        day: day as i32,
        hour: (of_day / 3600) as i32,
        minute: (of_day % 3600 / 60) as i32,
        second: (of_day % 60) as i32,
        weekday: ((days + 4) % 7) as i32,
        yearday: yearday as i32,
        isdst: 0,
    })
}

/// A `struct_time` from broken-down time.
fn struct_time(vm: &Vm, time: &BrokenDownTime) -> PyResult<Value> {
    let class = struct_time_type(vm)?;
    let fields = [
        time.year + 1900,
        time.month + 1,
        time.day,
        time.hour,
        time.minute,
        time.second,
        (time.weekday + 6) % 7,
        time.yearday + 1,
        time.isdst,
    ];

    Ok(new_struct_sequence(
        vm,
        &class,
        fields
            .into_iter()
            .map(|field| Value::Int(i64::from(field)))
            .collect(),
    ))
}

/// The optional seconds argument of `gmtime`, `localtime`, and `ctime`;
/// `None` when it is absent, `None`, or unknown.
fn optional_seconds(vm: &Vm, argument: Option<&Value>) -> PyResult<Option<f64>> {
    match argument {
        None | Some(Value::None) => Ok(None),
        Some(value) => c_double(vm, value),
    }
}

/// Whether a `secs` argument of `None` or absent reads the current time.
fn reads_clock(argument: Option<&Value>) -> bool {
    matches!(argument, None | Some(Value::None))
}

/// A time tuple argument; `None` when a field is unknown.
fn time_argument(vm: &Vm, tuple: &Value) -> PyResult<Option<BrokenDownTime>> {
    if tuple.is_unknown() {
        return Ok(None);
    }

    let items = match vm.as_tuple(tuple) {
        Some(items) => items.to_vec(),
        None => match vm.as_list(tuple) {
            Some(items) => items,
            None => {
                return Err(vm.type_error(&format!(
                    "argument must be 9-item sequence, not {}",
                    vm.type_name(tuple)
                )));
            }
        },
    };
    if items.len() != 9 {
        return Err(vm.type_error(&format!(
            "argument must be sequence of length 9, not {}",
            items.len()
        )));
    }

    let mut fields = [0i32; 9];
    let mut unknown = false;
    for (slot, item) in fields.iter_mut().zip(&items) {
        match c_int(vm, item)? {
            Some(number) => *slot = number,
            None => unknown = true,
        }
    }
    if unknown {
        return Ok(None);
    }

    let [
        mut year,
        month,
        day,
        hour,
        minute,
        second,
        weekday,
        yearday,
        isdst,
    ] = fields;
    if year < 1900 {
        let accept = accept2dyear(vm)?;
        let Some(accept) = accept else {
            return Ok(None);
        };
        if !accept {
            return Err(vm.raise(ExceptionKind::ValueError, "year >= 1900 required"));
        }
        year = match year {
            69..=99 => year + 1900,
            0..=68 => year + 2000,
            _ => return Err(vm.raise(ExceptionKind::ValueError, "year out of range")),
        };
    }

    Ok(Some(BrokenDownTime {
        year: year - 1900,
        month: month.wrapping_sub(1),
        day,
        hour,
        minute,
        second,
        weekday: weekday.wrapping_add(1) % 7,
        yearday: yearday.wrapping_sub(1),
        isdst,
    }))
}

/// Whether `accept2dyear` in the module dict is a nonzero `int`; `None`
/// when it is unknown.
fn accept2dyear(vm: &Vm) -> PyResult<Option<bool>> {
    let state = vm.native_state::<TimeState>();
    let dict = state.module_dict.borrow().clone();
    let Some(dict) = dict else {
        return Ok(Some(false));
    };

    let value = vm.dict_get_str(&dict, "accept2dyear")?;
    let flag = match value {
        Some(Value::Unknown(_)) => return Ok(None),
        Some(Value::Int(number)) => number != 0,
        Some(Value::Bool(flag)) => flag,
        Some(Value::Object(object)) => match &object.payload {
            Payload::Int(number) => *number != 0,
            _ => false,
        },
        _ => false,
    };

    Ok(Some(flag))
}

/// The range checks of a time tuple.
fn check_time(vm: &Vm, time: &mut BrokenDownTime) -> PyResult<()> {
    let error = |message: &str| Err(vm.raise(ExceptionKind::ValueError, message));

    if time.month == -1 {
        time.month = 0;
    } else if !(0..=11).contains(&time.month) {
        return error("month out of range");
    }
    if time.day == 0 {
        time.day = 1;
    } else if !(0..=31).contains(&time.day) {
        return error("day of month out of range");
    }
    if !(0..=23).contains(&time.hour) {
        return error("hour out of range");
    }
    if !(0..=59).contains(&time.minute) {
        return error("minute out of range");
    }
    if !(0..=61).contains(&time.second) {
        return error("seconds out of range");
    }
    if time.weekday < 0 {
        return error("day of week out of range");
    }
    if time.yearday == -1 {
        time.yearday = 0;
    } else if !(0..=365).contains(&time.yearday) {
        return error("day of year out of range");
    }

    Ok(())
}

/// The CRT's `asctime`, `None` when a field is out of its range. Day 0 is
/// in range and a day past the end of the month is not. The thousands of
/// the year print as one character, `'0'` plus their count modulo 256.
fn format_asctime(time: &BrokenDownTime) -> Option<Value> {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const MONTH_DAYS: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let year = 1900 + i64::from(time.year);
    let weekday = WEEKDAYS.get(usize::try_from(time.weekday).ok()?)?;
    let month_index = usize::try_from(time.month).ok()?;
    let month = MONTHS.get(month_index)?;
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = MONTH_DAYS[month_index] + i32::from(month_index == 1 && is_leap);
    if time.year < 0
        || !(0..=month_days).contains(&time.day)
        || !(0..=23).contains(&time.hour)
        || !(0..=59).contains(&time.minute)
        || !(0..=59).contains(&time.second)
    {
        return None;
    }

    let BrokenDownTime { day, hour, minute, second, .. } = time;
    let mut text = format!("{weekday} {month} {day:02} {hour:02}:{minute:02}:{second:02} ").into_bytes();
    text.push(b'0'.wrapping_add((year / 1000) as u8));
    text.extend_from_slice(format!("{:03}", year % 1000).as_bytes());

    Some(Value::Str(PyBytes::new(text)))
}

/// At most one positional argument, with count errors naming `name`.
fn unpack_optional(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Option<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }
    if args.positional.len() > 1 {
        return Err(vm.type_error(&format!(
            "{function} expected at most 1 arguments, got {}",
            args.positional.len()
        )));
    }

    Ok(args.positional.into_iter().next())
}

fn time_time(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "time")?;

    vm.host_operation(HostCapability::Clock, "time.time()")
}

fn time_clock(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "clock")?;

    vm.host_operation(HostCapability::Clock, "time.clock()")
}

/// `time.sleep`: the delay itself has no observable effect.
fn time_sleep(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "sleep", 1, 1)?;
    if let Some(seconds) = c_double(vm, &args[0])? {
        if seconds * 1000.0 > f64::from(u32::MAX) {
            return Err(vm.raise(ExceptionKind::OverflowError, "sleep length is too large"));
        }
    }
    vm.host_permit(HostCapability::Clock, Denial::Native, None)?;

    Ok(Value::None)
}

fn time_gmtime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "gmtime", 0, 1)?;
    if reads_clock(args.first()) {
        return vm.host_operation(HostCapability::Clock, "time.gmtime() of the current time");
    }
    let Some(when) = optional_seconds(vm, args.first())? else {
        return Ok(Value::unknown("time.gmtime() of an unknown time"));
    };

    let seconds = double_to_time_t(vm, when)?;
    let time = utc_time(vm, seconds)?;

    struct_time(vm, &time)
}

fn time_localtime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "localtime", 0, 1)?;
    if reads_clock(args.first()) {
        vm.host_permit(HostCapability::Clock, Denial::Native, None)?;
    }
    if let Some(when) = optional_seconds(vm, args.first())? {
        double_to_time_t(vm, when)?;
    }

    Ok(Value::unknown("time.localtime() (host time zone)"))
}

fn time_asctime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(tuple) = unpack_optional(vm, args, "asctime")? else {
        return vm.host_operation(HostCapability::Clock, "time.asctime() of the current time");
    };

    match time_argument(vm, &tuple)? {
        Some(time) => format_asctime(&time).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "invalid time")),
        None => Ok(Value::unknown("time.asctime() of an unknown time")),
    }
}

fn time_ctime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = unpack_optional(vm, args, "ctime")?;
    if reads_clock(argument.as_ref()) {
        vm.host_permit(HostCapability::Clock, Denial::Native, None)?;
    }
    if let Some(when) = optional_seconds(vm, argument.as_ref())? {
        double_to_time_t(vm, when)?;
    }

    Ok(Value::unknown("time.ctime() (host time zone)"))
}

/// `time.mktime`: the tuple is converted but not range
/// checked, since `mktime` normalizes it.
fn time_mktime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("mktime() takes no keyword arguments"));
    }
    let [tuple] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!(
            "mktime() takes exactly one argument ({} given)",
            args.positional.len()
        )));
    };

    time_argument(vm, tuple)?;

    Ok(Value::unknown("time.mktime() (host time zone)"))
}

/// `time.strftime`: the C runtime's `strftime` in the C locale. The current
/// time, another `LC_TIME` locale, and the zone names `%Z` and `%z` print
/// without host facts are unknown.
fn time_strftime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.positional.is_empty() && !args.has_keywords() {
        return Err(vm.type_error("strftime() takes at least 1 argument (0 given)"));
    }
    let args = positional(vm, args, "strftime", 1, 2)?;
    let format = c_string(vm, &args[0], Some("strftime"), 1)?;

    let time = match args.get(1) {
        Some(tuple) => match time_argument(vm, tuple)? {
            Some(mut time) => {
                check_time(vm, &mut time)?;
                // Normalized in case a `%Z` implementation indexes by it.
                time.isdst = time.isdst.clamp(-1, 1);
                Some(time)
            }
            None => None,
        },
        None => None,
    };
    let permit_clock = || match args.get(1) {
        Some(_) => Ok(()),
        None => vm.host_permit(HostCapability::Clock, Denial::Native, None),
    };

    let Some(format) = format else {
        permit_clock()?;
        return Ok(Value::unknown("time.strftime() of an unknown format"));
    };
    check_strftime_directives(vm, format.as_bytes())?;
    permit_clock()?;

    let Some(time) = time else {
        return Ok(Value::unknown("time.strftime() of the current or an unknown time"));
    };
    if !super::locale::time_is_c(vm) {
        return Ok(Value::unknown("time.strftime() (host LC_TIME locale)"));
    }

    format_time(vm, format.as_bytes(), &time)
}

/// `_Strftime_l` of the Visual C++ 2008 runtime with the C locale's
/// `__lc_time_data`. A `#` flag drops leading zeros of numbers and selects
/// the long date of `%c` and `%x`.
fn format_time(vm: &Vm, format: &[u8], time: &BrokenDownTime) -> PyResult<Value> {
    let mut output = Vec::with_capacity(format.len());
    let mut position = 0;
    while let Some(&byte) = format.get(position) {
        position += 1;
        if byte != b'%' {
            output.push(byte);
            continue;
        }

        let alternate = format.get(position) == Some(&b'#');
        if alternate {
            position += 1;
        }
        // The directive check ensures a conversion follows.
        let Some(&specifier) = format.get(position) else {
            return Err(vm.raise(ExceptionKind::ValueError, "Invalid format string"));
        };
        position += 1;

        if expand_time(vm, specifier, alternate, time, &mut output)?.is_none() {
            return Ok(Value::unknown("time.strftime() time zone name (host time zone)"));
        }
    }

    Ok(Value::Str(PyBytes::new(output)))
}

/// The CRT's `_VALIDATE_RETURN` failing in `_expandtime`: the default
/// invalid parameter handler of the release runtime terminates the process.
fn invalid_parameter(vm: &Vm, specifier: u8) -> Signal {
    vm.halt_unsupported(format!("strftime %{} of an out-of-range field (the CRT terminates the process)", char::from(specifier)))
}

/// `_expandtime` for one conversion. `None` when it prints a host time
/// zone name that is unknown.
fn expand_time(vm: &Vm, specifier: u8, alternate: bool, time: &BrokenDownTime, output: &mut Vec<u8>) -> PyResult<Option<()>> {
    const WEEKDAYS_ABBR: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const WEEKDAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const MONTHS_ABBR: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

    let name = |names: &[&'static str], index: i32| usize::try_from(index).ok().and_then(|index| names.get(index).copied());
    let check = |valid: bool| if valid { Ok(()) } else { Err(invalid_parameter(vm, specifier)) };
    let weekday_valid = (0..=6).contains(&time.weekday);
    let hour_valid = (0..=23).contains(&time.hour);
    let yearday_valid = (0..=365).contains(&time.yearday);

    match specifier {
        b'a' | b'A' | b'b' | b'B' => {
            let (names, index): (&[&str], i32) = match specifier {
                b'a' => (&WEEKDAYS_ABBR, time.weekday),
                b'A' => (&WEEKDAYS, time.weekday),
                b'b' => (&MONTHS_ABBR, time.month),
                _ => (&MONTHS, time.month),
            };
            let Some(text) = name(names, index) else {
                return Err(invalid_parameter(vm, specifier));
            };
            output.extend_from_slice(text.as_bytes());
        }
        b'c' => {
            if alternate {
                store_long_date(vm, time, output)?;
            } else {
                store_short_date(vm, time, output)?;
            }
            output.push(b' ');
            store_time_of_day(vm, time, output)?;
        }
        b'x' => {
            if alternate {
                store_long_date(vm, time, output)?;
            } else {
                store_short_date(vm, time, output)?;
            }
        }
        b'X' => store_time_of_day(vm, time, output)?,
        b'd' => {
            check((1..=31).contains(&time.day))?;
            store_number(time.day, 2, alternate, output);
        }
        b'H' => {
            check(hour_valid)?;
            store_number(time.hour, 2, alternate, output);
        }
        b'I' => {
            check(hour_valid)?;
            let hour = match time.hour % 12 {
                0 => 12,
                hour => hour,
            };
            store_number(hour, 2, alternate, output);
        }
        b'j' => {
            check(yearday_valid)?;
            store_number(time.yearday + 1, 3, alternate, output);
        }
        b'm' => {
            check((0..=11).contains(&time.month))?;
            store_number(time.month + 1, 2, alternate, output);
        }
        b'M' => {
            check((0..=59).contains(&time.minute))?;
            store_number(time.minute, 2, alternate, output);
        }
        b'p' => {
            check(hour_valid)?;
            output.extend_from_slice(if time.hour <= 11 { b"AM" } else { b"PM" });
        }
        b'S' => {
            check((0..=59).contains(&time.second))?;
            store_number(time.second, 2, alternate, output);
        }
        b'U' | b'W' => {
            check(weekday_valid)?;
            let start = match specifier {
                b'U' => time.weekday,
                _ if time.weekday == 0 => 6,
                _ => time.weekday - 1,
            };
            check(yearday_valid)?;
            let week = if time.yearday < start { 0 } else { (time.yearday - start) / 7 + 1 };
            store_number(week, 2, alternate, output);
        }
        b'w' => {
            check(weekday_valid)?;
            store_number(time.weekday, 1, alternate, output);
        }
        b'y' => {
            check(time.year >= 0)?;
            store_number(time.year % 100, 2, alternate, output);
        }
        b'Y' => {
            check((-1900..=8099).contains(&time.year))?;
            store_number((time.year / 100 + 19) * 100 + time.year % 100, 4, alternate, output);
        }
        b'Z' | b'z' => {
            let Some(zone) = &vm.config.host.time_zone else {
                return Ok(None);
            };
            let [standard, daylight] = &zone.tzname;
            output.extend_from_slice(if time.isdst != 0 { daylight } else { standard });
        }
        b'%' => output.push(b'%'),
        _ => return Err(vm.raise(ExceptionKind::ValueError, "Invalid format string")),
    }

    Ok(Some(()))
}

/// `_store_num`: `digits` digits with leading zeros, or `_store_number`'s
/// shortest form under the `#` flag.
fn store_number(number: i32, digits: usize, alternate: bool, output: &mut Vec<u8>) {
    let text = if alternate { format!("{number}") } else { format!("{number:0digits$}") };

    output.extend_from_slice(text.as_bytes());
}

/// `_store_winword(WW_SDATEFMT)` of the C locale: `MM/dd/yy`.
fn store_short_date(vm: &Vm, time: &BrokenDownTime, output: &mut Vec<u8>) -> PyResult<()> {
    for (index, specifier) in b"mdy".iter().copied().enumerate() {
        if index > 0 {
            output.push(b'/');
        }
        expand_time(vm, specifier, false, time, output)?;
    }

    Ok(())
}

/// `_store_winword(WW_LDATEFMT)` of the C locale: `dddd, MMMM dd, yyyy`.
fn store_long_date(vm: &Vm, time: &BrokenDownTime, output: &mut Vec<u8>) -> PyResult<()> {
    expand_time(vm, b'A', false, time, output)?;
    output.extend_from_slice(b", ");
    expand_time(vm, b'B', false, time, output)?;
    output.push(b' ');
    expand_time(vm, b'd', false, time, output)?;
    output.extend_from_slice(b", ");
    expand_time(vm, b'Y', false, time, output)?;

    Ok(())
}

/// `_store_winword(WW_TIMEFMT)` of the C locale: `HH:mm:ss`.
fn store_time_of_day(vm: &Vm, time: &BrokenDownTime, output: &mut Vec<u8>) -> PyResult<()> {
    for (index, specifier) in b"HMS".iter().copied().enumerate() {
        if index > 0 {
            output.push(b':');
        }
        expand_time(vm, specifier, false, time, output)?;
    }

    Ok(())
}

/// The Windows directive check of `time.strftime`: every `%` (optionally
/// followed by `#`) must introduce a directive the CRT supports.
fn check_strftime_directives(vm: &Vm, format: &[u8]) -> PyResult<()> {
    const DIRECTIVES: &[u8] = b"aAbBcdHIjmMpSUwWxXyYzZ%";

    let find = |start: usize| {
        format
            .get(start..)
            .and_then(|rest| rest.iter().position(|byte| *byte == b'%'))
            .map(|offset| start + offset)
    };
    let mut next = find(0);
    while let Some(mut position) = next {
        if format.get(position + 1) == Some(&b'#') {
            position += 1;
        }
        match format.get(position + 1) {
            Some(directive) if DIRECTIVES.contains(directive) => {}
            _ => return Err(vm.raise(ExceptionKind::ValueError, "Invalid format string")),
        }
        next = find(position + 2);
    }

    Ok(())
}

/// `time.strptime` calls `_strptime._strptime_time(*args)`. Importing
/// `_strptime` branches on the host time zone and `LC_TIME` names; without
/// them, the argument errors of `_strptime_time` are reproduced and the
/// result is unknown.
fn time_strptime(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("strptime() takes no keyword arguments"));
    }
    if strptime_importable(vm)? {
        let module = vm.import_module("_strptime")?;
        return vm.call_method(&module, "_strptime_time", args.positional);
    }

    let given = args.positional.len();
    if given == 0 {
        return Err(vm.type_error("_strptime_time() takes at least 1 argument (0 given)"));
    }
    if given > 2 {
        return Err(vm.type_error(&format!(
            "_strptime_time() takes at most 2 arguments ({given} given)"
        )));
    }

    // `_strptime` compiles the format before matching the data string; both
    // reach `re`, which rejects anything but strings.
    for argument in args.positional.iter().rev() {
        let is_text = argument.is_unknown()
            || vm.as_str_bytes(argument).is_some()
            || vm.as_text(argument).is_some();
        if !is_text {
            return Err(vm.type_error("expected string or buffer"));
        }
    }

    Ok(Value::unknown("time.strptime() (host locale)"))
}

/// Whether importing `_strptime` gives known results: it is imported
/// already, or the host time zone is known and `LC_TIME` is the C locale.
pub(super) fn strptime_importable(vm: &Vm) -> PyResult<bool> {
    if vm.dict_get_str(vm.modules(), "_strptime")?.is_some() {
        return Ok(true);
    }

    Ok(vm.config.host.time_zone.is_some() && super::locale::time_is_c(vm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::vm::HostTimeZone;
    use crate::interp::vm::ModuleCode;
    use crate::interp::vm::ModuleSource;
    use crate::interp::vm::VmConfig;

    struct NoModules;

    impl ModuleSource for NoModules {
        fn find(&self, _name: &str) -> Option<ModuleCode> {
            None
        }
    }

    fn vm(time_zone: Option<HostTimeZone>) -> Vm {
        let mut config = VmConfig::windows_x64();
        config.host.time_zone = time_zone;

        match Vm::new(config, Box::new(NoModules)) {
            Ok(vm) => vm,
            Err(_) => panic!("interpreter bootstrap failed"),
        }
    }

    /// `time.strftime(format, fields)`, as text or the exception message.
    fn strftime(vm: &Vm, format: &str, fields: [i64; 9]) -> String {
        let module = vm.import_module("time").expect("time imports");
        let tuple = Value::tuple(fields.into_iter().map(Value::Int).collect());

        match vm.call_method(&module, "strftime", vec![Value::str(format), tuple]) {
            Ok(value) => vm.repr_text(&value).expect("repr"),
            Err(Signal::Raise(error)) => vm.describe_exception(&error),
            Err(Signal::Halt(halt)) => format!("halt: {halt}"),
        }
    }

    const MOMENT: [i64; 9] = [2003, 1, 2, 4, 5, 6, 3, 2, 0];

    /// Outputs of CPython 2.7.12 for Windows x64.
    #[test]
    fn windows_conversions() {
        let vm = vm(None);
        let cases = [
            ("%c", "'01/02/03 04:05:06'"),
            ("%#c", "'Thursday, January 02, 2003 04:05:06'"),
            ("%x", "'01/02/03'"),
            ("%#x", "'Thursday, January 02, 2003'"),
            ("%X|%#X", "'04:05:06|04:05:06'"),
            ("%#d %#H %#I %#j %#m %#M %#S %#U %#w %#W %#y %#Y", "'2 4 4 2 1 5 6 0 4 0 3 2003'"),
            ("%#a|%#A|%#b|%#B|%#p|%#%", "'Thu|Thursday|Jan|January|AM|%'"),
        ];
        for (format, expected) in cases {
            assert_eq!(strftime(&vm, format, MOMENT), expected, "{format}");
        }

        assert_eq!(strftime(&vm, "%c", [1900, 1, 1, 0, 0, 0, 0, 1, 0]), "'01/01/00 00:00:00'");
        assert_eq!(strftime(&vm, "%#c", [9999, 12, 31, 0, 0, 0, 4, 365, 0]), "'Friday, December 31, 9999 00:00:00'");
    }

    #[test]
    fn windows_rejects_unknown_conversions() {
        let vm = vm(None);
        for format in ["%Q", "%#", "%", "a%#Qb", "%E", "%Hx%"] {
            assert_eq!(strftime(&vm, format, MOMENT), "ValueError: Invalid format string", "{format}");
        }
    }

    /// The CRT validates fields Python lets through; its default invalid
    /// parameter handler ends the process.
    #[test]
    fn crt_invalid_parameters_halt() {
        let vm = vm(None);

        assert!(strftime(&vm, "%S", [2003, 1, 1, 0, 0, 60, 2, 1, 0]).starts_with("halt:"));
        assert!(strftime(&vm, "%Y", [10000, 1, 1, 0, 0, 0, 2, 1, 0]).starts_with("halt:"));
        assert_eq!(strftime(&vm, "%H:%M %y", [10000, 1, 1, 0, 0, 61, 2, 1, 0]), "'00:00 00'");
    }

    #[test]
    fn zone_names_need_the_host_time_zone() {
        assert_eq!(strftime(&vm(None), "%Z", MOMENT), "<unknown time.strftime() time zone name (host time zone)>");

        let zone = HostTimeZone { timezone: 28800, daylight: 1, tzname: [b"Pacific Standard Time".to_vec(), b"Pacific Daylight Time".to_vec()] };
        let vm = vm(Some(zone));
        assert_eq!(strftime(&vm, "%Z|%#z", MOMENT), "'Pacific Standard Time|Pacific Standard Time'");
        assert_eq!(strftime(&vm, "%z", [2003, 7, 1, 0, 0, 0, 1, 182, 5]), "'Pacific Daylight Time'");
        assert_eq!(strftime(&vm, "%Z", [2003, 7, 1, 0, 0, 0, 1, 182, -3]), "'Pacific Daylight Time'");
    }
}
