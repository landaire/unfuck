//! Methods of `str` and `unicode`, written once over `CodeUnit`.

use std::cmp::Ordering;

use num_bigint::Sign;
use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::install as install_methods;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::codecs::Direction;
use crate::interp::builtins::modules::codecs::code_with_registry;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::text::chars::CodeUnit;
use crate::interp::builtins::text::check_size;
use crate::interp::builtins::text::codecs;
use crate::interp::builtins::text::format;
use crate::interp::builtins::text::formatter::formatter_field_name_split;
use crate::interp::builtins::text::formatter::formatter_parser;
use crate::interp::builtins::text::index_result;
use crate::interp::builtins::text::int_argument;
use crate::interp::builtins::text::is_raised;
use crate::interp::builtins::text::repr_bytes;
use crate::interp::builtins::text::repr_unicode;
use crate::interp::builtins::text::string_argument;
use crate::interp::builtins::text::unknown_argument;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub(crate) type Body<T> = fn(&Vm, &[T], CallArgs) -> PyResult<Value>;

/// Which arguments of a `str` method switch it to the `unicode`
/// implementation when they are `unicode`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Promotion {
    Never,
    /// The substring, separator, or character set in the first position.
    First,
    /// The first argument or a member of a tuple there (`startswith`).
    Affix,
    /// Both strings of `replace`.
    FirstTwo,
}

macro_rules! text_methods {
    ($($name:literal => $body:ident, $promotion:ident;)*) => {
        fn str_methods() -> Vec<MethodSpec> {
            vec![$(method($name, |vm, args| on_str(vm, args, $name, Promotion::$promotion, $body::<u8>, $body::<u16>)),)*]
        }

        fn unicode_methods() -> Vec<MethodSpec> {
            vec![$(method($name, |vm, args| on_unicode(vm, args, $name, $body::<u16>)),)*]
        }

        /// The `str` implementation of the method `name`, for `bytearray`
        /// methods that share it.
        pub(crate) fn str_method_body(name: &str) -> Option<Body<u8>> {
            match name {
                $($name => Some($body::<u8>),)*
                _ => None,
            }
        }
    };
}

text_methods! {
    "capitalize" => capitalize, Never;
    "center" => center, Never;
    "count" => count, First;
    "decode" => decode, Never;
    "encode" => encode, Never;
    "endswith" => endswith, Affix;
    "expandtabs" => expandtabs, Never;
    "find" => find, First;
    "format" => format_method, Never;
    "index" => index, First;
    "isalnum" => isalnum, Never;
    "isalpha" => isalpha, Never;
    "isdigit" => isdigit, Never;
    "islower" => islower, Never;
    "isspace" => isspace, Never;
    "istitle" => istitle, Never;
    "isupper" => isupper, Never;
    "join" => join, Never;
    "ljust" => ljust, Never;
    "lower" => lower, Never;
    "lstrip" => lstrip, First;
    "partition" => partition, First;
    "replace" => replace, FirstTwo;
    "rfind" => rfind, First;
    "rindex" => rindex, First;
    "rjust" => rjust, Never;
    "rpartition" => rpartition, First;
    "rsplit" => rsplit, First;
    "rstrip" => rstrip, First;
    "split" => split, First;
    "splitlines" => splitlines, Never;
    "startswith" => startswith, Affix;
    "strip" => strip, First;
    "swapcase" => swapcase, Never;
    "title" => title, Never;
    "translate" => translate, Never;
    "upper" => upper, Never;
    "zfill" => zfill, Never;
    "__add__" => add, Never;
    "__contains__" => contains, Never;
    "__eq__" => equal, Never;
    "__ge__" => greater_equal, Never;
    "__getitem__" => getitem, Never;
    "__getnewargs__" => getnewargs, Never;
    "__getslice__" => getslice, Never;
    "__gt__" => greater, Never;
    "__hash__" => hash, Never;
    "__le__" => less_equal, Never;
    "__len__" => length, Never;
    "__lt__" => less, Never;
    "__mod__" => modulo, Never;
    "__mul__" => multiply, Never;
    "__ne__" => not_equal, Never;
    "__repr__" => repr, Never;
    "__rmod__" => reflected_modulo, Never;
    "__rmul__" => multiply, Never;
    "__str__" => str_method, Never;
    "_formatter_field_name_split" => formatter_field_name_split, Never;
    "_formatter_parser" => formatter_parser, Never;
}

pub fn install(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    let mut narrow = str_methods();
    narrow.push(method("__format__", |vm, args| format_spec_method(vm, args, false)));
    install_methods(vm, &types.str, &narrow)?;

    let mut wide = unicode_methods();
    wide.push(method("__format__", |vm, args| format_spec_method(vm, args, true)));
    wide.push(method("isdecimal", |vm, args| on_unicode(vm, args, "isdecimal", isdecimal)));
    wide.push(method("isnumeric", |vm, args| on_unicode(vm, args, "isnumeric", isnumeric)));

    install_methods(vm, &types.unicode, &wide)
}

/// Runs a `str` method, switching to the `unicode` implementation when
/// `promotion` allows and an argument is `unicode`.
fn on_str(vm: &Vm, args: CallArgs, name: &str, promotion: Promotion, narrow: Body<u8>, wide: Body<u16>) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, name)?;
    if receiver.is_unknown() {
        return Ok(receiver);
    }
    let Some(bytes) = vm.as_str_bytes(&receiver) else {
        return Err(descriptor_mismatch(vm, name, "str", &receiver));
    };
    if let Some(unknown) = unknown_argument(&args) {
        return Ok(unknown);
    }

    if has_unicode_argument(vm, &args, promotion) {
        let text = codecs::decode_default(vm, bytes.as_bytes())?;
        return wide(vm, text.units(), args);
    }

    let Value::Str(exact) = &receiver else {
        return narrow(vm, bytes.as_bytes(), args);
    };
    if name == "__getitem__" {
        let index = slot_argument(vm, args, name)?;
        return vm.getitem(&receiver, &index);
    }
    if name == "__add__"
        && exact.as_bytes().is_empty()
        && let Some(other @ Value::Str(_)) = args.positional.first()
        && args.positional.len() == 1
        && !args.has_keywords()
    {
        return Ok(other.clone());
    }
    let copies_equal = match name {
        "__add__" => !matches!(args.positional.first(), Some(Value::Str(_))),
        "replace" => replace_copies_equal::<u8>(vm, exact.as_bytes(), &args),
        _ => false,
    };

    let result = narrow(vm, exact.as_bytes(), args)?;
    if copies_equal {
        return Ok(result);
    }

    const RETURNS_SELF: &[&str] = &["strip", "lstrip", "rstrip", "center", "ljust", "rjust", "zfill", "translate", "replace", "__str__", "__getslice__", "__add__", "__mul__", "__rmul__"];
    Ok(reuse_receiver(name, &receiver, RETURNS_SELF, result))
}

/// The receiver in place of a part of `result` equal to it, where the
/// method of an exact `str` or `unicode` returns `self` rather than a copy.
/// `returns_self` names the methods whose whole result may be `self`; the
/// split methods put `self` in their result when nothing splits.
fn reuse_receiver(name: &str, receiver: &Value, returns_self: &[&str], result: Value) -> Value {
    let is_receiver = |value: &Value| match (receiver, value) {
        (Value::Str(receiver), Value::Str(bytes)) => bytes.as_bytes() == receiver.as_bytes(),
        (Value::Unicode(receiver), Value::Unicode(text)) => text.units() == receiver.units(),
        _ => false,
    };

    match name {
        _ if returns_self.contains(&name) => {
            if is_receiver(&result) {
                return receiver.clone();
            }
            result
        }
        "partition" | "rpartition" => {
            let Value::Tuple(parts) = &result else {
                return result;
            };
            let whole = if name == "partition" { 0 } else { 2 };
            if !parts.get(whole).is_some_and(is_receiver) {
                return result;
            }
            let mut parts = parts.to_vec();
            parts[whole] = receiver.clone();
            Value::tuple(parts)
        }
        "split" | "rsplit" | "splitlines" => {
            if let Some(object) = result.as_object()
                && let Payload::List(items) = &object.payload
            {
                let mut items = items.borrow_mut();
                if let [item] = &mut items[..]
                    && is_receiver(item)
                {
                    *item = receiver.clone();
                }
            }
            result
        }
        _ => result,
    }
}

/// Whether `replace` rewrites occurrences of `old` with an equal `new`,
/// which copies the string rather than returning it.
fn replace_copies_equal<T: CodeUnit>(vm: &Vm, units: &[T], args: &CallArgs) -> bool {
    let coerce = |index: usize| args.positional.get(index).and_then(|value| T::coerce(vm, value).ok().flatten());
    let (Some(old), Some(new)) = (coerce(0), coerce(1)) else {
        return false;
    };
    if old.is_empty() || old[..] != new[..] || !units.windows(old.len()).any(|window| window == &old[..]) {
        return false;
    }

    args.positional.get(2).and_then(|count| vm.as_index(count)) != Some(0)
}

fn on_unicode(vm: &Vm, args: CallArgs, name: &str, wide: Body<u16>) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, name)?;
    if receiver.is_unknown() {
        return Ok(receiver);
    }
    let Some(text) = vm.as_text(&receiver) else {
        return Err(descriptor_mismatch(vm, name, "unicode", &receiver));
    };
    if let Some(unknown) = unknown_argument(&args) {
        return Ok(unknown);
    }

    let Value::Unicode(exact) = &receiver else {
        return wide(vm, text.units(), args);
    };
    if name == "__getitem__" {
        let index = slot_argument(vm, args, name)?;
        return vm.getitem(&receiver, &index);
    }
    if name == "__add__"
        && let [other] = &args.positional[..]
        && !args.has_keywords()
    {
        // Concatenation returns the other operand, converted, when this one
        // is the shared empty `unicode`.
        let converts_empty = match other {
            Value::Unicode(other) => other.is_shared_empty(),
            _ => vm.as_str_bytes(other).is_some_and(|bytes| bytes.as_bytes().is_empty()) || vm.as_text(other).is_some_and(|other| other.units().is_empty()),
        };
        if converts_empty {
            return Ok(receiver.clone());
        }
        if exact.is_shared_empty() && matches!(other, Value::Unicode(_)) {
            return Ok(other.clone());
        }
    }
    let copies_equal = match name {
        "__add__" => true,
        "replace" => replace_copies_equal::<u16>(vm, exact.units(), &args),
        // `unicode.title` copies any string longer than one unit, changed
        // or not.
        "title" => exact.units().len() != 1,
        _ => false,
    };

    let result = wide(vm, exact.units(), args)?;
    if copies_equal {
        return Ok(result);
    }

    const RETURNS_SELF: &[&str] = &["strip", "lstrip", "rstrip", "center", "ljust", "rjust", "zfill", "replace", "lower", "upper", "swapcase", "capitalize", "title", "__getslice__", "__mul__", "__rmul__"];
    Ok(reuse_receiver(name, &receiver, RETURNS_SELF, result))
}

fn descriptor_mismatch(vm: &Vm, name: &str, owner: &str, receiver: &Value) -> Signal {
    vm.type_error(&format!("descriptor '{name}' requires a '{owner}' object but received a '{}'", vm.type_name(receiver)))
}

/// Whether an argument that `promotion` names is `unicode`.
fn has_unicode_argument(vm: &Vm, args: &CallArgs, promotion: Promotion) -> bool {
    let is_unicode = |index: usize| args.positional.get(index).is_some_and(|value| vm.as_text(value).is_some());

    match promotion {
        Promotion::Never => false,
        Promotion::First => is_unicode(0),
        Promotion::FirstTwo => is_unicode(0) || is_unicode(1),
        Promotion::Affix => is_unicode(0) || args.positional.first().and_then(|value| vm.as_tuple(value)).is_some_and(|items| items.iter().any(|item| vm.as_text(item).is_some())),
    }
}

/// Units of a `unicode` receiver. Valid only when `T::UNICODE`.
fn as_wide<T: CodeUnit>(units: &[T]) -> Vec<u16> {
    units.iter().map(|unit| (*unit).into() as u16).collect()
}

/// Bytes of a `str` receiver. Valid only when `!T::UNICODE`.
fn as_narrow<T: CodeUnit>(units: &[T]) -> Vec<u8> {
    units.iter().map(|unit| (*unit).into() as u8).collect()
}

/// The receiver as `unicode`, decoding a `str` with the default encoding.
fn promote<T: CodeUnit>(vm: &Vm, units: &[T]) -> PyResult<Vec<u16>> {
    if T::UNICODE {
        return Ok(as_wide(units));
    }

    Ok(codecs::decode_default(vm, &as_narrow(units))?.units().to_vec())
}

fn plain<T: CodeUnit>(units: &[T]) -> Value {
    T::new_value(units.to_vec())
}

fn no_arguments(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    if !args.positional.is_empty() {
        return Err(vm.type_error(&format!("{name}() takes no arguments ({} given)", args.positional.len())));
    }

    Ok(())
}

/// A string argument converted to the receiver's kind. `str` methods take
/// any character buffer; `unicode` methods coerce other strings and
/// buffers to `unicode`.
fn required_string<T: CodeUnit>(vm: &Vm, value: &Value) -> PyResult<T::Shared> {
    if let Some(units) = T::coerce_buffer(vm, value)? {
        return Ok(units);
    }

    if T::UNICODE {
        return Err(vm.type_error(&format!("coercing to Unicode: need string or buffer, {} found", vm.type_name(value))));
    }

    Err(vm.type_error("expected a string or other character buffer object"))
}

/// A search bound: `None` or an integer, clamped to the 64-bit range.
fn slice_index(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_none() {
        return Ok(None);
    }

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let Some(method) = vm.user_override(value, "__index__")? else {
                return Err(vm.type_error("slice indices must be integers or None or have an __index__ method"));
            };
            let result = index_result(vm.call0(&method)?)?;
            let Some(integral) = vm.as_integral(&result) else {
                return Err(vm.type_error(&format!("__index__ returned non-(int,long) (type {})", vm.type_name(&result))));
            };
            integral
        }
    };

    Ok(Some(match integral {
        Integral::Int(number) => number,
        Integral::Long(number) => number.to_i64().unwrap_or(if number.sign() == Sign::Minus { i64::MIN } else { i64::MAX }),
    }))
}

/// Search bounds against a string of `length` units: a negative bound
/// counts from the end and stops at its start, and `end` stops at the
/// end. `start` may still lie past `end` or the string.
fn adjust_indices(start: i64, end: i64, length: usize) -> (i64, i64) {
    let length = i64::try_from(length).unwrap_or(i64::MAX);
    let from_end = |bound: i64| if bound < 0 { bound.saturating_add(length).max(0) } else { bound };

    (from_end(start), from_end(end).min(length))
}

/// `sub[, start[, end]]` of the search methods, with adjusted bounds.
fn find_arguments(vm: &Vm, length: usize, args: CallArgs, name: &str) -> PyResult<(Value, i64, i64)> {
    let args = positional(vm, args, name, 1, 3)?;
    let start = match args.get(1) {
        Some(value) => slice_index(vm, value)?,
        None => None,
    };
    let end = match args.get(2) {
        Some(value) => slice_index(vm, value)?,
        None => None,
    };
    let (start, end) = adjust_indices(start.unwrap_or(0), end.unwrap_or(i64::MAX), length);

    Ok((args[0].clone(), start, end))
}

fn find_slice<T: PartialEq>(haystack: &[T], needle: &[T], start: i64, end: i64, reverse: bool) -> i64 {
    if end < start {
        return -1;
    }
    if needle.is_empty() {
        return if reverse { end } else { start };
    }

    let window = &haystack[start as usize..end as usize];
    if needle.len() > window.len() {
        return -1;
    }

    let found = if reverse { window.windows(needle.len()).rposition(|candidate| candidate == needle) } else { window.windows(needle.len()).position(|candidate| candidate == needle) };

    found.map_or(-1, |position| start + position as i64)
}

/// `str` names its search methods together in arity errors.
fn search<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, reverse: bool) -> PyResult<i64> {
    let shown = if T::UNICODE { name } else { "find/rfind/index/rindex" };
    let (needle, start, end) = find_arguments(vm, units.len(), args, shown)?;
    let needle = required_string::<T>(vm, &needle)?;

    Ok(find_slice(units, &needle, start, end, reverse))
}

fn find<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    Ok(Value::Int(search(vm, units, args, "find", false)?))
}

fn rfind<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    Ok(Value::Int(search(vm, units, args, "rfind", true)?))
}

fn index<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    match search(vm, units, args, "index", false)? {
        -1 => Err(vm.raise(ExceptionKind::ValueError, "substring not found")),
        position => Ok(Value::Int(position)),
    }
}

fn rindex<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    match search(vm, units, args, "rindex", true)? {
        -1 => Err(vm.raise(ExceptionKind::ValueError, "substring not found")),
        position => Ok(Value::Int(position)),
    }
}

/// Non-overlapping occurrences.
fn count<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (needle, start, end) = find_arguments(vm, units.len(), args, "count")?;
    let needle = required_string::<T>(vm, &needle)?;
    if end < start {
        return Ok(Value::Int(0));
    }

    let window = &units[start as usize..end as usize];
    if needle.is_empty() {
        return Ok(Value::Int(window.len() as i64 + 1));
    }

    let mut total = 0;
    let mut position = 0;
    while position + needle.len() <= window.len() {
        if window[position..position + needle.len()] == needle[..] {
            total += 1;
            position += needle.len();
        } else {
            position += 1;
        }
    }

    Ok(Value::Int(total))
}

/// Whether `affix` begins (or, with `at_end`, ends) the window
/// `start..end` of `units`, with the bounds already adjusted. The window
/// must hold the affix, so for `str` even an empty affix fails when
/// `start` lies past `end`; `unicode` matches an empty affix anywhere.
fn tail_match<T: CodeUnit>(units: &[T], affix: &[T], start: i64, end: i64, at_end: bool) -> bool {
    if T::UNICODE && affix.is_empty() {
        return true;
    }

    // `end` lies in `0..=len` and `start` is not negative, so neither the
    // difference nor the window below can leave the string.
    let width = affix.len() as i64;
    if end - start < width {
        return false;
    }

    let from = if at_end { end - width } else { start } as usize;

    units[from..from + affix.len()] == *affix
}

fn affix_match<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, at_end: bool) -> PyResult<Value> {
    let (affix, start, end) = find_arguments(vm, units.len(), args, name)?;

    if let Some(items) = vm.as_tuple(&affix) {
        for item in items.iter() {
            if item.is_unknown() {
                return Ok(item.clone());
            }
            let candidate = required_string::<T>(vm, item)?;
            if tail_match(units, &candidate, start, end, at_end) {
                return Ok(Value::Bool(true));
            }
        }
        return Ok(Value::Bool(false));
    }

    // A `TypeError` while converting the affix becomes the method's own.
    let candidate = if T::UNICODE { T::coerce(vm, &affix) } else { T::coerce_buffer(vm, &affix) };
    let candidate = match candidate {
        Ok(Some(candidate)) => candidate,
        Err(Signal::Raise(error)) if !vm.is_exception(&error, ExceptionKind::TypeError) => return Err(Signal::Raise(error)),
        Err(Signal::Halt(halt)) => return Err(Signal::Halt(halt)),
        Ok(None) | Err(Signal::Raise(_)) => return Err(vm.type_error(&format!("{name} first arg must be str, unicode, or tuple, not {}", vm.type_name(&affix)))),
    };

    Ok(Value::Bool(tail_match(units, &candidate, start, end, at_end)))
}

fn startswith<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    affix_match(vm, units, args, "startswith", false)
}

fn endswith<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    affix_match(vm, units, args, "endswith", true)
}

fn map_units<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, mapping: fn(T) -> T) -> PyResult<Value> {
    no_arguments(vm, &args, name)?;

    Ok(T::new_unshared_value(units.iter().map(|unit| mapping(*unit)).collect()))
}

fn lower<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    map_units(vm, units, args, "lower", T::to_lower)
}

fn upper<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    map_units(vm, units, args, "upper", T::to_upper)
}

fn swapcase<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    map_units(vm, units, args, "swapcase", |unit| {
        if unit.is_upper() {
            unit.to_lower()
        } else if unit.is_lower() {
            unit.to_upper()
        } else {
            unit
        }
    })
}

/// The first character to uppercase unless it already is, the rest to
/// lowercase.
fn capitalize<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "capitalize")?;

    let mapped = units
        .iter()
        .enumerate()
        .map(|(position, &unit)| match position {
            0 if !unit.is_upper() => unit.to_upper(),
            0 => unit,
            _ if !unit.is_lower() => unit.to_lower(),
            _ => unit,
        })
        .collect();

    Ok(T::new_unshared_value(mapped))
}

/// Titlecase after an uncased character, lowercase after a cased one.
fn title<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "title")?;

    let mut previous_cased = false;
    let mut mapped = Vec::with_capacity(units.len());
    for &unit in units {
        mapped.push(if previous_cased { unit.to_lower() } else { unit.to_title() });
        previous_cased = unit.is_lower() || unit.is_upper() || unit.is_title();
    }

    Ok(T::new_unshared_value(mapped))
}

fn all_units<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, test: fn(T) -> bool) -> PyResult<Value> {
    no_arguments(vm, &args, name)?;

    Ok(Value::Bool(!units.is_empty() && units.iter().all(|unit| test(*unit))))
}

fn isalnum<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isalnum", T::is_alnum)
}

fn isalpha<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isalpha", T::is_alpha)
}

fn isdigit<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isdigit", T::is_digit)
}

fn isspace<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isspace", T::is_space)
}

fn isdecimal(vm: &Vm, units: &[u16], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isdecimal", u16::is_decimal)
}

fn isnumeric(vm: &Vm, units: &[u16], args: CallArgs) -> PyResult<Value> {
    all_units(vm, units, args, "isnumeric", u16::is_numeric)
}

/// Lowercase letters only, at least one: titlecase counts as uppercase.
fn islower<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "islower")?;

    let mut cased = false;
    for &unit in units {
        if unit.is_upper() || unit.is_title() {
            return Ok(Value::Bool(false));
        }
        cased |= unit.is_lower();
    }

    Ok(Value::Bool(cased))
}

fn isupper<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "isupper")?;

    let mut cased = false;
    for &unit in units {
        if unit.is_lower() || unit.is_title() {
            return Ok(Value::Bool(false));
        }
        cased |= unit.is_upper();
    }

    Ok(Value::Bool(cased))
}

fn istitle<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "istitle")?;

    let mut cased = false;
    let mut previous_cased = false;
    for &unit in units {
        if unit.is_upper() || unit.is_title() {
            if previous_cased {
                return Ok(Value::Bool(false));
            }
            previous_cased = true;
            cased = true;
        } else if unit.is_lower() {
            if !previous_cased {
                return Ok(Value::Bool(false));
            }
            previous_cased = true;
            cased = true;
        } else {
            previous_cased = false;
        }
    }

    Ok(Value::Bool(cased))
}

/// The fill character of `center`, `ljust`, and `rjust`.
fn fill_argument<T: CodeUnit>(vm: &Vm, value: &Value, name: &str) -> PyResult<T> {
    if !T::UNICODE {
        return match vm.as_str_bytes(value) {
            Some(bytes) if bytes.as_bytes().len() == 1 => Ok(T::from_ascii(bytes.as_bytes()[0])),
            _ => Err(vm.type_error(&format!("{name}() argument 2 must be char, not {}", vm.type_name(value)))),
        };
    }

    let converted = match vm.as_str_bytes(value) {
        Some(bytes) if !bytes.as_bytes().is_ascii() => None,
        _ => T::coerce(vm, value)?,
    };
    let Some(units) = converted else {
        return Err(vm.type_error("The fill character cannot be converted to Unicode"));
    };
    let [unit] = units[..] else {
        return Err(vm.type_error("The fill character must be exactly one character long"));
    };

    Ok(unit)
}

fn pad<T: CodeUnit>(units: &[T], left: i64, right: i64, fill: T) -> Value {
    let left = usize::try_from(left).unwrap_or(0);
    let right = usize::try_from(right).unwrap_or(0);
    let mut padded = Vec::with_capacity(left + units.len() + right);
    padded.extend(std::iter::repeat_n(fill, left));
    padded.extend_from_slice(units);
    padded.extend(std::iter::repeat_n(fill, right));

    T::new_unshared_value(padded)
}

fn justify_arguments<T: CodeUnit>(vm: &Vm, args: CallArgs, name: &str) -> PyResult<(i64, T)> {
    let args = positional(vm, args, name, 1, 2)?;
    let width = ssize_argument(vm, &args[0])?;
    check_size(vm, width)?;
    let fill = match args.get(1) {
        Some(value) => fill_argument(vm, value, name)?,
        None => T::from_ascii(b' '),
    };

    Ok((width, fill))
}

fn center<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (width, fill) = justify_arguments(vm, args, "center")?;
    let length = units.len() as i64;
    if length >= width {
        return Ok(pad(units, 0, 0, fill));
    }

    let margin = width - length;
    let left = margin / 2 + (margin & width & 1);

    Ok(pad(units, left, margin - left, fill))
}

fn ljust<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (width, fill) = justify_arguments(vm, args, "ljust")?;

    Ok(pad(units, 0, width.saturating_sub(units.len() as i64), fill))
}

fn rjust<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (width, fill) = justify_arguments(vm, args, "rjust")?;

    Ok(pad(units, width.saturating_sub(units.len() as i64), 0, fill))
}

/// Pads with zeros on the left, keeping a leading sign in front.
fn zfill<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "zfill", 1, 1)?;
    let width = ssize_argument(vm, &args[0])?;
    check_size(vm, width)?;
    let length = units.len() as i64;
    if length >= width {
        return Ok(plain(units));
    }

    let fill = (width - length) as usize;
    let mut padded = vec![T::from_ascii(b'0'); fill];
    padded.extend_from_slice(units);
    if let Some(&sign) = padded.get(fill).filter(|sign| **sign == T::from_ascii(b'+') || **sign == T::from_ascii(b'-')) {
        padded[0] = sign;
        padded[fill] = T::from_ascii(b'0');
    }

    Ok(T::new_unshared_value(padded))
}

fn expandtabs<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "expandtabs", 0, 1)?;
    let tab_size = match args.first() {
        Some(value) => int_argument(vm, value)?,
        None => 8,
    };

    let mut column: i64 = 0;
    let mut expanded = Vec::with_capacity(units.len());
    for &unit in units {
        if unit == T::from_ascii(b'\t') {
            if tab_size > 0 {
                let increment = tab_size - column % tab_size;
                column += increment;
                check_size(vm, expanded.len() as i64 + increment)?;
                expanded.extend(std::iter::repeat_n(T::from_ascii(b' '), increment as usize));
            }
            continue;
        }

        column += 1;
        expanded.push(unit);
        if unit == T::from_ascii(b'\n') || unit == T::from_ascii(b'\r') {
            column = 0;
        }
    }

    Ok(T::new_unshared_value(expanded))
}

/// `[sep[, maxsplit]]`: `None` splits on whitespace runs.
fn split_arguments<T: CodeUnit>(vm: &Vm, args: CallArgs, name: &str) -> PyResult<(Option<T::Shared>, usize)> {
    let args = positional(vm, args, name, 0, 2)?;
    let limit = match args.get(1) {
        Some(value) => usize::try_from(ssize_argument(vm, value)?).unwrap_or(usize::MAX),
        None => usize::MAX,
    };

    let separator = match args.first() {
        Some(value) if !value.is_none() => {
            let separator = required_string::<T>(vm, value)?;
            if separator.is_empty() {
                return Err(vm.raise(ExceptionKind::ValueError, "empty separator"));
            }
            Some(separator)
        }
        _ => None,
    };

    Ok((separator, limit))
}

/// Fields separated by runs of whitespace, scanning from the start; at
/// most `limit` splits, after which the rest of the string, less its
/// leading whitespace, is the last field. Whitespace at either end yields
/// no empty fields.
fn split_whitespace<T: CodeUnit>(units: &[T], limit: usize) -> Vec<&[T]> {
    let mut parts = Vec::new();
    let mut position = 0;

    loop {
        while units.get(position).is_some_and(|unit| unit.is_space()) {
            position += 1;
        }
        if position == units.len() {
            break;
        }
        if parts.len() == limit {
            parts.push(&units[position..]);
            break;
        }

        let start = position;
        while units.get(position).is_some_and(|unit| !unit.is_space()) {
            position += 1;
        }
        parts.push(&units[start..position]);
    }

    parts
}

/// Fields separated by runs of whitespace, scanning from the end; at most
/// `limit` splits, after which the rest of the string, less its trailing
/// whitespace, is the first field. Whitespace at either end yields no
/// empty fields.
fn rsplit_whitespace<T: CodeUnit>(units: &[T], limit: usize) -> Vec<&[T]> {
    let mut parts = Vec::new();
    let mut position = units.len();

    loop {
        while position > 0 && units[position - 1].is_space() {
            position -= 1;
        }
        if position == 0 {
            break;
        }
        if parts.len() == limit {
            parts.push(&units[..position]);
            break;
        }

        let end = position;
        while position > 0 && !units[position - 1].is_space() {
            position -= 1;
        }
        parts.push(&units[position..end]);
    }

    parts.reverse();
    parts
}

fn split_on<'a, T: CodeUnit>(units: &'a [T], separator: &[T], limit: usize) -> Vec<&'a [T]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut remaining = limit;

    while remaining > 0 {
        let found = find_slice(units, separator, start as i64, units.len() as i64, false);
        if found < 0 {
            break;
        }
        let found = found as usize;
        parts.push(&units[start..found]);
        start = found + separator.len();
        remaining -= 1;
    }
    parts.push(&units[start..]);

    parts
}

fn rsplit_on<'a, T: CodeUnit>(units: &'a [T], separator: &[T], limit: usize) -> Vec<&'a [T]> {
    let mut parts = Vec::new();
    let mut end = units.len();
    let mut remaining = limit;

    while remaining > 0 {
        let found = find_slice(units, separator, 0, end as i64, true);
        if found < 0 {
            break;
        }
        let found = found as usize;
        parts.push(&units[found + separator.len()..end]);
        end = found;
        remaining -= 1;
    }
    parts.push(&units[..end]);

    parts.reverse();
    parts
}

fn parts_list<T: CodeUnit>(vm: &Vm, parts: Vec<&[T]>) -> Value {
    vm.new_list(parts.into_iter().map(plain).collect())
}

fn split<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (separator, limit) = split_arguments::<T>(vm, args, "split")?;
    let parts = match &separator {
        Some(separator) => split_on(units, separator, limit),
        None => split_whitespace(units, limit),
    };

    Ok(parts_list(vm, parts))
}

fn rsplit<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let (separator, limit) = split_arguments::<T>(vm, args, "rsplit")?;
    let parts = match &separator {
        Some(separator) => rsplit_on(units, separator, limit),
        None => rsplit_whitespace(units, limit),
    };

    Ok(parts_list(vm, parts))
}

/// `splitlines([keepends])`. `str` breaks lines at `\n` and `\r`,
/// `unicode` also at the other Unicode line separators; `\r\n` is one
/// break. With `keepends` each break stays on its line. A last line
/// without a break is kept; no empty line follows a final break.
fn splitlines<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "splitlines", 0, 1)?;
    let keep_ends = match args.first() {
        Some(value) => int_argument(vm, value)? != 0,
        None => false,
    };

    let carriage_return = T::from_ascii(b'\r');
    let line_feed = T::from_ascii(b'\n');
    let mut lines = Vec::new();
    let mut start = 0;

    while start < units.len() {
        let Some(offset) = units[start..].iter().position(|unit| unit.is_linebreak()) else {
            lines.push(&units[start..]);
            break;
        };

        let content_end = start + offset;
        let mut next = content_end + 1;
        if units[content_end] == carriage_return && units.get(next) == Some(&line_feed) {
            next += 1;
        }
        lines.push(&units[start..if keep_ends { next } else { content_end }]);
        start = next;
    }

    Ok(parts_list(vm, lines))
}

fn partition_units<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, reverse: bool) -> PyResult<Value> {
    let separator_value = single_argument(vm, args, name)?;
    let separator = required_string::<T>(vm, &separator_value)?;
    if separator.is_empty() {
        return Err(vm.raise(ExceptionKind::ValueError, "empty separator"));
    }

    let empty: &[T] = &[];
    let found = find_slice(units, &separator, 0, units.len() as i64, reverse);
    let parts = match usize::try_from(found) {
        Ok(found) => [&units[..found], &separator[..], &units[found + separator.len()..]],
        Err(_) if reverse => [empty, empty, units],
        Err(_) => [units, empty, empty],
    };
    let mut parts: Vec<Value> = parts.into_iter().map(plain).collect();

    // `str` puts the separator object itself in the result; `unicode` puts
    // the separator coerced to `unicode`.
    if found >= 0 && !T::UNICODE {
        parts[1] = separator_value;
    }

    Ok(Value::tuple(parts))
}

fn partition<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    partition_units(vm, units, args, "partition", false)
}

fn rpartition<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    partition_units(vm, units, args, "rpartition", true)
}

/// `replace(old, new[, count])`. An empty `old` inserts `new` before every
/// character and at the end.
fn replace<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "replace", 2, 3)?;
    let count = match args.get(2) {
        Some(value) => Some(ssize_argument(vm, value)?),
        None => None,
    };
    let old = required_string::<T>(vm, &args[0])?;
    let new = required_string::<T>(vm, &args[1])?;

    let limit = match count {
        Some(count) if count >= 0 => {
            if count == 0 || units.is_empty() {
                return Ok(plain(units));
            }
            count as usize
        }
        _ => usize::MAX,
    };

    if old.is_empty() {
        if new.is_empty() {
            return Ok(plain(units));
        }
        let insertions = (units.len() + 1).min(limit);
        let mut replaced = new.to_vec();
        for &unit in &units[..insertions - 1] {
            replaced.push(unit);
            replaced.extend_from_slice(&new);
        }
        replaced.extend_from_slice(&units[insertions - 1..]);
        return Ok(T::new_unshared_value(replaced));
    }

    let mut replaced = Vec::with_capacity(units.len());
    let mut position = 0;
    let mut remaining = limit;
    while remaining > 0 {
        let found = find_slice(units, &old, position as i64, units.len() as i64, false);
        if found < 0 {
            break;
        }
        let found = found as usize;
        replaced.extend_from_slice(&units[position..found]);
        replaced.extend_from_slice(&new);
        position = found + old.len();
        remaining -= 1;
    }
    if remaining == limit {
        return Ok(plain(units));
    }
    replaced.extend_from_slice(&units[position..]);

    Ok(T::new_unshared_value(replaced))
}

fn strip_units<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, left: bool, right: bool) -> PyResult<Value> {
    let args = positional(vm, args, name, 0, 1)?;
    let characters = match args.first() {
        Some(value) if !value.is_none() => match T::coerce(vm, value)? {
            Some(characters) => Some(characters),
            None if T::UNICODE => return Err(vm.type_error(&format!("{name} arg must be None, unicode or str"))),
            None => return Err(vm.type_error(&format!("{name} arg must be None, str or unicode"))),
        },
        _ => None,
    };
    let stripped = |unit: T| match &characters {
        Some(characters) => characters.contains(&unit),
        None => unit.is_space(),
    };

    let mut start = 0;
    let mut end = units.len();
    if left {
        while start < end && stripped(units[start]) {
            start += 1;
        }
    }
    if right {
        while end > start && stripped(units[end - 1]) {
            end -= 1;
        }
    }

    Ok(plain(&units[start..end]))
}

fn strip<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    strip_units(vm, units, args, "strip", true, true)
}

fn lstrip<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    strip_units(vm, units, args, "lstrip", true, false)
}

fn rstrip<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    strip_units(vm, units, args, "rstrip", false, true)
}

/// `sep.join(iterable)`. A `str` separator switches to `unicode` when it
/// meets a `unicode` item.
fn join<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let iterable = single_argument(vm, args, "join")?;
    let iterator = match vm.iter(&iterable) {
        Ok(iterator) => iterator,
        Err(signal) if is_raised(vm, &signal, ExceptionKind::TypeError) => return Err(vm.type_error("can only join an iterable")),
        Err(signal) => return Err(signal),
    };
    let items = vm.collect(&iterator)?;
    if let Some(unknown) = items.iter().find(|item| item.is_unknown()) {
        return Ok(unknown.clone());
    }

    if items.is_empty() {
        return Ok(T::new_value(Vec::new()));
    }
    if let [item] = &items[..]
        && (matches!(item, Value::Unicode(_)) || (!T::UNICODE && matches!(item, Value::Str(_))))
    {
        return Ok(item.clone());
    }

    let first_other = items.iter().find(|item| vm.as_str_bytes(item).is_none());
    if !T::UNICODE && first_other.is_some_and(|item| vm.as_text(item).is_some()) {
        let separator = promote(vm, units)?;
        return join_items::<u16>(vm, &separator, &items);
    }

    join_items(vm, units, &items)
}

fn join_items<T: CodeUnit>(vm: &Vm, separator: &[T], items: &[Value]) -> PyResult<Value> {
    let mut joined = Vec::new();

    for (position, item) in items.iter().enumerate() {
        let Some(units) = T::coerce(vm, item)? else {
            let expected = if T::UNICODE { "string or Unicode" } else { "string" };
            return Err(vm.type_error(&format!("sequence item {position}: expected {expected}, {} found", vm.type_name(item))));
        };
        if position > 0 {
            joined.extend_from_slice(separator);
        }
        joined.extend_from_slice(&units);
    }

    // `str` builds the result at its exact size; `unicode` grows a buffer
    // and shrinks it at the end.
    if T::UNICODE {
        return Ok(T::allocated_value(joined));
    }

    Ok(T::new_unshared_value(joined))
}

/// `str.translate(table[, deletechars])` and `unicode.translate(mapping)`.
fn translate<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    if T::UNICODE {
        let table = single_argument(vm, args, "translate")?;
        return translate_mapping(vm, &as_wide(units), &table);
    }

    if args.has_keywords() {
        return Err(vm.type_error("translate() takes no keyword arguments"));
    }
    let args = args.positional;
    if args.is_empty() || args.len() > 2 {
        let bound = if args.is_empty() { "at least 1" } else { "at most 2" };
        return Err(vm.type_error(&format!("translate expected {bound} arguments, got {}", args.len())));
    }
    let table = &args[0];
    if vm.as_text(table).is_some() {
        if args.len() > 1 {
            return Err(vm.type_error("deletions are implemented differently for unicode"));
        }
        let text = promote(vm, units)?;
        return translate_mapping(vm, &text, table);
    }

    let table = if table.is_none() {
        None
    } else {
        let Some(bytes) = vm.buffer(table, BufferInterface::Character)? else {
            return Err(vm.type_error("expected a string or other character buffer object"));
        };
        if bytes.as_bytes().len() != 256 {
            return Err(vm.raise(ExceptionKind::ValueError, "translation table must be 256 characters long"));
        }
        Some(bytes)
    };

    let deleted = match args.get(1) {
        Some(value) if vm.as_text(value).is_some() => return Err(vm.type_error("deletions are implemented differently for unicode")),
        Some(value) => match vm.buffer(value, BufferInterface::Character)? {
            Some(bytes) => bytes.as_bytes().to_vec(),
            None => return Err(vm.type_error("expected a string or other character buffer object")),
        },
        None => Vec::new(),
    };

    let translated: Vec<u8> = as_narrow(units)
        .into_iter()
        .filter(|byte| !deleted.contains(byte))
        .map(|byte| match &table {
            Some(table) => table.as_bytes()[usize::from(byte)],
            None => byte,
        })
        .collect();

    // Without deletions and with a table, the output keeps its allocated
    // size; otherwise a nonempty one is shrunk to fit.
    if (table.is_none() || !deleted.is_empty()) && !units.is_empty() {
        return Ok(Value::Str(PyBytes::allocate(translated)));
    }

    Ok(Value::Str(PyBytes::new_unshared(translated)))
}

/// Translates each unit through `table`: missing keys keep the unit, `None`
/// deletes it, an integer or `unicode` replaces it.
fn translate_mapping(vm: &Vm, units: &[u16], table: &Value) -> PyResult<Value> {
    let mut translated = Vec::with_capacity(units.len());

    for &unit in units {
        let mapped = match vm.getitem(table, &Value::Int(i64::from(unit))) {
            Ok(mapped) => mapped,
            Err(signal) if is_raised(vm, &signal, ExceptionKind::LookupError) => {
                translated.push(unit);
                continue;
            }
            Err(signal) => return Err(signal),
        };

        if mapped.is_unknown() {
            return Ok(mapped);
        }
        if mapped.is_none() {
            continue;
        }
        if let Some(text) = vm.as_text(&mapped) {
            translated.extend_from_slice(text.units());
            continue;
        }
        let code = match &mapped {
            Value::Int(code) => Some(*code),
            Value::Bool(flag) => Some(i64::from(*flag)),
            Value::Object(_) => match vm.as_integral(&mapped) {
                Some(Integral::Int(code)) => Some(code),
                _ => None,
            },
            _ => None,
        };
        let Some(code) = code else {
            return Err(vm.type_error("character mapping must return integer, None or unicode"));
        };
        let Ok(code) = u16::try_from(code) else {
            // The reference build's message formatter lacks `%lx`, so the
            // directive appears literally.
            return Err(vm.type_error("character mapping must be in range(0x%lx)"));
        };
        translated.push(code);
    }

    // The result is allocated at the input's size and then resized.
    Ok(Value::Unicode(codecs::resized_text(units.len(), translated)))
}

/// `encoding` and `errors` of `decode` and `encode`.
struct CodecArguments {
    encoding: Option<Vec<u8>>,
    errors: Option<Vec<u8>>,
}

fn codec_arguments(vm: &Vm, args: CallArgs, name: &str) -> PyResult<CodecArguments> {
    let mut slots = parse_with(vm, args, name, &["encoding", "errors"], 0, |vm, index, value| string_argument(vm, &value, name, index + 1))?.into_iter();
    let encoding = slots.next().flatten();
    let errors = slots.next().flatten();

    Ok(CodecArguments { encoding, errors })
}

fn decode<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let CodecArguments { encoding, errors } = codec_arguments(vm, args, "decode")?;
    let bytes = if T::UNICODE { codecs::encode_default(vm, &as_wide(units))?.as_bytes().to_vec() } else { as_narrow(units) };

    vm.decode_bytes(&bytes, encoding.as_deref(), errors.as_deref())
}

fn encode<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let CodecArguments { encoding, errors } = codec_arguments(vm, args, "encode")?;
    let Some(codec) = vm.native_codec(encoding.as_deref()) else {
        let name = encoding.as_deref().unwrap_or(b"ascii");
        let input = if T::UNICODE { Value::Unicode(PyText::new(as_wide(units))) } else { Value::Str(PyBytes::new(as_narrow(units))) };
        let encoded = code_with_registry(vm, name, input, errors.as_deref(), Direction::Encode)?;
        return vm.require_string_result(encoded, "encoder");
    };

    if T::UNICODE {
        return codecs::encode(vm, codec, &as_wide(units), errors.as_deref());
    }

    codecs::encode_bytes(vm, codec, &as_narrow(units), errors.as_deref())
}

fn format_method<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    format::format_method(vm, units, args)
}

/// `str.__format__` and `unicode.__format__`. An empty spec formats as
/// `str(self)` or `unicode(self)`, which honor overrides in subclasses.
fn format_spec_method(vm: &Vm, args: CallArgs, unicode: bool) -> PyResult<Value> {
    let owner = if unicode { "unicode" } else { "str" };
    let (receiver, args) = receiver(vm, args, "__format__")?;
    if receiver.is_unknown() {
        return Ok(receiver);
    }
    let args = positional(vm, args, "__format__", 1, 1)?;
    let spec = &args[0];

    let empty = vm.as_str_bytes(spec).is_some_and(|bytes| bytes.as_bytes().is_empty()) || vm.as_text(spec).is_some_and(|text| text.units().is_empty());
    if unicode {
        let Some(text) = vm.as_text(&receiver) else {
            return Err(descriptor_mismatch(vm, "__format__", owner, &receiver));
        };
        if empty {
            return vm.to_unicode(&receiver);
        }
        return format::string_format_spec(vm, &receiver, text.units(), spec);
    }

    let Some(bytes) = vm.as_str_bytes(&receiver) else {
        return Err(descriptor_mismatch(vm, "__format__", owner, &receiver));
    };
    if empty {
        return vm.to_str(&receiver);
    }

    format::string_format_spec(vm, &receiver, bytes.as_bytes(), spec)
}

/// The argument of a method taking exactly one.
fn single_argument(vm: &Vm, mut args: CallArgs, name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    if args.positional.len() != 1 {
        return Err(vm.type_error(&format!("{name}() takes exactly one argument ({} given)", args.positional.len())));
    }

    Ok(args.positional.remove(0))
}

/// Arguments of a slot wrapper such as `__add__`. The sequence-repeat
/// wrappers report with a leading space.
fn slot_arguments(vm: &Vm, args: CallArgs, name: &str, expected: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("wrapper {name} doesn't take keyword arguments")));
    }
    if args.positional.len() != expected {
        let lead = if matches!(name, "__mul__" | "__rmul__") { " " } else { "" };
        return Err(vm.type_error(&format!("{lead}expected {expected} arguments, got {}", args.positional.len())));
    }

    Ok(args.positional)
}

fn slot_argument(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let mut args = slot_arguments(vm, args, name, 1)?;

    Ok(args.remove(0))
}

/// `self + other`.
fn add<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let other = slot_argument(vm, args, "__add__")?;

    // A `unicode` operand makes the result `unicode`.
    if !T::UNICODE && vm.as_text(&other).is_some() {
        let receiver = Value::Str(PyBytes::new(as_narrow(units)));
        if let Some(result) = vm.concatenate(&receiver, &other)? {
            return Ok(result);
        }
    }

    // A `bytearray` operand makes the result a `bytearray`.
    if !T::UNICODE
        && let Some(tail) = vm.as_bytearray(&other)
    {
        let mut joined = as_narrow(units);
        joined.extend_from_slice(&tail);
        return Ok(vm.new_bytearray(joined));
    }

    let tail = if T::UNICODE { T::coerce_buffer(vm, &other)? } else { T::coerce(vm, &other)? };
    let Some(tail) = tail else {
        if T::UNICODE {
            return Err(vm.type_error(&format!("coercing to Unicode: need string or buffer, {} found", vm.type_name(&other))));
        }
        return Err(vm.type_error(&format!("cannot concatenate 'str' and '{}' objects", vm.type_name(&other))));
    };

    let mut joined = units.to_vec();
    joined.extend_from_slice(&tail);

    // `str` allocates the result directly; `unicode` allocates it unshared.
    if T::UNICODE {
        return Ok(T::new_unshared_value(joined));
    }

    Ok(T::allocated_value(joined))
}

/// `self * count`: the count converts through `__index__`.
fn multiply<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let other = slot_argument(vm, args, "__mul__")?;
    if vm.as_float(&other).is_some() {
        return Err(vm.type_error(&format!("'{}' object cannot be interpreted as an index", vm.type_name(&other))));
    }
    let count = ssize_argument(vm, &other)?;

    let count = usize::try_from(count).unwrap_or(0);
    let Some(total) = units.len().checked_mul(count).and_then(|total| i64::try_from(total).ok()) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "repeated string is too long"));
    };
    check_size(vm, total)?;

    // `str` allocates the result directly; `unicode` allocates it unshared.
    if T::UNICODE {
        return Ok(T::new_unshared_value(units.repeat(count)));
    }

    Ok(T::allocated_value(units.repeat(count)))
}

fn modulo<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let other = slot_argument(vm, args, "__mod__")?;

    vm.format_percent(&plain(units), &other)
}

/// `__rmod__`: only a format of the same type applies.
fn reflected_modulo<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let other = slot_argument(vm, args, "__rmod__")?;
    let same_kind = if T::UNICODE { vm.as_text(&other).is_some() } else { vm.as_str_bytes(&other).is_some() };
    if !same_kind {
        return Ok(Value::NotImplemented);
    }

    vm.format_percent(&other, &plain(units))
}

fn getitem<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let index = slot_argument(vm, args, "__getitem__")?;

    vm.getitem(&plain(units), &index)
}

/// `__getslice__`: both bounds clamp into the string without wrapping.
fn getslice<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__getslice__", 2, 2)?;
    let length = units.len() as i64;
    let stop = ssize_argument(vm, &args[1])?.clamp(0, length);
    let start = ssize_argument(vm, &args[0])?.clamp(0, stop);

    Ok(plain(&units[start as usize..stop as usize]))
}

fn length<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    slot_arguments(vm, args, "__len__", 0)?;

    Ok(Value::Int(units.len() as i64))
}

fn contains<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    let item = slot_argument(vm, args, "__contains__")?;

    vm.contains(&plain(units), &item)
}

fn hash<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    slot_arguments(vm, args, "__hash__", 0)?;

    Ok(Value::Int(vm.hash(&plain(units))?.value()))
}

fn repr<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    slot_arguments(vm, args, "__repr__", 0)?;
    let text = if T::UNICODE { repr_unicode(&as_wide(units)) } else { repr_bytes(&as_narrow(units)) };

    Ok(Value::str(&text))
}

fn str_method<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    slot_arguments(vm, args, "__str__", 0)?;
    if !T::UNICODE {
        return Ok(plain(units));
    }

    Ok(Value::Str(codecs::encode_default(vm, &as_wide(units))?))
}

fn getnewargs<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "__getnewargs__")?;

    Ok(Value::tuple(vec![plain(units)]))
}

/// Rich comparison: other types are `NotImplemented`; a `str` that cannot
/// be decoded is unequal to any `unicode`.
fn compare<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs, name: &str, holds: fn(Ordering) -> bool) -> PyResult<Value> {
    let other = slot_argument(vm, args, name)?;

    let other_units = match T::coerce(vm, &other) {
        Ok(Some(other_units)) => other_units,
        Ok(None) => return Ok(Value::NotImplemented),
        Err(signal) if is_raised(vm, &signal, ExceptionKind::UnicodeDecodeError) => {
            return match name {
                "__eq__" => Ok(Value::Bool(false)),
                "__ne__" => Ok(Value::Bool(true)),
                _ => Err(signal),
            };
        }
        Err(signal) => return Err(signal),
    };

    Ok(Value::Bool(holds(units.cmp(&other_units[..]))))
}

fn equal<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__eq__", Ordering::is_eq)
}

fn not_equal<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__ne__", Ordering::is_ne)
}

fn less<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__lt__", Ordering::is_lt)
}

fn less_equal<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__le__", Ordering::is_le)
}

fn greater<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__gt__", Ordering::is_gt)
}

fn greater_equal<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    compare(vm, units, args, "__ge__", Ordering::is_ge)
}
