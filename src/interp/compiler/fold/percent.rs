//! `str % args` and `unicode % args` with constant arguments.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::fold::MAX_FOLDED_SIZE;
use crate::interp::compiler::fold::number::float_to_integer;
use crate::interp::compiler::fold::number::long_to_float;
use crate::interp::compiler::fold::sequence::coerce_unicode;
use crate::interp::compiler::fold::text::FloatCode;
use crate::interp::compiler::fold::text::FloatFormat;
use crate::interp::compiler::fold::text::format_float;
use crate::interp::compiler::fold::text::prefixed_radix;
use crate::interp::compiler::fold::text::repr;
use crate::interp::compiler::fold::text::str;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::object::StrObject;
use crate::interp::hash::LongWidth;

const LEFT_JUSTIFY: u8 = 1 << 0;
const SIGN: u8 = 1 << 1;
const BLANK: u8 = 1 << 2;
const ALTERNATE: u8 = 1 << 3;
const ZERO: u8 = 1 << 4;

/// One conversion specification after `%`.
struct Spec {
    flags: u8,
    width: Option<i64>,
    precision: Option<i32>,
    conversion: u32,
}

/// The values conversions consume: the items of a tuple in turn, or any
/// other object once.
#[derive(Clone)]
enum Arguments<'a> {
    Tuple { items: &'a [Object], next: usize },
    Single { value: &'a Object, used: bool },
}

impl<'a> Arguments<'a> {
    fn new(args: &'a Object) -> Self {
        match args {
            Object::Tuple(items) => Self::Tuple { items, next: 0 },
            _ => Self::Single { value: args, used: false },
        }
    }

    fn next(&mut self) -> Option<&'a Object> {
        match self {
            Self::Tuple { items, next } => {
                let item = items.get(*next)?;
                *next += 1;

                Some(item)
            }
            Self::Single { value, used } => {
                if *used {
                    return None;
                }

                *used = true;

                Some(*value)
            }
        }
    }

    fn all_used(&self) -> bool {
        match self {
            Self::Tuple { items, next } => *next >= items.len(),
            Self::Single { used, .. } => *used,
        }
    }

    /// The arguments not consumed yet, as the right operand of a new `%`.
    fn remaining(&self, args: &Object) -> Option<Object> {
        match self {
            Self::Tuple { items, next } if *next > 0 => Some(Object::Tuple(items.get(*next..)?.iter().cloned().collect())),
            Self::Tuple { .. } | Self::Single { .. } => Some(args.clone()),
        }
    }
}

/// A converted value before padding.
struct Field<T> {
    body: Vec<T>,
    /// Numeric conversions keep a sign ahead of zero padding and may pad
    /// with zeros.
    numeric: bool,
    zero_fill: bool,
}

impl<T> Field<T> {
    fn text(body: Vec<T>) -> Self {
        Self { body, numeric: false, zero_fill: false }
    }

    fn number(body: Vec<T>, flags: u8) -> Self {
        Self { body, numeric: true, zero_fill: flags & ZERO != 0 }
    }
}

/// What one conversion produced.
enum Converted<T> {
    Field(Field<T>),
    /// A `str` format met a `unicode` argument for `%s` or `%c`, so the
    /// rest of it is formatted as `unicode`.
    Unicode,
}

/// The result of a format, or the point where it continues as `unicode`.
enum Formatted<'f, 'a, T> {
    Done(Vec<T>),
    Unicode {
        output: Vec<T>,
        /// The format from the `%` of the conversion that switched.
        rest: &'f [T],
        /// The arguments as they were before that conversion.
        arguments: Arguments<'a>,
    },
}

/// Reads a format one unit at a time.
struct Reader<'f, T> {
    units: &'f [T],
    position: usize,
}

impl<T> Reader<'_, T>
where
    T: Copy + Into<u32>,
{
    fn peek(&self) -> Option<u32> {
        self.units.get(self.position).map(|&unit| unit.into())
    }

    fn next(&mut self) -> Option<u32> {
        let unit = self.peek()?;
        self.position += 1;

        Some(unit)
    }
}

/// `str % args`. An empty result is the interned empty string; any other
/// is a new object. Continues as `unicode % args` at the first `%s` or `%c`
/// whose argument is `unicode`.
pub(super) fn format_str(format: &Rc<StrObject>, args: &Object, context: &mut dyn CompileContext) -> Option<Object> {
    // Output length past which a format whose result may still turn into
    // `unicode` is treated as running out of memory.
    const MEMORY_LIMIT: usize = 1 << 20;

    let may_become_unicode = match args {
        Object::Tuple(items) => items.iter().any(|item| matches!(item, Object::Unicode(_))),
        other => matches!(other, Object::Unicode(_)),
    };
    let limit = if may_become_unicode { MEMORY_LIMIT } else { MAX_FOLDED_SIZE };
    let width = context.long_width();

    let formatted = format_units(&format.value, args, limit, |spec, conversion, value| {
        let field = match (conversion, value) {
            (b'%', _) => Field::text(b"%".to_vec()),
            (b's' | b'c', Some(Object::Unicode(_))) => return Some(Converted::Unicode),
            (b's', Some(value)) => Field::text(cut_to_precision(str(value)?, spec.precision)),
            (b'r', Some(value)) => Field::text(cut_to_precision(repr(value)?, spec.precision)),
            (b'i' | b'd' | b'u' | b'o' | b'x' | b'X', Some(value)) => Field::number(integer_conversion(value, spec, conversion, width, limit)?, spec.flags),
            (b'e' | b'E' | b'f' | b'F' | b'g' | b'G', Some(value)) => Field::number(float_conversion(value, spec, conversion, limit)?, spec.flags),
            (b'c', Some(value)) => Field::text(vec![str_char(value)?]),
            _ => return None,
        };

        Some(Converted::Field(field))
    })?;

    match formatted {
        Formatted::Done(output) => {
            let interned = output.is_empty();

            Some(Object::str(output, interned))
        }
        Formatted::Unicode { output, rest, arguments } => continue_as_unicode(&output, rest, &arguments.remaining(args)?, context),
    }
}

/// `unicode % args`.
pub(super) fn format_unicode(format: &[u16], args: &Object, context: &mut dyn CompileContext) -> Option<Object> {
    Some(Object::Unicode(unicode_units(format, args, context)?.into()))
}

/// Formats the rest of a `str` format, decoded, with the remaining
/// arguments, and decodes the `str` output so far in front of it.
fn continue_as_unicode(output: &[u8], rest: &[u8], args: &Object, context: &mut dyn CompileContext) -> Option<Object> {
    let rest = context.decode_default(rest)?;
    let formatted = unicode_units(&rest, args, context)?;
    let prefix = coerce_unicode(&Object::str(output.to_vec(), false), context)?;

    if formatted.is_empty() {
        return Some(Object::Unicode(prefix));
    }

    if prefix.len() + formatted.len() > MAX_FOLDED_SIZE {
        return None;
    }

    Some(Object::Unicode([&prefix[..], &formatted[..]].concat().into()))
}

fn unicode_units(format: &[u16], args: &Object, context: &mut dyn CompileContext) -> Option<Vec<u16>> {
    let width = context.long_width();
    let context = &*context;

    let formatted = format_units(format, args, MAX_FOLDED_SIZE, |spec, conversion, value| {
        let field = match (conversion, value) {
            (b'%', _) => Field::text(vec![u16::from(b'%')]),
            (b's', Some(Object::Unicode(units))) => Field::text(cut_to_precision(units.to_vec(), spec.precision)),
            (b's', Some(value @ Object::Str(_))) => Field::text(cut_to_precision(coerce_unicode(value, context)?.to_vec(), spec.precision)),
            (b's', Some(value)) => Field::text(cut_to_precision(decode(&str(value)?, context)?, spec.precision)),
            (b'r', Some(value)) => Field::text(cut_to_precision(decode(&repr(value)?, context)?, spec.precision)),
            (b'i' | b'd' | b'u' | b'o' | b'x' | b'X', Some(value)) => Field::number(widen(integer_conversion(value, spec, conversion, width, MAX_FOLDED_SIZE)?), spec.flags),
            (b'e' | b'E' | b'f' | b'F' | b'g' | b'G', Some(value)) => Field::number(widen(float_conversion(value, spec, conversion, MAX_FOLDED_SIZE)?), spec.flags),
            (b'c', Some(value)) => Field::text(vec![unicode_char(value, context)?]),
            _ => return None,
        };

        Some(Converted::Field(field))
    })?;

    match formatted {
        Formatted::Done(output) => Some(output),
        // Only `str` formats continue as `unicode`.
        Formatted::Unicode { .. } => None,
    }
}

/// Copies literal text and converts each specification with `convert`,
/// which gets the specification, its conversion character, and the
/// argument it consumes (none for `%%`). `None` where formatting raises,
/// including when arguments are left over, and once the output exceeds
/// `limit`.
fn format_units<'f, 'a, T>(
    format: &'f [T],
    args: &'a Object,
    limit: usize,
    mut convert: impl FnMut(&Spec, u8, Option<&'a Object>) -> Option<Converted<T>>,
) -> Option<Formatted<'f, 'a, T>>
where
    T: Copy + Into<u32> + From<u8> + PartialEq,
{
    let mut output = Vec::new();
    let mut arguments = Arguments::new(args);
    let mut rest = format;

    loop {
        let literal = rest.iter().position(|&unit| unit.into() == u32::from(b'%')).unwrap_or(rest.len());
        output.extend_from_slice(&rest[..literal]);
        if output.len() > limit {
            return None;
        }

        let Some(after_percent) = rest.get(literal + 1..) else {
            break;
        };

        let before = arguments.clone();
        let (spec, spec_length) = parse_spec(after_percent, &mut arguments)?;
        let conversion = u8::try_from(spec.conversion).ok()?;
        let value = if conversion == b'%' { None } else { Some(arguments.next()?) };

        match convert(&spec, conversion, value)? {
            Converted::Field(field) => pad(&mut output, &spec, field, limit)?,
            Converted::Unicode => return Some(Formatted::Unicode { output, rest: &rest[literal..], arguments: before }),
        }

        rest = after_percent.get(spec_length..)?;
    }

    if !arguments.all_used() {
        return None;
    }

    Some(Formatted::Done(output))
}

/// Parses the specification after a `%`, consuming the arguments of `*`
/// fields, and returns it with the number of units it spans. `None` where
/// formatting raises: an incomplete or oversized specification, a `*`
/// argument that is not an `int`, or `%(key)`, since no constant is a
/// mapping.
fn parse_spec<T>(units: &[T], arguments: &mut Arguments<'_>) -> Option<(Spec, usize)>
where
    T: Copy + Into<u32>,
{
    let mut reader = Reader { units, position: 0 };
    if reader.peek() == Some(u32::from(b'(')) {
        return None;
    }

    let mut flags = 0;
    let mut unit = reader.next()?;
    while let Some(flag) = flag_bit(unit) {
        flags |= flag;
        unit = reader.next()?;
    }

    let mut width = None;
    if unit == u32::from(b'*') {
        let mut value = int_argument(arguments)?;
        if value < 0 {
            flags |= LEFT_JUSTIFY;
            value = value.wrapping_neg();
        }

        width = Some(value);
        unit = reader.next()?;
    } else if let Some(first) = decimal_digit(unit) {
        let (value, after) = read_number(&mut reader, first)?;
        width = Some(value);
        unit = after;
    }

    let mut precision = None;
    if unit == u32::from(b'.') {
        unit = reader.next()?;
        let value = if unit == u32::from(b'*') {
            let value = i32::try_from(int_argument(arguments)?).ok()?.max(0);
            unit = reader.next()?;
            value
        } else if let Some(first) = decimal_digit(unit) {
            let (value, after) = read_number(&mut reader, first)?;
            unit = after;
            i32::try_from(value).ok()?
        } else {
            0
        };

        precision = Some(value);
    }

    // Length modifiers are accepted and ignored.
    if (*b"hlL").map(u32::from).contains(&unit) {
        unit = reader.next()?;
    }

    Some((Spec { flags, width, precision, conversion: unit }, reader.position))
}

fn flag_bit(unit: u32) -> Option<u8> {
    match u8::try_from(unit) {
        Ok(b'-') => Some(LEFT_JUSTIFY),
        Ok(b'+') => Some(SIGN),
        Ok(b' ') => Some(BLANK),
        Ok(b'#') => Some(ALTERNATE),
        Ok(b'0') => Some(ZERO),
        _ => None,
    }
}

fn decimal_digit(unit: u32) -> Option<i64> {
    char::from_u32(unit)?.to_digit(10).map(i64::from)
}

/// The decimal number starting with `first`, and the unit after it.
fn read_number<T>(reader: &mut Reader<'_, T>, first: i64) -> Option<(i64, u32)>
where
    T: Copy + Into<u32>,
{
    let mut value = first;
    loop {
        let unit = reader.next()?;
        let Some(digit) = decimal_digit(unit) else {
            return Some((value, unit));
        };

        value = value.checked_mul(10)?.checked_add(digit)?;
    }
}

/// The value of a `*` width or precision, which must be an `int`.
fn int_argument(arguments: &mut Arguments<'_>) -> Option<i64> {
    match arguments.next()? {
        Object::Int(value) => Some(*value),
        _ => None,
    }
}

/// Appends a converted field with its sign, `0x` prefix, and padding.
/// `None` once the output exceeds `limit`.
fn pad<T>(output: &mut Vec<T>, spec: &Spec, field: Field<T>, limit: usize) -> Option<()>
where
    T: Copy + From<u8> + PartialEq,
{
    let Field { body, numeric, zero_fill } = field;
    let mut body = body.as_slice();

    let mut sign = None;
    if numeric {
        match body.first() {
            Some(&first) if first == T::from(b'-') || first == T::from(b'+') => {
                sign = Some(first);
                body = body.get(1..)?;
            }
            _ if spec.flags & SIGN != 0 => sign = Some(T::from(b'+')),
            _ if spec.flags & BLANK != 0 => sign = Some(T::from(b' ')),
            _ => {}
        }
    }

    let length = body.len() as i64;
    let width = spec.width.map_or(length, |width| width.max(length));
    if width > limit as i64 {
        return None;
    }

    let mut padding = width - length;
    if sign.is_some() && padding > 0 {
        padding -= 1;
    }
    let padding = usize::try_from(padding).ok()?;

    let is_hex = spec.conversion == u32::from(b'x') || spec.conversion == u32::from(b'X');
    let (prefix, digits) = if spec.flags & ALTERNATE != 0 && is_hex { body.split_at_checked(2)? } else { (&[][..], body) };

    let left_justify = spec.flags & LEFT_JUSTIFY != 0;
    if zero_fill {
        output.extend(sign);
        output.extend_from_slice(prefix);
        if !left_justify {
            output.extend(std::iter::repeat_n(T::from(b'0'), padding));
        }
    } else {
        if !left_justify {
            output.extend(std::iter::repeat_n(T::from(b' '), padding));
        }
        output.extend(sign);
        output.extend_from_slice(prefix);
    }

    output.extend_from_slice(digits);
    if left_justify {
        output.extend(std::iter::repeat_n(T::from(b' '), padding));
    }

    if output.len() > limit {
        return None;
    }

    Some(())
}

/// `%s` and `%r` keep at most `precision` characters.
fn cut_to_precision<T>(mut body: Vec<T>, precision: Option<i32>) -> Vec<T> {
    if let Some(precision) = precision.and_then(|precision| usize::try_from(precision).ok()) {
        body.truncate(precision);
    }

    body
}

fn widen(text: Vec<u8>) -> Vec<u16> {
    text.into_iter().map(u16::from).collect()
}

/// Decodes with the default encoding.
fn decode(text: &[u8], context: &dyn CompileContext) -> Option<Vec<u16>> {
    if text.is_empty() {
        return Some(Vec::new());
    }

    context.decode_default(text)
}

/// The integer conversions, with `%i` read as `%d`. Floats are truncated
/// to an integer first.
fn integer_conversion(value: &Object, spec: &Spec, conversion: u8, width: LongWidth, limit: usize) -> Option<Vec<u8>> {
    let conversion = if conversion == b'i' { b'd' } else { conversion };
    let integer = match value {
        Object::Int(_) | Object::Long(_) => value.clone(),
        Object::Float(value) => float_to_integer(*value, width)?,
        _ => return None,
    };

    match integer {
        Object::Int(value) => int_conversion(value, spec.flags, spec.precision, conversion),
        Object::Long(value) => long_conversion(&value, spec.flags, spec.precision, conversion, limit),
        _ => None,
    }
}

/// An `int` as C `printf` writes `%[#].<precision>l<conversion>`, except
/// that `%#x` and `%#X` get Python's `0x` and `0X` prefixes.
fn int_conversion(value: i64, flags: u8, precision: Option<i32>, conversion: u8) -> Option<Vec<u8>> {
    // A larger precision raises OverflowError.
    const MAX_PRECISION: i64 = 116;

    let conversion = if value < 0 && conversion == b'u' { b'd' } else { conversion };
    let precision = i64::from(precision.unwrap_or(1));
    if precision > MAX_PRECISION {
        return None;
    }

    // A negative value is written as `-` and its magnitude, which also
    // covers the smallest `int`.
    let magnitude = value.unsigned_abs();
    let mut digits = match conversion {
        b'o' => format!("{magnitude:o}"),
        b'x' => format!("{magnitude:x}"),
        b'X' => format!("{magnitude:X}"),
        _ => magnitude.to_string(),
    }
    .into_bytes();
    if precision == 0 && magnitude == 0 {
        digits.clear();
    }

    let padding = usize::try_from(precision).ok()?.saturating_sub(digits.len());
    let mut text = Vec::new();
    if value < 0 {
        text.push(b'-');
    }

    let alternate = flags & ALTERNATE != 0;
    match conversion {
        b'x' if alternate => text.extend_from_slice(b"0x"),
        b'X' if alternate => text.extend_from_slice(b"0X"),
        b'o' if alternate && padding == 0 && digits.first().is_some_and(|digit| *digit != b'0') => text.push(b'0'),
        _ => {}
    }

    text.extend(std::iter::repeat_n(b'0', padding));
    text.extend(digits);

    Some(text)
}

/// A `long` in the requested base, with the `0x` or octal `0` prefix only
/// under `#`, and zeros up to `precision` digits.
fn long_conversion(value: &BigInt, flags: u8, precision: Option<i32>, conversion: u8, limit: usize) -> Option<Vec<u8>> {
    let text = match conversion {
        b'o' => prefixed_radix(value, 8),
        b'x' | b'X' => prefixed_radix(value, 16),
        _ => value.to_string().into_bytes(),
    };

    let sign = usize::from(text.first() == Some(&b'-'));
    let alternate = flags & ALTERNATE != 0;
    let mut kept_prefix = sign;
    let mut dropped_prefix = 0;
    match conversion {
        b'o' if !alternate && text.len() - sign > 1 => dropped_prefix = 1,
        b'x' | b'X' if alternate => kept_prefix += 2,
        b'x' | b'X' => dropped_prefix = 2,
        _ => {}
    }

    let digits = text.get(kept_prefix + dropped_prefix..)?;
    let precision = usize::try_from(precision.unwrap_or(-1)).unwrap_or(0);
    let zeros = precision.saturating_sub(digits.len());
    if zeros > limit {
        return None;
    }

    let mut result = text.get(..kept_prefix)?.to_vec();
    result.extend(std::iter::repeat_n(b'0', zeros));
    result.extend_from_slice(digits);
    if conversion == b'X' {
        result.make_ascii_uppercase();
    }

    Some(result)
}

/// The float conversions. `int` and `long` values are converted to float
/// first.
fn float_conversion(value: &Object, spec: &Spec, conversion: u8, limit: usize) -> Option<Vec<u8>> {
    let value = match value {
        Object::Float(value) => *value,
        Object::Int(value) => *value as f64,
        Object::Long(value) => long_to_float(value)?,
        _ => return None,
    };

    let precision = usize::try_from(spec.precision.unwrap_or(6)).ok()?;
    let alternate = spec.flags & ALTERNATE != 0;
    let code = match conversion.to_ascii_lowercase() {
        b'e' => FloatCode::Exponent,
        b'f' => FloatCode::Fixed,
        _ => FloatCode::General,
    };

    // These codes write at least `precision` digits.
    if precision > limit && (code != FloatCode::General || alternate) {
        return None;
    }

    let format = FloatFormat { upper: conversion.is_ascii_uppercase(), alternate, ..FloatFormat::new(code, precision) };

    Some(format_float(value, format))
}

/// `%c` in a `str` format: a one-byte `str`, or an integer in `range(256)`.
/// Floats are rejected.
fn str_char(value: &Object) -> Option<u8> {
    match value {
        Object::Str(object) if object.value.len() == 1 => object.value.first().copied(),
        Object::Int(_) | Object::Long(_) => u8::try_from(integer_value(value)?).ok(),
        _ => None,
    }
}

/// `%c` in a `unicode` format on a narrow build: a one-unit `unicode`, a
/// one-byte `str` (decoded when not ASCII), or a number in
/// `range(0x10000)`, floats truncated.
fn unicode_char(value: &Object, context: &dyn CompileContext) -> Option<u16> {
    match value {
        Object::Unicode(units) if units.len() == 1 => units.first().copied(),
        Object::Unicode(_) => None,
        Object::Str(object) => {
            let [byte] = object.value.as_slice() else {
                return None;
            };

            if *byte <= 0x7f {
                return Some(u16::from(*byte));
            }

            let decoded = context.decode_default(&[*byte])?;

            // A byte that decodes to nothing gives U+0000.
            Some(decoded.first().copied().unwrap_or(0))
        }
        Object::Float(number) => {
            let whole = number.trunc();
            if !(0.0..=65535.0).contains(&whole) {
                return None;
            }

            Some(whole as u16)
        }
        _ => u16::try_from(integer_value(value)?).ok(),
    }
}

fn integer_value(value: &Object) -> Option<i64> {
    match value {
        Object::Int(value) => Some(*value),
        Object::Long(value) => value.to_i64(),
        _ => None,
    }
}
