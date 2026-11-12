//! `repr()` and `str()` of constants, and float formatting.

use num_bigint::BigInt;
use num_traits::Signed;

use crate::interp::compiler::object::Object;
use crate::interp::complex::Complex;

/// How a float is written: like `%e`, `%f`, `%g`, or `repr()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FloatCode {
    Exponent,
    Fixed,
    General,
    Repr,
}

/// How to write a float.
#[derive(Clone, Copy, Debug)]
pub(super) struct FloatFormat {
    pub code: FloatCode,
    /// `E`, `F`, or `G`: `INF`, `NAN`, and `E` in upper case.
    pub upper: bool,
    pub precision: usize,
    /// A `+` before nonnegative values.
    pub always_sign: bool,
    /// An integral value keeps a `.0`, as `repr()` and `str()` write it.
    pub point_zero: bool,
    /// The `#` flag: keep the point and trailing zeros.
    pub alternate: bool,
}

impl FloatFormat {
    pub fn new(code: FloatCode, precision: usize) -> Self {
        Self { code, upper: false, precision, always_sign: false, point_zero: false, alternate: false }
    }
}

/// The decimal digits of a finite double: the value is
/// `0.digits * 10**decimal_point`, without trailing zeros.
struct Digits {
    digits: Vec<u8>,
    decimal_point: i64,
}

/// Which digits `decimal_digits` produces.
#[derive(Clone, Copy)]
enum DigitMode {
    /// The shortest string that reads back as the value.
    Shortest,
    /// This many significant digits.
    Significant(usize),
    /// This many digits after the decimal point.
    Fixed(usize),
}

/// `repr()`. `None` for code objects, whose repr holds an address and
/// which `MAKE_FUNCTION` always consumes before an operation could fold
/// them.
pub(super) fn repr(object: &Object) -> Option<Vec<u8>> {
    stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || match object {
        Object::None => Some(b"None".to_vec()),
        Object::Ellipsis => Some(b"Ellipsis".to_vec()),
        Object::Int(value) => Some(value.to_string().into_bytes()),
        Object::Long(value) => {
            let mut text = value.to_string().into_bytes();
            text.push(b'L');
            Some(text)
        }
        Object::Float(value) => {
            let format = FloatFormat { point_zero: true, ..FloatFormat::new(FloatCode::Repr, 0) };
            Some(format_float(*value, format))
        }
        Object::Complex(value) => Some(complex_text(*value, FloatCode::Repr, 0)),
        Object::Str(object) => Some(repr_str(&object.value)),
        Object::Unicode(units) => Some(repr_unicode(units)),
        Object::Tuple(items) => repr_tuple(items),
        Object::Code(_) => None,
    })
}

/// `str()`. `None` for code objects (see `repr`) and for `unicode`, which
/// `str()` would encode with the default encoding; both `%` formatters
/// switch to `unicode` formatting before they could ask for that.
pub(super) fn str(object: &Object) -> Option<Vec<u8>> {
    match object {
        Object::Str(object) => Some(object.value.clone()),
        Object::Long(value) => Some(value.to_string().into_bytes()),
        Object::Float(value) => {
            let format = FloatFormat { point_zero: true, ..FloatFormat::new(FloatCode::General, 12) };
            Some(format_float(*value, format))
        }
        Object::Complex(value) => Some(complex_text(*value, FloatCode::General, 12)),
        Object::Unicode(_) => None,
        Object::None | Object::Ellipsis | Object::Int(_) | Object::Tuple(_) | Object::Code(_) => repr(object),
    }
}

fn repr_tuple(items: &[Object]) -> Option<Vec<u8>> {
    let mut text = vec![b'('];
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            text.extend_from_slice(b", ");
        }

        text.extend(repr(item)?);
    }

    if items.len() == 1 {
        text.push(b',');
    }

    text.push(b')');

    Some(text)
}

/// Quoted with `"` when that avoids escaping a `'`.
fn repr_str(value: &[u8]) -> Vec<u8> {
    let quote = if value.contains(&b'\'') && !value.contains(&b'"') { b'"' } else { b'\'' };
    let mut text = vec![quote];

    for &byte in value {
        match byte {
            _ if byte == quote || byte == b'\\' => text.extend_from_slice(&[b'\\', byte]),
            b'\t' => text.extend_from_slice(b"\\t"),
            b'\n' => text.extend_from_slice(b"\\n"),
            b'\r' => text.extend_from_slice(b"\\r"),
            _ if !(b' '..0x7f).contains(&byte) => push_hex(&mut text, b'x', u32::from(byte), 2),
            _ => text.push(byte),
        }
    }

    text.push(quote);

    text
}

/// As a narrow (UTF-16) build writes it: surrogate pairs become `\U`
/// escapes, lone surrogates `\u` escapes.
fn repr_unicode(units: &[u16]) -> Vec<u8> {
    let quote = if units.contains(&u16::from(b'\'')) && !units.contains(&u16::from(b'"')) { b'"' } else { b'\'' };
    let mut text = vec![b'u', quote];
    let mut index = 0;

    while let Some(&unit) = units.get(index) {
        index += 1;

        if unit == u16::from(quote) || unit == u16::from(b'\\') {
            text.extend_from_slice(&[b'\\', unit as u8]);
            continue;
        }

        if (0xd800..0xdc00).contains(&unit)
            && let Some(&low) = units.get(index)
            && (0xdc00..=0xdfff).contains(&low)
        {
            index += 1;
            let code_point = ((u32::from(unit & 0x03ff) << 10) | u32::from(low & 0x03ff)) + 0x1_0000;
            push_hex(&mut text, b'U', code_point, 8);
            continue;
        }

        match unit {
            0x100.. => push_hex(&mut text, b'u', u32::from(unit), 4),
            0x09 => text.extend_from_slice(b"\\t"),
            0x0a => text.extend_from_slice(b"\\n"),
            0x0d => text.extend_from_slice(b"\\r"),
            _ if !(0x20..0x7f).contains(&unit) => push_hex(&mut text, b'x', u32::from(unit), 2),
            _ => text.push(unit as u8),
        }
    }

    text.push(quote);

    text
}

fn push_hex(text: &mut Vec<u8>, marker: u8, value: u32, digits: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    text.push(b'\\');
    text.push(marker);
    for position in (0..digits).rev() {
        text.push(HEX[((value >> (4 * position)) & 0xf) as usize]);
    }
}

/// The real part is omitted when it is `+0.0`.
fn complex_text(value: Complex, code: FloatCode, precision: usize) -> Vec<u8> {
    let format = FloatFormat::new(code, precision);

    if value.real == 0.0 && value.real.is_sign_positive() {
        let mut text = format_float(value.imag, format);
        text.push(b'j');
        return text;
    }

    let mut text = vec![b'('];
    text.extend(format_float(value.real, format));
    text.extend(format_float(value.imag, FloatFormat { always_sign: true, ..format }));
    text.extend_from_slice(b"j)");

    text
}

/// Writes a float. Callers bound the precision of the `Exponent` and
/// `Fixed` codes, whose output grows with it.
pub(super) fn format_float(value: f64, format: FloatFormat) -> Vec<u8> {
    let (exponent_marker, infinity, nan): (u8, &[u8], &[u8]) = if format.upper { (b'E', b"INF", b"NAN") } else { (b'e', b"inf", b"nan") };
    let mut text = Vec::new();

    if !value.is_finite() {
        let negative = value.is_sign_negative() && !value.is_nan();
        if negative {
            text.push(b'-');
        } else if format.always_sign {
            text.push(b'+');
        }

        text.extend_from_slice(if value.is_nan() { nan } else { infinity });
        return text;
    }

    let precision = i64::try_from(format.precision).unwrap_or(i64::MAX);
    let mode = match format.code {
        FloatCode::Exponent => DigitMode::Significant(format.precision.saturating_add(1)),
        FloatCode::Fixed => DigitMode::Fixed(format.precision),
        FloatCode::General => DigitMode::Significant(format.precision.max(1)),
        FloatCode::Repr => DigitMode::Shortest,
    };
    let Digits { digits, decimal_point } = decimal_digits(value, mode);
    let digits_len = digits.len() as i64;
    let mut decimal_point = decimal_point;

    let mut use_exponent = false;
    let mut digits_end = digits_len;
    match format.code {
        FloatCode::Exponent => {
            use_exponent = true;
            digits_end = precision.saturating_add(1);
        }
        FloatCode::Fixed => digits_end = decimal_point.saturating_add(precision),
        FloatCode::General => {
            let precision = precision.max(1);
            let threshold = if format.point_zero { precision - 1 } else { precision };
            if decimal_point <= -4 || decimal_point > threshold {
                use_exponent = true;
            }

            if format.alternate {
                digits_end = precision;
            }
        }
        FloatCode::Repr => {
            if decimal_point <= -4 || decimal_point > 16 {
                use_exponent = true;
            }
        }
    }

    let mut exponent = 0;
    if use_exponent {
        exponent = decimal_point - 1;
        decimal_point = 1;
    }

    let digits_start = if decimal_point <= 0 { decimal_point - 1 } else { 0 };
    let minimum_end = if !use_exponent && format.point_zero { decimal_point + 1 } else { decimal_point };
    let digits_end = digits_end.max(minimum_end);

    let zeros = |text: &mut Vec<u8>, count: i64| text.extend(std::iter::repeat_n(b'0', usize::try_from(count).unwrap_or(0)));

    if value.is_sign_negative() {
        text.push(b'-');
    } else if format.always_sign {
        text.push(b'+');
    }

    if decimal_point <= 0 {
        zeros(&mut text, decimal_point - digits_start);
        text.push(b'.');
        zeros(&mut text, -decimal_point);
    } else {
        zeros(&mut text, -digits_start);
    }

    match usize::try_from(decimal_point) {
        Ok(point) if point > 0 && point <= digits.len() => {
            text.extend_from_slice(&digits[..point]);
            text.push(b'.');
            text.extend_from_slice(&digits[point..]);
        }
        _ => text.extend_from_slice(&digits),
    }

    if digits_len < decimal_point {
        zeros(&mut text, decimal_point - digits_len);
        text.push(b'.');
        zeros(&mut text, digits_end - decimal_point);
    } else {
        zeros(&mut text, digits_end - digits_len);
    }

    if text.last() == Some(&b'.') && !format.alternate {
        text.pop();
    }

    if use_exponent {
        text.push(exponent_marker);
        text.push(if exponent < 0 { b'-' } else { b'+' });
        text.extend(format!("{:02}", exponent.unsigned_abs()).into_bytes());
    }

    text
}

/// The digits of a finite value. Rust's float formatting gives the digits
/// needed: the shortest round-trip digits closest to the value, and
/// correctly rounded (half to even) fixed-length digits.
fn decimal_digits(value: f64, mode: DigitMode) -> Digits {
    // A double has at most 767 significant decimal digits and 1074 digits
    // after the point; asking for more only appends zeros, which are
    // stripped below.
    const MAX_SIGNIFICANT: usize = 800;
    const MAX_FRACTION: usize = 1100;

    let magnitude = value.abs();
    if magnitude == 0.0 {
        return Digits { digits: vec![b'0'], decimal_point: 1 };
    }

    let (text, fixed) = match mode {
        DigitMode::Shortest => (format!("{magnitude:e}"), None),
        DigitMode::Significant(count) => (format!("{magnitude:.precision$e}", precision = count.clamp(1, MAX_SIGNIFICANT) - 1), None),
        DigitMode::Fixed(count) => (format!("{magnitude:.precision$}", precision = count.min(MAX_FRACTION)), Some(count)),
    };

    let mut digits = Vec::new();
    let mut decimal_point = 0i64;
    let mut seen_point = false;
    let mut exponent = 0i64;
    let mut exponent_negative = false;
    let mut in_exponent = false;
    for byte in text.bytes() {
        match byte {
            b'e' => in_exponent = true,
            b'-' if in_exponent => exponent_negative = true,
            b'0'..=b'9' if in_exponent => exponent = exponent * 10 + i64::from(byte - b'0'),
            b'0'..=b'9' => {
                digits.push(byte);
                if !seen_point {
                    decimal_point += 1;
                }
            }
            b'.' => seen_point = true,
            _ => {}
        }
    }

    if fixed.is_none() {
        // Scientific notation has one digit before the point.
        decimal_point = 1 + if exponent_negative { -exponent } else { exponent };
    }

    let leading = digits.iter().take_while(|&&digit| digit == b'0').count();
    digits.drain(..leading);
    decimal_point -= leading as i64;

    let trailing = digits.iter().rev().take_while(|&&digit| digit == b'0').count();
    digits.truncate(digits.len() - trailing);

    if digits.is_empty() {
        // The value rounds to zero at this many places: no digits, with the
        // point that many places left of them.
        let count = fixed.unwrap_or(0);
        return Digits { digits, decimal_point: -i64::try_from(count).unwrap_or(i64::MAX) };
    }

    Digits { digits, decimal_point }
}

/// `hex()` or `oct()` of a `long` without the `L`: `0x1f`, `-0x1f`, `017`,
/// `0`.
pub(super) fn prefixed_radix(value: &BigInt, radix: u32) -> Vec<u8> {
    let mut text = Vec::new();
    if value.is_negative() {
        text.push(b'-');
    }

    let digits = value.magnitude().to_str_radix(radix).into_bytes();
    if radix == 16 {
        text.extend_from_slice(b"0x");
    } else if digits != b"0" {
        text.push(b'0');
    }

    text.extend(digits);

    text
}
