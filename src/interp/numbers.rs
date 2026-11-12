use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Signed;
use num_traits::ToPrimitive;
use num_traits::Zero;

use crate::interp::hash::LongWidth;

/// Inclusive range of the C `long` backing Python 2 `int`.
pub fn int_bounds(width: LongWidth) -> (i64, i64) {
    match width {
        LongWidth::Bits32 => (i64::from(i32::MIN), i64::from(i32::MAX)),
        LongWidth::Bits64 => (i64::MIN, i64::MAX),
    }
}

pub fn fits_int(width: LongWidth, value: i64) -> bool {
    let (low, high) = int_bounds(width);

    (low..=high).contains(&value)
}

/// Integer operand: either a machine `int` or an arbitrary-precision `long`.
#[derive(Clone, Debug)]
pub enum Integral {
    Int(i64),
    Long(BigInt),
}

impl Integral {
    pub fn to_bigint(&self) -> BigInt {
        match self {
            Self::Int(value) => BigInt::from(*value),
            Self::Long(value) => value.clone(),
        }
    }

    pub fn is_long(&self) -> bool {
        matches!(self, Self::Long(_))
    }

    /// The value clamped to the `i64` range, as an index conversion that
    /// does not raise on overflow clamps to the platform size.
    pub fn saturating_i64(&self) -> i64 {
        match self {
            Self::Int(value) => *value,
            Self::Long(value) => value.to_i64().unwrap_or(if value.is_negative() { i64::MIN } else { i64::MAX }),
        }
    }

    /// The value when it fits an `i64` (the size type on x64).
    pub fn to_i64(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::Long(value) => value.to_i64(),
        }
    }
}

/// Floor division and modulo with Python sign rules. `None` on division by
/// zero.
pub fn floor_divmod(left: &BigInt, right: &BigInt) -> Option<(BigInt, BigInt)> {
    if right.is_zero() {
        return None;
    }

    Some(left.div_mod_floor(right))
}

/// Python float modulo: the result takes the sign of the divisor.
pub fn float_mod(left: f64, right: f64) -> f64 {
    let modulo = left % right;

    if modulo != 0.0 && ((right < 0.0) != (modulo < 0.0)) {
        return modulo + right;
    }

    if modulo == 0.0 {
        return 0.0f64.copysign(right);
    }

    modulo
}

pub fn float_floor_div(left: f64, right: f64) -> f64 {
    let modulo = left % right;
    let mut division = (left - modulo) / right;

    if modulo != 0.0 && ((right < 0.0) != (modulo < 0.0)) {
        division -= 1.0;
    }

    if division == 0.0 {
        return 0.0f64.copysign(left / right);
    }

    let floored = division.floor();
    if division - floored > 0.5 {
        return floored + 1.0;
    }

    floored
}

pub fn bigint_to_f64(value: &BigInt) -> Option<f64> {
    let converted = value.to_f64()?;

    converted.is_finite().then_some(converted)
}

/// `a / b` for integers as a correctly rounded float.
/// `None` when the result overflows. `b` must be nonzero.
pub fn true_divide(a: &BigInt, b: &BigInt) -> Option<f64> {
    /// Operands below 2**53 convert exactly, so one float division rounds
    /// correctly.
    const EXACT_BITS: u64 = 53;

    if a.bits() <= EXACT_BITS && b.bits() <= EXACT_BITS {
        return Some(a.to_f64()? / b.to_f64()?);
    }

    let negative = (a.sign() == num_bigint::Sign::Minus) != (b.sign() == num_bigint::Sign::Minus);
    let numerator = num_bigint::BigInt::from(a.magnitude().clone());
    let denominator = num_bigint::BigInt::from(b.magnitude().clone());

    // Scale so the integer quotient carries 55 significant bits; the
    // remainder becomes a sticky bit so converting it to a float rounds
    // once, correctly.
    let shift = numerator.bits() as i64 - denominator.bits() as i64 - 55;
    let (scaled_numerator, scaled_denominator) = if shift >= 0 { (numerator, denominator << shift as usize) } else { (numerator << (-shift) as usize, denominator) };
    let (quotient, remainder) = scaled_numerator.div_mod_floor(&scaled_denominator);
    let sticky = if remainder.is_zero() { quotient } else { quotient | num_bigint::BigInt::from(1) };

    let magnitude = sticky.to_f64()? * 2f64.powi(i32::try_from(shift).ok()?);
    if !magnitude.is_finite() {
        return None;
    }

    Some(if negative { -magnitude } else { magnitude })
}

/// Parses a float literal as `float()` and `atof` accept it.
pub fn parse_float_literal(text: &str) -> Option<f64> {
    let trimmed = text.trim();
    let lowered = trimmed.to_ascii_lowercase();

    match lowered.trim_start_matches(['+', '-']) {
        "inf" | "infinity" => return Some(if lowered.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY }),
        "nan" => return Some(if lowered.starts_with('-') { -PY_NAN } else { PY_NAN }),
        _ => {}
    }

    trimmed.parse::<f64>().ok()
}

/// Shortest round-trip digits and decimal exponent of a finite, nonzero
/// float: `value = 0.d1d2... * 10^exponent`.
fn shortest_digits(value: f64) -> (String, i32) {
    let formatted = format!("{:e}", value.abs());
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);

    (digits, exponent + 1)
}

/// Digits of `value` rounded to `precision` significant digits.
fn rounded_digits(value: f64, precision: usize) -> (String, i32) {
    let formatted = format!("{:.*e}", precision.saturating_sub(1), value.abs());
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);

    (digits, exponent + 1)
}

fn special_float(value: f64) -> Option<String> {
    if value.is_nan() {
        return Some("nan".to_owned());
    }

    if value.is_infinite() {
        return Some(if value < 0.0 { "-inf" } else { "inf" }.to_owned());
    }

    None
}

/// Lays out digits as CPython's float formatting does: positional when the
/// decimal exponent is in `(-4, threshold]`, scientific otherwise.
fn layout_digits(negative: bool, digits: &str, exponent: i32, threshold: i32, keep_point_zero: bool, minimum_digits: usize) -> String {
    let mut output = String::new();
    if negative {
        output.push('-');
    }

    let mut digits = digits.trim_end_matches('0').to_owned();
    if digits.is_empty() {
        digits.push('0');
    }
    while digits.len() < minimum_digits {
        digits.push('0');
    }

    if exponent > -4 && exponent <= threshold {
        if exponent <= 0 {
            output.push_str("0.");
            output.push_str(&"0".repeat(exponent.unsigned_abs() as usize));
            output.push_str(&digits);
        } else {
            let exponent = exponent as usize;
            if digits.len() <= exponent {
                output.push_str(&digits);
                output.push_str(&"0".repeat(exponent - digits.len()));
                if keep_point_zero {
                    output.push_str(".0");
                }
            } else {
                output.push_str(&digits[..exponent]);
                output.push('.');
                output.push_str(&digits[exponent..]);
            }
        }
        return output;
    }

    output.push_str(&digits[..1]);
    if digits.len() > 1 {
        output.push('.');
        output.push_str(&digits[1..]);
    }
    let shown = exponent - 1;
    output.push('e');
    output.push(if shown < 0 { '-' } else { '+' });
    output.push_str(&format!("{:02}", shown.unsigned_abs()));

    output
}

/// `repr(float)` in Python 2.7: shortest round-trip digits, scientific
/// notation outside `1e-4 <= |x| < 1e16`.
pub fn float_repr(value: f64) -> String {
    if let Some(special) = special_float(value) {
        return special;
    }

    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }

    let (digits, exponent) = shortest_digits(value);

    layout_digits(value < 0.0, &digits, exponent, 16, true, 0)
}

/// CPython's NaN, computed as infinity times zero at run time: the x86
/// default NaN, sign bit set.
pub const PY_NAN: f64 = f64::from_bits(0xfff8_0000_0000_0000);

/// `repr` digits without
/// the `.0` an integral `float` repr gains.
pub fn float_repr_plain(value: f64) -> String {
    if let Some(special) = special_float(value) {
        return special;
    }

    if value == 0.0 {
        return if value.is_sign_negative() { "-0" } else { "0" }.to_owned();
    }

    let (digits, exponent) = shortest_digits(value);

    layout_digits(value < 0.0, &digits, exponent, 16, false, 0)
}

/// `str(float)` in Python 2.7: 12 significant digits, with `.0` added to
/// integral results.
pub fn float_str(value: f64) -> String {
    format_general_dot_zero(value, 12)
}

/// `%g` with `.0` added to integral results, as `str(float)`
/// and a format spec without a type use it: the exponent appears from
/// `precision` integer digits on, and an integral result gains `.0`.
pub fn format_general_dot_zero(value: f64, precision: usize) -> String {
    if let Some(special) = special_float(value) {
        return special;
    }

    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }

    let precision = precision.max(1);
    let (digits, exponent) = rounded_digits(value, precision);

    layout_digits(value < 0.0, &digits, exponent, precision as i32 - 1, true, 0)
}

/// `%g`-style formatting with the given precision. `alternate` keeps
/// trailing zeros and always shows a decimal point (`%#g`).
pub fn format_general(value: f64, precision: usize, alternate: bool, upper: bool) -> String {
    if let Some(special) = special_float(value) {
        return if upper { special.to_uppercase() } else { special };
    }

    let precision = precision.max(1);

    if value == 0.0 {
        let mut text = if value.is_sign_negative() { "-0".to_owned() } else { "0".to_owned() };
        if alternate {
            text.push('.');
            text.push_str(&"0".repeat(precision - 1));
        }
        return text;
    }

    let (digits, exponent) = rounded_digits(value, precision);
    let minimum = if alternate { precision } else { 0 };
    let mut text = layout_digits(value < 0.0, &digits, exponent, precision as i32, false, minimum);
    if alternate && !text.contains('.') {
        let mantissa_end = text.find('e').unwrap_or(text.len());
        text.insert(mantissa_end, '.');
    }

    if upper { text.to_uppercase() } else { text }
}

/// `%f`-style fixed formatting.
pub fn format_fixed(value: f64, precision: usize, upper: bool) -> String {
    if let Some(special) = special_float(value) {
        return if upper { special.to_uppercase() } else { special };
    }

    format!("{value:.precision$}")
}

/// `%e`-style formatting with a two-digit minimum exponent.
pub fn format_exponent(value: f64, precision: usize, upper: bool) -> String {
    if let Some(special) = special_float(value) {
        return if upper { special.to_uppercase() } else { special };
    }

    let formatted = format!("{value:.precision$e}");
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((&formatted, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let marker = if upper { 'E' } else { 'e' };

    format!("{mantissa}{marker}{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.unsigned_abs())
}

/// Parses an integer literal the way `int(text, base)` does.
pub fn parse_int_literal(text: &str, base: u32) -> Option<BigInt> {
    let trimmed = text.trim();
    let (negative, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let unsigned = unsigned.trim_end_matches(['l', 'L']);

    let (base, body) = match base {
        0 => {
            let lowered = unsigned.to_ascii_lowercase();
            if let Some(rest) = lowered.strip_prefix("0x") {
                (16, rest.to_owned())
            } else if let Some(rest) = lowered.strip_prefix("0o") {
                (8, rest.to_owned())
            } else if let Some(rest) = lowered.strip_prefix("0b") {
                (2, rest.to_owned())
            } else if lowered.len() > 1 && lowered.starts_with('0') {
                (8, lowered[1..].to_owned())
            } else {
                (10, lowered)
            }
        }
        16 => (16, unsigned.to_ascii_lowercase().trim_start_matches("0x").to_owned()),
        8 => (8, unsigned.to_ascii_lowercase().trim_start_matches("0o").to_owned()),
        2 => (2, unsigned.to_ascii_lowercase().trim_start_matches("0b").to_owned()),
        other => (other, unsigned.to_owned()),
    };

    if body.is_empty() || body.contains('_') {
        return None;
    }

    let value = BigInt::parse_bytes(body.as_bytes(), base)?;

    Some(if negative { -value } else { value })
}

/// Integer power, or `None` when the exponent is negative.
pub fn int_pow(base: &BigInt, exponent: &BigInt) -> Option<BigInt> {
    if exponent.is_negative() {
        return None;
    }

    let exponent = exponent.to_u32()?;

    Some(num_traits::pow::Pow::pow(base, exponent))
}
