//! Text conversions of `int()`, `long()`, `float()`, `float.hex`, and
//! `float.fromhex`.

use num_bigint::BigInt;
use num_traits::Zero;

use crate::interp::numbers::PY_NAN;

/// Fraction bits of a double.
const FRACTION_BITS: u32 = 52;

/// The exponent bias of a double.
const EXPONENT_BIAS: i64 = 1023;

/// Why a string did not convert to a float.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatSyntax {
    /// Nothing at the start parsed (`could not convert string to float`).
    NoNumber,
    /// A number followed by other text (`invalid literal for float()`).
    TrailingText,
}

/// Why `float.fromhex` rejected its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexFloatError {
    Invalid,
    Overflow,
}

/// The digits and exponent of a hexadecimal float literal.
struct HexLiteral {
    /// Every hex digit, integer and fraction parts together.
    digits: Vec<u8>,
    /// The power of two the digits, read as an integer, are scaled by.
    scale: i64,
}

impl HexLiteral {
    /// Larger exponents than this overflow or underflow whatever the
    /// digits; clamping keeps the arithmetic in range.
    const EXPONENT_LIMIT: i64 = 1 << 53;

    fn parse(text: &[u8]) -> Option<Self> {
        let mut position = 0;
        if text.len() >= 2 && text[0] == b'0' && text[1].eq_ignore_ascii_case(&b'x') {
            position = 2;
        }

        let mut digits = Vec::new();
        let mut fraction_digits: i64 = 0;
        let mut seen_point = false;
        while let Some(&byte) = text.get(position) {
            if byte == b'.' && !seen_point {
                seen_point = true;
            } else if let Some(digit) = char::from(byte).to_digit(16) {
                digits.push(digit as u8);
                if seen_point {
                    fraction_digits += 1;
                }
            } else {
                break;
            }
            position += 1;
        }
        if digits.is_empty() {
            return None;
        }

        let mut exponent: i64 = 0;
        if matches!(text.get(position), Some(b'p' | b'P')) {
            position += 1;
            let negative = match text.get(position) {
                Some(b'-') => {
                    position += 1;
                    true
                }
                Some(b'+') => {
                    position += 1;
                    false
                }
                _ => false,
            };
            let exponent_start = position;
            while let Some(byte) = text.get(position).filter(|byte| byte.is_ascii_digit()) {
                exponent = (exponent * 10 + i64::from(byte - b'0')).min(Self::EXPONENT_LIMIT);
                position += 1;
            }
            if position == exponent_start {
                return None;
            }
            if negative {
                exponent = -exponent;
            }
        }
        if position != text.len() {
            return None;
        }

        let scale = exponent.saturating_sub(fraction_digits.saturating_mul(4));

        Some(Self { digits, scale })
    }

    /// Bit `index` of the digits read as an integer, counting from the
    /// least significant bit.
    fn bit(&self, index: i64) -> bool {
        let Ok(index) = usize::try_from(index) else {
            return false;
        };
        let nibble = index / 4;
        let Some(position) = self.digits.len().checked_sub(nibble + 1) else {
            return false;
        };

        (self.digits[position] >> (index % 4)) & 1 == 1
    }

    /// Whether any bit below `index` is set.
    fn any_below(&self, index: i64) -> bool {
        if index <= 0 {
            return false;
        }
        let whole_nibbles = (index / 4) as usize;
        let length = self.digits.len();
        let low_digits = &self.digits[length.saturating_sub(whole_nibbles)..];
        if low_digits.iter().any(|digit| *digit != 0) {
            return true;
        }

        (whole_nibbles as i64 * 4..index).any(|bit| self.bit(bit))
    }

    fn to_double(&self) -> Result<f64, HexFloatError> {
        const PRECISION: i64 = 53;
        const MIN_NORMAL_EXPONENT: i64 = -1022;
        const MAX_EXPONENT: i64 = 1023;

        let Some(leading) = self.digits.iter().position(|digit| *digit != 0) else {
            return Ok(0.0);
        };
        let top_digit = self.digits[leading];
        let top_bit = (self.digits.len() - leading - 1) as i64 * 4 + i64::from(u8::BITS - 1 - top_digit.leading_zeros());

        // The exponent of the leading bit; values with it beyond the
        // largest finite exponent overflow even before rounding.
        let exponent = top_bit.saturating_add(self.scale);
        if exponent > MAX_EXPONENT {
            return Err(HexFloatError::Overflow);
        }

        // Bits kept: all 53 for a normal result, fewer below the normal
        // range, where the last kept bit is worth the smallest subnormal.
        let kept = PRECISION.min(exponent - (MIN_NORMAL_EXPONENT - PRECISION + 1) + 1);
        if kept < 0 {
            return Ok(0.0);
        }

        let mut mantissa: u64 = 0;
        for offset in 0..kept {
            mantissa = (mantissa << 1) | u64::from(self.bit(top_bit - offset));
        }
        let round_bit = top_bit - kept;
        let half = self.bit(round_bit);
        let sticky = self.any_below(round_bit);
        if half && (sticky || mantissa & 1 == 1) {
            mantissa += 1;
        }

        let mut exponent = exponent;
        if mantissa >> kept != 0 {
            exponent += 1;
            if kept == PRECISION {
                mantissa >>= 1;
            }
        }
        if exponent > MAX_EXPONENT {
            return Err(HexFloatError::Overflow);
        }

        if kept < PRECISION {
            return Ok(f64::from_bits(mantissa));
        }

        let biased = (exponent + EXPONENT_BIAS) as u64;

        Ok(f64::from_bits((biased << FRACTION_BITS) | (mantissa & ((1 << FRACTION_BITS) - 1))))
    }
}

/// Whitespace as the C library classifies it in the "C" locale.
pub fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

fn skip_space(text: &[u8], mut position: usize) -> usize {
    while text.get(position).is_some_and(|byte| is_space(*byte)) {
        position += 1;
    }

    position
}

/// The value of a digit in radixes up to 36, or `None` for any other byte.
fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'Z' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

/// The radix of the digits at `position` and where they begin. A `0x`,
/// `0o`, or `0b` prefix (any case) is skipped when it names `base`; with
/// `base` 0 it selects the radix, a zero without one selects octal, and
/// anything else decimal.
fn digits_radix(text: &[u8], position: usize, base: u32) -> (u32, usize) {
    if text.get(position) != Some(&b'0') {
        return (if base == 0 { 10 } else { base }, position);
    }

    let prefixed = match text.get(position + 1).map(u8::to_ascii_lowercase) {
        Some(b'x') => Some(16),
        Some(b'o') => Some(8),
        Some(b'b') => Some(2),
        _ => None,
    };

    match (base, prefixed) {
        (0, Some(radix)) => (radix, position + 2),
        (0, None) => (8, position),
        (base, Some(radix)) if radix == base => (base, position + 2),
        (base, _) => (base, position),
    }
}

/// The digits of `radix` at `position` and the position after them;
/// `None` when there are none.
fn read_digits(text: &[u8], mut position: usize, radix: u32) -> Option<(BigInt, usize)> {
    let start = position;
    let mut value = BigInt::zero();
    while let Some(digit) = text.get(position).and_then(|byte| digit_value(*byte)).filter(|digit| *digit < radix) {
        value = value * radix + digit;
        position += 1;
    }

    (position > start).then_some((value, position))
}

/// An optional sign and the whitespace after it; whether it was `-`.
fn read_sign(text: &[u8], position: usize) -> (bool, usize) {
    match text.get(position) {
        Some(b'-') => (true, skip_space(text, position + 1)),
        Some(b'+') => (false, skip_space(text, position + 1)),
        _ => (false, position),
    }
}

/// `int(text, base)`: whitespace, an optional sign, a radix prefix, the
/// digits, and whitespace. `None` for an invalid literal. `base` is 0 or
/// in `2..=36`.
pub fn int_from_bytes(text: &[u8], base: u32) -> Option<BigInt> {
    let (negative, position) = read_sign(text, skip_space(text, 0));
    let (radix, position) = digits_radix(text, position, base);
    let (value, position) = read_digits(text, position, radix)?;

    if skip_space(text, position) != text.len() {
        return None;
    }

    Some(if negative { -value } else { value })
}

/// `long(text, base)`: as `int`, with an optional `L` suffix. On failure,
/// the radix the error message reports, which `base` 0 resolves from the
/// prefix.
pub fn long_from_bytes(text: &[u8], base: u32) -> Result<BigInt, u32> {
    let (negative, position) = read_sign(text, skip_space(text, 0));
    let (radix, position) = digits_radix(text, position, base);
    let Some((value, mut position)) = read_digits(text, position, radix) else {
        return Err(radix);
    };

    if matches!(text.get(position), Some(b'l' | b'L')) {
        position += 1;
    }
    if skip_space(text, position) != text.len() {
        return Err(radix);
    }

    Ok(if negative { -value } else { value })
}

/// `float(text)`: the value, or the error and the offset of the text its
/// message quotes.
pub fn float_from_bytes(text: &[u8]) -> Result<f64, (FloatSyntax, usize)> {
    let start = skip_space(text, 0);
    let mut last = text.len();
    while last > start + 1 && is_space(text[last - 1]) {
        last -= 1;
    }

    let body = &text[start..last.max(start)];
    let Some((value, consumed)) = scan_float(body) else {
        return Err((FloatSyntax::NoNumber, start));
    };
    if consumed != body.len() {
        return Err((FloatSyntax::TrailingText, start));
    }

    Ok(value)
}

/// The longest decimal float at the start of `text`, else an infinity or
/// NaN spelling, with the length read. `None` when nothing parses.
pub fn scan_float(text: &[u8]) -> Option<(f64, usize)> {
    let digits = |from: usize| text[from..].iter().take_while(|byte| byte.is_ascii_digit()).count();

    let mut position = usize::from(matches!(text.first(), Some(b'+' | b'-')));
    let whole = digits(position);
    position += whole;
    let mut fraction = 0;
    if text.get(position) == Some(&b'.') {
        fraction = digits(position + 1);
        if whole + fraction > 0 {
            position += 1 + fraction;
        }
    }

    if whole + fraction == 0 {
        return scan_special(text);
    }

    if matches!(text.get(position), Some(b'e' | b'E')) {
        let mut exponent = position + 1;
        if matches!(text.get(exponent), Some(b'+' | b'-')) {
            exponent += 1;
        }
        let exponent_digits = digits(exponent);
        if exponent_digits > 0 {
            position = exponent + exponent_digits;
        }
    }

    let literal = std::str::from_utf8(&text[..position]).ok()?;

    Some((literal.parse::<f64>().ok()?, position))
}

/// A signed `inf`, `infinity`, or `nan` in any case at the start of
/// `text`.
fn scan_special(text: &[u8]) -> Option<(f64, usize)> {
    let negative = text.first() == Some(&b'-');
    let start = usize::from(matches!(text.first(), Some(b'+' | b'-')));
    let matches_at = |position: usize, word: &[u8]| text.get(position..position + word.len()).is_some_and(|slice| slice.eq_ignore_ascii_case(word));

    let (magnitude, end) = if matches_at(start, b"inf") {
        let end = if matches_at(start + 3, b"inity") { start + 8 } else { start + 3 };
        (f64::INFINITY, end)
    } else if matches_at(start, b"nan") {
        (PY_NAN, start + 3)
    } else {
        return None;
    };

    Some((if negative { -magnitude } else { magnitude }, end))
}

/// A mantissa in `[0.5, 1)` and a binary exponent; zero and non-finite
/// values come back unchanged with exponent 0.
pub fn frexp(value: f64) -> (f64, i32) {
    if value == 0.0 || !value.is_finite() {
        return (value, 0);
    }

    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    if exponent == 0 {
        let (mantissa, exponent) = frexp(value * 2f64.powi(54));
        return (mantissa, exponent - 54);
    }

    let mantissa = f64::from_bits((bits & !(0x7ff << 52)) | (1022 << 52));

    (mantissa, exponent - 1022)
}

/// `float.hex()` of a finite value: `[-]0x1.` and the thirteen fraction
/// digits for a normal value, `0x0.` and the digits with exponent -1022
/// for a subnormal one, and `0x0.0p+0` for zero.
pub fn float_hex(value: f64) -> String {
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0x0.0p+0");
    }

    let bits = value.to_bits();
    let fraction = bits & ((1 << FRACTION_BITS) - 1);
    let biased = ((bits >> FRACTION_BITS) & 0x7ff) as i64;
    if biased == 0 {
        return format!("{sign}0x0.{fraction:013x}p-1022");
    }

    let exponent = biased - EXPONENT_BIAS;

    format!("{sign}0x1.{fraction:013x}p{exponent:+}")
}

/// `float.fromhex(text)`: whitespace, an optional sign, then an infinity
/// or NaN spelling or `[0x] hexdigits [. hexdigits] [p exponent]`, then
/// whitespace. The value rounds half to even, through the subnormal
/// range; a NaN is always the default one.
pub fn float_from_hex(text: &[u8]) -> Result<f64, HexFloatError> {
    let start = skip_space(text, 0);
    let mut end = text.len();
    while end > start && is_space(text[end - 1]) {
        end -= 1;
    }
    let body = &text[start..end];

    let (negative, body) = match body.first() {
        Some(b'-') => (true, &body[1..]),
        Some(b'+') => (false, &body[1..]),
        _ => (false, body),
    };
    let apply_sign = |magnitude: f64| if negative { -magnitude } else { magnitude };

    if body.eq_ignore_ascii_case(b"inf") || body.eq_ignore_ascii_case(b"infinity") {
        return Ok(apply_sign(f64::INFINITY));
    }
    if body.eq_ignore_ascii_case(b"nan") {
        return Ok(PY_NAN);
    }

    let literal = HexLiteral::parse(body).ok_or(HexFloatError::Invalid)?;

    literal.to_double().map(apply_sign)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radix_prefixes_follow_the_base() {
        assert_eq!(int_from_bytes(b"0x10", 0), Some(BigInt::from(16)));
        assert_eq!(int_from_bytes(b"010", 0), Some(BigInt::from(8)));
        assert_eq!(int_from_bytes(b"0x", 16), None);
        assert_eq!(int_from_bytes(b"0b", 16), Some(BigInt::from(11)));
        assert_eq!(int_from_bytes(b"- 0b1", 0), Some(BigInt::from(-1)));
        assert_eq!(int_from_bytes(b"08", 0), None);
        assert_eq!(long_from_bytes(b"0b1L", 0), Ok(BigInt::from(1)));
        assert_eq!(long_from_bytes(b"0x", 0), Err(16));
    }

    #[test]
    fn hex_floats_round_half_to_even() {
        assert_eq!(float_from_hex(b"0x1.00000000000008p0"), Ok(1.0));
        assert_eq!(float_from_hex(b"0x1.00000000000018p0").map(f64::to_bits), Ok(0x3ff0_0000_0000_0002));
        assert_eq!(float_from_hex(b"0x1p-1075"), Ok(0.0));
        assert_eq!(float_from_hex(b"0x1.8p-1075").map(f64::to_bits), Ok(1));
        assert_eq!(float_from_hex(b"0x0.fffffffffffff8p-1022").map(f64::to_bits), Ok(0x0010_0000_0000_0000));
        assert_eq!(float_from_hex(b"0x1.fffffffffffff8p1023"), Err(HexFloatError::Overflow));
        assert_eq!(float_from_hex(b"0x1p"), Err(HexFloatError::Invalid));
    }

    #[test]
    fn hex_text_of_doubles() {
        assert_eq!(float_hex(1.0), "0x1.0000000000000p+0");
        assert_eq!(float_hex(-0.0), "-0x0.0p+0");
        assert_eq!(float_hex(5e-324), "0x0.0000000000001p-1022");
        assert_eq!(float_hex(0.1), "0x1.999999999999ap-4");
    }
}
