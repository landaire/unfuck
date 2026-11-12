//! Arithmetic on `int`, `long`, and `float` values.

use std::rc::Rc;

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::One;
use num_traits::Signed;
use num_traits::ToPrimitive;
use num_traits::Zero;

use crate::interp::compiler::fold::BinaryFold;
use crate::interp::compiler::object::Object;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::int_bounds;
use crate::interp::sse;

/// Bit length above which a `long` result is treated as the `MemoryError`
/// computing it would eventually cause.
const MAX_LONG_BITS: u64 = 1 << 24;

/// Significand bits and binary exponent range of a float.
const MANTISSA_BITS: i64 = f64::MANTISSA_DIGITS as i64;
const MAX_EXPONENT: i64 = f64::MAX_EXP as i64;
const MIN_EXPONENT: i64 = f64::MIN_EXP as i64;

/// The result of `int` arithmetic: an `int` when it fits the C `long` of
/// `width`, otherwise a `long`.
pub(super) fn int_result(width: LongWidth, value: i128) -> Object {
    let (low, high) = int_bounds(width);
    if let Ok(small) = i64::try_from(value)
        && (low..=high).contains(&small)
    {
        return Object::Int(small);
    }

    Object::Long(Rc::new(BigInt::from(value)))
}

/// A `long` result, or `None` above `MAX_LONG_BITS`.
pub(super) fn long_result(value: BigInt) -> Option<Object> {
    if value.bits() > MAX_LONG_BITS {
        return None;
    }

    Some(Object::Long(Rc::new(value)))
}

/// An operation on two `int` values.
pub(super) fn int_binary(op: BinaryFold, left: i64, right: i64, width: LongWidth) -> Option<Object> {
    let (minimum, _) = int_bounds(width);
    let (wide_left, wide_right) = (i128::from(left), i128::from(right));

    match op {
        BinaryFold::Add => Some(int_result(width, wide_left + wide_right)),
        BinaryFold::Subtract => Some(int_result(width, wide_left - wide_right)),
        BinaryFold::Multiply => Some(int_result(width, wide_left * wide_right)),
        BinaryFold::FloorDivide | BinaryFold::Modulo => {
            if right == 0 {
                return None;
            }

            let (quotient, remainder) = wide_left.div_mod_floor(&wide_right);
            let value = if op == BinaryFold::FloorDivide { quotient } else { remainder };

            // Dividing the smallest `int` by -1 overflows, which makes both
            // the quotient and the zero remainder `long`.
            if right == -1 && left == minimum {
                return long_result(BigInt::from(value));
            }

            Some(int_result(width, value))
        }
        BinaryFold::TrueDivide => {
            if right == 0 {
                return None;
            }

            true_divide(&BigInt::from(left), &BigInt::from(right)).map(Object::Float)
        }
        BinaryFold::Power => {
            if right < 0 {
                return float_power(left as f64, right as f64).map(Object::Float);
            }

            let value = integer_power(&BigInt::from(left), &BigInt::from(right))?;
            match value.to_i128() {
                Some(small) => Some(int_result(width, small)),
                None => long_result(value),
            }
        }
        BinaryFold::LShift => {
            if right < 0 {
                return None;
            }

            if left == 0 || right == 0 {
                return Some(Object::Int(left));
            }

            let value = shift_left(&BigInt::from(left), right)?;
            match value.to_i128() {
                Some(small) => Some(int_result(width, small)),
                None => long_result(value),
            }
        }
        BinaryFold::RShift => {
            if right < 0 {
                return None;
            }

            Some(Object::Int(left >> right.min(63)))
        }
        BinaryFold::And => Some(Object::Int(left & right)),
        BinaryFold::Xor => Some(Object::Int(left ^ right)),
        BinaryFold::Or => Some(Object::Int(left | right)),
        BinaryFold::Subscript => None,
    }
}

/// An operation where either operand is a `long` and neither is a float.
pub(super) fn long_binary(op: BinaryFold, left: &BigInt, right: &BigInt) -> Option<Object> {
    match op {
        BinaryFold::Add => long_result(left + right),
        BinaryFold::Subtract => long_result(left - right),
        BinaryFold::Multiply => {
            if left.bits() + right.bits() > MAX_LONG_BITS + 1 {
                return None;
            }

            long_result(left * right)
        }
        BinaryFold::FloorDivide => {
            if right.is_zero() {
                return None;
            }

            long_result(left.div_floor(right))
        }
        BinaryFold::Modulo => {
            if right.is_zero() {
                return None;
            }

            long_result(left.mod_floor(right))
        }
        BinaryFold::TrueDivide => {
            if right.is_zero() {
                return None;
            }

            true_divide(left, right).map(Object::Float)
        }
        BinaryFold::Power => {
            if right.is_negative() {
                let base = long_to_float(left)?;
                let exponent = long_to_float(right)?;
                return float_power(base, exponent).map(Object::Float);
            }

            long_result(integer_power(left, right)?)
        }
        BinaryFold::LShift => {
            let count = right.to_i64()?;
            if count < 0 {
                return None;
            }

            long_result(shift_left(left, count)?)
        }
        BinaryFold::RShift => {
            let count = right.to_i64()?;
            if count < 0 {
                return None;
            }

            let count = u64::try_from(count).ok()?;
            if count >= left.bits() {
                let value = if left.is_negative() { -BigInt::one() } else { BigInt::zero() };
                return long_result(value);
            }

            long_result(floor_shift_right(left, count))
        }
        BinaryFold::And => long_result(left & right),
        BinaryFold::Xor => long_result(left ^ right),
        BinaryFold::Or => long_result(left | right),
        BinaryFold::Subscript => None,
    }
}

/// An operation on two floats. Addition and multiplication evaluate
/// `right op left`, as the reference build's machine code does, which
/// decides the NaN payload of the result.
pub(super) fn float_binary(op: BinaryFold, left: f64, right: f64) -> Option<Object> {
    let value = match op {
        BinaryFold::Add => sse::add(right, left),
        BinaryFold::Subtract => sse::sub(left, right),
        BinaryFold::Multiply => sse::mul(right, left),
        BinaryFold::TrueDivide => {
            if right == 0.0 {
                return None;
            }

            sse::div(left, right)
        }
        BinaryFold::FloorDivide => float_floor_divide(left, right)?,
        BinaryFold::Modulo => float_modulo(left, right)?,
        BinaryFold::Power => float_power(left, right)?,
        BinaryFold::Subscript | BinaryFold::LShift | BinaryFold::RShift | BinaryFold::And | BinaryFold::Xor | BinaryFold::Or => return None,
    };

    Some(Object::Float(value))
}

/// The float nearest to a `long`, ties to even. `None` when it reaches
/// 2**1024, where the conversion raises OverflowError.
pub(super) fn long_to_float(value: &BigInt) -> Option<f64> {
    let magnitude = value.magnitude();
    let bits = i64::try_from(magnitude.bits()).ok()?;

    let rounded = if bits <= MANTISSA_BITS {
        magnitude.to_u64()? as f64
    } else {
        // Keep two bits past the mantissa; the lowest is sticky.
        let shift = bits - MANTISSA_BITS - 2;
        let (top, sticky) = if shift <= 0 {
            (magnitude << u64::try_from(-shift).ok()?, false)
        } else {
            let shift_bits = u64::try_from(shift).ok()?;
            let sticky = magnitude.trailing_zeros().is_some_and(|zeros| zeros < shift_bits);
            (magnitude >> shift_bits, sticky)
        };
        let top = top.to_u64()? | u64::from(sticky);
        let mut mantissa = top >> 2;
        let rest = top & 3;
        if rest == 3 || (rest == 2 && mantissa & 1 == 1) {
            mantissa += 1;
        }

        if i64::from(64 - mantissa.leading_zeros() as i32) + shift + 2 > MAX_EXPONENT {
            return None;
        }

        times_power_of_two(mantissa as f64, shift + 2)
    };

    Some(if value.is_negative() { -rounded } else { rounded })
}

/// `x * 2**exponent`, exact whenever the result is representable.
fn times_power_of_two(value: f64, exponent: i64) -> f64 {
    let mut value = value;
    let mut exponent = exponent;

    while exponent > 1000 {
        value *= 2f64.powi(1000);
        exponent -= 1000;
    }

    while exponent < -1000 {
        value *= 2f64.powi(-1000);
        exponent += 1000;
    }

    let Ok(exponent) = i32::try_from(exponent) else {
        return value;
    };

    value * 2f64.powi(exponent)
}

/// The correctly rounded quotient of two integers, `None` on overflow.
/// `right` is nonzero.
fn true_divide(left: &BigInt, right: &BigInt) -> Option<f64> {
    let negate = left.is_negative() != right.is_negative();
    let signed = |value: f64| if negate { -value } else { value };

    if left.is_zero() {
        return Some(signed(0.0));
    }

    let numerator = left.magnitude();
    let denominator = right.magnitude();
    let numerator_bits = i64::try_from(numerator.bits()).ok()?;
    let denominator_bits = i64::try_from(denominator.bits()).ok()?;

    // Both operands are exact doubles, so one division rounds correctly.
    if numerator_bits <= MANTISSA_BITS && denominator_bits <= MANTISSA_BITS {
        return Some(signed(numerator.to_u64()? as f64 / denominator.to_u64()? as f64));
    }

    let difference = numerator_bits - denominator_bits;
    if difference > MAX_EXPONENT {
        return None;
    }

    if difference < MIN_EXPONENT - MANTISSA_BITS - 1 {
        return Some(signed(0.0));
    }

    let shift = difference.max(MIN_EXPONENT) - MANTISSA_BITS - 2;
    let mut inexact = false;
    let scaled = if shift <= 0 {
        numerator << u64::try_from(-shift).ok()?
    } else {
        let shift_bits = u64::try_from(shift).ok()?;
        inexact = numerator.trailing_zeros().is_some_and(|zeros| zeros < shift_bits);
        numerator >> shift_bits
    };

    let (quotient, remainder) = scaled.div_rem(denominator);
    inexact |= !remainder.is_zero();

    let quotient_bits = i64::try_from(quotient.bits()).ok()?;
    let extra_bits = quotient_bits.max(MIN_EXPONENT - shift) - MANTISSA_BITS;
    let extra = u64::try_from(extra_bits).ok()?;
    let mask = 1u64 << (extra - 1);
    let low = (&quotient & BigUint::from(u64::MAX)).to_u64()? | u64::from(inexact);
    let round_up = low & mask != 0 && low & (3 * mask - 1) != 0;
    let mut truncated = quotient >> extra;
    if round_up {
        truncated += 1u32;
    }

    let total_bits = i64::try_from(truncated.bits()).ok()? + extra_bits + shift;
    if total_bits > MAX_EXPONENT {
        return None;
    }

    Some(signed(times_power_of_two(truncated.to_u64()? as f64, shift + extra_bits)))
}

/// `base ** exponent` for a nonnegative exponent, `None` when the result
/// would exceed `MAX_LONG_BITS`.
fn integer_power(base: &BigInt, exponent: &BigInt) -> Option<BigInt> {
    if exponent.is_zero() {
        return Some(BigInt::one());
    }

    let magnitude = base.magnitude();
    if magnitude.is_zero() || magnitude.is_one() {
        let negative = base.is_negative() && exponent.is_odd();
        let value = BigInt::from_biguint(Sign::Plus, magnitude.clone());
        return Some(if negative { -value } else { value });
    }

    let exponent = exponent.to_u64()?;
    if exponent.checked_mul(magnitude.bits())? > MAX_LONG_BITS {
        return None;
    }

    Some(num_traits::pow::Pow::pow(base, u32::try_from(exponent).ok()?))
}

/// `value << count` for a nonnegative count, `None` above `MAX_LONG_BITS`.
fn shift_left(value: &BigInt, count: i64) -> Option<BigInt> {
    if value.is_zero() {
        return Some(BigInt::zero());
    }

    let count = u64::try_from(count).ok()?;
    if value.bits().checked_add(count)? > MAX_LONG_BITS {
        return None;
    }

    Some(value << count)
}

/// Arithmetic right shift, rounding toward negative infinity.
fn floor_shift_right(value: &BigInt, count: u64) -> BigInt {
    if value.is_negative() {
        let inverted = -(value + BigInt::one());
        return -((inverted >> count) + BigInt::one());
    }

    value >> count
}

/// Whether `left % right`, a nonzero C remainder, has the opposite sign of
/// `right` and must wrap around to it.
fn remainder_wraps(remainder: f64, right: f64) -> bool {
    remainder != 0.0 && (right < 0.0) != (remainder < 0.0)
}

/// `left // right` for floats, `None` for a zero divisor. The quotient is
/// derived from the remainder so that it agrees with `%`, and is snapped to
/// the nearest integer; a zero quotient takes the sign of the exact one.
fn float_floor_divide(left: f64, right: f64) -> Option<f64> {
    if right == 0.0 {
        return None;
    }

    let remainder = left % right;
    let mut quotient = (left - remainder) / right;
    if remainder_wraps(remainder, right) {
        quotient -= 1.0;
    }

    if quotient == 0.0 {
        return Some(quotient * quotient * left / right);
    }

    let floored = quotient.floor();

    Some(if quotient - floored > 0.5 { floored + 1.0 } else { floored })
}

/// `left % right` for floats, with the sign of `right`. `None` for a zero
/// divisor.
fn float_modulo(left: f64, right: f64) -> Option<f64> {
    if right == 0.0 {
        return None;
    }

    let remainder = left % right;
    if remainder_wraps(remainder, right) {
        return Some(remainder + right);
    }

    if remainder != 0.0 {
        return Some(remainder);
    }

    // Zero takes the sign of the divisor.
    Some(if right < 0.0 { -0.0 } else { 0.0 })
}

/// `base ** exponent` for floats. `None` where it raises: zero to a
/// negative power, a negative base to a fractional power, and results that
/// overflow to infinity.
pub(super) fn float_power(base: f64, exponent: f64) -> Option<f64> {
    let is_odd_integer = |value: f64| value.abs() % 2.0 == 1.0;

    if exponent == 0.0 {
        return Some(1.0);
    }

    if base.is_nan() {
        return Some(base);
    }

    if exponent.is_nan() {
        return Some(if base == 1.0 { 1.0 } else { exponent });
    }

    if exponent.is_infinite() {
        let magnitude = base.abs();
        if magnitude == 1.0 {
            return Some(1.0);
        }

        if (exponent > 0.0) == (magnitude > 1.0) {
            return Some(exponent.abs());
        }

        return Some(0.0);
    }

    if base.is_infinite() {
        let odd = is_odd_integer(exponent);
        if exponent > 0.0 {
            return Some(if odd { base } else { base.abs() });
        }

        return Some(if odd { 0.0f64.copysign(base) } else { 0.0 });
    }

    if base == 0.0 {
        if exponent < 0.0 {
            return None;
        }

        return Some(if is_odd_integer(exponent) { base } else { 0.0 });
    }

    let mut base = base;
    let mut negate = false;
    if base < 0.0 {
        if exponent != exponent.floor() {
            return None;
        }

        base = -base;
        negate = is_odd_integer(exponent);
    }

    if base == 1.0 {
        return Some(if negate { -1.0 } else { 1.0 });
    }

    let result = base.powf(exponent);
    if result.is_infinite() {
        return None;
    }

    Some(if negate { -result } else { result })
}

/// `int()` of a float: an `int` when the truncated value fits the C `long`
/// of `width`, otherwise a `long`. `None` for NaN and infinities.
pub(super) fn float_to_integer(value: f64, width: LongWidth) -> Option<Object> {
    if !value.is_finite() {
        return None;
    }

    let whole = value.trunc();
    let (minimum, _) = int_bounds(width);
    let limit = -(minimum as f64);
    if minimum as f64 <= whole && whole < limit {
        return Some(Object::Int(whole as i64));
    }

    long_result(integral_float_to_long(whole)?)
}

/// The `long` equal to an integral, finite float.
fn integral_float_to_long(value: f64) -> Option<BigInt> {
    let bits = value.to_bits();
    let exponent = i64::try_from((bits >> 52) & 0x7ff).ok()? - 1075;
    let mantissa = (bits & ((1 << 52) - 1)) | (1 << 52);
    let magnitude = if exponent >= 0 { BigInt::from(mantissa) << u64::try_from(exponent).ok()? } else { BigInt::from(mantissa >> u64::try_from(-exponent).ok()?.min(63)) };

    Some(if value < 0.0 { -magnitude } else { magnitude })
}
