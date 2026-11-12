//! Complex numbers as two IEEE doubles: the arithmetic of the reference
//! build, including which NaN survives when two meet and the `errno` its
//! math library leaves, and the `repr` and `str` text forms.

use crate::interp::hash;
use crate::interp::hash::LongWidth;
use crate::interp::hash::PyHash;
use crate::interp::numbers;
use crate::interp::sse;

/// A complex number.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Complex {
    pub real: f64,
    pub imag: f64,
}

impl std::ops::Neg for Complex {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.real, -self.imag)
    }
}

/// The `errno` an operation leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    Ok,
    /// `EDOM`
    Domain,
    /// `ERANGE`
    Range,
}

/// A result with the `errno` its computation leaves.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Computed {
    pub value: Complex,
    pub errno: Errno,
}

impl Complex {
    pub const ONE: Self = Self { real: 1.0, imag: 0.0 };

    pub fn new(real: f64, imag: f64) -> Self {
        Self { real, imag }
    }

    /// `self + other`. Each part of `other` is the destination operand, so
    /// its NaN wins over one in `self`.
    pub fn sum(self, other: Self) -> Self {
        Self::new(sse::add(other.real, self.real), sse::add(other.imag, self.imag))
    }

    /// `self - other`.
    pub fn diff(self, other: Self) -> Self {
        Self::new(sse::sub(self.real, other.real), sse::sub(self.imag, other.imag))
    }

    /// `self * other` with the operand order of the reference build.
    pub fn prod(self, other: Self) -> Self {
        let real = sse::sub(sse::mul(other.real, self.real), sse::mul(other.imag, self.imag));
        let imag = sse::add(sse::mul(self.imag, other.real), sse::mul(other.imag, self.real));

        Self::new(real, imag)
    }

    /// `self / divisor`, scaling by the ratio of the divisor's smaller part
    /// to its larger one so the denominator cannot overflow. A zero divisor
    /// is `EDOM`; a divisor with a NaN part gives a NaN quotient.
    pub fn quot(self, divisor: Self) -> Computed {
        let real_size = divisor.real.abs();
        let imag_size = divisor.imag.abs();

        let value = if real_size >= imag_size {
            if real_size == 0.0 {
                return Computed { value: Self::new(numbers::PY_NAN, numbers::PY_NAN), errno: Errno::Domain };
            }
            let ratio = sse::div(divisor.imag, divisor.real);
            let denominator = sse::add(divisor.real, sse::mul(divisor.imag, ratio));
            let real = sse::add(sse::mul(self.imag, ratio), self.real);
            let imag = sse::sub(self.imag, sse::mul(ratio, self.real));
            Self::new(sse::div(real, denominator), sse::div(imag, denominator))
        } else if imag_size > real_size {
            let ratio = sse::div(divisor.real, divisor.imag);
            let denominator = sse::add(sse::mul(divisor.real, ratio), divisor.imag);
            let real = sse::add(sse::mul(self.real, ratio), self.imag);
            let imag = sse::sub(sse::mul(self.imag, ratio), self.real);
            Self::new(sse::div(real, denominator), sse::div(imag, denominator))
        } else {
            Self::new(numbers::PY_NAN, numbers::PY_NAN)
        };

        Computed { value, errno: Errno::Ok }
    }

    /// `self ** exponent` as the `**` operator computes it. A real integral
    /// exponent of magnitude at most 100 multiplies; any other goes through
    /// polar form. `EDOM` marks a zero base raised to a negative or complex
    /// power, a NaN reaching `exp`, and an infinite phase; otherwise an
    /// infinite part is `ERANGE`.
    pub fn power(self, exponent: Self) -> Computed {
        const MULTIPLIED_LIMIT: f64 = 100.0;

        let multiplied = exponent.imag == 0.0 && exponent.real.trunc() == exponent.real && exponent.real.abs() <= MULTIPLIED_LIMIT;
        let value = if multiplied { self.integer_power(exponent.real as i32) } else { self.polar_power(exponent) };
        let Some(value) = value else {
            return Computed { value: Self::new(numbers::PY_NAN, numbers::PY_NAN), errno: Errno::Domain };
        };

        let errno = if value.real.is_infinite() || value.imag.is_infinite() { Errno::Range } else { Errno::Ok };

        Computed { value, errno }
    }

    /// `self ** exponent` by repeated multiplication; a negative exponent
    /// divides one by the positive power. `None` when that power is zero.
    fn integer_power(self, exponent: i32) -> Option<Self> {
        let magnitude = self.natural_power(exponent.unsigned_abs());
        if exponent > 0 {
            return Some(magnitude);
        }

        let reciprocal = Self::ONE.quot(magnitude);

        (reciprocal.errno == Errno::Ok).then_some(reciprocal.value)
    }

    /// Binary powering from the low bit up: the running square multiplies
    /// into the result for each set bit.
    fn natural_power(self, exponent: u32) -> Self {
        let mut result = Self::ONE;
        let mut square = self;
        let mut remaining = exponent;

        while remaining != 0 {
            if remaining & 1 == 1 {
                result = square.prod(result);
            }
            remaining >>= 1;
            if remaining != 0 {
                square = square.prod(square);
            }
        }

        result
    }

    /// `self ** exponent` through the modulus and argument of `self`. `None`
    /// for a domain error.
    fn polar_power(self, exponent: Self) -> Option<Self> {
        if self.real == 0.0 && self.imag == 0.0 {
            if exponent.imag != 0.0 || exponent.real < 0.0 {
                return None;
            }
            return Some(Self::new(0.0, 0.0));
        }

        let modulus = library_hypot(self.real, self.imag);
        let argument = library_atan2(self.imag, self.real);
        let mut length = library_pow(modulus, exponent.real);
        let mut phase = sse::mul(exponent.real, argument);

        if exponent.imag != 0.0 {
            let decay = sse::mul(argument, exponent.imag);
            if decay.is_nan() {
                return None;
            }
            length = sse::div(length, decay.exp());
            phase = sse::add(phase, sse::mul(exponent.imag, modulus.ln()));
        }

        // `cos` and `sin` of an infinite phase are domain errors.
        if phase.is_infinite() {
            return None;
        }

        Some(Self::new(sse::mul(phase.cos(), length), sse::mul(phase.sin(), length)))
    }

    /// The floored quotient and the remainder of `self / divisor`: the
    /// quotient keeps only the floor of its real part. `None` for a zero
    /// divisor.
    pub fn divmod(self, divisor: Self) -> Option<(Self, Self)> {
        let quotient = self.quot(divisor);
        if quotient.errno == Errno::Domain {
            return None;
        }

        let floored = Self::new(quotient.value.real.floor(), 0.0);

        // The divisor is the destination of each product here, unlike in
        // `prod`.
        let product_real = sse::sub(sse::mul(divisor.real, floored.real), sse::mul(divisor.imag, floored.imag));
        let product_imag = sse::add(sse::mul(divisor.imag, floored.real), sse::mul(divisor.real, floored.imag));
        let remainder = Self::new(sse::sub(self.real, product_real), sse::sub(self.imag, product_imag));

        Some((floored, remainder))
    }

    /// `abs(self)`: an infinite part wins over a NaN; an overflowing finite
    /// result is `ERANGE`.
    pub fn abs(self) -> (f64, Errno) {
        if !self.real.is_finite() || !self.imag.is_finite() {
            if self.real.is_infinite() {
                return (self.real.abs(), Errno::Ok);
            }
            if self.imag.is_infinite() {
                return (self.imag.abs(), Errno::Ok);
            }
            return (numbers::PY_NAN, Errno::Ok);
        }

        let result = self.real.hypot(self.imag);
        let errno = if result.is_finite() { Errno::Ok } else { Errno::Range };

        (result, errno)
    }

    /// `hash(self)`: the hashes of the parts combined in a C `long`.
    pub fn hash(self, width: LongWidth) -> PyHash {
        let real = hash::hash_float(width, self.real).value();
        let imag = hash::hash_float(width, self.imag).value();

        PyHash::from_long(width, real.wrapping_add(imag.wrapping_mul(1_000_003)))
    }

    pub fn repr(self) -> String {
        self.format(Notation::Repr)
    }

    pub fn str(self) -> String {
        self.format(Notation::General(12))
    }

    /// A positive zero real part is left out; otherwise the parts appear in
    /// parentheses, the imaginary one signed.
    fn format(self, notation: Notation) -> String {
        if self.real == 0.0 && self.real.is_sign_positive() {
            return format!("{}j", double_to_string(self.imag, notation, false));
        }

        format!("({}{}j)", double_to_string(self.real, notation, false), double_to_string(self.imag, notation, true))
    }
}

/// How `repr` and `str` format each part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notation {
    /// Shortest round-trip digits.
    Repr,
    /// `'g'` with a precision.
    General(usize),
}

/// A part of a complex number as text, without a `.0` suffix. `sign` adds
/// `+` before a non-negative value; a NaN never shows a sign of its own.
pub fn double_to_string(value: f64, notation: Notation, sign: bool) -> String {
    let text = match notation {
        Notation::Repr => numbers::float_repr_plain(value),
        Notation::General(precision) => numbers::format_general(value, precision, false, false),
    };

    if sign && !text.starts_with('-') {
        return format!("+{text}");
    }

    text
}

/// The magnitude bits of a double.
fn magnitude_bits(value: f64) -> u64 {
    value.to_bits() & !(1 << 63)
}

/// `value` as a quiet NaN.
fn quieted(value: f64) -> f64 {
    f64::from_bits(value.to_bits() | (1 << 51))
}

/// `hypot` of the reference math library: an infinite part wins over a
/// NaN; of two NaNs the one with the smaller magnitude bits is returned.
/// The NaN keeps its payload and loses its sign.
fn library_hypot(x: f64, y: f64) -> f64 {
    if x.is_infinite() || y.is_infinite() {
        return f64::INFINITY;
    }

    let nan = match (x.is_nan(), y.is_nan()) {
        (true, true) => magnitude_bits(x).min(magnitude_bits(y)),
        (true, false) => magnitude_bits(x),
        (false, true) => magnitude_bits(y),
        (false, false) => return x.hypot(y),
    };

    f64::from_bits(nan)
}

/// `atan2(y, x)` of the reference math library: `x` wins when both are
/// NaN, and the result is quiet.
fn library_atan2(y: f64, x: f64) -> f64 {
    if x.is_nan() {
        return quieted(x);
    }
    if y.is_nan() {
        return quieted(y);
    }

    y.atan2(x)
}

/// `pow(x, y)` of the reference math library: `x ** 0` and `1 ** y` are
/// one; otherwise a NaN `x` wins over a NaN `y`, and the result is quiet.
fn library_pow(x: f64, y: f64) -> f64 {
    if y == 0.0 || x == 1.0 {
        return 1.0;
    }
    if x.is_nan() {
        return quieted(x);
    }
    if y.is_nan() {
        return quieted(y);
    }

    x.powf(y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_complex_repr_and_str() {
        assert_eq!(Complex::new(0.0, 1.0).repr(), "1j");
        assert_eq!(Complex::new(-0.0, 1.0).repr(), "(-0+1j)");
        assert_eq!(Complex::new(1.5, -2.0).repr(), "(1.5-2j)");
        assert_eq!(Complex::new(1e16, 1e15).repr(), "(1e+16+1000000000000000j)");
        assert_eq!(Complex::new(1.0, f64::NAN).repr(), "(1+nanj)");
        assert_eq!(Complex::new(123456789012.0, 1e11).str(), "(123456789012+100000000000j)");
        assert_eq!(Complex::new(0.0, 1e12).str(), "1e+12j");
    }

    #[test]
    fn hash_combines_parts_in_c_long() {
        assert_eq!(Complex::new(0.0, 1.0).hash(LongWidth::Bits32).value(), 1_000_003);
        assert_eq!(Complex::new(-1_000_004.0, 1.0).hash(LongWidth::Bits64).value(), -2);
        assert_eq!(Complex::new(0.0, 5000.0).hash(LongWidth::Bits32).value(), (5000i64 * 1_000_003) as i32 as i64);
    }

    #[test]
    fn small_integer_powers_multiply() {
        assert_eq!(Complex::new(0.0, 1.0).power(Complex::new(2.0, 0.0)).value, Complex::new(-1.0, 0.0));
        assert_eq!(Complex::new(0.0, 0.0).power(Complex::new(-1.0, 0.0)).errno, Errno::Domain);
        assert_eq!(Complex::new(1e200, 0.0).power(Complex::new(2.0, 0.0)).errno, Errno::Range);
    }

    #[test]
    fn nan_exponent_part_reaching_exp_is_a_domain_error() {
        assert_eq!(Complex::new(1.0, 0.0).power(Complex::new(0.0, f64::NAN)).errno, Errno::Domain);
        assert_eq!(Complex::new(2.0, 0.0).power(Complex::new(f64::NAN, 0.0)).errno, Errno::Ok);
    }
}
