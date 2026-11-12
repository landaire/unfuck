//! CPython 2.7 hash functions. Results depend on the width of C `long`,
//! which is 32 bits on Win64 and 64 bits on LP64 Unix.

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::Sign;

/// Width of C `long` on the emulated platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongWidth {
    /// LLP64 (Win64). Hashes wrap at 32 bits and are sign-extended to
    /// the pointer width when stored in tables.
    Bits32,
    /// LP64 (Linux x64).
    Bits64,
}

impl LongWidth {
    fn bits(self) -> u32 {
        match self {
            LongWidth::Bits32 => 32,
            LongWidth::Bits64 => 64,
        }
    }

    /// Reduces `value` modulo 2^bits and sign-extends it, matching the
    /// wrapping behavior of signed `long` arithmetic.
    pub fn wrap(self, value: i64) -> i64 {
        match self {
            LongWidth::Bits32 => i64::from(value as i32),
            LongWidth::Bits64 => value,
        }
    }

    /// Returns true when `value` is representable as a C `long`.
    fn fits(self, value: i64) -> bool {
        self.wrap(value) == value
    }
}

/// A CPython hash value, already wrapped to the width of C `long` and
/// sign-extended to 64 bits. It is never -1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PyHash(i64);

impl PyHash {
    /// Wraps a raw C `long` hash result, remapping -1 to -2: -1 signals an
    /// error, so no Python hash, including a `__hash__` result, is ever -1.
    pub fn from_long(width: LongWidth, value: i64) -> Self {
        let value = width.wrap(value);

        if value == -1 { Self(-2) } else { Self(value) }
    }

    /// The hash as a sign-extended signed value.
    pub fn value(self) -> i64 {
        self.0
    }

    /// The hash as `size_t`, used for table indexing and probing.
    pub(crate) fn as_size_t(self) -> u64 {
        self.0 as u64
    }
}

/// Hash of a `str`, with hash randomization off as in the client.
pub fn hash_bytes(width: LongWidth, bytes: &[u8]) -> PyHash {
    hash_code_units(width, bytes)
}

/// Hash of a `unicode` object given as UTF-16 code units. The client's
/// build stores unicode as UTF-16, so a character outside the BMP counts
/// as two units.
pub fn hash_unicode(width: LongWidth, code_units: &[u16]) -> PyHash {
    hash_code_units(width, code_units)
}

/// Hash of an `int`: the value itself. A value outside the range of C
/// `long` cannot be a Python `int`, so it is hashed as the equal `long`.
pub fn hash_int(width: LongWidth, value: i64) -> PyHash {
    if !width.fits(value) {
        return hash_long(width, &BigInt::from(value));
    }

    PyHash::from_long(width, value)
}

/// Hash of a `long`: the unique x in [1, ULONG_MAX] congruent to |v|
/// modulo ULONG_MAX (or 0 when v is 0), negated for a negative v. This
/// does not depend on the digit size, so it is computed here directly.
pub fn hash_long(width: LongWidth, value: &BigInt) -> PyHash {
    let ulong_max = (BigUint::from(1u8) << width.bits()) - 1u8;
    let mut folded = value.magnitude() % &ulong_max;
    if folded == BigUint::from(0u8) && value.sign() != Sign::NoSign {
        folded = ulong_max;
    }

    let digits = folded.to_u64_digits();
    let folded = digits.first().copied().unwrap_or(0);
    let signed = match value.sign() {
        Sign::Minus => (folded as i64).wrapping_neg(),
        Sign::NoSign | Sign::Plus => folded as i64,
    };

    PyHash::from_long(width, signed)
}

/// Hash of a `float`. An integral value hashes like the equal `int` or
/// `long`. Any other finite value mixes its significand with its exponent.
pub fn hash_float(width: LongWidth, value: f64) -> PyHash {
    if value.is_nan() || value == 0.0 {
        return PyHash::from_long(width, 0);
    }
    if value.is_infinite() {
        let hash = if value > 0.0 { 314_159 } else { -271_828 };
        return PyHash::from_long(width, hash);
    }

    let parts = FloatParts::new(value);
    if value.fract() == 0.0 {
        return hash_integral_float(width, parts);
    }

    hash_fractional_float(width, parts)
}

/// Hash of a tuple from the hashes of its items. `len` is the tuple length
/// and must equal the number of items.
pub fn hash_tuple(width: LongWidth, items: impl IntoIterator<Item = PyHash>, len: usize) -> PyHash {
    // Each item is xored into the accumulator, which is then multiplied by
    // a factor that grows by 82520 plus twice the count of items still to
    // come. C `long` arithmetic wraps, and only +, *, and ^ are used, so
    // computing modulo 2^64 and truncating at the end gives the same bits.
    let mut accumulator: u64 = 0x34_5678;
    let mut factor: u64 = 1_000_003;

    for (position, item) in items.into_iter().enumerate() {
        let remaining = len.saturating_sub(position + 1) as u64;
        accumulator = (accumulator ^ item.value() as u64).wrapping_mul(factor);
        factor = factor
            .wrapping_add(82_520)
            .wrapping_add(remaining.wrapping_mul(2));
    }

    PyHash::from_long(width, accumulator.wrapping_add(97_531) as i64)
}

/// Hash of an object identity: the 64-bit address rotated right by 4 bits.
pub fn hash_pointer(width: LongWidth, address: u64) -> PyHash {
    PyHash::from_long(width, address.rotate_right(4) as i64)
}

/// The string hash shared by `str` and `unicode`. The seed is the first
/// unit shifted left by 7. Each unit then multiplies the state by 1000003
/// and is xored in, and the length is xored in last. The empty string
/// hashes to 0. As in `hash_tuple`, wrapping 64-bit arithmetic truncated
/// at the end matches C `long` arithmetic.
fn hash_code_units<T>(width: LongWidth, units: &[T]) -> PyHash
where
    T: Copy + Into<u64>,
{
    let Some(first) = units.first() else {
        return PyHash::from_long(width, 0);
    };

    let seed = (*first).into() << 7;
    let mixed = units.iter().fold(seed, |state, unit| {
        state.wrapping_mul(1_000_003) ^ (*unit).into()
    });

    PyHash::from_long(width, (mixed ^ units.len() as u64) as i64)
}

/// A finite nonzero float as `significand * 2^exponent`, with the
/// significand scaled so that bit 52 is its highest set bit.
#[derive(Debug, Clone, Copy)]
struct FloatParts {
    negative: bool,
    significand: u64,
    exponent: i32,
}

impl FloatParts {
    fn new(value: f64) -> Self {
        const FRACTION_MASK: u64 = (1 << 52) - 1;

        let bits = value.to_bits();
        let biased_exponent = ((bits >> 52) & 0x7ff) as i32;
        let fraction = bits & FRACTION_MASK;

        let (significand, exponent) = if biased_exponent == 0 {
            // Subnormal: move the leading fraction bit up to bit 52.
            let shift = fraction.leading_zeros().saturating_sub(11);
            (fraction << shift, -1074 - shift as i32)
        } else {
            (fraction | (1 << 52), biased_exponent - 1075)
        };

        Self {
            negative: value.is_sign_negative(),
            significand,
            exponent,
        }
    }
}

/// An integral float hashes like the equal integer: the residue of its
/// magnitude modulo 2^bits - 1, taken in [1, 2^bits - 1] because the value
/// is nonzero, and negated for a negative value.
fn hash_integral_float(width: LongWidth, parts: FloatParts) -> PyHash {
    let modulus = (1u128 << width.bits()) - 1;
    let shift = parts.exponent.unsigned_abs();

    let residue = if parts.exponent >= 0 {
        // 2^bits is 1 modulo the modulus, so the shift reduces modulo bits.
        (u128::from(parts.significand) << (shift % width.bits())) % modulus
    } else {
        // The value is integral, so only zero bits are shifted out.
        u128::from(parts.significand.checked_shr(shift).unwrap_or(0)) % modulus
    };
    let magnitude = if residue == 0 { modulus } else { residue };

    // The magnitude is below 2^64. Reinterpreting it as signed wraps the
    // same way the C `long` result does.
    let magnitude = magnitude as u64 as i64;
    let signed = if parts.negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };

    PyHash::from_long(width, signed)
}

/// A float with a fractional part hashes as the sum of three C `long`
/// terms. With `value = m * 2^e` and `0.5 <= |m| < 1`, they are the integer
/// part of `m * 2^31`, the integer part of the remainder scaled by another
/// 2^31, and `e << 15`. In significand terms the first two are its top 31
/// bits and its low 22 bits shifted left by 9, both carrying the sign.
fn hash_fractional_float(width: LongWidth, parts: FloatParts) -> PyHash {
    let high = (parts.significand >> 22) as i64;
    let low = ((parts.significand & 0x3f_ffff) << 9) as i64;
    let magnitude = high + low;
    let signed = if parts.negative {
        -magnitude
    } else {
        magnitude
    };
    let exponent = i64::from(parts.exponent + 53);

    PyHash::from_long(width, signed + (exponent << 15))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win64_values() {
        // Hand-derived from the ULONG_MAX congruence with a 32-bit long.
        assert_eq!(
            hash_long(LongWidth::Bits32, &(BigInt::from(1) << 32usize)).value(),
            1
        );
        assert_eq!(
            hash_long(LongWidth::Bits32, &BigInt::from(u32::MAX)).value(),
            -2
        );
        assert_eq!(
            hash_long(LongWidth::Bits32, &(BigInt::from(u32::MAX) * 3)).value(),
            -2
        );
        assert_eq!(
            hash_long(LongWidth::Bits32, &-(BigInt::from(1) << 33usize)).value(),
            -2
        );
        assert_eq!(
            hash_long(LongWidth::Bits32, &-(BigInt::from(1) << 34usize)).value(),
            -4
        );
        assert_eq!(hash_float(LongWidth::Bits32, 4294967296.0).value(), 1);
        assert_eq!(hash_bytes(LongWidth::Bits32, b"").value(), 0);
        assert_eq!(
            hash_bytes(LongWidth::Bits32, b"ab"),
            hash_unicode(LongWidth::Bits32, &[97, 98])
        );
    }

    /// Values printed by CPython 2.7.12 for Windows x64 and 2.7.18 for
    /// Linux x64.
    #[test]
    fn float_hashes_match_reference() {
        let cases = [
            (5e-324, 1_038_581_760, 1_038_581_760),
            (-2.5e-310, 1_653_032_652, -2_641_934_644),
            (-0.1, 1_717_888_410, -2_577_078_886),
            (1.5, 1_610_645_504, 1_610_645_504),
            (-1e20, 824_746_446, -7_766_279_631_452_241_925),
            (2f64.powi(63), -2_147_483_648, i64::MIN),
            (-4_294_967_295.0, 1, -4_294_967_295),
            (1e308, -324_232_145, -8_185_402_070_463_610_880),
        ];

        for (value, bits32, bits64) in cases {
            assert_eq!(
                hash_float(LongWidth::Bits32, value).value(),
                bits32,
                "{value:e}"
            );
            assert_eq!(
                hash_float(LongWidth::Bits64, value).value(),
                bits64,
                "{value:e}"
            );
        }
    }

    /// Values printed by CPython 2.7.12 for Windows x64.
    #[test]
    fn sequence_hashes_match_win64() {
        let width = LongWidth::Bits32;
        let items = [
            hash_bytes(width, b"a"),
            hash_float(width, 1.5),
            hash_int(width, -1),
        ];

        assert_eq!(hash_tuple(width, items, 3).value(), -1_201_792_879);
        assert_eq!(hash_tuple(width, [], 0).value(), 3_527_539);
        assert_eq!(
            hash_tuple(width, [hash_int(width, -1)], 1).value(),
            1_658_677_005
        );
        assert_eq!(
            hash_unicode(width, &[0x20AC, 0xD83D, 0xDE00]).value(),
            379_963_368
        );
        assert_eq!(hash_bytes(width, b"\xff\x00credits").value(), 1_854_174_428);
    }
}
