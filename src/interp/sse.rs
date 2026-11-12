//! Scalar SSE2 arithmetic as the reference CPython build executes it. When
//! both operands are NaN, `addsd`/`subsd`/`mulsd`/`divsd` return the
//! destination operand (quieted); Rust leaves the operand order to LLVM,
//! so callers name the destination GCC chose to get the same NaN sign.
//! Every other result, including a fresh NaN from an invalid operation,
//! is already the same.

pub fn add(destination: f64, source: f64) -> f64 {
    pick(destination, source, destination + source)
}

pub fn sub(destination: f64, source: f64) -> f64 {
    pick(destination, source, destination - source)
}

pub fn mul(destination: f64, source: f64) -> f64 {
    pick(destination, source, destination * source)
}

pub fn div(destination: f64, source: f64) -> f64 {
    pick(destination, source, destination / source)
}

fn pick(destination: f64, source: f64, result: f64) -> f64 {
    const QUIET_BIT: u64 = 1 << 51;

    if destination.is_nan() && source.is_nan() {
        return f64::from_bits(destination.to_bits() | QUIET_BIT);
    }

    result
}
