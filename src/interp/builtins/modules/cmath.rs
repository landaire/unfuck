//! `cmath`. Arguments with an infinite or NaN part take their results from
//! tables measured on the reference interpreter (`cmath_special.rs`). Finite
//! arguments use the formulas of Kahan's "Branch Cuts for Complex Elementary
//! Functions" and the C99 definitions, with the overflow and underflow
//! guards and thresholds fixed by comparison with the reference interpreter.
//! `real_asinh`, `real_atan2`, and `real_log1p` are shared with `math`.

use std::f64::consts::E;
use std::f64::consts::LN_10;
use std::f64::consts::LN_2;
use std::f64::consts::PI;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::cmath_special;
use crate::interp::builtins::modules::math::real_asinh;
use crate::interp::builtins::modules::math::real_atan2;
use crate::interp::builtins::modules::math::real_log1p;
use crate::interp::builtins::numeric::complex::complex_argument;
use crate::interp::builtins::numeric::float::float_as_double;
use crate::interp::builtins::set_attribute;
use crate::interp::complex::Complex;
use crate::interp::complex::Computed;
use crate::interp::complex::Errno;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The category of one part of an argument. It selects the row (real part)
/// or column (imaginary part) of a special-value table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    NegativeInfinity,
    NegativeFinite,
    NegativeZero,
    PositiveZero,
    PositiveFinite,
    PositiveInfinity,
    NotANumber,
}

impl Category {
    fn of(value: f64) -> Self {
        if value.is_nan() {
            return Category::NotANumber;
        }
        if value.is_infinite() {
            return if value > 0.0 { Category::PositiveInfinity } else { Category::NegativeInfinity };
        }
        if value == 0.0 {
            return if value.is_sign_negative() { Category::NegativeZero } else { Category::PositiveZero };
        }

        if value > 0.0 { Category::PositiveFinite } else { Category::NegativeFinite }
    }
}

/// A special-value cell of a function whose non-finite arguments can raise
/// or give results that depend on the finite part.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum SpecialValue {
    Fixed(Complex),
    /// The function raises ValueError.
    Invalid,
    /// The parts are infinities, zeros, or ones whose signs follow the
    /// finite part of the argument.
    Signed,
}

/// Results of a function that never raises for non-finite arguments.
pub(super) type FixedTable = [[Complex; 7]; 7];

pub(super) type SpecialTable = [[SpecialValue; 7]; 7];

const FUNCTIONS: &[MethodSpec] = &[
    function("acos", |vm, args| complex_unary(vm, args, "acos", |z| no_error(complex_acos(z)))),
    function("acosh", |vm, args| complex_unary(vm, args, "acosh", |z| no_error(complex_acosh(z)))),
    function("asin", |vm, args| complex_unary(vm, args, "asin", |z| no_error(complex_asin(z)))),
    function("asinh", |vm, args| complex_unary(vm, args, "asinh", |z| no_error(complex_asinh(z)))),
    function("atan", |vm, args| complex_unary(vm, args, "atan", complex_atan)),
    function("atanh", |vm, args| complex_unary(vm, args, "atanh", complex_atanh)),
    function("cos", |vm, args| complex_unary(vm, args, "cos", complex_cos)),
    function("cosh", |vm, args| complex_unary(vm, args, "cosh", complex_cosh)),
    function("exp", |vm, args| complex_unary(vm, args, "exp", complex_exp)),
    function("isinf", cmath_isinf),
    function("isnan", cmath_isnan),
    function("log", cmath_log),
    function("log10", |vm, args| complex_unary(vm, args, "log10", complex_log10)),
    function("phase", cmath_phase),
    function("polar", cmath_polar),
    function("rect", cmath_rect),
    function("sin", |vm, args| complex_unary(vm, args, "sin", complex_sin)),
    function("sinh", |vm, args| complex_unary(vm, args, "sinh", complex_sinh)),
    function("sqrt", |vm, args| complex_unary(vm, args, "sqrt", |z| no_error(complex_sqrt(z)))),
    function("tan", |vm, args| complex_unary(vm, args, "tan", complex_tan)),
    function("tanh", |vm, args| complex_unary(vm, args, "tanh", complex_tanh)),
];

/// A quarter of the largest double. Parts beyond it would overflow the
/// general formulas, so those arguments use asymptotic forms.
const LARGE: f64 = f64::MAX / 4.0;

/// ln(LARGE). Past it, e^x would overflow before a sine or cosine factor
/// scales it down, so one factor of e is applied separately.
const LOG_LARGE: f64 = 708.3964185322641;

/// Scale for arguments whose parts are both subnormal.
const TWO_POW_53: f64 = 9007199254740992.0;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)?;

    set_attribute(vm, module, "pi", Value::Float(PI))?;
    set_attribute(vm, module, "e", Value::Float(E))
}

fn no_error(value: Complex) -> Computed {
    Computed { value, errno: Errno::Ok }
}

/// A result for an invalid operation. Callers raise without reading the
/// value.
fn invalid() -> Computed {
    Computed {
        value: Complex::new(f64::NAN, f64::NAN),
        errno: Errno::Domain,
    }
}

/// `value`, or a range error when a part overflowed.
fn overflow_checked(value: Complex) -> Computed {
    let errno = if value.real.is_infinite() || value.imag.is_infinite() {
        Errno::Range
    } else {
        Errno::Ok
    };

    Computed { value, errno }
}

/// The table cell for `z`, or `None` when both parts are finite.
fn table_entry<T>(z: Complex, table: &[[T; 7]; 7]) -> Option<T>
where
    T: Copy,
{
    if z.real.is_finite() && z.imag.is_finite() {
        return None;
    }

    let row = table.get(Category::of(z.real) as usize)?;
    row.get(Category::of(z.imag) as usize).copied()
}

/// The result of a cell of a special table. `signed` computes a signed
/// cell from the argument.
fn special_result(z: Complex, table: &SpecialTable, signed: fn(Complex) -> Complex) -> Option<Computed> {
    let entry = table_entry(z, table)?;

    let result = match entry {
        SpecialValue::Fixed(value) => no_error(value),
        SpecialValue::Invalid => invalid(),
        SpecialValue::Signed => no_error(signed(z)),
    };

    Some(result)
}

/// i z
fn times_i(z: Complex) -> Complex {
    Complex::new(-z.imag, z.real)
}

/// -i z
fn times_minus_i(z: Complex) -> Complex {
    Complex::new(z.imag, -z.real)
}

fn times_minus_i_computed(computed: Computed) -> Computed {
    Computed {
        value: times_minus_i(computed.value),
        errno: computed.errno,
    }
}

/// ln|z| + 2 ln 2 for parts large enough that |z| itself might overflow:
/// the asymptotic real part of the inverse functions.
fn ln_twice_abs_large(z: Complex) -> f64 {
    (z.real / 2.0).hypot(z.imag / 2.0).ln() + LN_2 * 2.0
}

fn complex_acos(z: Complex) -> Complex {
    if let Some(value) = table_entry(z, &cmath_special::ACOS) {
        return value;
    }

    if z.real.abs() > LARGE || z.imag.abs() > LARGE {
        // acos z ~ -i ln(2z).
        let real = real_atan2(z.imag.abs(), z.real);
        let magnitude = ln_twice_abs_large(z);
        let imag = if z.real < 0.0 { -magnitude.copysign(z.imag) } else { magnitude.copysign(-z.imag) };
        return Complex::new(real, imag);
    }

    // Kahan: Re = 2 atan(Re sqrt(1 - z) / Re sqrt(1 + z)),
    // Im = asinh(Im(conj(sqrt(1 + z)) sqrt(1 - z))).
    let minus = complex_sqrt(Complex::new(1.0 - z.real, -z.imag));
    let plus = complex_sqrt(Complex::new(1.0 + z.real, z.imag));
    let real = 2.0 * real_atan2(minus.real, plus.real);
    let imag = real_asinh(plus.real * minus.imag - plus.imag * minus.real);

    Complex::new(real, imag)
}

fn complex_acosh(z: Complex) -> Complex {
    if let Some(value) = table_entry(z, &cmath_special::ACOSH) {
        return value;
    }

    if z.real.abs() > LARGE || z.imag.abs() > LARGE {
        // acosh z ~ ln(2z).
        return Complex::new(ln_twice_abs_large(z), real_atan2(z.imag, z.real));
    }

    // Kahan: Re = asinh(Re(conj(sqrt(z - 1)) sqrt(z + 1))),
    // Im = 2 atan(Im sqrt(z - 1) / Re sqrt(z + 1)).
    let minus = complex_sqrt(Complex::new(z.real - 1.0, z.imag));
    let plus = complex_sqrt(Complex::new(z.real + 1.0, z.imag));
    let real = real_asinh(minus.real * plus.real + minus.imag * plus.imag);
    let imag = 2.0 * real_atan2(minus.imag, plus.real);

    Complex::new(real, imag)
}

fn complex_asin(z: Complex) -> Complex {
    // asin z = -i asinh(i z)
    times_minus_i(complex_asinh(times_i(z)))
}

fn complex_asinh(z: Complex) -> Complex {
    if let Some(value) = table_entry(z, &cmath_special::ASINH) {
        return value;
    }

    if z.real.abs() > LARGE || z.imag.abs() > LARGE {
        // asinh z ~ ln(2z) on the side of the real part's sign.
        let magnitude = ln_twice_abs_large(z);
        let real = if z.imag >= 0.0 { magnitude.copysign(z.real) } else { -magnitude.copysign(-z.real) };
        return Complex::new(real, real_atan2(z.imag, z.real.abs()));
    }

    // Kahan: with u = sqrt(1 + iz) and v = sqrt(1 - iz),
    // Re = asinh(Im(conj(u) v)), Im = atan(Im z / Re(u v)).
    let up = complex_sqrt(Complex::new(1.0 + z.imag, -z.real));
    let down = complex_sqrt(Complex::new(1.0 - z.imag, z.real));
    let real = real_asinh(up.real * down.imag - down.real * up.imag);
    let imag = real_atan2(z.imag, up.real * down.real - up.imag * down.imag);

    Complex::new(real, imag)
}

fn complex_atan(z: Complex) -> Computed {
    // atan z = -i atanh(i z)
    times_minus_i_computed(complex_atanh(times_i(z)))
}

fn complex_atanh(z: Complex) -> Computed {
    if let Some(value) = table_entry(z, &cmath_special::ATANH) {
        return no_error(value);
    }

    // atanh is odd, so the work is done for a real part that is not negative.
    if z.real < 0.0 {
        let reflected = atanh_right_half(-z);
        return Computed {
            value: -reflected.value,
            errno: reflected.errno,
        };
    }

    atanh_right_half(z)
}

/// atanh z = ln((1 + z) / (1 - z)) / 2 for finite z with Re z >= 0.
fn atanh_right_half(z: Complex) -> Computed {
    // The square root of `LARGE`, rounded: squares of smaller parts stay
    // finite.
    const SQRT_LARGE: f64 = 6.703903964971298e153;
    // The square root of the smallest normal double.
    const SQRT_MIN_NORMAL: f64 = 1.4916681462400413e-154;

    let Complex { real: x, imag: y } = z;
    let ay = y.abs();

    if x > SQRT_LARGE || ay > SQRT_LARGE {
        // atanh z ~ 1/z + i pi/2 sign(y): Re(1/z) = x / |z|^2.
        let half = (x / 2.0).hypot(y / 2.0);
        let real = x / 4.0 / half / half;
        let imag = -(PI / 2.0).copysign(-y);
        return no_error(Complex::new(real, imag));
    }

    if x == 1.0 && ay < SQRT_MIN_NORMAL {
        // At z = 1 the function has a pole; next to it the general formula
        // underflows, and Re = -ln(sqrt(|y|) / sqrt(|1 + i y/2| * 2)).
        if ay == 0.0 {
            return Computed {
                value: Complex::new(f64::INFINITY, y),
                errno: Errno::Domain,
            };
        }
        let real = -(ay.sqrt() / ay.hypot(2.0).sqrt()).ln();
        let imag = (real_atan2(2.0, -ay) / 2.0).copysign(y);
        return no_error(Complex::new(real, imag));
    }

    // Re = ln|1 + z|^2 / |1 - z|^2 / 4 = ln(1 + 4x / |1 - z|^2) / 4,
    // Im = arg((1 + z)(1 - conj z)) / 2.
    let real = real_log1p(4.0 * x / ((1.0 - x) * (1.0 - x) + ay * ay)) / 4.0;
    let imag = -real_atan2(-2.0 * y, (1.0 - x) * (1.0 + x) - ay * ay) / 2.0;

    no_error(Complex::new(real, imag))
}

fn complex_cos(z: Complex) -> Computed {
    // cos z = cosh(i z)
    complex_cosh(times_i(z))
}

fn complex_cosh(z: Complex) -> Computed {
    let signed = |z: Complex| {
        // cosh(+-inf + iy) = +inf (cos y +- i sin y)
        let real = f64::INFINITY.copysign(z.imag.cos());
        let imag = f64::INFINITY.copysign(z.imag.sin()) * z.real.signum();
        Complex::new(real, imag)
    };
    if let Some(result) = special_result(z, &cmath_special::COSH, signed) {
        return result;
    }

    let (real, imag) = if z.real.abs() > LOG_LARGE {
        let shifted = z.real - 1.0f64.copysign(z.real);
        (z.imag.cos() * shifted.cosh() * E, z.imag.sin() * shifted.sinh() * E)
    } else {
        (z.imag.cos() * z.real.cosh(), z.imag.sin() * z.real.sinh())
    };

    overflow_checked(Complex::new(real, imag))
}

fn complex_exp(z: Complex) -> Computed {
    let signed = |z: Complex| {
        // exp(+inf + iy) = +inf cis y, exp(-inf + iy) = +0 cis y
        let magnitude = if z.real > 0.0 { f64::INFINITY } else { 0.0 };
        Complex::new(magnitude.copysign(z.imag.cos()), magnitude.copysign(z.imag.sin()))
    };
    if let Some(result) = special_result(z, &cmath_special::EXP, signed) {
        return result;
    }

    let (real, imag) = if z.real > LOG_LARGE {
        let scale = (z.real - 1.0).exp();
        (scale * z.imag.cos() * E, scale * z.imag.sin() * E)
    } else {
        let scale = z.real.exp();
        (scale * z.imag.cos(), scale * z.imag.sin())
    };

    overflow_checked(Complex::new(real, imag))
}

fn complex_log(z: Complex) -> Computed {
    if let Some(value) = table_entry(z, &cmath_special::LOG) {
        return no_error(value);
    }

    let ax = z.real.abs();
    let ay = z.imag.abs();
    let angle = real_atan2(z.imag, z.real);

    let real = if ax > LARGE || ay > LARGE {
        (ax / 2.0).hypot(ay / 2.0).ln() + LN_2
    } else if ax < f64::MIN_POSITIVE && ay < f64::MIN_POSITIVE {
        if ax == 0.0 && ay == 0.0 {
            return Computed {
                value: Complex::new(f64::NEG_INFINITY, angle),
                errno: Errno::Domain,
            };
        }
        // Subnormal parts: scale up by 2^53 so the modulus keeps its bits.
        (ax * TWO_POW_53).hypot(ay * TWO_POW_53).ln() - 53.0 * LN_2
    } else {
        let modulus = ax.hypot(ay);
        if (0.71..=1.73).contains(&modulus) {
            // Near the unit circle, ln|z| = ln(1 + (|z|^2 - 1)) / 2 with
            // |z|^2 - 1 = (a - 1)(a + 1) + b^2 for the larger part a.
            let larger = ax.max(ay);
            let smaller = ax.min(ay);
            real_log1p((larger - 1.0) * (larger + 1.0) + smaller * smaller) / 2.0
        } else {
            modulus.ln()
        }
    };

    no_error(Complex::new(real, angle))
}

fn complex_log10(z: Complex) -> Computed {
    let natural = complex_log(z);

    Computed {
        value: Complex::new(natural.value.real / LN_10, natural.value.imag / LN_10),
        errno: natural.errno,
    }
}

fn complex_sin(z: Complex) -> Computed {
    // sin z = -i sinh(i z)
    times_minus_i_computed(complex_sinh(times_i(z)))
}

fn complex_sinh(z: Complex) -> Computed {
    let signed = |z: Complex| {
        // sinh(+-inf + iy) = +-inf cos y + i inf sin y
        let real = f64::INFINITY.copysign(z.imag.cos()) * z.real.signum();
        let imag = f64::INFINITY.copysign(z.imag.sin());
        Complex::new(real, imag)
    };
    if let Some(result) = special_result(z, &cmath_special::SINH, signed) {
        return result;
    }

    let (real, imag) = if z.real.abs() > LOG_LARGE {
        let shifted = z.real - 1.0f64.copysign(z.real);
        (z.imag.cos() * shifted.sinh() * E, z.imag.sin() * shifted.cosh() * E)
    } else {
        (z.imag.cos() * z.real.sinh(), z.imag.sin() * z.real.cosh())
    };

    overflow_checked(Complex::new(real, imag))
}

fn complex_sqrt(z: Complex) -> Complex {
    const TWO_POW_MINUS_27: f64 = 7.450580596923828e-9;

    if let Some(value) = table_entry(z, &cmath_special::SQRT) {
        return value;
    }

    if z.real == 0.0 && z.imag == 0.0 {
        return Complex::new(0.0, z.imag);
    }

    // Kahan: s = sqrt((|x| + |z|) / 2), then the other part is |y| / 2s.
    let ax = z.real.abs();
    let ay = z.imag.abs();
    let s = if ax < f64::MIN_POSITIVE && ay < f64::MIN_POSITIVE {
        // Both parts subnormal. The odd scale 2^53 makes the final 2^-27
        // also perform the halving: sqrt(2^53 v) 2^-27 = sqrt(v / 2).
        let scaled = ax * TWO_POW_53;
        (scaled + scaled.hypot(ay * TWO_POW_53)).sqrt() * TWO_POW_MINUS_27
    } else {
        // Dividing by 8 keeps the sum finite: 2 sqrt(v / 8) = sqrt(v / 2).
        let scaled = ax / 8.0;
        2.0 * (scaled + scaled.hypot(ay / 8.0)).sqrt()
    };
    let other = ay / (2.0 * s);

    if z.real >= 0.0 {
        Complex::new(s, other.copysign(z.imag))
    } else {
        Complex::new(other, s.copysign(z.imag))
    }
}

fn complex_tan(z: Complex) -> Computed {
    // tan z = -i tanh(i z)
    times_minus_i_computed(complex_tanh(times_i(z)))
}

fn complex_tanh(z: Complex) -> Computed {
    let signed = |z: Complex| {
        // tanh(+-inf + iy) = +-1 + i 0 sin 2y
        Complex::new(1.0f64.copysign(z.real), 0.0f64.copysign(z.imag.sin() * z.imag.cos()))
    };
    if let Some(result) = special_result(z, &cmath_special::TANH, signed) {
        return result;
    }

    if z.real.abs() > LOG_LARGE {
        // tanh(x + iy) - sign(x) is about 4 sin y cos y e^(-2|x|) i.
        let real = 1.0f64.copysign(z.real);
        let imag = 4.0 * z.imag.sin() * z.imag.cos() * (-2.0 * z.real.abs()).exp();
        return no_error(Complex::new(real, imag));
    }

    // tanh(x + iy) = (tanh x (1 + tan^2 y) + i tan y sech^2 x) / (1 + tanh^2 x tan^2 y)
    let tanh_x = z.real.tanh();
    let tan_y = z.imag.tan();
    let sech_x = 1.0 / z.real.cosh();
    let product = tanh_x * tan_y;
    let denominator = 1.0 + product * product;
    let real = tanh_x * (1.0 + tan_y * tan_y) / denominator;
    let imag = ((tan_y / denominator) * sech_x) * sech_x;

    no_error(Complex::new(real, imag))
}

/// Positional arguments of a varargs function checked against a format.
/// `format_name` is the name after `:` in the format, which the count
/// message shows in place of "function".
fn arguments(vm: &Vm, args: CallArgs, name: &str, format_name: Option<&str>, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    if count < minimum || count > maximum {
        let (expected, shown) = if minimum == maximum { ("exactly", minimum) } else if count < minimum { ("at least", minimum) } else { ("at most", maximum) };
        let plural = if shown == 1 { "" } else { "s" };
        let function = match format_name {
            Some(format_name) => format!("{format_name}()"),
            None => "function".to_owned(),
        };
        return Err(vm.type_error(&format!("{function} takes {expected} {shown} argument{plural} ({count} given)")));
    }

    Ok(args.positional)
}

/// The single argument of a `"D"` or `"D:name"` format.
fn single(vm: &Vm, args: CallArgs, name: &str, format_name: Option<&str>) -> PyResult<Value> {
    let mut positional = arguments(vm, args, name, format_name, 1, 1)?.into_iter();
    let Some(argument) = positional.next() else {
        return Err(vm.type_error(&format!("{name}() takes exactly one argument")));
    };

    Ok(argument)
}

fn unknown_result(name: &str) -> Value {
    Value::unknown(format!("cmath.{name}"))
}

/// The `"D"` conversion; `None` when the value is unknown.
fn complex_value(vm: &Vm, value: &Value) -> PyResult<Option<Complex>> {
    if let Value::Unknown(_) = value {
        return Ok(None);
    }

    complex_argument(vm, value).map(Some)
}

/// The `"d"` conversion; `None` when the value is unknown.
fn double_value(vm: &Vm, value: &Value) -> PyResult<Option<f64>> {
    if let Value::Unknown(_) = value {
        return Ok(None);
    }

    float_as_double(vm, value).map(Some)
}

/// Raises for a nonzero `errno`.
fn math_error(vm: &Vm, errno: Errno) -> PyResult<()> {
    match errno {
        Errno::Ok => Ok(()),
        Errno::Domain => Err(vm.raise(ExceptionKind::ValueError, "math domain error")),
        Errno::Range => Err(vm.raise(ExceptionKind::OverflowError, "math range error")),
    }
}

/// Applies a complex function of one argument to the argument converted to `complex`.
fn complex_unary(vm: &Vm, args: CallArgs, name: &str, compute: fn(Complex) -> Computed) -> PyResult<Value> {
    let argument = single(vm, args, name, None)?;
    let Some(z) = complex_value(vm, &argument)? else {
        return Ok(unknown_result(name));
    };

    let computed = compute(z);
    math_error(vm, computed.errno)?;

    Ok(vm.new_complex(computed.value))
}

/// `cmath.log`: the quotient of the logs for a base. The base's
/// complex log replaces the `errno` of the first, and only a zero divisor
/// in the division sets it again.
fn cmath_log(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let positional = arguments(vm, args, "log", None, 1, 2)?;
    let mut converted = Vec::with_capacity(positional.len());
    for argument in &positional {
        let Some(z) = complex_value(vm, argument)? else {
            return Ok(unknown_result("log"));
        };
        converted.push(z);
    }
    let Some(&x) = converted.first() else {
        return Err(vm.type_error("function takes at least 1 argument (0 given)"));
    };

    let mut computed = complex_log(x);
    if let Some(&base) = converted.get(1) {
        let base_log = complex_log(base);
        let quotient = computed.value.quot(base_log.value);
        let errno = if quotient.errno == Errno::Ok { base_log.errno } else { quotient.errno };
        computed = Computed { value: quotient.value, errno };
    }
    math_error(vm, computed.errno)?;

    Ok(vm.new_complex(computed.value))
}

/// `cmath.phase`. The Windows libm `atan2` sets no `errno` for finite
/// arguments, including an underflowing result, so this never raises.
fn cmath_phase(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "phase", Some("phase"))?;
    let Some(z) = complex_value(vm, &argument)? else {
        return Ok(unknown_result("phase"));
    };

    Ok(Value::Float(real_atan2(z.imag, z.real)))
}

/// `cmath.polar`: the absolute value sets the `errno`, `ERANGE` on overflow.
fn cmath_polar(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "polar", Some("polar"))?;
    let Some(z) = complex_value(vm, &argument)? else {
        return Ok(unknown_result("polar"));
    };

    let phi = real_atan2(z.imag, z.real);
    let (r, errno) = z.abs();
    math_error(vm, errno)?;

    Ok(Value::tuple(vec![Value::Float(r), Value::Float(phi)]))
}

/// `cmath.rect`: `rect(x, t)` behaves as `exp(log(x) + it)` for positive
/// `x` and as `-exp(log(-x) + it)` for negative `x`.
fn cmath_rect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let positional = arguments(vm, args, "rect", Some("rect"), 2, 2)?;
    let [r_argument, phi_argument] = positional.as_slice() else {
        return Err(vm.type_error("rect() takes exactly 2 arguments"));
    };
    let Some(r) = double_value(vm, r_argument)? else {
        return Ok(unknown_result("rect"));
    };
    let Some(phi) = double_value(vm, phi_argument)? else {
        return Ok(unknown_result("rect"));
    };

    let computed = rect(r, phi);
    math_error(vm, computed.errno)?;

    Ok(vm.new_complex(computed.value))
}

fn rect(r: f64, phi: f64) -> Computed {
    let signed = |z: Complex| {
        // rect(+-inf, phi) = +-inf (cos phi + i sin phi)
        let real = f64::INFINITY.copysign(z.imag.cos()) * z.real.signum();
        let imag = f64::INFINITY.copysign(z.imag.sin()) * z.real.signum();
        Complex::new(real, imag)
    };
    if let Some(result) = special_result(Complex::new(r, phi), &cmath_special::RECT, signed) {
        return result;
    }

    no_error(Complex::new(r * phi.cos(), r * phi.sin()))
}

fn cmath_isnan(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "isnan", Some("isnan"))?;
    let Some(z) = complex_value(vm, &argument)? else {
        return Ok(unknown_result("isnan"));
    };

    Ok(Value::Bool(z.real.is_nan() || z.imag.is_nan()))
}

/// `cmath.isinf`; its format names `isnan`.
fn cmath_isinf(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "isinf", Some("isnan"))?;
    let Some(z) = complex_value(vm, &argument)? else {
        return Ok(unknown_result("isinf"));
    };

    Ok(Value::Bool(z.real.is_infinite() || z.imag.is_infinite()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_follow_sign_and_class() {
        assert_eq!(Category::of(f64::NEG_INFINITY), Category::NegativeInfinity);
        assert_eq!(Category::of(-1e-320), Category::NegativeFinite);
        assert_eq!(Category::of(-0.0), Category::NegativeZero);
        assert_eq!(Category::of(0.0), Category::PositiveZero);
        assert_eq!(Category::of(f64::MAX), Category::PositiveFinite);
        assert_eq!(Category::of(f64::INFINITY), Category::PositiveInfinity);
        assert_eq!(Category::of(-f64::NAN), Category::NotANumber);
    }

    fn bits(text: &str) -> f64 {
        f64::from_bits(u64::from_str_radix(text, 16).expect("hex bits"))
    }

    fn render(computed: Computed) -> String {
        match computed.errno {
            Errno::Domain => "ValueError".to_owned(),
            Errno::Range => "OverflowError".to_owned(),
            Errno::Ok => format!("{:016x} {:016x}", computed.value.real.to_bits(), computed.value.imag.to_bits()),
        }
    }

    /// `cpython27_numeric.json` holds results on which the Windows and
    /// Linux reference builds agree, including every argument with an
    /// infinite or NaN part.
    #[test]
    fn functions_match_reference() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/interp/cpython27_numeric.json");
        let text = std::fs::read_to_string(path).expect("fixture exists");
        let data: serde_json::Value = serde_json::from_str(&text).expect("fixture parses");

        let mut checked = 0;
        for row in data["cmath"].as_array().expect("cmath rows") {
            let row = row.as_array().expect("row");
            let (real, imag) = row[0].as_str().expect("argument").split_once(' ').expect("two parts");
            let z = Complex::new(bits(real), bits(imag));
            let actual = [
                no_error(complex_acos(z)),
                no_error(complex_acosh(z)),
                no_error(complex_asin(z)),
                no_error(complex_asinh(z)),
                complex_atan(z),
                complex_atanh(z),
                complex_cos(z),
                complex_cosh(z),
                complex_exp(z),
                complex_log(z),
                complex_log10(z),
                complex_sin(z),
                complex_sinh(z),
                no_error(complex_sqrt(z)),
                complex_tan(z),
                complex_tanh(z),
                rect(z.real, z.imag),
            ];
            for (index, (expected, actual)) in row[1..].iter().zip(actual).enumerate() {
                let Some(expected) = expected.as_str() else {
                    continue;
                };
                assert_eq!(render(actual), expected, "function {index} at {real} {imag}");
                checked += 1;
            }
        }

        assert!(checked > 14000, "{checked} values checked");
    }

    #[test]
    fn finite_arguments_skip_tables() {
        assert_eq!(table_entry(Complex::new(1e308, -0.0), &cmath_special::SQRT), None);
        assert_eq!(
            table_entry(Complex::new(f64::INFINITY, -0.0), &cmath_special::SQRT),
            Some(Complex::new(f64::INFINITY, -0.0))
        );
    }
}

