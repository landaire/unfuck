//! `math`. The functions the client's build implements itself instead of
//! taking them from the C runtime (gamma, lgamma, erf, erfc, acosh, asinh,
//! atanh, expm1, and log1p) follow published formulas, with the formula
//! variants, term counts, and thresholds fixed by comparison with the
//! reference interpreter so results are bit-identical; the rest call libm.

use std::f64::consts::E;
use std::f64::consts::LN_2;
use std::f64::consts::PI;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::One;
use num_traits::Signed;
use num_traits::ToPrimitive;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::ops::BinaryOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// C `errno` value reported by a libm-style computation.
#[derive(Clone, Copy)]
enum MathError {
    /// `EDOM`.
    Domain,
    /// `ERANGE`.
    Range,
}

/// `errno` assigned to an infinite result from a finite argument.
#[derive(Clone, Copy)]
enum InfiniteResult {
    Domain,
    Overflow,
}

/// Result of a computation together with the `errno` it set.
struct Outcome {
    value: f64,
    error: Option<MathError>,
}

impl Outcome {
    fn new(value: f64) -> Self {
        Self { value, error: None }
    }

    fn failed(value: f64, error: MathError) -> Self {
        Self { value, error: Some(error) }
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("acos", math_acos),
            function("acosh", math_acosh),
            function("asin", math_asin),
            function("asinh", math_asinh),
            function("atan", math_atan),
            function("atan2", math_atan2),
            function("atanh", math_atanh),
            function("ceil", math_ceil),
            function("copysign", math_copysign),
            function("cos", math_cos),
            function("cosh", math_cosh),
            function("degrees", math_degrees),
            function("erf", math_erf),
            function("erfc", math_erfc),
            function("exp", math_exp),
            function("expm1", math_expm1),
            function("fabs", math_fabs),
            function("factorial", math_factorial),
            function("floor", math_floor),
            function("fmod", math_fmod),
            function("frexp", math_frexp),
            function("fsum", math_fsum),
            function("gamma", math_gamma),
            function("hypot", math_hypot),
            function("isinf", math_isinf),
            function("isnan", math_isnan),
            function("ldexp", math_ldexp),
            function("lgamma", math_lgamma),
            function("log", math_log),
            function("log1p", math_log1p),
            function("log10", math_log10),
            function("modf", math_modf),
            function("pow", math_pow),
            function("radians", math_radians),
            function("sin", math_sin),
            function("sinh", math_sinh),
            function("sqrt", math_sqrt),
            function("tan", math_tan),
            function("tanh", math_tanh),
            function("trunc", math_trunc),
        ],
    )?;

    set_attribute(vm, module, "pi", Value::Float(PI))?;
    set_attribute(vm, module, "e", Value::Float(E))
}

fn unknown_result(name: &str) -> Value {
    Value::unknown(format!("math.{name}"))
}

/// The single argument of a single-argument function.
fn single(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    let mut positional = args.positional.into_iter();
    match (positional.next(), count) {
        (Some(argument), 1) => Ok(argument),
        _ => Err(vm.type_error(&format!("{name}() takes exactly one argument ({count} given)"))),
    }
}

/// Arguments of a varargs function unpacked by count.
fn unpack(vm: &Vm, args: CallArgs, name: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    if count < minimum {
        let qualifier = if minimum == maximum { "" } else { "at least " };
        return Err(vm.type_error(&format!("{name} expected {qualifier}{minimum} arguments, got {count}")));
    }
    if count > maximum {
        let qualifier = if minimum == maximum { "" } else { "at most " };
        return Err(vm.type_error(&format!("{name} expected {qualifier}{maximum} arguments, got {count}")));
    }

    Ok(args.positional)
}

/// Both arguments of a two-argument varargs function.
fn pair(vm: &Vm, args: CallArgs, name: &str) -> PyResult<(Value, Value)> {
    let mut arguments = unpack(vm, args, name, 2, 2)?.into_iter();
    let (Some(first), Some(second)) = (arguments.next(), arguments.next()) else {
        return Err(vm.type_error(&format!("{name} expected 2 arguments")));
    };

    Ok((first, second))
}

fn is_classic_instance(vm: &Vm, value: &Value) -> bool {
    matches!(value, Value::Object(object) if vm.is_classic_class(&object.class()))
}

/// Bound `__float__` or `__trunc__` defined by a user class. Classic
/// instances always fill the slot, so a missing method raises AttributeError
/// for them.
fn numeric_slot(vm: &Vm, value: &Value, name: &str) -> PyResult<Option<Value>> {
    if is_classic_instance(vm, value) {
        return vm.getattr_str(value, name).map(Some);
    }

    vm.user_override(value, name)
}

fn long_to_double(vm: &Vm, value: &BigInt) -> PyResult<f64> {
    numbers::bigint_to_f64(value).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"))
}

/// Float conversion; `None` when the value is unknown.
fn as_double(vm: &Vm, value: &Value) -> PyResult<Option<f64>> {
    if let Value::Unknown(_) = value {
        return Ok(None);
    }

    if let Some(number) = vm.as_float(value) {
        return Ok(Some(number));
    }

    if let Some(method) = numeric_slot(vm, value, "__float__")? {
        let result = vm.call0(&method)?;
        if let Value::Unknown(_) = result {
            return Ok(None);
        }
        let Some(number) = vm.as_float(&result) else {
            return Err(vm.type_error("nb_float should return float object"));
        };
        return Ok(Some(number));
    }

    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to float"));
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(Some(number as f64)),
        Some(Integral::Long(number)) => long_to_double(vm, &number).map(Some),
        None => Err(vm.type_error("a float is required")),
    }
}

/// Range check against the configured C `long` width.
fn c_long(vm: &Vm, value: &BigInt) -> PyResult<i64> {
    match value.to_i64() {
        Some(number) if numbers::fits_int(vm.config.long_width, number) => Ok(number),
        _ => Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
    }
}

/// C `long` conversion; `None` when the value is unknown.
fn as_c_long(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if let Value::Unknown(_) = value {
        return Ok(None);
    }

    if let Some(integral) = vm.as_integral(value) {
        return c_long(vm, &integral.to_bigint()).map(Some);
    }

    let result = if is_classic_instance(vm, value) {
        classic_int(vm, value)?
    } else {
        let Some(method) = vm.user_override(value, "__int__")? else {
            return Err(vm.type_error("an integer is required"));
        };
        vm.call0(&method)?
    };
    if let Value::Unknown(_) = result {
        return Ok(None);
    }
    let Some(integral) = vm.as_integral(&result) else {
        return Err(vm.type_error("nb_int should return int object"));
    };

    c_long(vm, &integral.to_bigint()).map(Some)
}

/// Integer conversion of a classic instance: `__int__`, else `__trunc__`
/// converted to an integer.
pub(super) fn classic_int(vm: &Vm, value: &Value) -> PyResult<Value> {
    if let Some(method) = vm.getattr_opt(value, &PyBytes::from("__int__"))? {
        return vm.call0(&method);
    }

    let truncate = vm.getattr_str(value, "__trunc__")?;
    let truncated = vm.call0(&truncate)?;
    if matches!(truncated, Value::Unknown(_)) || vm.as_integral(&truncated).is_some() {
        return Ok(truncated);
    }

    // float.__int__ applied directly; other results need an `__int__`
    // attribute returning an integer.
    if let Some(x) = vm.as_float(&truncated) {
        return float_to_int(vm, x.trunc());
    }
    let non_integral = |result: &Value| {
        let type_name = match result {
            Value::Object(object) if vm.is_classic_class(&object.class()) => vm.class_name(&object.class()),
            _ => vm.type_name(result),
        };
        vm.type_error(&format!("__trunc__ returned non-Integral (type {type_name})"))
    };
    let Some(method) = vm.getattr_opt(&truncated, &PyBytes::from("__int__"))? else {
        return Err(non_integral(&truncated));
    };
    let result = vm.call0(&method)?;
    if matches!(result, Value::Unknown(_)) || vm.as_integral(&result).is_some() {
        return Ok(result);
    }

    Err(non_integral(&result))
}

/// Raises for the `errno` a computation set. Underflow
/// (`ERANGE` with a result below one in magnitude) is not an error.
fn check(vm: &Vm, outcome: Outcome) -> PyResult<f64> {
    match outcome.error {
        None => Ok(outcome.value),
        Some(MathError::Domain) => Err(vm.raise(ExceptionKind::ValueError, "math domain error")),
        Some(MathError::Range) if outcome.value.abs() < 1.0 => Ok(outcome.value),
        Some(MathError::Range) => Err(vm.raise(ExceptionKind::OverflowError, "math range error")),
    }
}

/// Error classification for a libm result of one argument.
fn classify_1(x: f64, value: f64, infinite: InfiniteResult) -> Outcome {
    let error = if value.is_nan() {
        (!x.is_nan()).then_some(MathError::Domain)
    } else if value.is_infinite() && x.is_finite() {
        Some(match infinite {
            InfiniteResult::Domain => MathError::Domain,
            InfiniteResult::Overflow => MathError::Range,
        })
    } else {
        None
    };

    Outcome { value, error }
}

/// Wraps a libm function of one argument.
fn math_unary(vm: &Vm, args: CallArgs, name: &str, compute: fn(f64) -> f64, infinite: InfiniteResult) -> PyResult<Value> {
    let argument = single(vm, args, name)?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result(name));
    };

    check(vm, classify_1(x, compute(x), infinite)).map(Value::Float)
}

/// Wraps a function of one argument that reports its own `errno`.
fn math_unary_outcome(vm: &Vm, args: CallArgs, name: &str, compute: fn(f64) -> Outcome) -> PyResult<Value> {
    let argument = single(vm, args, name)?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result(name));
    };

    check(vm, compute(x)).map(Value::Float)
}

/// Both arguments of a two-argument function as doubles; `None` when either
/// is unknown.
fn doubles_2(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Option<(f64, f64)>> {
    let (first, second) = pair(vm, args, name)?;
    let x = as_double(vm, &first)?;
    let y = as_double(vm, &second)?;

    Ok(x.zip(y))
}

/// Wraps a libm function of two arguments.
fn math_binary(vm: &Vm, args: CallArgs, name: &str, compute: fn(f64, f64) -> f64) -> PyResult<Value> {
    let Some((x, y)) = doubles_2(vm, args, name)? else {
        return Ok(unknown_result(name));
    };

    let value = compute(x, y);
    let error = if value.is_nan() {
        (!x.is_nan() && !y.is_nan()).then_some(MathError::Domain)
    } else if value.is_infinite() && x.is_finite() && y.is_finite() {
        Some(MathError::Range)
    } else {
        None
    };

    check(vm, Outcome { value, error }).map(Value::Float)
}

fn math_acos(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "acos", f64::acos, InfiniteResult::Domain)
}

fn math_acosh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "acosh", real_acosh, InfiniteResult::Domain)
}

fn math_asin(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "asin", f64::asin, InfiniteResult::Domain)
}

fn math_asinh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "asinh", real_asinh, InfiniteResult::Domain)
}

fn math_atan(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "atan", f64::atan, InfiniteResult::Domain)
}

fn math_atan2(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_binary(vm, args, "atan2", real_atan2)
}

fn math_atanh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "atanh", real_atanh, InfiniteResult::Domain)
}

fn math_ceil(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "ceil", f64::ceil, InfiniteResult::Domain)
}

fn math_copysign(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_binary(vm, args, "copysign", f64::copysign)
}

fn math_cos(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "cos", f64::cos, InfiniteResult::Domain)
}

fn math_cosh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "cosh", f64::cosh, InfiniteResult::Overflow)
}

fn math_erf(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary_outcome(vm, args, "erf", |x| Outcome::new(real_erf(x)))
}

fn math_erfc(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary_outcome(vm, args, "erfc", |x| Outcome::new(real_erfc(x)))
}

fn math_exp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "exp", f64::exp, InfiniteResult::Overflow)
}

fn math_expm1(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "expm1", real_expm1, InfiniteResult::Overflow)
}

fn math_fabs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "fabs", f64::abs, InfiniteResult::Domain)
}

fn math_floor(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "floor", f64::floor, InfiniteResult::Domain)
}

fn math_gamma(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary_outcome(vm, args, "gamma", real_tgamma)
}

fn math_lgamma(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary_outcome(vm, args, "lgamma", real_lgamma)
}

fn math_log1p(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "log1p", real_log1p, InfiniteResult::Overflow)
}

fn math_sin(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "sin", f64::sin, InfiniteResult::Domain)
}

fn math_sinh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "sinh", f64::sinh, InfiniteResult::Overflow)
}

fn math_sqrt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "sqrt", f64::sqrt, InfiniteResult::Domain)
}

fn math_tan(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "tan", f64::tan, InfiniteResult::Domain)
}

fn math_tanh(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    math_unary(vm, args, "tanh", f64::tanh, InfiniteResult::Domain)
}

/// `math.fsum`: Shewchuk's exact summation with correctly rounded result.
fn math_fsum(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let sequence = single(vm, args, "fsum")?;
    let iterator = vm.iter(&sequence)?;

    let mut partials: Vec<f64> = Vec::new();
    let mut special_sum = 0.0;
    let mut inf_sum = 0.0;
    while let Some(item) = vm.next(&iterator)? {
        let Some(mut x) = as_double(vm, &item)? else {
            return Ok(unknown_result("fsum"));
        };

        let original = x;
        let mut kept = 0;
        for index in 0..partials.len() {
            let mut y = partials[index];
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let high = x + y;
            let low = y - (high - x);
            if low != 0.0 {
                partials[kept] = low;
                kept += 1;
            }
            x = high;
        }
        partials.truncate(kept);

        if x == 0.0 {
            continue;
        }
        if x.is_finite() {
            partials.push(x);
            continue;
        }

        // A non-finite partial comes from overflow or from a special summand.
        if original.is_finite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "intermediate overflow in fsum"));
        }
        if original.is_infinite() {
            inf_sum += original;
        }
        special_sum += original;
        partials.clear();
    }

    if special_sum != 0.0 {
        if inf_sum.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "-inf + inf in fsum"));
        }
        return Ok(Value::Float(special_sum));
    }

    Ok(Value::Float(sum_partials(&partials)))
}

/// Correctly rounded sum of non-overlapping partials in increasing
/// magnitude, summed from the top until the sum becomes inexact.
fn sum_partials(partials: &[f64]) -> f64 {
    let Some((&top, rest)) = partials.split_last() else {
        return 0.0;
    };

    let mut high = top;
    let mut low = 0.0;
    let mut remaining = rest;
    while let Some((&y, below)) = remaining.split_last() {
        let x = high;
        high = x + y;
        low = y - (high - x);
        remaining = below;
        if low != 0.0 {
            break;
        }
    }

    // Half-even rounding across partials: the sign of the next partial
    // breaks a tie in `low`.
    if let Some(&next) = remaining.last()
        && ((low < 0.0 && next < 0.0) || (low > 0.0 && next > 0.0))
    {
        let y = low * 2.0;
        let x = high + y;
        if y == x - high {
            high = x;
        }
    }

    high
}

/// `math.factorial`: `int` (promoting to `long`) for integral arguments.
fn math_factorial(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "factorial")?;

    let count = if let Some(x) = vm.as_float(&argument) {
        if !(x.is_finite() && x == x.floor()) {
            return Err(vm.raise(ExceptionKind::ValueError, "factorial() only accepts integral values"));
        }
        let Some(whole) = BigInt::from_f64(x) else {
            return Err(vm.raise(ExceptionKind::ValueError, "factorial() only accepts integral values"));
        };
        c_long(vm, &whole)?
    } else {
        let Some(count) = as_c_long(vm, &argument)? else {
            return Ok(unknown_result("factorial"));
        };
        count
    };
    if count < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "factorial() not defined for negative values"));
    }

    let mut product = BigInt::one();
    for factor in 1..=count {
        vm.count_step()?;
        product *= factor;
    }

    Ok(vm.new_int(product))
}

/// `math.trunc`: calls `__trunc__`. The builtin numeric implementations
/// are applied directly.
fn math_trunc(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "trunc")?;
    if let Value::Unknown(_) = argument {
        return Ok(argument);
    }

    if let Some(method) = numeric_slot(vm, &argument, "__trunc__")? {
        return vm.call0(&method);
    }

    if let Some(x) = vm.as_float(&argument) {
        return float_to_int(vm, x.trunc());
    }

    match vm.as_integral(&argument) {
        Some(Integral::Int(number)) => Ok(Value::Int(number)),
        Some(Integral::Long(_)) if matches!(argument, Value::Long(_)) => Ok(argument),
        Some(Integral::Long(number)) => Ok(Value::Long(Rc::new(number))),
        None => vm.call_method(&argument, "__trunc__", Vec::new()),
    }
}

/// An integral double as a `long`, demoted to `int` when it fits.
fn float_to_int(vm: &Vm, x: f64) -> PyResult<Value> {
    if x.is_infinite() {
        return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
    }

    let Some(whole) = BigInt::from_f64(x) else {
        return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
    };

    Ok(vm.new_int(whole))
}

fn math_frexp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "frexp")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("frexp"));
    };

    let (mantissa, exponent) = frexp(x);

    Ok(Value::tuple(vec![Value::Float(mantissa), Value::Int(i64::from(exponent))]))
}

/// `math.ldexp`: the exponent saturates to the C `int` range.
fn math_ldexp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "ldexp", 2, 2)?;
    let [mantissa, exponent] = arguments.as_slice() else {
        return Err(vm.type_error("ldexp() takes exactly 2 arguments"));
    };

    let Some(x) = as_double(vm, mantissa)? else {
        return Ok(unknown_result("ldexp"));
    };
    if let Value::Unknown(_) = exponent {
        return Ok(unknown_result("ldexp"));
    }
    let exponent = match vm.as_integral(exponent) {
        Some(Integral::Int(number)) => number,
        Some(Integral::Long(number)) => number.to_i64().unwrap_or(if number.is_negative() { i64::MIN } else { i64::MAX }),
        None => return Err(vm.type_error("Expected an int or long as second argument to ldexp.")),
    };

    let outcome = if x == 0.0 || !x.is_finite() {
        Outcome::new(x)
    } else if exponent > i64::from(i32::MAX) {
        Outcome::failed(f64::INFINITY.copysign(x), MathError::Range)
    } else if exponent < i64::from(i32::MIN) {
        Outcome::new(0.0f64.copysign(x))
    } else {
        let value = scalbn(x, exponent);
        if value.is_infinite() { Outcome::failed(value, MathError::Range) } else { Outcome::new(value) }
    };

    check(vm, outcome).map(Value::Float)
}

fn math_modf(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "modf")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("modf"));
    };

    let (fraction, whole) = if x.is_infinite() {
        (0.0f64.copysign(x), x)
    } else if x.is_nan() {
        (x, x)
    } else {
        let whole = x.trunc();
        ((x - whole).copysign(x), whole)
    };

    Ok(Value::tuple(vec![Value::Float(fraction), Value::Float(whole)]))
}

/// Logarithm argument handling: positive `long` arguments too large for a
/// double are reduced to mantissa and exponent. `None` when the argument
/// is unknown.
fn log_argument(vm: &Vm, argument: &Value, compute: fn(f64) -> f64) -> PyResult<Option<f64>> {
    if let Some(Integral::Long(number)) = vm.as_integral(argument) {
        if !number.is_positive() {
            return Err(vm.raise(ExceptionKind::ValueError, "math domain error"));
        }
        let result = match numbers::bigint_to_f64(&number) {
            Some(x) => compute(x),
            None => {
                let (mantissa, exponent) = long_frexp(&number);
                compute(mantissa) + compute(2.0) * exponent as f64
            }
        };
        return Ok(Some(result));
    }

    let Some(x) = as_double(vm, argument)? else {
        return Ok(None);
    };

    check(vm, classify_1(x, compute(x), InfiniteResult::Domain)).map(Some)
}

fn math_log(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = unpack(vm, args, "log", 1, 2)?;
    let mut arguments = arguments.into_iter();
    let Some(argument) = arguments.next() else {
        return Err(vm.type_error("log expected at least 1 arguments, got 0"));
    };

    let Some(numerator) = log_argument(vm, &argument, real_log)? else {
        return Ok(unknown_result("log"));
    };
    let Some(base) = arguments.next() else {
        return Ok(Value::Float(numerator));
    };
    let Some(denominator) = log_argument(vm, &base, real_log)? else {
        return Ok(unknown_result("log"));
    };

    vm.binary_op(BinaryOp::Divide, &Value::Float(numerator), &Value::Float(denominator))
}

fn math_log10(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "log10")?;

    match log_argument(vm, &argument, real_log10)? {
        Some(result) => Ok(Value::Float(result)),
        None => Ok(unknown_result("log10")),
    }
}

fn math_fmod(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((x, y)) = doubles_2(vm, args, "fmod")? else {
        return Ok(unknown_result("fmod"));
    };

    if y.is_infinite() && x.is_finite() {
        return Ok(Value::Float(x));
    }

    let value = x % y;
    let error = (value.is_nan() && !x.is_nan() && !y.is_nan()).then_some(MathError::Domain);

    check(vm, Outcome { value, error }).map(Value::Float)
}

fn math_hypot(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((x, y)) = doubles_2(vm, args, "hypot")? else {
        return Ok(unknown_result("hypot"));
    };

    // hypot(x, +-inf) is inf even when x is a NaN.
    if x.is_infinite() {
        return Ok(Value::Float(x.abs()));
    }
    if y.is_infinite() {
        return Ok(Value::Float(y.abs()));
    }

    let value = x.hypot(y);
    let error = if value.is_nan() {
        (!x.is_nan() && !y.is_nan()).then_some(MathError::Domain)
    } else if value.is_infinite() && x.is_finite() && y.is_finite() {
        Some(MathError::Range)
    } else {
        None
    };

    check(vm, Outcome { value, error }).map(Value::Float)
}

/// `math.pow`: IEEE special values follow C99 Annex F directly.
fn math_pow(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((x, y)) = doubles_2(vm, args, "pow")? else {
        return Ok(unknown_result("pow"));
    };

    let outcome = if x.is_finite() && y.is_finite() {
        let value = x.powf(y);
        if value.is_nan() || (value.is_infinite() && x == 0.0) {
            Outcome::failed(value, MathError::Domain)
        } else if value.is_infinite() {
            Outcome::failed(value, MathError::Range)
        } else {
            Outcome::new(value)
        }
    } else if x.is_nan() {
        Outcome::new(if y == 0.0 { 1.0 } else { x })
    } else if y.is_nan() {
        Outcome::new(if x == 1.0 { 1.0 } else { y })
    } else if x.is_infinite() {
        let odd_y = y.is_finite() && y.abs() % 2.0 == 1.0;
        let value = if y > 0.0 {
            if odd_y { x } else { x.abs() }
        } else if y == 0.0 {
            1.0
        } else if odd_y {
            0.0f64.copysign(x)
        } else {
            0.0
        };
        Outcome::new(value)
    } else if x.abs() == 1.0 {
        Outcome::new(1.0)
    } else if y > 0.0 && x.abs() > 1.0 {
        Outcome::new(y)
    } else if y < 0.0 && x.abs() < 1.0 {
        // 0 ** -inf is a division by zero.
        if x == 0.0 { Outcome::failed(-y, MathError::Domain) } else { Outcome::new(-y) }
    } else {
        Outcome::new(0.0)
    };

    check(vm, outcome).map(Value::Float)
}

fn math_degrees(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const RADIANS_TO_DEGREES: f64 = 180.0 / PI;

    let argument = single(vm, args, "degrees")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("degrees"));
    };

    Ok(Value::Float(x * RADIANS_TO_DEGREES))
}

fn math_radians(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const DEGREES_TO_RADIANS: f64 = PI / 180.0;

    let argument = single(vm, args, "radians")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("radians"));
    };

    Ok(Value::Float(x * DEGREES_TO_RADIANS))
}

fn math_isnan(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "isnan")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("isnan"));
    };

    Ok(Value::Bool(x.is_nan()))
}

fn math_isinf(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "isinf")?;
    let Some(x) = as_double(vm, &argument)? else {
        return Ok(unknown_result("isinf"));
    };

    Ok(Value::Bool(x.is_infinite()))
}

/// C `frexp` for finite non-zero `x`; other values return `(x, 0)`.
fn frexp(x: f64) -> (f64, i32) {
    const TWO_POW_54: f64 = 18014398509481984.0;
    const EXPONENT_MASK: u64 = 0x7ff << 52;

    if x == 0.0 || !x.is_finite() {
        return (x, 0);
    }

    let (normal, adjustment) = if x.abs() < f64::MIN_POSITIVE { (x * TWO_POW_54, -54) } else { (x, 0) };
    let bits = normal.to_bits();
    let biased = ((bits & EXPONENT_MASK) >> 52) as i32;
    let mantissa = f64::from_bits((bits & !EXPONENT_MASK) | (1022 << 52));

    (mantissa, biased - 1022 + adjustment)
}

/// `scalbn` (musl): `x * 2**exponent` with a single rounding.
pub(crate) fn scalbn(x: f64, exponent: i64) -> f64 {
    const TWO_POW_1023: f64 = f64::from_bits(0x7fe << 52);
    // 2**-1022 * 2**53: keeps the final step below -53 so subnormal
    // results round once.
    const TWO_POW_MINUS_969: f64 = f64::from_bits(54 << 52);

    let mut value = x;
    let mut exponent = exponent;
    if exponent > 1023 {
        value *= TWO_POW_1023;
        exponent -= 1023;
        if exponent > 1023 {
            value *= TWO_POW_1023;
            exponent = (exponent - 1023).min(1023);
        }
    } else if exponent < -1022 {
        value *= TWO_POW_MINUS_969;
        exponent += 1022 - 53;
        if exponent < -1022 {
            value *= TWO_POW_MINUS_969;
            exponent = (exponent + 1022 - 53).max(-1022);
        }
    }

    let scale = f64::from_bits(((0x3ff + exponent) as u64) << 52);

    value * scale
}

/// Splits a positive value: `value ~= mantissa * 2**exponent` with the
/// mantissa in `[0.5, 1)` rounded half-even to 53 bits.
fn long_frexp(value: &BigInt) -> (f64, u64) {
    const MANTISSA_BITS: u64 = 53;
    const TWO_POW_53: f64 = 9007199254740992.0;

    let magnitude = value.magnitude();
    let bits = magnitude.bits();
    let shift = bits.saturating_sub(MANTISSA_BITS);

    let mut top = (magnitude >> shift).to_u64().unwrap_or(0);
    if shift > 0 && magnitude.bit(shift - 1) {
        let sticky = magnitude.trailing_zeros().is_some_and(|zeros| zeros < shift - 1);
        if sticky || top & 1 == 1 {
            top += 1;
        }
    }

    if top == 1 << MANTISSA_BITS {
        return (0.5, bits + 1);
    }

    (top as f64 / TWO_POW_53, bits)
}

/// `atan2` with special values handled directly for cross-platform results.
pub(crate) fn real_atan2(y: f64, x: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return numbers::PY_NAN;
    }

    if y.is_infinite() {
        if x.is_infinite() {
            let quadrant = if x.is_sign_positive() { 0.25 } else { 0.75 };
            return (quadrant * PI).copysign(y);
        }
        return (0.5 * PI).copysign(y);
    }

    if x.is_infinite() || y == 0.0 {
        if x.is_sign_positive() {
            return 0.0f64.copysign(y);
        }
        return PI.copysign(y);
    }

    y.atan2(x)
}

/// `log` with special values handled directly.
fn real_log(x: f64) -> f64 {
    if x.is_finite() {
        if x > 0.0 {
            return x.ln();
        }
        return if x == 0.0 { f64::NEG_INFINITY } else { f64::NAN };
    }

    if x.is_nan() || x > 0.0 {
        return x;
    }

    f64::NAN
}

/// `log10` with special values handled directly.
fn real_log10(x: f64) -> f64 {
    if x.is_finite() {
        if x > 0.0 {
            return x.log10();
        }
        return if x == 0.0 { f64::NEG_INFINITY } else { f64::NAN };
    }

    if x.is_nan() || x > 0.0 {
        return x;
    }

    f64::NAN
}

/// ln(1 + x). Within [-0.5, 1] the sum `u = 1 + x` is rounded, and the
/// exactly computable rounding error `(u - 1) - x` is removed to first
/// order. Below half an ulp of 1 the sum rounds to 1 and `x` itself is the
/// correctly rounded answer.
pub(crate) fn real_log1p(x: f64) -> f64 {
    if x.abs() < f64::EPSILON / 2.0 {
        return x;
    }

    if (-0.5..=1.0).contains(&x) {
        let u = 1.0 + x;
        return u.ln() - ((u - 1.0) - x) / u;
    }

    (1.0 + x).ln()
}

/// exp(x) - 1. Near zero the subtraction cancels, so the rounded
/// difference is rescaled by `x / ln(u)`, where `u` is the rounded `exp(x)`;
/// the same rounding error appears in both and divides out.
fn real_expm1(x: f64) -> f64 {
    if x.abs() < 0.7 {
        let u = x.exp();
        if u == 1.0 {
            return x;
        }

        return (u - 1.0) * x / u.ln();
    }

    x.exp() - 1.0
}

/// Magnitude above which `x + sqrt(x^2 + 1)` is `2x` to double precision.
const HUGE_HYPERBOLIC: f64 = 268_435_456.0;

/// Magnitude below which asinh(x) and atanh(x) round to `x`.
const TINY_HYPERBOLIC: f64 = 1.0 / HUGE_HYPERBOLIC;

/// ln(x + sqrt(x^2 - 1)), with forms chosen per range to avoid cancellation.
fn real_acosh(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x < 1.0 {
        return f64::NAN;
    }

    if x >= HUGE_HYPERBOLIC {
        if x.is_infinite() {
            return x;
        }
        return x.ln() + LN_2;
    }

    if x == 1.0 {
        return 0.0;
    }

    if x > 2.0 {
        let root = (x * x - 1.0).sqrt();
        return (2.0 * x - 1.0 / (x + root)).ln();
    }

    // Near 1, with t = x - 1: x + sqrt(x^2 - 1) = 1 + t + sqrt(2t + t^2).
    let t = x - 1.0;
    real_log1p(t + (2.0 * t + t * t).sqrt())
}

/// ln(x + sqrt(x^2 + 1)), computed for |x| and given the sign of `x`.
pub(crate) fn real_asinh(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        return x;
    }

    let magnitude = x.abs();
    if magnitude < TINY_HYPERBOLIC {
        return x;
    }

    let result = if magnitude > HUGE_HYPERBOLIC {
        magnitude.ln() + LN_2
    } else if magnitude > 2.0 {
        let root = (x * x + 1.0).sqrt();
        (2.0 * magnitude + 1.0 / (root + magnitude)).ln()
    } else {
        // sqrt(x^2 + 1) - 1 = x^2 / (1 + sqrt(1 + x^2)) keeps the small
        // argument of ln(1 + ...) accurate.
        let square = x * x;
        real_log1p(magnitude + square / (1.0 + (1.0 + square).sqrt()))
    };

    result.copysign(x)
}

/// ln((1 + x) / (1 - x)) / 2, computed for |x| and given the sign of `x`.
fn real_atanh(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }

    let magnitude = x.abs();
    if magnitude >= 1.0 {
        return f64::NAN;
    }
    if magnitude < TINY_HYPERBOLIC {
        return x;
    }

    // (1 + a) / (1 - a) = 1 + 2a / (1 - a), and for small a the term
    // 2a + 2a * a / (1 - a) keeps more of 2a exact.
    let doubled = magnitude + magnitude;
    let result = if magnitude < 0.5 {
        0.5 * real_log1p(doubled + doubled * magnitude / (1.0 - magnitude))
    } else {
        0.5 * real_log1p(doubled / (1.0 - magnitude))
    };

    result.copysign(x)
}

/// sin(pi * x). The argument is reduced modulo 2 exactly and then folded
/// to within a quarter period of a zero or extremum of sine, so the
/// multiplication by pi never sees a large argument.
fn sin_pi(x: f64) -> f64 {
    let reduced = x.abs() % 2.0;
    let quarter = (2.0 * reduced).round();

    let magnitude = if quarter == 0.0 {
        (PI * reduced).sin()
    } else if quarter == 1.0 {
        (PI * (reduced - 0.5)).cos()
    } else if quarter == 2.0 {
        (PI * (1.0 - reduced)).sin()
    } else if quarter == 3.0 {
        -(PI * (reduced - 1.5)).cos()
    } else {
        (PI * (reduced - 2.0)).sin()
    };

    1.0f64.copysign(x) * magnitude
}

/// The Lanczos approximation with N = 13 terms and
/// g = 6.024680040776729583740234375 (exact in binary):
/// Gamma(x) = L(x) * (x + g - 1/2)^(x - 1/2) * e^-(x + g - 1/2), with
/// L(x) = P(x) / Q(x) and Q(x) = x (x + 1) ... (x + 11). The numerator was
/// computed from the series definition by `generate_lanczos.py`.
const LANCZOS_G: f64 = 6.02468004077673;
const LANCZOS_G_MINUS_HALF: f64 = 5.52468004077673;
const LANCZOS_NUMERATOR: [f64; 13] = [
    23531376880.41076,
    42919803642.6491,
    35711959237.35567,
    17921034426.03721,
    6039542586.352028,
    1439720407.3117216,
    248874557.86205417,
    31426415.585400194,
    2876370.6289353725,
    186056.26539522348,
    8071.672002365816,
    210.82427775157936,
    2.5066282746310002,
];
const LANCZOS_DENOMINATOR: [f64; 13] = rising_product_coefficients();

/// Coefficients, in ascending powers, of x (x + 1) ... (x + 11).
const fn rising_product_coefficients() -> [f64; 13] {
    let mut integral = [0u64; 13];
    integral[0] = 1;

    let mut factor = 0;
    while factor < 12 {
        // Multiply the polynomial by (x + factor).
        let mut power = factor + 1;
        while power > 0 {
            integral[power] = integral[power - 1] + integral[power] * factor as u64;
            power -= 1;
        }
        integral[0] *= factor as u64;
        factor += 1;
    }

    let mut coefficients = [0.0; 13];
    let mut index = 0;
    while index < 13 {
        coefficients[index] = integral[index] as f64;
        index += 1;
    }

    coefficients
}

/// L(x) = P(x) / Q(x). Small arguments use Horner's rule in x; larger ones
/// divide numerator and denominator by x^12 and use Horner's rule in 1/x,
/// which keeps the intermediate values in range.
fn lanczos_sum(x: f64) -> f64 {
    let (numerator, denominator) = if x < 5.0 {
        LANCZOS_NUMERATOR
            .iter()
            .zip(LANCZOS_DENOMINATOR.iter())
            .rev()
            .fold((0.0, 0.0), |(num, den), (p, q)| (num * x + p, den * x + q))
    } else {
        LANCZOS_NUMERATOR
            .iter()
            .zip(LANCZOS_DENOMINATOR.iter())
            .fold((0.0, 0.0), |(num, den), (p, q)| (num / x + p, den / x + q))
    };

    numerator / denominator
}

/// The relative correction for the rounding of `y = absx + g - 1/2`. With
/// `e` the rounding error of `y`, (y - e)^(x - 1/2) e^-(y - e) is about the
/// computed power times `1 + e g / y`. The error is found exactly by
/// subtracting the larger addend first.
fn lanczos_shift_correction(absx: f64, y: f64) -> f64 {
    let error = if absx > LANCZOS_G_MINUS_HALF {
        (y - absx) - LANCZOS_G_MINUS_HALF
    } else {
        (y - LANCZOS_G_MINUS_HALF) - absx
    };

    error * LANCZOS_G / y
}

/// Gamma at the integers 1 through 23, which double precision holds
/// exactly.
const INTEGER_GAMMA: [f64; 23] = factorials();

const fn factorials() -> [f64; 23] {
    let mut exact = [1u128; 23];
    let mut index = 1;
    while index < 23 {
        exact[index] = exact[index - 1] * index as u128;
        index += 1;
    }

    let mut values = [0.0; 23];
    let mut index = 0;
    while index < 23 {
        values[index] = exact[index] as f64;
        index += 1;
    }

    values
}

/// Below this magnitude Gamma(x) is 1/x to double precision.
const TINY_GAMMA_ARGUMENT: f64 = 1e-20;

fn finished(value: f64) -> Outcome {
    if value.is_infinite() {
        return Outcome::failed(value, MathError::Range);
    }

    Outcome::new(value)
}

/// Gamma(x), with poles at zero and the negative integers.
fn real_tgamma(x: f64) -> Outcome {
    // Arguments at or above this use y^(x/2 - 1/4) twice, since y^(x - 1/2)
    // alone would overflow before the division by e^y.
    const SPLIT_POWER: f64 = 140.0;
    // Above this magnitude Gamma overflows for positive arguments and
    // underflows to a signed zero for negative ones.
    const HUGE_ARGUMENT: f64 = 200.0;

    if x.is_nan() || x == f64::INFINITY {
        return Outcome::new(x);
    }
    if x == f64::NEG_INFINITY || x == 0.0 {
        return Outcome::failed(f64::NAN, MathError::Domain);
    }

    if x == x.floor() {
        if x < 0.0 {
            return Outcome::failed(f64::NAN, MathError::Domain);
        }
        // The saturating conversion sends large integers past the table.
        if let Some(value) = INTEGER_GAMMA.get((x as usize).wrapping_sub(1)) {
            return Outcome::new(*value);
        }
    }

    let absx = x.abs();
    if absx < TINY_GAMMA_ARGUMENT {
        return finished(1.0 / x);
    }
    if absx > HUGE_ARGUMENT {
        if x < 0.0 {
            return Outcome::new(0.0 / sin_pi(x));
        }
        return Outcome::failed(f64::INFINITY, MathError::Range);
    }

    let y = absx + LANCZOS_G_MINUS_HALF;
    let correction = lanczos_shift_correction(absx, y);

    if x > 0.0 {
        let mut result = lanczos_sum(absx) / y.exp();
        result += correction * result;
        if absx < SPLIT_POWER {
            result *= y.powf(absx - 0.5);
        } else {
            let half_power = y.powf(absx / 2.0 - 0.25);
            result *= half_power;
            result *= half_power;
        }
        return finished(result);
    }

    // Reflection: Gamma(-a) = -pi / (a sin(pi a) Gamma(a)).
    let mut result = -PI / sin_pi(absx) / absx * y.exp() / lanczos_sum(absx);
    result -= correction * result;
    if absx < SPLIT_POWER {
        result /= y.powf(absx - 0.5);
    } else {
        let half_power = y.powf(absx / 2.0 - 0.25);
        result /= half_power;
        result /= half_power;
    }

    finished(result)
}

/// ln|Gamma(x)|, with poles at zero and the negative integers.
fn real_lgamma(x: f64) -> Outcome {
    // ln(pi), rounded.
    const LN_PI: f64 = 1.1447298858494002;

    if x.is_nan() {
        return Outcome::new(x);
    }
    if x.is_infinite() {
        return Outcome::new(f64::INFINITY);
    }

    if x == x.floor() && x <= 2.0 {
        if x <= 0.0 {
            return Outcome::failed(f64::INFINITY, MathError::Domain);
        }
        return Outcome::new(0.0);
    }

    let absx = x.abs();
    if absx < TINY_GAMMA_ARGUMENT {
        return Outcome::new(-absx.ln());
    }

    // ln L(a) + (a - 1/2) ln(a + g - 1/2) - (a + g - 1/2), with the
    // trailing a - 1/2 folded into the logarithm term.
    let mut result = lanczos_sum(absx).ln() - LANCZOS_G;
    result += (absx - 0.5) * ((absx + LANCZOS_G - 0.5).ln() - 1.0);

    if x < 0.0 {
        result = LN_PI - sin_pi(absx).abs().ln() - absx.ln() - result;
    }

    finished(result)
}


/// The magnitude below which erf and erfc use the power series rather than
/// the continued fraction.
const ERF_SERIES_LIMIT: f64 = 1.5;

/// sqrt(pi), rounded.
const SQRT_PI: f64 = 1.772453850905516;

/// erf(x) = 2/sqrt(pi) x e^(-x^2) sum_n (2x^2)^n / (1 * 3 * ... * (2n + 1)).
/// The series is summed from its innermost term outward, as twice the sum
/// (each step multiplies by x^2 / (n + 1/2) and adds 2).
fn erf_series(x: f64) -> f64 {
    const TERMS: u32 = 25;

    let square = x * x;
    let twice_sum = (0..TERMS)
        .rev()
        .fold(0.0, |sum, n| 2.0 + square * sum / (f64::from(n) + 1.5));

    twice_sum * x * (-square).exp() / SQRT_PI
}

/// erfc(x) for x >= ERF_SERIES_LIMIT from the even part of Laplace's
/// continued fraction:
/// erfc(x) = e^(-x^2) / sqrt(pi) * x / (x^2 + 1/2 - a1 / (x^2 + 5/2 - a2 / ...)),
/// with a_n = n (2n - 1) / 2 and partial denominators x^2 + 2n + 1/2. The
/// convergents follow the three-term recurrence for numerator and
/// denominator.
fn erfc_continued_fraction(x: f64) -> f64 {
    const TERMS: u32 = 50;
    // From here on erfc(x) is below the smallest subnormal.
    const UNDERFLOW: f64 = 30.0;

    if x >= UNDERFLOW {
        return 0.0;
    }

    let square = x * x;
    let mut numerator = (1.0, 0.0);
    let mut denominator = (0.5 + square, 1.0);
    for n in 1..=TERMS {
        let n = f64::from(n);
        let partial_numerator = n * (2.0 * n - 1.0) / 2.0;
        let partial_denominator = 2.0 * n + 0.5 + square;
        numerator = (
            partial_denominator * numerator.0 - partial_numerator * numerator.1,
            numerator.0,
        );
        denominator = (
            partial_denominator * denominator.0 - partial_numerator * denominator.1,
            denominator.0,
        );
    }

    numerator.0 / denominator.0 * x * (-square).exp() / SQRT_PI
}

fn real_erf(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }

    let magnitude = x.abs();
    if magnitude < ERF_SERIES_LIMIT {
        return erf_series(x);
    }

    let tail = erfc_continued_fraction(magnitude);
    if x > 0.0 { 1.0 - tail } else { tail - 1.0 }
}

fn real_erfc(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }

    let magnitude = x.abs();
    if magnitude < ERF_SERIES_LIMIT {
        return 1.0 - erf_series(x);
    }

    let tail = erfc_continued_fraction(magnitude);
    if x > 0.0 { tail } else { 2.0 - tail }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(text: &str) -> f64 {
        f64::from_bits(u64::from_str_radix(text, 16).expect("hex bits"))
    }

    /// A result as the reference fixture prints it: the bits, or the
    /// exception the module raises for it.
    fn render(argument: f64, value: f64, error: Option<MathError>) -> String {
        match error {
            Some(MathError::Domain) => return "ValueError".to_owned(),
            Some(MathError::Range) => return "OverflowError".to_owned(),
            None => {}
        }
        if value.is_nan() && !argument.is_nan() {
            return "ValueError".to_owned();
        }
        if value.is_infinite() && argument.is_finite() {
            return "OverflowError".to_owned();
        }

        format!("{:016x}", value.to_bits())
    }

    #[test]
    fn lanczos_denominator_is_the_rising_product() {
        for x in [0.0, 1.0, 2.0, 7.5] {
            let horner = LANCZOS_DENOMINATOR.iter().rev().fold(0.0, |sum, coefficient| sum * x + coefficient);
            let product: f64 = (0..12).map(|offset| x + f64::from(offset)).product();
            assert_eq!(horner, product, "x = {x}");
        }
    }

    #[test]
    fn integer_gamma_values_are_factorials() {
        assert_eq!(INTEGER_GAMMA[0], 1.0);
        assert_eq!(INTEGER_GAMMA[5], 120.0);
        assert_eq!(INTEGER_GAMMA[22], 1_124_000_727_777_607_680_000.0);
    }

    /// `cpython27_numeric.json` holds results on which the Windows and
    /// Linux reference builds agree.
    #[test]
    fn special_functions_match_reference() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/interp/cpython27_numeric.json");
        let text = std::fs::read_to_string(path).expect("fixture exists");
        let data: serde_json::Value = serde_json::from_str(&text).expect("fixture parses");

        let mut checked = 0;
        for row in data["math"].as_array().expect("math rows") {
            let row = row.as_array().expect("row");
            let x = bits(row[0].as_str().expect("argument"));
            let gamma = real_tgamma(x);
            let lgamma = real_lgamma(x);
            let actual = [
                render(x, gamma.value, gamma.error),
                render(x, lgamma.value, lgamma.error),
                render(x, real_erf(x), None),
                render(x, real_erfc(x), None),
                render(x, real_log1p(x), None),
                render(x, real_expm1(x), None),
                render(x, real_acosh(x), None),
                render(x, real_asinh(x), None),
                render(x, real_atanh(x), None),
            ];
            for (index, (expected, actual)) in row[1..].iter().zip(actual).enumerate() {
                let Some(expected) = expected.as_str() else {
                    continue;
                };
                assert_eq!(actual, expected, "function {index} at {:016x}", x.to_bits());
                checked += 1;
            }
        }

        assert!(checked > 8000, "{checked} values checked");
    }
}
