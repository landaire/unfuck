//! The `complex` type: construction, string parsing, and the slot methods
//! that forward to the interpreter's complex arithmetic.

use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::method;
use crate::interp::builtins::numeric::decimal_bytes;
use crate::interp::builtins::numeric::float::float_as_double;
use crate::interp::builtins::numeric::float::number_to_float;
use crate::interp::builtins::numeric::parse;
use crate::interp::builtins::parse as parse_arguments;
use crate::interp::builtins::static_method;
use crate::interp::complex::Complex;
use crate::interp::complex::Errno;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::sse;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().complex);

    crate::interp::builtins::install(
        vm,
        &class,
        &[
            static_method("__new__", complex_new),
            method("__add__", |vm, args| binary(vm, args, "__add__", BinaryOp::Add, false)),
            method("__radd__", |vm, args| binary(vm, args, "__radd__", BinaryOp::Add, true)),
            method("__sub__", |vm, args| binary(vm, args, "__sub__", BinaryOp::Subtract, false)),
            method("__rsub__", |vm, args| binary(vm, args, "__rsub__", BinaryOp::Subtract, true)),
            method("__mul__", |vm, args| binary(vm, args, "__mul__", BinaryOp::Multiply, false)),
            method("__rmul__", |vm, args| binary(vm, args, "__rmul__", BinaryOp::Multiply, true)),
            method("__div__", |vm, args| binary(vm, args, "__div__", BinaryOp::Divide, false)),
            method("__rdiv__", |vm, args| binary(vm, args, "__rdiv__", BinaryOp::Divide, true)),
            method("__truediv__", |vm, args| binary(vm, args, "__truediv__", BinaryOp::TrueDivide, false)),
            method("__rtruediv__", |vm, args| binary(vm, args, "__rtruediv__", BinaryOp::TrueDivide, true)),
            method("__floordiv__", |vm, args| binary(vm, args, "__floordiv__", BinaryOp::FloorDivide, false)),
            method("__rfloordiv__", |vm, args| binary(vm, args, "__rfloordiv__", BinaryOp::FloorDivide, true)),
            method("__mod__", |vm, args| binary(vm, args, "__mod__", BinaryOp::Modulo, false)),
            method("__rmod__", |vm, args| binary(vm, args, "__rmod__", BinaryOp::Modulo, true)),
            method("__divmod__", |vm, args| divmod(vm, args, "__divmod__", false)),
            method("__rdivmod__", |vm, args| divmod(vm, args, "__rdivmod__", true)),
            method("__pow__", |vm, args| power(vm, args, "__pow__", false)),
            method("__rpow__", |vm, args| power(vm, args, "__rpow__", true)),
            method("__eq__", |vm, args| compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__neg__", |vm, args| unary(vm, args, "__neg__", Unary::Negative)),
            method("__pos__", |vm, args| unary(vm, args, "__pos__", Unary::Positive)),
            method("__abs__", |vm, args| unary(vm, args, "__abs__", Unary::Absolute)),
            method("__nonzero__", |vm, args| unary(vm, args, "__nonzero__", Unary::Truth)),
            method("__int__", |vm, args| unary(vm, args, "__int__", Unary::Refused("int"))),
            method("__long__", |vm, args| unary(vm, args, "__long__", Unary::Refused("long"))),
            method("__float__", |vm, args| unary(vm, args, "__float__", Unary::Refused("float"))),
            method("__hash__", |vm, args| unary(vm, args, "__hash__", Unary::Hash)),
            method("__repr__", |vm, args| unary(vm, args, "__repr__", Unary::Repr)),
            method("__str__", |vm, args| unary(vm, args, "__str__", Unary::Str)),
            method("__coerce__", complex_coerce),
            method("__getnewargs__", complex_getnewargs),
            method("conjugate", complex_conjugate),
        ],
    )
}

fn bind_complex(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Complex, Value, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "complex")?;
    let Some(value) = vm.as_complex(&target) else {
        return Err(wrong_receiver(vm, method, "complex", &target));
    };

    Ok((value, target, rest))
}

/// The other operand of a binary slot as a complex number, or `None` for
/// `NotImplemented`: complex, float, int, and long operands convert.
fn operand(vm: &Vm, value: &Value) -> PyResult<Option<Complex>> {
    if let Some(number) = vm.as_complex(value) {
        return Ok(Some(number));
    }
    if let Some(number) = vm.as_float(value) {
        return Ok(Some(Complex::new(number, 0.0)));
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(Some(Complex::new(number as f64, 0.0))),
        Some(Integral::Long(number)) => match numbers::bigint_to_f64(&number) {
            Some(real) => Ok(Some(Complex::new(real, 0.0))),
            None => Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float")),
        },
        None => Ok(None),
    }
}

fn binary(vm: &Vm, args: CallArgs, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = operand(vm, &other)? else {
        return Ok(Value::NotImplemented);
    };
    let (value, other) = (vm.new_complex(value), vm.new_complex(other));

    if reflected { vm.binary_op(operation, &other, &value) } else { vm.binary_op(operation, &value, &other) }
}

/// `__divmod__` and `__rdivmod__`: the floored quotient and remainder.
fn divmod(vm: &Vm, args: CallArgs, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = operand(vm, &other)? else {
        return Ok(Value::NotImplemented);
    };
    let (value, other) = (vm.new_complex(value), vm.new_complex(other));
    let (dividend, divisor) = if reflected { (other, value) } else { (value, other) };

    Ok(vm.number_divmod(&dividend, &divisor)?.unwrap_or(Value::NotImplemented))
}

/// `__pow__` and `__rpow__`. The exponent converts before the modulus is
/// checked; any modulus but `None` is refused.
fn power(vm: &Vm, args: CallArgs, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, method)?;
    let arguments = unpack(vm, rest, "", 1, 2)?;
    if let Some(unknown) = arguments.iter().find(|argument| argument.is_unknown()) {
        return Ok(unknown.clone());
    }

    let Some(other) = operand(vm, &arguments[0])? else {
        return Ok(Value::NotImplemented);
    };
    if arguments.get(1).is_some_and(|modulus| !modulus.is_none()) {
        return Err(vm.raise(ExceptionKind::ValueError, "complex modulo"));
    }
    let (value, other) = (vm.new_complex(value), vm.new_complex(other));

    if reflected { vm.binary_op(BinaryOp::Power, &other, &value) } else { vm.binary_op(BinaryOp::Power, &value, &other) }
}

/// Rich comparison: ordering against another builtin number is an error;
/// other operands are `NotImplemented`.
fn compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let builtin_number = vm.as_complex(&other).is_some() || vm.as_float(&other).is_some() || vm.as_integral(&other).is_some();
    if !builtin_number {
        return Ok(Value::NotImplemented);
    }

    vm.compare(&vm.new_complex(value), &other, operation)
}

#[derive(Clone, Copy)]
enum Unary {
    Negative,
    Positive,
    Absolute,
    Truth,
    /// `__int__`, `__long__`, and `__float__`, which always fail.
    Refused(&'static str),
    Hash,
    Repr,
    Str,
}

fn unary(vm: &Vm, args: CallArgs, method: &str, operation: Unary) -> PyResult<Value> {
    let (value, target, rest) = bind_complex(vm, args, method)?;
    wrapper_arguments(vm, rest, 0)?;

    let result = match operation {
        Unary::Negative => vm.new_complex(-value),
        Unary::Positive => vm.positive(&target)?,
        Unary::Absolute => complex_abs(vm, value)?,
        Unary::Truth => Value::Bool(value.real != 0.0 || value.imag != 0.0),
        Unary::Refused(kind) => return Err(vm.type_error(&format!("can't convert complex to {kind}"))),
        Unary::Hash => Value::Int(value.hash(vm.config.long_width).value()),
        Unary::Repr => Value::str(&value.repr()),
        Unary::Str => Value::str(&value.str()),
    };

    Ok(result)
}

/// `abs()` of a complex number.
pub fn complex_abs(vm: &Vm, value: Complex) -> PyResult<Value> {
    let (magnitude, errno) = value.abs();
    if errno == Errno::Range {
        return Err(vm.raise(ExceptionKind::OverflowError, "absolute value too large"));
    }

    Ok(Value::Float(magnitude))
}

/// `__coerce__`: an int, long, or float becomes a complex.
fn complex_coerce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, target, rest) = bind_complex(vm, args, "__coerce__")?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    if vm.as_complex(&other).is_some() {
        return Ok(Value::tuple(vec![target, other]));
    }
    let Some(converted) = operand(vm, &other)? else {
        return Ok(Value::NotImplemented);
    };

    Ok(Value::tuple(vec![target, vm.new_complex(converted)]))
}

fn complex_getnewargs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, "__getnewargs__")?;
    no_arguments(vm, rest, "__getnewargs__")?;

    Ok(Value::tuple(vec![Value::Float(value.real), Value::Float(value.imag)]))
}

fn complex_conjugate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, _, rest) = bind_complex(vm, args, "conjugate")?;
    no_arguments(vm, rest, "conjugate")?;

    Ok(vm.new_complex(Complex::new(value.real, -value.imag)))
}

/// `complex([real[, imag]])`. A string is parsed whole and allows no
/// second argument. Otherwise `real` may convert through `__complex__`,
/// and each argument that is not complex converts through `__float__`;
/// the result is `real + imag * 1j` computed part by part.
fn complex_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().complex);
    let (class, rest) = new_class(vm, args, &base)?;
    let exact_class = Rc::ptr_eq(&class, &base);
    let mut slots = parse_arguments(vm, rest, "complex", &["real", "imag"], 0)?.into_iter();
    let real = slots.next().flatten();
    let imag = slots.next().flatten();

    if let Some(unknown) = real.iter().chain(imag.iter()).find(|value| value.is_unknown()) {
        return Ok(unknown.clone());
    }

    if let Some(real) = &real {
        if exact_class && imag.is_none() && is_exact_complex(real, &base) {
            return Ok(real.clone());
        }
        if is_string(vm, real) {
            if imag.is_some() {
                return Err(vm.type_error("complex() can't take second arg if first is a string"));
            }
            let value = complex_from_string(vm, real)?;
            return Ok(new_complex_of(vm, &class, exact_class, value));
        }
    }
    if imag.as_ref().is_some_and(|imag| is_string(vm, imag)) {
        return Err(vm.type_error("complex() second arg can't be a string"));
    }

    let real = match real {
        Some(real) => match special_complex(vm, &real)? {
            Some(converted) => Some(converted),
            None => Some(real),
        },
        None => None,
    };

    let real_convertible = match &real {
        Some(real) => has_float_slot(vm, real)?,
        None => true,
    };
    let imag_convertible = match &imag {
        Some(imag) => has_float_slot(vm, imag)?,
        None => true,
    };
    if !real_convertible || !imag_convertible {
        return Err(vm.type_error("complex() argument must be a string or a number"));
    }

    let real_part = match &real {
        Some(real) => match vm.as_complex(real) {
            Some(value) => Part::Complex(value),
            None => Part::Real(float_of(vm, real)?),
        },
        None => Part::Real(0.0),
    };
    let imag_part = match &imag {
        Some(imag) => match vm.as_complex(imag) {
            Some(value) => Part::Complex(value),
            None => Part::Real(float_as_double(vm, &float_slot(vm, imag)?)?),
        },
        None => Part::Real(0.0),
    };

    Ok(new_complex_of(vm, &class, exact_class, combine(real_part, imag_part)))
}

/// An argument of `complex()` after conversion.
#[derive(Clone, Copy)]
enum Part {
    Real(f64),
    Complex(Complex),
}

fn is_exact_complex(value: &Value, base: &ObjectRef) -> bool {
    matches!(value, Value::Object(object) if matches!(object.payload, Payload::Complex(_)) && Rc::ptr_eq(&object.class(), base))
}

/// `real + imag * 1j`. A complex `imag` subtracts its imaginary part from
/// the real one, where a zero difference is always positive; a complex
/// `real` adds its imaginary part to `imag`, which is the destination
/// operand.
fn combine(real: Part, imag: Part) -> Complex {
    let (real_value, real_imag) = match real {
        Part::Real(value) => (value, None),
        Part::Complex(value) => (value.real, Some(value.imag)),
    };
    let (imag_value, imag_imag) = match imag {
        Part::Real(value) => (value, None),
        Part::Complex(value) => (value.real, Some(value.imag)),
    };

    let result_real = match imag_imag {
        Some(shift) => sse::add(sse::sub(real_value, shift), 0.0),
        None => real_value,
    };
    let result_imag = match real_imag {
        Some(shift) => sse::add(imag_value, shift),
        None => imag_value,
    };

    Complex::new(result_real, result_imag)
}

fn is_string(vm: &Vm, value: &Value) -> bool {
    vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some()
}

fn new_complex_of(vm: &Vm, class: &ObjectRef, exact_class: bool, value: Complex) -> Value {
    if exact_class {
        return vm.new_complex(value);
    }

    new_instance(vm, class, Payload::Complex(value))
}

/// A real part through `float()` conversion, which checks the type of what
/// `__float__` returns.
fn float_of(vm: &Vm, value: &Value) -> PyResult<f64> {
    let converted = number_to_float(vm, value)?;
    match vm.as_float(&converted) {
        Some(number) => Ok(number),
        None => Err(vm.type_error("float(r) didn't return a float")),
    }
}

/// What the float conversion slot of `value` returns, unchecked: builtin
/// numbers convert, a classic instance needs a `__float__` attribute, and
/// other objects call their class's `__float__`.
fn float_slot(vm: &Vm, value: &Value) -> PyResult<Value> {
    if let Some(number) = vm.as_float(value) {
        return Ok(Value::Float(number));
    }
    if vm.as_integral(value).is_some() {
        return Ok(Value::Float(float_as_double(vm, value)?));
    }

    if let Value::Object(object) = value
        && vm.is_classic_class(&object.class())
    {
        return match vm.user_override(value, "__float__")? {
            Some(method) => vm.call0(&method),
            None => Err(vm.raise(ExceptionKind::AttributeError, &format!("{} instance has no attribute '__float__'", vm.class_name(&object.class())))),
        };
    }

    match vm.lookup_special(value, "__float__")? {
        Some(method) => vm.call0(&method),
        None => Err(vm.type_error("complex() argument must be a string or a number")),
    }
}

/// Whether `value` converts to a float: builtin numbers, classes defining
/// `__float__`, and every classic instance.
fn has_float_slot(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.as_complex(value).is_some() || vm.as_float(value).is_some() || vm.as_integral(value).is_some() {
        return Ok(true);
    }
    if let Value::Object(object) = value
        && vm.is_classic_class(&object.class())
    {
        return Ok(true);
    }

    Ok(vm.lookup_special(value, "__float__")?.is_some())
}

/// The result of `__complex__`, if the object has one.
fn special_complex(vm: &Vm, value: &Value) -> PyResult<Option<Value>> {
    match vm.lookup_special(value, "__complex__")? {
        Some(method) => Ok(Some(vm.call0(&method)?)),
        None => Ok(None),
    }
}

/// A complex function argument: a complex, the result of `__complex__`
/// (which must be complex), or the value as a float real part.
pub fn complex_argument(vm: &Vm, value: &Value) -> PyResult<Complex> {
    if let Some(number) = vm.as_complex(value) {
        return Ok(number);
    }

    if let Some(converted) = special_complex(vm, value)? {
        return match vm.as_complex(&converted) {
            Some(number) => Ok(number),
            None => Err(vm.type_error("__complex__ should return a complex object")),
        };
    }

    Ok(Complex::new(float_as_double(vm, value)?, 0.0))
}

/// A `str` or `unicode` argument of `complex()`. Unicode text converts
/// through the decimal encoding first.
fn complex_from_string(vm: &Vm, value: &Value) -> PyResult<Complex> {
    let bytes = match vm.as_str_bytes(value) {
        Some(bytes) => bytes.as_bytes().to_vec(),
        None => match vm.as_text(value) {
            Some(text) => decimal_bytes(vm, &text)?,
            None => return Err(vm.type_error("complex() argument must be a string or a number")),
        },
    };

    parse_complex(&bytes).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "complex() arg is a malformed string"))
}

/// Parses complex literal text. Whitespace may surround the literal and,
/// with one pair of parentheses, the inner literal. The literal is a real
/// number, an imaginary number (a number or a bare sign followed by `j`),
/// or a real number directly followed by a signed imaginary one.
fn parse_complex(text: &[u8]) -> Option<Complex> {
    let mut reader = LiteralReader { text, position: 0 };

    reader.skip_space();
    let parenthesized = reader.accept(b'(');
    if parenthesized {
        reader.skip_space();
    }

    let value = reader.literal()?;

    reader.skip_space();
    if parenthesized {
        if !reader.accept(b')') {
            return None;
        }
        reader.skip_space();
    }

    (reader.position == text.len()).then_some(value)
}

/// A position in complex literal text.
struct LiteralReader<'a> {
    text: &'a [u8],
    position: usize,
}

impl LiteralReader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.position).copied()
    }

    fn accept(&mut self, byte: u8) -> bool {
        if self.peek() != Some(byte) {
            return false;
        }

        self.position += 1;
        true
    }

    fn accept_imaginary_unit(&mut self) -> bool {
        self.accept(b'j') || self.accept(b'J')
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(parse::is_space) {
            self.position += 1;
        }
    }

    /// A float with at most one leading sign.
    fn number(&mut self) -> Option<f64> {
        let (value, length) = parse::scan_float(&self.text[self.position..])?;
        self.position += length;

        Some(value)
    }

    /// The unit `j` after an optional sign: `1j` or `-1j`.
    fn unit(&mut self) -> Option<f64> {
        let start = self.position;
        let negative = self.accept(b'-');
        if !negative {
            self.accept(b'+');
        }

        if self.accept_imaginary_unit() {
            return Some(if negative { -1.0 } else { 1.0 });
        }

        self.position = start;
        None
    }

    fn literal(&mut self) -> Option<Complex> {
        let Some(first) = self.number() else {
            let imag = self.unit()?;
            return Some(Complex::new(0.0, imag));
        };

        if self.accept_imaginary_unit() {
            return Some(Complex::new(0.0, first));
        }
        if !matches!(self.peek(), Some(b'+' | b'-')) {
            return Some(Complex::new(first, 0.0));
        }

        let imag = match self.unit() {
            Some(imag) => imag,
            None => {
                let imag = self.number()?;
                if !self.accept_imaginary_unit() {
                    return None;
                }
                imag
            }
        };

        Some(Complex::new(first, imag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_parse_like_complex_constructor() {
        assert_eq!(parse_complex(b" (1+2j) "), Some(Complex::new(1.0, 2.0)));
        assert_eq!(parse_complex(b"( 1+2j )"), Some(Complex::new(1.0, 2.0)));
        assert_eq!(parse_complex(b"-j"), Some(Complex::new(0.0, -1.0)));
        assert_eq!(parse_complex(b"J"), Some(Complex::new(0.0, 1.0)));
        assert_eq!(parse_complex(b"1-j"), Some(Complex::new(1.0, -1.0)));
        assert_eq!(parse_complex(b"1e3J"), Some(Complex::new(0.0, 1000.0)));
        assert_eq!(parse_complex(b"5"), Some(Complex::new(5.0, 0.0)));
        assert_eq!(parse_complex(b"1+2"), None);
        assert_eq!(parse_complex(b"1+-2j"), None);
        assert_eq!(parse_complex(b"1 +2j"), None);
        assert_eq!(parse_complex(b"((1))"), None);
        assert_eq!(parse_complex(b"(1+2j"), None);
        assert_eq!(parse_complex(b""), None);
    }
}
