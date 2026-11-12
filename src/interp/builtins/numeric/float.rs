//! `float`.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::FromPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::class_method;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::numeric::decimal_bytes;
use crate::interp::builtins::numeric::parse::FloatSyntax;
use crate::interp::builtins::numeric::parse::HexFloatError;
use crate::interp::builtins::numeric::parse;
use crate::interp::builtins::parse as parse_arguments;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().float);

    crate::interp::builtins::install(
        vm,
        &class,
        &[
            static_method("__new__", float_new),
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
            method("__pos__", |vm, args| unary(vm, args, "__pos__", Unary::Plain)),
            method("__abs__", |vm, args| unary(vm, args, "__abs__", Unary::Absolute)),
            method("__nonzero__", |vm, args| unary(vm, args, "__nonzero__", Unary::Truth)),
            method("__int__", |vm, args| unary(vm, args, "__int__", Unary::ToInt)),
            method("__trunc__", |vm, args| unary(vm, args, "__trunc__", Unary::ToInt)),
            method("__long__", |vm, args| unary(vm, args, "__long__", Unary::ToLong)),
            method("__float__", |vm, args| unary(vm, args, "__float__", Unary::Plain)),
            method("__hash__", |vm, args| unary(vm, args, "__hash__", Unary::Hash)),
            method("__repr__", |vm, args| unary(vm, args, "__repr__", Unary::Repr)),
            method("__str__", |vm, args| unary(vm, args, "__str__", Unary::Str)),
            method("__coerce__", float_coerce),
            method("__getnewargs__", float_getnewargs),
            method("conjugate", float_conjugate),
            method("is_integer", float_is_integer),
            method("as_integer_ratio", float_as_integer_ratio),
            method("hex", float_hex),
            class_method("fromhex", float_fromhex),
            class_method("__getformat__", float_getformat),
        ],
    )?;

    add_getset(vm, &class, GetSet { name: "real", owner: "float", get: getset, set: None })?;
    add_getset(vm, &class, GetSet { name: "imag", owner: "float", get: getset, set: None })
}

fn bind_float(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(f64, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "float")?;
    let Some(value) = vm.as_float(&target) else {
        return Err(wrong_receiver(vm, method, "float", &target));
    };

    Ok((value, rest))
}

/// An operand `float` arithmetic accepts (`float`, `int`, or `long`), as a plain
/// value.
fn operand(vm: &Vm, value: &Value) -> Option<Value> {
    if let Some(float) = vm.as_float(value) {
        return Some(Value::Float(float));
    }

    match vm.as_integral(value)? {
        Integral::Int(number) => Some(Value::Int(number)),
        Integral::Long(number) => Some(Value::long(number)),
    }
}

/// The integer conversion of `__trunc__`.
pub fn float_to_integer(vm: &Vm, value: f64) -> PyResult<BigInt> {
    if value.is_nan() {
        return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
    }

    match BigInt::from_f64(value.trunc()) {
        Some(number) => Ok(number),
        None => Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer")),
    }
}

/// `real` and `imag`.
fn getset(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(value) = vm.as_float(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Float(if getset.name == "imag" { 0.0 } else { value }))
}

fn binary(vm: &Vm, args: CallArgs, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let value = Value::Float(value);

    if reflected { vm.binary_op(operation, &other, &value) } else { vm.binary_op(operation, &value, &other) }
}

fn divmod(vm: &Vm, args: CallArgs, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let value = Value::Float(value);
    let (left, right) = if reflected { (other, value) } else { (value, other) };

    Ok(Value::tuple(vec![vm.binary_op(BinaryOp::FloorDivide, &left, &right)?, vm.binary_op(BinaryOp::Modulo, &left, &right)?]))
}

/// `**`, which refuses a modulus.
fn power(vm: &Vm, args: CallArgs, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, method)?;
    let arguments = positional(vm, rest, method, 1, 2)?;
    if let Some(unknown) = arguments.iter().find(|argument| argument.is_unknown()) {
        return Ok(unknown.clone());
    }

    let Some(other) = operand(vm, &arguments[0]) else {
        return Ok(Value::NotImplemented);
    };
    if arguments.get(1).is_some_and(|modulus| !modulus.is_none()) {
        return Err(vm.type_error("pow() 3rd argument not allowed unless all arguments are integers"));
    }

    let value = Value::Float(value);
    if reflected { vm.binary_op(BinaryOp::Power, &other, &value) } else { vm.binary_op(BinaryOp::Power, &value, &other) }
}

fn compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };

    vm.compare(&Value::Float(value), &other, operation)
}

#[derive(Clone, Copy)]
enum Unary {
    Negative,
    Plain,
    Absolute,
    Truth,
    ToInt,
    ToLong,
    Hash,
    Repr,
    Str,
}

fn unary(vm: &Vm, args: CallArgs, method: &str, operation: Unary) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, method)?;
    wrapper_arguments(vm, rest, 0)?;

    let result = match operation {
        Unary::Negative => Value::Float(-value),
        Unary::Plain => Value::Float(value),
        Unary::Absolute => Value::Float(value.abs()),
        Unary::Truth => Value::Bool(value != 0.0),
        Unary::ToInt => vm.new_int(float_to_integer(vm, value)?),
        Unary::ToLong => Value::long(float_to_integer(vm, value)?),
        Unary::Hash => Value::Int(vm.hash(&Value::Float(value))?.value()),
        Unary::Repr => Value::str(&numbers::float_repr(value)),
        Unary::Str => Value::str(&numbers::float_str(value)),
    };

    Ok(result)
}

/// An int or long operand becomes a float.
fn float_coerce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__coerce__", "float")?;
    if vm.as_float(&target).is_none() {
        return Err(wrong_receiver(vm, "__coerce__", "float", &target));
    }
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let converted = match vm.as_integral(&other) {
        _ if vm.as_float(&other).is_some() => other,
        Some(Integral::Int(number)) => Value::Float(number as f64),
        Some(Integral::Long(number)) => match numbers::bigint_to_f64(&number) {
            Some(float) => Value::Float(float),
            None => return Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float")),
        },
        None => return Ok(Value::NotImplemented),
    };

    Ok(Value::tuple(vec![target, converted]))
}

fn float_getnewargs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, "__getnewargs__")?;
    no_arguments(vm, rest, "__getnewargs__")?;

    Ok(Value::tuple(vec![Value::Float(value)]))
}

fn float_conjugate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, "conjugate")?;
    no_arguments(vm, rest, "conjugate")?;

    Ok(Value::Float(value))
}

fn float_is_integer(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, "is_integer")?;
    no_arguments(vm, rest, "is_integer")?;

    Ok(Value::Bool(value.is_finite() && value.floor() == value))
}

/// Doubles the frexp mantissa until it is integral, then folds the
/// exponent into one side.
fn float_as_integer_ratio(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, "as_integer_ratio")?;
    no_arguments(vm, rest, "as_integer_ratio")?;

    if value.is_infinite() {
        return Err(vm.raise(ExceptionKind::OverflowError, "Cannot pass infinity to float.as_integer_ratio."));
    }
    if value.is_nan() {
        return Err(vm.raise(ExceptionKind::ValueError, "Cannot pass NaN to float.as_integer_ratio."));
    }

    let (mut mantissa, mut exponent) = parse::frexp(value);
    for _ in 0..300 {
        if mantissa == mantissa.floor() {
            break;
        }
        mantissa *= 2.0;
        exponent -= 1;
    }

    let mut numerator = float_to_integer(vm, mantissa)?;
    let mut denominator = BigInt::from(1);
    let shift = exponent.unsigned_abs() as usize;
    if exponent > 0 {
        numerator <<= shift;
    } else {
        denominator <<= shift;
    }

    Ok(Value::tuple(vec![vm.new_int(numerator), vm.new_int(denominator)]))
}

fn float_hex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (value, rest) = bind_float(vm, args, "hex")?;
    no_arguments(vm, rest, "hex")?;

    if !value.is_finite() {
        return Ok(Value::str(&numbers::float_repr(value)));
    }

    Ok(Value::str(&parse::float_hex(value)))
}

/// Bytes of a `str`, or of a `unicode` in the default encoding, for the
/// `s#` argument format.
fn text_argument(vm: &Vm, value: &Value, function: &str) -> PyResult<Vec<u8>> {
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(bytes.as_bytes().to_vec());
    }
    if let Some(text) = vm.as_text(value) {
        if let Value::Str(bytes) = vm.encode_default(&text)? {
            return Ok(bytes.as_bytes().to_vec());
        }
    }

    Err(vm.type_error(&format!("{function}() argument 1 must be string or read-only character buffer, not {}", vm.type_name(value))))
}

/// A subclass receives the parsed float through its constructor.
fn float_fromhex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, rest) = bind(vm, args, "fromhex", "float")?;
    let text = one_argument(vm, rest, "fromhex")?;
    if text.is_unknown() {
        return Ok(text);
    }

    let value = match parse::float_from_hex(&text_argument(vm, &text, "fromhex")?) {
        Ok(value) => value,
        Err(HexFloatError::Invalid) => return Err(vm.raise(ExceptionKind::ValueError, "invalid hexadecimal floating-point string")),
        Err(HexFloatError::Overflow) => return Err(vm.raise(ExceptionKind::OverflowError, "hexadecimal value too large to represent as a float")),
    };

    if let Value::Object(class_object) = &class {
        if !Rc::ptr_eq(class_object, &vm.types().float) {
            return vm.call1(&class, Value::Float(value));
        }
    }

    Ok(Value::Float(value))
}

/// `float.__getformat__`: the interpreter models IEEE little-endian
/// doubles, as on every platform the client runs on.
fn float_getformat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = bind(vm, args, "__getformat__", "float")?;
    let kind = one_argument(vm, rest, "__getformat__")?;
    let Some(kind) = vm.as_str_bytes(&kind) else {
        return Err(vm.type_error(&format!("__getformat__() argument 1 must be string, not {}", vm.type_name(&kind))));
    };

    match kind.as_bytes() {
        b"double" | b"float" => Ok(Value::str("IEEE, little-endian")),
        _ => Err(vm.raise(ExceptionKind::ValueError, "__getformat__() argument 1 must be 'double' or 'float'")),
    }
}

/// `float.__new__` for `float` and its subclasses.
fn float_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().float);
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse_arguments(vm, rest, "float", &["x"], 0)?;

    let value = match &slots[0] {
        None => Value::Float(0.0),
        Some(value) => number_to_float(vm, value)?,
    };

    if Rc::ptr_eq(&class, &base) || value.is_unknown() {
        return Ok(value);
    }

    let float = vm.as_float(&value).unwrap_or(0.0);

    Ok(new_instance(vm, &class, Payload::Float(float)))
}

/// Parses strings; other values convert through `__float__`.
pub(super) fn number_to_float(vm: &Vm, value: &Value) -> PyResult<Value> {
    if value.is_unknown() {
        return Ok(value.clone());
    }

    if let Some(bytes) = vm.as_str_bytes(value) {
        return string_to_float(vm, bytes.as_bytes()).map(Value::Float);
    }

    if let Some(result) = conversion_hook(vm, value)? {
        if result.is_unknown() || vm.as_float(&result).is_some() {
            return Ok(result);
        }
        return Err(vm.type_error(&format!("__float__ returned non-float (type {})", vm.type_name(&result))));
    }

    if let Some(float) = vm.as_float(value) {
        return Ok(Value::Float(float));
    }
    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to float"));
    }
    match vm.as_integral(value) {
        Some(Integral::Int(number)) => return Ok(Value::Float(number as f64)),
        Some(Integral::Long(number)) => {
            return numbers::bigint_to_f64(&number).map(Value::Float).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"));
        }
        None => {}
    }
    if let Some(text) = vm.as_text(value) {
        return string_to_float(vm, &decimal_bytes(vm, &text)?).map(Value::Float);
    }
    if let Some(bytes) = vm.single_segment_buffer(value, BufferInterface::Character)? {
        return string_to_float(vm, bytes.as_bytes()).map(Value::Float);
    }

    Err(vm.type_error("float() argument must be a string or a number"))
}

/// A float, or the result of the type's `__float__`, which must be a
/// float.
pub fn float_as_double(vm: &Vm, value: &Value) -> PyResult<f64> {
    if let Some(number) = vm.as_float(value) {
        return Ok(number);
    }
    match vm.as_integral(value) {
        Some(Integral::Int(number)) => return Ok(number as f64),
        Some(Integral::Long(number)) => {
            return numbers::bigint_to_f64(&number).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"));
        }
        None => {}
    }

    let hook = match value {
        Value::Object(object) if vm.is_classic_class(&object.class()) => conversion_hook(vm, value)?,
        _ => match vm.user_override(value, "__float__")? {
            Some(method) => Some(vm.call0(&method)?),
            None => None,
        },
    };
    let Some(result) = hook else {
        if vm.as_complex(value).is_some() {
            return Err(vm.type_error("can't convert complex to float"));
        }
        return Err(vm.type_error("a float is required"));
    };

    vm.as_float(&result).ok_or_else(|| vm.type_error("nb_float should return float object"))
}

/// `__float__` of a user object; classic instances always have the slot.
fn conversion_hook(vm: &Vm, value: &Value) -> PyResult<Option<Value>> {
    if let Value::Object(object) = value {
        if vm.is_classic_class(&object.class()) {
            return match vm.user_override(value, "__float__")? {
                Some(method) => Ok(Some(vm.call0(&method)?)),
                None => Err(vm.raise(ExceptionKind::AttributeError, &format!("{} instance has no attribute '__float__'", vm.class_name(&object.class())))),
            };
        }
    }

    match vm.user_override(value, "__float__")? {
        Some(method) => Ok(Some(vm.call0(&method)?)),
        None => Ok(None),
    }
}

/// Parses a float from a string. Messages quote the text as a C string,
/// so they stop at a NUL byte.
fn string_to_float(vm: &Vm, text: &[u8]) -> PyResult<f64> {
    let (syntax, start) = match parse::float_from_bytes(text) {
        Ok(value) => return Ok(value),
        Err(failure) => failure,
    };

    let quoted = &text[start..];
    let quoted = &quoted[..quoted.iter().position(|byte| *byte == 0).unwrap_or(quoted.len()).min(200)];
    let quoted = String::from_utf8_lossy(quoted);
    let message = match syntax {
        FloatSyntax::NoNumber => format!("could not convert string to float: {quoted}"),
        FloatSyntax::TrailingText => format!("invalid literal for float(): {quoted}"),
    };

    Err(vm.raise(ExceptionKind::ValueError, &message))
}
