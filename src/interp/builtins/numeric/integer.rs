//! `int`, `long`, and `bool`.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::Signed;
use num_traits::ToPrimitive;
use num_traits::Zero;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::classic_instance_int;
use crate::interp::builtins::arguments::classic_instance_long;
use crate::interp::builtins::arguments::is_classic_instance;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::cmp_operand_check;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::numeric::decimal_bytes;
use crate::interp::builtins::numeric::float::float_to_integer;
use crate::interp::builtins::numeric::parse;
use crate::interp::builtins::numeric::quoted;
use crate::interp::builtins::parse as parse_arguments;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::ops::BinaryOp;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Which of the two integer types a method belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Int,
    Long,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Long => "long",
        }
    }

    /// The value of a receiver of this type, subclasses included.
    fn receiver(self, vm: &Vm, value: &Value) -> Option<Integral> {
        match (self, vm.as_integral(value)?) {
            (Self::Int, integral @ Integral::Int(_)) | (Self::Long, integral @ Integral::Long(_)) => Some(integral),
            _ => None,
        }
    }

    /// An operand converted as this type's binary slots convert it:
    /// `int` slots take ints, `long` slots take ints and longs.
    fn operand(self, vm: &Vm, value: &Value) -> Option<Value> {
        match (self, vm.as_integral(value)?) {
            (Self::Int, Integral::Int(number)) => Some(Value::Int(number)),
            (Self::Int, Integral::Long(_)) => None,
            (Self::Long, integral) => Some(Value::Long(Rc::new(integral.to_bigint()))),
        }
    }

    /// A plain value of this type.
    fn plain(self, integral: &Integral) -> Value {
        match (self, integral) {
            (Self::Int, Integral::Int(number)) => Value::Int(*number),
            _ => Value::Long(Rc::new(integral.to_bigint())),
        }
    }
}

macro_rules! integer_methods {
    ($kind:expr) => {
        [
            method("__add__", |vm, args| binary(vm, args, $kind, "__add__", BinaryOp::Add, false)),
            method("__radd__", |vm, args| binary(vm, args, $kind, "__radd__", BinaryOp::Add, true)),
            method("__sub__", |vm, args| binary(vm, args, $kind, "__sub__", BinaryOp::Subtract, false)),
            method("__rsub__", |vm, args| binary(vm, args, $kind, "__rsub__", BinaryOp::Subtract, true)),
            method("__mul__", |vm, args| binary(vm, args, $kind, "__mul__", BinaryOp::Multiply, false)),
            method("__rmul__", |vm, args| binary(vm, args, $kind, "__rmul__", BinaryOp::Multiply, true)),
            method("__div__", |vm, args| binary(vm, args, $kind, "__div__", BinaryOp::Divide, false)),
            method("__rdiv__", |vm, args| binary(vm, args, $kind, "__rdiv__", BinaryOp::Divide, true)),
            method("__truediv__", |vm, args| binary(vm, args, $kind, "__truediv__", BinaryOp::TrueDivide, false)),
            method("__rtruediv__", |vm, args| binary(vm, args, $kind, "__rtruediv__", BinaryOp::TrueDivide, true)),
            method("__floordiv__", |vm, args| binary(vm, args, $kind, "__floordiv__", BinaryOp::FloorDivide, false)),
            method("__rfloordiv__", |vm, args| binary(vm, args, $kind, "__rfloordiv__", BinaryOp::FloorDivide, true)),
            method("__mod__", |vm, args| binary(vm, args, $kind, "__mod__", BinaryOp::Modulo, false)),
            method("__rmod__", |vm, args| binary(vm, args, $kind, "__rmod__", BinaryOp::Modulo, true)),
            method("__lshift__", |vm, args| binary(vm, args, $kind, "__lshift__", BinaryOp::LeftShift, false)),
            method("__rlshift__", |vm, args| binary(vm, args, $kind, "__rlshift__", BinaryOp::LeftShift, true)),
            method("__rshift__", |vm, args| binary(vm, args, $kind, "__rshift__", BinaryOp::RightShift, false)),
            method("__rrshift__", |vm, args| binary(vm, args, $kind, "__rrshift__", BinaryOp::RightShift, true)),
            method("__and__", |vm, args| binary(vm, args, $kind, "__and__", BinaryOp::And, false)),
            method("__rand__", |vm, args| binary(vm, args, $kind, "__rand__", BinaryOp::And, true)),
            method("__or__", |vm, args| binary(vm, args, $kind, "__or__", BinaryOp::Or, false)),
            method("__ror__", |vm, args| binary(vm, args, $kind, "__ror__", BinaryOp::Or, true)),
            method("__xor__", |vm, args| binary(vm, args, $kind, "__xor__", BinaryOp::Xor, false)),
            method("__rxor__", |vm, args| binary(vm, args, $kind, "__rxor__", BinaryOp::Xor, true)),
            method("__divmod__", |vm, args| divmod(vm, args, $kind, "__divmod__", false)),
            method("__rdivmod__", |vm, args| divmod(vm, args, $kind, "__rdivmod__", true)),
            method("__pow__", |vm, args| power(vm, args, $kind, "__pow__", false)),
            method("__rpow__", |vm, args| power(vm, args, $kind, "__rpow__", true)),
            method("__neg__", |vm, args| unary(vm, args, $kind, "__neg__", Unary::Negative)),
            method("__pos__", |vm, args| unary(vm, args, $kind, "__pos__", Unary::Positive)),
            method("__abs__", |vm, args| unary(vm, args, $kind, "__abs__", Unary::Absolute)),
            method("__invert__", |vm, args| unary(vm, args, $kind, "__invert__", Unary::Invert)),
            method("__nonzero__", |vm, args| unary(vm, args, $kind, "__nonzero__", Unary::Truth)),
            method("__int__", |vm, args| unary(vm, args, $kind, "__int__", Unary::ToInt)),
            method("__long__", |vm, args| unary(vm, args, $kind, "__long__", Unary::ToLong)),
            method("__float__", |vm, args| unary(vm, args, $kind, "__float__", Unary::ToFloat)),
            method("__index__", |vm, args| unary(vm, args, $kind, "__index__", Unary::Plain)),
            method("__trunc__", |vm, args| unary(vm, args, $kind, "__trunc__", Unary::Plain)),
            method("__hash__", |vm, args| unary(vm, args, $kind, "__hash__", Unary::Hash)),
            method("__hex__", |vm, args| unary(vm, args, $kind, "__hex__", Unary::Hex)),
            method("__oct__", |vm, args| unary(vm, args, $kind, "__oct__", Unary::Oct)),
            method("__repr__", |vm, args| unary(vm, args, $kind, "__repr__", Unary::Repr)),
            method("__str__", |vm, args| unary(vm, args, $kind, "__str__", Unary::Str)),
            method("__cmp__", |vm, args| compare(vm, args, $kind)),
            method("__coerce__", |vm, args| coerce(vm, args, $kind)),
            method("__getnewargs__", |vm, args| getnewargs(vm, args, $kind)),
            method("bit_length", |vm, args| bit_length(vm, args, $kind)),
            method("conjugate", |vm, args| conjugate(vm, args, $kind)),
        ]
    };
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    crate::interp::builtins::install(vm, &types.int, &integer_methods!(Kind::Int))?;
    crate::interp::builtins::install(vm, &types.int, &[static_method("__new__", int_new)])?;
    install_getsets(vm, &types.int, Kind::Int)?;

    crate::interp::builtins::install(vm, &types.long, &integer_methods!(Kind::Long))?;
    crate::interp::builtins::install(vm, &types.long, &[static_method("__new__", long_new)])?;
    install_getsets(vm, &types.long, Kind::Long)?;

    crate::interp::builtins::install(
        vm,
        &types.bool,
        &[
            static_method("__new__", bool_new),
            method("__repr__", bool_repr),
            method("__str__", bool_repr),
            method("__and__", |vm, args| bool_binary(vm, args, "__and__", BinaryOp::And, false)),
            method("__rand__", |vm, args| bool_binary(vm, args, "__rand__", BinaryOp::And, true)),
            method("__or__", |vm, args| bool_binary(vm, args, "__or__", BinaryOp::Or, false)),
            method("__ror__", |vm, args| bool_binary(vm, args, "__ror__", BinaryOp::Or, true)),
            method("__xor__", |vm, args| bool_binary(vm, args, "__xor__", BinaryOp::Xor, false)),
            method("__rxor__", |vm, args| bool_binary(vm, args, "__rxor__", BinaryOp::Xor, true)),
        ],
    )
}

/// `real`, `imag`, `numerator`, and `denominator`, as read-only
/// properties.
fn install_getsets(vm: &Vm, class: &crate::interp::value::ObjectRef, kind: Kind) -> PyResult<()> {
    let get: fn(&Vm, &GetSet, &Value) -> PyResult<Value> = match kind {
        Kind::Int => |vm, getset, instance| getset_value(vm, getset, instance, Kind::Int),
        Kind::Long => |vm, getset, instance| getset_value(vm, getset, instance, Kind::Long),
    };

    for name in ["real", "imag", "numerator", "denominator"] {
        add_getset(vm, class, GetSet { name, owner: kind.name(), get, set: None })?;
    }

    Ok(())
}

/// `real`, `imag`, `numerator`, and `denominator`.
fn getset_value(vm: &Vm, getset: &GetSet, instance: &Value, kind: Kind) -> PyResult<Value> {
    let Some(value) = kind.receiver(vm, instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(match getset.name {
        "imag" => kind.plain(&Integral::Int(0)),
        "denominator" => kind.plain(&Integral::Int(1)),
        _ => kind.plain(&value),
    })
}

fn bind_integer(vm: &Vm, args: CallArgs, kind: Kind, method: &str) -> PyResult<(Integral, CallArgs)> {
    let (target, rest) = bind(vm, args, method, kind.name())?;
    let Some(value) = kind.receiver(vm, &target) else {
        return Err(wrong_receiver(vm, method, kind.name(), &target));
    };

    Ok((value, rest))
}

/// A binary slot: `NotImplemented` for operands the type does not take.
fn binary(vm: &Vm, args: CallArgs, kind: Kind, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = kind.operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let value = kind.plain(&value);

    if reflected { vm.binary_op(operation, &other, &value) } else { vm.binary_op(operation, &value, &other) }
}

fn divmod(vm: &Vm, args: CallArgs, kind: Kind, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = kind.operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let value = kind.plain(&value);
    let (left, right) = if reflected { (other, value) } else { (value, other) };

    Ok(Value::tuple(vec![vm.binary_op(BinaryOp::FloorDivide, &left, &right)?, vm.binary_op(BinaryOp::Modulo, &left, &right)?]))
}

/// `**` for `int` and `long`, including the three-argument form.
fn power(vm: &Vm, args: CallArgs, kind: Kind, method: &str, reflected: bool) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, method)?;
    let arguments = positional(vm, rest, method, 1, 2)?;
    if let Some(unknown) = arguments.iter().find(|argument| argument.is_unknown()) {
        return Ok(unknown.clone());
    }

    let Some(other) = kind.operand(vm, &arguments[0]) else {
        return Ok(Value::NotImplemented);
    };
    let value = kind.plain(&value);
    let (base, exponent) = if reflected { (other, value) } else { (value, other) };

    let modulus = match arguments.get(1) {
        None => return vm.binary_op(BinaryOp::Power, &base, &exponent),
        Some(modulus) if modulus.is_none() => return vm.binary_op(BinaryOp::Power, &base, &exponent),
        Some(modulus) => match kind.operand(vm, modulus) {
            Some(modulus) => modulus,
            None => return Ok(Value::NotImplemented),
        },
    };

    let (Some(base), Some(exponent), Some(modulus)) = (vm.as_integral(&base), vm.as_integral(&exponent), vm.as_integral(&modulus)) else {
        return Ok(Value::NotImplemented);
    };
    let (base, exponent, modulus) = (base.to_bigint(), exponent.to_bigint(), modulus.to_bigint());
    if exponent.is_negative() {
        return Err(vm.type_error("pow() 2nd argument cannot be negative when 3rd argument specified"));
    }
    if modulus.is_zero() {
        return Err(vm.raise(ExceptionKind::ValueError, "pow() 3rd argument cannot be 0"));
    }

    let result = base.modpow(&exponent, &modulus);

    Ok(match kind {
        Kind::Int => vm.new_int(result),
        Kind::Long => Value::Long(Rc::new(result)),
    })
}

#[derive(Clone, Copy)]
enum Unary {
    Negative,
    Positive,
    Absolute,
    Invert,
    Truth,
    ToInt,
    ToLong,
    ToFloat,
    Plain,
    Hash,
    Hex,
    Oct,
    Repr,
    Str,
}

fn unary(vm: &Vm, args: CallArgs, kind: Kind, method: &str, operation: Unary) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, method)?;
    wrapper_arguments(vm, rest, 0)?;

    let number = value.to_bigint();
    let plain = kind.plain(&value);

    let result = match operation {
        Unary::Negative => vm.negative(&plain)?,
        Unary::Positive | Unary::Plain => plain,
        Unary::Absolute => match kind {
            Kind::Int => vm.new_int(number.abs()),
            Kind::Long => Value::Long(Rc::new(number.abs())),
        },
        Unary::Invert => vm.invert(&plain)?,
        Unary::Truth => Value::Bool(!number.is_zero()),
        Unary::ToInt => vm.new_int(number),
        Unary::ToLong => Value::Long(Rc::new(number)),
        Unary::ToFloat => match numbers::bigint_to_f64(&number) {
            Some(float) => Value::Float(float),
            None => return Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float")),
        },
        Unary::Hash => Value::Int(vm.hash(&plain)?.value()),
        Unary::Hex => Value::str(&radix_text(&number, kind, 16)),
        Unary::Oct => Value::str(&radix_text(&number, kind, 8)),
        Unary::Repr => Value::str(&if kind == Kind::Long { format!("{number}L") } else { number.to_string() }),
        Unary::Str => Value::str(&number.to_string()),
    };

    Ok(result)
}

/// `hex` and `oct`, with an `L` suffix for longs.
fn radix_text(number: &BigInt, kind: Kind, radix: u32) -> String {
    let sign = if number.is_negative() { "-" } else { "" };
    let suffix = if kind == Kind::Long { "L" } else { "" };
    let magnitude = number.magnitude();

    match radix {
        16 => format!("{sign}0x{magnitude:x}{suffix}"),
        _ if magnitude.is_zero() => format!("0{suffix}"),
        _ => format!("{sign}0{magnitude:o}{suffix}"),
    }
}

/// Three-way comparison as `__cmp__`.
fn compare(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__cmp__", kind.name())?;
    let Some(value) = kind.receiver(vm, &target) else {
        return Err(wrong_receiver(vm, "__cmp__", kind.name(), &target));
    };
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }
    let same_comparison = kind.receiver(vm, &other).is_some();
    cmp_operand_check(vm, &target, &other, same_comparison)?;

    let Some(other) = kind.operand(vm, &other).and_then(|other| vm.as_integral(&other)) else {
        return Ok(Value::NotImplemented);
    };

    Ok(Value::Int(match value.to_bigint().cmp(&other.to_bigint()) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }))
}

/// `int` coercion keeps both operands; `long` coercion widens an int.
fn coerce(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__coerce__", kind.name())?;
    if kind.receiver(vm, &target).is_none() {
        return Err(wrong_receiver(vm, "__coerce__", kind.name(), &target));
    }
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(converted) = kind.operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let other = match (kind, vm.as_integral(&other)) {
        (Kind::Long, Some(Integral::Int(_))) => converted,
        _ => other,
    };

    Ok(Value::tuple(vec![target, other]))
}

fn getnewargs(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, "__getnewargs__")?;
    no_arguments(vm, rest, "__getnewargs__")?;

    Ok(Value::tuple(vec![kind.plain(&value)]))
}

fn bit_length(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, "bit_length")?;
    no_arguments(vm, rest, "bit_length")?;

    Ok(vm.new_int_from_i64(value.to_bigint().magnitude().bits() as i64))
}

fn conjugate(vm: &Vm, args: CallArgs, kind: Kind) -> PyResult<Value> {
    let (value, rest) = bind_integer(vm, args, kind, "conjugate")?;
    no_arguments(vm, rest, "conjugate")?;

    Ok(kind.plain(&value))
}

/// `&`, `|`, `^`: a bool for two bools, otherwise the `int` operation.
fn bool_binary(vm: &Vm, args: CallArgs, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, method, "bool")?;
    let Value::Bool(flag) = target else {
        return Err(wrong_receiver(vm, method, "bool", &target));
    };
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    if let Value::Bool(other) = other {
        return Ok(Value::Bool(match operation {
            BinaryOp::And => flag & other,
            BinaryOp::Or => flag | other,
            _ => flag ^ other,
        }));
    }

    let Some(other) = Kind::Int.operand(vm, &other) else {
        return Ok(Value::NotImplemented);
    };
    let value = Value::Int(i64::from(flag));

    if reflected { vm.binary_op(operation, &other, &value) } else { vm.binary_op(operation, &value, &other) }
}

fn bool_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__repr__", "bool")?;
    wrapper_arguments(vm, rest, 0)?;
    let Value::Bool(flag) = target else {
        return Err(wrong_receiver(vm, "__repr__", "bool", &target));
    };

    Ok(Value::str(if flag { "True" } else { "False" }))
}

/// The truth value. An unknown argument gives an unknown result rather
/// than halting, since no branch depends on it yet.
fn bool_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().bool);
    let (_, rest) = new_class(vm, args, &base)?;
    let slots = parse_arguments(vm, rest, "bool", &["x"], 0)?;

    match &slots[0] {
        None => Ok(Value::Bool(false)),
        Some(value) if value.is_unknown() => Ok(value.clone()),
        Some(value) => Ok(Value::Bool(vm.truthy(value, "bool()")?)),
    }
}

/// `int.__new__` for `int` and its subclasses.
fn int_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().int);
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse_arguments(vm, rest, "int", &["x", "base"], 0)?;
    let value = convert(vm, Kind::Int, slots[0].as_ref(), slots[1].as_ref())?;

    if Rc::ptr_eq(&class, &base) || value.is_unknown() {
        return Ok(value);
    }

    let number = match vm.as_integral(&value) {
        Some(Integral::Int(number)) => Some(number),
        Some(Integral::Long(number)) => number.to_i64().filter(|number| numbers::fits_int(vm.config.long_width, *number)),
        None => None,
    };
    let Some(number) = number else {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
    };

    Ok(new_instance(vm, &class, Payload::Int(number)))
}

/// `long.__new__` for `long` and its subclasses.
fn long_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().long);
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse_arguments(vm, rest, "long", &["x", "base"], 0)?;
    let value = convert(vm, Kind::Long, slots[0].as_ref(), slots[1].as_ref())?;

    if Rc::ptr_eq(&class, &base) || value.is_unknown() {
        return Ok(value);
    }

    let Some(number) = vm.as_integral(&value) else {
        return Err(vm.type_error("long() result is not an integer"));
    };

    Ok(new_instance(vm, &class, Payload::Long(Rc::new(number.to_bigint()))))
}

/// The `i` format for the `base` argument.
fn base_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    if let Value::Unknown(unknown) = value {
        return Err(Signal::Halt(Halt::UnknownCondition { context: "int() base".to_owned(), origin: unknown.origin.clone() }));
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(number),
        Some(Integral::Long(number)) => number.to_i64().ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum")),
        None => Err(vm.type_error("an integer is required")),
    }
}

/// `int(x, base)` or `long(x, base)` before any subclass wrapping.
fn convert(vm: &Vm, kind: Kind, value: Option<&Value>, base: Option<&Value>) -> PyResult<Value> {
    let name = kind.name();
    let base = match base {
        Some(base) => Some(base_argument(vm, base)?),
        None => None,
    };

    let Some(value) = value else {
        if base.is_some() {
            return Err(vm.type_error(&format!("{name}() missing string argument")));
        }
        return Ok(kind.plain(&Integral::Int(0)));
    };
    if value.is_unknown() {
        return Ok(value.clone());
    }

    let Some(base) = base else {
        return match kind {
            Kind::Int => number_to_int(vm, value),
            Kind::Long => number_to_long(vm, value),
        };
    };

    if let Some(bytes) = vm.as_str_bytes(value) {
        if bytes.as_bytes().contains(&0) {
            return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid literal for {name}() with base {base}: {}", vm.repr_text(value)?)));
        }
        return string_to_integer(vm, kind, bytes.as_bytes(), base);
    }
    if let Some(text) = vm.as_text(value) {
        return string_to_integer(vm, kind, &decimal_bytes(vm, &text)?, base);
    }

    Err(vm.type_error(&format!("{name}() can't convert non-string with explicit base")))
}

/// Parses an int or a long from a string.
fn string_to_integer(vm: &Vm, kind: Kind, text: &[u8], base: i64) -> PyResult<Value> {
    if (base != 0 && base < 2) || base > 36 {
        let message = match kind {
            Kind::Int => "int() base must be >= 2 and <= 36",
            Kind::Long => "long() arg 2 must be >= 2 and <= 36",
        };
        return Err(vm.raise(ExceptionKind::ValueError, message));
    }
    let radix = base as u32;

    match kind {
        Kind::Int => {
            let Some(number) = parse::int_from_bytes(text, radix) else {
                let start = text.iter().position(|byte| !parse::is_space(*byte)).unwrap_or(text.len());
                return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid literal for int() with base {base}: {}", quoted(&text[start..]))));
            };
            Ok(vm.new_int(number))
        }
        Kind::Long => match parse::long_from_bytes(text, radix) {
            Ok(number) => Ok(Value::Long(Rc::new(number))),
            Err(reported) => Err(vm.raise(ExceptionKind::ValueError, &format!("invalid literal for long() with base {reported}: {}", quoted(text)))),
        },
    }
}

/// Calls a conversion special method of a user object, if it has one. A
/// classic instance converts through its `__int__`, then `__trunc__`
/// (and for `long`, `__long__` first).
fn conversion_hook(vm: &Vm, value: &Value, name: &str) -> PyResult<Option<Value>> {
    if is_classic_instance(vm, value) {
        let result = if name == "__long__" { classic_instance_long(vm, value)? } else { classic_instance_int(vm, value)? };
        return Ok(Some(result));
    }

    match vm.user_override(value, name)? {
        Some(method) => Ok(Some(vm.call0(&method)?)),
        None => Ok(None),
    }
}

/// The conversion `int(value)` performs.
fn number_to_int(vm: &Vm, value: &Value) -> PyResult<Value> {
    if let Value::Int(_) = value {
        return Ok(value.clone());
    }

    if let Some(result) = conversion_hook(vm, value, "__int__")? {
        if result.is_unknown() || vm.as_integral(&result).is_some() {
            return Ok(result);
        }
        return Err(vm.type_error(&format!("__int__ returned non-int (type {})", vm.type_name(&result))));
    }

    if let Some(integral) = vm.as_integral(value) {
        return Ok(vm.new_int(integral.to_bigint()));
    }
    if let Some(float) = vm.as_float(value) {
        return float_to_integer(vm, float).map(|number| vm.new_int(number));
    }
    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to int"));
    }
    if let Some(result) = truncate(vm, value)? {
        return Ok(result);
    }
    if let Some(bytes) = vm.as_str_bytes(value) {
        return decimal_string(vm, Kind::Int, bytes.as_bytes());
    }
    if let Some(text) = vm.as_text(value) {
        return string_to_integer(vm, Kind::Int, &decimal_bytes(vm, &text)?, 10);
    }
    if let Some(bytes) = vm.single_segment_buffer(value, BufferInterface::Character)? {
        return decimal_string(vm, Kind::Int, bytes.as_bytes());
    }

    Err(vm.type_error(&format!("int() argument must be a string or a number, not '{}'", vm.type_name(value))))
}

/// The conversion `long(value)` performs.
fn number_to_long(vm: &Vm, value: &Value) -> PyResult<Value> {
    if let Some(result) = conversion_hook(vm, value, "__long__")? {
        return match vm.as_integral(&result) {
            Some(integral) => Ok(Value::Long(Rc::new(integral.to_bigint()))),
            None if result.is_unknown() => Ok(result),
            None => Err(vm.type_error(&format!("__long__ returned non-long (type {})", vm.type_name(&result)))),
        };
    }

    if let Some(integral) = vm.as_integral(value) {
        return Ok(Value::Long(Rc::new(integral.to_bigint())));
    }
    if let Some(float) = vm.as_float(value) {
        return float_to_integer(vm, float).map(|number| Value::Long(Rc::new(number)));
    }
    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to long"));
    }
    if let Some(result) = truncate(vm, value)? {
        return match vm.as_integral(&result) {
            Some(integral) => Ok(Value::Long(Rc::new(integral.to_bigint()))),
            None => Ok(result),
        };
    }
    if let Some(bytes) = vm.as_str_bytes(value) {
        return decimal_string(vm, Kind::Long, bytes.as_bytes());
    }
    if let Some(text) = vm.as_text(value) {
        return string_to_integer(vm, Kind::Long, &decimal_bytes(vm, &text)?, 10);
    }
    if let Some(bytes) = vm.single_segment_buffer(value, BufferInterface::Character)? {
        return decimal_string(vm, Kind::Long, bytes.as_bytes());
    }

    Err(vm.type_error(&format!("long() argument must be a string or a number, not '{}'", vm.type_name(value))))
}

/// String parsing stops at a NUL byte, and a valid prefix before one is
/// still an error.
fn decimal_string(vm: &Vm, kind: Kind, text: &[u8]) -> PyResult<Value> {
    let Some(null) = text.iter().position(|byte| *byte == 0) else {
        return string_to_integer(vm, kind, text, 10);
    };

    string_to_integer(vm, kind, &text[..null], 10)?;

    Err(vm.raise(ExceptionKind::ValueError, &format!("null byte in argument for {}()", kind.name())))
}

/// `__trunc__` and its conversion of the result to an integer.
fn truncate(vm: &Vm, value: &Value) -> PyResult<Option<Value>> {
    let Some(method) = vm.user_override(value, "__trunc__")? else {
        return Ok(None);
    };

    let result = vm.call0(&method)?;
    if result.is_unknown() || vm.as_integral(&result).is_some() {
        return Ok(Some(result));
    }

    if let Some(method) = vm.user_override(&result, "__int__")? {
        let converted = vm.call0(&method)?;
        if converted.is_unknown() || vm.as_integral(&converted).is_some() {
            return Ok(Some(converted));
        }
    }

    Err(vm.type_error(&format!("__trunc__ returned non-Integral (type {})", vm.type_name(&result))))
}
