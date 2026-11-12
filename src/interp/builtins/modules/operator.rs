//! `operator`: functions for the intrinsic operators and the `itemgetter`,
//! `attrgetter`, and `methodcaller` types.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::classic_instance_int;
use crate::interp::builtins::arguments::classic_instance_long;
use crate::interp::builtins::arguments::is_classic_instance;
use crate::interp::builtins::core::name_arg;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// C integer type an argument format unit converts to.
#[derive(Clone, Copy)]
pub(super) enum IntFormat {
    /// `i`: C `int`.
    Int,
    /// `n`: `ssize_t`.
    SSize,
}

/// The operand of an `itemgetter` or `attrgetter`: one key, or several
/// whose results form a tuple.
enum Selection {
    Single(Value),
    Multiple(Rc<[Value]>),
}

struct ItemGetter {
    items: Selection,
}

impl_native_data!(ItemGetter, "operator.itemgetter");

struct AttrGetter {
    attrs: Selection,
}

impl_native_data!(AttrGetter, "operator.attrgetter");

struct MethodCaller {
    name: Value,
    arguments: CallArgs,
}

impl_native_data!(MethodCaller, "operator.methodcaller");

/// The module's functions. Each entry passes its method name (for keyword
/// and single-argument errors) and the function name for count errors,
/// which CPython reports separately.
const FUNCTIONS: &[MethodSpec] = &[
    function("isCallable", |vm, args| predicate(vm, args, "isCallable", is_callable)),
    function("isNumberType", |vm, args| predicate(vm, args, "isNumberType", is_number_type)),
    function("isSequenceType", |vm, args| predicate(vm, args, "isSequenceType", is_sequence)),
    function("isMappingType", |vm, args| predicate(vm, args, "isMappingType", is_mapping)),
    function("truth", |vm, args| predicate(vm, args, "truth", |vm, value| vm.truthy(value, "operator.truth"))),
    function("contains", |vm, args| contains(vm, args, "contains", "op_contains")),
    function("__contains__", |vm, args| contains(vm, args, "__contains__", "op_contains")),
    function("sequenceIncludes", |vm, args| contains(vm, args, "sequenceIncludes", "sequenceIncludes")),
    function("indexOf", index_of),
    function("countOf", count_of),
    function("is_", |vm, args| identity(vm, args, "is_", false)),
    function("is_not", |vm, args| identity(vm, args, "is_not", true)),
    function("index", |vm, args| unary(vm, args, "index", number_index)),
    function("__index__", |vm, args| unary(vm, args, "__index__", number_index)),
    function("add", |vm, args| binary(vm, args, "add", "op_add", BinaryOp::Add)),
    function("__add__", |vm, args| binary(vm, args, "__add__", "op_add", BinaryOp::Add)),
    function("sub", |vm, args| binary(vm, args, "sub", "op_sub", BinaryOp::Subtract)),
    function("__sub__", |vm, args| binary(vm, args, "__sub__", "op_sub", BinaryOp::Subtract)),
    function("mul", |vm, args| binary(vm, args, "mul", "op_mul", BinaryOp::Multiply)),
    function("__mul__", |vm, args| binary(vm, args, "__mul__", "op_mul", BinaryOp::Multiply)),
    function("div", |vm, args| binary(vm, args, "div", "op_div", BinaryOp::Divide)),
    function("__div__", |vm, args| binary(vm, args, "__div__", "op_div", BinaryOp::Divide)),
    function("floordiv", |vm, args| binary(vm, args, "floordiv", "op_floordiv", BinaryOp::FloorDivide)),
    function("__floordiv__", |vm, args| binary(vm, args, "__floordiv__", "op_floordiv", BinaryOp::FloorDivide)),
    function("truediv", |vm, args| binary(vm, args, "truediv", "op_truediv", BinaryOp::TrueDivide)),
    function("__truediv__", |vm, args| binary(vm, args, "__truediv__", "op_truediv", BinaryOp::TrueDivide)),
    function("mod", |vm, args| binary(vm, args, "mod", "op_mod", BinaryOp::Modulo)),
    function("__mod__", |vm, args| binary(vm, args, "__mod__", "op_mod", BinaryOp::Modulo)),
    function("neg", |vm, args| unary(vm, args, "neg", Vm::negative)),
    function("__neg__", |vm, args| unary(vm, args, "__neg__", Vm::negative)),
    function("pos", |vm, args| unary(vm, args, "pos", Vm::positive)),
    function("__pos__", |vm, args| unary(vm, args, "__pos__", Vm::positive)),
    function("abs", |vm, args| unary(vm, args, "abs", absolute)),
    function("__abs__", |vm, args| unary(vm, args, "__abs__", absolute)),
    function("inv", |vm, args| unary(vm, args, "inv", Vm::invert)),
    function("__inv__", |vm, args| unary(vm, args, "__inv__", Vm::invert)),
    function("invert", |vm, args| unary(vm, args, "invert", Vm::invert)),
    function("__invert__", |vm, args| unary(vm, args, "__invert__", Vm::invert)),
    function("lshift", |vm, args| binary(vm, args, "lshift", "op_lshift", BinaryOp::LeftShift)),
    function("__lshift__", |vm, args| binary(vm, args, "__lshift__", "op_lshift", BinaryOp::LeftShift)),
    function("rshift", |vm, args| binary(vm, args, "rshift", "op_rshift", BinaryOp::RightShift)),
    function("__rshift__", |vm, args| binary(vm, args, "__rshift__", "op_rshift", BinaryOp::RightShift)),
    function("not_", |vm, args| predicate(vm, args, "not_", |vm, value| Ok(!vm.truthy(value, "operator.not_")?))),
    function("__not__", |vm, args| predicate(vm, args, "__not__", |vm, value| Ok(!vm.truthy(value, "operator.not_")?))),
    function("and_", |vm, args| binary(vm, args, "and_", "op_and_", BinaryOp::And)),
    function("__and__", |vm, args| binary(vm, args, "__and__", "op_and_", BinaryOp::And)),
    function("xor", |vm, args| binary(vm, args, "xor", "op_xor", BinaryOp::Xor)),
    function("__xor__", |vm, args| binary(vm, args, "__xor__", "op_xor", BinaryOp::Xor)),
    function("or_", |vm, args| binary(vm, args, "or_", "op_or_", BinaryOp::Or)),
    function("__or__", |vm, args| binary(vm, args, "__or__", "op_or_", BinaryOp::Or)),
    function("iadd", |vm, args| inplace(vm, args, "iadd", "op_iadd", BinaryOp::Add)),
    function("__iadd__", |vm, args| inplace(vm, args, "__iadd__", "op_iadd", BinaryOp::Add)),
    function("isub", |vm, args| inplace(vm, args, "isub", "op_isub", BinaryOp::Subtract)),
    function("__isub__", |vm, args| inplace(vm, args, "__isub__", "op_isub", BinaryOp::Subtract)),
    function("imul", |vm, args| inplace(vm, args, "imul", "op_imul", BinaryOp::Multiply)),
    function("__imul__", |vm, args| inplace(vm, args, "__imul__", "op_imul", BinaryOp::Multiply)),
    function("idiv", |vm, args| inplace(vm, args, "idiv", "op_idiv", BinaryOp::Divide)),
    function("__idiv__", |vm, args| inplace(vm, args, "__idiv__", "op_idiv", BinaryOp::Divide)),
    function("ifloordiv", |vm, args| inplace(vm, args, "ifloordiv", "op_ifloordiv", BinaryOp::FloorDivide)),
    function("__ifloordiv__", |vm, args| inplace(vm, args, "__ifloordiv__", "op_ifloordiv", BinaryOp::FloorDivide)),
    function("itruediv", |vm, args| inplace(vm, args, "itruediv", "op_itruediv", BinaryOp::TrueDivide)),
    function("__itruediv__", |vm, args| inplace(vm, args, "__itruediv__", "op_itruediv", BinaryOp::TrueDivide)),
    function("imod", |vm, args| inplace(vm, args, "imod", "op_imod", BinaryOp::Modulo)),
    function("__imod__", |vm, args| inplace(vm, args, "__imod__", "op_imod", BinaryOp::Modulo)),
    function("ilshift", |vm, args| inplace(vm, args, "ilshift", "op_ilshift", BinaryOp::LeftShift)),
    function("__ilshift__", |vm, args| inplace(vm, args, "__ilshift__", "op_ilshift", BinaryOp::LeftShift)),
    function("irshift", |vm, args| inplace(vm, args, "irshift", "op_irshift", BinaryOp::RightShift)),
    function("__irshift__", |vm, args| inplace(vm, args, "__irshift__", "op_irshift", BinaryOp::RightShift)),
    function("iand", |vm, args| inplace(vm, args, "iand", "op_iand", BinaryOp::And)),
    function("__iand__", |vm, args| inplace(vm, args, "__iand__", "op_iand", BinaryOp::And)),
    function("ixor", |vm, args| inplace(vm, args, "ixor", "op_ixor", BinaryOp::Xor)),
    function("__ixor__", |vm, args| inplace(vm, args, "__ixor__", "op_ixor", BinaryOp::Xor)),
    function("ior", |vm, args| inplace(vm, args, "ior", "op_ior", BinaryOp::Or)),
    function("__ior__", |vm, args| inplace(vm, args, "__ior__", "op_ior", BinaryOp::Or)),
    function("concat", |vm, args| concat(vm, args, "concat", "op_concat", false)),
    function("__concat__", |vm, args| concat(vm, args, "__concat__", "op_concat", false)),
    function("iconcat", |vm, args| concat(vm, args, "iconcat", "op_iconcat", true)),
    function("__iconcat__", |vm, args| concat(vm, args, "__iconcat__", "op_iconcat", true)),
    function("repeat", |vm, args| repeat(vm, args, "repeat", "op_repeat", false)),
    function("__repeat__", |vm, args| repeat(vm, args, "__repeat__", "op_repeat", false)),
    function("irepeat", |vm, args| repeat(vm, args, "irepeat", "op_irepeat", true)),
    function("__irepeat__", |vm, args| repeat(vm, args, "__irepeat__", "op_irepeat", true)),
    function("getitem", |vm, args| getitem(vm, args, "getitem")),
    function("__getitem__", |vm, args| getitem(vm, args, "__getitem__")),
    function("setitem", |vm, args| setitem(vm, args, "setitem")),
    function("__setitem__", |vm, args| setitem(vm, args, "__setitem__")),
    function("delitem", |vm, args| delitem(vm, args, "delitem")),
    function("__delitem__", |vm, args| delitem(vm, args, "__delitem__")),
    function("pow", |vm, args| binary(vm, args, "pow", "pow", BinaryOp::Power)),
    function("__pow__", |vm, args| binary(vm, args, "__pow__", "pow", BinaryOp::Power)),
    function("ipow", |vm, args| inplace(vm, args, "ipow", "ipow", BinaryOp::Power)),
    function("__ipow__", |vm, args| inplace(vm, args, "__ipow__", "ipow", BinaryOp::Power)),
    function("getslice", |vm, args| getslice(vm, args, "getslice")),
    function("__getslice__", |vm, args| getslice(vm, args, "__getslice__")),
    function("setslice", |vm, args| setslice(vm, args, "setslice")),
    function("__setslice__", |vm, args| setslice(vm, args, "__setslice__")),
    function("delslice", |vm, args| delslice(vm, args, "delslice")),
    function("__delslice__", |vm, args| delslice(vm, args, "__delslice__")),
    function("lt", |vm, args| compare(vm, args, "lt", "op_lt", CompareOp::Less)),
    function("__lt__", |vm, args| compare(vm, args, "__lt__", "op_lt", CompareOp::Less)),
    function("le", |vm, args| compare(vm, args, "le", "op_le", CompareOp::LessEqual)),
    function("__le__", |vm, args| compare(vm, args, "__le__", "op_le", CompareOp::LessEqual)),
    function("eq", |vm, args| compare(vm, args, "eq", "op_eq", CompareOp::Equal)),
    function("__eq__", |vm, args| compare(vm, args, "__eq__", "op_eq", CompareOp::Equal)),
    function("ne", |vm, args| compare(vm, args, "ne", "op_ne", CompareOp::NotEqual)),
    function("__ne__", |vm, args| compare(vm, args, "__ne__", "op_ne", CompareOp::NotEqual)),
    function("gt", |vm, args| compare(vm, args, "gt", "op_gt", CompareOp::Greater)),
    function("__gt__", |vm, args| compare(vm, args, "__gt__", "op_gt", CompareOp::Greater)),
    function("ge", |vm, args| compare(vm, args, "ge", "op_ge", CompareOp::GreaterEqual)),
    function("__ge__", |vm, args| compare(vm, args, "__ge__", "op_ge", CompareOp::GreaterEqual)),
    function("_compare_digest", compare_digest),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)?;

    set_attribute(vm, module, "itemgetter", Value::Object(native_type(vm, "operator.itemgetter", create_itemgetter_type)?))?;
    set_attribute(vm, module, "attrgetter", Value::Object(native_type(vm, "operator.attrgetter", create_attrgetter_type)?))?;
    set_attribute(vm, module, "methodcaller", Value::Object(native_type(vm, "operator.methodcaller", create_methodcaller_type)?))?;

    Ok(())
}

/// Rejects keyword arguments of a function that takes none.
pub(super) fn reject_keywords(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if !args.has_keywords() {
        return Ok(());
    }

    Err(vm.type_error(&format!("{name}() takes no keyword arguments")))
}

/// The argument of a single-argument function.
pub(super) fn single(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    reject_keywords(vm, &args, name)?;

    let count = args.positional.len();
    let mut positional = args.positional.into_iter();
    match (positional.next(), count) {
        (Some(value), 1) => Ok(value),
        _ => Err(vm.type_error(&format!("{name}() takes exactly one argument ({count} given)"))),
    }
}

/// The arguments of a varargs function that reads exactly `count` of them,
/// with count errors naming `operation`.
pub(super) fn unpack(vm: &Vm, args: CallArgs, name: &str, operation: &str, count: usize) -> PyResult<Vec<Value>> {
    reject_keywords(vm, &args, name)?;

    unpack_positional(vm, args.positional, operation, count)
}

/// Positional arguments unpacked by an exact count.
fn unpack_positional(vm: &Vm, positional: Vec<Value>, operation: &str, count: usize) -> PyResult<Vec<Value>> {
    if positional.len() != count {
        return Err(vm.type_error(&format!("{operation} expected {count} arguments, got {}", positional.len())));
    }

    Ok(positional)
}

/// The arguments of a varargs function that parses exactly `count` with a
/// format named `operation`.
pub(super) fn parse_exact(vm: &Vm, args: CallArgs, name: &str, operation: &str, count: usize) -> PyResult<Vec<Value>> {
    reject_keywords(vm, &args, name)?;

    let given = args.positional.len();
    if given != count {
        return Err(vm.type_error(&format!("{operation}() takes exactly {count} arguments ({given} given)")));
    }

    Ok(args.positional)
}

/// Converts an integer argument (the `i` and `n` format units, which
/// accept any object with `__int__`).
pub(super) fn integer_arg(vm: &Vm, value: &Value, format: IntFormat) -> PyResult<i64> {
    if let Value::Unknown(unknown) = value {
        return Err(Signal::Halt(Halt::UnknownCondition { context: "integer argument".to_owned(), origin: unknown.origin.clone() }));
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let converted = match vm.as_integral(value) {
        Some(_) => value.clone(),
        // The `ssize_t` conversion tries `__long__` before `__int__` (Windows x64).
        None if is_classic_instance(vm, value) && matches!(format, IntFormat::SSize) => classic_instance_long(vm, value)?,
        None if is_classic_instance(vm, value) => classic_instance_int(vm, value)?,
        None => {
            let Some(method) = vm.user_override(value, "__int__")? else {
                return Err(vm.type_error("an integer is required"));
            };
            vm.call0(&method)?
        }
    };
    let Some(integral) = vm.as_integral(&converted) else {
        return Err(vm.type_error("nb_int should return int object"));
    };
    let Some(number) = integral.to_bigint().to_i64() else {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
    };

    match format {
        IntFormat::SSize => Ok(number),
        IntFormat::Int if number > i64::from(i32::MAX) => Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum")),
        IntFormat::Int if number < i64::from(i32::MIN) => Err(vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum")),
        IntFormat::Int => Ok(number),
    }
}

/// A single-argument function returning a bool.
fn predicate(vm: &Vm, args: CallArgs, name: &str, test: fn(&Vm, &Value) -> PyResult<bool>) -> PyResult<Value> {
    let value = single(vm, args, name)?;
    if value.is_unknown() {
        return Ok(value);
    }

    Ok(Value::Bool(test(vm, &value)?))
}

fn unary(vm: &Vm, args: CallArgs, name: &str, operation: fn(&Vm, &Value) -> PyResult<Value>) -> PyResult<Value> {
    let value = single(vm, args, name)?;

    operation(vm, &value)
}

fn binary(vm: &Vm, args: CallArgs, name: &str, operation_name: &str, operation: BinaryOp) -> PyResult<Value> {
    let operands = unpack(vm, args, name, operation_name, 2)?;

    vm.binary_op(operation, &operands[0], &operands[1])
}

fn inplace(vm: &Vm, args: CallArgs, name: &str, operation_name: &str, operation: BinaryOp) -> PyResult<Value> {
    let operands = unpack(vm, args, name, operation_name, 2)?;

    vm.inplace_op(operation, &operands[0], &operands[1])
}

fn compare(vm: &Vm, args: CallArgs, name: &str, operation_name: &str, operation: CompareOp) -> PyResult<Value> {
    let operands = unpack(vm, args, name, operation_name, 2)?;

    vm.compare(&operands[0], &operands[1], operation)
}

fn identity(vm: &Vm, args: CallArgs, name: &str, negate: bool) -> PyResult<Value> {
    let operands = unpack(vm, args, name, name, 2)?;

    Ok(Value::Bool(vm.is_same(&operands[0], &operands[1]) != negate))
}

/// Absolute value, shared with the `abs` builtin.
fn absolute(vm: &Vm, value: &Value) -> PyResult<Value> {
    let builtin = vm.builtin_value("abs")?;

    vm.call1(&builtin, value.clone())
}

/// Whether a value is callable, shared with the `callable` builtin.
fn is_callable(vm: &Vm, value: &Value) -> PyResult<bool> {
    let builtin = vm.builtin_value("callable")?;
    let result = vm.call1(&builtin, value.clone())?;

    vm.truthy(&result, "operator.isCallable")
}

/// Conversion through `__index__`.
pub(crate) fn number_index(vm: &Vm, value: &Value) -> PyResult<Value> {
    if value.is_unknown() {
        return Ok(value.clone());
    }

    vm.number_index(value)
}

/// An attribute presence check that treats any exception as absence.
pub(super) fn has_attribute(vm: &Vm, value: &Value, name: &str) -> PyResult<bool> {
    match vm.getattr_opt(value, &vm.name(name)) {
        Ok(found) => Ok(found.is_some()),
        Err(Signal::Raise(_)) => Ok(false),
        Err(signal) => Err(signal),
    }
}

/// Whether a value is a number: its type converts with `__int__` or
/// `__float__`. Classic instances always support both.
pub(crate) fn is_number_type(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.is_number(value) || is_classic_instance(vm, value) {
        return Ok(true);
    }

    Ok(vm.lookup_special(value, "__int__")?.is_some() || vm.lookup_special(value, "__float__")?.is_some())
}

/// Whether the type of `value` is a builtin sequence with slicing.
fn is_builtin_sequence(value: &Value) -> bool {
    match value {
        Value::Str(_) | Value::Unicode(_) | Value::Tuple(_) => true,
        Value::Object(object) => matches!(object.payload, Payload::Str(_) | Payload::Unicode(_) | Payload::Tuple(_) | Payload::List(_)),
        _ => false,
    }
}

/// Whether a value is a sequence.
pub(crate) fn is_sequence(vm: &Vm, value: &Value) -> PyResult<bool> {
    if is_classic_instance(vm, value) {
        return has_attribute(vm, value, "__getitem__");
    }
    if is_builtin_sequence(value) {
        return Ok(true);
    }
    if let Value::Object(object) = value {
        match object.payload {
            Payload::XRange(_) => return Ok(true),
            Payload::Dict(_) | Payload::DictProxy(_) => return Ok(false),
            _ => {}
        }
    }

    Ok(vm.lookup_special(value, "__getitem__")?.is_some())
}

/// Whether a value is a mapping: item access without slicing.
pub(crate) fn is_mapping(vm: &Vm, value: &Value) -> PyResult<bool> {
    if is_classic_instance(vm, value) {
        return has_attribute(vm, value, "__getitem__");
    }
    if is_builtin_sequence(value) {
        return Ok(false);
    }
    if let Value::Object(object) = value {
        match object.payload {
            Payload::XRange(_) => return Ok(false),
            Payload::Dict(_) | Payload::DictProxy(_) => return Ok(true),
            _ => {}
        }
    }

    Ok(vm.lookup_special(value, "__getitem__")?.is_some() && vm.lookup_special(value, "__getslice__")?.is_none())
}

/// Whether the type of `value` supports sequence concatenation and
/// repetition.
fn has_sequence_arithmetic(vm: &Vm, value: &Value) -> bool {
    is_builtin_sequence(value) || is_classic_instance(vm, value)
}

/// Sequence concatenation, in place or not.
fn concat(vm: &Vm, args: CallArgs, name: &str, operation_name: &str, in_place: bool) -> PyResult<Value> {
    let operands = unpack(vm, args, name, operation_name, 2)?;
    let (left, right) = (&operands[0], &operands[1]);
    if left.is_unknown() {
        return Ok(left.clone());
    }

    let supported = has_sequence_arithmetic(vm, left) || (is_sequence(vm, left)? && is_sequence(vm, right)?);
    if !supported {
        return Err(vm.type_error(&format!("'{}' object can't be concatenated", vm.type_name(left))));
    }

    if in_place {
        return vm.inplace_op(BinaryOp::Add, left, right);
    }

    vm.binary_op(BinaryOp::Add, left, right)
}

/// Sequence repetition, in place or not.
fn repeat(vm: &Vm, args: CallArgs, name: &str, operation_name: &str, in_place: bool) -> PyResult<Value> {
    let operands = parse_exact(vm, args, name, operation_name, 2)?;
    let sequence = &operands[0];
    let count = Value::Int(integer_arg(vm, &operands[1], IntFormat::Int)?);
    if sequence.is_unknown() {
        return Ok(sequence.clone());
    }

    let supported = has_sequence_arithmetic(vm, sequence) || is_sequence(vm, sequence)?;
    if !supported {
        return Err(vm.type_error(&format!("'{}' object can't be repeated", vm.type_name(sequence))));
    }

    if in_place {
        return vm.inplace_op(BinaryOp::Multiply, sequence, &count);
    }

    vm.binary_op(BinaryOp::Multiply, sequence, &count)
}

/// Membership test with the container first.
fn contains(vm: &Vm, args: CallArgs, name: &str, operation_name: &str) -> PyResult<Value> {
    let operands = unpack(vm, args, name, operation_name, 2)?;

    vm.contains(&operands[0], &operands[1])
}

/// What an iterating sequence search computes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Search {
    Count,
    Index,
}

/// Searches a sequence by iteration.
fn sequence_search(vm: &Vm, args: CallArgs, name: &'static str, search: Search) -> PyResult<Value> {
    let operands = unpack(vm, args, name, name, 2)?;
    let (sequence, target) = (&operands[0], &operands[1]);

    let iterator = match vm.iter(sequence) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(_)) => return Err(vm.type_error(&format!("argument of type '{}' is not iterable", vm.type_name(sequence)))),
        Err(signal) => return Err(signal),
    };

    let mut position: i64 = 0;
    let mut count: i64 = 0;
    while let Some(item) = vm.next(&iterator)? {
        if vm.is_same(target, &item) || vm.equals(target, &item)? {
            if search == Search::Index {
                return Ok(Value::Int(position));
            }
            count += 1;
        }
        position += 1;
    }

    match search {
        Search::Count => Ok(Value::Int(count)),
        Search::Index => Err(vm.raise(ExceptionKind::ValueError, "sequence.index(x): x not in sequence")),
    }
}

fn index_of(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    sequence_search(vm, args, "indexOf", Search::Index)
}

fn count_of(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    sequence_search(vm, args, "countOf", Search::Count)
}

fn getitem(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let operands = unpack(vm, args, name, "op_getitem", 2)?;

    vm.getitem(&operands[0], &operands[1])
}

fn setitem(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let mut operands = unpack(vm, args, name, "op_setitem", 3)?;
    let Some(value) = operands.pop() else {
        return Err(vm.type_error("op_setitem expected 3 arguments, got 0"));
    };

    vm.setitem(&operands[0], &operands[1], value)?;

    Ok(Value::None)
}

fn delitem(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let operands = unpack(vm, args, name, "op_delitem", 2)?;

    vm.delitem(&operands[0], &operands[1])?;

    Ok(Value::None)
}

/// The `Onn` arguments of the slice functions: the sequence and bounds.
fn slice_arguments(vm: &Vm, args: CallArgs, name: &str, operation: &str, count: usize) -> PyResult<Vec<Value>> {
    let mut operands = parse_exact(vm, args, name, operation, count)?;
    for bound in &mut operands[1..3] {
        *bound = Value::Int(integer_arg(vm, bound, IntFormat::SSize)?);
    }

    Ok(operands)
}

fn getslice(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let operands = slice_arguments(vm, args, name, "getslice", 3)?;

    vm.get_slice(&operands[0], &operands[1], &operands[2])
}

fn setslice(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let mut operands = slice_arguments(vm, args, name, "setslice", 4)?;
    let value = operands.pop();

    vm.set_slice(&operands[0], &operands[1], &operands[2], value)?;

    Ok(Value::None)
}

fn delslice(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let operands = slice_arguments(vm, args, name, "delslice", 3)?;

    vm.set_slice(&operands[0], &operands[1], &operands[2], None)?;

    Ok(Value::None)
}

/// `compare_digest`: equality of two unicode strings or two buffers (of
/// the buffer types the interpreter has, `str`).
fn compare_digest(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let operands = parse_exact(vm, args, "_compare_digest", "compare_digest", 2)?;
    let (left, right) = (&operands[0], &operands[1]);
    if left.is_unknown() {
        return Ok(left.clone());
    }
    if right.is_unknown() {
        return Ok(right.clone());
    }

    if let (Some(left), Some(right)) = (vm.as_text(left), vm.as_text(right)) {
        return Ok(Value::Bool(left.units() == right.units()));
    }

    let (left_bytes, right_bytes) = (vm.as_str_bytes(left), vm.as_str_bytes(right));
    let (left_bytes, right_bytes) = match (left_bytes, right_bytes) {
        (Some(left), Some(right)) => (left, right),
        (None, None) => return Err(vm.type_error(&format!("unsupported operand types(s) or combination of types: '{}' and '{}'", vm.type_name(left), vm.type_name(right)))),
        (None, Some(_)) => return Err(vm.type_error(&format!("'{}' does not have the buffer interface", vm.type_name(left)))),
        (Some(_), None) => return Err(vm.type_error(&format!("'{}' does not have the buffer interface", vm.type_name(right)))),
    };

    Ok(Value::Bool(left_bytes.as_bytes() == right_bytes.as_bytes()))
}

/// Splits the class off the arguments of a native `__new__` and rejects
/// keywords.
fn new_arguments(vm: &Vm, args: CallArgs, type_name: &str) -> PyResult<(ObjectRef, Vec<Value>)> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{type_name}() does not take keyword arguments")));
    }

    let mut positional = args.positional.into_iter();
    let Some(Value::Object(class)) = positional.next() else {
        return Err(vm.type_error(&format!("{type_name}.__new__(X): X is not a type object")));
    };

    Ok((class, positional.collect()))
}

/// The keys of an `itemgetter` or `attrgetter`: the single argument, or
/// all of them when there are several.
fn selection(vm: &Vm, mut keys: Vec<Value>, type_name: &str) -> PyResult<Selection> {
    if keys.len() > 1 {
        return Ok(Selection::Multiple(keys.into()));
    }

    let Some(key) = keys.pop() else {
        return Err(vm.type_error(&format!("{type_name} expected 1 arguments, got 0")));
    };

    Ok(Selection::Single(key))
}

/// The operand of a getter call, after the receiver.
fn call_operand(vm: &Vm, args: CallArgs, type_name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{type_name} does not take keyword arguments")));
    }

    let operands = args.positional.get(1..).map(<[Value]>::to_vec).unwrap_or_default();
    let mut operands = unpack_positional(vm, operands, type_name, 1)?;

    operands.pop().ok_or_else(|| vm.type_error(&format!("{type_name} expected 1 arguments, got 0")))
}

/// Applies `fetch` to each key of `selection`.
fn select(selection: &Selection, mut fetch: impl FnMut(&Value) -> PyResult<Value>) -> PyResult<Value> {
    match selection {
        Selection::Single(key) => fetch(key),
        Selection::Multiple(keys) => {
            let values = keys.iter().map(fetch).collect::<PyResult<Vec<_>>>()?;
            Ok(Value::tuple(values))
        }
    }
}

fn getter_type(vm: &Vm, name: &'static str, new: fn(&Vm, CallArgs) -> PyResult<Value>, call: fn(&Vm, CallArgs) -> PyResult<Value>) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name,
            module: "operator",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[static_method("__new__", new), method("__call__", call)],
        },
    )
}

fn create_itemgetter_type(vm: &Vm) -> PyResult<ObjectRef> {
    getter_type(vm, "itemgetter", itemgetter_new, itemgetter_call)
}

fn create_attrgetter_type(vm: &Vm) -> PyResult<ObjectRef> {
    getter_type(vm, "attrgetter", attrgetter_new, attrgetter_call)
}

fn create_methodcaller_type(vm: &Vm) -> PyResult<ObjectRef> {
    getter_type(vm, "methodcaller", methodcaller_new, methodcaller_call)
}

/// `operator.itemgetter.__new__`.
fn itemgetter_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, keys) = new_arguments(vm, args, "itemgetter")?;
    let items = selection(vm, keys, "itemgetter")?;

    Ok(new_native_object(vm, &class, ItemGetter { items }))
}

/// `operator.itemgetter.__call__`.
fn itemgetter_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let getter = this::<ItemGetter>(vm, &args, "operator.itemgetter", "__call__")?;
    let target = call_operand(vm, args.clone(), "itemgetter")?;

    select(&getter.items, |key| vm.getitem(&target, key))
}

/// `operator.attrgetter.__new__`.
fn attrgetter_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, names) = new_arguments(vm, args, "attrgetter")?;
    let attrs = selection(vm, names, "attrgetter")?;

    Ok(new_native_object(vm, &class, AttrGetter { attrs }))
}

/// `operator.attrgetter.__call__`.
fn attrgetter_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let getter = this::<AttrGetter>(vm, &args, "operator.attrgetter", "__call__")?;
    let target = call_operand(vm, args.clone(), "attrgetter")?;

    select(&getter.attrs, |name| dotted_getattr(vm, &target, name))
}

/// Follows each `.`-separated attribute name.
fn dotted_getattr(vm: &Vm, target: &Value, name: &Value) -> PyResult<Value> {
    let name = match vm.as_text(name) {
        Some(text) => vm.encode_default(&text)?,
        None => name.clone(),
    };
    let Some(bytes) = vm.as_str_bytes(&name) else {
        return Err(vm.type_error("attribute name must be a string"));
    };

    let mut current = target.clone();
    for part in bytes.as_bytes().split(|byte| *byte == b'.') {
        current = vm.getattr(&current, &PyBytes::new(part))?;
    }

    Ok(current)
}

/// `operator.methodcaller.__new__`.
fn methodcaller_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut positional = args.positional.into_iter();
    let Some(Value::Object(class)) = positional.next() else {
        return Err(vm.type_error("methodcaller.__new__(X): X is not a type object"));
    };
    let Some(name) = positional.next() else {
        return Err(vm.type_error("methodcaller needs at least one argument, the method name"));
    };

    let arguments = CallArgs { positional: positional.collect(), keywords: args.keywords, keyword_dict: args.keyword_dict };

    Ok(new_native_object(vm, &class, MethodCaller { name, arguments }))
}

/// `operator.methodcaller.__call__`.
fn methodcaller_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let caller = this::<MethodCaller>(vm, &args, "operator.methodcaller", "__call__")?;
    let target = call_operand(vm, args.clone(), "methodcaller")?;

    let name = name_arg(vm, &caller.name)?;
    let method = vm.getattr(&target, &name)?;

    vm.call(&method, caller.arguments.clone())
}
