use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::containers::count_item;
use crate::interp::builtins::containers::find_item;
use crate::interp::builtins::containers::index_bounds;
use crate::interp::builtins::containers::repeat_items;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::parse;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::CompareOp;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().tuple);

    install(
        vm,
        &class,
        &[
            static_method("__new__", tuple_new),
            method("__getitem__", tuple_getitem),
            method("__getslice__", tuple_getslice),
            method("__len__", tuple_len),
            method("__contains__", tuple_contains),
            method("__add__", tuple_add),
            method("__mul__", tuple_mul),
            method("__rmul__", tuple_mul),
            method("__hash__", tuple_hash),
            method("__eq__", |vm, args| tuple_compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| tuple_compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| tuple_compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| tuple_compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| tuple_compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| tuple_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__iter__", tuple_iter),
            method("__getnewargs__", tuple_getnewargs),
            method("__repr__", tuple_repr),
            method("count", tuple_count),
            method("index", tuple_index),
        ],
    )
}

/// Items of the receiver of a `tuple` method; tuple subclasses included.
fn bind_tuple(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Rc<[Value]>, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "tuple")?;
    let Some(items) = vm.as_tuple(&target) else {
        return Err(wrong_receiver(vm, method, "tuple", &target));
    };

    Ok((items, rest))
}

/// `tuple.__new__` for `tuple` and its subclasses.
fn tuple_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().tuple);
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse(vm, rest, "tuple", &["sequence"], 0)?;
    let exact = Rc::ptr_eq(&class, &base);

    let items: Rc<[Value]> = match &slots[0] {
        None => Rc::from(Vec::new()),
        Some(sequence @ Value::Tuple(_)) if exact => return Ok(sequence.clone()),
        Some(sequence) => vm.collect(sequence)?.into(),
    };

    if exact {
        return Ok(Value::Tuple(items.into()));
    }

    Ok(new_instance(vm, &class, Payload::Tuple(items)))
}

fn tuple_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;

    vm.getitem(&Value::Tuple(items.into()), &index)
}

/// `tuple.__getslice__`: bounds clamp to the tuple without wrapping negatives.
fn tuple_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__getslice__")?;
    let bounds = positional(vm, rest, "__getslice__", 2, 2)?;
    let (start, stop) = clamp_slice(items.len(), ssize_argument(vm, &bounds[0])?, ssize_argument(vm, &bounds[1])?);

    Ok(Value::tuple(items[start..stop].to_vec()))
}

/// The bound clamping shared by the `__getslice__` family.
pub(super) fn clamp_slice(length: usize, start: i64, stop: i64) -> (usize, usize) {
    let length = length as i64;
    let start = start.clamp(0, length);
    let stop = stop.clamp(start, length);

    (start as usize, stop as usize)
}

fn tuple_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(items.len() as i64))
}

fn tuple_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__contains__")?;
    let item = wrapper_operand(vm, rest)?;

    let found = find_item(vm, |position| items.get(position).cloned(), &item, 0, usize::MAX)?;

    Ok(Value::Bool(found.is_some()))
}

fn tuple_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__add__")?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(extra) = vm.as_tuple(&other) else {
        return Err(vm.type_error(&format!("can only concatenate tuple (not \"{}\") to tuple", vm.type_name(&other))));
    };

    let mut joined = items.to_vec();
    joined.extend(extra.iter().cloned());

    Ok(Value::tuple(joined))
}

fn tuple_mul(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__mul__")?;
    let count = wrapper_operand(vm, rest)?;
    if count.is_unknown() {
        return Ok(count);
    }

    let count = usize::try_from(index_value(vm, &count)?).unwrap_or(0);

    Ok(Value::tuple(repeat_items(vm, &items, count)?))
}

fn tuple_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__hash__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Int(vm.hash(&Value::Tuple(items.into()))?.value()))
}

/// Tuple comparison: `NotImplemented` unless both operands are tuples.
fn tuple_compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other_items) = vm.as_tuple(&other) else {
        return Ok(Value::NotImplemented);
    };

    vm.compare_sequences(&items, &other_items, operation)
}

fn tuple_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_iterator(NativeIterator::Sequence { sequence: Value::Tuple(items.into()), index: 0 }))
}

fn tuple_getnewargs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__getnewargs__")?;
    no_arguments(vm, rest, "__getnewargs__")?;

    Ok(Value::tuple(vec![Value::Tuple(items.into())]))
}

fn tuple_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&Value::Tuple(items.into()))?.into_bytes())))
}

fn tuple_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "count")?;
    let item = one_argument(vm, rest, "count")?;

    Ok(vm.new_int_from_i64(count_item(vm, |position| items.get(position).cloned(), &item)? as i64))
}

fn tuple_index(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (items, rest) = bind_tuple(vm, args, "index")?;
    let arguments = positional(vm, rest, "index", 1, 3)?;
    let (start, stop) = index_bounds(vm, &arguments[1..], items.len())?;

    match find_item(vm, |position| items.get(position).cloned(), &arguments[0], start, stop)? {
        Some(position) => Ok(vm.new_int_from_i64(position as i64)),
        None => Err(vm.raise(ExceptionKind::ValueError, "tuple.index(x): x not in tuple")),
    }
}
