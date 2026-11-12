use std::cell::RefCell;
use std::rc::Rc;

use num_traits::Zero;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::containers::count_item;
use crate::interp::builtins::containers::find_item;
use crate::interp::builtins::containers::index_bounds;
use crate::interp::builtins::containers::repeat_items;
use crate::interp::builtins::containers::tuple::clamp_slice;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::parse;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::SliceData;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().list);

    install(
        vm,
        &class,
        &[
            static_method("__new__", list_new),
            method("__init__", list_init),
            method("__getitem__", list_getitem),
            method("__setitem__", list_setitem),
            method("__delitem__", list_delitem),
            method("__getslice__", list_getslice),
            method("__setslice__", list_setslice),
            method("__delslice__", list_delslice),
            method("__len__", list_len),
            method("__contains__", list_contains),
            method("__iter__", list_iter),
            method("__reversed__", list_reversed),
            method("__add__", list_add),
            method("__iadd__", list_iadd),
            method("__mul__", list_mul),
            method("__rmul__", list_mul),
            method("__imul__", list_imul),
            method("__eq__", |vm, args| list_compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| list_compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| list_compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| list_compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| list_compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| list_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__repr__", list_repr),
            method("append", list_append),
            method("extend", list_extend),
            method("insert", list_insert),
            method("pop", list_pop),
            method("remove", list_remove),
            method("index", list_index),
            method("count", list_count),
            method("reverse", list_reverse),
            method("sort", list_sort),
        ],
    )?;

    crate::interp::builtins::arguments::set_class_attribute(vm, &class, "__hash__", Value::None)
}

/// The receiver of a `list` method; list subclasses included.
fn bind_list(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "list")?;
    match &target {
        Value::Object(object) if matches!(object.payload, Payload::List(_)) => Ok((Rc::clone(object), rest)),
        _ => Err(wrong_receiver(vm, method, "list", &target)),
    }
}

fn items_of(list: &ObjectRef) -> &RefCell<Vec<Value>> {
    match &list.payload {
        Payload::List(items) => items,
        _ => unreachable!("bind_list accepts only list payloads"),
    }
}

fn snapshot(list: &ObjectRef) -> Vec<Value> {
    items_of(list).borrow().clone()
}

fn list_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().list);
    let (class, _) = new_class(vm, args, &base)?;

    vm.instantiate_layout(&class)
}

/// Clears, then extends from the optional iterable.
fn list_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__init__")?;
    let slots = parse(vm, rest, "list", &["sequence"], 0)?;

    items_of(&list).borrow_mut().clear();
    if let Some(sequence) = &slots[0] {
        let extra = vm.collect(sequence)?;
        items_of(&list).borrow_mut().extend(extra);
    }

    Ok(Value::None)
}

fn list_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;
    let items = snapshot(&list);

    if let Some(slice) = vm.slice_of(&index) {
        let indices = vm.slice_indices(&slice, items.len())?;
        return Ok(vm.new_list(indices.positions().map(|position| items[position].clone()).collect()));
    }

    let position = vm.normalize_index(&index, items.len(), "list")?;

    Ok(items[position].clone())
}

fn store(vm: &Vm, list: &ObjectRef, index: &Value, value: Option<Value>) -> PyResult<()> {
    if let Some(slice) = vm.slice_of(index) {
        return vm.list_assign_slice(list, &slice, value);
    }

    let items = items_of(list);
    let length = items.borrow().len();
    let position = vm.normalize_index(index, length, "list assignment")?;
    match value {
        Some(value) => items.borrow_mut()[position] = value,
        None => {
            items.borrow_mut().remove(position);
        }
    }

    Ok(())
}

fn list_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__setitem__")?;
    let (index, value) = wrapper_pair(vm, rest)?;
    store(vm, &list, &index, Some(value))?;

    Ok(Value::None)
}

fn list_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__delitem__")?;
    let index = wrapper_operand(vm, rest)?;
    store(vm, &list, &index, None)?;

    Ok(Value::None)
}

/// Clamped `ilow:ihigh` bounds of the `__getslice__` family as a slice.
fn legacy_slice(vm: &Vm, list: &ObjectRef, start: &Value, stop: &Value) -> PyResult<SliceData> {
    let length = items_of(list).borrow().len();
    let (start, stop) = clamp_slice(length, ssize_argument(vm, start)?, ssize_argument(vm, stop)?);

    Ok(SliceData { start: Value::Int(start as i64), stop: Value::Int(stop as i64), step: Value::None })
}

fn list_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__getslice__")?;
    let bounds = positional(vm, rest, "__getslice__", 2, 2)?;
    let items = snapshot(&list);
    let (start, stop) = clamp_slice(items.len(), ssize_argument(vm, &bounds[0])?, ssize_argument(vm, &bounds[1])?);

    Ok(vm.new_list(items[start..stop].to_vec()))
}

fn list_setslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__setslice__")?;
    let arguments = positional(vm, rest, "__setslice__", 3, 3)?;
    let slice = legacy_slice(vm, &list, &arguments[0], &arguments[1])?;
    vm.list_assign_slice(&list, &slice, Some(arguments[2].clone()))?;

    Ok(Value::None)
}

fn list_delslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__delslice__")?;
    let bounds = positional(vm, rest, "__delslice__", 2, 2)?;
    let slice = legacy_slice(vm, &list, &bounds[0], &bounds[1])?;
    vm.list_assign_slice(&list, &slice, None)?;

    Ok(Value::None)
}

fn list_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(items_of(&list).borrow().len() as i64))
}

fn list_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__contains__")?;
    let item = wrapper_operand(vm, rest)?;

    let found = find_item(vm, item_at(&list), &item, 0, usize::MAX)?;

    Ok(Value::Bool(found.is_some()))
}

fn list_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_iterator(NativeIterator::Sequence { sequence: Value::Object(list), index: 0 }))
}

fn list_reversed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__reversed__")?;
    no_arguments(vm, rest, "__reversed__")?;
    let last = items_of(&list).borrow().len().checked_sub(1);

    Ok(vm.new_iterator(NativeIterator::Reversed { sequence: Value::Object(list), index: last }))
}

fn list_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__add__")?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(extra) = vm.as_list(&other) else {
        return Err(vm.type_error(&format!("can only concatenate list (not \"{}\") to list", vm.type_name(&other))));
    };

    let mut joined = snapshot(&list);
    joined.extend(extra);

    Ok(vm.new_list(joined))
}

fn list_iadd(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__iadd__")?;
    let other = wrapper_operand(vm, rest)?;
    let extra = vm.collect(&other)?;
    items_of(&list).borrow_mut().extend(extra);

    Ok(Value::Object(list))
}

fn list_mul(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__mul__")?;
    let count = wrapper_operand(vm, rest)?;
    if count.is_unknown() {
        return Ok(count);
    }

    let count = usize::try_from(index_value(vm, &count)?).unwrap_or(0);

    Ok(vm.new_list(repeat_items(vm, &snapshot(&list), count)?))
}

fn list_imul(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__imul__")?;
    let count = wrapper_operand(vm, rest)?;
    let count = usize::try_from(index_value(vm, &count)?).unwrap_or(0);

    let repeated = repeat_items(vm, &snapshot(&list), count)?;
    *items_of(&list).borrow_mut() = repeated;

    Ok(Value::Object(list))
}

/// `NotImplemented` unless both operands are lists.
fn list_compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other_items) = vm.as_list(&other) else {
        return Ok(Value::NotImplemented);
    };

    vm.compare_sequences(&snapshot(&list), &other_items, operation)
}

fn list_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&Value::Object(list))?.into_bytes())))
}

fn list_append(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "append")?;
    let item = one_argument(vm, rest, "append")?;
    items_of(&list).borrow_mut().push(item);

    Ok(Value::None)
}

fn list_extend(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "extend")?;
    let other = one_argument(vm, rest, "extend")?;
    let extra = vm.collect(&other)?;
    items_of(&list).borrow_mut().extend(extra);

    Ok(Value::None)
}

/// `list.insert`: negative positions count from the end; both ends clamp.
fn list_insert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "insert")?;
    let arguments = positional(vm, rest, "insert", 2, 2)?;
    let position = ssize_argument(vm, &arguments[0])?;

    let items = items_of(&list);
    let length = items.borrow().len() as i64;
    let position = if position < 0 { (position + length).max(0) } else { position.min(length) };
    items.borrow_mut().insert(position as usize, arguments[1].clone());

    Ok(Value::None)
}

fn list_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "pop")?;
    let arguments = positional(vm, rest, "pop", 0, 1)?;
    let requested = match arguments.first() {
        Some(index) => ssize_argument(vm, index)?,
        None => -1,
    };

    let items = items_of(&list);
    let length = items.borrow().len() as i64;
    if length == 0 {
        return Err(vm.raise(ExceptionKind::IndexError, "pop from empty list"));
    }

    let position = if requested < 0 { requested + length } else { requested };
    if position < 0 || position >= length {
        return Err(vm.raise(ExceptionKind::IndexError, "pop index out of range"));
    }

    Ok(items.borrow_mut().remove(position as usize))
}

/// Reads one item of the live list, for scans whose comparisons may
/// mutate it.
fn item_at(list: &ObjectRef) -> impl Fn(usize) -> Option<Value> + '_ {
    move |position| items_of(list).borrow().get(position).cloned()
}

fn list_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "remove")?;
    let item = one_argument(vm, rest, "remove")?;

    let Some(position) = find_item(vm, item_at(&list), &item, 0, usize::MAX)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "list.remove(x): x not in list"));
    };
    // The comparison may have shortened the list; the slice assignment then
    // removes nothing.
    let mut items = items_of(&list).borrow_mut();
    if position < items.len() {
        items.remove(position);
    }
    drop(items);

    Ok(Value::None)
}

fn list_index(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "index")?;
    let arguments = positional(vm, rest, "index", 1, 3)?;
    let length = items_of(&list).borrow().len();
    let (start, stop) = index_bounds(vm, &arguments[1..], length)?;

    match find_item(vm, item_at(&list), &arguments[0], start, stop)? {
        Some(position) => Ok(vm.new_int_from_i64(position as i64)),
        None => Err(vm.raise(ExceptionKind::ValueError, &format!("{} is not in list", vm.repr_text(&arguments[0])?))),
    }
}

fn list_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "count")?;
    let item = one_argument(vm, rest, "count")?;

    Ok(vm.new_int_from_i64(count_item(vm, item_at(&list), &item)? as i64))
}

fn list_reverse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "reverse")?;
    no_arguments(vm, rest, "reverse")?;
    items_of(&list).borrow_mut().reverse();

    Ok(Value::None)
}

/// `list.sort`. The list reads as empty while sorting, and a comparison
/// that adds items to it is reported afterwards.
fn list_sort(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (list, rest) = bind_list(vm, args, "sort")?;
    let slots = parse_with(vm, rest, "sort", &["cmp", "key", "reverse"], 0, |vm, index, value| match index {
        2 => sort_flag(vm, &value).map(Value::Bool),
        _ => Ok(value),
    })?;
    let reverse = matches!(slots[2], Some(Value::Bool(true)));

    let items = items_of(&list);
    let mut sorted = std::mem::take(&mut *items.borrow_mut());
    let result = vm.sort_values(&mut sorted, slots[1].as_ref(), slots[0].as_ref(), reverse);
    let modified = !items.borrow().is_empty();
    *items.borrow_mut() = sorted;

    result?;
    if modified {
        return Err(vm.raise(ExceptionKind::ValueError, "list modified during sort"));
    }

    Ok(Value::None)
}

/// The `i` format used for `reverse`.
fn sort_flag(vm: &Vm, flag: &Value) -> PyResult<bool> {
    if vm.as_float(flag).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    match vm.as_integral(flag) {
        Some(Integral::Int(number)) => Ok(number != 0),
        Some(Integral::Long(number)) => Ok(!number.is_zero()),
        None if flag.is_unknown() => vm.truthy(flag, "sort reverse"),
        None => Err(vm.type_error("an integer is required")),
    }
}
