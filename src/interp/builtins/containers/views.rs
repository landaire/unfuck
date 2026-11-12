//! `dict.viewkeys()`, `viewvalues()`, and `viewitems()`.

use std::any::Any;
use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::containers::set;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewKind {
    Keys,
    Values,
    Items,
}

impl ViewKind {
    fn type_name(self) -> &'static str {
        match self {
            Self::Keys => "dict_keys",
            Self::Values => "dict_values",
            Self::Items => "dict_items",
        }
    }
}

/// A live view of a dict.
pub struct DictView {
    dict: ObjectRef,
    kind: ViewKind,
}

impl NativeData for DictView {
    fn type_name(&self) -> &'static str {
        self.kind.type_name()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn new_view(vm: &Vm, dict: ObjectRef, kind: ViewKind) -> Value {
    let types = vm.types();
    let class = match kind {
        ViewKind::Keys => &types.dict_keys,
        ViewKind::Values => &types.dict_values,
        ViewKind::Items => &types.dict_items,
    };

    Value::Object(vm.alloc(class, Payload::Native(Box::new(DictView { dict, kind })), None))
}

fn view_of(object: &ObjectRef) -> Option<&DictView> {
    match &object.payload {
        Payload::Native(native) => native.as_any().downcast_ref::<DictView>(),
        _ => None,
    }
}

/// A keys or items view, which supports set operations.
fn set_like_view(value: &Value) -> Option<&DictView> {
    let view = view_of(value.as_object()?)?;

    (view.kind != ViewKind::Values).then_some(view)
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let types = vm.types();
    let common = [method("__len__", view_len_method), method("__iter__", view_iter_method), method("__repr__", view_repr_method)];
    install(vm, &types.dict_values, &common)?;

    for class in [&types.dict_keys, &types.dict_items] {
        install(vm, class, &common)?;
        install(
            vm,
            class,
            &[
                method("__contains__", view_contains_method),
                method("__eq__", |vm, args| view_compare_method(vm, args, "__eq__", CompareOp::Equal)),
                method("__ne__", |vm, args| view_compare_method(vm, args, "__ne__", CompareOp::NotEqual)),
                method("__lt__", |vm, args| view_compare_method(vm, args, "__lt__", CompareOp::Less)),
                method("__le__", |vm, args| view_compare_method(vm, args, "__le__", CompareOp::LessEqual)),
                method("__gt__", |vm, args| view_compare_method(vm, args, "__gt__", CompareOp::Greater)),
                method("__ge__", |vm, args| view_compare_method(vm, args, "__ge__", CompareOp::GreaterEqual)),
                method("__and__", |vm, args| view_operator(vm, args, "__and__", BinaryOp::And, false)),
                method("__or__", |vm, args| view_operator(vm, args, "__or__", BinaryOp::Or, false)),
                method("__sub__", |vm, args| view_operator(vm, args, "__sub__", BinaryOp::Subtract, false)),
                method("__xor__", |vm, args| view_operator(vm, args, "__xor__", BinaryOp::Xor, false)),
                method("__rand__", |vm, args| view_operator(vm, args, "__rand__", BinaryOp::And, true)),
                method("__ror__", |vm, args| view_operator(vm, args, "__ror__", BinaryOp::Or, true)),
                method("__rsub__", |vm, args| view_operator(vm, args, "__rsub__", BinaryOp::Subtract, true)),
                method("__rxor__", |vm, args| view_operator(vm, args, "__rxor__", BinaryOp::Xor, true)),
            ],
        )?;
        crate::interp::builtins::arguments::set_class_attribute(vm, class, "__hash__", Value::None)?;
    }

    Ok(())
}

fn bind_view(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "dict_keys")?;
    if target.as_object().and_then(view_of).is_none() {
        return Err(wrong_receiver(vm, method, "dict_keys", &target));
    }

    Ok((target, rest))
}

pub fn view_len(vm: &Vm, object: &ObjectRef) -> PyResult<Option<usize>> {
    let Some(view) = view_of(object) else {
        return Ok(None);
    };

    Ok(Some(vm.dict_len(&view.dict)?))
}

pub fn view_iter(vm: &Vm, object: &ObjectRef) -> PyResult<Option<Value>> {
    let Some(view) = view_of(object) else {
        return Ok(None);
    };

    let dict = Rc::clone(&view.dict);
    let length = vm.dict_len(&dict)?;
    let iterator = match view.kind {
        ViewKind::Keys => NativeIterator::DictKeys { dict, position: 0, length, remaining: length },
        ViewKind::Values => NativeIterator::DictValues { dict, position: 0, length, remaining: length },
        ViewKind::Items => NativeIterator::DictItems { dict, position: 0, length, remaining: length },
    };

    Ok(Some(vm.new_iterator(iterator)))
}

/// The type name around the repr of the view as a list.
pub fn view_repr(vm: &Vm, object: &ObjectRef) -> PyResult<Option<String>> {
    let Some(view) = view_of(object) else {
        return Ok(None);
    };

    let items = vm.collect(&Value::Object(Rc::clone(object)))?;

    Ok(Some(format!("{}({})", view.kind.type_name(), vm.repr_text(&vm.new_list(items))?)))
}

fn view_len_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    match vm.len(&target)? {
        Some(length) => Ok(vm.new_int_from_i64(length as i64)),
        None => Ok(Value::unknown("len of a dict view")),
    }
}

fn view_iter_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    vm.iter(&target)
}

fn view_repr_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    vm.repr(&target)
}

/// Membership of keys and items views; `None` for values views, which
/// test membership by iteration.
pub fn view_contains(vm: &Vm, object: &ObjectRef, item: &Value) -> PyResult<Option<bool>> {
    let Some(view) = view_of(object) else {
        return Ok(None);
    };

    match view.kind {
        ViewKind::Values => Ok(None),
        ViewKind::Keys => Ok(Some(vm.dict_get(&view.dict, item)?.is_some())),
        ViewKind::Items => {
            let pair = match vm.as_tuple(item) {
                Some(pair) if pair.len() == 2 => pair,
                _ => return Ok(Some(false)),
            };
            let Some(stored) = vm.dict_get(&view.dict, &pair[0])? else {
                return Ok(Some(false));
            };

            Ok(Some(vm.is_same(&stored, &pair[1]) || vm.equals(&stored, &pair[1])?))
        }
    }
}

fn view_contains_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, "__contains__")?;
    let item = wrapper_operand(vm, rest)?;

    vm.contains(&target, &item)
}

fn view_compare_method(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    Ok(rich_compare(vm, &target, &other, operation)?.unwrap_or(Value::NotImplemented))
}

/// `None` when `other` is neither a set nor a set-like view.
fn rich_compare(vm: &Vm, view: &Value, other: &Value, operation: CompareOp) -> PyResult<Option<Value>> {
    if vm.set_snapshot(other).is_none() && set_like_view(other).is_none() {
        return Ok(None);
    }

    let (Some(length), Some(other_length)) = (vm.len(view)?, vm.len(other)?) else {
        return Ok(Some(Value::unknown("length of a dict view operand")));
    };

    let result = match operation {
        CompareOp::Equal => length == other_length && all_contained_in(vm, view, other)?,
        CompareOp::NotEqual => !(length == other_length && all_contained_in(vm, view, other)?),
        CompareOp::Less => length < other_length && all_contained_in(vm, view, other)?,
        CompareOp::LessEqual => length <= other_length && all_contained_in(vm, view, other)?,
        CompareOp::Greater => length > other_length && all_contained_in(vm, other, view)?,
        CompareOp::GreaterEqual => length >= other_length && all_contained_in(vm, other, view)?,
        _ => return Ok(None),
    };

    Ok(Some(Value::Bool(result)))
}

fn all_contained_in(vm: &Vm, items: &Value, container: &Value) -> PyResult<bool> {
    let iterator = vm.iter(items)?;
    while let Some(item) = vm.next(&iterator)? {
        let contained = vm.contains(container, &item)?;
        if !vm.truthy(&contained, "dict view comparison")? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Comparison of a set-like view with a set or another view, from either
/// side, for the comparison operators.
pub fn view_compare(vm: &Vm, left: &Value, right: &Value, operation: CompareOp) -> PyResult<Option<Value>> {
    if set_like_view(left).is_some() {
        if let Some(result) = rich_compare(vm, left, right, operation)? {
            return Ok(Some(result));
        }
    }

    if set_like_view(right).is_none() {
        return Ok(None);
    }

    let reflected = match operation {
        CompareOp::Less => CompareOp::Greater,
        CompareOp::LessEqual => CompareOp::GreaterEqual,
        CompareOp::Greater => CompareOp::Less,
        CompareOp::GreaterEqual => CompareOp::LessEqual,
        other => other,
    };

    rich_compare(vm, right, left, reflected)
}

/// The set operators: a new set built from the left operand, updated in
/// place with the right one. Either operand may be the view.
pub fn view_binary(vm: &Vm, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Option<Value>> {
    if set_like_view(left).is_none() && set_like_view(right).is_none() {
        return Ok(None);
    }
    if !matches!(operation, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor | BinaryOp::Subtract) {
        return Ok(None);
    }

    let result = vm.new_set_from(left)?;
    let Value::Object(object) = &result else {
        return Ok(None);
    };
    set::update_in_place(vm, object, operation, right)?;

    Ok(Some(result))
}

fn view_operator(vm: &Vm, args: CallArgs, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let (left, right) = if reflected { (other, target) } else { (target, other) };

    Ok(view_binary(vm, operation, &left, &right)?.unwrap_or(Value::NotImplemented))
}
