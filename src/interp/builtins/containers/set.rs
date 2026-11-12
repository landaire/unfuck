//! `set` and `frozenset`. Each operation picks the table algorithm the
//! reference interpreter uses for its operand: another set, an exact dict,
//! or any other iterable.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::cmp_operand_check;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::containers::views::view_binary;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::pyset::PySet;
use crate::interp::pyset::SetSource;
use crate::interp::table::Hashed;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The type a shared method descriptor belongs to; its receiver must be
/// an instance of that type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owner {
    Set,
    FrozenSet,
}

impl Owner {
    fn name(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::FrozenSet => "frozenset",
        }
    }

    fn accepts(self, payload: &Payload) -> bool {
        matches!((self, payload), (Self::Set, Payload::Set(_)) | (Self::FrozenSet, Payload::FrozenSet(_)))
    }
}

macro_rules! shared_methods {
    ($owner:expr) => {
        [
            method("__contains__", |vm, args| set_contains(vm, args, $owner)),
            method("__len__", |vm, args| set_len(vm, args, $owner)),
            method("__iter__", |vm, args| set_iter(vm, args, $owner)),
            method("__repr__", |vm, args| set_repr(vm, args, $owner)),
            method("__cmp__", |vm, args| set_cmp(vm, args, $owner)),
            method("__eq__", |vm, args| set_compare(vm, args, $owner, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| set_compare(vm, args, $owner, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| set_compare(vm, args, $owner, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| set_compare(vm, args, $owner, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| set_compare(vm, args, $owner, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| set_compare(vm, args, $owner, "__ge__", CompareOp::GreaterEqual)),
            method("__or__", |vm, args| set_operator_method(vm, args, $owner, "__or__", BinaryOp::Or, false)),
            method("__and__", |vm, args| set_operator_method(vm, args, $owner, "__and__", BinaryOp::And, false)),
            method("__sub__", |vm, args| set_operator_method(vm, args, $owner, "__sub__", BinaryOp::Subtract, false)),
            method("__xor__", |vm, args| set_operator_method(vm, args, $owner, "__xor__", BinaryOp::Xor, false)),
            method("__ror__", |vm, args| set_operator_method(vm, args, $owner, "__ror__", BinaryOp::Or, true)),
            method("__rand__", |vm, args| set_operator_method(vm, args, $owner, "__rand__", BinaryOp::And, true)),
            method("__rsub__", |vm, args| set_operator_method(vm, args, $owner, "__rsub__", BinaryOp::Subtract, true)),
            method("__rxor__", |vm, args| set_operator_method(vm, args, $owner, "__rxor__", BinaryOp::Xor, true)),
            method("__reduce__", |vm, args| set_reduce(vm, args, $owner)),
            method("copy", |vm, args| set_copy(vm, args, $owner)),
            method("union", |vm, args| set_union(vm, args, $owner)),
            method("intersection", |vm, args| set_intersection(vm, args, $owner)),
            method("difference", |vm, args| set_difference(vm, args, $owner)),
            method("symmetric_difference", |vm, args| set_symmetric_difference(vm, args, $owner)),
            method("issubset", |vm, args| set_issubset(vm, args, $owner)),
            method("issuperset", |vm, args| set_issuperset(vm, args, $owner)),
            method("isdisjoint", |vm, args| set_isdisjoint(vm, args, $owner)),
        ]
    };
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install(vm, &types.set, &shared_methods!(Owner::Set))?;
    install(
        vm,
        &types.set,
        &[
            static_method("__new__", set_new),
            method("__init__", set_init),
            method("__ior__", |vm, args| set_inplace_method(vm, args, "__ior__", BinaryOp::Or)),
            method("__iand__", |vm, args| set_inplace_method(vm, args, "__iand__", BinaryOp::And)),
            method("__isub__", |vm, args| set_inplace_method(vm, args, "__isub__", BinaryOp::Subtract)),
            method("__ixor__", |vm, args| set_inplace_method(vm, args, "__ixor__", BinaryOp::Xor)),
            method("add", set_add),
            method("discard", set_discard),
            method("remove", set_remove),
            method("pop", set_pop),
            method("clear", set_clear),
            method("update", set_update),
            method("intersection_update", set_intersection_update),
            method("difference_update", set_difference_update),
            method("symmetric_difference_update", set_symmetric_difference_update),
        ],
    )?;
    crate::interp::builtins::arguments::set_class_attribute(vm, &types.set, "__hash__", Value::None)?;

    install(vm, &types.frozenset, &shared_methods!(Owner::FrozenSet))?;
    install(vm, &types.frozenset, &[static_method("__new__", frozenset_new), method("__hash__", frozenset_hash)])
}

/// The receiver of a method shared by `set` and `frozenset`, with its
/// table.
fn bind_any(vm: &Vm, args: CallArgs, owner: Owner, method: &str) -> PyResult<(Value, PySet, CallArgs)> {
    let (target, rest) = bind(vm, args, method, owner.name())?;
    let accepted = target.as_object().is_some_and(|object| owner.accepts(&object.payload));
    let (true, Some(table)) = (accepted, vm.set_snapshot(&target)) else {
        return Err(wrong_receiver(vm, method, owner.name(), &target));
    };

    Ok((target, table, rest))
}

/// The receiver of a method only `set` has.
fn bind_mutable(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "set")?;
    match &target {
        Value::Object(object) if matches!(object.payload, Payload::Set(_)) => Ok((Rc::clone(object), rest)),
        _ => Err(wrong_receiver(vm, method, "set", &target)),
    }
}

fn eq(vm: &Vm) -> impl FnMut(&Value, &Value) -> PyResult<bool> + '_ {
    move |stored, probe| vm.keys_equal(stored, probe)
}

fn same_object(left: &Value, right: &Value) -> bool {
    matches!((left, right), (Value::Object(a), Value::Object(b)) if Rc::ptr_eq(a, b))
}

/// A new set of the receiver's type:
/// subclass results are instances of the subclass with an empty dict.
fn result_value(vm: &Vm, receiver: &Value, table: PySet) -> Value {
    let Value::Object(object) = receiver else {
        return vm.new_set(table);
    };
    let class = object.class();
    let types = vm.types();

    match &object.payload {
        Payload::FrozenSet(_) if Rc::ptr_eq(&class, &types.frozenset) => vm.new_frozenset(table),
        Payload::FrozenSet(_) => new_instance(vm, &class, Payload::FrozenSet(table)),
        Payload::Set(_) if !Rc::ptr_eq(&class, &types.set) => new_instance(vm, &class, Payload::Set(RefCell::new(table))),
        _ => vm.new_set(table),
    }
}

fn changed_during_lookup(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::RuntimeError, "set changed size during lookup")
}

/// Runs `operation` on a set's table taken out of the set, then puts the
/// table back even after a failure, so partial updates stay visible. Hash
/// and equality methods run meanwhile see an empty set rather than a
/// borrowed one, and changes they make to it are dropped.
fn mutate<T>(vm: &Vm, set: &ObjectRef, operation: impl FnOnce(&mut PySet) -> PyResult<T>) -> PyResult<T> {
    let cell = vm.mutable_set(set)?;
    let mut table = std::mem::take(&mut *cell.try_borrow_mut().map_err(|_| changed_during_lookup(vm))?);
    let result = operation(&mut table);
    *cell.try_borrow_mut().map_err(|_| changed_during_lookup(vm))? = table;

    result
}

fn table_of(vm: &Vm, set: &ObjectRef) -> PyResult<PySet> {
    let cell = vm.mutable_set(set)?;
    let table = cell.try_borrow().map_err(|_| changed_during_lookup(vm))?.clone();

    Ok(table)
}

/// The set takes over a freshly computed table.
fn replace_table(vm: &Vm, set: &ObjectRef, table: PySet) -> PyResult<()> {
    let cell = vm.mutable_set(set)?;
    *cell.try_borrow_mut().map_err(|_| changed_during_lookup(vm))? = table;

    Ok(())
}

fn dict_keys(table: &crate::interp::pydict::PyDict) -> Vec<Hashed<Value>> {
    table.entries().map(|entry| Hashed { hash: entry.hash, key: entry.key.clone() }).collect()
}

/// Update, without a shortcut for the set itself.
fn update_from(vm: &Vm, table: &mut PySet, source: SetSource) -> PyResult<()> {
    match source {
        SetSource::Set(other) => table.update_from_set(&other, eq(vm)),
        SetSource::Dict(other) => table.update_from_dict(&other, eq(vm)),
        SetSource::Items(items) => table.update_from_iter(vm.hashed_items(items), eq(vm)),
    }
}

/// Difference update, without a shortcut for the set itself.
fn difference_update_from(vm: &Vm, table: &mut PySet, source: SetSource) -> PyResult<()> {
    match source {
        SetSource::Set(other) => table.difference_update_set(&other, eq(vm)),
        SetSource::Dict(other) => table.difference_update_iter(dict_keys(&other).into_iter().map(Ok), eq(vm)),
        SetSource::Items(items) => table.difference_update_iter(vm.hashed_items(items), eq(vm)),
    }
}

/// Symmetric difference update, without a shortcut for the set itself.
fn symmetric_difference_update_from(vm: &Vm, table: &mut PySet, source: SetSource) -> PyResult<()> {
    match source {
        SetSource::Set(other) => table.symmetric_difference_update_set(&other, eq(vm)),
        SetSource::Dict(other) => table.symmetric_difference_update_dict(&other, eq(vm)),
        SetSource::Items(items) => table.symmetric_difference_update_iter(vm.hashed_items(items), eq(vm)),
    }
}

fn intersection(vm: &Vm, receiver: &Value, table: &PySet, other: &Value) -> PyResult<PySet> {
    if same_object(receiver, other) {
        return PySet::from_set(table, eq(vm));
    }

    match vm.set_source(other)? {
        SetSource::Set(other) => table.intersection_set(&other, eq(vm)),
        SetSource::Dict(other) => table.intersection_iter(dict_keys(&other).into_iter().map(Ok), eq(vm)),
        SetSource::Items(items) => table.intersection_iter(vm.hashed_items(items), eq(vm)),
    }
}

fn difference(vm: &Vm, table: &PySet, other: &Value) -> PyResult<PySet> {
    match vm.set_source(other)? {
        SetSource::Set(other) => table.difference_set(&other, eq(vm)),
        SetSource::Dict(other) => table.difference_dict(&other, eq(vm)),
        SetSource::Items(items) => table.difference_iter(vm.hashed_items(items), eq(vm)),
    }
}

fn symmetric_difference(vm: &Vm, table: &PySet, other: &Value) -> PyResult<PySet> {
    match vm.set_source(other)? {
        SetSource::Set(other) => table.symmetric_difference_set(&other, eq(vm)),
        SetSource::Dict(other) => table.symmetric_difference_dict(&other, eq(vm)),
        SetSource::Items(items) => table.symmetric_difference_iter(vm.hashed_items(items), eq(vm)),
    }
}

/// The four set operators `|`, `&`, `-`, and `^` on two sets or
/// frozensets; the result type follows the left operand.
fn operator(vm: &Vm, operation: BinaryOp, left: &Value, left_table: &PySet, right: &Value) -> PyResult<Option<Value>> {
    let table = match operation {
        BinaryOp::Or => {
            let mut result = PySet::from_set(left_table, eq(vm))?;
            if !same_object(left, right) {
                update_from(vm, &mut result, vm.set_source(right)?)?;
            }
            result
        }
        BinaryOp::And => intersection(vm, left, left_table, right)?,
        BinaryOp::Subtract => difference(vm, left_table, right)?,
        BinaryOp::Xor => symmetric_difference(vm, left_table, right)?,
        _ => return Ok(None),
    };

    Ok(Some(result_value(vm, left, table)))
}

/// Binary operators on builtin sets and set-like dict views. `None` when
/// neither applies, so the caller tries reflected user methods.
pub fn set_binary(vm: &Vm, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Option<Value>> {
    if let (Some(left_table), Some(_)) = (vm.set_snapshot(left), vm.set_snapshot(right)) {
        return operator(vm, operation, left, &left_table, right);
    }

    view_binary(vm, operation, left, right)
}

/// The in-place set operators on `set`, which update with the matching
/// method's algorithm. The operand is read before the set's table is taken
/// out for the update.
pub(super) fn update_in_place(vm: &Vm, set: &ObjectRef, operation: BinaryOp, other: &Value) -> PyResult<()> {
    let receiver = Value::Object(Rc::clone(set));
    let alias = same_object(&receiver, other);

    match operation {
        BinaryOp::Or if alias => Ok(()),
        BinaryOp::Subtract | BinaryOp::Xor if alias => mutate(vm, set, |table| {
            table.clear();
            Ok(())
        }),
        BinaryOp::Or => {
            let source = vm.set_source(other)?;
            mutate(vm, set, |table| update_from(vm, table, source))
        }
        BinaryOp::Subtract => {
            let source = vm.set_source(other)?;
            mutate(vm, set, |table| difference_update_from(vm, table, source))
        }
        BinaryOp::Xor => {
            let source = vm.set_source(other)?;
            mutate(vm, set, |table| symmetric_difference_update_from(vm, table, source))
        }
        BinaryOp::And => {
            let result = intersection(vm, &receiver, &table_of(vm, set)?, other)?;
            replace_table(vm, set, result)
        }
        _ => Ok(()),
    }
}

/// An empty set; `__init__` fills it.
fn set_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().set);
    let (class, rest) = new_class(vm, args, &base)?;
    if Rc::ptr_eq(&class, &base) && rest.has_keywords() {
        return Err(vm.type_error("set() does not take keyword arguments"));
    }

    vm.instantiate_layout(&class)
}

/// Clears a used table, then updates from the iterable, which is a no-op
/// when the iterable is the set itself.
fn set_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "__init__")?;
    if rest.has_keywords() {
        return Err(vm.type_error("set() does not take keyword arguments"));
    }

    let name = vm.class_name(&set.class());
    let arguments = unpack(vm, rest, &name, 0, 1)?;
    let receiver = Value::Object(Rc::clone(&set));
    let source = match arguments.first() {
        Some(iterable) if !same_object(&receiver, iterable) => Some(vm.set_source(iterable)?),
        _ => None,
    };

    mutate(vm, &set, |table| {
        if table.fill() != 0 {
            table.clear();
        }
        match source {
            Some(source) => update_from(vm, table, source),
            None => Ok(()),
        }
    })?;

    Ok(Value::None)
}

/// An exact frozenset argument is returned as is.
fn frozenset_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().frozenset);
    let (class, rest) = new_class(vm, args, &base)?;
    let exact = Rc::ptr_eq(&class, &base);
    if exact && rest.has_keywords() {
        return Err(vm.type_error("frozenset() does not take keyword arguments"));
    }

    // Subclass keywords are left for the subclass's `__init__`.
    let name = vm.class_name(&class);
    let arguments = unpack(vm, CallArgs::new(rest.positional), &name, 0, 1)?;
    let Some(iterable) = arguments.first() else {
        return Ok(if exact { vm.new_frozenset(PySet::new()) } else { new_instance(vm, &class, Payload::FrozenSet(PySet::new())) });
    };

    if exact {
        if let Value::Object(object) = iterable {
            if matches!(object.payload, Payload::FrozenSet(_)) && Rc::ptr_eq(&object.class(), &base) {
                return Ok(iterable.clone());
            }
        }
        return Ok(vm.new_frozenset(vm.set_table_from(iterable)?));
    }

    Ok(new_instance(vm, &class, Payload::FrozenSet(vm.set_table_from(iterable)?)))
}

fn set_contains(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, owner, "__contains__")?;
    let item = wrapper_operand(vm, rest)?;
    if item.is_unknown() {
        return Ok(item);
    }

    Ok(Value::Bool(vm.set_contains(&table, &item)?))
}

fn set_len(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, owner, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(table.len() as i64))
}

fn set_iter(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;
    let Value::Object(set) = target else {
        return Err(wrong_receiver(vm, "__iter__", owner.name(), &target));
    };

    let length = table.len();
    Ok(vm.new_iterator(NativeIterator::Set { set, position: 0, length, remaining: length }))
}

fn set_repr(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, _, rest) = bind_any(vm, args, owner, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&target)?.into_bytes())))
}

/// Refusal of ordering behind the `__cmp__` wrapper's operand check.
fn set_cmp(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, _, rest) = bind_any(vm, args, owner, "__cmp__")?;
    let other = wrapper_operand(vm, rest)?;
    cmp_operand_check(vm, &target, &other, vm.set_snapshot(&other).is_some())?;

    Err(vm.type_error("cannot compare sets using cmp()"))
}

/// `(type(s), (list(s),), getattr(s, '__dict__', None))`.
fn set_reduce(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "__reduce__")?;
    no_arguments(vm, rest, "__reduce__")?;

    let keys = vm.new_list(table.iter().cloned().collect());
    let state = match vm.getattr_str(&target, "__dict__") {
        Ok(dict) => dict,
        Err(Signal::Raise(_)) => Value::None,
        Err(halt) => return Err(halt),
    };

    Ok(Value::tuple(vec![Value::Object(vm.class_of(&target)), Value::tuple(vec![keys]), state]))
}

fn frozenset_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, Owner::FrozenSet, "__hash__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Int(vm.frozenset_hash(&table).value()))
}

/// Subset tests; `NotImplemented` for non-sets.
fn set_compare(vm: &Vm, args: CallArgs, owner: Owner, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, owner, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = vm.set_snapshot(&other) else {
        return Ok(Value::NotImplemented);
    };

    let result = match operation {
        CompareOp::Equal => table.len() == other.len() && table.is_subset(&other, eq(vm))?,
        CompareOp::NotEqual => !(table.len() == other.len() && table.is_subset(&other, eq(vm))?),
        CompareOp::LessEqual => table.is_subset(&other, eq(vm))?,
        CompareOp::GreaterEqual => other.is_subset(&table, eq(vm))?,
        CompareOp::Less => table.len() < other.len() && table.is_subset(&other, eq(vm))?,
        CompareOp::Greater => table.len() > other.len() && other.is_subset(&table, eq(vm))?,
        _ => return Ok(Value::NotImplemented),
    };

    Ok(Value::Bool(result))
}

fn set_operator_method(vm: &Vm, args: CallArgs, owner: Owner, method: &str, operation: BinaryOp, reflected: bool) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other_table) = vm.set_snapshot(&other) else {
        return Ok(Value::NotImplemented);
    };

    let result = if reflected { operator(vm, operation, &other, &other_table, &target)? } else { operator(vm, operation, &target, &table, &other)? };

    Ok(result.unwrap_or(Value::NotImplemented))
}

fn set_inplace_method(vm: &Vm, args: CallArgs, method: &str, operation: BinaryOp) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }
    if vm.set_snapshot(&other).is_none() {
        return Ok(Value::NotImplemented);
    }

    update_in_place(vm, &set, operation, &other)?;

    Ok(Value::Object(set))
}

/// `set.copy`, and `frozenset.copy`, which returns an exact frozenset
/// itself.
fn set_copy(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "copy")?;
    no_arguments(vm, rest, "copy")?;

    let exact_frozenset = target.as_object().is_some_and(|object| Rc::ptr_eq(&object.class(), &vm.types().frozenset));
    if exact_frozenset {
        return Ok(target);
    }

    Ok(result_value(vm, &target, PySet::from_set(&table, eq(vm))?))
}

/// A copy updated with each operand except the receiver.
fn set_union(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "union")?;
    let others = unpack(vm, rest, "union", 0, usize::MAX)?;

    let mut result = PySet::from_set(&table, eq(vm))?;
    for other in &others {
        // The result of combining with an unknown iterable is unknown; no
        // control flow depends on it yet.
        if other.is_unknown() {
            return Ok(other.clone());
        }
        if !same_object(&target, other) {
            update_from(vm, &mut result, vm.set_source(other)?)?;
        }
    }

    Ok(result_value(vm, &target, result))
}

/// Intersection with any number of operands.
fn intersection_multi(vm: &Vm, target: &Value, table: PySet, others: &[Value]) -> PyResult<Option<PySet>> {
    let Some((first, rest)) = others.split_first() else {
        return PySet::from_set(&table, eq(vm)).map(Some);
    };
    if first.is_unknown() {
        return Ok(None);
    }

    let mut result = intersection(vm, target, &table, first)?;
    for other in rest {
        if other.is_unknown() {
            return Ok(None);
        }
        result = intersection(vm, &Value::None, &result, other)?;
    }

    Ok(Some(result))
}

fn set_intersection(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "intersection")?;
    let others = unpack(vm, rest, "intersection", 0, usize::MAX)?;

    let Some(result) = intersection_multi(vm, &target, table, &others)? else {
        return Ok(Value::unknown("set.intersection with an unknown operand"));
    };

    Ok(result_value(vm, &target, result))
}

/// Difference with any number of operands.
fn set_difference(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "difference")?;
    let others = unpack(vm, rest, "difference", 0, usize::MAX)?;
    let Some((first, rest)) = others.split_first() else {
        return Ok(result_value(vm, &target, PySet::from_set(&table, eq(vm))?));
    };
    if first.is_unknown() {
        return Ok(first.clone());
    }

    let mut result = difference(vm, &table, first)?;
    for other in rest {
        if other.is_unknown() {
            return Ok(other.clone());
        }
        difference_update_from(vm, &mut result, vm.set_source(other)?)?;
    }

    Ok(result_value(vm, &target, result))
}

fn set_symmetric_difference(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "symmetric_difference")?;
    let other = one_argument(vm, rest, "symmetric_difference")?;
    if other.is_unknown() {
        return Ok(other);
    }

    let result = symmetric_difference(vm, &table, &other)?;

    Ok(result_value(vm, &target, result))
}

/// A set operand of `issubset` and `issuperset`; anything else becomes a
/// temporary set first.
fn as_set_table(vm: &Vm, other: &Value) -> PyResult<PySet> {
    match vm.set_snapshot(other) {
        Some(other) => Ok(other),
        None => vm.set_table_from(other),
    }
}

fn set_issubset(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, owner, "issubset")?;
    let other = one_argument(vm, rest, "issubset")?;
    if other.is_unknown() {
        return Ok(other);
    }

    Ok(Value::Bool(table.is_subset(&as_set_table(vm, &other)?, eq(vm))?))
}

/// `other.issubset(self)`.
fn set_issuperset(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (_, table, rest) = bind_any(vm, args, owner, "issuperset")?;
    let other = one_argument(vm, rest, "issuperset")?;
    if other.is_unknown() {
        return Ok(other);
    }

    Ok(Value::Bool(as_set_table(vm, &other)?.is_subset(&table, eq(vm))?))
}

/// Only exact sets and frozensets take the table path.
fn set_isdisjoint(vm: &Vm, args: CallArgs, owner: Owner) -> PyResult<Value> {
    let (target, table, rest) = bind_any(vm, args, owner, "isdisjoint")?;
    let other = one_argument(vm, rest, "isdisjoint")?;
    if other.is_unknown() {
        return Ok(other);
    }

    if same_object(&target, &other) {
        return Ok(Value::Bool(table.is_empty()));
    }

    if let Value::Object(object) = &other {
        let class = object.class();
        let types = vm.types();
        if Rc::ptr_eq(&class, &types.set) || Rc::ptr_eq(&class, &types.frozenset) {
            if let Some(other_table) = vm.set_snapshot(&other) {
                return Ok(Value::Bool(table.is_disjoint_set(&other_table, eq(vm))?));
            }
        }
    }

    let items = vm.collect(&other)?;

    Ok(Value::Bool(table.is_disjoint_iter(vm.hashed_items(items), eq(vm))?))
}

fn set_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "add")?;
    let item = one_argument(vm, rest, "add")?;
    vm.set_add(&Value::Object(set), item)?;

    Ok(Value::None)
}

/// Removes a key, retried with a frozenset when the key is an unhashable
/// set (`discard` and `remove`). Returns whether a key was removed.
fn discard_key(vm: &Vm, set: &ObjectRef, item: &Value) -> PyResult<bool> {
    let hash = match vm.hash(item) {
        Ok(hash) => hash,
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => match vm.set_snapshot(item) {
            Some(frozen) => vm.frozenset_hash(&frozen),
            None => return Err(Signal::Raise(error)),
        },
        Err(signal) => return Err(signal),
    };

    let removed = mutate(vm, set, |table| table.discard(hash, |stored| vm.keys_equal(stored, item)))?;

    Ok(removed.is_some())
}

fn set_discard(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "discard")?;
    let item = one_argument(vm, rest, "discard")?;
    discard_key(vm, &set, &item)?;

    Ok(Value::None)
}

fn set_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "remove")?;
    let item = one_argument(vm, rest, "remove")?;
    if !discard_key(vm, &set, &item)? {
        return Err(vm.key_error(item));
    }

    Ok(Value::None)
}

fn set_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "pop")?;
    no_arguments(vm, rest, "pop")?;

    let cell = vm.mutable_set(&set)?;
    let popped = cell.try_borrow_mut().map_err(|_| changed_during_lookup(vm))?.pop();
    match popped {
        Some(item) => Ok(item),
        None => Err(vm.raise(ExceptionKind::KeyError, "pop from an empty set")),
    }
}

fn set_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "clear")?;
    no_arguments(vm, rest, "clear")?;

    let cell = vm.mutable_set(&set)?;
    cell.try_borrow_mut().map_err(|_| changed_during_lookup(vm))?.clear();

    Ok(Value::None)
}

fn set_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "update")?;
    let others = unpack(vm, rest, "update", 0, usize::MAX)?;

    for other in &others {
        update_in_place(vm, &set, BinaryOp::Or, other)?;
    }

    Ok(Value::None)
}

/// The receiver takes the table of the combined intersection.
fn set_intersection_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "intersection_update")?;
    let others = unpack(vm, rest, "intersection_update", 0, usize::MAX)?;

    let receiver = Value::Object(Rc::clone(&set));
    // The receiver cannot hold a partly unknown table.
    let Some(result) = intersection_multi(vm, &receiver, table_of(vm, &set)?, &others)? else {
        return Err(Signal::Halt(crate::interp::error::Halt::UnknownIteration { origin: "set.intersection_update with an unknown operand".to_owned() }));
    };
    replace_table(vm, &set, result)?;

    Ok(Value::None)
}

fn set_difference_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "difference_update")?;
    let others = unpack(vm, rest, "difference_update", 0, usize::MAX)?;

    for other in &others {
        update_in_place(vm, &set, BinaryOp::Subtract, other)?;
    }

    Ok(Value::None)
}

fn set_symmetric_difference_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (set, rest) = bind_mutable(vm, args, "symmetric_difference_update")?;
    let other = one_argument(vm, rest, "symmetric_difference_update")?;
    update_in_place(vm, &set, BinaryOp::Xor, &other)?;

    Ok(Value::None)
}
