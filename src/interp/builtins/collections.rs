//! `collections.deque` and `collections.defaultdict`.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::iterator_result;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::NativeIterator;
use crate::interp::ops::CompareOp;
use crate::interp::value::Object;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const DEQUE: &str = "collections.deque";
const DEFAULTDICT: &str = "collections.defaultdict";

/// A `collections.deque`. `state` counts mutations so iterators can detect
/// them.
struct Deque {
    items: RefCell<VecDeque<Value>>,
    maxlen: Cell<Option<usize>>,
    state: Cell<u64>,
}

impl_native_data!(Deque, "collections.deque");

impl Deque {
    fn mutated(&self) {
        self.state.set(self.state.get().wrapping_add(1));
    }

    fn snapshot(&self) -> Vec<Value> {
        self.items.borrow().iter().cloned().collect()
    }

    fn len(&self) -> usize {
        self.items.borrow().len()
    }

    /// Appends, dropping from the left when bounded.
    fn push_back(&self, item: Value) {
        let mut items = self.items.borrow_mut();
        items.push_back(item);
        if let Some(maxlen) = self.maxlen.get() {
            while items.len() > maxlen {
                items.pop_front();
            }
        }
        drop(items);
        self.mutated();
    }

    fn push_front(&self, item: Value) {
        let mut items = self.items.borrow_mut();
        items.push_front(item);
        if let Some(maxlen) = self.maxlen.get() {
            while items.len() > maxlen {
                items.pop_back();
            }
        }
        drop(items);
        self.mutated();
    }

    /// `_deque_rotate`: positive `count` moves items from the right end to
    /// the left.
    fn rotate(&self, count: i64) {
        let mut items = self.items.borrow_mut();
        let length = items.len() as i64;
        if length <= 1 {
            return;
        }

        let shift = count.rem_euclid(length) as usize;
        items.rotate_right(shift);
        drop(items);
        self.mutated();
    }
}

/// Iterator over a deque, front to back or back to front.
struct DequeIterator {
    deque: Value,
    index: Cell<usize>,
    state: u64,
    remaining: Cell<usize>,
    reverse: bool,
}

impl_native_data!(DequeIterator, "deque_iterator");

/// `default_factory` of each defaultdict, keyed by the dict. The dict's own
/// storage is a builtin dict table, which has no room for it.
#[derive(Default)]
struct DefaultFactories {
    factories: RefCell<HashMap<ObjectId, (Weak<Object>, Value)>>,
    collected_at: Cell<usize>,
}

/// Containers whose `repr` is in progress.
#[derive(Default)]
struct ReprGuard {
    active: RefCell<HashSet<ObjectId>>,
}

/// Creates the `deque` and `defaultdict` types at bootstrap.
pub fn install_types(vm: &Vm) -> PyResult<()> {
    deque_type(vm)?;
    defaultdict_type(vm)?;

    Ok(())
}

pub fn deque_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DEQUE, create_deque_type)
}

pub fn defaultdict_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DEFAULTDICT, create_defaultdict_type)
}

/// The value for a missing key of a defaultdict, or `None` when `dict` is
/// not a defaultdict.
pub fn defaultdict_missing(vm: &Vm, dict: &ObjectRef, key: &Value) -> PyResult<Option<Value>> {
    let class = defaultdict_type(vm)?;
    if !vm.is_subclass(&dict.class(), &class)? {
        return Ok(None);
    }

    let factory = default_factory(vm, dict);
    if factory.is_none() {
        return Err(vm.key_error(key.clone()));
    }

    let value = vm.call0(&factory)?;
    vm.setitem(&Value::Object(Rc::clone(dict)), key, value.clone())?;

    Ok(Some(value))
}

/// `deque[index]`; `None` when `object` is not a deque.
pub fn deque_getitem(vm: &Vm, object: &ObjectRef, index: &Value) -> PyResult<Option<Value>> {
    let target = Value::Object(Rc::clone(object));
    let Some(deque) = native_data::<Deque>(&target) else {
        return Ok(None);
    };

    let position = deque_index(vm, deque, index)?;
    let item = deque.items.borrow().get(position).cloned();

    item.map(Some).ok_or_else(|| vm.raise(ExceptionKind::IndexError, "deque index out of range"))
}

/// Stores or, for `None`, deletes an item. `false` when `object` is not a
/// deque.
pub fn deque_setitem(vm: &Vm, object: &ObjectRef, index: &Value, value: Option<Value>) -> PyResult<bool> {
    let target = Value::Object(Rc::clone(object));
    let Some(deque) = native_data::<Deque>(&target) else {
        return Ok(false);
    };

    let position = deque_index(vm, deque, index)?;
    match value {
        Some(value) => {
            if let Some(slot) = deque.items.borrow_mut().get_mut(position) {
                *slot = value;
            }
        }
        None => {
            deque.items.borrow_mut().remove(position);
            deque.mutated();
        }
    }

    Ok(true)
}

pub fn deque_len(_vm: &Vm, object: &ObjectRef) -> PyResult<Option<usize>> {
    let target = Value::Object(Rc::clone(object));

    Ok(native_data::<Deque>(&target).map(Deque::len))
}

pub fn deque_iter(vm: &Vm, object: &ObjectRef) -> PyResult<Option<Value>> {
    let target = Value::Object(Rc::clone(object));
    let Some(deque) = native_data::<Deque>(&target) else {
        return Ok(None);
    };

    let iterator = new_deque_iterator(vm, &target, deque, false)?;

    Ok(Some(iterator))
}

/// Normalizes a deque index, raising like `deque[index]` for bad ones.
fn deque_index(vm: &Vm, deque: &Deque, index: &Value) -> PyResult<usize> {
    if index.is_unknown() {
        return Err(Signal::Halt(crate::interp::error::Halt::UnknownCondition { context: "deque index".to_owned(), origin: format!("{index:?}") }));
    }
    let Some(position) = vm.as_index(index) else {
        return Err(vm.type_error(&format!("sequence index must be integer, not '{}'", vm.type_name(index))));
    };

    let length = deque.len() as i64;
    let adjusted = if position < 0 { position + length } else { position };
    if adjusted < 0 || adjusted >= length {
        return Err(vm.raise(ExceptionKind::IndexError, "deque index out of range"));
    }

    Ok(adjusted as usize)
}

fn new_deque_iterator(vm: &Vm, target: &Value, deque: &Deque, reverse: bool) -> PyResult<Value> {
    let class = if reverse { native_type(vm, "deque_reverse_iterator", create_reverse_iterator_type)? } else { native_type(vm, "deque_iterator", create_iterator_type)? };
    let iterator = DequeIterator { deque: target.clone(), index: Cell::new(0), state: deque.state.get(), remaining: Cell::new(deque.len()), reverse };

    Ok(new_native_object(vm, &class, iterator))
}

fn create_deque_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "deque",
            module: "collections",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", deque_new),
                method("__init__", deque_init),
                method("append", deque_append),
                method("appendleft", deque_appendleft),
                method("pop", deque_pop),
                method("popleft", deque_popleft),
                method("extend", deque_extend),
                method("extendleft", deque_extendleft),
                method("rotate", deque_rotate),
                method("remove", deque_remove),
                method("clear", deque_clear),
                method("count", deque_count),
                method("reverse", deque_reverse),
                method("__copy__", deque_copy),
                method("__reduce__", deque_reduce),
                method("__len__", deque_len_method),
                method("__iter__", deque_iter_method),
                method("__reversed__", deque_reversed),
                method("__getitem__", deque_getitem_method),
                method("__setitem__", deque_setitem_method),
                method("__delitem__", deque_delitem_method),
                method("__iadd__", deque_iadd),
                method("__repr__", deque_repr),
                method("__eq__", deque_eq),
                method("__ne__", deque_ne),
                method("__lt__", deque_lt),
                method("__le__", deque_le),
                method("__gt__", deque_gt),
                method("__ge__", deque_ge),
            ],
        },
    )?;

    if let Some(data) = class.as_class() {
        vm.dict_set_str(&data.dict, "__hash__", Value::None)?;
    }
    add_getset(vm, &class, GetSet { name: "maxlen", owner: DEQUE, get: deque_maxlen, set: None })?;

    Ok(class)
}

fn create_iterator_type(vm: &Vm) -> PyResult<ObjectRef> {
    create_iterator_class(vm, "deque_iterator")
}

fn create_reverse_iterator_type(vm: &Vm) -> PyResult<ObjectRef> {
    create_iterator_class(vm, "deque_reverse_iterator")
}

fn create_iterator_class(vm: &Vm, name: &'static str) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name,
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("__iter__", iterator_self), method("next", iterator_next), method("__length_hint__", iterator_length_hint)],
        },
    )
}

fn the_deque<'a>(vm: &Vm, args: &'a CallArgs, name: &str) -> PyResult<&'a Deque> {
    this::<Deque>(vm, args, DEQUE, name)
}

fn deque_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(Value::Object(class)) = args.positional.first() else {
        return Err(vm.type_error("deque.__new__(X): X is not a type object"));
    };

    let deque = Deque { items: RefCell::new(VecDeque::new()), maxlen: Cell::new(None), state: Cell::new(0) };

    Ok(new_native_object(vm, class, deque))
}

fn deque_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    the_deque(vm, &args, "__init__")?;
    let (target, rest) = receiver(vm, args, "__init__")?;
    let slots = parse(vm, rest, "deque", &["iterable", "maxlen"], 0)?;

    let maxlen = match &slots[1] {
        None | Some(Value::None) => None,
        Some(value) => {
            if value.is_unknown() {
                return Err(vm.halt_unsupported("deque with an unknown maxlen"));
            }
            // Converts through `__int__`, truncating floats.
            let maxlen = match vm.as_float(value) {
                Some(number) => number.trunc() as i64,
                None => match vm.as_index(value) {
                    Some(maxlen) => maxlen,
                    None => return Err(vm.type_error("an integer is required")),
                },
            };
            if maxlen < 0 {
                return Err(vm.raise(ExceptionKind::ValueError, "maxlen must be non-negative"));
            }
            Some(maxlen as usize)
        }
    };

    let Some(deque) = native_data::<Deque>(&target) else {
        return Err(vm.type_error("deque.__init__ requires a deque"));
    };
    deque.maxlen.set(maxlen);
    if deque.len() > 0 {
        deque.items.borrow_mut().clear();
        deque.mutated();
    }

    if let Some(iterable) = &slots[0] {
        extend(vm, &target, deque, iterable, false)?;
    }

    Ok(Value::None)
}

fn deque_maxlen(vm: &Vm, _getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(deque) = native_data::<Deque>(instance) else {
        return Err(vm.type_error(&format!("descriptor 'maxlen' for 'collections.deque' objects doesn't apply to '{}' object", vm.type_name(instance))));
    };

    Ok(match deque.maxlen.get() {
        Some(maxlen) => vm.new_int_from_i64(maxlen as i64),
        None => Value::None,
    })
}

fn deque_append(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "append")?;
    let item = method_one_argument(vm, &args, "append")?;
    deque.push_back(item);

    Ok(Value::None)
}

fn deque_appendleft(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "appendleft")?;
    let item = method_one_argument(vm, &args, "appendleft")?;
    deque.push_front(item);

    Ok(Value::None)
}

fn deque_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "pop")?;
    method_no_arguments(vm, &args, "pop")?;

    let item = deque.items.borrow_mut().pop_back();
    let Some(item) = item else {
        return Err(vm.raise(ExceptionKind::IndexError, "pop from an empty deque"));
    };
    deque.mutated();

    Ok(item)
}

fn deque_popleft(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "popleft")?;
    method_no_arguments(vm, &args, "popleft")?;

    let item = deque.items.borrow_mut().pop_front();
    let Some(item) = item else {
        return Err(vm.raise(ExceptionKind::IndexError, "pop from an empty deque"));
    };
    deque.mutated();

    Ok(item)
}

/// `extend` / `extendleft`. Extending a deque with itself iterates a copy.
fn extend(vm: &Vm, target: &Value, deque: &Deque, iterable: &Value, left: bool) -> PyResult<()> {
    if vm.is_same(target, iterable) {
        for item in deque.snapshot() {
            if left {
                deque.push_front(item);
            } else {
                deque.push_back(item);
            }
        }
        return Ok(());
    }

    let iterator = vm.iter(iterable)?;
    while let Some(item) = vm.next(&iterator)? {
        if left {
            deque.push_front(item);
        } else {
            deque.push_back(item);
        }
    }

    Ok(())
}

fn deque_extend(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "extend")?;
    let iterable = method_one_argument(vm, &args, "extend")?;
    extend(vm, &args.positional[0], deque, &iterable, false)?;

    Ok(Value::None)
}

fn deque_extendleft(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "extendleft")?;
    let iterable = method_one_argument(vm, &args, "extendleft")?;
    extend(vm, &args.positional[0], deque, &iterable, true)?;

    Ok(Value::None)
}

fn deque_iadd(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__iadd__")?;
    let iterable = method_one_argument(vm, &args, "__iadd__")?;
    extend(vm, &args.positional[0], deque, &iterable, false)?;

    Ok(args.positional[0].clone())
}

fn deque_rotate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "rotate")?;
    let args = method_arguments(vm, &args, "rotate", 0, 1)?;

    let count = match args.first() {
        None => 1,
        Some(value) => {
            if value.is_unknown() {
                return Err(vm.halt_unsupported("deque.rotate by an unknown count"));
            }
            if vm.as_float(value).is_some() {
                return Err(vm.type_error("integer argument expected, got float"));
            }
            let Some(count) = vm.as_index(value) else {
                return Err(vm.type_error("an integer is required"));
            };
            count
        }
    };
    deque.rotate(count);

    Ok(Value::None)
}

/// Removes the first item equal to the value.
fn deque_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "remove")?;
    let value = method_one_argument(vm, &args, "remove")?;

    let snapshot = deque.snapshot();
    let length = snapshot.len();
    for (position, item) in snapshot.iter().enumerate() {
        let equal = vm.is_same(item, &value) || vm.equals(item, &value)?;
        if deque.len() != length {
            return Err(vm.raise(ExceptionKind::IndexError, "deque mutated during remove()."));
        }
        if equal {
            deque.items.borrow_mut().remove(position);
            deque.mutated();
            return Ok(Value::None);
        }
    }

    Err(vm.raise(ExceptionKind::ValueError, "deque.remove(x): x not in deque"))
}

/// `clear` pops every item; an empty deque is left untouched.
fn deque_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "clear")?;
    method_no_arguments(vm, &args, "clear")?;

    if deque.len() > 0 {
        deque.items.borrow_mut().clear();
        deque.mutated();
    }

    Ok(Value::None)
}

fn deque_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "count")?;
    let value = method_one_argument(vm, &args, "count")?;

    let state = deque.state.get();
    let mut count = 0i64;
    for item in deque.snapshot() {
        let equal = vm.is_same(&item, &value) || vm.equals(&item, &value)?;
        if deque.state.get() != state {
            return Err(vm.raise(ExceptionKind::RuntimeError, "deque mutated during iteration"));
        }
        if equal {
            count += 1;
        }
    }

    Ok(vm.new_int_from_i64(count))
}

/// `reverse` swaps items in place without counting a mutation, so live
/// iterators continue over the reversed order.
fn deque_reverse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "reverse")?;
    method_no_arguments(vm, &args, "reverse")?;

    deque.items.borrow_mut().make_contiguous().reverse();

    Ok(Value::None)
}

/// Calls the deque's own type, so subclasses copy as themselves.
fn deque_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__copy__")?;
    let target = args.positional[0].clone();

    let class = Value::Object(vm.class_of(&target));
    let mut arguments = vec![target];
    if let Some(maxlen) = deque.maxlen.get() {
        arguments.push(vm.new_int_from_i64(maxlen as i64));
    }

    vm.call(&class, CallArgs::new(arguments))
}

/// The constructor arguments include `maxlen`, as `None` for an unbounded
/// deque, whenever the instance has a `__dict__`.
fn deque_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__reduce__")?;
    let target = args.positional[0].clone();

    let dict = match &target {
        Value::Object(object) => object.dict().map(Value::Object),
        _ => None,
    };
    let items = vm.new_list(deque.snapshot());
    let maxlen = deque.maxlen.get().map(|maxlen| vm.new_int_from_i64(maxlen as i64));
    let class = Value::Object(vm.class_of(&target));

    Ok(match (dict, maxlen) {
        (None, None) => Value::tuple(vec![class, Value::tuple(vec![items])]),
        (None, Some(maxlen)) => Value::tuple(vec![class, Value::tuple(vec![items, maxlen])]),
        (Some(dict), maxlen) => Value::tuple(vec![class, Value::tuple(vec![items, maxlen.unwrap_or(Value::None)]), dict]),
    })
}

fn deque_len_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__len__")?;

    Ok(vm.new_int_from_i64(deque.len() as i64))
}

fn deque_iter_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__iter__")?;

    new_deque_iterator(vm, &args.positional[0], deque, false)
}

fn deque_reversed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__reversed__")?;

    new_deque_iterator(vm, &args.positional[0], deque, true)
}

fn deque_getitem_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    the_deque(vm, &args, "__getitem__")?;
    let args = positional(vm, args, "__getitem__", 2, 2)?;
    let Value::Object(object) = &args[0] else {
        return Err(vm.type_error("deque.__getitem__ requires a deque"));
    };

    match deque_getitem(vm, object, &args[1])? {
        Some(item) => Ok(item),
        None => Err(vm.type_error("deque.__getitem__ requires a deque")),
    }
}

fn deque_setitem_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    the_deque(vm, &args, "__setitem__")?;
    let args = positional(vm, args, "__setitem__", 3, 3)?;
    let Value::Object(object) = &args[0] else {
        return Err(vm.type_error("deque.__setitem__ requires a deque"));
    };

    deque_setitem(vm, object, &args[1], Some(args[2].clone()))?;

    Ok(Value::None)
}

fn deque_delitem_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    the_deque(vm, &args, "__delitem__")?;
    let args = positional(vm, args, "__delitem__", 2, 2)?;
    let Value::Object(object) = &args[0] else {
        return Err(vm.type_error("deque.__delitem__ requires a deque"));
    };

    deque_setitem(vm, object, &args[1], None)?;

    Ok(Value::None)
}

/// `deque([...])`, with `maxlen=n` when bounded and `[...]` for a deque
/// that contains itself.
fn deque_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let deque = the_deque(vm, &args, "__repr__")?;
    let Value::Object(object) = &args.positional[0] else {
        return Err(vm.type_error("deque.__repr__ requires a deque"));
    };

    let guard = vm.native_state::<ReprGuard>();
    if !guard.active.borrow_mut().insert(object.id) {
        return Ok(Value::str("[...]"));
    }
    let parts: PyResult<Vec<String>> = deque.snapshot().iter().map(|item| vm.repr_text(item)).collect();
    guard.active.borrow_mut().remove(&object.id);

    let list = format!("[{}]", parts?.join(", "));
    let text = match deque.maxlen.get() {
        Some(maxlen) => format!("deque({list}, maxlen={maxlen})"),
        None => format!("deque({list})"),
    };

    Ok(Value::str(&text))
}

/// Sequence comparison against another deque. Both deques are walked with
/// iterators, so a comparison that mutates either deque fails at the next
/// step.
fn deque_compare(vm: &Vm, args: CallArgs, operation: CompareOp, name: &str) -> PyResult<Value> {
    let deque = the_deque(vm, &args, name)?;
    let other_value = method_one_argument(vm, &args, name)?;
    let Some(other) = native_data::<Deque>(&other_value) else {
        return Ok(Value::NotImplemented);
    };

    let left = deque.snapshot();
    let right = other.snapshot();
    let same = vm.is_same(&args.positional[0], &other_value);
    match operation {
        CompareOp::Equal if same || left.len() != right.len() => return Ok(Value::Bool(same)),
        CompareOp::NotEqual if same || left.len() != right.len() => return Ok(Value::Bool(!same)),
        _ => {}
    }

    let (left_state, right_state) = (deque.state.get(), other.state.get());
    let mutated = || vm.raise(ExceptionKind::RuntimeError, "deque mutated during iteration");
    for (index, (a, b)) in left.iter().zip(right.iter()).enumerate() {
        if !(vm.is_same(a, b) || vm.equals(a, b)?) {
            return match operation {
                CompareOp::Equal => Ok(Value::Bool(false)),
                CompareOp::NotEqual => Ok(Value::Bool(true)),
                _ => vm.compare(a, b, operation),
            };
        }
        if deque.state.get() != left_state {
            return Err(mutated());
        }
        if index + 1 < left.len() && other.state.get() != right_state {
            return Err(mutated());
        }
    }

    vm.compare(&Value::Int(left.len() as i64), &Value::Int(right.len() as i64), operation)
}

fn deque_eq(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::Equal, "__eq__")
}

fn deque_ne(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::NotEqual, "__ne__")
}

fn deque_lt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::Less, "__lt__")
}

fn deque_le(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::LessEqual, "__le__")
}

fn deque_gt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::Greater, "__gt__")
}

fn deque_ge(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    deque_compare(vm, args, CompareOp::GreaterEqual, "__ge__")
}

fn iterator_self(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<DequeIterator>(vm, &args, "deque_iterator", "__iter__")?;

    Ok(args.positional[0].clone())
}

/// Forward and reverse deque iteration.
fn iterator_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let iterator = this::<DequeIterator>(vm, &args, "deque_iterator", "next")?;
    let Some(deque) = native_data::<Deque>(&iterator.deque) else {
        return Err(vm.type_error("deque iterator lost its deque"));
    };

    if deque.state.get() != iterator.state {
        iterator.remaining.set(0);
        return Err(vm.raise(ExceptionKind::RuntimeError, "deque mutated during iteration"));
    }
    if iterator.remaining.get() == 0 {
        return iterator_result(vm, None);
    }

    let index = iterator.index.get();
    let item = {
        let items = deque.items.borrow();
        let position = if iterator.reverse { items.len().checked_sub(index + 1) } else { Some(index) };
        position.and_then(|position| items.get(position).cloned())
    };
    iterator.index.set(index + 1);
    iterator.remaining.set(iterator.remaining.get() - 1);

    iterator_result(vm, item)
}

fn iterator_length_hint(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let iterator = this::<DequeIterator>(vm, &args, "deque_iterator", "__length_hint__")?;

    Ok(vm.new_int_from_i64(iterator.remaining.get() as i64))
}

fn create_defaultdict_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "defaultdict",
            module: "collections",
            base: Some(Rc::clone(&vm.types().dict)),
            layout: Layout::Dict,
            instance_dict: false,
            methods: &[
                method("__init__", defaultdict_init),
                method("__missing__", defaultdict_missing_method),
                method("copy", defaultdict_copy),
                method("__copy__", defaultdict_copy),
                method("__reduce__", defaultdict_reduce),
                method("__repr__", defaultdict_repr),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "default_factory", owner: DEFAULTDICT, get: factory_get, set: Some(factory_set) })?;

    Ok(class)
}

fn the_defaultdict(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<ObjectRef> {
    let class = defaultdict_type(vm)?;
    let Some(target) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{name}' of '{DEFAULTDICT}' object needs an argument")));
    };

    match target {
        Value::Object(object) if vm.is_subclass(&object.class(), &class)? => Ok(Rc::clone(object)),
        _ => Err(vm.type_error(&format!("descriptor '{name}' requires a '{DEFAULTDICT}' object but received a '{}'", vm.type_name(target)))),
    }
}

fn default_factory(vm: &Vm, dict: &ObjectRef) -> Value {
    let state = vm.native_state::<DefaultFactories>();
    let factories = state.factories.borrow();

    factories.get(&dict.id).map(|(_, factory)| factory.clone()).unwrap_or(Value::None)
}

/// Records the factory of `dict`. Entries of collected dicts are dropped
/// whenever the table doubles.
fn set_default_factory(vm: &Vm, dict: &ObjectRef, factory: Value) {
    let state = vm.native_state::<DefaultFactories>();
    let mut factories = state.factories.borrow_mut();

    factories.insert(dict.id, (Rc::downgrade(dict), factory));
    if factories.len() > 2 * state.collected_at.get().max(32) {
        factories.retain(|_, (owner, _)| owner.strong_count() > 0);
        state.collected_at.set(factories.len());
    }
}

/// The first positional argument is the factory; the rest initialize the
/// dict as `dict.__init__` does.
fn defaultdict_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dict = the_defaultdict(vm, &args, "__init__")?;
    let (_, mut rest) = receiver(vm, args, "__init__")?;

    let factory = if rest.positional.is_empty() { Value::None } else { rest.positional.remove(0) };
    if !factory.is_none() && !is_callable(vm, &factory)? {
        return Err(vm.type_error("first argument must be callable or None"));
    }
    set_default_factory(vm, &dict, factory);

    if rest.positional.len() > 1 {
        return Err(vm.type_error(&format!("dict expected at most 1 arguments, got {}", rest.positional.len())));
    }
    if let Some(source) = rest.positional.first() {
        let is_dict = source.as_object().is_some_and(|object| object.as_dict().is_some());
        if is_dict || vm.getattr_opt(source, &crate::interp::value::PyBytes::from("keys"))?.is_some() {
            vm.dict_merge(&dict, source, true)?;
        } else {
            vm.dict_merge_pairs(&dict, source)?;
        }
    }
    if rest.has_keywords() {
        let keywords = vm.keywords_as_dict(rest.keywords, rest.keyword_dict)?;
        vm.dict_merge(&dict, &Value::Object(keywords), true)?;
    }

    Ok(Value::None)
}

fn defaultdict_missing_method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dict = the_defaultdict(vm, &args, "__missing__")?;
    let args = positional(vm, args, "__missing__", 2, 2)?;

    match defaultdict_missing(vm, &dict, &args[1])? {
        Some(value) => Ok(value),
        None => Err(vm.key_error(args[1].clone())),
    }
}

/// `type(self)(self.default_factory, self)`.
fn defaultdict_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dict = the_defaultdict(vm, &args, "copy")?;
    let class = Value::Object(dict.class());
    let factory = default_factory(vm, &dict);

    vm.call(&class, CallArgs::new(vec![factory, Value::Object(dict)]))
}

/// `(type, (factory,) or (), None, None, iteritems)`.
fn defaultdict_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dict = the_defaultdict(vm, &args, "__reduce__")?;
    let factory = default_factory(vm, &dict);

    let arguments = if factory.is_none() { Value::tuple(Vec::new()) } else { Value::tuple(vec![factory]) };
    let length = vm.dict_len(&dict)?;
    let items = vm.new_iterator(NativeIterator::DictItems { dict: Rc::clone(&dict), position: 0, length, remaining: length });

    Ok(Value::tuple(vec![Value::Object(dict.class()), arguments, Value::None, Value::None, items]))
}

/// `defaultdict(factory, {...})`.
fn defaultdict_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dict = the_defaultdict(vm, &args, "__repr__")?;
    let factory = default_factory(vm, &dict);

    let factory_repr = if factory.is_none() {
        "None".to_owned()
    } else {
        let guard = vm.native_state::<ReprGuard>();
        if guard.active.borrow().contains(&dict.id) {
            "...".to_owned()
        } else {
            guard.active.borrow_mut().insert(dict.id);
            let text = vm.repr_text(&factory);
            guard.active.borrow_mut().remove(&dict.id);
            text?
        }
    };
    let base = vm.builtin_repr(&Value::Object(Rc::clone(&dict)))?;

    Ok(Value::str(&format!("defaultdict({factory_repr}, {base})")))
}

fn factory_get(vm: &Vm, _getset: &GetSet, instance: &Value) -> PyResult<Value> {
    match instance {
        Value::Object(object) => Ok(default_factory(vm, object)),
        _ => Err(vm.type_error("default_factory requires a defaultdict")),
    }
}

fn factory_set(vm: &Vm, _getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Value::Object(object) = instance else {
        return Err(vm.type_error("default_factory requires a defaultdict"));
    };

    set_default_factory(vm, object, value.unwrap_or(Value::None));

    Ok(())
}
