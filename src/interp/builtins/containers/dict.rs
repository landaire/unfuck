use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::containers::views::ViewKind;
use crate::interp::builtins::containers::views::new_view;
use crate::interp::builtins::class_method;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::CompareOp;
use crate::interp::table::Hashed;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install(
        vm,
        &types.dict,
        &[
            static_method("__new__", dict_new),
            method("__init__", dict_init),
            method("__getitem__", dict_getitem),
            method("__setitem__", dict_setitem),
            method("__delitem__", dict_delitem),
            method("__contains__", dict_contains),
            method("__len__", dict_len),
            method("__iter__", dict_iter),
            method("__eq__", |vm, args| dict_compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| dict_compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| dict_compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| dict_compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| dict_compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| dict_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__cmp__", dict_cmp),
            method("__repr__", dict_repr),
            method("get", dict_get),
            method("setdefault", dict_setdefault),
            method("pop", dict_pop),
            method("popitem", dict_popitem),
            method("clear", dict_clear),
            method("copy", dict_copy),
            method("update", dict_update),
            method("has_key", dict_has_key),
            method("keys", |vm, args| dict_listing(vm, args, "keys", ViewKind::Keys)),
            method("values", |vm, args| dict_listing(vm, args, "values", ViewKind::Values)),
            method("items", |vm, args| dict_listing(vm, args, "items", ViewKind::Items)),
            method("iterkeys", |vm, args| dict_iterator(vm, args, "iterkeys", ViewKind::Keys)),
            method("itervalues", |vm, args| dict_iterator(vm, args, "itervalues", ViewKind::Values)),
            method("iteritems", |vm, args| dict_iterator(vm, args, "iteritems", ViewKind::Items)),
            method("viewkeys", |vm, args| dict_view(vm, args, "viewkeys", ViewKind::Keys)),
            method("viewvalues", |vm, args| dict_view(vm, args, "viewvalues", ViewKind::Values)),
            method("viewitems", |vm, args| dict_view(vm, args, "viewitems", ViewKind::Items)),
            class_method("fromkeys", dict_fromkeys),
        ],
    )?;
    crate::interp::builtins::arguments::set_class_attribute(vm, &types.dict, "__hash__", Value::None)?;

    install(
        vm,
        &types.dictproxy,
        &[
            method("__getitem__", proxy_getitem),
            method("__contains__", proxy_contains),
            method("__len__", proxy_len),
            method("__iter__", proxy_iter),
            method("__eq__", |vm, args| proxy_compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| proxy_compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| proxy_compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| proxy_compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| proxy_compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| proxy_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__repr__", proxy_repr),
            method("__str__", proxy_str),
            method("get", proxy_get),
            method("has_key", proxy_has_key),
            method("copy", proxy_copy),
            method("keys", |vm, args| proxy_listing(vm, args, "keys", ViewKind::Keys)),
            method("values", |vm, args| proxy_listing(vm, args, "values", ViewKind::Values)),
            method("items", |vm, args| proxy_listing(vm, args, "items", ViewKind::Items)),
            method("iterkeys", |vm, args| proxy_iterator(vm, args, "iterkeys", ViewKind::Keys)),
            method("itervalues", |vm, args| proxy_iterator(vm, args, "itervalues", ViewKind::Values)),
            method("iteritems", |vm, args| proxy_iterator(vm, args, "iteritems", ViewKind::Items)),
        ],
    )
}

/// The receiver of a `dict` method; dict subclasses included.
fn bind_dict(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "dict")?;
    match &target {
        Value::Object(object) if matches!(object.payload, Payload::Dict(_)) => Ok((Rc::clone(object), rest)),
        _ => Err(wrong_receiver(vm, method, "dict", &target)),
    }
}

fn is_exact_dict(vm: &Vm, object: &ObjectRef) -> bool {
    matches!(object.payload, Payload::Dict(_)) && Rc::ptr_eq(&object.class(), &vm.types().dict)
}

fn dict_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().dict);
    let (class, _) = new_class(vm, args, &base)?;

    vm.instantiate_layout(&class)
}

fn dict_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__init__")?;
    update_common(vm, &dict, rest, "dict")?;

    Ok(Value::None)
}

fn dict_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "update")?;
    update_common(vm, &dict, rest, "update")?;

    Ok(Value::None)
}

/// A mapping (anything with `keys`) merges directly, any other iterable as
/// key/value pairs; keyword arguments then merge as a dict of their own.
fn update_common(vm: &Vm, dict: &ObjectRef, args: CallArgs, name: &str) -> PyResult<()> {
    let CallArgs { positional, keywords, keyword_dict } = args;
    if positional.len() > 1 {
        return Err(vm.type_error(&format!("{name} expected at most 1 arguments, got {}", positional.len())));
    }

    if let Some(source) = positional.first() {
        if let Value::Unknown(unknown) = source {
            return Err(Signal::Halt(Halt::UnknownIteration { origin: unknown.origin.clone() }));
        }
        if has_attribute(vm, source, "keys")? {
            vm.dict_merge(dict, source, true)?;
        } else {
            vm.dict_merge_pairs(dict, source)?;
        }
    }

    if let Some(extra) = keyword_dict {
        return vm.dict_merge(dict, &Value::Object(extra), true);
    }

    if keywords.is_empty() {
        return Ok(());
    }

    let extra = vm.new_dict();
    for (name, value) in keywords {
        vm.dict_set(&extra, Value::Str(name), value)?;
    }

    vm.dict_merge(dict, &Value::Object(extra), true)
}

/// `hasattr` semantics: any exception reads as absent.
fn has_attribute(vm: &Vm, target: &Value, name: &str) -> PyResult<bool> {
    match vm.getattr_opt(target, &PyBytes::from(name)) {
        Ok(found) => Ok(found.is_some()),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt),
    }
}

/// Subclasses fall back to `__missing__`.
fn dict_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__getitem__")?;
    let key = wrapper_operand(vm, rest)?;

    if let Some(value) = vm.dict_get(&dict, &key)? {
        return Ok(value);
    }

    if !is_exact_dict(vm, &dict) {
        if let Some(missing) = vm.user_override(&Value::Object(Rc::clone(&dict)), "__missing__")? {
            return vm.call1(&missing, key);
        }
        if let Some(value) = crate::interp::builtins::collections::defaultdict_missing(vm, &dict, &key)? {
            return Ok(value);
        }
    }

    Err(vm.key_error(key))
}

fn dict_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__setitem__")?;
    let (key, value) = wrapper_pair(vm, rest)?;
    vm.dict_set(&dict, key, value)?;

    Ok(Value::None)
}

fn dict_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__delitem__")?;
    let key = wrapper_operand(vm, rest)?;
    if !vm.dict_delete(&dict, &key)? {
        return Err(vm.key_error(key));
    }

    Ok(Value::None)
}

fn dict_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__contains__")?;
    let key = wrapper_operand(vm, rest)?;

    Ok(Value::Bool(vm.dict_get(&dict, &key)?.is_some()))
}

fn dict_has_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "has_key")?;
    let key = one_argument(vm, rest, "has_key")?;

    Ok(Value::Bool(vm.dict_get(&dict, &key)?.is_some()))
}

fn dict_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(vm.dict_len(&dict)? as i64))
}

fn dict_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    iterator_over(vm, dict, ViewKind::Keys)
}

/// Equality only; ordering is left to `__cmp__`.
fn dict_compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Value::Object(other) = &other else {
        return Ok(Value::NotImplemented);
    };
    if !matches!(other.payload, Payload::Dict(_)) {
        return Ok(Value::NotImplemented);
    }

    match operation {
        CompareOp::Equal => Ok(Value::Bool(vm.dicts_equal(&dict, other)?)),
        CompareOp::NotEqual => Ok(Value::Bool(!vm.dicts_equal(&dict, other)?)),
        _ => Ok(Value::NotImplemented),
    }
}

/// Dicts order by their smallest differing key, which the interpreter
/// does not emulate.
fn dict_cmp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__cmp__")?;
    let other = wrapper_operand(vm, rest)?;
    let same_comparison = matches!(other.as_object().map(|object| &object.payload), Some(Payload::Dict(_)));
    crate::interp::builtins::arguments::cmp_operand_check(vm, &Value::Object(dict), &other, same_comparison)?;

    Err(vm.halt_unsupported("dict.__cmp__ ordering"))
}

fn dict_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&Value::Object(dict))?.into_bytes())))
}

/// The key and optional default of `get`, `setdefault`, and `pop`.
fn key_and_default(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, Option<Value>)> {
    let mut arguments = unpack(vm, args, method, 1, 2)?.into_iter();
    let key = arguments.next().ok_or_else(|| vm.type_error(&format!("{method} expected at least 1 arguments, got 0")))?;

    Ok((key, arguments.next()))
}

fn dict_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "get")?;
    let (key, default) = key_and_default(vm, rest, "get")?;

    Ok(vm.dict_get(&dict, &key)?.or(default).unwrap_or(Value::None))
}

/// One hash serves the lookup and the insertion.
fn dict_setdefault(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "setdefault")?;
    let (key, default) = key_and_default(vm, rest, "setdefault")?;
    let hash = vm.hash(&key)?;

    if let Some(value) = vm.dict_get_hashed(&dict, &key, hash)? {
        return Ok(value);
    }

    let default = default.unwrap_or(Value::None);
    vm.dict_set_hashed(&dict, key, hash, default.clone())?;

    Ok(default)
}

/// An empty dict answers before the key is hashed.
fn dict_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "pop")?;
    let (key, default) = key_and_default(vm, rest, "pop")?;

    let removed = if vm.dict_len(&dict)? == 0 { None } else { vm.dict_pop(&dict, &key)? };
    match (removed, default) {
        (Some(value), _) => Ok(value),
        (None, Some(default)) => Ok(default),
        (None, None) => Err(vm.key_error(key)),
    }
}

fn dict_popitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "popitem")?;
    no_arguments(vm, rest, "popitem")?;

    let cell = vm.dict_cell(&dict)?;
    let popped = cell.try_borrow_mut().map_err(|_| vm.raise(ExceptionKind::RuntimeError, "dictionary changed size during lookup"))?.popitem();
    match popped {
        Some((key, value)) => Ok(Value::tuple(vec![key, value])),
        None => Err(vm.raise(ExceptionKind::KeyError, "popitem(): dictionary is empty")),
    }
}

fn dict_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "clear")?;
    no_arguments(vm, rest, "clear")?;

    let cell = vm.dict_cell(&dict)?;
    cell.try_borrow_mut().map_err(|_| vm.raise(ExceptionKind::RuntimeError, "dictionary changed size during lookup"))?.clear();

    Ok(Value::None)
}

fn dict_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, "copy")?;
    no_arguments(vm, rest, "copy")?;

    Ok(Value::Object(vm.dict_copy(&dict)?))
}

fn listing(vm: &Vm, dict: &ObjectRef, kind: ViewKind) -> PyResult<Value> {
    let items = match kind {
        ViewKind::Keys => vm.dict_keys(dict)?,
        ViewKind::Values => vm.dict_values(dict)?,
        ViewKind::Items => vm.dict_items(dict)?.into_iter().map(|(key, value)| Value::tuple(vec![key, value])).collect(),
    };

    Ok(vm.new_list(items))
}

fn iterator_over(vm: &Vm, dict: ObjectRef, kind: ViewKind) -> PyResult<Value> {
    let length = vm.dict_len(&dict)?;
    let iterator = match kind {
        ViewKind::Keys => NativeIterator::DictKeys { dict, position: 0, length, remaining: length },
        ViewKind::Values => NativeIterator::DictValues { dict, position: 0, length, remaining: length },
        ViewKind::Items => NativeIterator::DictItems { dict, position: 0, length, remaining: length },
    };

    Ok(vm.new_iterator(iterator))
}

fn dict_listing(vm: &Vm, args: CallArgs, method: &str, kind: ViewKind) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, method)?;
    no_arguments(vm, rest, method)?;

    listing(vm, &dict, kind)
}

fn dict_iterator(vm: &Vm, args: CallArgs, method: &str, kind: ViewKind) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, method)?;
    no_arguments(vm, rest, method)?;

    iterator_over(vm, dict, kind)
}

fn dict_view(vm: &Vm, args: CallArgs, method: &str, kind: ViewKind) -> PyResult<Value> {
    let (dict, rest) = bind_dict(vm, args, method)?;
    no_arguments(vm, rest, method)?;

    Ok(new_view(vm, dict, kind))
}

/// `dict.fromkeys`. An exact dict result filled from an exact dict or any
/// exact set is presized once and filled without growth checks. The
/// presize is one and a half times the source size rounded down to an even
/// count, where a dict's size is its fill (deleted slots included) and a
/// set's size is its length.
fn dict_fromkeys(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, rest) = bind(vm, args, "fromkeys", "dict")?;
    let arguments = unpack(vm, rest, "fromkeys", 1, 2)?;
    let source = &arguments[0];
    let value = arguments.get(1).cloned().unwrap_or(Value::None);

    let result = vm.call(&class, CallArgs::default())?;
    let exact_result = match &result {
        Value::Object(object) if is_exact_dict(vm, object) => Some(Rc::clone(object)),
        _ => None,
    };

    if let Some(target) = &exact_result {
        if let Some((source_size, entries)) = presized_source(vm, source) {
            let eq = |stored: &Value, probe: &Value| vm.keys_equal(stored, probe);
            let cell = vm.dict_cell(target)?;
            let mut table = cell.try_borrow_mut().map_err(|_| vm.raise(ExceptionKind::RuntimeError, "dictionary changed size during lookup"))?;
            table.presize(source_size / 2 * 3);
            for entry in entries {
                table.insert_no_resize(entry.hash, entry.key.clone(), value.clone(), |stored| eq(stored, &entry.key))?;
            }
            drop(table);
            return Ok(result);
        }
    }

    let iterator = vm.iter(source)?;
    while let Some(key) = vm.next(&iterator)? {
        match &exact_result {
            Some(target) => vm.dict_set(target, key, value.clone())?,
            None => vm.setitem(&result, &key, value.clone())?,
        }
    }

    Ok(result)
}

/// The size and hashed keys of an exact dict or exact set source.
fn presized_source(vm: &Vm, source: &Value) -> Option<(usize, Vec<Hashed<Value>>)> {
    let Value::Object(object) = source else {
        return None;
    };
    let class = object.class();
    let types = vm.types();

    match &object.payload {
        Payload::Dict(table) if Rc::ptr_eq(&class, &types.dict) => {
            let table = table.borrow();
            Some((table.fill(), table.entries().map(|entry| Hashed { hash: entry.hash, key: entry.key.clone() }).collect()))
        }
        Payload::Set(table) if Rc::ptr_eq(&class, &types.set) => {
            let table = table.borrow();
            Some((table.len(), table.entries().map(|entry| Hashed { hash: entry.hash, key: entry.key.clone() }).collect()))
        }
        Payload::FrozenSet(table) if Rc::ptr_eq(&class, &types.frozenset) => Some((table.len(), table.entries().map(|entry| Hashed { hash: entry.hash, key: entry.key.clone() }).collect())),
        _ => None,
    }
}

/// The dict behind the receiver of a `dictproxy` method.
fn bind_proxy(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "dictproxy")?;
    match &target {
        Value::Object(object) => match &object.payload {
            Payload::DictProxy(dict) => Ok((Rc::clone(dict), rest)),
            _ => Err(wrong_receiver(vm, method, "dictproxy", &target)),
        },
        _ => Err(wrong_receiver(vm, method, "dictproxy", &target)),
    }
}

fn proxy_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__getitem__")?;
    let key = wrapper_operand(vm, rest)?;

    match vm.dict_get(&dict, &key)? {
        Some(value) => Ok(value),
        None => Err(vm.key_error(key)),
    }
}

fn proxy_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__contains__")?;
    let key = wrapper_operand(vm, rest)?;

    Ok(Value::Bool(vm.dict_get(&dict, &key)?.is_some()))
}

fn proxy_has_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "has_key")?;
    let key = one_argument(vm, rest, "has_key")?;

    Ok(Value::Bool(vm.dict_get(&dict, &key)?.is_some()))
}

fn proxy_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(vm.dict_len(&dict)? as i64))
}

fn proxy_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    iterator_over(vm, dict, ViewKind::Keys)
}

/// Compares the underlying dict.
fn proxy_compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;

    vm.compare(&Value::Object(dict), &other, operation)
}

fn proxy_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::str(&format!("dict_proxy({})", vm.repr_text(&Value::Object(dict))?)))
}

fn proxy_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "__str__")?;
    wrapper_arguments(vm, rest, 0)?;

    vm.to_str(&Value::Object(dict))
}

fn proxy_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "get")?;
    let (key, default) = key_and_default(vm, rest, "get")?;

    Ok(vm.dict_get(&dict, &key)?.or(default).unwrap_or(Value::None))
}

fn proxy_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, "copy")?;
    no_arguments(vm, rest, "copy")?;

    Ok(Value::Object(vm.dict_copy(&dict)?))
}

fn proxy_listing(vm: &Vm, args: CallArgs, method: &str, kind: ViewKind) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, method)?;
    no_arguments(vm, rest, method)?;

    listing(vm, &dict, kind)
}

fn proxy_iterator(vm: &Vm, args: CallArgs, method: &str, kind: ViewKind) -> PyResult<Value> {
    let (dict, rest) = bind_proxy(vm, args, method)?;
    no_arguments(vm, rest, method)?;

    iterator_over(vm, dict, kind)
}
