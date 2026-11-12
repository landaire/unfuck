//! `_weakref`. References hold `Weak` pointers, so they die with the last
//! strong reference; the VM's finalizer queue then clears them and runs
//! their callbacks (see `crate::interp::lifecycle`).

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::lifecycle::Lifecycle;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::Object;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A `weakref` or a proxy.
struct WeakReference {
    /// `None` once cleared.
    referent: RefCell<Option<Weak<Object>>>,
    callback: RefCell<Option<Value>>,
    hash: Cell<Option<i64>>,
}

impl WeakReference {
    fn new(referent: &ObjectRef, callback: Value) -> Self {
        let callback = if callback.is_none() { None } else { Some(callback) };

        Self { referent: RefCell::new(Some(Rc::downgrade(referent))), callback: RefCell::new(callback), hash: Cell::new(None) }
    }

    /// The referent while it is alive.
    fn object(&self) -> Option<Value> {
        self.referent.borrow().as_ref().and_then(Weak::upgrade).map(Value::Object)
    }
}

/// Marks `object` as weakly referenced, so its death is queued.
fn mark_referenced(object: &ObjectRef) {
    object.lifecycle.set(object.lifecycle.get().with(Lifecycle::WEAKLY_REFERENCED));
}

/// Clears every reference to the dying `object`, then, when `callbacks` is
/// set, calls each reference's callback with it in list order. Callback
/// exceptions are reported, not raised.
pub fn clear_weak_references(vm: &Vm, object: &ObjectRef, callbacks: bool) -> PyResult<()> {
    let entries = vm.native_state::<WeakLists>().lists.borrow_mut().remove(&object.id).unwrap_or_default();

    let mut pending = Vec::new();
    for entry in entries {
        let Some(reference) = entry.reference.upgrade() else {
            continue;
        };
        let reference = Value::Object(reference);
        let Some(data) = native_data::<WeakReference>(&reference) else {
            continue;
        };
        *data.referent.borrow_mut() = None;
        let callback = data.callback.borrow_mut().take();
        if let (true, Some(callback)) = (callbacks, callback) {
            pending.push((reference, callback));
        }
    }

    for (reference, callback) in pending {
        match vm.call1(&callback, reference) {
            Ok(_) => {}
            Err(Signal::Raise(error)) => vm.write_unraisable(&callback, &error),
            Err(halt) => return Err(halt),
        }
    }

    Ok(())
}

/// The first live reference to `object`, for `__weakref__`.
pub fn first_weak_reference(vm: &Vm, object: &ObjectRef) -> Option<ObjectRef> {
    vm.native_state::<WeakLists>().live(object.id).into_iter().next().map(|(reference, _)| reference)
}

impl_native_data!(WeakReference, "weakref");

/// How a reference sits in its referent's reference list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An exact `weakref` without a callback, shared by every such request.
    BasicRef,
    /// A proxy without a callback, likewise shared.
    BasicProxy,
    Other,
}

struct Entry {
    reference: Weak<Object>,
    kind: Kind,
}

/// Each referent's references in CPython's reference list order.
#[derive(Default)]
struct WeakLists {
    lists: RefCell<HashMap<ObjectId, Vec<Entry>>>,
}

impl WeakLists {
    /// The live references of `referent`, dropping collected ones.
    fn live(&self, referent: ObjectId) -> Vec<(ObjectRef, Kind)> {
        let mut lists = self.lists.borrow_mut();
        let Some(list) = lists.get_mut(&referent) else {
            return Vec::new();
        };

        list.retain(|entry| entry.reference.strong_count() > 0);

        list.iter().filter_map(|entry| entry.reference.upgrade().map(|object| (object, entry.kind))).collect()
    }

    /// The shared reference and proxy at the list head.
    fn basic(&self, referent: ObjectId) -> (Option<ObjectRef>, Option<ObjectRef>) {
        let live = self.live(referent);
        let mut entries = live.into_iter().peekable();

        let reference = entries.next_if(|(_, kind)| *kind == Kind::BasicRef).map(|(object, _)| object);
        let proxy = entries.next_if(|(_, kind)| *kind == Kind::BasicProxy).map(|(object, _)| object);

        (reference, proxy)
    }

    /// Inserts at the head when `previous` is `None`, else after `previous`.
    fn insert(&self, referent: ObjectId, reference: &ObjectRef, kind: Kind, previous: Option<&ObjectRef>) {
        let mut lists = self.lists.borrow_mut();
        let list = lists.entry(referent).or_default();
        let entry = Entry { reference: Rc::downgrade(reference), kind };

        let position = previous.and_then(|previous| list.iter().position(|entry| entry.reference.as_ptr() == Rc::as_ptr(previous)));
        match position {
            Some(index) => list.insert(index + 1, entry),
            None => list.insert(0, entry),
        }
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("getweakrefcount", getweakrefcount), function("getweakrefs", getweakrefs), function("proxy", proxy), function("_remove_dead_weakref", remove_dead_weakref)])?;

    let reference = Value::Object(reference_type(vm)?);
    set_attribute(vm, module, "ref", reference.clone())?;
    set_attribute(vm, module, "ReferenceType", reference)?;
    set_attribute(vm, module, "ProxyType", Value::Object(native_type(vm, "weakproxy", create_proxy_type)?))?;
    set_attribute(vm, module, "CallableProxyType", Value::Object(native_type(vm, "weakcallableproxy", create_callable_proxy_type)?))
}

fn reference_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "weakref", create_reference_type)
}

fn create_reference_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_type(
        vm,
        TypeSpec {
            name: "weakref",
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", reference_new),
                method("__init__", reference_init),
                method("__call__", reference_call),
                method("__hash__", reference_hash),
                method("__eq__", reference_eq),
                method("__ne__", reference_ne),
                method("__repr__", reference_repr),
            ],
        },
    )
}

/// The referent of a weak reference object.
fn referent_object(vm: &Vm, referent: &Value) -> PyResult<ObjectRef> {
    match referent {
        Value::Object(object) if is_weakly_referenceable(vm, object)? => Ok(Rc::clone(object)),
        _ => Err(vm.type_error(&format!("cannot create weak reference to '{}' object", vm.type_name(referent)))),
    }
}

/// Native types whose objects CPython 2.7 lets be weakly referenced.
const WEAKLY_REFERENCEABLE_NATIVE: [&str; 9] = ["collections.deque", "functools.partial", "sys.StandardStream", "thread.lock", "thread._local", "_sre.SRE_Pattern", "_multiprocessing.Connection", "_multiprocessing.PipeConnection", "_socket.socket"];

/// Whether instances of the referent's type have a weak reference list.
fn is_weakly_referenceable(vm: &Vm, object: &ObjectRef) -> PyResult<bool> {
    let class = object.class();
    if vm.is_classic_class(&class) {
        return Ok(true);
    }

    let by_payload = match &object.payload {
        Payload::Class(_) | Payload::Function(_) | Payload::Method(_) | Payload::Set(_) | Payload::FrozenSet(_) | Payload::Generator(_) | Payload::Code(_) => true,
        Payload::Native(data) => WEAKLY_REFERENCEABLE_NATIVE.contains(&data.type_name()),
        _ => false,
    };
    if by_payload || class.as_class().is_some_and(|data| data.builtin) {
        return Ok(by_payload);
    }

    // Classes defined in Python have `__weakref__` unless their
    // `__slots__` leave it out.
    vm.class_has_weakref(&class)
}

/// `weakref.ref.__new__`.
fn reference_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut positional_args = args.positional;
    if positional_args.is_empty() {
        return Err(vm.type_error("weakref.__new__(X): X is not a type object"));
    }
    let Value::Object(class) = positional_args.remove(0) else {
        return Err(vm.type_error("weakref.__new__(X): X is not a type object"));
    };
    let (referent, callback) = reference_arguments(vm, positional_args, "__new__")?;
    let object = referent_object(vm, &referent)?;

    let lists = vm.native_state::<WeakLists>();
    let exact = Rc::ptr_eq(&class, &reference_type(vm)?);
    let (basic_ref, basic_proxy) = lists.basic(object.id);

    if exact && callback.is_none() {
        if let Some(existing) = basic_ref {
            return Ok(Value::Object(existing));
        }
    }

    let reference = vm.alloc(&class, Payload::Native(Box::new(WeakReference::new(&object, callback.clone()))), None);
    mark_referenced(&object);

    if exact && callback.is_none() {
        lists.insert(object.id, &reference, Kind::BasicRef, None);
    } else {
        let previous = basic_proxy.or(basic_ref);
        lists.insert(object.id, &reference, Kind::Other, previous.as_ref());
    }

    Ok(Value::Object(reference))
}

/// One or two positional arguments, the referent and a callback, with a
/// `None` callback treated as absent.
fn reference_arguments(vm: &Vm, arguments: Vec<Value>, name: &str) -> PyResult<(Value, Value)> {
    match arguments.len() {
        0 => Err(vm.type_error(&format!("{name} expected at least 1 arguments, got 0"))),
        1 | 2 => {
            let mut arguments = arguments.into_iter();
            let referent = arguments.next().unwrap_or(Value::None);
            let callback = arguments.next().unwrap_or(Value::None);
            Ok((referent, callback))
        }
        count => Err(vm.type_error(&format!("{name} expected at most 2 arguments, got {count}"))),
    }
}

fn reference_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<WeakReference>(vm, &args, "weakref", "__init__")?;
    reference_arguments(vm, args.positional[1..].to_vec(), "__init__")?;

    Ok(Value::None)
}

fn reference_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reference = this::<WeakReference>(vm, &args, "weakref", "__call__")?;
    if args.positional.len() > 1 || args.has_keywords() {
        return Err(vm.type_error(&format!("weakref() takes no arguments ({} given)", args.positional.len() - 1 + args.keywords.len())));
    }

    Ok(reference.object().unwrap_or(Value::None))
}

/// `weakref.ref.__hash__`: the referent's hash, computed once.
fn reference_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reference = this::<WeakReference>(vm, &args, "weakref", "__hash__")?;
    if let Some(hash) = reference.hash.get() {
        return Ok(Value::Int(hash));
    }

    let Some(referent) = reference.object() else {
        return Err(vm.type_error("weak object has gone away"));
    };
    let hash = vm.hash(&referent)?.value();
    reference.hash.set(Some(hash));

    Ok(Value::Int(hash))
}

/// `weakref.ref` comparison: live references compare their referents.
fn reference_compare(vm: &Vm, args: CallArgs, operation: CompareOp, name: &str) -> PyResult<Value> {
    let reference = this::<WeakReference>(vm, &args, "weakref", name)?;
    let other = method_one_argument(vm, &args, name)?;
    let same_type = Rc::ptr_eq(&vm.class_of(&args.positional[0]), &vm.class_of(&other));
    let Some(other_reference) = native_data::<WeakReference>(&other).filter(|_| same_type) else {
        return Ok(Value::NotImplemented);
    };

    match (reference.object(), other_reference.object()) {
        (Some(left), Some(right)) => vm.compare(&left, &right, operation),
        _ => {
            let same = vm.is_same(&args.positional[0], &other);
            Ok(Value::Bool(same == (operation == CompareOp::Equal)))
        }
    }
}

fn is_reference(vm: &Vm, value: &Value) -> bool {
    let Ok(class) = reference_type(vm) else {
        return false;
    };

    vm.is_instance_of(value, &class).unwrap_or(false)
}

fn reference_eq(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    reference_compare(vm, args, CompareOp::Equal, "__eq__")
}

fn reference_ne(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    reference_compare(vm, args, CompareOp::NotEqual, "__ne__")
}

/// `weakref.ref.__repr__`.
fn reference_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reference = this::<WeakReference>(vm, &args, "weakref", "__repr__")?;
    let address = vm.c_pointer_text(vm.value_address(&args.positional[0]));
    let Some(referent) = reference.object() else {
        return Ok(Value::str(&format!("<weakref at {address}; dead>")));
    };
    let referent = &referent;
    let target = vm.c_pointer_text(vm.value_address(referent));
    let type_name = vm.type_name(referent);

    let name = vm.getattr_opt(referent, &PyBytes::from("__name__"))?;
    let text = match name.as_ref().and_then(|name| vm.text_of(name)) {
        Some(name) => format!("<weakref at {address}; to '{type_name}' at {target} ({name})>"),
        None => format!("<weakref at {address}; to '{type_name}' at {target}>"),
    };

    Ok(Value::str(&text))
}

fn getweakrefcount(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "getweakrefcount", 1, 1)?;
    let Value::Object(object) = &args[0] else {
        return Ok(Value::Int(0));
    };

    let count = vm.native_state::<WeakLists>().live(object.id).len();

    Ok(vm.new_int_from_i64(count as i64))
}

fn getweakrefs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "getweakrefs", 1, 1)?;
    let Value::Object(object) = &args[0] else {
        return Ok(vm.new_list(Vec::new()));
    };

    let references = vm.native_state::<WeakLists>().live(object.id).into_iter().map(|(reference, _)| Value::Object(reference)).collect();

    Ok(vm.new_list(references))
}

/// `_remove_dead_weakref(dict, key)`: deletes `dict[key]` when it is a
/// dead weak reference; a missing key is ignored.
fn remove_dead_weakref(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "_remove_dead_weakref", 2, 2)?;
    let Some(dict) = args[0].as_object().filter(|object| object.as_dict().is_some()) else {
        return Err(vm.type_error(&format!("_remove_dead_weakref() argument 1 must be dict, not {}", vm.type_name(&args[0]))));
    };

    let Some(value) = vm.dict_get(dict, &args[1])? else {
        return Ok(Value::None);
    };
    let dead = native_data::<WeakReference>(&value).is_some_and(|reference| reference.object().is_none());
    if dead {
        vm.dict_delete(dict, &args[1])?;
    }

    Ok(Value::None)
}

/// Creates a weak proxy.
fn proxy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "proxy", 1, 2)?;
    let (referent, callback) = reference_arguments(vm, args, "proxy")?;
    let object = referent_object(vm, &referent)?;

    let lists = vm.native_state::<WeakLists>();
    let (basic_ref, basic_proxy) = lists.basic(object.id);
    if callback.is_none() {
        if let Some(existing) = basic_proxy {
            return Ok(Value::Object(existing));
        }
    }

    let class = if is_callable(vm, &referent)? { native_type(vm, "weakcallableproxy", create_callable_proxy_type)? } else { native_type(vm, "weakproxy", create_proxy_type)? };
    let reference = vm.alloc(&class, Payload::Native(Box::new(WeakReference::new(&object, callback.clone()))), None);
    mark_referenced(&object);

    let (kind, previous) = if callback.is_none() { (Kind::BasicProxy, basic_ref) } else { (Kind::Other, basic_proxy.or(basic_ref)) };
    lists.insert(object.id, &reference, kind, previous.as_ref());

    Ok(Value::Object(reference))
}

fn create_proxy_type(vm: &Vm) -> PyResult<ObjectRef> {
    create_proxy_class(vm, "weakproxy", false)
}

fn create_callable_proxy_type(vm: &Vm) -> PyResult<ObjectRef> {
    create_proxy_class(vm, "weakcallableproxy", true)
}

/// Proxies forward every operation to the referent.
fn create_proxy_class(vm: &Vm, name: &'static str, callable: bool) -> PyResult<ObjectRef> {
    let mut methods = vec![
        method("__getattribute__", proxy_getattr),
        method("__getattr__", proxy_getattr),
        method("__setattr__", proxy_setattr),
        method("__delattr__", proxy_delattr),
        method("__repr__", proxy_repr),
        method("__str__", proxy_str),
        method("__nonzero__", proxy_nonzero),
        method("__len__", proxy_len),
        method("__getitem__", proxy_getitem),
        method("__setitem__", proxy_setitem),
        method("__delitem__", proxy_delitem),
        method("__contains__", proxy_contains),
        method("__iter__", proxy_iter),
        method("next", proxy_next),
        method("__eq__", proxy_eq),
        method("__ne__", proxy_ne),
        method("__lt__", proxy_lt),
        method("__le__", proxy_le),
        method("__gt__", proxy_gt),
        method("__ge__", proxy_ge),
        method("__add__", proxy_add),
        method("__sub__", proxy_sub),
        method("__mul__", proxy_mul),
        method("__div__", proxy_div),
        method("__truediv__", proxy_truediv),
        method("__floordiv__", proxy_floordiv),
        method("__mod__", proxy_mod),
        method("__neg__", proxy_neg),
        method("__pos__", proxy_pos),
        method("__invert__", proxy_invert),
    ];
    if callable {
        methods.push(method("__call__", proxy_call));
    }

    let class = new_final_type(vm, TypeSpec { name, module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: &methods })?;
    if let Some(data) = class.as_class() {
        vm.dict_set_str(&data.dict, "__hash__", Value::None)?;
    }

    Ok(class)
}

/// The referent behind a proxy receiver and the remaining arguments.
fn proxied(vm: &Vm, args: CallArgs, name: &str) -> PyResult<(Value, Vec<Value>)> {
    let reference = this::<WeakReference>(vm, &args, "weakproxy", name)?;
    let referent = live_referent(vm, reference)?;

    Ok((referent, args.positional[1..].to_vec()))
}

/// A dead proxy raises `ReferenceError`.
fn live_referent(vm: &Vm, reference: &WeakReference) -> PyResult<Value> {
    reference.object().ok_or_else(|| vm.raise(ExceptionKind::ReferenceError, "weakly-referenced object no longer exists"))
}

/// Unwraps a proxy operand.
fn unwrap(vm: &Vm, value: Value) -> PyResult<Value> {
    match native_data::<WeakReference>(&value) {
        Some(reference) if !is_reference(vm, &value) => live_referent(vm, reference),
        _ => Ok(value),
    }
}

fn single(vm: &Vm, rest: Vec<Value>, name: &str) -> PyResult<Value> {
    let Ok([value]) = <[Value; 1]>::try_from(rest) else {
        return Err(vm.type_error(&format!("{name} expected 1 argument")));
    };

    unwrap(vm, value)
}

fn proxy_getattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__getattribute__")?;
    let name = single(vm, rest, "__getattribute__")?;
    let Some(name) = vm.as_str_bytes(&name) else {
        return Err(vm.type_error("attribute name must be string"));
    };

    vm.getattr(&referent, &name)
}

fn proxy_setattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__setattr__")?;
    let [name, value] = <[Value; 2]>::try_from(rest).map_err(|_| vm.type_error("__setattr__ expected 2 arguments"))?;
    let Some(name) = vm.as_str_bytes(&name) else {
        return Err(vm.type_error("attribute name must be string"));
    };

    vm.setattr(&referent, &name, value)?;

    Ok(Value::None)
}

fn proxy_delattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__delattr__")?;
    let name = single(vm, rest, "__delattr__")?;
    let Some(name) = vm.as_str_bytes(&name) else {
        return Err(vm.type_error("attribute name must be string"));
    };

    vm.delattr(&referent, &name)?;

    Ok(Value::None)
}

/// `weakproxy.__repr__`.
fn proxy_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let proxy_address = vm.value_address(&args.positional[0]);
    let (referent, _) = proxied(vm, args, "__repr__")?;

    Ok(Value::str(&format!("<weakproxy at {} to {} at {}>", vm.c_pointer_text(proxy_address), vm.type_name(&referent), vm.c_pointer_text(vm.value_address(&referent)))))
}

fn proxy_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__str__")?;

    vm.to_str(&referent)
}

fn proxy_nonzero(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__nonzero__")?;
    if referent.is_unknown() {
        return Ok(referent);
    }

    Ok(Value::Bool(vm.truthy(&referent, "weakproxy")?))
}

fn proxy_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__len__")?;

    match vm.len(&referent)? {
        Some(length) => Ok(vm.new_int_from_i64(length as i64)),
        None => Ok(Value::unknown("len(weakproxy)")),
    }
}

fn proxy_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__getitem__")?;
    let key = single(vm, rest, "__getitem__")?;

    vm.getitem(&referent, &key)
}

fn proxy_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__setitem__")?;
    let [key, value] = <[Value; 2]>::try_from(rest).map_err(|_| vm.type_error("__setitem__ expected 2 arguments"))?;

    vm.setitem(&referent, &unwrap(vm, key)?, unwrap(vm, value)?)?;

    Ok(Value::None)
}

fn proxy_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__delitem__")?;
    let key = single(vm, rest, "__delitem__")?;

    vm.delitem(&referent, &key)?;

    Ok(Value::None)
}

fn proxy_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, "__contains__")?;
    let item = single(vm, rest, "__contains__")?;

    vm.contains(&referent, &item)
}

fn proxy_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__iter__")?;

    vm.iter(&referent)
}

/// `next` on a proxy: the referent must itself be an iterator.
fn proxy_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "next")?;
    if vm.lookup_special(&referent, "next")?.is_none() && !matches!(referent.as_object().map(|object| &object.payload), Some(Payload::Iterator(_) | Payload::Generator(_))) {
        return Err(vm.type_error(&format!("Weakref proxy referenced a non-iterator '{}' object", vm.type_name(&referent))));
    }

    crate::interp::builtins::modules::iterator_result(vm, vm.next(&referent)?)
}

fn proxy_compare(vm: &Vm, args: CallArgs, operation: CompareOp, name: &str) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, name)?;
    let other = single(vm, rest, name)?;

    vm.compare(&referent, &other, operation)
}

fn proxy_eq(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::Equal, "__eq__")
}

fn proxy_ne(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::NotEqual, "__ne__")
}

fn proxy_lt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::Less, "__lt__")
}

fn proxy_le(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::LessEqual, "__le__")
}

fn proxy_gt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::Greater, "__gt__")
}

fn proxy_ge(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_compare(vm, args, CompareOp::GreaterEqual, "__ge__")
}

fn proxy_binary(vm: &Vm, args: CallArgs, operation: BinaryOp, name: &str) -> PyResult<Value> {
    let (referent, rest) = proxied(vm, args, name)?;
    let other = single(vm, rest, name)?;

    vm.binary_op(operation, &referent, &other)
}

fn proxy_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::Add, "__add__")
}

fn proxy_sub(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::Subtract, "__sub__")
}

fn proxy_mul(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::Multiply, "__mul__")
}

fn proxy_div(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::Divide, "__div__")
}

fn proxy_truediv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::TrueDivide, "__truediv__")
}

fn proxy_floordiv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::FloorDivide, "__floordiv__")
}

fn proxy_mod(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    proxy_binary(vm, args, BinaryOp::Modulo, "__mod__")
}

fn proxy_neg(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__neg__")?;

    vm.negative(&referent)
}

fn proxy_pos(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__pos__")?;

    vm.positive(&referent)
}

fn proxy_invert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (referent, _) = proxied(vm, args, "__invert__")?;

    vm.invert(&referent)
}

fn proxy_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reference = this::<WeakReference>(vm, &args, "weakcallableproxy", "__call__")?;
    let referent = live_referent(vm, reference)?;

    vm.call(&referent, CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords, keyword_dict: args.keyword_dict })
}
