//! The types of native callables: `method_descriptor`,
//! `classmethod_descriptor`, `wrapper_descriptor` (slot wrappers),
//! `method-wrapper` (bound slot wrappers), and
//! `builtin_function_or_method`. They share the `NativeFunction` payload;
//! the class tells them apart.

use std::rc::Rc;

use crate::interp::builtins::positional;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFn;
use crate::interp::object::NativeFunction;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The kind of a native callable, from its class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallableKind {
    MethodDescriptor,
    ClassMethodDescriptor,
    WrapperDescriptor,
    MethodWrapper,
    BuiltinFunction,
}

/// Names whose native methods are slot wrappers in a builtin type's dict,
/// sorted. Observed as the `wrapper_descriptor` entries of the reference
/// interpreter's types.
const SLOT_NAMES: &[&str] = &[
    "__abs__",
    "__add__",
    "__and__",
    "__call__",
    "__cmp__",
    "__coerce__",
    "__contains__",
    "__delattr__",
    "__delete__",
    "__delitem__",
    "__delslice__",
    "__div__",
    "__divmod__",
    "__eq__",
    "__float__",
    "__floordiv__",
    "__ge__",
    "__get__",
    "__getattribute__",
    "__getitem__",
    "__getslice__",
    "__gt__",
    "__hash__",
    "__hex__",
    "__iadd__",
    "__iand__",
    "__idiv__",
    "__ifloordiv__",
    "__ilshift__",
    "__imod__",
    "__imul__",
    "__index__",
    "__init__",
    "__int__",
    "__invert__",
    "__ior__",
    "__ipow__",
    "__irshift__",
    "__isub__",
    "__iter__",
    "__itruediv__",
    "__ixor__",
    "__le__",
    "__len__",
    "__long__",
    "__lshift__",
    "__lt__",
    "__mod__",
    "__mul__",
    "__ne__",
    "__neg__",
    "__nonzero__",
    "__oct__",
    "__or__",
    "__pos__",
    "__pow__",
    "__radd__",
    "__rand__",
    "__rdiv__",
    "__rdivmod__",
    "__repr__",
    "__rfloordiv__",
    "__rlshift__",
    "__rmod__",
    "__rmul__",
    "__ror__",
    "__rpow__",
    "__rrshift__",
    "__rshift__",
    "__rsub__",
    "__rtruediv__",
    "__rxor__",
    "__set__",
    "__setattr__",
    "__setitem__",
    "__setslice__",
    "__str__",
    "__sub__",
    "__truediv__",
    "__xor__",
    "next",
];

/// Builtin types that define a slot name as an ordinary method, which the
/// type dict then holds as a method descriptor.
const SLOT_METHOD_OVERRIDES: &[(&str, &str)] = &[("dict", "__contains__"), ("dict", "__getitem__"), ("frozenset", "__contains__"), ("list", "__getitem__"), ("set", "__contains__")];

fn is_slot_wrapper(vm: &Vm, class: &ObjectRef, name: &str) -> bool {
    if SLOT_NAMES.binary_search(&name).is_err() {
        return false;
    }
    if !class.as_class().is_some_and(|data| data.builtin) {
        return true;
    }
    let type_name = vm.qualified_class_name(class);

    !SLOT_METHOD_OVERRIDES.iter().any(|&(owner, method)| owner == type_name.as_str() && method == name)
}

/// Allocates the descriptor that type setup stores in the dict of `class`
/// for a native method: a slot wrapper for a name filled from a slot, a
/// method descriptor otherwise.
pub fn new_class_entry(vm: &Vm, class: &ObjectRef, name: &'static str, function: NativeFn, binding: NativeBinding) -> Value {
    let types = vm.types();
    let descriptor_class = match binding {
        NativeBinding::Function | NativeBinding::StaticMethod => &types.builtin_function,
        NativeBinding::ClassMethod => &types.classmethod_descriptor,
        NativeBinding::Method if is_slot_wrapper(vm, class, name) => &types.wrapper_descriptor,
        NativeBinding::Method => &types.method_descriptor,
    };
    let payload = Payload::NativeFunction(NativeFunction { name, function, binding, receiver: None, owner: Some(Rc::clone(class)) });

    Value::Object(vm.alloc(descriptor_class, payload, None))
}

/// The class of `descriptor` bound to a receiver: `method-wrapper` for a
/// slot wrapper, `builtin_function_or_method` otherwise.
pub fn bound_class(vm: &Vm, descriptor: &ObjectRef) -> ObjectRef {
    let types = vm.types();
    let class = if kind_of(vm, descriptor) == CallableKind::WrapperDescriptor { &types.method_wrapper } else { &types.builtin_function };

    Rc::clone(class)
}

fn kind_of(vm: &Vm, object: &ObjectRef) -> CallableKind {
    let types = vm.types();
    let class = object.class();

    if Rc::ptr_eq(&class, &types.method_descriptor) {
        CallableKind::MethodDescriptor
    } else if Rc::ptr_eq(&class, &types.classmethod_descriptor) {
        CallableKind::ClassMethodDescriptor
    } else if Rc::ptr_eq(&class, &types.wrapper_descriptor) {
        CallableKind::WrapperDescriptor
    } else if Rc::ptr_eq(&class, &types.method_wrapper) {
        CallableKind::MethodWrapper
    } else {
        CallableKind::BuiltinFunction
    }
}

/// `__self__` of a `builtin_function_or_method`: the receiver it is bound
/// to, the type for `__new__`, and NULL for a module function.
fn function_self(native: &NativeFunction) -> Option<Value> {
    if let Some(receiver) = &native.receiver {
        return Some(receiver.clone());
    }
    if native.binding != NativeBinding::StaticMethod {
        return None;
    }

    native.owner.as_ref().filter(|owner| owner.as_class().is_some()).map(|owner| Value::Object(Rc::clone(owner)))
}

/// Attributes of native callables: descriptors, slot wrappers, and
/// builtin functions.
pub fn native_attribute(vm: &Vm, object: &ObjectRef, native: &NativeFunction, name: &str) -> Option<Value> {
    let kind = kind_of(vm, object);
    let objclass = || native.owner.as_ref().map(|owner| Value::Object(Rc::clone(owner))).unwrap_or(Value::None);

    match (kind, name) {
        // A descriptor's name is interned; a builtin function or a
        // method-wrapper builds a fresh string for its name.
        (CallableKind::MethodDescriptor | CallableKind::ClassMethodDescriptor | CallableKind::WrapperDescriptor, "__name__") => Some(Value::Str(vm.intern(&PyBytes::from(native.name)))),
        (_, "__name__") => Some(Value::str(native.name)),
        (_, "__doc__") => Some(Value::None),
        (CallableKind::BuiltinFunction, "__self__") => Some(function_self(native).unwrap_or(Value::None)),
        (CallableKind::BuiltinFunction, "__module__") => {
            let module = native.owner.as_ref().and_then(|owner| owner.as_module()).filter(|_| native.receiver.is_none());
            Some(module.map(|module| Value::Str(module.name.clone())).unwrap_or(Value::None))
        }
        (CallableKind::MethodWrapper, "__self__") => Some(native.receiver.clone().unwrap_or(Value::None)),
        (CallableKind::BuiltinFunction, _) => None,
        (_, "__objclass__") => Some(objclass()),
        _ => None,
    }
}

/// `repr` of a native callable, which shows a function bound to anything
/// but a module as a method of its receiver.
pub fn callable_repr(vm: &Vm, object: &ObjectRef, native: &NativeFunction) -> String {
    let owner = || native.owner.as_ref().map(|owner| vm.qualified_class_name(owner)).unwrap_or_default();
    let name = native.name;
    let receiver_text = |receiver: &Value| format!("{} object at {}", vm.qualified_class_name(&vm.type_of(receiver)), vm.pointer_text(vm.value_address(receiver)));

    match kind_of(vm, object) {
        CallableKind::MethodDescriptor | CallableKind::ClassMethodDescriptor => format!("<method '{name}' of '{}' objects>", owner()),
        CallableKind::WrapperDescriptor => format!("<slot wrapper '{name}' of '{}' objects>", owner()),
        CallableKind::MethodWrapper => format!("<method-wrapper '{name}' of {}>", receiver_text(&native.receiver.clone().unwrap_or(Value::None))),
        CallableKind::BuiltinFunction => match function_self(native) {
            Some(receiver) if !receiver.as_object().is_some_and(|receiver| receiver.as_module().is_some()) => format!("<built-in method {name} of {}>", receiver_text(&receiver)),
            _ => format!("<built-in function {name}>"),
        },
    }
}

/// `__get__` of a native callable stored in a class dict: method and slot
/// wrapper descriptors bind an instance of the owning type, class method
/// descriptors bind a subtype of it.
pub fn native_descriptor_get(vm: &Vm, object: &ObjectRef, native: &NativeFunction, instance: Option<Value>, class: Option<Value>) -> PyResult<Value> {
    let descriptor = Value::Object(Rc::clone(object));
    let Some(owner) = &native.owner else {
        return Ok(descriptor);
    };

    match native.binding {
        NativeBinding::Function | NativeBinding::StaticMethod => Ok(descriptor),
        NativeBinding::Method => {
            let Some(receiver) = instance.filter(|_| native.receiver.is_none()) else {
                return Ok(descriptor);
            };
            if !receiver.is_unknown() && !vm.is_subclass(&vm.type_of(&receiver), owner)? {
                let message = format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", native.name, vm.qualified_class_name(owner), vm.qualified_class_name(&vm.type_of(&receiver)));
                return Err(vm.type_error(&message));
            }

            Ok(vm.bind_native(object, receiver))
        }
        NativeBinding::ClassMethod => {
            let class = match (class, instance) {
                (Some(class), _) => class,
                (None, Some(receiver)) => Value::Object(vm.type_of(&receiver)),
                (None, None) => return Err(vm.type_error(&format!("descriptor '{}' for type '{}' needs either an object or a type", native.name, vm.qualified_class_name(owner)))),
            };
            let Some(class_object) = class.as_object().filter(|class| class.as_class().is_some()) else {
                if class.is_unknown() {
                    return Ok(class);
                }
                return Err(vm.type_error(&format!("descriptor '{}' for type '{}' needs a type, not a '{}' as arg 2", native.name, vm.qualified_class_name(owner), vm.type_name(&class))));
            };
            if !vm.is_subclass(class_object, owner)? {
                return Err(vm.type_error(&format!("descriptor '{}' for type '{}' doesn't apply to type '{}'", native.name, vm.qualified_class_name(owner), vm.qualified_class_name(class_object))));
            }

            Ok(vm.bind_native(object, class))
        }
    }
}

/// `__get__` of `method_descriptor`, `classmethod_descriptor`, and
/// `wrapper_descriptor`.
pub fn descriptor_get_slot(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__get__", 2, 3)?;
    let instance = Some(args[1].clone()).filter(|value| !value.is_none());
    let class = args.get(2).cloned().filter(|value| !value.is_none());
    if instance.is_none() && class.is_none() {
        return Err(vm.type_error("__get__(None, None) is invalid"));
    }

    let Some(object) = args[0].as_object() else {
        return Ok(args[0].clone());
    };
    let Payload::NativeFunction(native) = &object.payload else {
        return Ok(args[0].clone());
    };

    native_descriptor_get(vm, object, native, instance, class)
}
