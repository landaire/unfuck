//! Builtin functions, methods of builtin types, and native modules.

pub mod arguments;
pub mod collections;
pub mod compile;
pub mod containers;
pub mod core;
pub mod descriptors;
pub mod docs;
pub mod exception_types;
pub mod exec;
pub mod functions;
pub mod iterators;
pub mod modules;
pub mod numeric;
pub mod source_codecs;
pub mod text;
pub mod type_attributes;
pub mod winerror_map;

use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFn;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A native method to install in a class dict.
pub struct MethodSpec {
    pub name: &'static str,
    pub function: NativeFn,
    pub binding: NativeBinding,
}

pub const fn method(name: &'static str, function: NativeFn) -> MethodSpec {
    MethodSpec { name, function, binding: NativeBinding::Method }
}

pub const fn class_method(name: &'static str, function: NativeFn) -> MethodSpec {
    MethodSpec { name, function, binding: NativeBinding::ClassMethod }
}

pub const fn static_method(name: &'static str, function: NativeFn) -> MethodSpec {
    MethodSpec { name, function, binding: NativeBinding::StaticMethod }
}

pub const fn function(name: &'static str, function: NativeFn) -> MethodSpec {
    MethodSpec { name, function, binding: NativeBinding::Function }
}

/// Stores native methods in a class dict.
pub fn install(vm: &Vm, class: &ObjectRef, methods: &[MethodSpec]) -> PyResult<()> {
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("install target is not a class"));
    };

    for spec in methods {
        let native = descriptors::new_class_entry(vm, class, spec.name, spec.function, spec.binding);
        vm.dict_set_str(&data.dict, spec.name, native)?;
    }

    Ok(())
}

/// Stores native functions in a module.
pub fn install_functions(vm: &Vm, module: &ObjectRef, functions: &[MethodSpec]) -> PyResult<()> {
    let dict = vm.instance_dict(module)?;

    // Each function is bound to the module that defines it.
    for spec in functions {
        let native = vm.new_native(spec.name, spec.function, NativeBinding::Function, Some(Rc::clone(module)));
        vm.dict_set_str(&dict, spec.name, native)?;
    }

    Ok(())
}

pub fn set_attribute(vm: &Vm, module: &ObjectRef, name: &str, value: Value) -> PyResult<()> {
    let dict = vm.instance_dict(module)?;

    vm.dict_set_str(&dict, name, value)
}

/// Binds call arguments to parameter names as keyword argument parsing
/// does. The result has one slot per name; `required` leading names must
/// be given. `function` is the format's name after `:`; an empty name
/// reports as `function`.
pub fn parse(vm: &Vm, args: CallArgs, function: &str, names: &[&str], required: usize) -> PyResult<Vec<Option<Value>>> {
    parse_with(vm, args, function, names, required, |_, _, value| Ok(value))
}

/// `parse` that converts each given argument with `convert(vm, index,
/// value)` as it is bound. As in `vgetargskeywords`, a conversion error
/// takes precedence over errors about later parameters and extraneous
/// keywords.
pub fn parse_with<T>(vm: &Vm, args: CallArgs, function: &str, names: &[&str], required: usize, mut convert: impl FnMut(&Vm, usize, Value) -> PyResult<T>) -> PyResult<Vec<Option<T>>> {
    let keyword_count = match &args.keyword_dict {
        Some(dict) => vm.dict_len(dict)?,
        None => args.keywords.len(),
    };
    let given = args.positional.len() + keyword_count;
    if given > names.len() {
        let shown = if function.is_empty() { "function".to_owned() } else { format!("{function}()") };
        let plural = if names.len() == 1 { "" } else { "s" };
        return Err(vm.type_error(&format!("{shown} takes at most {} argument{plural} ({given} given)", names.len())));
    }

    let mut slots = Vec::with_capacity(names.len());
    let mut remaining = keyword_count;
    for (index, name) in names.iter().enumerate() {
        let keyword = if remaining > 0 { args.keyword(name).cloned() } else { None };
        let value = match keyword {
            Some(value) => {
                remaining -= 1;
                if index < args.positional.len() {
                    return Err(vm.type_error(&format!("Argument given by name ('{name}') and position ({})", index + 1)));
                }
                Some(value)
            }
            None => args.positional.get(index).cloned(),
        };

        if let Some(value) = value {
            slots.push(Some(convert(vm, index, value)?));
            continue;
        }
        if index < required {
            return Err(vm.type_error(&format!("Required argument '{name}' (pos {}) not found", index + 1)));
        }
        // With no keyword left, the remaining optional names are absent.
        if remaining == 0 {
            slots.resize_with(names.len(), || None);
            return Ok(slots);
        }
        slots.push(None);
    }

    if remaining > 0 {
        extraneous_keyword(vm, &args, names)?;
    }

    Ok(slots)
}

/// The check for unexpected keywords in native argument parsing, over the keyword
/// dict in its iteration order.
fn extraneous_keyword(vm: &Vm, args: &CallArgs, names: &[&str]) -> PyResult<()> {
    let dict = match &args.keyword_dict {
        Some(dict) => Rc::clone(dict),
        None => {
            let dict = vm.new_dict();
            for (key, value) in &args.keywords {
                vm.dict_set(&dict, Value::Str(key.clone()), value.clone())?;
            }
            dict
        }
    };

    for (key, _) in vm.dict_items(&dict)? {
        let Some(key) = vm.as_str_bytes(&key) else {
            return Err(vm.type_error("keywords must be strings"));
        };
        if !names.iter().any(|name| name.as_bytes() == key.as_bytes()) {
            return Err(vm.type_error(&format!("'{}' is an invalid keyword argument for this function", key.to_string_lossy())));
        }
    }

    Ok(())
}

/// Positional-only arguments with an exact count range.
pub fn positional(vm: &Vm, args: CallArgs, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    if count < minimum || count > maximum {
        let (expected, shown) = if minimum == maximum { ("exactly", minimum) } else if count < minimum { ("at least", minimum) } else { ("at most", maximum) };
        return Err(vm.type_error(&format!("{function}() takes {expected} {shown} argument{} ({count} given)", if shown == 1 { "" } else { "s" })));
    }

    Ok(args.positional)
}

/// Splits off the receiver of a native method call.
pub fn receiver(vm: &Vm, mut args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("descriptor '{method}' needs an argument")));
    }

    let receiver = args.positional.remove(0);

    Ok((receiver, args))
}

pub fn create_builtin_module(vm: &Vm) -> PyResult<ObjectRef> {
    core::install_type_methods(vm)?;
    docs::document_builtin_classes(vm)?;

    let module = vm.new_module("__builtin__", crate::interp::object::ModuleKind::Native)?;
    docs::document_module(vm, &module)?;
    functions::populate(vm, &module)?;
    vm.dict_set_str(vm.modules(), "__builtin__", Value::Object(Rc::clone(&module)))?;

    Ok(module)
}

pub fn register_native_modules(vm: &Vm) {
    modules::register(vm);
}

/// Dispatches item access on interpreter-implemented native objects.
pub fn native_getitem(vm: &Vm, object: &ObjectRef, index: &Value) -> PyResult<Option<Value>> {
    let Payload::Native(_) = &object.payload else {
        return Ok(None);
    };

    match crate::interp::builtins::collections::deque_getitem(vm, object, index)? {
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

pub fn native_setitem(vm: &Vm, object: &ObjectRef, index: &Value, value: Option<Value>) -> PyResult<bool> {
    crate::interp::builtins::collections::deque_setitem(vm, object, index, value)
}

pub fn native_len(vm: &Vm, object: &ObjectRef) -> PyResult<Option<usize>> {
    if let Some(length) = crate::interp::builtins::collections::deque_len(vm, object)? {
        return Ok(Some(length));
    }

    crate::interp::builtins::containers::view_len(vm, object)
}

pub fn native_iter(vm: &Vm, object: &ObjectRef) -> PyResult<Option<Value>> {
    if let Some(iterator) = crate::interp::builtins::collections::deque_iter(vm, object)? {
        return Ok(Some(iterator));
    }
    if let Some(iterator) = modules::mmap::sequence_iter(vm, object) {
        return Ok(Some(iterator));
    }

    crate::interp::builtins::containers::view_iter(vm, object)
}

/// `in` for interpreter-implemented native objects; `None` falls back to
/// iteration.
pub fn native_contains(vm: &Vm, object: &ObjectRef, item: &Value) -> PyResult<Option<bool>> {
    crate::interp::builtins::containers::view_contains(vm, object, item)
}

/// `repr` of interpreter-implemented native objects; `None` falls back to
/// the default `<type object at address>` form.
pub fn native_repr(vm: &Vm, object: &ObjectRef) -> PyResult<Option<String>> {
    if let Some(text) = crate::interp::builtins::modules::descriptor_repr(vm, &Value::Object(Rc::clone(object))) {
        return Ok(Some(text));
    }

    crate::interp::builtins::containers::view_repr(vm, object)
}

/// Whether `class` implements `+` and `*` only through the sequence
/// concatenation and repetition slots, without numeric slots.
pub fn has_sequence_operators(vm: &Vm, class: &ObjectRef) -> bool {
    Rc::ptr_eq(class, &vm.types().bytearray) || Rc::ptr_eq(class, &vm.types().buffer) || modules::array::is_array_type(vm, class) || modules::mmap::is_mmap_type(vm, class)
}

/// Raises the exception for a wrong argument type.
pub fn wrong_type(vm: &Vm, function: &str, expected: &str, got: &Value) -> crate::interp::error::Signal {
    vm.raise(ExceptionKind::TypeError, &format!("{function}() argument must be {expected}, not {}", vm.type_name(got)))
}
