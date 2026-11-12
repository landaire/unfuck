//! The attributes `type` gives every class: `__name__`, `__module__`,
//! `__bases__`, `__mro__`, and `__doc__`, and the module part of builtin
//! type names.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::ClassData;
use crate::interp::object::ClassStyle;
use crate::interp::type_flags;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The module part of the dotted name of builtin types whose name has one.
/// Builtin types live as long as the interpreter, so their addresses stay
/// unique.
#[derive(Default)]
struct StaticModules {
    modules: RefCell<HashMap<usize, &'static str>>,
}

impl Vm {
    /// Records the module of a builtin type's dotted name.
    pub fn set_static_module(&self, class: &ObjectRef, module: &'static str) {
        self.native_state::<StaticModules>().modules.borrow_mut().insert(Rc::as_ptr(class) as usize, module);
    }

    /// The module of a builtin type's dotted name, if it has one.
    pub fn static_module(&self, class: &ObjectRef) -> Option<&'static str> {
        self.native_state::<StaticModules>().modules.borrow().get(&(Rc::as_ptr(class) as usize)).copied()
    }

    /// A heap type's `__module__` entry; for builtin types the dotted name's
    /// prefix, or `__builtin__` without one.
    pub fn type_module(&self, class: &ObjectRef, data: &ClassData) -> PyResult<Value> {
        if !data.builtin || self.is_extension_type(class) {
            return match self.dict_get_str(&data.dict, "__module__")? {
                Some(module) => Ok(module),
                None if data.builtin => Ok(Value::str(self.static_module(class).unwrap_or("__builtin__"))),
                None => Err(self.raise(ExceptionKind::AttributeError, "__module__")),
            };
        }

        Ok(Value::str(self.static_module(class).unwrap_or("__builtin__")))
    }

    /// The type's own `__doc__` entry, through its `__get__` when it has one;
    /// None without an entry.
    pub fn type_doc(&self, class: &ObjectRef, data: &ClassData) -> PyResult<Value> {
        let Some(doc) = self.dict_get_str(&data.dict, "__doc__")? else {
            return Ok(Value::None);
        };

        self.descriptor_get(&doc, None, class)
    }
}

/// Adds the `type` getsets and members.
pub fn install_type_attributes(vm: &Vm) -> PyResult<()> {
    let types = vm.types();
    let class = Rc::clone(&types.type_);
    let owner = "type";

    add_getset(vm, &class, GetSet { name: "__name__", owner, get: type_get, set: Some(type_set) })?;
    add_getset(vm, &class, GetSet { name: "__module__", owner, get: type_get, set: Some(module_set) })?;
    add_getset(vm, &class, GetSet { name: "__bases__", owner, get: type_get, set: Some(type_set) })?;
    add_getset(vm, &class, GetSet { name: "__abstractmethods__", owner, get: abstract_methods_get, set: Some(abstract_methods_set) })?;
    add_getset(vm, &class, GetSet { name: "__doc__", owner, get: type_get, set: None })?;
    add_member(vm, &class, GetSet { name: "__flags__", owner, get: type_get, set: None })?;
    add_member(vm, &class, GetSet { name: "__mro__", owner, get: type_get, set: None })?;

    Ok(())
}

/// The class a `type` descriptor applies to.
fn class_of<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a ObjectRef> {
    match instance {
        Value::Object(object) if object.as_class().is_some_and(|data| data.style == ClassStyle::NewStyle) => Ok(object),
        _ => Err(descriptor_mismatch(vm, getset, instance)),
    }
}

/// Reads the attribute through the type's attribute lookup, which answers
/// these names before consulting any descriptor.
fn type_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let class = class_of(vm, getset, instance)?;
    let Some(data) = class.as_class() else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    match getset.name {
        "__module__" => vm.type_module(class, data),
        "__doc__" => vm.type_doc(class, data),
        "__flags__" => Ok(vm.type_flags_value(data)),
        name => vm.getattr(instance, &PyBytes::from(name)),
    }
}

/// Static types are fixed, and these attributes cannot be deleted.
fn check_special<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value, value: Option<Value>) -> PyResult<(&'a ObjectRef, Value)> {
    let class = class_of(vm, getset, instance)?;
    if class.as_class().is_some_and(|data| data.builtin) {
        return Err(vm.type_error(&format!("can't set {}.{}", vm.class_name(class), getset.name)));
    }
    let Some(value) = value else {
        return Err(vm.type_error(&format!("can't delete {}.{}", vm.class_name(class), getset.name)));
    };

    Ok((class, value))
}

/// `__name__` and `__bases__`, which type attribute assignment handles
/// itself.
fn type_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let (_, value) = check_special(vm, getset, instance, value)?;

    vm.setattr(instance, &PyBytes::from(getset.name), value)
}

/// Assigns `__module__`.
fn module_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let (class, value) = check_special(vm, getset, instance, value)?;
    let Some(data) = class.as_class() else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    vm.dict_set_str(&data.dict, "__module__", value)
}

/// Only the class's own dict holds the value, and `type` keeps this
/// descriptor there instead.
fn abstract_methods_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let class = class_of(vm, getset, instance)?;
    let Some(data) = class.as_class() else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    let value = if Rc::ptr_eq(class, &vm.types().type_) { None } else { vm.dict_get_str(&data.dict, "__abstractmethods__")? };
    value.ok_or_else(|| vm.raise(ExceptionKind::AttributeError, "__abstractmethods__"))
}

/// The class becomes abstract according to the truth of the stored value.
fn abstract_methods_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let class = class_of(vm, getset, instance)?;
    let Some(data) = class.as_class() else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    let abstract_methods = match value {
        Some(value) => {
            let abstract_methods = vm.truthy(&value, "__abstractmethods__")?;
            vm.dict_set_str(&data.dict, "__abstractmethods__", value)?;
            abstract_methods
        }
        None => {
            if !vm.dict_delete(&data.dict, &Value::str("__abstractmethods__"))? {
                return Err(vm.raise(ExceptionKind::AttributeError, "__abstractmethods__"));
            }
            false
        }
    };
    type_flags::set_abstract(class, abstract_methods);

    Ok(())
}
