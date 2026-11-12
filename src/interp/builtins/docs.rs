//! `__doc__` entries of native modules and builtin classes. Native objects
//! carry no docstrings, so every entry is None.

use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Gives a native module its `__doc__` entry. Its init function may replace
/// it.
pub fn document_module(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let dict = vm.instance_dict(module)?;

    vm.dict_set_str(&dict, "__doc__", Value::None)
}

/// Gives a builtin class a `__doc__` entry when its dict has none.
pub fn document_class(vm: &Vm, class: &ObjectRef) -> PyResult<()> {
    let Some(data) = class.as_class() else {
        return Ok(());
    };
    if vm.dict_get_str(&data.dict, "__doc__")?.is_some() {
        return Ok(());
    }

    vm.dict_set_str(&data.dict, "__doc__", Value::None)
}

/// Documents every builtin class that bootstrap created: `object` and its
/// subclasses.
pub fn document_builtin_classes(vm: &Vm) -> PyResult<()> {
    let mut pending = vec![Rc::clone(&vm.types().object)];

    while let Some(class) = pending.pop() {
        let Some(data) = class.as_class() else {
            continue;
        };
        if !data.builtin {
            continue;
        }

        document_class(vm, &class)?;
        pending.extend(data.subclasses.borrow().iter().filter_map(std::rc::Weak::upgrade));
    }

    Ok(())
}
