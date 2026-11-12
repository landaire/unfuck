//! `exceptions`: the builtin exception classes.

use std::rc::Rc;

use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    for kind in ExceptionKind::ALL {
        let class = Rc::clone(vm.types().exception(*kind));
        set_attribute(vm, module, kind.name(), Value::Object(class))?;
    }

    Ok(())
}
