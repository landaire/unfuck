//! `_collections`.

use crate::interp::builtins::collections::defaultdict_type;
use crate::interp::builtins::collections::deque_type;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "deque", Value::Object(deque_type(vm)?))?;
    set_attribute(vm, module, "defaultdict", Value::Object(defaultdict_type(vm)?))
}
