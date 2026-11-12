//! Capsules: the opaque C API pointers that native modules export. Only
//! the name and identity are observable from Python.

use std::any::Any;

use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const CAPSULE_TYPE: &str = "PyCapsule";

/// A capsule; the pointer it wraps belongs to the emulated C module, which
/// may keep what it points at in `pointer`.
struct Capsule {
    name: &'static str,
    pointer: Option<Box<dyn Any>>,
}

impl_native_data!(Capsule, "PyCapsule");

/// A capsule named `name`.
pub fn new_capsule(vm: &Vm, name: &'static str) -> PyResult<Value> {
    let class = native_type(vm, CAPSULE_TYPE, create_capsule_type)?;

    Ok(new_native_object(vm, &class, Capsule { name, pointer: None }))
}

/// A capsule named `name` whose pointer the emulated module reads back
/// with `capsule_pointer`.
pub fn new_capsule_with(vm: &Vm, name: &'static str, pointer: impl Any) -> PyResult<Value> {
    let class = native_type(vm, CAPSULE_TYPE, create_capsule_type)?;

    Ok(new_native_object(vm, &class, Capsule { name, pointer: Some(Box::new(pointer)) }))
}

/// The pointer of a capsule named `name` when it holds a `T`.
pub fn capsule_pointer<'a, T: 'static>(value: &'a Value, name: &str) -> Option<&'a T> {
    native_data::<Capsule>(value).filter(|capsule| capsule.name == name).and_then(|capsule| capsule.pointer.as_ref()).and_then(|pointer| pointer.downcast_ref::<T>())
}

fn create_capsule_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name: "PyCapsule",
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("__repr__", capsule_repr)],
        },
    )
}

/// `PyCapsule.__repr__`, whose `%p` the Windows CRT prints as 16 uppercase digits.
fn capsule_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let name = this::<Capsule>(vm, &args, CAPSULE_TYPE, "__repr__")?.name;
    let mut rest = args.clone();
    let receiver = rest.positional.remove(0);
    wrapper_arguments(vm, rest, 0)?;

    let address = vm.value_address(&receiver);

    Ok(Value::str(&format!("<capsule object \"{name}\" at 0x{address:016X}>")))
}
