//! `zipimport`. Whether a path names an archive
//! depends on the file system, so constructing a `zipimporter` checks its
//! argument as CPython does and then yields an unknown value. No instance
//! is ever built, so every method rejects its receiver.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::io::allocation_class;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `MAXPATHLEN` of the Windows build.
const MAX_PATH_LENGTH: usize = 260;

#[derive(Default)]
struct ZipState {
    error: RefCell<Option<ObjectRef>>,
}

/// A method of `zipimporter` that rejects its receiver.
macro_rules! importer_methods {
    ($($name:literal),* $(,)?) => {
        [static_method("__new__", zipimporter_new), $(method($name, |vm, args| importer_method(vm, &args, $name))),*]
    };
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let error = new_exception_class(vm, "zipimport", "ZipImportError", vm.types().exception(ExceptionKind::ImportError))?;
    *vm.native_state::<ZipState>().error.borrow_mut() = Some(Rc::clone(&error));
    set_attribute(vm, module, "ZipImportError", Value::Object(error))?;

    set_attribute(vm, module, "zipimporter", Value::Object(zipimporter_type(vm)?))?;

    set_attribute(vm, module, "_zip_directory_cache", Value::Object(vm.new_dict()))
}

fn zipimporter_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "zipimport.zipimporter", create_zipimporter_type)
}

fn create_zipimporter_type(vm: &Vm) -> PyResult<ObjectRef> {
    let methods = importer_methods!("__init__", "__repr__", "find_module", "load_module", "get_data", "get_code", "get_source", "get_filename", "is_package");
    let class = new_type(vm, TypeSpec { name: "zipimporter", module: "zipimport", base: None, layout: Layout::Native, instance_dict: false, methods: &methods })?;

    for name in ["archive", "prefix", "_files"] {
        add_member(vm, &class, GetSet { name, owner: "zipimport.zipimporter", get: member_get, set: None })?;
    }

    Ok(class)
}

/// `ZipImportError(message)`.
fn zip_import_error(vm: &Vm, message: &str) -> Signal {
    let class = vm.native_state::<ZipState>().error.borrow().clone();
    let Some(class) = class else {
        return vm.raise(ExceptionKind::ImportError, message);
    };

    vm.raise_string(&class, Value::str(message))
}

/// Construction: the checks of `zipimporter.__init__` before it searches the
/// path for an archive.
fn zipimporter_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    allocation_class(vm, &args, &zipimporter_type(vm)?)?;
    if args.has_keywords() {
        return Err(vm.type_error("zipimporter() does not take keyword arguments"));
    }
    let given = args.positional.len() - 1;
    if given != 1 {
        return Err(vm.type_error(&format!("zipimporter() takes exactly 1 argument ({given} given)")));
    }

    let path = &args.positional[1];
    if path.is_unknown() {
        return Ok(path.clone());
    }
    let path = c_string(vm, "zipimporter", 1, path)?;
    if path.as_bytes().is_empty() {
        return Err(zip_import_error(vm, "archive path is empty"));
    }
    if path.as_bytes().len() >= MAX_PATH_LENGTH {
        return Err(zip_import_error(vm, "archive path too long"));
    }

    vm.host_operation_on(HostCapability::FileSystem, "zipimport.zipimporter", Denial::Native, Some(&args.positional[1]))
}

/// A method called on a value that is not a `zipimporter`.
fn importer_method(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{name}' of 'zipimport.zipimporter' object needs an argument")));
    };

    Err(vm.type_error(&format!("descriptor '{name}' requires a 'zipimport.zipimporter' object but received a '{}'", vm.type_name(receiver))))
}

fn member_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}
