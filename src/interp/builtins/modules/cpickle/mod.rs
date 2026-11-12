//! `cPickle`: serializes object graphs to the pickle format of protocols 0
//! through 2 and reads them back.

mod load;
mod opcodes;
mod pickler;
mod save;
mod unpickler;

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::descriptors::new_class_entry;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFn;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The highest protocol this module writes and reads.
const HIGHEST_PROTOCOL: i64 = 2;

/// Why pickling or unpickling stopped short.
pub(super) enum Stop {
    Signal(Signal),
    /// The result depends on a value the interpreter does not know.
    Unknown { origin: String },
}

impl From<Signal> for Stop {
    fn from(signal: Signal) -> Self {
        Self::Signal(signal)
    }
}

/// The exception classes and `copy_reg` tables a module instance shares
/// between its picklers and unpicklers.
pub(super) struct ModuleState {
    pickle_error: ObjectRef,
    pickling_error: ObjectRef,
    unpickleable_error: ObjectRef,
    unpickling_error: ObjectRef,
    bad_pickle_get: ObjectRef,

    /// `copy_reg.dispatch_table`: reducers by type.
    dispatch_table: ObjectRef,
    /// `copy_reg._extension_registry`: `(module, name)` to code.
    extension_registry: ObjectRef,
    /// `copy_reg._inverted_registry`: code to `(module, name)`.
    inverted_registry: ObjectRef,
    /// `copy_reg._extension_cache`: code to the loaded object.
    extension_cache: ObjectRef,
}

/// Where `init` leaves the state of this interpreter's module.
#[derive(Default)]
struct StateCell {
    state: RefCell<Option<Rc<ModuleState>>>,
}

/// The state of the initialized module.
fn module_state(vm: &Vm) -> PyResult<Rc<ModuleState>> {
    let cell = vm.native_state::<StateCell>();
    let state = cell.state.borrow().as_ref().map(Rc::clone);

    state.ok_or_else(|| vm.raise(ExceptionKind::SystemError, "cPickle module state is missing"))
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const FUNCTIONS: &[MethodSpec] = &[
        function("dump", pickler::module_dump),
        function("dumps", pickler::module_dumps),
        function("load", unpickler::module_load),
        function("loads", unpickler::module_loads),
        function("Pickler", pickler::new_pickler),
        function("Unpickler", unpickler::new_unpickler),
    ];

    install_functions(vm, module, FUNCTIONS)?;

    let state = create_state(vm)?;
    let exports = [
        ("PickleError", &state.pickle_error),
        ("PicklingError", &state.pickling_error),
        ("UnpickleableError", &state.unpickleable_error),
        ("UnpicklingError", &state.unpickling_error),
        ("BadPickleGet", &state.bad_pickle_get),
    ];
    for (name, class) in exports {
        set_attribute(vm, module, name, Value::Object(Rc::clone(class)))?;
    }
    *vm.native_state::<StateCell>().state.borrow_mut() = Some(Rc::new(state));

    let formats = ["1.0", "1.1", "1.2", "1.3", "2.0"].into_iter().map(Value::str).collect();
    set_attribute(vm, module, "__builtins__", Value::Object(Rc::clone(vm.builtin_module())))?;
    set_attribute(vm, module, "__version__", Value::str("1.71"))?;
    set_attribute(vm, module, "format_version", Value::str("2.0"))?;
    set_attribute(vm, module, "compatible_formats", vm.new_list(formats))?;
    set_attribute(vm, module, "HIGHEST_PROTOCOL", Value::Int(HIGHEST_PROTOCOL))
}

/// Imports `copy_reg` for its tables and creates the exception classes.
fn create_state(vm: &Vm) -> PyResult<ModuleState> {
    let copy_reg = vm.import_module("copy_reg")?;
    let table = |name: &str| -> PyResult<ObjectRef> {
        let value = vm.getattr_str(&copy_reg, name)?;
        match value {
            Value::Object(object) if object.as_dict().is_some() => Ok(object),
            _ => Err(vm.type_error(&format!("copy_reg.{name} is not a dict"))),
        }
    };
    let dispatch_table = table("dispatch_table")?;
    let extension_registry = table("_extension_registry")?;
    let inverted_registry = table("_inverted_registry")?;
    let extension_cache = table("_extension_cache")?;

    let exception = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let pickle_error = new_exception_class(vm, "cPickle", "PickleError", &exception)?;
    install_str(vm, &pickle_error, pickle_error_str)?;
    let pickling_error = new_exception_class(vm, "cPickle", "PicklingError", &pickle_error)?;
    let unpickleable_error = new_exception_class(vm, "cPickle", "UnpickleableError", &pickling_error)?;
    install_str(vm, &unpickleable_error, unpickleable_error_str)?;
    let unpickling_error = new_exception_class(vm, "cPickle", "UnpicklingError", &pickle_error)?;
    let bad_pickle_get = new_exception_class(vm, "cPickle", "BadPickleGet", &unpickling_error)?;

    Ok(ModuleState { pickle_error, pickling_error, unpickleable_error, unpickling_error, bad_pickle_get, dispatch_table, extension_registry, inverted_registry, extension_cache })
}

/// Defines `__str__` in the dict of an exception class.
fn install_str(vm: &Vm, class: &ObjectRef, function: NativeFn) -> PyResult<()> {
    let entry = new_class_entry(vm, class, "__str__", function, NativeBinding::Method);

    vm.setattr_str(&Value::Object(Rc::clone(class)), "__str__", entry)
}

/// The `args` of the exception a `__str__` call receives.
fn exception_args(vm: &Vm, args: &CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("__str__() takes no keyword arguments"));
    }
    let [receiver] = args.positional.as_slice() else {
        let given = args.positional.len();
        return Err(vm.type_error(&format!("__str__() takes exactly 1 argument ({given} given)")));
    };

    vm.getattr_str(receiver, "args")
}

/// `'%s' % args[0]` when that text is not empty, else `(what)`.
fn pickle_error_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = exception_args(vm, &args)?;
    if !vm.truthy(&arguments, "PickleError args")? {
        return Ok(Value::str("(what)"));
    }

    let first = vm.getitem(&arguments, &Value::Int(0))?;
    let text = vm.format_percent(&Value::str("%s"), &first)?;
    if vm.truthy(&text, "PickleError text")? {
        return Ok(text);
    }

    Ok(Value::str("(what)"))
}

/// `Cannot pickle <type of args[0]> objects`, with `(what)` when there are
/// no arguments.
fn unpickleable_error_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = exception_args(vm, &args)?;
    let subject = if vm.truthy(&arguments, "UnpickleableError args")? {
        let first = vm.getitem(&arguments, &Value::Int(0))?;
        Value::tuple(vec![vm.type_value(&first)])
    } else {
        Value::str("(what)")
    };

    vm.format_percent(&Value::str("Cannot pickle %s objects"), &subject)
}
