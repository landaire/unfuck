//! The per-interpreter codec registry: search functions, the lookup cache,
//! and the error handler registry.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::interp::builtins::modules::codecs::errors::Builtin;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Default)]
struct Registry {
    initialized: Cell<bool>,
    search_path: RefCell<Vec<Value>>,
    /// Lookup results by normalized encoding name.
    cache: RefCell<HashMap<Vec<u8>, Value>>,
    error_handlers: RefCell<HashMap<Vec<u8>, Value>>,
    /// The builtin handler functions, to recognize them in the registry.
    builtins: RefCell<Vec<(Builtin, Value)>>,
}

/// Registers the builtin error handlers and imports `encodings`, which
/// registers its search function. A missing `encodings` package is
/// ignored, as in CPython.
fn registry(vm: &Vm) -> PyResult<Rc<Registry>> {
    let registry = vm.native_state::<Registry>();
    if registry.initialized.get() {
        return Ok(registry);
    }
    registry.initialized.set(true);

    for builtin in Builtin::ALL {
        let function = vm.new_native_function(builtin.function_name(), builtin.function());
        registry.error_handlers.borrow_mut().insert(builtin.name().as_bytes().to_vec(), function.clone());
        registry.builtins.borrow_mut().push((builtin, function));
    }

    match vm.import_module("encodings") {
        Ok(_) => Ok(registry),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::ImportError) => Ok(registry),
        Err(signal) => Err(signal),
    }
}

/// Whether a value is callable.
pub fn is_callable(vm: &Vm, value: &Value) -> PyResult<bool> {
    match value {
        Value::Unknown(_) => Ok(true),
        Value::Object(object) => match &object.payload {
            Payload::Function(_) | Payload::NativeFunction(_) | Payload::Method(_) | Payload::Class(_) => Ok(true),
            _ => Ok(vm.lookup_special(value, "__call__")?.is_some()),
        },
        _ => Ok(false),
    }
}

/// Registers a codec search function.
pub fn register(vm: &Vm, function: Value) -> PyResult<()> {
    let registry = registry(vm)?;
    if !is_callable(vm, &function)? {
        return Err(vm.type_error("argument must be callable"));
    }

    registry.search_path.borrow_mut().push(function);

    Ok(())
}

/// Encoding name normalization: lowercase, with spaces turned into hyphens.
fn normalize(encoding: &[u8]) -> Vec<u8> {
    encoding.iter().map(|&byte| if byte == b' ' { b'-' } else { byte.to_ascii_lowercase() }).collect()
}

/// Codec lookup: the cached result, else the first search function
/// result that is not `None`.
pub fn lookup(vm: &Vm, encoding: &[u8]) -> PyResult<Value> {
    let registry = registry(vm)?;
    let normalized = normalize(encoding);

    if let Some(result) = registry.cache.borrow().get(&normalized) {
        return Ok(result.clone());
    }

    let search_path = registry.search_path.borrow().clone();
    if search_path.is_empty() {
        return Err(vm.raise(ExceptionKind::LookupError, "no codec search functions registered: can't find encoding"));
    }

    for function in &search_path {
        let result = vm.call(function, CallArgs::new(vec![Value::Str(PyBytes::new(normalized.clone()))]))?;
        if result.is_unknown() {
            return Ok(result);
        }
        if result.is_none() {
            continue;
        }
        if vm.as_tuple(&result).is_none_or(|items| items.len() != 4) {
            return Err(vm.type_error("codec search functions must return 4-tuples"));
        }

        registry.cache.borrow_mut().insert(normalized, result.clone());
        return Ok(result);
    }

    Err(lookup_failure(vm, [b"unknown encoding: ".as_slice(), encoding].concat()))
}

/// Registers an error handler by name.
pub fn register_error(vm: &Vm, name: &[u8], handler: Value) -> PyResult<()> {
    let registry = registry(vm)?;
    if !is_callable(vm, &handler)? {
        return Err(vm.type_error("handler must be callable"));
    }

    registry.error_handlers.borrow_mut().insert(name.to_vec(), handler);

    Ok(())
}

/// Looks up an error handler by name.
pub fn lookup_error(vm: &Vm, name: &[u8]) -> PyResult<Value> {
    let registry = registry(vm)?;

    if let Some(handler) = registry.error_handlers.borrow().get(name) {
        return Ok(handler.clone());
    }

    let name = name.get(..400).unwrap_or(name);

    Err(lookup_failure(vm, [b"unknown error handler name '".as_slice(), name, b"'"].concat()))
}

/// A `LookupError` whose message holds raw bytes, as `%s` formatting
/// produces.
fn lookup_failure(vm: &Vm, message: Vec<u8>) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::LookupError));

    vm.raise_string(&class, Value::Str(PyBytes::new(message)))
}

/// The builtin handler `handler` is, when it is one.
pub fn builtin_handler(vm: &Vm, handler: &Value) -> Option<Builtin> {
    let registry = vm.native_state::<Registry>();
    let builtins = registry.builtins.borrow();

    builtins.iter().find(|(_, function)| vm.is_same(function, handler)).map(|(builtin, _)| *builtin)
}
