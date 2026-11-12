//! The `Unpickler` type, its input sources, and the `load` and `loads`
//! functions.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use super::ModuleState;
use super::Stop;
use super::load::LoadResult;
use super::load::Mode;
use super::module_state;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::cstringio::StringIo;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const UNPICKLER_TYPE: &str = "cPickle.Unpickler";

/// The methods `__methods__` lists.
const METHOD_NAMES: [&str; 2] = ["load", "noload"];

/// Where an unpickler reads from.
enum Input {
    /// `loads`: a string and the read position in it.
    Bytes { data: PyBytes, position: Cell<usize> },
    /// A `cStringIO` stream, read directly.
    Stream(Value),
    /// An object with `read` and `readline` methods.
    Reader { read: Value, readline: Value },
}

impl Input {
    /// The source for `file`; `None` when what it reads is unknown to the
    /// interpreter.
    fn for_file(vm: &Vm, file: &Value) -> PyResult<Option<Self>> {
        if file.is_unknown() {
            return Ok(None);
        }
        if vm.is_instance_of(file, &vm.types().file)? {
            vm.host_permit(HostCapability::FileSystem, Denial::Crt, None)?;
            return Ok(None);
        }
        if native_data::<StringIo>(file).is_some() {
            return Ok(Some(Self::Stream(file.clone())));
        }

        let method = |name: &str| match vm.getattr_opt(file, &PyBytes::from(name)) {
            Ok(found) => Ok(found),
            Err(Signal::Raise(_)) => Ok(None),
            Err(halt) => Err(halt),
        };
        let (Some(read), Some(readline)) = (method("read")?, method("readline")?) else {
            return Err(vm.type_error("argument must have 'read' and 'readline' attributes"));
        };

        Ok(Some(Self::Reader { read, readline }))
    }
}

/// A `cPickle.Unpickler`, or the state of a `loads` call.
pub(super) struct Unpickler {
    pub(super) state: Rc<ModuleState>,
    input: Input,
    memo: RefCell<ObjectRef>,
    pub(super) persistent_load: RefCell<Option<Value>>,
    /// `Some(None)` refuses globals; unset uses the module system.
    pub(super) find_global: RefCell<Option<Value>>,
}

impl_native_data!(Unpickler, "cPickle.Unpickler");

impl Unpickler {
    fn new(vm: &Vm, state: Rc<ModuleState>, input: Input) -> Self {
        Self { state, input, memo: RefCell::new(vm.new_dict()), persistent_load: RefCell::new(None), find_global: RefCell::new(None) }
    }

    pub(super) fn memo(&self) -> ObjectRef {
        Rc::clone(&self.memo.borrow())
    }

    /// Exactly `count` bytes, or EOFError.
    pub(super) fn read(&self, vm: &Vm, count: usize) -> LoadResult<Vec<u8>> {
        let bytes = match &self.input {
            Input::Bytes { data, position } => {
                let start = position.get();
                let Some(bytes) = data.as_bytes().get(start..start + count) else {
                    position.set(data.as_bytes().len());
                    return Err(eof_error(vm).into());
                };
                position.set(start + count);
                bytes.to_vec()
            }
            Input::Stream(stream) => {
                let Some(stream) = native_data::<StringIo>(stream) else {
                    return Err(eof_error(vm).into());
                };
                match stream.read(vm, Some(count)) {
                    Ok(bytes) => bytes,
                    Err(Signal::Raise(_)) => return Err(eof_error(vm).into()),
                    Err(halt) => return Err(halt.into()),
                }
            }
            Input::Reader { read, .. } => {
                let result = vm.call(read, CallArgs::new(vec![Value::Int(count as i64)]))?;
                string_result(vm, &result)?
            }
        };

        if bytes.len() != count {
            return Err(eof_error(vm).into());
        }

        Ok(bytes)
    }

    /// The bytes through the next newline, or to the end of the input.
    pub(super) fn read_line(&self, vm: &Vm) -> LoadResult<Vec<u8>> {
        match &self.input {
            Input::Bytes { data, position } => {
                let start = position.get();
                let rest = data.as_bytes().get(start..).unwrap_or_default();
                let length = rest.iter().position(|byte| *byte == b'\n').map_or(rest.len(), |newline| newline + 1);
                position.set(start + length);
                Ok(rest[..length].to_vec())
            }
            Input::Stream(stream) => {
                let Some(stream) = native_data::<StringIo>(stream) else {
                    return Err(eof_error(vm).into());
                };
                match stream.read_line(vm) {
                    Ok(line) => Ok(line),
                    Err(Signal::Raise(_)) => Err(eof_error(vm).into()),
                    Err(halt) => Err(halt.into()),
                }
            }
            Input::Reader { readline, .. } => {
                let result = vm.call0(readline)?;
                string_result(vm, &result)
            }
        }
    }

    /// One pickle from the input. An EOFError from reading becomes a bare
    /// EOFError.
    fn run(&self, vm: &Vm, mode: Mode) -> LoadResult<Value> {
        match self.load(vm, mode) {
            Err(Stop::Signal(Signal::Raise(error))) if is_eof_error(vm, &error) => Err(eof_error(vm).into()),
            outcome => outcome,
        }
    }
}

/// The bytes a `read` or `readline` method returned: a string, or unicode
/// in the default encoding.
fn string_result(vm: &Vm, result: &Value) -> LoadResult<Vec<u8>> {
    if let Value::Unknown(unknown) = result {
        return Err(Stop::Unknown { origin: unknown.origin.clone() });
    }
    if let Some(bytes) = vm.as_str_bytes(result) {
        return Ok(bytes.as_bytes().to_vec());
    }
    if let Some(text) = vm.as_text(result) {
        return Ok(args::encode_default(vm, &text)?.as_bytes().to_vec());
    }

    Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(result))).into())
}

/// An EOFError without arguments.
pub(super) fn eof_error(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::EOFError));

    match vm.instantiate_exception(&class, Vec::new()) {
        Ok(error) => Signal::Raise(error),
        Err(signal) => signal,
    }
}

fn is_eof_error(vm: &Vm, error: &Value) -> bool {
    Rc::ptr_eq(&vm.class_of(error), vm.types().exception(ExceptionKind::EOFError))
}

/// The result of a load nothing can read again: an unknown value in it
/// makes the result unknown.
fn finished(outcome: LoadResult<Value>, function: &str) -> PyResult<Value> {
    match outcome {
        Ok(value) => Ok(value),
        Err(Stop::Signal(signal)) => Err(signal),
        Err(Stop::Unknown { origin }) => Ok(Value::unknown(format!("{function} of a pickle containing {origin}"))),
    }
}

/// `load(file)`.
pub(super) fn module_load(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let file = args::single(vm, args, "load")?;
    let Some(input) = Input::for_file(vm, &file)? else {
        return Ok(Value::unknown("cPickle.load from an unknown file"));
    };
    let unpickler = Unpickler::new(vm, module_state(vm)?, input);

    finished(unpickler.run(vm, Mode::Build), "cPickle.load")
}

/// `loads(string)`.
pub(super) fn module_loads(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "loads", 1, 1)?;
    let Some(data) = args.into_iter().next() else {
        return Err(vm.type_error("loads() takes exactly 1 argument (0 given)"));
    };
    if data.is_unknown() {
        return Ok(Value::unknown("cPickle.loads of an unknown string"));
    }

    let data = args::exact_string(vm, "loads", 1, &data)?;
    let unpickler = Unpickler::new(vm, module_state(vm)?, Input::Bytes { data, position: Cell::new(0) });

    finished(unpickler.run(vm, Mode::Build), "cPickle.loads")
}

/// `Unpickler(file)`.
pub(super) fn new_unpickler(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let file = args::single(vm, args, "Unpickler")?;
    let Some(input) = Input::for_file(vm, &file)? else {
        return Ok(Value::unknown("cPickle.Unpickler on an unknown file"));
    };

    let class = native_type(vm, UNPICKLER_TYPE, create_unpickler_type)?;
    let unpickler = Unpickler::new(vm, module_state(vm)?, input);

    Ok(new_native_object(vm, &class, unpickler))
}

/// A type whose dict holds only `__doc__`: its attributes come from
/// `Unpickler.__getattr__`, and it cannot be instantiated.
fn create_unpickler_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(vm, TypeSpec { name: "Unpickler", module: "cPickle", base: None, layout: Layout::Native, instance_dict: false, methods: &[] })?;
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("cPickle.Unpickler is not a class"));
    };
    vm.dict_delete(&data.dict, &Value::str("__module__"))?;
    vm.dict_delete(&data.dict, &Value::str("__new__"))?;
    vm.set_static_module(&class, "cPickle");
    vm.clear_new(&class);
    vm.register_native_getattr(&class, unpickler_getattr);
    vm.register_native_setattr(&class, unpickler_setattr);

    Ok(class)
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a Unpickler> {
    let Some(target) = args.positional.first() else {
        return Err(vm.type_error(&format!("{method}() needs an Unpickler")));
    };

    native_data::<Unpickler>(target).ok_or_else(|| vm.type_error(&format!("{method}() requires a '{UNPICKLER_TYPE}' object but received a '{}'", vm.type_name(target))))
}

/// `Unpickler.load()`.
fn unpickler_load(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let unpickler = receiver(vm, &args, "load")?;
    args::no_arguments(vm, &args, 1, "load")?;

    loaded(vm, unpickler.run(vm, Mode::Build), "cPickle.Unpickler.load")
}

/// `Unpickler.noload()`: reads a pickle without importing globals or
/// building objects.
fn unpickler_noload(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let unpickler = receiver(vm, &args, "noload")?;
    args::no_arguments(vm, &args, 1, "noload")?;

    loaded(vm, unpickler.run(vm, Mode::Skim), "cPickle.Unpickler.noload")
}

/// The result of a load from an unpickler that may read again: after an
/// unknown value its memo is unknown too.
fn loaded(vm: &Vm, outcome: LoadResult<Value>, function: &str) -> PyResult<Value> {
    match outcome {
        Ok(value) => Ok(value),
        Err(Stop::Signal(signal)) => Err(signal),
        Err(Stop::Unknown { origin }) => Err(vm.halt_unsupported(format!("{function} of a pickle containing {origin}"))),
    }
}

/// The name of an attribute as the C string an attribute hook receives.
fn attribute_name(name: &PyBytes) -> &[u8] {
    let bytes = name.as_bytes();

    bytes.iter().position(|byte| *byte == 0).map_or(bytes, |end| &bytes[..end])
}

/// The attributes of an unpickler: its hooks, memo, exception class, and
/// methods.
fn unpickler_getattr(vm: &Vm, target: &Value, name: &PyBytes) -> PyResult<Option<Value>> {
    let Some(unpickler) = native_data::<Unpickler>(target) else {
        return Ok(None);
    };

    let hook = |slot: &RefCell<Option<Value>>, name: &str| -> PyResult<Option<Value>> {
        let value = slot.borrow().clone();
        match value {
            Some(value) => Ok(Some(value)),
            None => Err(vm.raise(ExceptionKind::AttributeError, name)),
        }
    };

    match attribute_name(name) {
        b"persistent_load" => hook(&unpickler.persistent_load, "persistent_load"),
        b"find_global" => hook(&unpickler.find_global, "find_global"),
        b"memo" => Ok(Some(Value::Object(unpickler.memo()))),
        b"UnpicklingError" => Ok(Some(Value::Object(Rc::clone(&unpickler.state.unpickling_error)))),
        b"load" => Ok(Some(vm.new_bound_native("load", unpickler_load, target.clone(), None))),
        b"noload" => Ok(Some(vm.new_bound_native("noload", unpickler_noload, target.clone(), None))),
        b"__methods__" => Ok(Some(vm.new_list(METHOD_NAMES.iter().map(|name| Value::str(name)).collect()))),
        b"__doc__" => Ok(Some(Value::None)),
        _ => Ok(None),
    }
}

/// Stores or deletes (`value` of `None`) an unpickler attribute. Only the
/// hooks and the memo can be assigned.
fn unpickler_setattr(vm: &Vm, target: &Value, name: &PyBytes, value: Option<Value>) -> PyResult<()> {
    let Some(unpickler) = native_data::<Unpickler>(target) else {
        return Err(vm.type_error("cPickle.Unpickler attribute set on another object"));
    };

    match attribute_name(name) {
        b"persistent_load" => {
            let previous = std::mem::replace(&mut *unpickler.persistent_load.borrow_mut(), value);
            drop(previous);
        }
        b"find_global" => {
            let previous = std::mem::replace(&mut *unpickler.find_global.borrow_mut(), value);
            drop(previous);
        }
        _ if value.is_none() => return Err(vm.type_error("attribute deletion is not supported")),
        b"memo" => {
            let Some(memo) = value.as_ref().and_then(Value::as_object).filter(|object| object.as_dict().is_some()) else {
                return Err(vm.type_error("memo must be a dictionary"));
            };
            let previous = std::mem::replace(&mut *unpickler.memo.borrow_mut(), Rc::clone(memo));
            drop(previous);
        }
        other => return Err(vm.raise(ExceptionKind::AttributeError, &String::from_utf8_lossy(other))),
    }

    Ok(())
}
