//! `marshal`: `dumps`/`loads` in memory, and `dump`/`load`, which only
//! take real files and so reach the host.

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::marshal;
use crate::interp::marshal::DumpStop;
use crate::interp::marshal::writer::Marshalled;
use crate::interp::marshal::writer::WriteError;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("dump", dump), function("load", load), function("dumps", dumps), function("loads", loads)])?;

    set_attribute(vm, module, "version", Value::Int(marshal::VERSION))
}

/// The `version` argument of `dump` and `dumps` (`i`); `None` when it is
/// unknown.
fn version(vm: &Vm, value: Option<&Value>) -> PyResult<Option<i64>> {
    match value {
        Some(value) if value.is_unknown() => Ok(None),
        Some(value) => args::c_int(vm, value).map(|version| Some(i64::from(version))),
        None => Ok(Some(marshal::VERSION)),
    }
}

/// The exception for a marshal write failure.
fn write_error(vm: &Vm, error: WriteError) -> Signal {
    let message = match error {
        WriteError::Unmarshallable => "unmarshallable object",
        WriteError::NestedTooDeep => "object too deeply nested to marshal",
    };

    vm.raise(ExceptionKind::ValueError, message)
}

/// The marshalled bytes of `value`, or the value standing for them when
/// they are unknown.
fn marshalled(vm: &Vm, value: &Value, version: i64, origin: &str) -> PyResult<Result<Vec<u8>, Value>> {
    match marshal::dumps(vm, value, version) {
        Ok(Marshalled::Written(bytes)) => Ok(Ok(bytes)),
        Ok(Marshalled::Failed { error, .. }) => Err(write_error(vm, error)),
        Err(DumpStop::Signal(signal)) => Err(signal),
        Err(DumpStop::Unknown { origin: inner }) => Ok(Err(Value::unknown(format!("{origin} of a value containing {inner}")))),
    }
}

/// `dumps(value[, version])`.
fn dumps(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "dumps", 1, 2)?;
    let Some(version) = version(vm, args.get(1))? else {
        return Ok(Value::unknown("marshal.dumps with an unknown version"));
    };

    match marshalled(vm, &args[0], version, "marshal.dumps")? {
        Ok(bytes) => Ok(Value::Str(PyBytes::allocate(bytes))),
        Err(unknown) => Ok(unknown),
    }
}

/// `loads(string)`: extra bytes after the first value are ignored.
fn loads(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "loads", 1, 1)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let bytes = args::read_buffer(vm, "loads", 1, &args[0])?;

    marshal::loads(vm, bytes.as_bytes())
}

/// `dump(value, file[, version])`. Only a real file is accepted; what is
/// written to it is host state.
fn dump(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "dump", 2, 3)?;
    let Some(version) = version(vm, args.get(2))? else {
        return Ok(Value::unknown("marshal.dump with an unknown version"));
    };
    if args[1].is_unknown() {
        return Ok(Value::unknown("marshal.dump to an unknown file"));
    }
    if !vm.is_instance_of(&args[1], &vm.types().file)? {
        return Err(vm.type_error("marshal.dump() 2nd arg must be file"));
    }

    // The bytes go to the host file; only a write error is observable here.
    if let Err(unknown) = marshalled(vm, &args[0], version, "marshal.dump")? {
        return Ok(unknown);
    }

    vm.host_operation_on(HostCapability::FileSystem, "marshal.dump to a host file", Denial::Crt, None)
}

/// `load(file)`: reads from a real file, which is host state.
fn load(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let file = args::single(vm, args, "load")?;
    if file.is_unknown() {
        return Ok(file);
    }
    if !vm.is_instance_of(&file, &vm.types().file)? {
        return Err(vm.type_error("marshal.load() arg must be file"));
    }

    vm.host_operation_on(HostCapability::FileSystem, "marshal.load from a host file", Denial::Crt, None)
}
