//! The `_multiprocessing` module built for Windows. Connections and
//! semaphores wrap host handles: their in-memory state (handle values,
//! flags, acquisition counts) is exact, while every operation on the handle
//! itself yields an unknown result. Operations that would store host data
//! into interpreter objects halt.

mod connection;
mod semaphore;
mod win32;

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::set_attribute;
use crate::interp::buffer::BufferInterface;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::Integral;
use crate::interp::numbers::int_bounds;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `cPickle.dumps` and `cPickle.HIGHEST_PROTOCOL` as read at module import,
/// read them, for `Connection.send`.
struct Pickler {
    dumps: Value,
    protocol: Value,
}

#[derive(Default)]
struct MultiprocessingState {
    pickler: RefCell<Option<Rc<Pickler>>>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("address_of_buffer", address_of_buffer)])?;

    let pickle = vm.import_module("cPickle")?;
    let dumps = vm.getattr_str(&pickle, "dumps")?;
    vm.getattr_str(&pickle, "loads")?;
    let protocol = vm.getattr_str(&pickle, "HIGHEST_PROTOCOL")?;
    *vm.native_state::<MultiprocessingState>().pickler.borrow_mut() = Some(Rc::new(Pickler { dumps, protocol }));

    let package = vm.import_module("multiprocessing")?;
    vm.getattr_str(&package, "BufferTooShort")?;

    set_attribute(vm, module, "Connection", Value::Object(connection::connection_type(vm)?))?;
    set_attribute(vm, module, "SemLock", Value::Object(semaphore::semlock_type(vm)?))?;
    set_attribute(vm, module, "PipeConnection", Value::Object(connection::pipe_connection_type(vm)?))?;
    set_attribute(vm, module, "win32", Value::Object(win32::win32_type(vm)?))?;

    // `HAVE_FD_TRANSFER` is defined as 0 when `CMSG_LEN` is missing, so the
    // Windows build reports it with that value.
    let flags = vm.new_dict();
    vm.dict_set_str(&flags, "HAVE_FD_TRANSFER", Value::Int(0))?;
    set_attribute(vm, module, "flags", Value::Object(flags))
}

/// The pickler `init` stored; it is set before any type is exposed.
fn pickler(vm: &Vm) -> PyResult<Rc<Pickler>> {
    let stored = vm.native_state::<MultiprocessingState>().pickler.borrow().clone();

    stored.ok_or_else(|| vm.halt_unsupported("_multiprocessing used before its initialization"))
}

/// `_multiprocessing.address_of_buffer` over a writable buffer. The address is host memory
/// and unknown; the length is exact.
fn address_of_buffer(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("address_of_buffer() takes no keyword arguments"));
    }
    let [object] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!("address_of_buffer() takes exactly one argument ({} given)", args.positional.len())));
    };
    if object.is_unknown() {
        return Ok(object.clone());
    }

    // `str` and `unicode` provide a write slot that refuses.
    if vm.as_str_bytes(object).is_some() {
        return Err(vm.type_error("Cannot use string as modifiable buffer"));
    }
    if vm.as_text(object).is_some() {
        return Err(vm.type_error("cannot use unicode as modifiable buffer"));
    }
    let Some(contents) = vm.buffer(object, BufferInterface::Writable)? else {
        return Err(vm.type_error("expected a writeable buffer object"));
    };

    let length = i64::try_from(contents.as_bytes().len()).map_err(|_| vm.halt_unsupported("buffer longer than Py_ssize_t"))?;

    let address = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.address_of_buffer() (host address)")?;

    Ok(Value::tuple(vec![address, Value::Int(length)]))
}

/// A `long` or `int` value for an unsigned result.
fn unsigned_value(vm: &Vm, number: u64) -> Value {
    let (_, high) = int_bounds(vm.config.long_width);

    match i64::try_from(number) {
        Ok(number) if number <= high => Value::Int(number),
        _ => Value::long(BigInt::from(number)),
    }
}

/// The width of a C `long`.
fn long_bits(vm: &Vm) -> u32 {
    match vm.config.long_width {
        LongWidth::Bits32 => 32,
        LongWidth::Bits64 => 64,
    }
}

/// Positional arguments of a varargs function whose format has no name,
/// after `skip` receivers.
fn unnamed_arguments(vm: &Vm, args: &CallArgs, skip: usize, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let rest: Vec<Value> = args.positional.iter().skip(skip).cloned().collect();
    let count = rest.len();
    if count < minimum || count > maximum {
        let (bound, limit) = if minimum == maximum {
            ("exactly", minimum)
        } else if count < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if limit == 1 { "" } else { "s" };
        return Err(vm.type_error(&format!("function takes {bound} {limit} argument{plural} ({count} given)")));
    }

    Ok(rest)
}

/// `value` reduced modulo `2**bits`, as the `*Mask` conversions do.
fn masked(number: &Integral, bits: u32) -> Option<u64> {
    let modulus = BigInt::from(1u128 << bits);
    let number = match number {
        Integral::Int(number) => BigInt::from(*number),
        Integral::Long(number) => number.clone(),
    };

    number.mod_floor(&modulus).to_u64()
}

/// The `K` format (handles and pointers on Win64): an `int` masked to the
/// C `long`, a `long` masked to 64 bits. `None` when the argument is
/// unknown.
fn handle_argument(vm: &Vm, value: &Value, position: usize) -> PyResult<Option<u64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let Some(number) = vm.as_integral(value) else {
        return Err(vm.type_error(&format!("argument {position} must be an integer, not {}", converted_type_name(vm, value))));
    };
    let bits = match number {
        Integral::Int(_) => long_bits(vm),
        Integral::Long(_) => 64,
    };

    Ok(masked(&number, bits))
}

/// The `k` format: any `int` or `long`, masked to 32 bits.
fn dword_argument(vm: &Vm, value: &Value, position: usize) -> PyResult<()> {
    if value.is_unknown() || vm.as_integral(value).is_some() {
        return Ok(());
    }

    Err(vm.type_error(&format!("argument {position} must be an integer, not {}", converted_type_name(vm, value))))
}

/// The `i` format; `None` when the argument is unknown.
fn int_value(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let number = int_argument(vm, value)?;

    i32::try_from(number).map(Some).map_err(|_| vm.halt_unsupported("C int out of range after conversion"))
}

/// Unsigned masked conversion of any object, through `__int__`; only its
/// errors are kept.
fn check_unsigned_long_mask(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() || vm.as_integral(value).is_some() {
        return Ok(());
    }
    if let Some(number) = vm.as_float(value) {
        if number.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        }
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        return Ok(());
    }
    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to int"));
    }

    let Some(method) = vm.user_override(value, "__int__")? else {
        return Err(vm.type_error("an integer is required"));
    };
    let result = vm.call0(&method)?;
    if result.is_unknown() || vm.as_integral(&result).is_some() {
        return Ok(());
    }

    Err(vm.type_error("__int__ method should return an integer"))
}

/// The `n` format of the Win64 build, which tries `__long__` and `__int__`
/// rather than `__index__`; `None` when unknown.
fn ssize_value(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let converted = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let method = match vm.user_override(value, "__long__")? {
                Some(method) => method,
                None => match vm.user_override(value, "__int__")? {
                    Some(method) => method,
                    None if vm.as_complex(value).is_some() => return Err(vm.type_error("can't convert complex to int")),
                    None => return Err(vm.type_error("an integer is required")),
                },
            };
            let result = vm.call0(&method)?;
            if result.is_unknown() {
                return Ok(None);
            }
            let Some(integral) = vm.as_integral(&result) else {
                return Err(vm.type_error("__int__ method should return an integer"));
            };
            integral
        }
    };

    match converted {
        Integral::Int(number) => Ok(Some(number)),
        Integral::Long(number) => number.to_i64().map(Some).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to int")),
    }
}
