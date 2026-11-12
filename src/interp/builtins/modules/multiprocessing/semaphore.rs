//! `SemLock` for Windows. Creating a semaphore and waiting on or releasing
//! one go through the host; the per-process acquisition count is tracked
//! exactly until a host operation may have changed it.

use std::cell::Cell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::class_method;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::numbers::int_bounds;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::handle_argument;
use super::int_value;
use super::unnamed_arguments;

const TYPE_NAME: &str = "_multiprocessing.SemLock";

/// `RECURSIVE_MUTEX` of the `kind` enumeration; `SEMAPHORE` is 1.
const RECURSIVE_MUTEX: i32 = 0;

/// `INFINITE` of `winbase.h`.
const INFINITE: f64 = 4_294_967_295.0;

/// A `SemLockObject`.
struct SemLock {
    handle: u64,
    kind: i32,
    maxvalue: i32,
    /// `count`; `None` once a host wait or release may have changed it.
    count: Cell<Option<i32>>,
}

impl_native_data!(SemLock, "_multiprocessing.SemLock");

/// A converted argument of `acquire`.
enum AcquireArgument {
    /// `None` when unknown.
    Block(Option<i32>),
    Timeout(Value),
}

impl SemLock {
    /// Whether the count is positive and the last acquiring thread is the current one. The
    /// thread identifier comes from the host, so a positive count leaves
    /// the answer unknown.
    fn is_mine(&self) -> Option<bool> {
        match self.count.get() {
            Some(count) if count <= 0 => Some(false),
            _ => None,
        }
    }
}

pub(super) fn semlock_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, TYPE_NAME, create_semlock_type)
}

fn create_semlock_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "SemLock",
            module: "_multiprocessing",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", semlock_new),
                method("acquire", semlock_acquire),
                method("release", semlock_release),
                method("__enter__", semlock_enter),
                method("__exit__", semlock_exit),
                method("_count", semlock_count),
                method("_is_mine", semlock_is_mine),
                method("_get_value", semlock_get_value),
                method("_is_zero", semlock_is_zero),
                class_method("_rebuild", semlock_rebuild),
                method("_after_fork", semlock_after_fork),
            ],
        },
    )?;

    let Some(data) = class.as_class() else {
        return Err(vm.type_error("SemLock is not a class"));
    };

    // `SEM_VALUE_MAX` is `LONG_MAX` on Windows, stored as an `int`.
    let (_, long_max) = int_bounds(vm.config.long_width);
    vm.dict_set_str(&data.dict, "SEM_VALUE_MAX", Value::Long(Rc::new(BigInt::from(long_max))))?;

    add_member(vm, &class, GetSet { name: "handle", owner: TYPE_NAME, get: semlock_handle, set: None })?;
    add_member(vm, &class, GetSet { name: "kind", owner: TYPE_NAME, get: semlock_kind, set: None })?;
    add_member(vm, &class, GetSet { name: "maxvalue", owner: TYPE_NAME, get: semlock_maxvalue, set: None })?;

    Ok(class)
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a SemLock> {
    this::<SemLock>(vm, args, TYPE_NAME, method)
}

/// `SemLock.__new__`: `"iii"` over `kind`, `value`, `maxvalue`, then the kind
/// check before the host creates the semaphore.
fn semlock_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = semlock_type(vm)?;
    let (_, args) = new_class(vm, args, &base)?;

    let arguments = parse_with(vm, args, "", &["kind", "value", "maxvalue"], 3, |vm, _, value| int_value(vm, &value))?;
    if let Some(Some(Some(kind))) = arguments.first()
        && *kind != RECURSIVE_MUTEX
        && *kind != 1
    {
        return Err(vm.raise(ExceptionKind::ValueError, "unrecognized kind"));
    }

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock() (host semaphore)")
}

/// `SemLock._rebuild` (a classmethod): a handle and two `int`s; wraps the
/// handle without a host call.
fn semlock_rebuild(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(Value::Object(class)) = args.positional.first() else {
        return Err(vm.type_error("descriptor '_rebuild' of '_multiprocessing.SemLock' object needs an argument"));
    };
    let class = Rc::clone(class);
    let arguments = unnamed_arguments(vm, &args, 1, "_rebuild", 3, 3)?;

    let handle = handle_argument(vm, &arguments[0], 1)?;
    let kind = int_value(vm, &arguments[1])?;
    let maxvalue = int_value(vm, &arguments[2])?;
    let (Some(handle), Some(kind), Some(maxvalue)) = (handle, kind, maxvalue) else {
        return Ok(Value::unknown("_multiprocessing.SemLock._rebuild() of unknown arguments"));
    };

    let semlock = SemLock { handle, kind, maxvalue, count: Cell::new(Some(0)) };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(semlock))))
}

/// `SemLock.acquire`: `"|iO"` over `block`, `timeout`, then the timeout
/// conversion before the wait.
fn acquire(vm: &Vm, mut args: CallArgs, method: &str) -> PyResult<Value> {
    receiver(vm, &args, method)?;
    let this = args.positional.remove(0);
    let semlock = native_data::<SemLock>(&this).ok_or_else(|| vm.type_error(&format!("descriptor '{method}' requires a '{TYPE_NAME}' object but received a '{}'", vm.type_name(&this))))?;

    let arguments = parse_with(vm, args, "", &["block", "timeout"], 0, |vm, index, value| match index {
        0 => int_value(vm, &value).map(AcquireArgument::Block),
        _ => Ok(AcquireArgument::Timeout(value)),
    })?;
    let block = match arguments.first() {
        Some(Some(AcquireArgument::Block(block))) => *block,
        _ => Some(1),
    };
    let timeout = match arguments.get(1) {
        Some(Some(AcquireArgument::Timeout(timeout))) => timeout.clone(),
        _ => Value::None,
    };

    // Without knowing whether the call blocks, the timeout may or may not
    // be converted, and the wait happens on the host either way.
    let Some(block) = block else {
        let result = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock.acquire() of unknown arguments")?;
        semlock.count.set(None);
        return Ok(result);
    };
    if block != 0 && !timeout.is_none() {
        let Some(seconds) = c_double(vm, &timeout)? else {
            let result = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock.acquire() of unknown arguments")?;
            semlock.count.set(None);
            return Ok(result);
        };
        if seconds * 1000.0 >= 0.5 * INFINITE {
            return Err(vm.raise(ExceptionKind::OverflowError, "timeout is too large"));
        }
    }

    if semlock.kind == RECURSIVE_MUTEX
        && semlock.is_mine() == Some(true)
        && let Some(count) = semlock.count.get()
    {
        semlock.count.set(Some(count.saturating_add(1)));
        return Ok(Value::Bool(true));
    }
    let result = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock.acquire() (host semaphore)")?;
    semlock.count.set(None);

    Ok(result)
}

fn semlock_acquire(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    acquire(vm, args, "acquire")
}

fn semlock_enter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    acquire(vm, args, "__enter__")
}

fn semlock_release(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let semlock = receiver(vm, &args, "release")?;
    method_no_arguments(vm, &args, "release")?;

    release(vm, semlock)
}

/// `__exit__` is `release` taking varargs: any positional arguments are
/// ignored.
fn semlock_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let semlock = receiver(vm, &args, "__exit__")?;
    if args.has_keywords() {
        return Err(vm.type_error("__exit__() takes no keyword arguments"));
    }

    release(vm, semlock)
}

/// `SemLock.release`.
fn release(vm: &Vm, semlock: &SemLock) -> PyResult<Value> {
    if semlock.kind == RECURSIVE_MUTEX {
        match semlock.is_mine() {
            Some(false) => return Err(vm.raise(ExceptionKind::AssertionError, "attempt to release recursive lock not owned by thread")),
            None => return vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock.release() of a lock whose owner is unknown"),
            Some(true) => {
                if let Some(count) = semlock.count.get().filter(|count| *count > 1) {
                    semlock.count.set(Some(count - 1));
                    return Ok(Value::None);
                }
            }
        }
    }

    let result = vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock.release() (host semaphore)")?;
    semlock.count.set(None);

    Ok(result)
}

fn semlock_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let semlock = receiver(vm, &args, "_count")?;
    method_no_arguments(vm, &args, "_count")?;

    Ok(match semlock.count.get() {
        Some(count) => Value::Int(i64::from(count)),
        None => Value::unknown("_multiprocessing.SemLock._count() after a host wait or release"),
    })
}

fn semlock_is_mine(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let semlock = receiver(vm, &args, "_is_mine")?;
    method_no_arguments(vm, &args, "_is_mine")?;

    Ok(match semlock.is_mine() {
        Some(mine) => Value::Bool(mine),
        None => Value::unknown("_multiprocessing.SemLock._is_mine() (host thread)"),
    })
}

fn semlock_get_value(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_get_value")?;
    method_no_arguments(vm, &args, "_get_value")?;

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock._get_value() (host semaphore)")
}

fn semlock_is_zero(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "_is_zero")?;
    method_no_arguments(vm, &args, "_is_zero")?;

    vm.host_operation(HostCapability::SharedMemory, "_multiprocessing.SemLock._is_zero() (host semaphore)")
}

fn semlock_after_fork(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let semlock = receiver(vm, &args, "_after_fork")?;
    method_no_arguments(vm, &args, "_after_fork")?;

    semlock.count.set(Some(0));

    Ok(Value::None)
}

/// The semaphore behind a member's `instance`; `None` when it is unknown.
fn member_receiver<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<Option<&'a SemLock>> {
    if instance.is_unknown() {
        return Ok(None);
    }

    native_data::<SemLock>(instance).map(Some).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

/// `handle` is an unsigned 64-bit member, always read as a `long`.
fn semlock_handle(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(semlock) = member_receiver(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(Value::Long(Rc::new(BigInt::from(semlock.handle))))
}

fn semlock_kind(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(semlock) = member_receiver(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(Value::Int(i64::from(semlock.kind)))
}

fn semlock_maxvalue(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(semlock) = member_receiver(vm, getset, instance)? else {
        return Ok(instance.clone());
    };

    Ok(Value::Int(i64::from(semlock.maxvalue)))
}
