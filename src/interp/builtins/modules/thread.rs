//! `thread`. The interpreter runs one thread: locks track their state, and
//! starting a thread halts.

use std::cell::Cell;
use std::rc::Rc;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The only thread's identifier. CPython reports the OS thread id, which
/// varies between runs; code only compares it or uses it as a key, so any
/// fixed value behaves the same.
const MAIN_THREAD_IDENT: i64 = 1;

struct Lock {
    locked: Cell<bool>,
}

impl_native_data!(Lock, "thread.lock");

/// `thread._local`: with a single thread, its `__dict__` is the only one.
struct Local;

impl_native_data!(Local, "thread._local");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("allocate_lock", allocate_lock),
            function("allocate", allocate_lock),
            function("get_ident", get_ident),
            function("start_new_thread", start_new_thread),
            function("start_new", start_new_thread),
            function("exit", thread_exit),
            function("exit_thread", thread_exit),
            function("interrupt_main", interrupt_main),
            function("stack_size", stack_size),
            function("_count", thread_count),
        ],
    )?;

    set_attribute(vm, module, "LockType", Value::Object(lock_type(vm)?))?;
    set_attribute(vm, module, "_local", Value::Object(native_type(vm, "thread._local", create_local_type)?))?;

    let error = new_exception_class(vm, "thread", "error", vm.types().exception(ExceptionKind::Exception))?;
    set_attribute(vm, module, "error", Value::Object(error))
}

fn lock_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "thread.lock", create_lock_type)
}

fn create_lock_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name: "lock",
            module: "thread",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("acquire", lock_acquire),
                method("acquire_lock", lock_acquire),
                method("release", lock_release),
                method("release_lock", lock_release),
                method("locked", lock_locked),
                method("locked_lock", lock_locked),
                method("__enter__", lock_acquire),
                method("__exit__", lock_exit),
            ],
        },
    )
}

fn create_local_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_type(vm, TypeSpec { name: "_local", module: "thread", base: None, layout: Layout::Native, instance_dict: true, methods: &[static_method("__new__", local_new)] })
}

fn allocate_lock(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "allocate_lock")?;
    let class = lock_type(vm)?;

    Ok(new_native_object(vm, &class, Lock { locked: Cell::new(false) }))
}

/// Lock acquisition. Waiting for a lock held by the only thread would never
/// return.
fn lock_acquire(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let lock = this::<Lock>(vm, &args, "thread.lock", "acquire")?;
    let args = method_arguments(vm, &args, "acquire", 0, 1)?;

    let blocking = match args.first() {
        None => true,
        Some(flag) => {
            if flag.is_unknown() {
                return Err(vm.halt_unsupported("lock.acquire with an unknown wait flag"));
            }
            let Some(flag) = vm.as_index(flag) else {
                return Err(vm.type_error("an integer is required"));
            };
            flag != 0
        }
    };

    if !lock.locked.get() {
        lock.locked.set(true);
        return Ok(Value::Bool(true));
    }
    if blocking {
        return Err(vm.halt_unsupported("blocking acquire of a lock the only thread holds"));
    }

    Ok(Value::Bool(false))
}

fn lock_release(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let lock = this::<Lock>(vm, &args, "thread.lock", "release")?;
    method_no_arguments(vm, &args, "release")?;

    if !lock.locked.get() {
        return Err(thread_error(vm, "release unlocked lock"));
    }
    lock.locked.set(false);

    Ok(Value::None)
}

fn lock_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let lock = this::<Lock>(vm, &args, "thread.lock", "__exit__")?;
    if !lock.locked.get() {
        return Err(thread_error(vm, "release unlocked lock"));
    }
    lock.locked.set(false);

    Ok(Value::None)
}

fn lock_locked(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let lock = this::<Lock>(vm, &args, "thread.lock", "locked")?;

    Ok(Value::Bool(lock.locked.get()))
}

/// `thread.error`, looked up through the imported module so callers can
/// catch the class they see.
fn thread_error(vm: &Vm, message: &str) -> Signal {
    let class = vm.import_module("thread").and_then(|module| vm.getattr_str(&module, "error"));
    let class = match class {
        Ok(class) => class,
        Err(signal) => return signal,
    };

    match vm.call1(&class, Value::str(message)) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

fn get_ident(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_ident")?;

    Ok(Value::Int(MAIN_THREAD_IDENT))
}

fn start_new_thread(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("starting threads"))
}

fn thread_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "exit")?;
    let class = Rc::clone(vm.types().exception(ExceptionKind::SystemExit));

    Err(Signal::Raise(vm.instantiate_exception(&class, Vec::new())?))
}

/// Raises KeyboardInterrupt in the main thread at a later bytecode
/// boundary, which the interpreter does not schedule.
fn interrupt_main(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("thread.interrupt_main"))
}

/// `thread.stack_size([size])`: 0 means the platform default.
fn stack_size(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "stack_size", 0, 1)?;
    let Some(size) = args.first() else {
        return Ok(Value::Int(0));
    };
    if size.is_unknown() {
        return Err(vm.halt_unsupported("thread.stack_size with an unknown size"));
    }
    let Some(size) = vm.as_index(size) else {
        return Err(vm.type_error("an integer is required"));
    };
    if size != 0 && size < 32_768 {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("size not valid: {size} bytes")));
    }

    Ok(Value::Int(0))
}

fn thread_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "_count")?;

    Ok(Value::Int(0))
}

/// `thread._local.__new__`: arguments are only accepted when a subclass defines
/// `__init__`.
fn local_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(Value::Object(class)) = args.positional.first() else {
        return Err(vm.type_error("thread._local.__new__(X): X is not a type object"));
    };

    if args.positional.len() > 1 || args.has_keywords() {
        let object_init = vm.lookup_mro(&vm.types().object, "__init__")?;
        let class_init = vm.lookup_mro(class, "__init__")?;
        let inherits_object_init = match (&object_init, &class_init) {
            (crate::interp::attr::MroLookup::Found { value: base, .. }, crate::interp::attr::MroLookup::Found { value: own, .. }) => vm.is_same(base, own),
            _ => false,
        };
        if inherits_object_init {
            return Err(vm.type_error("Initialization arguments are not supported"));
        }
    }

    let local = vm.alloc(class, Payload::Native(Box::new(Local)), Some(vm.new_dict()));

    Ok(Value::Object(local))
}
