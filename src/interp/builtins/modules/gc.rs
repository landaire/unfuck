//! The `gc` module. The collector's switches and thresholds are kept per
//! interpreter; anything that depends on the heap the collector sees
//! (counts, collected objects, referrers) is unknown.

use std::cell::Cell;
use std::cell::RefCell;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::modules::time::no_arguments;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Collector settings. Values set from unknown arguments stay unknown.
struct GcState {
    enabled: Cell<bool>,
    debug: RefCell<Value>,
    thresholds: RefCell<[Value; 3]>,
}

impl Default for GcState {
    fn default() -> Self {
        Self {
            enabled: Cell::new(true),
            debug: RefCell::new(Value::Int(0)),
            thresholds: RefCell::new([Value::Int(700), Value::Int(10), Value::Int(10)]),
        }
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("enable", gc_enable),
            function("disable", gc_disable),
            function("isenabled", gc_isenabled),
            function("set_debug", gc_set_debug),
            function("get_debug", gc_get_debug),
            function("get_count", gc_get_count),
            function("set_threshold", gc_set_threshold),
            function("get_threshold", gc_get_threshold),
            function("collect", gc_collect),
            function("get_objects", gc_get_objects),
            function("is_tracked", gc_is_tracked),
            function("get_referrers", gc_get_referrers),
            function("get_referents", gc_get_referents),
        ],
    )?;

    set_attribute(vm, module, "garbage", vm.new_list(Vec::new()))?;

    let flags = [
        ("DEBUG_STATS", 1),
        ("DEBUG_COLLECTABLE", 2),
        ("DEBUG_UNCOLLECTABLE", 4),
        ("DEBUG_INSTANCES", 8),
        ("DEBUG_OBJECTS", 16),
        ("DEBUG_SAVEALL", 32),
        ("DEBUG_LEAK", 62),
    ];
    for (name, value) in flags {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    Ok(())
}

/// A C `int` argument as a value: an `int`, or the unknown argument.
fn int_value(vm: &Vm, value: &Value) -> PyResult<Value> {
    Ok(match c_int(vm, value)? {
        Some(number) => Value::Int(i64::from(number)),
        None => value.clone(),
    })
}

fn gc_enable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "enable")?;
    vm.native_state::<GcState>().enabled.set(true);

    Ok(Value::None)
}

fn gc_disable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "disable")?;
    vm.native_state::<GcState>().enabled.set(false);

    Ok(Value::None)
}

fn gc_isenabled(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "isenabled")?;

    Ok(Value::Bool(vm.native_state::<GcState>().enabled.get()))
}

fn gc_set_debug(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "set_debug", 1, 1)?;
    let debug = int_value(vm, &args[0])?;
    *vm.native_state::<GcState>().debug.borrow_mut() = debug;

    Ok(Value::None)
}

fn gc_get_debug(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_debug")?;

    Ok(vm.native_state::<GcState>().debug.borrow().clone())
}

/// `gc.set_threshold`: omitted thresholds keep their values.
fn gc_set_threshold(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.positional.is_empty() && !args.has_keywords() {
        return Err(vm.type_error("set_threshold() takes at least 1 argument (0 given)"));
    }
    let args = positional(vm, args, "set_threshold", 1, 3)?;
    let mut values = Vec::with_capacity(args.len());
    for argument in &args {
        values.push(int_value(vm, argument)?);
    }

    let state = vm.native_state::<GcState>();
    let mut thresholds = state.thresholds.borrow_mut();
    for (slot, value) in thresholds.iter_mut().zip(values) {
        *slot = value;
    }

    Ok(Value::None)
}

fn gc_get_threshold(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_threshold")?;

    Ok(Value::tuple(
        vm.native_state::<GcState>().thresholds.borrow().to_vec(),
    ))
}

fn gc_get_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_count")?;

    Ok(Value::unknown("gc.get_count() (allocation counts)"))
}

/// `gc.collect`: reference counting already freed every object that is
/// not part of a cycle, and cycles are never collected (see
/// `crate::interp::lifecycle`), so nothing is found. CPython would free
/// cycles without `__del__` here and count them.
fn gc_collect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "", &["generation"], 0, |vm, _, value| int_value(vm, &value))?;
    if let Some(Value::Int(generation)) = slots[0]
        && !(0..3).contains(&generation)
    {
        return Err(vm.raise(ExceptionKind::ValueError, "invalid generation"));
    }

    vm.run_finalizers()?;

    Ok(Value::Int(0))
}

fn gc_get_objects(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_objects")?;

    Ok(Value::unknown("gc.get_objects()"))
}

/// `gc.is_tracked`: objects of types without GC support are never tracked;
/// whether a container is tracked depends on collector history.
fn gc_is_tracked(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("is_tracked() takes no keyword arguments"));
    }
    let [object] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!(
            "is_tracked() takes exactly one argument ({} given)",
            args.positional.len()
        )));
    };

    Ok(match object {
        Value::None
        | Value::NotImplemented
        | Value::Ellipsis
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Long(_)
        | Value::Float(_)
        | Value::Str(_)
        | Value::Unicode(_) => Value::Bool(false),
        Value::Unknown(_) => object.clone(),
        Value::Tuple(_) | Value::Object(_) => Value::unknown("gc.is_tracked() of a container"),
    })
}

fn gc_get_referrers(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("get_referrers() takes no keyword arguments"));
    }

    Ok(Value::unknown("gc.get_referrers()"))
}

fn gc_get_referents(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("get_referents() takes no keyword arguments"));
    }

    Ok(Value::unknown("gc.get_referents()"))
}
