//! The `_lsprof` module. The interpreter has no clock and does not report
//! call events, so the statistics a profiler collects while it is enabled
//! are unknown. A profiler that never collected, or was cleared while not
//! installed, reports its empty statistics exactly.

use std::cell::Cell;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_struct_sequence_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::sys::profile_object;
use crate::interp::builtins::modules::sys::ProfileSlot;
use crate::interp::builtins::modules::sys::profile_slot;
use crate::interp::builtins::modules::sys::set_profile_object;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const TYPE_NAME: &str = "_lsprof.Profiler";

const ENTRY_FIELDS: [&str; 6] = ["code", "callcount", "reccallcount", "totaltime", "inlinetime", "calls"];

const SUBENTRY_FIELDS: [&str; 5] = ["code", "callcount", "reccallcount", "totaltime", "inlinetime"];

/// A `ProfilerObject`. Its subcall and builtin flags and time unit only
/// shape statistics that are unknown, so they are validated and dropped.
struct Profiler {
    /// Whether a custom timer is set (to any object, `None` included).
    external_timer: Cell<bool>,
    /// The profiler may hold entries: it was installed after its last
    /// `clear()` that ran while it was not installed.
    collected: Cell<bool>,
    /// Set by `enable()`, cleared by `disable()`, and kept
    /// when another call replaces the installed hook.
    enabled: Cell<bool>,
    hook: Weak<ProfileSlot>,
}

impl_native_data!(Profiler, "_lsprof.Profiler");

/// Deallocation removes whatever hook is installed when the profiler
/// is still enabled. An installed profiler is referenced by the hook, so
/// this only happens once the hook was replaced or removed.
impl Drop for Profiler {
    fn drop(&mut self) {
        if !self.enabled.get() {
            return;
        }
        let Some(slot) = self.hook.upgrade() else {
            return;
        };

        // The displaced hook is released once the slot is free, since its
        // own deallocation may clear the slot.
        let previous = slot.try_borrow_mut().map(|mut current| current.take());
        drop(previous);
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "Profiler", Value::Object(native_type(vm, TYPE_NAME, create_profiler_type)?))?;

    let entry = native_type(vm, "_lsprof.profiler_entry", |vm| new_struct_sequence_type(vm, "_lsprof", "profiler_entry", &ENTRY_FIELDS))?;
    set_attribute(vm, module, "profiler_entry", Value::Object(entry))?;

    let subentry = native_type(vm, "_lsprof.profiler_subentry", |vm| new_struct_sequence_type(vm, "_lsprof", "profiler_subentry", &SUBENTRY_FIELDS))?;
    set_attribute(vm, module, "profiler_subentry", Value::Object(subentry))
}

fn create_profiler_type(vm: &Vm) -> PyResult<ObjectRef> {
    const DOC: &str = "Profiler(custom_timer=None, time_unit=None, subcalls=True, builtins=True)\n\n    Builds a profiler object using the specified timer function.\n    The default timer is a fast built-in one based on real time.\n    For custom timer functions returning integers, time_unit can\n    be a float specifying a scale (i.e. how long each integer unit\n    is, in seconds).\n";

    let class = new_type(
        vm,
        TypeSpec {
            name: "Profiler",
            module: "_lsprof",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", profiler_new),
                method("__init__", profiler_init),
                method("getstats", profiler_getstats),
                method("enable", profiler_enable),
                method("disable", profiler_disable),
                method("clear", profiler_clear),
            ],
        },
    )?;
    if let Some(data) = class.as_class() {
        vm.dict_set_str(&data.dict, "__doc__", Value::str(DOC))?;
    }

    Ok(class)
}

/// Generic allocation: arguments are left to `__init__`.
fn profiler_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = native_type(vm, TYPE_NAME, create_profiler_type)?;
    let (class, _) = new_class(vm, args, &base)?;

    let profiler = Profiler { external_timer: Cell::new(false), collected: Cell::new(false), enabled: Cell::new(false), hook: profile_slot(vm) };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(profiler))))
}

/// Removes the receiver of a method taking further arguments.
fn split_receiver(vm: &Vm, args: &mut CallArgs, method: &str) -> PyResult<Value> {
    this::<Profiler>(vm, args, TYPE_NAME, method)?;

    Ok(args.positional.remove(0))
}

fn profiler_of<'a>(vm: &Vm, receiver: &'a Value, method: &str) -> PyResult<&'a Profiler> {
    native_data::<Profiler>(receiver).ok_or_else(|| vm.type_error(&format!("descriptor '{method}' requires a '{TYPE_NAME}' object but received a '{}'", vm.type_name(receiver))))
}

/// Whether `receiver` is the argument of the installed profile function.
fn is_installed(vm: &Vm, receiver: &Value) -> bool {
    match (profile_object(vm), receiver) {
        (Some(Value::Object(installed)), Value::Object(receiver)) => Rc::ptr_eq(&installed, receiver),
        _ => false,
    }
}

/// The `i` format, which accepts an unknown value as unknown.
fn validate_int(vm: &Vm, value: &Value) -> PyResult<()> {
    if !value.is_unknown() {
        int_argument(vm, value)?;
    }

    Ok(())
}

/// `Profiler.__init__`: `"|Odii:Profiler"` over `timer`, `timeunit`,
/// `subcalls`, `builtins`.
fn profiler_init(vm: &Vm, mut args: CallArgs) -> PyResult<Value> {
    let receiver = split_receiver(vm, &mut args, "__init__")?;
    let profiler = profiler_of(vm, &receiver, "__init__")?;

    let arguments = parse_with(vm, args, "Profiler", &["timer", "timeunit", "subcalls", "builtins"], 0, |vm, index, value| match index {
        0 => Ok(()),
        1 => c_double(vm, &value).map(drop),
        _ => validate_int(vm, &value),
    })?;
    let timer_given = matches!(arguments.first(), Some(Some(())));

    // Each later call event would call the timer, running code whose effects
    // the interpreter cannot place.
    if timer_given && is_installed(vm, &receiver) {
        return Err(vm.halt_unsupported("an external timer for an installed _lsprof.Profiler"));
    }
    profiler.external_timer.set(timer_given);

    Ok(Value::None)
}

/// `Profiler.getstats`.
fn profiler_getstats(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let profiler = this::<Profiler>(vm, &args, TYPE_NAME, "getstats")?;
    method_no_arguments(vm, &args, "getstats")?;

    if profiler.collected.get() {
        return Ok(Value::unknown("_lsprof.Profiler.getstats() (timing data)"));
    }

    Ok(vm.new_list(Vec::new()))
}

/// `Profiler.enable`: `"|ii:enable"` over `subcalls`, `builtins`, then
/// installs the profiler as the profile function's argument.
fn profiler_enable(vm: &Vm, mut args: CallArgs) -> PyResult<Value> {
    let receiver = split_receiver(vm, &mut args, "enable")?;
    let profiler = profiler_of(vm, &receiver, "enable")?;

    parse_with(vm, args, "enable", &["subcalls", "builtins"], 0, |vm, _, value| validate_int(vm, &value))?;

    if profiler.external_timer.get() {
        return Err(vm.halt_unsupported("enabling an _lsprof.Profiler with an external timer"));
    }
    // The default timer reads the host performance counter.
    vm.host_permit(HostCapability::Clock, Denial::Native, None)?;
    profiler.collected.set(true);
    profiler.enabled.set(true);
    set_profile_object(vm, Some(receiver));

    Ok(Value::None)
}

/// `Profiler.disable`: removes whichever profile function is installed.
fn profiler_disable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let profiler = this::<Profiler>(vm, &args, TYPE_NAME, "disable")?;
    method_no_arguments(vm, &args, "disable")?;

    profiler.enabled.set(false);
    set_profile_object(vm, None);

    Ok(Value::None)
}

/// `Profiler.clear`. An installed profiler goes on collecting.
fn profiler_clear(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let profiler = this::<Profiler>(vm, &args, TYPE_NAME, "clear")?;
    method_no_arguments(vm, &args, "clear")?;

    if let Some(receiver) = args.positional.first()
        && !is_installed(vm, receiver)
    {
        profiler.collected.set(false);
    }

    Ok(Value::None)
}
