//! `xxsubtype`: example subtypes of `list` and `dict` with an extra C `int`
//! field.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::class_method;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::Object;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const SPAMLIST: &str = "xxsubtype.spamlist";
const SPAMDICT: &str = "xxsubtype.spamdict";

/// The two example types.
#[derive(Clone, Copy)]
enum Spam {
    List,
    Dict,
}

impl Spam {
    /// The type name, which also keys the type in the registry.
    fn type_name(self) -> &'static str {
        match self {
            Self::List => SPAMLIST,
            Self::Dict => SPAMDICT,
        }
    }

    fn class(self, vm: &Vm) -> PyResult<ObjectRef> {
        match self {
            Self::List => native_type(vm, SPAMLIST, create_spamlist_type),
            Self::Dict => native_type(vm, SPAMDICT, create_spamdict_type),
        }
    }

    /// The `__init__` of the builtin base.
    fn base_init(self, vm: &Vm) -> PyResult<Value> {
        let base = match self {
            Self::List => &vm.types().list,
            Self::Dict => &vm.types().dict,
        };

        vm.getattr_str(&Value::Object(Rc::clone(base)), "__init__")
    }
}

/// The `state` field of each instance, keyed by the object. The list and
/// dict storage of the instances has no room for it. A missing entry is 0,
/// as allocation zeroes the field.
#[derive(Default)]
struct SpamStates {
    states: RefCell<HashMap<ObjectId, (Weak<Object>, i32)>>,
    collected_at: Cell<usize>,
}

const FUNCTIONS: &[MethodSpec] = &[function("bench", spam_bench)];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)?;

    set_attribute(vm, module, "spamlist", Value::Object(Spam::List.class(vm)?))?;

    set_attribute(vm, module, "spamdict", Value::Object(Spam::Dict.class(vm)?))
}

fn create_spamlist_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "spamlist",
            module: "xxsubtype",
            base: Some(Rc::clone(&vm.types().list)),
            layout: Layout::List,
            instance_dict: false,
            methods: &[
                method("__init__", |vm, args| spam_init(vm, args, Spam::List)),
                method("getstate", |vm, args| spam_getstate(vm, args, Spam::List)),
                method("setstate", |vm, args| spam_setstate(vm, args, Spam::List)),
                class_method("classmeth", spam_classmeth),
                static_method("staticmeth", spam_staticmeth),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "state", owner: SPAMLIST, get: |vm, getset, instance| state_get(vm, getset, instance, Spam::List), set: None })?;

    Ok(class)
}

fn create_spamdict_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "spamdict",
            module: "xxsubtype",
            base: Some(Rc::clone(&vm.types().dict)),
            layout: Layout::Dict,
            instance_dict: false,
            methods: &[
                method("__init__", |vm, args| spam_init(vm, args, Spam::Dict)),
                method("getstate", |vm, args| spam_getstate(vm, args, Spam::Dict)),
                method("setstate", |vm, args| spam_setstate(vm, args, Spam::Dict)),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "state", owner: SPAMDICT, get: |vm, getset, instance| state_get(vm, getset, instance, Spam::Dict), set: None })?;

    Ok(class)
}

/// The receiver of a method of `spam`, checked as a method descriptor does.
fn receiver(vm: &Vm, args: &CallArgs, spam: Spam, method: &str) -> PyResult<ObjectRef> {
    let type_name = spam.type_name();
    let Some(target) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{type_name}' object needs an argument")));
    };

    match target {
        Value::Object(object) if vm.is_subclass(&object.class(), &spam.class(vm)?)? => Ok(Rc::clone(object)),
        _ => Err(vm.type_error(&format!("descriptor '{method}' requires a '{type_name}' object but received a '{}'", vm.type_name(target)))),
    }
}

fn state(vm: &Vm, object: &ObjectRef) -> i32 {
    let states = vm.native_state::<SpamStates>();
    let states = states.states.borrow();

    states.get(&object.id).map_or(0, |(_, state)| *state)
}

/// Records the state of `object`. Entries of collected objects are dropped
/// whenever the table doubles.
fn set_state(vm: &Vm, object: &ObjectRef, value: i32) {
    let table = vm.native_state::<SpamStates>();
    let mut states = table.states.borrow_mut();

    states.insert(object.id, (Rc::downgrade(object), value));
    if states.len() > 2 * table.collected_at.get().max(32) {
        states.retain(|_, (owner, _)| owner.strong_count() > 0);
        table.collected_at.set(states.len());
    }
}

/// `spamlist.__init__` and `spamdict.__init__`: the base `__init__`, then a zero
/// state.
fn spam_init(vm: &Vm, args: CallArgs, spam: Spam) -> PyResult<Value> {
    let object = receiver(vm, &args, spam, "__init__")?;

    vm.call(&spam.base_init(vm)?, args)?;
    set_state(vm, &object, 0);

    Ok(Value::None)
}

fn spam_getstate(vm: &Vm, args: CallArgs, spam: Spam) -> PyResult<Value> {
    let object = receiver(vm, &args, spam, "getstate")?;
    method_arguments(vm, &args, "getstate", 0, 0)?;

    Ok(Value::Int(i64::from(state(vm, &object))))
}

fn spam_setstate(vm: &Vm, args: CallArgs, spam: Spam) -> PyResult<Value> {
    let object = receiver(vm, &args, spam, "setstate")?;
    let arguments = method_arguments(vm, &args, "setstate", 1, 1)?;

    let value = int_argument(vm, &arguments[0])?;
    // `int_argument` keeps the value within C `int`.
    set_state(vm, &object, value as i32);

    Ok(Value::None)
}

/// The shared body of `classmeth` and `staticmeth`: `(self, args, kw)` with `None` for an absent
/// receiver or keyword dict.
fn special_method(vm: &Vm, receiver: Value, args: CallArgs) -> PyResult<Value> {
    let keywords = if args.has_keywords() { Value::Object(vm.keywords_as_dict(args.keywords, args.keyword_dict)?) } else { Value::None };

    Ok(Value::tuple(vec![receiver, Value::tuple(args.positional), keywords]))
}

fn spam_classmeth(vm: &Vm, mut args: CallArgs) -> PyResult<Value> {
    let class = if args.positional.is_empty() { Value::None } else { args.positional.remove(0) };

    special_method(vm, class, args)
}

fn spam_staticmeth(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    special_method(vm, Value::None, args)
}

/// The `state` attribute, after the instance type check of its descriptor.
fn state_get(vm: &Vm, getset: &GetSet, instance: &Value, spam: Spam) -> PyResult<Value> {
    match instance {
        Value::Object(object) if vm.is_subclass(&object.class(), &spam.class(vm)?)? => Ok(Value::Int(i64::from(state(vm, object)))),
        _ => Err(descriptor_mismatch(vm, getset, instance)),
    }
}

/// `bench`: an object, a string, and an optional count, then `n` attribute
/// reads. The elapsed processor time it returns depends on the host.
fn spam_bench(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("bench() takes no keyword arguments"));
    }
    let given = args.positional.len();
    if given < 2 {
        return Err(vm.type_error(&format!("function takes at least 2 arguments ({given} given)")));
    }
    if given > 3 {
        return Err(vm.type_error(&format!("function takes at most 3 arguments ({given} given)")));
    }

    let target = &args.positional[0];
    let name = &args.positional[1];
    halt_on_unknown(name, "xxsubtype.bench() name")?;
    let Some(name) = vm.as_str_bytes(name) else {
        let shown = if name.is_none() { "None".to_owned() } else { vm.type_name(name) };
        return Err(vm.type_error(&format!("argument 2 must be string, not {shown}")));
    };
    let count = match args.positional.get(2) {
        Some(count) => int_argument(vm, count)?,
        None => 1000,
    };

    vm.host_permit(HostCapability::Clock, Denial::Native, None)?;
    for _ in 0..count.max(0) {
        vm.getattr(target, &name)?;
    }

    Ok(Value::unknown("xxsubtype.bench() (host processor time)"))
}
