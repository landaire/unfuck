//! Struct sequences: tuples with named fields, such as
//! `sys.flags` and `time.struct_time`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Field names and type name of a struct sequence type.
struct Shape {
    qualified: String,
    fields: &'static [&'static str],
}

#[derive(Default)]
struct StructSequenceState {
    shapes: RefCell<HashMap<ObjectId, Rc<Shape>>>,
}

/// Creates a struct sequence type `module.name` whose fields are all
/// visible in the tuple. Instances carry tuple storage, so indexing,
/// comparison, and hashing work as for tuples, but as in 2.7 the type
/// derives from `object`, not `tuple`.
pub fn new_struct_sequence_type(vm: &Vm, module: &'static str, name: &'static str, fields: &'static [&'static str]) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name,
            module,
            base: None,
            layout: Layout::Tuple,
            instance_dict: false,
            methods: &[static_method("__new__", structseq_new), method("__repr__", structseq_repr), method("__reduce__", structseq_reduce)],
        },
    )?;

    let qualified = format!("{module}.{name}");
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("struct sequence type is not a class"));
    };

    let owner = intern(&qualified);
    for field in fields {
        add_member(vm, &class, GetSet { name: field, owner, get: field_get, set: None })?;
    }

    let count = Value::Int(fields.len() as i64);
    vm.dict_set_str(&data.dict, "n_sequence_fields", count.clone())?;
    vm.dict_set_str(&data.dict, "n_fields", count)?;
    vm.dict_set_str(&data.dict, "n_unnamed_fields", Value::Int(0))?;

    vm.native_state::<StructSequenceState>().shapes.borrow_mut().insert(class.id, Rc::new(Shape { qualified, fields }));

    Ok(class)
}

/// An instance of a struct sequence type holding `values`.
pub fn new_struct_sequence(vm: &Vm, class: &ObjectRef, values: Vec<Value>) -> Value {
    Value::Object(vm.alloc(class, Payload::Tuple(values.into()), None))
}

/// A field of a struct sequence, read from its tuple storage.
fn field_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let shape = shape_of(vm, &vm.type_of(instance));
    let index = shape.and_then(|shape| shape.fields.iter().position(|field| *field == getset.name));
    let (Some(index), Some(items)) = (index, vm.as_tuple(instance)) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    items.get(index).cloned().ok_or_else(|| vm.raise(ExceptionKind::AttributeError, getset.name))
}

/// A `'static` copy of a type name for `GetSet::owner`. Struct sequence
/// types are a fixed set, so each name is stored once per process.
fn intern(name: &str) -> &'static str {
    static NAMES: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

    let mut names = NAMES.get_or_init(|| Mutex::new(HashSet::new())).lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(interned) = names.get(name) {
        return interned;
    }
    let interned: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(interned);

    interned
}

/// The shape of `class` or of the struct sequence type it derives from.
fn shape_of(vm: &Vm, class: &ObjectRef) -> Option<Rc<Shape>> {
    let state = vm.native_state::<StructSequenceState>();
    let shapes = state.shapes.borrow();

    class.as_class()?.mro().into_iter().find_map(|entry| match entry {
        MroEntry::Class(candidate) => shapes.get(&candidate.id).cloned(),
        MroEntry::Unknown(_) => None,
    })
}

/// `structseq.__new__`.
fn structseq_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut args = args;
    if args.positional.is_empty() {
        return Err(vm.type_error("structseq.__new__(): not enough arguments"));
    }
    let Value::Object(class) = args.positional.remove(0) else {
        return Err(vm.type_error("structseq.__new__(X): X is not a type object"));
    };
    let Some(shape) = shape_of(vm, &class) else {
        return Err(vm.type_error("structseq.__new__(X): X is not a struct sequence type"));
    };

    let slots = parse(vm, args, "structseq", &["sequence", "dict"], 1)?;
    let [Some(sequence), dict] = <[Option<Value>; 2]>::try_from(slots).unwrap_or([None, None]) else {
        return Err(vm.type_error("structseq() takes at least 1 argument (0 given)"));
    };

    let iterator = match vm.iter(&sequence) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => return Err(vm.type_error("constructor requires a sequence")),
        Err(signal) => return Err(signal),
    };
    let items = vm.collect(&iterator)?;

    // Every field is visible, so the dict of hidden fields has nothing to
    // supply; it is only checked.
    if dict.is_some_and(|dict| dict.as_object().and_then(|object| object.as_dict()).is_none()) {
        return Err(vm.type_error(&format!("{}() takes a dict as second arg, if any", shape.qualified)));
    }

    let expected = shape.fields.len();
    if items.len() != expected {
        return Err(vm.type_error(&format!("{}() takes a {expected}-sequence ({}-sequence given)", shape.qualified, items.len())));
    }

    Ok(new_struct_sequence(vm, &class, items))
}

/// `structseq.__repr__`.
fn structseq_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = crate::interp::builtins::receiver(vm, args, "__repr__")?;
    let class = vm.class_of(&target);
    let (Some(shape), Some(items)) = (shape_of(vm, &class), vm.as_tuple(&target)) else {
        return Err(vm.type_error("descriptor '__repr__' requires a struct sequence"));
    };

    let mut parts = Vec::with_capacity(shape.fields.len());
    for (field, item) in shape.fields.iter().zip(items.iter()) {
        parts.push(format!("{field}={}", vm.repr_text(item)?));
    }

    Ok(Value::str(&format!("{}({})", shape.qualified, parts.join(", "))))
}

/// `structseq.__reduce__`: `(type, (visible_fields, hidden_fields))`.
fn structseq_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = crate::interp::builtins::receiver(vm, args, "__reduce__")?;
    let Some(items) = vm.as_tuple(&target) else {
        return Err(vm.type_error("descriptor '__reduce__' requires a struct sequence"));
    };

    let class = Value::Object(vm.class_of(&target));
    let state = Value::tuple(vec![Value::Tuple(items), Value::Object(vm.new_dict())]);

    Ok(Value::tuple(vec![class, state]))
}
