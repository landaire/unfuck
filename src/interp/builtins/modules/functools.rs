//! `_functools`: `partial` and `reduce`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const PARTIAL: &str = "functools.partial";

/// A `functools.partial`. `__setstate__` can replace every field.
struct Partial {
    function: RefCell<Value>,
    arguments: RefCell<Rc<[Value]>>,
    keywords: RefCell<ObjectRef>,
}

impl_native_data!(Partial, "functools.partial");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    set_attribute(vm, module, "partial", Value::Object(native_type(vm, PARTIAL, create_partial_type)?))?;
    set_attribute(vm, module, "reduce", vm.builtin_value("reduce")?)
}

fn create_partial_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "partial",
            module: "functools",
            base: None,
            layout: Layout::Native,
            instance_dict: true,
            methods: &[static_method("__new__", partial_new), method("__call__", partial_call), method("__reduce__", partial_reduce), method("__setstate__", partial_setstate)],
        },
    )?;

    add_member(vm, &class, GetSet { name: "func", owner: PARTIAL, get: partial_func, set: None })?;
    add_member(vm, &class, GetSet { name: "args", owner: PARTIAL, get: partial_args, set: None })?;
    add_member(vm, &class, GetSet { name: "keywords", owner: PARTIAL, get: partial_keywords, set: None })?;
    add_getset(vm, &class, GetSet { name: "__dict__", owner: PARTIAL, get: partial_dict, set: Some(partial_set_dict) })?;

    Ok(class)
}

/// `partial.__new__`.
fn partial_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut positional_args = args.positional;
    if positional_args.is_empty() {
        return Err(vm.type_error("partial.__new__(X): X is not a type object"));
    }
    let Value::Object(class) = positional_args.remove(0) else {
        return Err(vm.type_error("partial.__new__(X): X is not a type object"));
    };
    if positional_args.is_empty() {
        return Err(vm.type_error("type 'partial' takes at least one argument"));
    }

    let function = positional_args.remove(0);
    if !is_callable(vm, &function)? {
        return Err(vm.type_error("the first argument must be callable"));
    }

    let keywords = vm.keywords_as_dict(args.keywords, args.keyword_dict)?;

    let data = Partial { function: RefCell::new(function), arguments: RefCell::new(positional_args.into()), keywords: RefCell::new(keywords) };

    Ok(new_native_object(vm, &class, data))
}

fn the_partial<'a>(vm: &Vm, args: &'a CallArgs, name: &str) -> PyResult<&'a Partial> {
    this::<Partial>(vm, args, PARTIAL, name)
}

/// `partial.__call__`: stored arguments first; call keywords override stored
/// keywords.
fn partial_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let partial = the_partial(vm, &args, "__call__")?;
    let function = partial.function.borrow().clone();
    let stored_keywords = Rc::clone(&partial.keywords.borrow());

    let mut arguments = partial.arguments.borrow().to_vec();
    arguments.extend(args.positional.into_iter().skip(1));

    if vm.dict_len(&stored_keywords)? == 0 {
        return vm.call(&function, CallArgs { positional: arguments, keywords: args.keywords, keyword_dict: args.keyword_dict });
    }

    let merged = vm.dict_copy(&stored_keywords)?;
    let call_keywords = vm.keywords_as_dict(args.keywords, args.keyword_dict)?;
    vm.dict_merge(&merged, &Value::Object(call_keywords), true)?;

    vm.call(&function, vm.keyword_args(arguments, merged)?)
}

/// `partial.__reduce__`: `(type, (func,), (func, args, keywords, dict))`.
fn partial_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let partial = the_partial(vm, &args, "__reduce__")?;
    let target = &args.positional[0];

    let function = partial.function.borrow().clone();
    let dict = match target {
        Value::Object(object) => object.dict().map(Value::Object).unwrap_or(Value::None),
        _ => Value::None,
    };
    let state = Value::tuple(vec![function.clone(), Value::Tuple(Rc::clone(&partial.arguments.borrow()).into()), Value::Object(Rc::clone(&partial.keywords.borrow())), dict]);

    Ok(Value::tuple(vec![Value::Object(vm.class_of(target)), Value::tuple(vec![function]), state]))
}

/// `partial.__setstate__`: `(func, args, keywords or None, dict or None)`.
fn partial_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let partial = the_partial(vm, &args, "__setstate__")?;
    let state = method_one_argument(vm, &args, "__setstate__")?;
    let invalid = || vm.type_error("invalid partial state");

    let Some(Ok([function, arguments, keywords, dict])) = vm.as_tuple(&state).map(|items| <[Value; 4]>::try_from(items.to_vec())) else {
        return Err(invalid());
    };
    let Some(arguments) = vm.as_tuple(&arguments) else {
        return Err(invalid());
    };
    let keywords = match keywords {
        Value::None => vm.new_dict(),
        Value::Object(dict) if dict.as_dict().is_some() => dict,
        _ => return Err(invalid()),
    };
    if !is_callable(vm, &function)? {
        return Err(invalid());
    }

    *partial.function.borrow_mut() = function;
    *partial.arguments.borrow_mut() = arguments;
    *partial.keywords.borrow_mut() = keywords;
    if let Value::Object(target) = &args.positional[0] {
        *target.dict.borrow_mut() = dict.as_object().map(Rc::clone);
    }

    Ok(Value::None)
}

fn partial_of<'a>(vm: &Vm, instance: &'a Value, name: &str) -> PyResult<&'a Partial> {
    native_data::<Partial>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{name}' for '{PARTIAL}' objects doesn't apply to '{}' object", vm.type_name(instance))))
}

fn partial_func(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(partial_of(vm, instance, getset.name)?.function.borrow().clone())
}

fn partial_args(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(Value::Tuple(Rc::clone(&partial_of(vm, instance, getset.name)?.arguments.borrow()).into()))
}

fn partial_keywords(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(Value::Object(Rc::clone(&partial_of(vm, instance, getset.name)?.keywords.borrow())))
}

/// Members declared read-only raise TypeError on assignment.
fn partial_dict(vm: &Vm, _getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Value::Object(object) = instance else {
        return Err(vm.type_error("partial __dict__ requires a partial"));
    };

    Ok(Value::Object(vm.instance_dict(object)?))
}

/// `partial.__dict__` assignment.
fn partial_set_dict(vm: &Vm, _getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Value::Object(object) = instance else {
        return Err(vm.type_error("partial __dict__ requires a partial"));
    };
    let Some(value) = value else {
        return Err(vm.type_error("a partial object's dictionary may not be deleted"));
    };
    let Some(dict) = value.as_object().filter(|dict| dict.as_dict().is_some()) else {
        return Err(vm.type_error("setting partial object's dictionary to a non-dict"));
    };

    *object.dict.borrow_mut() = Some(Rc::clone(dict));

    Ok(())
}
