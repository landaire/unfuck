use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::attr::MroLookup;
use crate::interp::attr::SlotKind;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::class_method;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::static_method;
use crate::interp::code::CodeFlags;
use crate::interp::code::CodeObject;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::object::ClassStyle;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::object::ModuleData;
use crate::interp::object::ModuleKind;
use crate::interp::object::ModuleState;
use crate::interp::pydict::PyDict;
use crate::interp::pyset::PySet;
use crate::interp::sequence::Resume;
use crate::interp::type_flags;
use crate::interp::type_flags::TypeFlags;
use crate::interp::value::ExceptionData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PropertyData;
use crate::interp::value::PropertyFields;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::SuperData;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Installs the methods of `object`, `type`, and the descriptor types.
/// Other builtin types install theirs from their own modules.
pub fn install_type_methods(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install(
        vm,
        &types.object,
        &[
            static_method("__new__", object_new),
            method("__init__", object_init),
            method("__setattr__", object_setattr),
            method("__delattr__", object_delattr),
            method("__getattribute__", object_getattribute),
            method("__repr__", object_repr),
            method("__str__", object_str),
            method("__hash__", object_hash),
            method("__reduce_ex__", object_reduce_ex),
            method("__reduce__", object_reduce),
            method("__format__", object_format),
            class_method("__subclasshook__", object_subclasshook),
            method("__sizeof__", object_sizeof),
        ],
    )?;

    let object_dict = Rc::clone(&types.object.as_class().expect("object is a class").dict);
    let class_descriptor = vm.new_slot_descriptor(b"object", PyBytes::from("__class__"), SlotKind::Class);
    vm.set_descriptor_owner(&class_descriptor, &types.object);
    vm.dict_set_str(&object_dict, "__class__", class_descriptor)?;

    install(
        vm,
        &types.type_,
        &[
            static_method("__new__", type_new),
            method("__init__", type_init),
            method("__call__", type_call),
            method("mro", type_mro),
            method("__subclasses__", type_subclasses),
            method("__instancecheck__", type_instancecheck),
            method("__subclasscheck__", type_subclasscheck),
        ],
    )?;

    crate::interp::builtins::exception_types::install_exception_types(vm)?;

    install(vm, &types.classobj, &[static_method("__new__", classobj_new)])?;
    install(vm, &types.instance, &[static_method("__new__", instance_new)])?;
    install(vm, &types.code, &[static_method("__new__", code_new)])?;
    install(vm, &types.module, &[static_method("__new__", module_new), method("__init__", module_init)])?;
    install(vm, &types.property, &[static_method("__new__", property_new), method("__init__", property_init), method("getter", property_getter), method("setter", property_setter), method("deleter", property_deleter)])?;
    install(vm, &types.staticmethod, &[static_method("__new__", staticmethod_new)])?;
    install(vm, &types.classmethod, &[static_method("__new__", classmethod_new)])?;
    install(vm, &types.super_, &[static_method("__new__", super_new)])?;
    install(vm, &types.generator, &[method("next", generator_next), method("send", generator_send), method("throw", generator_throw), method("close", generator_close), method("__iter__", identity)])?;
    crate::interp::builtins::iterators::install_iterator_types(vm)?;
    install(vm, &types.function, &[static_method("__new__", function_new), method("__call__", callable_call), method("__get__", function_get)])?;
    install(vm, &types.builtin_function, &[method("__call__", callable_call)])?;
    install(vm, &types.method_wrapper, &[method("__call__", callable_call)])?;
    for descriptor in [&types.method_descriptor, &types.classmethod_descriptor, &types.wrapper_descriptor] {
        install(vm, descriptor, &[method("__call__", callable_call), method("__get__", crate::interp::builtins::descriptors::descriptor_get_slot)])?;
    }
    install(vm, &types.method, &[static_method("__new__", method_new), method("__call__", callable_call), method("__get__", method_get)])?;
    install(vm, &types.staticmethod, &[method("__get__", descriptor_get_native)])?;
    install(vm, &types.classmethod, &[method("__get__", descriptor_get_native)])?;
    install(vm, &types.property, &[method("__get__", descriptor_get_native), method("__set__", property_set), method("__delete__", property_delete)])?;
    crate::interp::builtins::modules::install_descriptor_types(vm)?;

    // `types.py` takes the function and frame descriptor types from
    // `FunctionType.func_code` and `func_globals`.
    let intrinsic: [(&ObjectRef, &[u8], &[&str], &[&str]); 3] = [
        (
            &types.function,
            b"function",
            &["func_code", "__code__", "func_defaults", "__defaults__", "func_dict", "__dict__", "func_name", "__name__"],
            &["func_closure", "__closure__", "func_doc", "__doc__", "func_globals", "__globals__", "__module__"],
        ),
        (&types.frame, b"frame", &["f_locals", "f_lineno", "f_trace", "f_restricted", "f_exc_traceback", "f_exc_type", "f_exc_value"], &["f_back", "f_code", "f_builtins", "f_globals", "f_lasti"]),
        (&types.complex, b"complex", &[], &["real", "imag"]),
    ];
    for (class, owner, getsets, members) in intrinsic {
        let dict = Rc::clone(&class.as_class().expect("builtin type is a class").dict);
        let descriptors = getsets.iter().map(|name| (name, SlotKind::IntrinsicGetSet)).chain(members.iter().map(|name| (name, SlotKind::IntrinsicMember)));
        for (name, kind) in descriptors {
            let descriptor = vm.new_slot_descriptor(owner, PyBytes::from(*name), kind);
            vm.set_descriptor_owner(&descriptor, class);
            vm.dict_set_str(&dict, name, descriptor)?;
        }
    }

    crate::interp::builtins::functions::install_type_methods(vm)?;
    crate::interp::builtins::type_attributes::install_type_attributes(vm)
}

fn identity(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "__iter__")?;

    Ok(target)
}

/// The type's call behavior exposed as `__call__`.
fn callable_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__call__")?;

    vm.call(&target, rest)
}

/// Function `__get__`: binds to an instance, or makes an unbound method.
fn function_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__get__", 2, 3)?;
    let instance = Some(args[1].clone()).filter(|value| !value.is_none());
    let owner = args.get(2).cloned().filter(|value| !value.is_none());
    if instance.is_none() && owner.is_none() {
        return Err(vm.type_error("__get__(None, None) is invalid"));
    }

    Ok(vm.bind_function(&args[0], instance, owner))
}

/// `instancemethod(function, instance[, class])`.
fn method_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = crate::interp::builtins::arguments::new_class(vm, args, &vm.types().method)?;
    if rest.has_keywords() {
        return Err(vm.type_error("instancemethod does not take keyword arguments"));
    }
    let args = crate::interp::builtins::arguments::unpack(vm, rest, "instancemethod", 2, 3)?;

    if !crate::interp::builtins::modules::is_callable(vm, &args[0])? {
        return Err(vm.type_error("first argument must be callable"));
    }
    let instance = if args[1].is_none() { None } else { Some(args[1].clone()) };
    let class = args.get(2).cloned();
    if instance.is_none() && class.is_none() {
        return Err(vm.type_error("unbound methods must have non-NULL im_class"));
    }

    Ok(vm.bind_function(&args[0], instance, class))
}

/// `instancemethod.__get__`.
fn method_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__get__", 2, 3)?;
    let Some(Payload::Method(method)) = args[0].as_object().map(|object| &object.payload) else {
        return Ok(args[0].clone());
    };

    let instance = Some(args[1].clone()).filter(|value| !value.is_none());
    let owner = args.get(2).cloned().filter(|value| !value.is_none());
    if instance.is_none() && owner.is_none() {
        return Err(vm.type_error("__get__(None, None) is invalid"));
    }

    vm.method_descr_get(&args[0], method, instance, owner)
}

/// `__get__` of the builtin descriptors: the attribute protocol applied
/// directly.
fn descriptor_get_native(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__get__", 2, 3)?;
    let instance = if args[1].is_none() { None } else { Some(args[1].clone()) };
    let owner = match (args.get(2), &instance) {
        (Some(Value::Object(owner)), _) => Rc::clone(owner),
        (_, Some(value)) => vm.class_of(value),
        _ => return Err(vm.type_error("__get__(None, None) is invalid")),
    };

    vm.descriptor_get(&args[0], instance, &owner)
}

fn property_set(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__set__", 3, 3)?;
    let Some(Payload::Property(property)) = args[0].as_object().map(|object| &object.payload) else {
        return Err(vm.type_error("descriptor '__set__' requires a 'property' object"));
    };

    let setter = property.fields().setter;
    if setter.is_none() {
        return Err(vm.raise(ExceptionKind::AttributeError, "can't set attribute"));
    }
    vm.call(&setter, CallArgs::new(vec![args[1].clone(), args[2].clone()]))?;

    Ok(Value::None)
}

fn property_delete(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__delete__", 2, 2)?;
    let Some(Payload::Property(property)) = args[0].as_object().map(|object| &object.payload) else {
        return Err(vm.type_error("descriptor '__delete__' requires a 'property' object"));
    };

    let deleter = property.fields().deleter;
    if deleter.is_none() {
        return Err(vm.raise(ExceptionKind::AttributeError, "can't delete attribute"));
    }
    vm.call(&deleter, CallArgs::new(vec![args[1].clone()]))?;

    Ok(Value::None)
}

fn iterator_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "next")?;

    match vm.next(&target)? {
        Some(value) => Ok(value),
        None => Err(Signal::Raise(vm.instantiate_exception(&Rc::clone(vm.types().exception(ExceptionKind::StopIteration)), Vec::new())?)),
    }
}

fn generator_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    iterator_next(vm, args)
}

fn generator_send(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "send", 2, 2)?;
    let Value::Object(generator) = &args[0] else {
        return Err(vm.type_error("send() requires a generator"));
    };

    match vm.generator_send(generator, args[1].clone())? {
        Some(value) => Ok(value),
        None => Err(Signal::Raise(vm.instantiate_exception(&Rc::clone(vm.types().exception(ExceptionKind::StopIteration)), Vec::new())?)),
    }
}

/// Raises the exception at the generator's yield point.
fn generator_throw(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut args = positional(vm, args, "throw", 2, 4)?;
    let Value::Object(generator) = args.remove(0) else {
        return Err(vm.type_error("throw() requires a generator"));
    };

    if args.get(2).is_some_and(|traceback| !traceback.is_none() && !crate::interp::traceback::is_traceback(traceback)) {
        return Err(vm.type_error("throw() third argument must be a traceback object"));
    }
    // The generator's frame adds itself to the thrown traceback.
    let (signal, _) = vm.raise_statement(args)?;

    match vm.generator_resume(&generator, Resume::Throw(signal))? {
        Some(value) => Ok(value),
        None => Err(Signal::Raise(vm.instantiate_exception(&Rc::clone(vm.types().exception(ExceptionKind::StopIteration)), Vec::new())?)),
    }
}

/// Throws GeneratorExit and expects the generator to finish.
fn generator_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "close")?;
    let Value::Object(generator) = &target else {
        return Err(vm.type_error("close() requires a generator"));
    };

    if let Payload::Generator(data) = &generator.payload {
        if matches!(data.borrow().state, crate::interp::object::GeneratorState::Created(_) | crate::interp::object::GeneratorState::Finished) {
            data.borrow_mut().finish();
            return Ok(Value::None);
        }
    }

    let exit = vm.instantiate_exception(&Rc::clone(vm.types().exception(ExceptionKind::GeneratorExit)), Vec::new())?;
    match vm.generator_resume(generator, Resume::Throw(Signal::Raise(exit))) {
        Ok(Some(_)) => Err(vm.raise(ExceptionKind::RuntimeError, "generator ignored GeneratorExit")),
        Ok(None) => Ok(Value::None),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::GeneratorExit) => Ok(Value::None),
        Err(error) => Err(error),
    }
}

/// `__reduce__(proto=0)`.
fn object_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__reduce__")?;
    let protocol = reduce_protocol(vm, rest, "__reduce__")?;

    common_reduce(vm, &target, protocol)
}

/// A `__reduce__` overriding `object.__reduce__` takes precedence over
/// the generic protocol.
fn object_reduce_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__reduce_ex__")?;
    let protocol = reduce_protocol(vm, rest, "__reduce_ex__")?;

    if let Some(reduce) = attribute_or_none(vm, &target, "__reduce__")? {
        let class = vm.getattr_str(&target, "__class__")?;
        let class_reduce = vm.getattr_str(&class, "__reduce__")?;
        let object_reduce = vm.dict_get_str(&vm.types().object.as_class().expect("object is a class").dict, "__reduce__")?;
        let overridden = match (&class_reduce, &object_reduce) {
            (Value::Object(found), Some(Value::Object(base))) => !Rc::ptr_eq(found, base),
            _ => true,
        };
        if overridden {
            return vm.call0(&reduce);
        }
    }

    common_reduce(vm, &target, protocol)
}

/// The optional `int` protocol argument.
fn reduce_protocol(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Option<i64>> {
    let mut arguments = crate::interp::builtins::positional(vm, args, name, 0, 1)?;

    let value = match arguments.pop() {
        None => return Ok(Some(0)),
        Some(Value::Unknown(_)) => return Ok(None),
        Some(value) => value,
    };
    let Some(integral) = vm.as_integral(&value) else {
        return Err(vm.type_error("an integer is required"));
    };
    let wide = match integral {
        numbers::Integral::Int(protocol) => Some(protocol),
        numbers::Integral::Long(protocol) => i64::try_from(&protocol).ok(),
    };

    match wide.and_then(|protocol| i32::try_from(protocol).ok()) {
        Some(protocol) => Ok(Some(i64::from(protocol))),
        None if wide.is_some_and(|protocol| protocol < 0) => Err(vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum")),
        None => Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum")),
    }
}

/// `_common_reduce`: protocol 2 and above reduce through `copy_reg.__newobj__`,
/// lower protocols through `copy_reg._reduce_ex`.
fn common_reduce(vm: &Vm, target: &Value, protocol: Option<i64>) -> PyResult<Value> {
    let Some(protocol) = protocol else {
        return Ok(Value::unknown("object.__reduce_ex__ with an unknown protocol"));
    };

    let copy_reg = vm.import_module("copy_reg")?;
    if protocol >= 2 {
        return reduce_2(vm, target, &copy_reg);
    }

    let reduce_ex = vm.getattr_str(&copy_reg, "_reduce_ex")?;

    vm.call(&reduce_ex, CallArgs::new(vec![target.clone(), Value::Int(protocol)]))
}

/// `reduce_2`: `(copy_reg.__newobj__, (cls,) + args, state, listitems,
/// dictitems)`.
fn reduce_2(vm: &Vm, target: &Value, copy_reg: &Value) -> PyResult<Value> {
    let class = vm.getattr_str(target, "__class__")?;

    let mut new_arguments = vec![class.clone()];
    if let Some(getnewargs) = attribute_or_none(vm, target, "__getnewargs__")? {
        let arguments = vm.call0(&getnewargs)?;
        let Some(items) = vm.as_tuple(&arguments) else {
            return Err(vm.type_error(&format!("__getnewargs__ should return a tuple, not '{}'", vm.type_name(&arguments))));
        };
        new_arguments.extend(items.iter().cloned());
    }

    let state = match attribute_or_none(vm, target, "__getstate__")? {
        Some(getstate) => vm.call0(&getstate)?,
        None => default_state(vm, target, &class)?,
    };

    let list_items = if vm.isinstance(target, &Value::Object(Rc::clone(&vm.types().list)))? { vm.iter(target)? } else { Value::None };
    let dict_items = if vm.isinstance(target, &Value::Object(Rc::clone(&vm.types().dict)))? { vm.call0(&vm.getattr_str(target, "iteritems")?)? } else { Value::None };

    let newobj = vm.getattr_str(copy_reg, "__newobj__")?;

    Ok(Value::tuple(vec![newobj, Value::tuple(new_arguments), state, list_items, dict_items]))
}

/// The state `reduce_2` saves without `__getstate__`: the instance dict,
/// paired with a dict of the `__slots__` values that are set.
fn default_state(vm: &Vm, target: &Value, class: &Value) -> PyResult<Value> {
    let instance_dict = attribute_or_none(vm, target, "__dict__")?.unwrap_or(Value::None);

    let names = slot_names(vm, class)?;
    let Some(names) = names else {
        return Ok(instance_dict);
    };

    let slots = vm.new_dict();
    let mut found = 0;
    for name in names {
        let Some(text) = vm.as_str_bytes(&name) else {
            return Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(&name))));
        };
        if let Some(value) = attribute_or_none(vm, target, &text.to_string_lossy())? {
            vm.dict_set(&slots, name, value)?;
            found += 1;
        }
    }

    if found == 0 {
        return Ok(instance_dict);
    }

    Ok(Value::tuple(vec![instance_dict, Value::Object(slots)]))
}

/// The `__slotnames__` list cached in the class dict, else
/// `copy_reg._slotnames(cls)`.
fn slot_names(vm: &Vm, class: &Value) -> PyResult<Option<Vec<Value>>> {
    let Some(class_object) = class.as_object().filter(|object| object.as_class().is_some()) else {
        return Ok(None);
    };

    let dict = Rc::clone(&class_object.as_class().expect("checked to be a class").dict);
    let cached = vm.dict_get_str(&dict, "__slotnames__")?;
    let names = match cached {
        Some(names) if vm.as_list(&names).is_some() => names,
        _ => {
            let copy_reg = vm.import_module("copy_reg")?;
            let compute = vm.getattr_str(&copy_reg, "_slotnames")?;
            vm.call1(&compute, class.clone())?
        }
    };

    if names.is_none() || names.is_unknown() {
        return Ok(None);
    }
    let Some(items) = vm.as_list(&names) else {
        return Err(vm.type_error("copy_reg._slotnames didn't return a list or None"));
    };

    Ok(Some(items))
}

/// An attribute lookup whose failure the copy protocol clears.
fn attribute_or_none(vm: &Vm, target: &Value, name: &str) -> PyResult<Option<Value>> {
    match vm.getattr_str(target, name) {
        Ok(value) => Ok(Some(value)),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

fn object_sizeof(_vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Ok(Value::unknown("object.__sizeof__"))
}

fn object_subclasshook(_vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Ok(Value::NotImplemented)
}

/// `object.__format__`: formats the string form of `self`.
fn object_format(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__format__", 2, 2)?;

    vm.format_string_form(&args[0], &args[1])
}

/// `object.__new__(cls, ...)`: allocates an instance with the storage of the
/// class's solid base.
pub fn object_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(Value::Object(class)) = args.positional.first().cloned() else {
        return Err(vm.type_error("object.__new__(X): X is not a type object"));
    };

    let excess = args.positional.len() > 1 || args.has_keywords();
    if excess {
        let overrides_new = !vm.defined_by_object(&class, "__new__")?;
        let overrides_init = !vm.defined_by_object(&class, "__init__")?;
        // Overriding both only warns in CPython 2.7.
        if !(overrides_new && overrides_init) && (overrides_new || !overrides_init) {
            return Err(vm.type_error("object() takes no parameters"));
        }
    }

    let is_abstract = class.as_class().and_then(|data| data.flags.as_ref()).is_some_and(|flags| flags.get().contains(TypeFlags::IS_ABSTRACT));
    if is_abstract {
        return Err(abstract_instantiation_error(vm, &class)?);
    }

    vm.instantiate_layout(&class)
}

/// The error `object.__new__` raises for an abstract class:
/// `", ".join(sorted(cls.__abstractmethods__))` names the methods.
fn abstract_instantiation_error(vm: &Vm, class: &ObjectRef) -> PyResult<Signal> {
    let methods = match class.as_class() {
        Some(data) if !Rc::ptr_eq(class, &vm.types().type_) => vm.dict_get_str(&data.dict, "__abstractmethods__")?,
        _ => None,
    };
    let Some(methods) = methods else {
        return Err(vm.raise(ExceptionKind::AttributeError, "__abstractmethods__"));
    };
    let Some(sorted) = vm.dict_get_str(&vm.builtins_dict(), "sorted")? else {
        return Err(vm.raise(ExceptionKind::SystemError, "error return without exception set"));
    };
    let sorted_methods = vm.call1(&sorted, methods)?;
    let join = vm.getattr_str(&Value::str(", "), "join")?;
    let joined = vm.call1(&join, sorted_methods)?;
    let joined = match vm.as_text(&joined) {
        Some(text) => vm.encode_default(&text)?,
        None => joined,
    };
    let Some(joined) = vm.as_str_bytes(&joined) else {
        return Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(&joined))));
    };

    Ok(vm.type_error(&format!("Can't instantiate abstract class {} with abstract methods {}", vm.class_name(class), joined.to_string_lossy())))
}

impl Vm {
    /// Creates a bare instance of `class` with empty builtin storage.
    pub fn instantiate_layout(&self, class: &ObjectRef) -> PyResult<Value> {
        let Some(data) = class.as_class() else {
            return Err(self.type_error("object.__new__(X): X is not a type object"));
        };

        let payload = match data.layout {
            Layout::Object | Layout::Native | Layout::Function | Layout::Module | Layout::Property => Payload::Instance,
            Layout::List => Payload::List(RefCell::new(Vec::new())),
            Layout::Dict => Payload::Dict(RefCell::new(PyDict::new())),
            Layout::Set => Payload::Set(RefCell::new(PySet::new())),
            Layout::Exception => Payload::Exception(ExceptionData::new(Value::tuple(Vec::new()))),
            Layout::Int | Layout::Long | Layout::Float | Layout::Str | Layout::Unicode | Layout::Tuple | Layout::FrozenSet | Layout::Type => {
                return Err(self.type_error(&format!("object.__new__({}) is not safe, use {}.__new__()", self.class_name(class), self.class_name(class))));
            }
        };

        // Exceptions create their dict on first use, which `__reduce__`
        // observes.
        let eager = data.instance_dict && data.layout != Layout::Exception;
        let dict = if eager { Some(self.new_dict()) } else { None };

        Ok(Value::Object(self.alloc(class, payload, dict)))
    }

    /// Calls a class: `type.__call__` for new-style classes and instance
    /// creation for classic classes.
    pub fn call_class(&self, class: &ObjectRef, args: CallArgs) -> PyResult<Value> {
        if self.is_classic_class(class) {
            return self.instantiate_classic(class, args);
        }

        let metaclass = class.class();
        if !Rc::ptr_eq(&metaclass, &self.types().type_) {
            let found = self.lookup_mro(&metaclass, "__call__")?;
            type_flags::note_slot_lookup(&metaclass, &found);
            if let MroLookup::Found { value: hook, owner } = found {
                if !self.is_builtin_type(&owner) {
                    let hook = self.descriptor_get(&hook, Some(Value::Object(Rc::clone(class))), &metaclass)?;
                    return self.call(&hook, args);
                }
            }
        }

        self.type_call_default(class, args)
    }

    fn type_call_default(&self, class: &ObjectRef, args: CallArgs) -> PyResult<Value> {
        if Rc::ptr_eq(class, &self.types().type_) && args.positional.len() == 1 && !args.has_keywords() {
            return Ok(self.type_value(&args.positional[0]));
        }

        // `__new__` is read through the type's attribute lookup.
        let found = self.lookup_mro(class, "__new__")?;
        type_flags::note_slot_lookup(&class.class(), &found);
        type_flags::note_slot_lookup(class, &found);
        let instance = match found {
            // A class without a constructor passes that to subclasses that do not
            // define `__new__`.
            MroLookup::Found { owner, .. } if Rc::ptr_eq(&owner, &self.types().object) && self.inherits_null_new(class) => {
                return Err(self.type_error(&format!("cannot create '{}' instances", self.class_name(class))));
            }
            MroLookup::Found { value: new, .. } => {
                let new = self.descriptor_get(&new, None, class)?;
                let mut new_args = args.clone();
                new_args.positional.insert(0, Value::Object(Rc::clone(class)));
                self.call_slot(&new, new_args)?
            }
            // A native base whose allocator is not emulated: allocate a plain
            // instance so attributes set by Python code stay visible.
            MroLookup::Unknown(_) => self.instantiate_layout(class)?,
            MroLookup::Missing => return Err(self.type_error(&format!("cannot create '{}' instances", self.class_name(class)))),
        };

        if instance.is_unknown() || !self.is_instance_of(&instance, class)? {
            return Ok(instance);
        }

        let instance_class = self.class_of(&instance);
        let found = self.lookup_mro(&instance_class, "__init__")?;
        type_flags::note_slot_lookup(&instance_class, &found);
        match found {
            MroLookup::Found { value: init, .. } => {
                let init = self.descriptor_get(&init, Some(instance.clone()), &instance_class)?;
                let result = self.call_slot(&init, args)?;
                // An `__init__` whose outcome is unknown, such as one that asks
                // the host for a resource, leaves the constructed object unknown.
                if result.is_unknown() {
                    return Ok(result);
                }
                if !result.is_none() {
                    return Err(self.type_error("__init__() should return None"));
                }
            }
            MroLookup::Unknown(_) | MroLookup::Missing => {}
        }

        Ok(instance)
    }

    /// `type(value)`; unknown for an unknown value.
    pub fn type_value(&self, value: &Value) -> Value {
        match value {
            Value::Unknown(unknown) => Value::unknown(format!("type({})", unknown.origin)),
            _ => Value::Object(self.type_of(value)),
        }
    }

    fn instantiate_classic(&self, class: &ObjectRef, args: CallArgs) -> PyResult<Value> {
        let dict = self.new_dict();
        let instance = Value::Object(self.alloc(class, Payload::Instance, Some(dict)));

        match self.lookup_mro(class, "__init__")? {
            MroLookup::Found { value: init, .. } => {
                let init = self.descriptor_get(&init, Some(instance.clone()), class)?;
                let result = self.call(&init, args)?;
                if !result.is_none() && !result.is_unknown() {
                    return Err(self.type_error("__init__() should return None"));
                }
            }
            MroLookup::Unknown(_) => {}
            MroLookup::Missing => {
                if !args.positional.is_empty() || args.has_keywords() {
                    return Err(self.type_error("this constructor takes no arguments"));
                }
            }
        }

        Ok(instance)
    }

    /// Attributes builtin objects expose without a class dict entry:
    /// function, method, code, and exception fields.
    pub fn intrinsic_attribute(&self, object: &ObjectRef, name: &str) -> PyResult<Option<Value>> {
        let value = match &object.payload {
            Payload::Function(function) => match name {
                "__name__" | "func_name" => Value::Str(function.name.borrow().clone()),
                "__doc__" | "func_doc" => function.doc.borrow().clone(),
                "__module__" => function.module.borrow().clone(),
                "__globals__" | "func_globals" => Value::Object(Rc::clone(&function.globals)),
                "__code__" | "func_code" => Value::Object(Rc::clone(&function.code_object)),
                "__defaults__" | "func_defaults" => {
                    function.defaults.borrow().clone().map_or(Value::None, Value::tuple)
                }
                "__closure__" | "func_closure" => {
                    let cells = function.closure.as_ref().map(|cells| cells.iter().map(|cell| Value::Object(Rc::clone(cell))).collect());
                    cells.map_or(Value::None, Value::tuple)
                }
                "__dict__" | "func_dict" => Value::Object(self.instance_dict(object)?),
                _ => return Ok(None),
            },
            Payload::Method(method) => match name {
                "im_func" | "__func__" => method.function.clone(),
                "im_self" | "__self__" => method.receiver.clone().unwrap_or(Value::None),
                "im_class" => method.class.clone().unwrap_or(Value::None),
                "__class__" => Value::Object(object.class()),
                "__doc__" => return self.getattr_opt(&method.function, &PyBytes::from(name)),
                // The type's attributes come before those of `im_func`.
                _ => {
                    let class = object.class();
                    return match self.lookup_mro(&class, name)? {
                        MroLookup::Found { value, .. } => Ok(Some(self.descriptor_get(&value, Some(Value::Object(Rc::clone(object))), &class)?)),
                        MroLookup::Unknown(unknown) => Ok(Some(Value::Unknown(unknown))),
                        MroLookup::Missing => self.getattr_opt(&method.function, &PyBytes::from(name)),
                    };
                }
            },
            Payload::NativeFunction(native) => return Ok(crate::interp::builtins::descriptors::native_attribute(self, object, native, name)),
            Payload::Complex(number) => match name {
                "real" => Value::Float(number.real),
                "imag" => Value::Float(number.imag),
                _ => return Ok(None),
            },
            Payload::Generator(generator) => {
                let generator = generator.borrow();
                match name {
                    "gi_frame" => match &generator.activation {
                        Some(activation) => self.frame_object_of(activation),
                        None => Value::None,
                    },
                    "gi_running" => Value::Bool(matches!(generator.state, crate::interp::object::GeneratorState::Running)),
                    "gi_code" => Value::Object(Rc::clone(&generator.code_object)),
                    "__name__" => Value::Str(generator.name.clone()),
                    _ => return Ok(None),
                }
            }
            Payload::Code(code) => match name {
                "co_name" => Value::Str(code.name.clone()),
                "co_filename" => Value::Str(code.filename.clone()),
                "co_argcount" => Value::Int(i64::from(code.argcount)),
                "co_nlocals" => Value::Int(i64::from(code.nlocals)),
                "co_stacksize" => Value::Int(i64::from(code.stacksize.cast_signed())),
                "co_flags" => Value::Int(i64::from(code.flags.0.cast_signed())),
                "co_firstlineno" => Value::Int(i64::from(code.firstlineno.cast_signed())),
                "co_lnotab" => Value::Str(code.lnotab.clone()),
                "co_varnames" => Value::tuple(code.varnames.iter().cloned().map(Value::Str).collect()),
                "co_names" => Value::tuple(code.names.iter().cloned().map(Value::Str).collect()),
                "co_freevars" => Value::tuple(code.freevars.iter().cloned().map(Value::Str).collect()),
                "co_cellvars" => Value::tuple(code.cellvars.iter().cloned().map(Value::Str).collect()),
                "co_consts" => Value::tuple(code.consts.clone()),
                "co_code" => Value::Str(PyBytes::new(code.code.clone())),
                _ => return Ok(None),
            },
            Payload::Property(property) => match name {
                "fget" => property.fields().getter,
                "fset" => property.fields().setter,
                "fdel" => property.fields().deleter,
                "__doc__" => property.fields().doc,
                _ => return Ok(None),
            },
            Payload::StaticMethod(function) | Payload::ClassMethod(function) => match name {
                "__func__" => function.clone(),
                _ => return Ok(None),
            },
            Payload::Slice(slice) => match name {
                "start" => slice.start.clone(),
                "stop" => slice.stop.clone(),
                "step" => slice.step.clone(),
                _ => return Ok(None),
            },
            Payload::Cell(content) => match name {
                "cell_contents" => match content.borrow().clone() {
                    Some(value) => value,
                    None => return Err(self.raise(ExceptionKind::ValueError, "Cell is empty")),
                },
                _ => return Ok(None),
            },
            Payload::Super(data) => {
                if name == "__thisclass__" {
                    Value::Object(Rc::clone(&data.class))
                } else if name == "__self__" {
                    data.receiver.clone().unwrap_or(Value::None)
                } else {
                    return self.super_getattr(object, data, name);
                }
            }
            Payload::Module(_) if name == "__dict__" => object.dict().map_or(Value::None, Value::Object),
            Payload::Frame(activation) => match name {
                "f_back" => match activation.back() {
                    Some(back) => self.frame_object_of(&back),
                    None => Value::None,
                },
                "f_code" => Value::Object(Rc::clone(&activation.code_object)),
                "f_globals" => Value::Object(Rc::clone(&activation.globals)),
                "f_builtins" => Value::Object(Rc::clone(&activation.builtins)),
                "f_locals" => activation.locals_value(self)?,
                "f_lasti" => Value::Int(activation.lasti()),
                "f_lineno" => Value::Int(i64::from(activation.line_number())),
                "f_restricted" => Value::Bool(false),
                "f_trace" => Value::None,
                // The exception a frame saved when it first caught one.
                "f_exc_type" | "f_exc_value" | "f_exc_traceback" => Value::unknown(format!("frame.{name}")),
                _ => return Ok(None),
            },
            _ => return Ok(None),
        };

        Ok(Some(value))
    }

    /// Assigns attributes builtin objects store outside their dict. Returns
    /// whether the assignment was handled.
    pub fn set_intrinsic_attribute(&self, object: &ObjectRef, name: &str, value: &Value) -> PyResult<bool> {
        match &object.payload {
            Payload::Function(function) => match name {
                "__name__" | "func_name" => {
                    // Assigning `__name__` keeps the given object.
                    let Some(name) = self.as_str_bytes(value) else {
                        return Err(self.type_error("__name__ must be set to a string object"));
                    };
                    *function.name.borrow_mut() = name;
                    Ok(true)
                }
                "__doc__" | "func_doc" => {
                    *function.doc.borrow_mut() = value.clone();
                    Ok(true)
                }
                "__module__" => {
                    *function.module.borrow_mut() = value.clone();
                    Ok(true)
                }
                "__defaults__" | "func_defaults" => {
                    let defaults = match value {
                        Value::None => None,
                        Value::Tuple(items) => Some(items.to_vec()),
                        _ => return Err(self.type_error("__defaults__ must be set to a tuple object")),
                    };
                    *function.defaults.borrow_mut() = defaults;
                    Ok(true)
                }
                "__dict__" | "func_dict" => {
                    let Value::Object(dict) = value else {
                        return Err(self.type_error("setting function's dictionary to a non-dict"));
                    };
                    *object.dict.borrow_mut() = Some(Rc::clone(dict));
                    Ok(true)
                }
                _ => Ok(false),
            },
            _ => Ok(false),
        }
    }

    fn super_getattr(&self, object: &ObjectRef, data: &SuperData, name: &str) -> PyResult<Option<Value>> {
        let Some(start_class) = &data.receiver_class else {
            return Ok(data.receiver.as_ref().filter(|receiver| receiver.is_unknown()).cloned());
        };
        if name == "__class__" {
            return Ok(Some(Value::Object(object.class())));
        }

        let Some(start_data) = start_class.as_class() else {
            return Ok(None);
        };
        let order = match start_data.style {
            ClassStyle::NewStyle => start_data.mro(),
            ClassStyle::Classic => self.classic_order(start_class),
        };

        let mut after = false;
        let key = Value::str(name);
        for entry in order {
            match entry {
                MroEntry::Class(candidate) => {
                    if !after {
                        after = Rc::ptr_eq(&candidate, &data.class);
                        continue;
                    }
                    let Some(candidate_data) = candidate.as_class() else {
                        continue;
                    };
                    let Some(found) = self.dict_get(&candidate_data.dict, &key)? else {
                        continue;
                    };
                    // `super` passes no instance when the receiver is the class itself
                    // (`super(B, B)`).
                    let instance = match &data.receiver {
                        Some(Value::Object(receiver)) if Rc::ptr_eq(receiver, start_class) => None,
                        Some(receiver) => Some(receiver.clone()),
                        None => None,
                    };
                    return Ok(Some(self.descriptor_get(&found, instance, start_class)?));
                }
                MroEntry::Unknown(unknown) => {
                    if after {
                        return Ok(Some(Value::Unknown(unknown)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// `str()` of an exception: the conversion its builtin class provides.
    pub fn exception_text(&self, exception: &Value) -> PyResult<Value> {
        let text = crate::interp::builtins::exception_types::exception_str(self, exception)?;
        // `str()` encodes a `unicode` the conversion returns and rejects anything
        // but strings.
        if let Some(unicode) = self.as_text(&text) {
            return self.encode_default(&unicode);
        }
        if text.is_unknown() || self.as_str_bytes(&text).is_some() {
            return Ok(text);
        }

        Err(self.type_error(&format!("__str__ returned non-string (type {})", self.type_name(&text))))
    }

    /// Whether `name` resolves on `class` to the definition in `object`.
    /// A base produced by native code counts as overriding it.
    pub fn defined_by_object(&self, class: &ObjectRef, name: &str) -> PyResult<bool> {
        match self.lookup_mro(class, name)? {
            MroLookup::Found { owner, .. } => Ok(Rc::ptr_eq(&owner, &self.types().object)),
            MroLookup::Unknown(_) | MroLookup::Missing => Ok(false),
        }
    }

    /// `repr(value)` as a `str`.
    pub fn repr(&self, value: &Value) -> PyResult<Value> {
        if value.is_unknown() {
            return Ok(value.clone());
        }

        if let Some(method) = self.user_override(value, "__repr__")? {
            let result = self.call0(&method)?;
            return self.ensure_str_result(result, "__repr__");
        }
        if let Value::Bool(flag) = value {
            return Ok(self.bool_text(*flag));
        }

        Ok(Value::Str(PyBytes::new(self.builtin_repr(value)?.into_bytes())))
    }

    /// The interned `'True'` or `'False'`.
    fn bool_text(&self, flag: bool) -> Value {
        let text = if flag { "True" } else { "False" };

        Value::Str(self.intern(&PyBytes::from(text)))
    }

    fn ensure_str_result(&self, result: Value, method: &str) -> PyResult<Value> {
        if result.is_unknown() || self.as_str_bytes(&result).is_some() {
            return Ok(result);
        }
        if let Some(text) = self.as_text(&result) {
            return self.encode_default(&text);
        }

        Err(self.type_error(&format!("{method} returned non-string (type {})", self.type_name(&result))))
    }

    /// Encodes unicode with the default encoding (ASCII).
    pub fn encode_default(&self, text: &PyText) -> PyResult<Value> {
        Ok(Value::Str(crate::interp::builtins::text::codecs::encode_default(self, text.units())?))
    }

    /// `str(value)`.
    pub fn to_str(&self, value: &Value) -> PyResult<Value> {
        if value.is_unknown() {
            return Ok(value.clone());
        }
        if let Value::Str(_) = value {
            return Ok(value.clone());
        }
        if let Value::Unicode(text) = value {
            return self.encode_default(text);
        }

        self.with_depth_in(" while getting the str of an object", || self.str_slot(value))
    }

    /// The type's string conversion, past the exact `str` and `unicode`
    /// cases.
    fn str_slot(&self, value: &Value) -> PyResult<Value> {
        if let Some(method) = self.user_override(value, "__str__")? {
            let result = self.call0(&method)?;
            return self.ensure_str_result(result, "__str__");
        }

        // A subclass instance is copied into an exact `str`.
        if let Some(bytes) = self.as_str_bytes(value) {
            return Ok(Value::Str(PyBytes::new(bytes.as_bytes())));
        }
        if let Value::Bool(flag) = value {
            return Ok(self.bool_text(*flag));
        }
        if let Some(numbers::Integral::Long(number)) = self.as_integral(value) {
            return Ok(Value::Str(PyBytes::new_unshared(number.to_string().into_bytes())));
        }
        if let Value::Object(object) = value {
            if let Payload::DictProxy(dict) = &object.payload {
                return self.to_str(&Value::Object(Rc::clone(dict)));
            }
        }
        if let Some(text) = self.as_text(value) {
            return self.encode_default(&text);
        }
        if let Some(number) = self.as_float(value) {
            return Ok(Value::str(&numbers::float_str(number)));
        }
        if let Some(number) = self.as_complex(value) {
            return Ok(Value::str(&number.str()));
        }

        if let Value::Object(object) = value {
            if let Payload::Exception(..) = &object.payload {
                return self.exception_text(value);
            }
        }

        if self.user_override(value, "__repr__")?.is_some() {
            return self.repr(value);
        }

        Ok(Value::Str(PyBytes::new(self.builtin_repr(value)?.into_bytes())))
    }

    /// Text of `repr` for builtin values, recursing through containers. A
    /// container already being rendered prints as `[...]`, `{...}`, or
    /// `set(...)`.
    pub fn builtin_repr(&self, value: &Value) -> PyResult<String> {
        if let Value::Object(object) = value {
            let marker = match &object.payload {
                Payload::List(_) => Some("[...]".to_owned()),
                Payload::Dict(_) => Some("{...}".to_owned()),
                Payload::Set(_) | Payload::FrozenSet(_) => Some(format!("{}(...)", self.class_name(&object.class()))),
                _ => None,
            };
            if let Some(marker) = marker {
                if !self.repr_enter(object) {
                    return Ok(marker);
                }
                let result = self.builtin_repr_unguarded(value);
                self.repr_leave(object);
                return result;
            }
        }

        self.builtin_repr_unguarded(value)
    }

    fn builtin_repr_unguarded(&self, value: &Value) -> PyResult<String> {
        const LIST: &str = " while getting the repr of a list";
        const TUPLE: &str = " while getting the repr of a tuple";

        let repr_items = |items: &[Value], context: &str| -> PyResult<Vec<String>> { items.iter().map(|item| self.with_depth_in(context, || self.repr_text(item))).collect() };

        let text = match value {
            Value::None => "None".to_owned(),
            Value::NotImplemented => "NotImplemented".to_owned(),
            Value::Ellipsis => "Ellipsis".to_owned(),
            Value::Bool(flag) => if *flag { "True" } else { "False" }.to_owned(),
            Value::Int(number) => number.to_string(),
            Value::Long(number) => format!("{number}L"),
            Value::Float(number) => numbers::float_repr(*number),
            Value::Str(bytes) => crate::interp::builtins::functions::repr_bytes(bytes.as_bytes()),
            Value::Unicode(text) => crate::interp::builtins::functions::repr_unicode(text.units()),
            Value::Tuple(items) => {
                let parts = repr_items(items, TUPLE)?;
                if parts.len() == 1 { format!("({},)", parts[0]) } else { format!("({})", parts.join(", ")) }
            }
            Value::Unknown(unknown) => format!("<unknown {}>", unknown.origin),
            Value::Object(object) => {
                let class = object.class();
                let class_name = class.as_class().map(|data| data.name().to_string_lossy()).unwrap_or_default();
                let module = match self.static_module(&class) {
                    Some(module) => Some(module.to_owned()),
                    None => self.lookup_mro(&class, "__module__").ok().and_then(|found| match found {
                        MroLookup::Found { value, .. } => self.text_of(&value),
                        _ => None,
                    }),
                };
                let qualified = match &module {
                    Some(module) if module != "__builtin__" => format!("{module}.{class_name}"),
                    _ => class_name.clone(),
                };
                let address = || self.pointer_text(self.address_of(object));

                match &object.payload {
                    Payload::Int(number) => number.to_string(),
                    Payload::Long(number) => format!("{number}L"),
                    Payload::Float(number) => numbers::float_repr(*number),
                    Payload::Complex(number) => number.repr(),
                    Payload::Str(bytes) => crate::interp::builtins::functions::repr_bytes(bytes.as_bytes()),
                    Payload::Unicode(text) => crate::interp::builtins::functions::repr_unicode(text.units()),
                    Payload::Tuple(items) => self.builtin_repr(&Value::Tuple(items.clone()))?,
                    Payload::List(items) => {
                        let items = items.borrow().clone();
                        format!("[{}]", repr_items(&items, LIST)?.join(", "))
                    }
                    Payload::Dict(_) => {
                        let mut parts = Vec::new();
                        // The dict repr has no recursion check; only the native stack bounds
                        // the nesting, as in CPython.
                        for (key, item) in self.dict_items(object)? {
                            parts.push(format!("{}: {}", self.repr_text(&key)?, self.repr_text(&item)?));
                        }
                        format!("{{{}}}", parts.join(", "))
                    }
                    Payload::Set(_) | Payload::FrozenSet(_) => {
                        let items = self.set_items(value).unwrap_or_default();
                        let name = if matches!(object.payload, Payload::Set(_)) { "set" } else { "frozenset" };
                        let name = if self.is_builtin_type(&class) { name.to_owned() } else { class_name.clone() };
                        // The set repr renders the items as a list.
                        format!("{name}([{}])", repr_items(&items, LIST)?.join(", "))
                    }
                    Payload::Exception(data) => {
                        let args = data.args.borrow().clone();
                        let parts = self.as_tuple(&args).map(|items| items.to_vec()).unwrap_or_default();
                        let inner = repr_items(&parts, TUPLE)?;
                        // The exception repr drops the module part of the type name.
                        let short = class_name.rsplit('.').next().unwrap_or_default();
                        if inner.len() == 1 { format!("{short}({},)", inner[0]) } else { format!("{short}({})", inner.join(", ")) }
                    }
                    Payload::Function(function) => format!("<function {} at {}>", function.name.borrow().to_string_lossy(), address()),
                    Payload::NativeFunction(native) => crate::interp::builtins::descriptors::callable_repr(self, object, native),
                    Payload::Method(method) => self.method_repr(method)?,
                    Payload::Class(data) => {
                        let module = match data.style {
                            ClassStyle::NewStyle => self.type_module(object, data).ok(),
                            ClassStyle::Classic => self.dict_get_str(&data.dict, "__module__")?,
                        };
                        let module = module.and_then(|value| self.text_of(&value));
                        let name = data.name().to_string_lossy();
                        let full = match module {
                            Some(module) if module != "__builtin__" => format!("{module}.{name}"),
                            _ => name,
                        };
                        match data.style {
                            ClassStyle::Classic => format!("<class {full} at {}>", address()),
                            ClassStyle::NewStyle if data.builtin => format!("<type '{full}'>"),
                            ClassStyle::NewStyle => format!("<class '{full}'>"),
                        }
                    }
                    Payload::Module(_) => module_repr(self, object)?,
                    Payload::XRange(range) => {
                        if range.step == 1 && range.start == 0 {
                            format!("xrange({})", range.length)
                        } else if range.step == 1 {
                            format!("xrange({}, {})", range.start, range.start + range.length)
                        } else {
                            // The range repr computes the end in C long arithmetic, which wraps.
                            let end = range.start.wrapping_add(range.length.wrapping_mul(range.step));
                            let end = if self.config.long_width == crate::interp::hash::LongWidth::Bits32 { i64::from(end as i32) } else { end };
                            format!("xrange({}, {end}, {})", range.start, range.step)
                        }
                    }
                    Payload::Slice(slice) => format!("slice({}, {}, {})", self.repr_text(&slice.start)?, self.repr_text(&slice.stop)?, self.repr_text(&slice.step)?),
                    Payload::DictProxy(dict) => format!("dict_proxy({})", self.builtin_repr(&Value::Object(Rc::clone(dict)))?),
                    Payload::Generator(generator) => format!("<generator object {} at {}>", c_string(generator.borrow().name.as_bytes(), 200), address()),
                    Payload::Cell(cell) => match cell.borrow().as_ref() {
                        None => format!("<cell at {}: empty>", address()),
                        Some(content) => format!("<cell at {}: {} object at {}>", address(), c_string(self.type_name(content).as_bytes(), 80), self.pointer_text(self.value_address(content))),
                    },
                    Payload::Instance if self.is_classic_class(&class) => format!("<{qualified} instance at {}>", address()),
                    Payload::Native(_) => match crate::interp::builtins::native_repr(self, object)? {
                        Some(text) => text,
                        None => format!("<{qualified} object at {}>", address()),
                    },
                    _ => format!("<{qualified} object at {}>", address()),
                }
            }
        };

        Ok(text)
    }

    /// `repr(value)` as a Rust string; unknown values render as a marker.
    pub fn repr_text(&self, value: &Value) -> PyResult<String> {
        let repr = self.repr(value)?;

        Ok(match &repr {
            Value::Unknown(unknown) => format!("<unknown {}>", unknown.origin),
            other => self.text_of(other).unwrap_or_default(),
        })
    }
}

/// `%.Ns` formatting: at most `limit` bytes, up to the first NUL.
pub(crate) fn c_string(bytes: &[u8], limit: usize) -> String {
    let text = bytes.split(|byte| *byte == 0).next().unwrap_or_default();
    let text = text.get(..limit).unwrap_or(text);

    String::from_utf8_lossy(text).into_owned()
}

/// `object.__init__`: excess arguments are an error unless the class
/// overrides `__new__` but not `__init__`; overriding both only warns.
fn object_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let excess = args.positional.len() > 1 || args.has_keywords();
    let Some(instance) = args.positional.first() else {
        return Ok(Value::None);
    };

    if excess {
        let class = vm.class_of(instance);
        let overrides_new = !vm.defined_by_object(&class, "__new__")?;
        let overrides_init = !vm.defined_by_object(&class, "__init__")?;
        if !(overrides_new && overrides_init) && (overrides_init || !overrides_new) {
            return Err(vm.type_error("object.__init__() takes no parameters"));
        }
    }

    Ok(Value::None)
}

pub(crate) fn object_setattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__setattr__", 3, 3)?;
    let Value::Object(object) = &args[0] else {
        return vm.setattr(&args[0], &name_arg(vm, &args[1])?, args[2].clone()).map(|_| Value::None);
    };

    let name = name_arg(vm, &args[1])?;
    unready_hackcheck(vm, object, "__setattr__")?;
    if vm.set_intrinsic_attribute(object, &name.to_string_lossy(), &args[2])? {
        return Ok(Value::None);
    }
    if object.as_class().is_some() || object.as_module().is_some() {
        vm.setattr(&args[0], &name, args[2].clone())?;
        return Ok(Value::None);
    }

    vm.generic_setattr(object, &object.class(), &name, Some(args[2].clone()))?;

    Ok(Value::None)
}

pub(crate) fn object_delattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__delattr__", 2, 2)?;
    let Value::Object(object) = &args[0] else {
        return Err(vm.type_error("can't delete attributes of a builtin value"));
    };

    let name = name_arg(vm, &args[1])?;
    unready_hackcheck(vm, object, "__delattr__")?;
    vm.generic_setattr(object, &object.class(), &name, None)?;

    Ok(Value::None)
}

/// The check that refuses setting attributes of a static type through
/// another type's `__setattr__`, applied before the type is readied.
fn unready_hackcheck(vm: &Vm, object: &ObjectRef, what: &str) -> PyResult<()> {
    let class = object.class();
    if vm.is_type_unready(&class) {
        return Err(vm.type_error(&format!("can't apply this {what} to {} object", vm.class_name(&class))));
    }

    Ok(())
}

pub(crate) fn object_getattribute(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__getattribute__", 2, 2)?;
    let name = name_arg(vm, &args[1])?;

    let Value::Object(object) = &args[0] else {
        return vm.getattr(&args[0], &name);
    };

    // Generic attribute lookup readies the type.
    vm.ready_type(&object.class());
    if let Some(value) = vm.intrinsic_attribute(object, &name.to_string_lossy())? {
        return Ok(value);
    }
    if object.as_class().is_some() || object.as_module().is_some() {
        return vm.getattr(&args[0], &name);
    }

    match vm.generic_getattr(&args[0], object, &object.class(), &name)? {
        Some(value) => Ok(value),
        None => Err(vm.raise(ExceptionKind::AttributeError, &format!("'{}' object has no attribute '{}'", vm.type_name(&args[0]), name.to_string_lossy()))),
    }
}

pub(crate) fn object_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "__repr__")?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&target)?.into_bytes())))
}

fn object_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "__str__")?;

    vm.repr(&target)
}

fn object_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "__hash__")?;
    let hash = match &target {
        Value::Object(object) => crate::interp::hash::hash_pointer(vm.config.long_width, vm.address_of(object)),
        _ => vm.hash(&target)?,
    };

    Ok(Value::Int(hash.value()))
}

pub fn name_arg(vm: &Vm, value: &Value) -> PyResult<PyBytes> {
    if let Value::Str(bytes) = value {
        return Ok(bytes.clone());
    }
    // Interning leaves a `str` subclass instance as it is; a copy keeps the
    // attribute machinery from interning its storage and the method cache
    // from accepting it.
    if let (Value::Object(object), Some(bytes)) = (value, vm.as_str_bytes(value)) {
        return Ok(PyBytes::subclass_name_copy(object, bytes.as_bytes()));
    }
    if let Some(text) = vm.as_text(value) {
        if let Value::Str(bytes) = vm.encode_default(&text)? {
            return Ok(bytes);
        }
    }

    Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(value))))
}

fn type_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "type.__new__", 2, 4)?;
    let Value::Object(metatype) = &args[0] else {
        return Err(vm.type_error("type.__new__(X): X is not a type object"));
    };

    if args.len() == 2 {
        return Ok(vm.type_value(&args[1]));
    }
    if args.len() != 4 {
        return Err(vm.type_error("type() takes 1 or 3 arguments"));
    }

    vm.type_new(metatype, &args[1], &args[2], &args[3])
}

fn type_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__call__")?;
    let Value::Object(class) = &target else {
        return Err(vm.type_error("type.__call__ requires a type"));
    };

    vm.type_call_default(class, rest)
}

fn type_mro(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "mro")?;
    let mro = vm.getattr_str(&target, "__mro__")?;

    Ok(vm.new_list(vm.collect(&mro)?))
}

/// Accepts the one- or three-argument forms of `type()`.
fn type_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = receiver(vm, args, "__init__")?;
    if rest.has_keywords() && rest.positional.len() == 1 {
        return Err(vm.type_error("type.__init__() takes no keyword arguments"));
    }

    if rest.positional.len() != 1 && rest.positional.len() != 3 {
        return Err(vm.type_error("type.__init__() takes 1 or 3 arguments"));
    }

    Ok(Value::None)
}

/// `type.__subclasses__()`: live direct subclasses in creation order.
fn type_subclasses(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = receiver(vm, args, "__subclasses__")?;
    let Some(data) = target.as_object().and_then(|object| object.as_class()) else {
        return Err(vm.type_error("descriptor '__subclasses__' requires a 'type' object"));
    };

    let subclasses = data.subclasses.borrow().iter().filter_map(std::rc::Weak::upgrade).map(Value::Object).collect();

    Ok(vm.new_list(subclasses))
}

fn type_instancecheck(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__instancecheck__", 2, 2)?;
    let Value::Object(class) = &args[0] else {
        return Err(vm.type_error("__instancecheck__ requires a type"));
    };

    Ok(Value::Bool(vm.is_instance_of(&args[1], class)?))
}

fn type_subclasscheck(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "__subclasscheck__", 2, 2)?;
    let (Value::Object(class), Value::Object(candidate)) = (&args[0], &args[1]) else {
        return Err(vm.type_error("issubclass() arg 1 must be a class"));
    };

    Ok(Value::Bool(vm.is_subclass(candidate, class)?))
}

/// The message of an argument converter for an argument of the wrong
/// type; `function` is empty for a format without a name.
fn argument_type_error(vm: &Vm, function: &str, index: usize, expected: &str, value: &Value) -> Signal {
    let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(value) };
    let prefix = if function.is_empty() { String::new() } else { format!("{function}() ") };

    vm.type_error(&format!("{prefix}argument {} must be {expected}, not {shown}", index + 1))
}

/// `classobj(name, bases, dict)`.
fn classobj_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = new_class(vm, args, &vm.types().classobj)?;
    let slots = parse_with(vm, rest, "", &["name", "bases", "dict"], 3, |vm, index, value| {
        if index == 0 && vm.as_str_bytes(&value).is_none() {
            return Err(argument_type_error(vm, "", index, "string", &value));
        }
        Ok(value)
    })?;
    let [Some(name), Some(bases), Some(dict)] = <[Option<Value>; 3]>::try_from(slots).unwrap_or_default() else {
        return Err(vm.type_error("classobj() requires 3 arguments"));
    };

    let dict = match dict {
        Value::Object(dict) if dict.as_dict().is_some() => dict,
        _ => return Err(vm.type_error("PyClass_New: dict must be a dictionary")),
    };
    let Some(bases) = vm.as_tuple(&bases) else {
        return Err(vm.type_error("PyClass_New: bases must be a tuple"));
    };

    vm.new_classic_class(&name, bases.to_vec(), dict)
}

/// `instance(class[, dict])`, which ignores keywords.
fn instance_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = new_class(vm, args, &vm.types().instance)?;
    let given = rest.positional.len();
    let mut values = rest.positional.into_iter();
    let Some(class) = values.next() else {
        return Err(vm.type_error(&format!("instance() takes at least 1 argument ({given} given)")));
    };
    if given > 2 {
        return Err(vm.type_error(&format!("instance() takes at most 2 arguments ({given} given)")));
    }

    let class = match &class {
        Value::Object(object) if vm.is_classic_class(object) => Rc::clone(object),
        _ => return Err(argument_type_error(vm, "instance", 0, "classobj", &class)),
    };
    let dict = match values.next() {
        None | Some(Value::None) => vm.new_dict(),
        Some(Value::Object(dict)) if dict.as_dict().is_some() => dict,
        Some(_) => return Err(vm.type_error("instance() second arg must be dictionary or None")),
    };

    Ok(Value::Object(vm.alloc(&class, Payload::Instance, Some(dict))))
}

fn function_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = new_class(vm, args, &vm.types().function)?;
    let slots = parse_with(vm, rest, "function", &["code", "globals", "name", "argdefs", "closure"], 2, |vm, index, value| {
        let accepted = match index {
            0 => matches!(value.as_object().map(|object| &object.payload), Some(Payload::Code(_))),
            1 => value.as_object().is_some_and(|object| object.as_dict().is_some()),
            _ => true,
        };
        if !accepted {
            return Err(argument_type_error(vm, "function", index, if index == 0 { "code" } else { "dict" }, &value));
        }
        Ok(value)
    })?;
    let mut slots = slots.into_iter();
    let (Some(Some(code)), Some(Some(globals))) = (slots.next(), slots.next()) else {
        return Err(vm.type_error("function() requires code and globals"));
    };
    let name = slots.next().flatten().unwrap_or(Value::None);
    let defaults = slots.next().flatten().unwrap_or(Value::None);
    let closure = slots.next().flatten().unwrap_or(Value::None);
    let (Value::Object(code_object), Value::Object(globals)) = (&code, &globals) else {
        return Err(vm.type_error("function() requires code and globals"));
    };
    let Payload::Code(code_data) = &code_object.payload else {
        return Err(vm.type_error("function() argument 1 must be code"));
    };

    let name = match &name {
        Value::None => None,
        Value::Str(bytes) => Some(bytes.clone()),
        _ => match vm.as_str_bytes(&name) {
            Some(bytes) => Some(PyBytes::new(bytes.as_bytes())),
            None => return Err(vm.type_error("arg 3 (name) must be None or string")),
        },
    };
    let defaults = match &defaults {
        Value::None => None,
        _ => match vm.as_tuple(&defaults) {
            Some(items) => Some(items.to_vec()),
            None => return Err(vm.type_error("arg 4 (defaults) must be None or tuple")),
        },
    };

    let free_count = code_data.freevars.len();
    let closure = match (&closure, vm.as_tuple(&closure)) {
        (_, Some(items)) => Some(items),
        (Value::None, None) if free_count > 0 => return Err(vm.type_error("arg 5 (closure) must be tuple")),
        (Value::None, None) => None,
        _ => return Err(vm.type_error("arg 5 (closure) must be None or tuple")),
    };
    let closure_count = closure.as_ref().map_or(0, |items| items.len());
    if free_count != closure_count {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("{} requires closure of length {free_count}, not {closure_count}", code_data.name.to_string_lossy())));
    }
    for item in closure.iter().flat_map(|items| items.iter()) {
        if !matches!(item.as_object().map(|object| &object.payload), Some(Payload::Cell(_))) {
            return Err(vm.type_error(&format!("arg 5 (closure) expected cell, found {}", vm.type_name(item))));
        }
    }

    let closure = closure.map(|items| Value::tuple(items.to_vec()));
    let function = vm.make_function(&code, globals, Vec::new(), closure)?;
    if let Some(Payload::Function(data)) = function.as_object().map(|object| &object.payload) {
        *data.defaults.borrow_mut() = defaults;
        if let Some(name) = name {
            *data.name.borrow_mut() = name;
        }
    }

    Ok(function)
}

/// `code(...)` with its fourteen required and two optional arguments,
/// which ignores keywords, then the checks of the code constructor.
fn code_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = new_class(vm, args, &vm.types().code)?;
    let values = rest.positional;
    let given = values.len();
    if given < 12 {
        return Err(vm.type_error(&format!("code() takes at least 12 arguments ({given} given)")));
    }
    if given > 14 {
        return Err(vm.type_error(&format!("code() takes at most 14 arguments ({given} given)")));
    }

    let mut integers = [0i32; 5];
    let mut strings = Vec::with_capacity(4);
    let mut tuples = Vec::with_capacity(5);
    for (index, value) in values.iter().enumerate() {
        match index {
            0..=3 | 10 => {
                let slot = if index == 10 { 4 } else { index };
                let number = int_argument(vm, value)?;
                integers[slot] = i32::try_from(number).map_err(|_| vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum"))?;
            }
            4 | 8 | 9 | 11 => match vm.as_str_bytes(value) {
                Some(bytes) => strings.push(bytes),
                None => return Err(argument_type_error(vm, "code", index, "string", value)),
            },
            _ => match vm.as_tuple(value) {
                Some(items) => tuples.push(items),
                None => return Err(argument_type_error(vm, "code", index, "tuple", value)),
            },
        }
    }
    let [argcount, nlocals, stacksize, flags, firstlineno] = integers;
    let Ok(argcount) = u32::try_from(argcount) else {
        return Err(vm.raise(ExceptionKind::ValueError, "code: argcount must not be negative"));
    };
    let Ok(nlocals) = u32::try_from(nlocals) else {
        return Err(vm.raise(ExceptionKind::ValueError, "code: nlocals must not be negative"));
    };

    let mut tuples = tuples.into_iter();
    let mut strings = strings.into_iter();
    let (Some(code), Some(filename), Some(name), Some(lnotab)) = (strings.next(), strings.next(), strings.next(), strings.next()) else {
        return Err(vm.type_error("code() requires 12 arguments"));
    };
    let (Some(consts), Some(names), Some(varnames)) = (tuples.next(), tuples.next(), tuples.next()) else {
        return Err(vm.type_error("code() requires 12 arguments"));
    };
    let names = name_tuple(vm, &names)?;
    let varnames = name_tuple(vm, &varnames)?;
    let freevars = tuples.next().map(|items| name_tuple(vm, &items)).transpose()?.unwrap_or_default();
    let cellvars = tuples.next().map(|items| name_tuple(vm, &items)).transpose()?.unwrap_or_default();

    // `co_stacksize`, `co_flags` and `co_firstlineno` keep the bits of a C
    // `int`.
    let code = CodeObject {
        argcount,
        nlocals,
        stacksize: stacksize.cast_unsigned(),
        flags: CodeFlags(flags.cast_unsigned()),
        code: code.as_bytes().into(),
        consts: consts.to_vec(),
        names,
        varnames,
        freevars,
        cellvars,
        filename,
        name,
        firstlineno: firstlineno.cast_unsigned(),
        lnotab,
    };

    Ok(vm.new_code(code))
}

/// An exact `str` is kept, a subclass instance is copied to a plain `str`.
fn name_tuple(vm: &Vm, items: &[Value]) -> PyResult<Vec<PyBytes>> {
    items
        .iter()
        .map(|item| match item {
            Value::Str(bytes) => Ok(bytes.clone()),
            _ => match vm.as_str_bytes(item) {
                Some(bytes) => Ok(PyBytes::new(bytes.as_bytes())),
                None => Err(vm.type_error(&format!("name tuples must contain only strings, not '{}'", vm.type_name(item)))),
            },
        })
        .collect()
}

/// `module.__new__`: the dict stays absent until `module.__init__` or the
/// first attribute store creates it.
fn module_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, _) = new_class(vm, args, &vm.types().module)?;
    let data = ModuleData { name: PyBytes::from(""), kind: ModuleKind::Source, state: std::cell::Cell::new(ModuleState::Ready) };

    Ok(Value::Object(vm.alloc(&class, Payload::Module(data), None)))
}

fn module_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__init__", "module")?;
    let module = match &target {
        Value::Object(module) if module.as_module().is_some() => Rc::clone(module),
        _ => return Err(wrong_receiver(vm, "__init__", "module", &target)),
    };
    let slots = parse_with(vm, rest, "module.__init__", &["name", "doc"], 1, |vm, index, value| {
        if index == 0 && vm.as_str_bytes(&value).is_none() {
            return Err(argument_type_error(vm, "module.__init__", index, "string", &value));
        }
        Ok(value)
    })?;
    let mut slots = slots.into_iter();
    let name = slots.next().flatten().unwrap_or(Value::None);
    let doc = slots.next().flatten().unwrap_or(Value::None);
    let dict = vm.instance_dict(&module)?;
    vm.dict_set_str(&dict, "__name__", name)?;
    vm.dict_set_str(&dict, "__doc__", doc)?;

    Ok(Value::None)
}

/// Module repr: the name and file are read from the dict as `__name__`
/// and `__file__` and fail unless they are `str`; `%s` stops at a NUL.
fn module_repr(vm: &Vm, module: &ObjectRef) -> PyResult<String> {
    let entry = |key: &str| -> PyResult<Option<String>> {
        let Some(dict) = module.dict() else {
            return Ok(None);
        };
        Ok(vm.dict_get_str(&dict, key)?.and_then(|value| vm.as_str_bytes(&value)).map(|bytes| c_string(bytes.as_bytes(), usize::MAX)))
    };
    let name = entry("__name__")?.unwrap_or_else(|| "?".to_owned());

    Ok(match entry("__file__")? {
        Some(filename) => format!("<module '{name}' from '{filename}'>"),
        None => format!("<module '{name}' (built-in)>"),
    })
}

fn property_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(Value::Object(class)) = args.positional.first().cloned() else {
        return Err(vm.type_error("property.__new__ requires a type"));
    };

    let data = PropertyData(RefCell::new(PropertyFields { getter: Value::None, setter: Value::None, deleter: Value::None, doc: Value::None }));
    let dict = if vm.is_builtin_type(&class) { None } else { Some(vm.new_dict()) };

    Ok(Value::Object(vm.alloc(&class, Payload::Property(data), dict)))
}

fn property_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__init__")?;
    let slots = crate::interp::builtins::parse(vm, rest, "property", &["fget", "fset", "fdel", "doc"], 0)?;

    let Value::Object(object) = &target else {
        return Err(vm.type_error("property.__init__ requires a property"));
    };
    let Payload::Property(property) = &object.payload else {
        return Err(vm.type_error("property.__init__ requires a property"));
    };

    let getter = slots[0].clone().unwrap_or(Value::None);
    let mut doc = slots[3].clone().unwrap_or(Value::None);
    if doc.is_none() && !getter.is_none() {
        doc = vm.getattr_opt(&getter, &PyBytes::from("__doc__"))?.unwrap_or(Value::None);
    }

    *property.0.borrow_mut() = PropertyFields { getter, setter: slots[1].clone().unwrap_or(Value::None), deleter: slots[2].clone().unwrap_or(Value::None), doc };

    Ok(Value::None)
}

fn property_copy(vm: &Vm, args: CallArgs, slot: usize, method: &str) -> PyResult<Value> {
    let args = positional(vm, args, method, 2, 2)?;
    let Value::Object(object) = &args[0] else {
        return Err(vm.type_error("property method requires a property"));
    };
    let Payload::Property(current) = &object.payload else {
        return Err(vm.type_error("property method requires a property"));
    };

    let current = current.fields();
    let mut parts = [current.getter, current.setter, current.deleter, current.doc];
    parts[slot] = args[1].clone();
    let class = Value::Object(object.class());

    vm.call(&class, CallArgs::new(parts.to_vec()))
}

fn property_getter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    property_copy(vm, args, 0, "getter")
}

fn property_setter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    property_copy(vm, args, 1, "setter")
}

fn property_deleter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    property_copy(vm, args, 2, "deleter")
}

fn staticmethod_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "staticmethod", 2, 2)?;

    Ok(vm.new_staticmethod(args[1].clone()))
}

fn classmethod_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "classmethod", 2, 2)?;
    let class = Rc::clone(&vm.types().classmethod);

    Ok(Value::Object(vm.alloc(&class, Payload::ClassMethod(args[1].clone()), None)))
}

fn super_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "super", 2, 3)?;
    let Value::Object(class) = &args[1] else {
        return Err(vm.type_error("super() argument 1 must be type"));
    };

    let receiver = args.get(2).cloned();
    let receiver_class = match &receiver {
        None => None,
        Some(Value::Unknown(_)) => None,
        Some(value) => {
            if let Value::Object(candidate) = value {
                if candidate.as_class().is_some() && vm.is_subclass(candidate, class)? {
                    Some(Rc::clone(candidate))
                } else {
                    Some(vm.class_of(value))
                }
            } else {
                Some(vm.class_of(value))
            }
        }
    };

    if let Some(receiver_class) = &receiver_class {
        if !vm.is_subclass(receiver_class, class)? {
            return Err(vm.type_error("super(type, obj): obj must be an instance or subtype of type"));
        }
    }

    let super_class = Rc::clone(&vm.types().super_);
    let data = SuperData { class: Rc::clone(class), receiver, receiver_class };

    Ok(Value::Object(vm.alloc(&super_class, Payload::Super(data), None)))
}
