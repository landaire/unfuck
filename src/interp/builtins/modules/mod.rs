//! Native modules the interpreter provides in place of C extension modules.

pub mod ast;
pub(crate) mod array;
mod audioop;
pub(crate) mod binascii;
mod bisect;
mod builtin_hashes;
pub(crate) mod capsule;
mod cmath;
mod cmath_special;
mod cjkcodecs;
pub(crate) mod codecs;
mod collections;
mod cpickle;
mod cstringio;
mod csv;
mod datetime;
mod digests;
mod elementtree;
mod errno;
mod exceptions;
pub(crate) mod expat;
mod functools;
mod future_builtins;
mod gc;
mod hashlib;
mod heapq;
mod host_arguments;
mod hotshot;
mod imp;
mod io;
mod itertools;
mod json;
mod locale;
mod lsprof;
mod marshal;
mod math;
pub(crate) mod mmap;
mod msvcrt;
mod multiprocessing;
mod nt;
pub(crate) mod operator;
mod parser;
mod pyexpat;
mod random;
mod select;
mod signal;
pub(crate) mod socket;
mod sre;
pub(crate) mod ssl;
mod strop;
mod structseq;
mod structs;
mod subprocess;
mod symtable;
mod sys;
mod thread;
mod time;
mod unicodedata;
pub(crate) mod warnings;
mod weakref;
mod winreg;
mod xxsubtype;
mod zipimport;
mod zlib;

pub use structseq::new_struct_sequence;
pub use weakref::clear_weak_references;
pub use weakref::first_weak_reference;
pub use structseq::new_struct_sequence_type;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::interp::attr::MroLookup;
use crate::interp::attr::SlotDescriptor;
use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::ClassData;
use crate::interp::object::ClassStyle;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::object::NativeFn;
use crate::interp::type_flags::ClassFlags;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::NativeModuleInit;
use crate::interp::vm::Vm;

/// Implements `NativeData` for a payload type with the given type name.
macro_rules! impl_native_data {
    ($type:ty, $name:literal) => {
        impl crate::interp::value::NativeData for $type {
            fn type_name(&self) -> &'static str {
                $name
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
    };
}

pub(crate) use impl_native_data;

/// A class a native module defines (a static type in CPython).
pub struct TypeSpec<'a> {
    /// The type name without the module prefix.
    pub name: &'static str,
    /// The module prefix of the type name, reported as `__module__`.
    pub module: &'static str,
    /// `object` when `None`.
    pub base: Option<ObjectRef>,
    pub layout: Layout,
    /// Instances own a `__dict__`.
    pub instance_dict: bool,
    pub methods: &'a [MethodSpec],
}

/// Native types created so far, by a key naming the type.
#[derive(Default)]
struct TypeRegistry {
    types: RefCell<HashMap<&'static str, ObjectRef>>,
}

pub fn register(vm: &Vm) {
    let modules: &[(&str, NativeModuleInit)] = &[
        ("_ast", ast::init),
        ("_bisect", bisect::init),
        ("_codecs", codecs::init),
        ("_codecs_cn", cjkcodecs::init_cn),
        ("_codecs_hk", cjkcodecs::init_hk),
        ("_codecs_iso2022", cjkcodecs::init_iso2022),
        ("_codecs_jp", cjkcodecs::init_jp),
        ("_codecs_kr", cjkcodecs::init_kr),
        ("_codecs_tw", cjkcodecs::init_tw),
        ("_multibytecodec", cjkcodecs::multibytecodec::init),
        ("_collections", collections::init),
        ("_elementtree", elementtree::init),
        ("_functools", functools::init),
        ("_hashlib", hashlib::init),
        ("_heapq", heapq::init),
        ("_hotshot", hotshot::init),
        ("_io", io::init),
        ("_json", json::init),
        ("_locale", locale::init),
        ("_lsprof", lsprof::init),
        ("_md5", builtin_hashes::init_md5),
        ("_multiprocessing", multiprocessing::init),
        ("_random", random::init),
        ("_sha", builtin_hashes::init_sha),
        ("_sha256", builtin_hashes::init_sha256),
        ("_sha512", builtin_hashes::init_sha512),
        ("_socket", socket::init),
        ("_sre", sre::init),
        ("_ssl", ssl::init),
        ("_struct", structs::init),
        ("_subprocess", subprocess::init),
        ("_symtable", symtable::init),
        ("_warnings", warnings::init),
        ("array", array::init),
        ("_weakref", weakref::init),
        ("_winreg", winreg::init),
        ("audioop", audioop::init),
        ("binascii", binascii::init),
        ("_csv", csv::init),
        ("cPickle", cpickle::init),
        ("cStringIO", cstringio::init),
        ("cmath", cmath::init),
        ("datetime", datetime::init),
        ("errno", errno::init),
        ("exceptions", exceptions::init),
        ("future_builtins", future_builtins::init),
        ("gc", gc::init),
        ("imp", imp::init),
        ("itertools", itertools::init),
        ("marshal", marshal::init),
        ("math", math::init),
        ("mmap", mmap::init),
        ("msvcrt", msvcrt::init),
        ("nt", nt::init),
        ("operator", operator::init),
        ("parser", parser::init),
        ("pyexpat", pyexpat::init),
        ("select", select::init),
        ("signal", signal::init),
        ("strop", strop::init),
        ("sys", sys::init),
        ("thread", thread::init),
        ("time", time::init),
        ("unicodedata", unicodedata::init),
        ("xxsubtype", xxsubtype::init),
        ("zipimport", zipimport::init),
        ("zlib", zlib::init),
    ];
    for &(name, init) in modules {
        vm.register_native_module(name, init);
    }

    // Modules of other platforms that the standard library probes for.
    let absent = ["MacOS", "_emx_link", "_scproxy", "_xmlplus", "ce", "fcntl", "gestalt", "grp", "java", "mac", "org", "os2", "posix", "pwd", "resource", "riscos", "riscosenviron", "termios"];
    for name in absent {
        vm.register_absent_module(name);
    }

    vm.register_import_hook("warnings", warnings::capture_stock_display);
}

/// `new_type` for a type that cannot be subclassed.
pub fn new_final_type(vm: &Vm, spec: TypeSpec<'_>) -> PyResult<ObjectRef> {
    let class = new_type(vm, spec)?;
    vm.forbid_subclassing(&class);

    Ok(class)
}

/// Creates a class for a type a native module defines. Operators dispatch
/// to its methods, since `ops` has no native support for it.
pub fn new_type(vm: &Vm, spec: TypeSpec<'_>) -> PyResult<ObjectRef> {
    let base = spec.base.unwrap_or_else(|| Rc::clone(&vm.types().object));
    let Some(base_data) = base.as_class() else {
        return Err(vm.type_error("native type base is not a class"));
    };

    let dict = vm.new_dict();
    let data = ClassData {
        name: RefCell::new(PyBytes::from(spec.name)),
        bases: RefCell::new(vec![Value::Object(Rc::clone(&base))]),
        mro: RefCell::new(Vec::new()),
        dict: Rc::clone(&dict),
        style: ClassStyle::NewStyle,
        layout: spec.layout,
        instance_dict: spec.instance_dict,
        builtin: true,
        subclasses: RefCell::new(Vec::new()),
        flags: ClassFlags::for_static_type(spec.module, spec.name),
        heap_layout: None,
    };
    let class = vm.alloc(&vm.types().type_, Payload::Class(data), None);

    let mut mro = vec![MroEntry::Class(Rc::clone(&class))];
    mro.extend(base_data.mro());
    if let Some(data) = class.as_class() {
        *data.mro.borrow_mut() = mro;
    }
    base_data.subclasses.borrow_mut().push(Rc::downgrade(&class));

    // The module comes from the dotted name; the dict holds no `__module__`.
    if spec.module != "__builtin__" {
        vm.set_static_module(&class, spec.module);
    }
    vm.register_extension_type(&class);
    crate::interp::builtins::docs::document_class(vm, &class)?;
    install(vm, &class, spec.methods)?;

    // Without its own allocator, `object.__new__` would build an instance
    // that lacks the native payload.
    let has_new = spec.methods.iter().any(|method| method.name == "__new__");
    if spec.layout == Layout::Native && !has_new {
        forbid_instances(vm, &class)?;
    }

    Ok(class)
}

/// Makes calling `class` raise as for a native type without a constructor.
pub fn forbid_instances(vm: &Vm, class: &ObjectRef) -> PyResult<()> {
    install(vm, class, &[static_method("__new__", no_instances)])
}

fn no_instances(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let name = match args.positional.first() {
        Some(Value::Object(class)) => vm.class_name(class),
        _ => "native".to_owned(),
    };

    Err(vm.type_error(&format!("cannot create '{name}' instances")))
}

/// Whether the type `class` has no constructor: it inherits one without
/// defining `__new__`, or `forbid_instances` refused it one.
pub fn has_null_new(vm: &Vm, class: &ObjectRef) -> PyResult<bool> {
    let MroLookup::Found { value, owner } = vm.lookup_mro(class, "__new__")? else {
        return Ok(false);
    };
    if Rc::ptr_eq(&owner, &vm.types().object) {
        return Ok(vm.inherits_null_new(class));
    }

    let refuses = matches!(value.as_object().map(|object| &object.payload), Some(Payload::NativeFunction(native)) if native.function as usize == no_instances as NativeFn as usize);

    Ok(refuses)
}

/// The native type registered under `key`, created by `create` on first use
/// so that every module sharing it sees one class per interpreter.
pub fn native_type(vm: &Vm, key: &'static str, create: fn(&Vm) -> PyResult<ObjectRef>) -> PyResult<ObjectRef> {
    let registry = vm.native_state::<TypeRegistry>();
    if let Some(class) = registry.types.borrow().get(key) {
        return Ok(Rc::clone(class));
    }

    let class = create(vm)?;
    registry.types.borrow_mut().insert(key, Rc::clone(&class));

    Ok(class)
}

/// The native type registered under `key`, if it was created.
pub fn registered_type(vm: &Vm, key: &'static str) -> Option<ObjectRef> {
    vm.native_state::<TypeRegistry>().types.borrow().get(key).map(Rc::clone)
}

/// Allocates an instance of `class` carrying native `data`.
pub fn new_native_object(vm: &Vm, class: &ObjectRef, data: impl NativeData) -> Value {
    Value::Object(vm.alloc(class, Payload::Native(Box::new(data)), None))
}

/// The native payload of `value` when it has type `T`.
pub fn native_data<T: 'static>(value: &Value) -> Option<&T> {
    let Value::Object(object) = value else {
        return None;
    };
    let Payload::Native(data) = &object.payload else {
        return None;
    };

    data.as_any().downcast_ref::<T>()
}

/// The receiver of a native method, which must carry a `T` payload.
/// `type_name` is the qualified type name CPython reports.
pub fn this<'a, T: 'static>(vm: &Vm, args: &'a CallArgs, type_name: &str, method: &str) -> PyResult<&'a T> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '{type_name}' object needs an argument")));
    };

    match native_data::<T>(receiver) {
        Some(data) => Ok(data),
        None => Err(vm.type_error(&format!("descriptor '{method}' requires a '{type_name}' object but received a '{}'", vm.type_name(receiver)))),
    }
}

/// A `StopIteration` to end a native iterator's `next`.
pub fn stop_iteration(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::StopIteration));

    match vm.instantiate_exception(&class, Vec::new()) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// An exception class a native module defines: a heap type deriving from
/// `base`.
pub fn new_exception_class(vm: &Vm, module: &str, name: &str, base: &ObjectRef) -> PyResult<ObjectRef> {
    let namespace = vm.new_dict();
    vm.dict_set_str(&namespace, "__module__", Value::str(module))?;

    let bases = Value::tuple(vec![Value::Object(Rc::clone(base))]);
    let class = vm.type_new(&vm.types().type_, &Value::str(name), &bases, &Value::Object(namespace))?;

    match class {
        Value::Object(class) => Ok(class),
        _ => Err(vm.type_error("exception class creation failed")),
    }
}

/// Ends a native `next` with the item or `StopIteration`.
pub fn iterator_result(vm: &Vm, item: Option<Value>) -> PyResult<Value> {
    item.ok_or_else(|| stop_iteration(vm))
}

/// Argument check of a no-argument function.
pub fn no_arguments(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    if !args.positional.is_empty() {
        return Err(vm.type_error(&format!("{name}() takes no arguments ({} given)", args.positional.len())));
    }

    Ok(())
}

/// Argument check of a no-argument method; the receiver is not counted.
pub fn method_no_arguments(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    let rest = CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };

    no_arguments(vm, &rest, name)
}

/// The argument of a single-argument method; the receiver is not counted.
pub fn method_one_argument(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    match args.positional.as_slice() {
        [_, argument] => Ok(argument.clone()),
        positional => Err(vm.type_error(&format!("{name}() takes exactly one argument ({} given)", positional.len().saturating_sub(1)))),
    }
}

/// Positional arguments of a varargs method after its receiver, checked
/// against a format with optional arguments.
pub fn method_arguments(vm: &Vm, args: &CallArgs, name: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let rest: Vec<Value> = args.positional.iter().skip(1).cloned().collect();
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
        return Err(vm.type_error(&format!("{name}() takes {bound} {limit} argument{plural} ({count} given)")));
    }

    Ok(rest)
}

/// Whether a value is callable. Unknown values count as callable: calling
/// them yields unknown results rather than errors.
pub fn is_callable(vm: &Vm, value: &Value) -> PyResult<bool> {
    match value {
        Value::Unknown(_) => Ok(true),
        Value::Object(object) => match &object.payload {
            Payload::Function(_) | Payload::NativeFunction(_) | Payload::Method(_) | Payload::Class(_) => Ok(true),
            _ => Ok(vm.lookup_special(value, "__call__")?.is_some()),
        },
        _ => Ok(false),
    }
}

/// A computed attribute of a native type (`getset_descriptor`).
pub struct GetSet {
    pub name: &'static str,
    /// Qualified name of the type the attribute belongs to.
    pub owner: &'static str,
    pub get: fn(&Vm, &GetSet, &Value) -> PyResult<Value>,
    /// `None` for read-only attributes. Receives `None` for deletion.
    pub set: Option<fn(&Vm, &GetSet, &Value, Option<Value>) -> PyResult<()>>,
}

impl_native_data!(GetSet, "getset_descriptor");

/// Stores a computed attribute in the dict of `class`.
pub fn add_getset(vm: &Vm, class: &ObjectRef, getset: GetSet) -> PyResult<()> {
    store_descriptor(vm, class, Rc::clone(&vm.types().getset_descriptor), getset)
}

/// Stores a struct member in the dict of `class`. A member
/// without a setter is read-only, which raises `TypeError` on assignment.
pub fn add_member(vm: &Vm, class: &ObjectRef, getset: GetSet) -> PyResult<()> {
    store_descriptor(vm, class, Rc::clone(&vm.types().member_descriptor), getset)
}

fn store_descriptor(vm: &Vm, class: &ObjectRef, descriptor_class: ObjectRef, getset: GetSet) -> PyResult<()> {
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("descriptor target is not a class"));
    };

    let name = getset.name;
    let descriptor = new_native_object(vm, &descriptor_class, getset);
    vm.set_descriptor_owner(&descriptor, class);

    vm.dict_set_str(&data.dict, name, descriptor)
}

/// Methods of `getset_descriptor` and `member_descriptor`, shared by native
/// module `GetSet`s and the interpreter's own `SlotDescriptor`s.
pub fn install_descriptor_types(vm: &Vm) -> PyResult<()> {
    let methods = [method("__get__", getset_get), method("__set__", getset_set), method("__delete__", getset_delete), method("__repr__", getset_repr)];

    let types = vm.types();
    for (class, owner) in [(&types.getset_descriptor, "getset_descriptor"), (&types.member_descriptor, "member_descriptor")] {
        install(vm, class, &methods)?;
        add_member(vm, class, GetSet { name: "__objclass__", owner, get: descriptor_objclass, set: None })?;
        add_member(vm, class, GetSet { name: "__name__", owner, get: descriptor_name, set: None })?;
        add_getset(vm, class, GetSet { name: "__doc__", owner, get: descriptor_doc, set: None })?;
    }

    Ok(())
}

/// The native descriptor a `__objclass__`, `__name__`, or `__doc__` read
/// applies to.
fn descriptor_receiver<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Value> {
    if native_data::<GetSet>(instance).is_some() || native_data::<SlotDescriptor>(instance).is_some() {
        return Ok(instance);
    }

    Err(descriptor_mismatch(vm, getset, instance))
}

fn descriptor_objclass(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let descriptor = descriptor_receiver(vm, getset, instance)?;
    let Some(owner) = vm.descriptor_owner(descriptor) else {
        return Err(vm.halt_unsupported("native descriptor without an owning type"));
    };

    Ok(Value::Object(owner))
}

fn descriptor_name(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let descriptor = descriptor_receiver(vm, getset, instance)?;
    if let Some(slot) = native_data::<SlotDescriptor>(descriptor) {
        return Ok(Value::Str(slot.name.clone()));
    }

    match native_data::<GetSet>(descriptor) {
        Some(native) => Ok(Value::str(native.name)),
        None => Err(descriptor_mismatch(vm, getset, instance)),
    }
}

/// Native descriptors carry no docstring.
fn descriptor_doc(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    descriptor_receiver(vm, getset, instance)?;

    Ok(Value::None)
}

fn getset_get(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (Some(descriptor), Some(instance)) = (args.positional.first(), args.positional.get(1)) else {
        return Err(vm.type_error("expected at least 1 arguments, got 0"));
    };

    if native_data::<SlotDescriptor>(descriptor).is_some() {
        let owner = match (args.positional.get(2), instance) {
            (Some(Value::Object(owner)), _) => Rc::clone(owner),
            (_, instance) if !instance.is_none() => vm.class_of(instance),
            _ => return Err(vm.type_error("__get__(None, None) is invalid")),
        };
        let instance = if instance.is_none() { None } else { Some(instance.clone()) };
        return vm.descriptor_get(descriptor, instance, &owner);
    }

    let getset = this::<GetSet>(vm, &args, "getset_descriptor", "__get__")?;
    if instance.is_none() {
        return Ok(descriptor.clone());
    }
    if !descriptor_applies(vm, descriptor, instance)? {
        return Err(descriptor_mismatch(vm, getset, instance));
    }

    (getset.get)(vm, getset, instance)
}

fn getset_store(vm: &Vm, args: &CallArgs, value: Option<Value>) -> PyResult<Value> {
    let (Some(descriptor), Some(instance)) = (args.positional.first(), args.positional.get(1)) else {
        return Err(vm.type_error("expected 2 arguments, got 0"));
    };

    if let Some(slot) = native_data::<SlotDescriptor>(descriptor) {
        if !descriptor_applies(vm, descriptor, instance)? {
            return Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", slot.name.to_string_lossy(), slot.owner.to_string_lossy(), vm.type_name(instance))));
        }
        vm.descriptor_set(descriptor, instance, &slot.name, value)?;
        return Ok(Value::None);
    }

    let getset = this::<GetSet>(vm, args, "getset_descriptor", "__set__")?;
    if !descriptor_applies(vm, descriptor, instance)? {
        return Err(descriptor_mismatch(vm, getset, instance));
    }
    let Some(set) = getset.set else {
        if is_member(vm, descriptor) {
            return Err(vm.type_error("readonly attribute"));
        }
        return Err(vm.raise(ExceptionKind::AttributeError, &format!("attribute '{}' of '{}' objects is not writable", getset.name, getset.owner)));
    };

    set(vm, getset, instance, value)?;

    Ok(Value::None)
}

fn getset_set(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(value) = args.positional.get(2).cloned() else {
        return Err(vm.type_error("expected 2 arguments, got 1"));
    };

    getset_store(vm, &args, Some(value))
}

fn getset_delete(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    getset_store(vm, &args, None)
}

/// The `TypeError` for `getset` applied to an instance of another type.
pub fn descriptor_mismatch(vm: &Vm, getset: &GetSet, instance: &Value) -> Signal {
    vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance)))
}

/// Whether `instance` is an instance of the type that owns `descriptor`
/// (checked before any writability check).
fn descriptor_applies(vm: &Vm, descriptor: &Value, instance: &Value) -> PyResult<bool> {
    // The type of an unknown value is unknown; its setter decides.
    if instance.is_unknown() {
        return Ok(true);
    }
    let Some(owner) = vm.descriptor_owner(descriptor) else {
        return Err(vm.halt_unsupported("native descriptor without an owning type"));
    };

    vm.is_subclass(&vm.type_of(instance), &owner)
}

/// Whether a native descriptor is a `member_descriptor`.
fn is_member(vm: &Vm, descriptor: &Value) -> bool {
    descriptor.as_object().is_some_and(|object| Rc::ptr_eq(&object.class(), &vm.types().member_descriptor))
}

fn getset_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(text) = args.positional.first().and_then(|descriptor| descriptor_repr(vm, descriptor)) else {
        return Err(vm.type_error("descriptor '__repr__' requires a 'getset_descriptor' object"));
    };

    Ok(Value::str(&text))
}

/// `repr` of a `getset_descriptor` or `member_descriptor`.
pub fn descriptor_repr(vm: &Vm, value: &Value) -> Option<String> {
    if let Some(slot) = native_data::<SlotDescriptor>(value) {
        let label = if slot.kind.is_member() { "member" } else { "attribute" };
        return Some(format!("<{label} '{}' of '{}' objects>", slot.name.to_string_lossy(), slot.owner.to_string_lossy()));
    }

    let label = if is_member(vm, value) { "member" } else { "attribute" };

    native_data::<GetSet>(value).map(|getset| format!("<{label} '{}' of '{}' objects>", getset.name, getset.owner))
}
