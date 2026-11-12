use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::ClassData;
use crate::interp::object::ClassStyle;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::pydict::PyDict;
use crate::interp::type_flags::ClassFlags;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The builtin classes every interpreter instance starts with.
pub struct BuiltinTypes {
    pub type_: ObjectRef,
    pub object: ObjectRef,
    pub dict: ObjectRef,
    pub int: ObjectRef,
    pub long: ObjectRef,
    pub float: ObjectRef,
    pub complex: ObjectRef,
    pub bool: ObjectRef,
    pub basestring: ObjectRef,
    pub str: ObjectRef,
    pub unicode: ObjectRef,
    pub bytearray: ObjectRef,
    pub tuple: ObjectRef,
    pub list: ObjectRef,
    pub set: ObjectRef,
    pub frozenset: ObjectRef,
    pub none_type: ObjectRef,
    pub not_implemented_type: ObjectRef,
    pub ellipsis_type: ObjectRef,
    pub function: ObjectRef,
    pub builtin_function: ObjectRef,
    pub method_descriptor: ObjectRef,
    pub classmethod_descriptor: ObjectRef,
    pub wrapper_descriptor: ObjectRef,
    pub method_wrapper: ObjectRef,
    pub method: ObjectRef,
    pub classobj: ObjectRef,
    pub instance: ObjectRef,
    pub module: ObjectRef,
    pub generator: ObjectRef,
    pub cell: ObjectRef,
    pub code: ObjectRef,
    pub frame: ObjectRef,
    pub traceback: ObjectRef,
    pub property: ObjectRef,
    pub staticmethod: ObjectRef,
    pub classmethod: ObjectRef,
    pub super_: ObjectRef,
    pub slice: ObjectRef,
    pub xrange: ObjectRef,
    pub dictproxy: ObjectRef,
    pub dict_keys: ObjectRef,
    pub dict_values: ObjectRef,
    pub dict_items: ObjectRef,
    /// `iterator`, the type of sequence iterators (`IteratorKind::Sequence`).
    pub iterator: ObjectRef,
    /// The native iterator types, indexed by `IteratorKind`.
    pub iterators: Vec<ObjectRef>,
    pub enumerate: ObjectRef,
    pub reversed: ObjectRef,
    pub file: ObjectRef,
    pub buffer: ObjectRef,
    pub memoryview: ObjectRef,
    pub unwind: ObjectRef,
    pub getset_descriptor: ObjectRef,
    pub member_descriptor: ObjectRef,
    /// Builtin exception classes, indexed by `ExceptionKind`.
    pub exceptions: Vec<ObjectRef>,
}

impl BuiltinTypes {
    pub fn exception(&self, kind: ExceptionKind) -> &ObjectRef {
        &self.exceptions[kind as usize]
    }

    pub fn iterator_type(&self, kind: IteratorKind) -> &ObjectRef {
        &self.iterators[kind as usize]
    }
}

/// CPython's types of native iterators over builtin containers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IteratorKind {
    /// Index-based iteration: `str`, `unicode`, and objects with `__getitem__`.
    Sequence,
    List,
    ListReverse,
    Tuple,
    ByteArray,
    Range,
    Set,
    DictKeys,
    DictValues,
    DictItems,
    Callable,
}

impl IteratorKind {
    pub const ALL: [Self; 11] = [
        Self::Sequence,
        Self::List,
        Self::ListReverse,
        Self::Tuple,
        Self::ByteArray,
        Self::Range,
        Self::Set,
        Self::DictKeys,
        Self::DictValues,
        Self::DictItems,
        Self::Callable,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Sequence => "iterator",
            Self::List => "listiterator",
            Self::ListReverse => "listreverseiterator",
            Self::Tuple => "tupleiterator",
            Self::ByteArray => "bytearray_iterator",
            Self::Range => "rangeiterator",
            Self::Set => "setiterator",
            Self::DictKeys => "dictionary-keyiterator",
            Self::DictValues => "dictionary-valueiterator",
            Self::DictItems => "dictionary-itemiterator",
            Self::Callable => "callable-iterator",
        }
    }
}

struct Bootstrap<'a> {
    vm: &'a Vm,
    type_: ObjectRef,
    dict: ObjectRef,
}

impl Bootstrap<'_> {
    fn new_dict(&self) -> ObjectRef {
        self.vm.alloc(&self.dict, Payload::Dict(RefCell::new(PyDict::new())), None)
    }

    fn class(&self, name: &str, base: Option<&ObjectRef>, layout: Layout, instance_dict: bool) -> ObjectRef {
        self.class_in("__builtin__", name, base, layout, instance_dict)
    }

    fn class_in(&self, module: &str, name: &str, base: Option<&ObjectRef>, layout: Layout, instance_dict: bool) -> ObjectRef {
        let dict = self.new_dict();
        let class = self.vm.alloc(&self.type_, class_payload(module, name, base, layout, instance_dict, dict), None);
        seal_mro(&class);

        class
    }
}

fn class_payload(module: &str, name: &str, base: Option<&ObjectRef>, layout: Layout, instance_dict: bool, dict: ObjectRef) -> Payload {
    let bases = base.map(|base| vec![Value::Object(Rc::clone(base))]).unwrap_or_default();

    Payload::Class(ClassData {
        name: RefCell::new(PyBytes::from(name)),
        bases: RefCell::new(bases),
        mro: RefCell::new(Vec::new()),
        dict,
        style: ClassStyle::NewStyle,
        layout,
        instance_dict,
        builtin: true,
        subclasses: RefCell::new(Vec::new()),
        flags: ClassFlags::for_static_type(module, name),
        heap_layout: None,
    })
}

/// Builtin classes have single inheritance, so the MRO is the class
/// followed by its base's MRO.
fn seal_mro(class: &ObjectRef) {
    let Some(data) = class.as_class() else {
        return;
    };

    let mut mro = vec![MroEntry::Class(Rc::clone(class))];

    if let Some(Value::Object(base)) = data.bases.borrow().first() {
        if let Some(base_data) = base.as_class() {
            mro.extend(base_data.mro());
            base_data.subclasses.borrow_mut().push(Rc::downgrade(class));
        }
    }

    *data.mro.borrow_mut() = mro;
}

/// Forbids subclassing the builtin types that cannot be subclassed in
/// CPython 2.7.
pub fn forbid_builtin_subclassing(vm: &Vm) {
    let types = vm.types();
    let finals = [
        &types.bool,
        &types.none_type,
        &types.not_implemented_type,
        &types.ellipsis_type,
        &types.function,
        &types.builtin_function,
        &types.method_descriptor,
        &types.classmethod_descriptor,
        &types.wrapper_descriptor,
        &types.method_wrapper,
        &types.method,
        &types.classobj,
        &types.instance,
        &types.generator,
        &types.cell,
        &types.code,
        &types.frame,
        &types.traceback,
        &types.slice,
        &types.xrange,
        &types.dictproxy,
        &types.dict_keys,
        &types.dict_values,
        &types.dict_items,
        &types.iterator,
        &types.buffer,
        &types.memoryview,
        &types.unwind,
        &types.getset_descriptor,
        &types.member_descriptor,
    ];
    for class in finals.into_iter().chain(&types.iterators) {
        vm.forbid_subclassing(class);
    }
}

pub fn bootstrap(vm: &Vm) -> PyResult<BuiltinTypes> {
    let type_dict = vm.alloc_unclassed(Payload::Dict(RefCell::new(PyDict::new())), None);
    let object_dict = vm.alloc_unclassed(Payload::Dict(RefCell::new(PyDict::new())), None);
    let dict_dict = vm.alloc_unclassed(Payload::Dict(RefCell::new(PyDict::new())), None);

    let object = vm.alloc_unclassed(class_payload("__builtin__", "object", None, Layout::Object, false, Rc::clone(&object_dict)), None);
    let type_ = vm.alloc_unclassed(class_payload("__builtin__", "type", Some(&object), Layout::Type, false, Rc::clone(&type_dict)), None);
    let dict = vm.alloc_unclassed(class_payload("__builtin__", "dict", Some(&object), Layout::Dict, false, Rc::clone(&dict_dict)), None);

    for class in [&object, &type_, &dict] {
        class.set_class(&type_);
        seal_mro(class);
    }
    for class_dict in [&type_dict, &object_dict, &dict_dict] {
        class_dict.set_class(&dict);
    }

    let boot = Bootstrap { vm, type_: Rc::clone(&type_), dict: Rc::clone(&dict) };
    let plain = |name: &str, layout: Layout| boot.class(name, Some(&object), layout, false);

    let int = plain("int", Layout::Int);
    let bool = boot.class("bool", Some(&int), Layout::Int, false);
    let basestring = plain("basestring", Layout::Object);
    let str = boot.class("str", Some(&basestring), Layout::Str, false);
    let unicode = boot.class("unicode", Some(&basestring), Layout::Unicode, false);

    let mut exceptions: Vec<ObjectRef> = Vec::with_capacity(ExceptionKind::ALL.len());
    for kind in ExceptionKind::ALL {
        let base = match kind.parent() {
            Some(parent) => Rc::clone(&exceptions[parent as usize]),
            None => Rc::clone(&object),
        };
        let class = boot.class_in("exceptions", kind.name(), Some(&base), Layout::Exception, true);
        exceptions.push(class);
    }

    let iterators: Vec<ObjectRef> = IteratorKind::ALL.iter().map(|kind| plain(kind.name(), Layout::Native)).collect();

    Ok(BuiltinTypes {
        long: plain("long", Layout::Long),
        float: plain("float", Layout::Float),
        complex: plain("complex", Layout::Native),
        bytearray: plain("bytearray", Layout::Native),
        tuple: plain("tuple", Layout::Tuple),
        list: plain("list", Layout::List),
        set: plain("set", Layout::Set),
        frozenset: plain("frozenset", Layout::FrozenSet),
        none_type: plain("NoneType", Layout::Object),
        not_implemented_type: plain("NotImplementedType", Layout::Object),
        ellipsis_type: plain("ellipsis", Layout::Object),
        function: boot.class("function", Some(&object), Layout::Function, true),
        builtin_function: plain("builtin_function_or_method", Layout::Native),
        method_descriptor: plain("method_descriptor", Layout::Native),
        classmethod_descriptor: plain("classmethod_descriptor", Layout::Native),
        wrapper_descriptor: plain("wrapper_descriptor", Layout::Native),
        method_wrapper: plain("method-wrapper", Layout::Native),
        method: plain("instancemethod", Layout::Native),
        classobj: plain("classobj", Layout::Native),
        instance: plain("instance", Layout::Object),
        module: boot.class("module", Some(&object), Layout::Module, true),
        generator: plain("generator", Layout::Native),
        cell: plain("cell", Layout::Native),
        code: plain("code", Layout::Native),
        frame: plain("frame", Layout::Native),
        traceback: plain("traceback", Layout::Native),
        property: plain("property", Layout::Property),
        staticmethod: plain("staticmethod", Layout::Native),
        classmethod: plain("classmethod", Layout::Native),
        super_: plain("super", Layout::Native),
        slice: plain("slice", Layout::Native),
        xrange: plain("xrange", Layout::Native),
        dictproxy: plain("dictproxy", Layout::Native),
        dict_keys: plain("dict_keys", Layout::Native),
        dict_values: plain("dict_values", Layout::Native),
        dict_items: plain("dict_items", Layout::Native),
        iterator: Rc::clone(&iterators[IteratorKind::Sequence as usize]),
        iterators,
        enumerate: plain("enumerate", Layout::Native),
        reversed: plain("reversed", Layout::Native),
        file: plain("file", Layout::Native),
        buffer: plain("buffer", Layout::Native),
        memoryview: plain("memoryview", Layout::Native),
        unwind: plain("unwind_marker", Layout::Native),
        getset_descriptor: plain("getset_descriptor", Layout::Native),
        member_descriptor: plain("member_descriptor", Layout::Native),
        int,
        bool,
        basestring,
        str,
        unicode,
        type_,
        object,
        dict,
        exceptions,
    })
}
