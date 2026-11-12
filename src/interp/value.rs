use std::any::Any;
use std::cell::Cell;
use std::cell::OnceCell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroU64;
use std::rc::Rc;
use std::rc::Weak;

use num_bigint::BigInt;

use crate::interp::code::CodeObject;
use crate::interp::hash::PyHash;
use crate::interp::lifecycle::ReleaseLevel;
use crate::interp::lifecycle::defer_items;
use crate::interp::object::ClassData;
use crate::interp::object::FunctionData;
use crate::interp::object::GeneratorData;
use crate::interp::object::ModuleData;
use crate::interp::object::NativeFunction;
use crate::interp::object::NativeIterator;
use crate::interp::object::SlotIndex;
use crate::interp::pydict::PyDict;
use crate::interp::pyset::PySet;

/// Identity of a value with identity. It stands in for the value's address:
/// `id()`, pointer hashes, and the fallback ordering derive from it. A VM
/// assigns identities from its counter, so they depend only on what the
/// program does, never on the host allocator. Identities are unique within
/// one VM, so values do not move between VMs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(NonZeroU64);

impl ObjectId {
    /// The first identity a VM counter assigns.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// The identity a VM counter assigns after this one.
    pub fn successor(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The fake address: 16-byte aligned like a heap pointer, and below the
    /// addresses of inline values.
    pub fn address(self) -> u64 {
        self.0.get() << 4
    }
}

/// The values every VM on a thread shares. Their identities are fixed, so
/// they do not depend on which VM observes them first. They lie far above
/// any identity a VM counter reaches.
#[derive(Clone, Copy)]
enum SharedIdentity {
    EmptyStr,
    Byte(u8),
    EmptyUnicode,
    Latin1(u8),
    EmptyTuple,
}

impl SharedIdentity {
    fn id(self) -> ObjectId {
        const BASE: u64 = 1 << 56;

        let index = match self {
            Self::EmptyStr => 0,
            Self::Byte(byte) => 1 + u64::from(byte),
            Self::EmptyUnicode => 257,
            Self::Latin1(unit) => 258 + u64::from(unit),
            Self::EmptyTuple => 514,
        };

        ObjectId(NonZeroU64::MIN.saturating_add(BASE + index))
    }
}

/// The identity of the empty tuple. Every empty tuple is the same object.
pub fn empty_tuple_id() -> ObjectId {
    SharedIdentity::EmptyTuple.id()
}

/// A Python 2 byte string with its hash cached once computed.
#[derive(Clone)]
pub struct PyBytes(Rc<BytesData>);

pub struct BytesData {
    pub bytes: Box<[u8]>,
    pub hash: Cell<Option<PyHash>>,
    /// Assigned when first observed.
    identity: OnceCell<ObjectId>,
    /// Whether the string is interned.
    interned: Cell<bool>,
    /// The `str` subclass instance passed as an attribute name that this is
    /// a copy of. The method cache rejects such a name, and a dict
    /// that stores the attribute keys it by that instance.
    subclass_name: Option<ObjectRef>,
}

thread_local! {
    /// The shared empty `str`.
    static NULLSTRING: PyBytes = PyBytes::cached(Box::default(), SharedIdentity::EmptyStr);

    /// The shared one-byte `str` objects. Each entry is interned when it is
    /// cached, and the Windows 2.7.12 build has created all of them before
    /// user code runs, so they exist from the start.
    static CHARACTERS: Box<[PyBytes]> = (0..=u8::MAX).map(|byte| PyBytes::cached(Box::new([byte]), SharedIdentity::Byte(byte))).collect();
}

impl PyBytes {
    /// A string from existing bytes: the empty and one-byte strings are the
    /// shared, interned objects.
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        let bytes = bytes.into();
        if let Some(shared) = Self::shared(&bytes) {
            return shared;
        }

        Self::fresh(bytes)
    }

    /// A string allocated before its bytes are filled in
    /// to be written later: only the empty string is the
    /// shared, interned object.
    pub fn new_unshared(bytes: impl Into<Box<[u8]>>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return NULLSTRING.with(Self::clone);
        }

        Self::fresh(bytes)
    }

    /// A string object allocated directly or resized in place
    /// (concatenation, repetition, the `%` operator):
    /// a new object even when empty.
    pub fn allocate(bytes: impl Into<Box<[u8]>>) -> Self {
        Self::fresh(bytes.into())
    }

    /// The bytes of `object`, a `str` subclass instance used as an attribute
    /// name.
    pub fn subclass_name_copy(object: &ObjectRef, bytes: impl Into<Box<[u8]>>) -> Self {
        Self(Rc::new(BytesData { bytes: bytes.into(), hash: Cell::new(None), identity: OnceCell::new(), interned: Cell::new(false), subclass_name: Some(Rc::clone(object)) }))
    }

    /// The shared empty or one-byte string equal to `bytes`.
    fn shared(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [] => Some(NULLSTRING.with(Self::clone)),
            [byte] => Some(CHARACTERS.with(|characters| characters[usize::from(*byte)].clone())),
            _ => None,
        }
    }

    fn fresh(bytes: Box<[u8]>) -> Self {
        Self(Rc::new(BytesData { bytes, hash: Cell::new(None), identity: OnceCell::new(), interned: Cell::new(false), subclass_name: None }))
    }

    /// An interned string every VM on the thread shares.
    fn cached(bytes: Box<[u8]>, shared: SharedIdentity) -> Self {
        Self(Rc::new(BytesData { bytes, hash: Cell::new(None), identity: OnceCell::from(shared.id()), interned: Cell::new(true), subclass_name: None }))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub fn cached_hash(&self) -> &Cell<Option<PyHash>> {
        &self.0.hash
    }

    pub fn is_interned(&self) -> bool {
        self.0.interned.get()
    }

    pub fn is_subclass_name(&self) -> bool {
        self.0.subclass_name.is_some()
    }

    /// The attribute name as a dict key: the `str` subclass instance it was
    /// given as, or the string itself.
    pub fn key(&self) -> Value {
        match &self.0.subclass_name {
            Some(object) => Value::Object(Rc::clone(object)),
            None => Value::Str(self.clone()),
        }
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Identity of the object, which `assign` provides when first asked.
    pub fn identity(&self, assign: impl FnOnce() -> ObjectId) -> ObjectId {
        *self.0.identity.get_or_init(assign)
    }

    /// The reference count of the string object.
    pub fn strong_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }

    /// Lossless only for ASCII and UTF-8 content; used for diagnostics and
    /// identifier comparison.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0.bytes).into_owned()
    }
}

/// The table of interned strings. Entries do not keep their
/// strings alive, as CPython's interned strings are mortal.
#[derive(Default)]
pub struct InternTable {
    strings: RefCell<HashMap<Box<[u8]>, Weak<BytesData>>>,
}

impl InternTable {
    /// The interned string equal to `string`,
    /// which becomes the interned one when there is none yet.
    pub fn intern(&self, string: &PyBytes) -> PyBytes {
        // A `str` subclass instance stays as it is.
        if string.is_interned() || string.is_subclass_name() {
            return string.clone();
        }
        // The shared strings are interned before any other string of their
        // value can be.
        if let Some(shared) = PyBytes::shared(string.as_bytes()) {
            return shared;
        }

        let mut strings = self.strings.borrow_mut();
        if let Some(existing) = strings.get(string.as_bytes()).and_then(Weak::upgrade) {
            return PyBytes(existing);
        }

        // Dropped strings leave dead entries; sweep them as the table grows.
        if strings.len() >= 1024 && strings.len().is_power_of_two() {
            strings.retain(|_, entry| entry.strong_count() > 0);
        }

        string.0.interned.set(true);
        strings.insert(string.as_bytes().into(), Rc::downgrade(&string.0));

        string.clone()
    }
}

impl From<&str> for PyBytes {
    fn from(text: &str) -> Self {
        Self::new(text.as_bytes())
    }
}

impl fmt::Debug for PyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string_lossy())
    }
}

/// A Python 2 unicode string. The Windows build of CPython 2.7 stores UCS-2
/// code units, so lengths and indices count UTF-16 units.
#[derive(Clone)]
pub struct PyText(Rc<TextData>);

pub struct TextData {
    pub units: Box<[u16]>,
    pub hash: Cell<Option<PyHash>>,
    /// Assigned when first observed.
    identity: OnceCell<ObjectId>,
}

thread_local! {
    /// The shared empty `unicode`.
    static UNICODE_EMPTY: PyText = PyText::cached(Box::default(), SharedIdentity::EmptyUnicode);

    /// The shared one-unit Latin-1 `unicode` objects. Entries are created on first
    /// use and kept, so creating them all up front is indistinguishable.
    static UNICODE_LATIN1: Box<[PyText]> = (0..=u8::MAX).map(|unit| PyText::cached(Box::new([u16::from(unit)]), SharedIdentity::Latin1(unit))).collect();
}

impl PyText {
    /// A unicode string from existing units: the empty string and
    /// one-unit Latin-1 strings are the shared objects.
    pub fn new(units: impl Into<Box<[u16]>>) -> Self {
        let units = units.into();
        match &*units {
            [] => UNICODE_EMPTY.with(Self::clone),
            [unit] if *unit < 256 => UNICODE_LATIN1.with(|latin1| latin1[usize::from(*unit)].clone()),
            _ => Self::fresh(units),
        }
    }

    /// A unicode object allocated before its units are filled in
    /// to be written later: only the empty string is shared.
    pub fn new_unshared(units: impl Into<Box<[u16]>>) -> Self {
        let units = units.into();
        if units.is_empty() {
            return UNICODE_EMPTY.with(Self::clone);
        }

        Self::fresh(units)
    }

    /// A unicode object shrunk or grown in place: a new
    /// object even when empty.
    pub fn allocate(units: impl Into<Box<[u16]>>) -> Self {
        Self::fresh(units.into())
    }

    fn fresh(units: Box<[u16]>) -> Self {
        Self(Rc::new(TextData { units, hash: Cell::new(None), identity: OnceCell::new() }))
    }

    /// A string every VM on the thread shares.
    fn cached(units: Box<[u16]>, shared: SharedIdentity) -> Self {
        Self(Rc::new(TextData { units, hash: Cell::new(None), identity: OnceCell::from(shared.id()) }))
    }

    /// Identity of the object, which `assign` provides when first asked.
    pub fn identity(&self, assign: impl FnOnce() -> ObjectId) -> ObjectId {
        *self.0.identity.get_or_init(assign)
    }

    pub fn from_str(text: &str) -> Self {
        Self::new(text.encode_utf16().collect::<Vec<u16>>())
    }

    pub fn units(&self) -> &[u16] {
        &self.0.units
    }

    pub fn cached_hash(&self) -> &Cell<Option<PyHash>> {
        &self.0.hash
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Whether this is the shared empty `unicode`.
    pub fn is_shared_empty(&self) -> bool {
        UNICODE_EMPTY.with(|empty| self.ptr_eq(empty))
    }

    /// The reference count of the unicode object.
    pub fn strong_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.0.units)
    }
}

impl fmt::Debug for PyText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "u{:?}", self.to_string_lossy())
    }
}

/// Why a value is unknown. Unknown values stand for results of native client
/// code the interpreter does not emulate.
#[derive(Debug)]
pub struct Unknown {
    pub origin: String,
    /// Assigned when first observed.
    identity: OnceCell<ObjectId>,
}

impl Unknown {
    pub fn new(origin: impl Into<String>) -> Self {
        Self { origin: origin.into(), identity: OnceCell::new() }
    }

    /// Identity of the value, which `assign` provides when first asked.
    pub fn identity(&self, assign: impl FnOnce() -> ObjectId) -> ObjectId {
        *self.identity.get_or_init(assign)
    }
}

/// A `long`.
#[derive(Clone)]
pub struct PyLong(Rc<LongData>);

pub struct LongData {
    value: BigInt,
    /// Assigned when first observed.
    identity: OnceCell<ObjectId>,
}

impl PyLong {
    pub fn new(value: BigInt) -> Self {
        Self(Rc::new(LongData { value, identity: OnceCell::new() }))
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Identity of the object, which `assign` provides when first asked.
    pub fn identity(&self, assign: impl FnOnce() -> ObjectId) -> ObjectId {
        *self.0.identity.get_or_init(assign)
    }

    /// The reference count of the long object.
    pub fn strong_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }
}

impl std::ops::Deref for PyLong {
    type Target = BigInt;

    fn deref(&self) -> &BigInt {
        &self.0.value
    }
}

impl fmt::Debug for PyLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.value)
    }
}

impl fmt::Display for PyLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.value)
    }
}

/// A Python value. Immutable builtin values are stored inline; everything
/// else is a reference-counted heap object.
#[derive(Clone)]
pub enum Value {
    None,
    NotImplemented,
    Ellipsis,
    Bool(bool),
    Int(i64),
    Long(PyLong),
    Float(f64),
    Str(PyBytes),
    Unicode(PyText),
    Tuple(TupleItems),
    Object(ObjectRef),
    Unknown(Rc<Unknown>),
}

impl Value {
    pub fn str(text: &str) -> Self {
        Self::Str(PyBytes::from(text))
    }

    pub fn tuple(items: Vec<Value>) -> Self {
        Self::Tuple(items.into())
    }

    pub fn long(value: BigInt) -> Self {
        Self::Long(PyLong::new(value))
    }

    pub fn unknown(origin: impl Into<String>) -> Self {
        Self::Unknown(Rc::new(Unknown::new(origin)))
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    pub fn as_object(&self) -> Option<&ObjectRef> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Byte content of a `str` value, including instances of `str`
    /// subclasses.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Str(bytes) => Some(bytes.as_bytes()),
            Self::Object(object) => match &object.payload {
                Payload::Str(bytes) => Some(bytes.as_bytes()),
                _ => None,
            },
            _ => None,
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::NotImplemented => write!(f, "NotImplemented"),
            Self::Ellipsis => write!(f, "Ellipsis"),
            Self::Bool(value) => write!(f, "{}", if *value { "True" } else { "False" }),
            Self::Int(value) => write!(f, "{value}"),
            Self::Long(value) => write!(f, "{value:?}L"),
            Self::Float(value) => write!(f, "{value:?}"),
            Self::Str(bytes) => write!(f, "{bytes:?}"),
            Self::Unicode(text) => write!(f, "{text:?}"),
            Self::Tuple(items) => f.debug_tuple("").field(&&items[..]).finish(),
            Self::Object(object) => write!(f, "<{} #{}>", object.payload.kind_name(), object.id.0),
            Self::Unknown(unknown) => write!(f, "<unknown: {}>", unknown.origin),
        }
    }
}

/// The items of a tuple. The last owner frees them from the end, as
/// tuple deallocation does, so finalizers run in CPython's order.
#[derive(Clone)]
pub struct TupleItems(Rc<TupleData>);

struct TupleData {
    items: Box<[Value]>,
    /// Assigned when first observed.
    identity: OnceCell<ObjectId>,
}

impl TupleItems {
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Identity of the tuple, which `assign` provides when first asked.
    /// Every empty tuple is the same object.
    pub fn identity(&self, assign: impl FnOnce() -> ObjectId) -> ObjectId {
        if self.0.items.is_empty() {
            return empty_tuple_id();
        }

        *self.0.identity.get_or_init(assign)
    }

    /// The reference count of the tuple object.
    pub fn strong_count(&self) -> usize {
        Rc::strong_count(&self.0)
    }

    /// The items, when this is the only owner.
    pub fn unique_items_mut(&mut self) -> Option<&mut [Value]> {
        Rc::get_mut(&mut self.0).map(|data| &mut *data.items)
    }
}

impl std::ops::Deref for TupleItems {
    type Target = [Value];

    fn deref(&self) -> &[Value] {
        &self.0.items
    }
}

impl fmt::Debug for TupleItems {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0.items, f)
    }
}

impl From<Vec<Value>> for TupleItems {
    fn from(items: Vec<Value>) -> Self {
        Self(Rc::new(TupleData { items: items.into_boxed_slice(), identity: OnceCell::new() }))
    }
}

impl Drop for TupleItems {
    fn drop(&mut self) {
        let Some(items) = self.unique_items_mut() else {
            return;
        };

        let Some(level) = ReleaseLevel::enter() else {
            defer_items(items.iter_mut().rev().map(|item| std::mem::replace(item, Value::None)).collect());
            return;
        };

        for item in items.iter_mut().rev() {
            drop(std::mem::replace(item, Value::None));
        }

        drop(level);
    }
}

/// Reference to a heap object.
pub type ObjectRef = Rc<Object>;

pub struct Object {
    pub id: ObjectId,
    /// Set for every object once bootstrap completes. Only the objects
    /// created before `type` exists start without a class.
    pub class: RefCell<Option<ObjectRef>>,
    pub dict: RefCell<Option<ObjectRef>>,
    /// Values of `__slots__` members, indexed by `SlotIndex`; empty until
    /// the first store.
    pub slots: RefCell<Box<[Option<Value>]>>,
    pub payload: Payload,
    pub lifecycle: Cell<crate::interp::lifecycle::Lifecycle>,
    /// The serial number of the VM that allocated the object, whose
    /// finalizer queue its death goes to.
    pub owner: u32,
}

impl Object {
    pub fn class(&self) -> ObjectRef {
        let class = self.class.borrow();

        Rc::clone(class.as_ref().expect("every object has a class after bootstrap"))
    }

    pub fn set_class(&self, class: &ObjectRef) {
        *self.class.borrow_mut() = Some(Rc::clone(class));
    }

    pub fn dict(&self) -> Option<ObjectRef> {
        self.dict.borrow().as_ref().map(Rc::clone)
    }

    /// The value of the member at `index`; `None` while unset.
    pub fn slot(&self, index: SlotIndex) -> Option<Value> {
        self.slots.borrow().get(index.0).cloned().flatten()
    }

    /// Stores or clears the member at `index` of an instance of a class
    /// with `count` slots, returning the previous value.
    pub fn replace_slot(&self, index: SlotIndex, value: Option<Value>, count: usize) -> Option<Value> {
        let mut slots = self.slots.borrow_mut();
        if index.0 >= slots.len() {
            if value.is_none() {
                return None;
            }
            let mut grown = std::mem::take(&mut *slots).into_vec();
            grown.resize(count.max(index.0 + 1), None);
            *slots = grown.into_boxed_slice();
        }

        slots.get_mut(index.0).and_then(|slot| std::mem::replace(slot, value))
    }

    pub fn as_class(&self) -> Option<&ClassData> {
        match &self.payload {
            Payload::Class(class) => Some(class),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&RefCell<PyDict>> {
        match &self.payload {
            Payload::Dict(dict) => Some(dict),
            _ => None,
        }
    }

    pub fn as_module(&self) -> Option<&ModuleData> {
        match &self.payload {
            Payload::Module(module) => Some(module),
            _ => None,
        }
    }
}

/// Bound or unbound method. Python 2 unbound methods carry no `self` but
/// check the type of their first argument.
pub struct MethodData {
    pub function: Value,
    pub receiver: Option<Value>,
    pub class: Option<Value>,
}

#[derive(Clone)]
pub struct PropertyFields {
    pub getter: Value,
    pub setter: Value,
    pub deleter: Value,
    pub doc: Value,
}

/// A `property`; `__init__` fills the fields after allocation.
pub struct PropertyData(pub RefCell<PropertyFields>);

impl PropertyData {
    pub fn fields(&self) -> PropertyFields {
        self.0.borrow().clone()
    }
}

pub struct SuperData {
    pub class: ObjectRef,
    pub receiver: Option<Value>,
    pub receiver_class: Option<ObjectRef>,
}

pub struct SliceData {
    pub start: Value,
    pub stop: Value,
    pub step: Value,
}

#[derive(Clone, Copy)]
pub struct XRangeData {
    pub start: i64,
    pub length: i64,
    pub step: i64,
}

/// State a `finally` or `with` block carries on the value stack while the
/// frame unwinds through it. Never visible to Python code.
#[derive(Clone)]
pub enum UnwindMarker {
    Return(Value),
    Continue(usize),
    Break,
}

/// Storage of a `BaseException`: `args`, then the C struct fields beyond
/// it (`message`, `errno`, ...).
pub struct ExceptionData {
    pub args: RefCell<Value>,
    pub fields: RefCell<ExceptionFields>,
}

impl ExceptionData {
    pub fn new(args: Value) -> Self {
        Self { args: RefCell::new(args), fields: RefCell::default() }
    }
}

/// Storage of a `bytearray`. `alloc` tracks the capacity
/// CPython's resize policy would have reserved, which `__alloc__` and
/// `__sizeof__` report.
pub struct ByteArrayData {
    pub bytes: Vec<u8>,
    pub alloc: usize,
    /// Live memoryviews over the storage, which forbid
    /// resizing. Shared so that a view can release its export on drop
    /// without borrowing the storage.
    pub exports: Rc<Cell<usize>>,
}

impl ByteArrayData {
    /// An empty array allocates nothing;
    /// others reserve a trailing NUL.
    pub fn new(bytes: Vec<u8>) -> Self {
        let alloc = if bytes.is_empty() { 0 } else { bytes.len() + 1 };

        Self { bytes, alloc, exports: Rc::new(Cell::new(0)) }
    }
}

pub trait NativeData: Any {
    fn type_name(&self) -> &'static str;
    fn as_any(&self) -> &dyn Any;
}

/// The fields of an exception beyond `args`. A missing entry is an unset
/// field, except `message`, which `BaseException.__new__` sets to "".
#[derive(Default)]
pub struct ExceptionFields {
    pub values: Vec<(&'static str, Value)>,
    pub message_deleted: bool,
}

pub enum Payload {
    Instance,
    Int(i64),
    Long(PyLong),
    Float(f64),
    Complex(crate::interp::complex::Complex),
    Str(PyBytes),
    Unicode(PyText),
    Tuple(TupleItems),
    List(RefCell<Vec<Value>>),
    ByteArray(RefCell<ByteArrayData>),
    Dict(RefCell<PyDict>),
    Set(RefCell<PySet>),
    FrozenSet(PySet),
    Exception(ExceptionData),
    Function(FunctionData),
    NativeFunction(NativeFunction),
    Method(MethodData),
    Class(ClassData),
    Module(ModuleData),
    Cell(RefCell<Option<Value>>),
    Code(Rc<CodeObject>),
    Generator(RefCell<GeneratorData>),
    Iterator(RefCell<NativeIterator>),
    Property(PropertyData),
    StaticMethod(Value),
    ClassMethod(Value),
    Super(SuperData),
    Slice(SliceData),
    XRange(XRangeData),
    DictProxy(ObjectRef),
    Unwind(UnwindMarker),
    Frame(Rc<crate::interp::activation::Activation>),
    Native(Box<dyn NativeData>),
}

impl Payload {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Int(_) => "int",
            Self::Long(_) => "long",
            Self::Float(_) => "float",
            Self::Complex(_) => "complex",
            Self::Str(_) => "str",
            Self::Unicode(_) => "unicode",
            Self::Tuple(_) => "tuple",
            Self::List(_) => "list",
            Self::ByteArray(_) => "bytearray",
            Self::Dict(_) => "dict",
            Self::Set(_) => "set",
            Self::FrozenSet(_) => "frozenset",
            Self::Exception(..) => "exception",
            Self::Function(_) => "function",
            Self::NativeFunction(_) => "builtin_function_or_method",
            Self::Method(_) => "instancemethod",
            Self::Class(_) => "class",
            Self::Module(_) => "module",
            Self::Cell(_) => "cell",
            Self::Code(_) => "code",
            Self::Generator(_) => "generator",
            Self::Iterator(_) => "iterator",
            Self::Property(_) => "property",
            Self::StaticMethod(_) => "staticmethod",
            Self::ClassMethod(_) => "classmethod",
            Self::Super(_) => "super",
            Self::Slice(_) => "slice",
            Self::XRange(_) => "xrange",
            Self::DictProxy(_) => "dictproxy",
            Self::Unwind(_) => "unwind",
            Self::Frame(_) => "frame",
            Self::Native(native) => native.type_name(),
        }
    }
}
