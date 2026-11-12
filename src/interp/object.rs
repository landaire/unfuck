use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::code::CodeObject;
use crate::interp::error::PyResult;
use crate::interp::frame::Frame;
use crate::interp::type_flags::ClassFlags;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Unknown;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Old-style (`classobj`) or new-style (`type`) class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassStyle {
    Classic,
    NewStyle,
}

/// The builtin storage instances of a class carry, inherited from its solid
/// base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Object,
    Int,
    Long,
    Float,
    Str,
    Unicode,
    Tuple,
    List,
    Dict,
    Set,
    FrozenSet,
    Exception,
    Type,
    Function,
    Module,
    Property,
    Native,
}

/// One entry of a method resolution order. A base that is the result of
/// unemulated native code stays in the order as an unknown entry; lookups
/// that reach it produce unknown values.
#[derive(Clone)]
pub enum MroEntry {
    Class(ObjectRef),
    Unknown(Rc<Unknown>),
}

/// Index into an object's slot array: the offset of the member
/// `type.__new__` made for a `__slots__` name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotIndex(pub usize);

/// Where instances keep their `__dict__` or weak reference list
/// (`__dictoffset__`, `__weakrefoffset__`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOffset {
    /// Inside the struct of a builtin type.
    Builtin,
    /// The pointer-sized word at this index past the builtin solid base.
    Word(usize),
    /// After the items of a variable-size object (a negative offset).
    Trailing,
}

/// The instance struct `type.__new__` lays out, in pointer-sized words past the
/// builtin solid base.
pub struct HeapLayout {
    /// `__base__`.
    pub base: RefCell<ObjectRef>,
    /// `__basicsize__`.
    pub size: usize,
    pub dict: Option<StorageOffset>,
    pub weak: Option<StorageOffset>,
    /// Length of the slot array of instances.
    pub slot_count: usize,
    /// The sorted, mangled member names of the class body's
    /// `__slots__`, which take the last slots; `None` without `__slots__`.
    pub members: Option<Box<[PyBytes]>>,
}

pub struct ClassData {
    pub name: RefCell<PyBytes>,
    pub bases: RefCell<Vec<Value>>,
    pub mro: RefCell<Vec<MroEntry>>,
    pub dict: ObjectRef,
    pub style: ClassStyle,
    pub layout: Layout,
    /// Instances own a `__dict__`. False for builtin types and for classes
    /// whose `__slots__` omit `__dict__`.
    pub instance_dict: bool,
    /// Defined by the interpreter rather than by Python code.
    pub builtin: bool,
    /// Direct subclasses in creation order (`__subclasses__()`), held weakly.
    pub subclasses: RefCell<Vec<std::rc::Weak<crate::interp::value::Object>>>,
    /// `__flags__` of a new-style class; `None` for a classic class and for a
    /// class whose flags are unknown.
    pub flags: Option<ClassFlags>,
    /// Set for a class `type.__new__` created.
    pub heap_layout: Option<HeapLayout>,
}

impl ClassData {
    pub fn name(&self) -> PyBytes {
        self.name.borrow().clone()
    }

    pub fn mro(&self) -> Vec<MroEntry> {
        self.mro.borrow().clone()
    }

    pub fn bases(&self) -> Vec<Value> {
        self.bases.borrow().clone()
    }
}

pub struct FunctionData {
    pub code: Rc<CodeObject>,
    /// The code object `code` came from, so `func_code` and `f_code` keep
    /// their identity.
    pub code_object: ObjectRef,
    pub globals: ObjectRef,
    pub name: RefCell<PyBytes>,
    pub defaults: RefCell<Option<Vec<Value>>>,
    pub closure: Option<Vec<ObjectRef>>,
    pub module: RefCell<Value>,
    pub doc: RefCell<Value>,
}

/// Positional and keyword arguments of a call, in source order.
#[derive(Clone, Default)]
pub struct CallArgs {
    pub positional: Vec<Value>,
    pub keywords: Vec<(PyBytes, Value)>,
    /// The complete keyword dict when `**mapping` supplied a key that is not
    /// a string; `keywords` then holds only the string-keyed entries. C
    /// callees such as `dict` accept any key, while Python functions and
    /// argument parsers reject the call.
    pub keyword_dict: Option<ObjectRef>,
}

impl CallArgs {
    pub fn new(positional: Vec<Value>) -> Self {
        Self { positional, keywords: Vec::new(), keyword_dict: None }
    }

    pub fn keyword(&self, name: &str) -> Option<&Value> {
        self.keywords.iter().find(|(key, _)| key.as_bytes() == name.as_bytes()).map(|(_, value)| value)
    }

    pub fn has_keywords(&self) -> bool {
        !self.keywords.is_empty() || self.keyword_dict.is_some()
    }
}

pub type NativeFn = fn(&Vm, CallArgs) -> PyResult<Value>;

/// How a native callable stored in a class dict binds on attribute access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeBinding {
    /// A plain function (`len`); never binds.
    Function,
    /// A method descriptor (`list.append`); binds the instance.
    Method,
    /// A class method descriptor (`dict.fromkeys`); binds the class.
    ClassMethod,
    /// `__new__` of a builtin type; a static method taking the class first.
    StaticMethod,
}

pub struct NativeFunction {
    pub name: &'static str,
    pub function: NativeFn,
    pub binding: NativeBinding,
    pub receiver: Option<Value>,
    pub owner: Option<ObjectRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    /// Executed from bytecode.
    Source,
    /// Implemented by the interpreter.
    Native,
    /// A client module implemented in the game executable that the
    /// interpreter does not emulate. Missing attributes are unknown values.
    Opaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleState {
    Loading,
    Ready,
    /// The module body stopped before completing. Missing attributes are
    /// unknown values because the remaining body never ran.
    Incomplete,
}

pub struct ModuleData {
    pub name: PyBytes,
    pub kind: ModuleKind,
    pub state: Cell<ModuleState>,
}

impl ModuleData {
    /// Whether a missing attribute should read as unknown rather than raise.
    pub fn missing_is_unknown(&self) -> bool {
        self.kind == ModuleKind::Opaque || self.state.get() == ModuleState::Incomplete
    }
}

pub enum GeneratorState {
    Created(Box<Frame>),
    Suspended(Box<Frame>),
    Running,
    Finished,
}

pub struct GeneratorData {
    pub state: GeneratorState,
    pub name: PyBytes,
    /// `gi_code`.
    pub code_object: ObjectRef,
    /// The frame's activation for `gi_frame`, released when the generator
    /// finishes as CPython releases `gi_frame`.
    pub activation: Option<Rc<crate::interp::activation::Activation>>,
}

impl GeneratorData {
    pub fn finish(&mut self) {
        self.state = GeneratorState::Finished;
        self.activation = None;
    }
}

/// Iterators over builtin containers and builtin lazy sequences.
pub enum NativeIterator {
    /// `list`, `tuple`, `str`, and `unicode` by index; sees list mutation as
    /// CPython's `listiterator` does.
    Sequence { sequence: Value, index: usize },
    /// Old iteration protocol: `__getitem__` with 0, 1, 2, ... until
    /// `IndexError`.
    GetItem { target: Value, index: i64 },
    /// `length` is the size at creation, which must not change;
    /// `remaining` counts the items not yet produced, which `len()` reports.
    DictKeys { dict: ObjectRef, position: usize, length: usize, remaining: usize },
    DictValues { dict: ObjectRef, position: usize, length: usize, remaining: usize },
    DictItems { dict: ObjectRef, position: usize, length: usize, remaining: usize },
    Set { set: ObjectRef, position: usize, length: usize, remaining: usize },
    Range { next: i64, remaining: i64, step: i64 },
    Reversed { sequence: Value, index: Option<usize> },
    /// `count` is the next index as a Python `int` or `long`.
    Enumerate { iterator: Value, count: Value },
    Zip { iterators: Vec<Value> },
    Map { function: Value, iterators: Vec<Value> },
    Filter { function: Value, iterator: Value, invert: bool },
    Callable { function: Value, sentinel: Value },
    Chain { iterables: Vec<Value>, current: Option<Value>, index: usize },
    Count { next: Value, step: Value },
    Repeat { value: Value, remaining: Option<i64> },
    Exhausted,
}
