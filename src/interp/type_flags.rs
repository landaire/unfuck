//! Type flags of new-style classes, read as `type.__flags__`. Static types
//! carry the flags CPython 2.7.12 for Windows x64 gives them; heap types
//! derive theirs from their base as `type.__new__` does.
//! `VALID_VERSION_TAG` follows the method cache: a cacheable
//! lookup on a type sets it on a class and its bases, and a change to a
//! type clears it on a class and its subclasses.

use std::cell::Cell;
use std::iter;
use std::rc::Rc;

use crate::interp::attr::MroLookup;
use crate::interp::object::ClassData;
use crate::interp::object::ClassStyle;
use crate::interp::object::MroEntry;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `__flags__` bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeFlags(u32);

impl TypeFlags {
    pub const HEAPTYPE: Self = Self(1 << 9);
    pub const HAVE_GC: Self = Self(1 << 14);
    pub const HAVE_VERSION_TAG: Self = Self(1 << 18);
    pub const VALID_VERSION_TAG: Self = Self(1 << 19);
    pub const IS_ABSTRACT: Self = Self(1 << 20);

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// The flags of a new-style class.
pub struct ClassFlags {
    flags: Cell<TypeFlags>,
    /// For a static type, the flags `type.__new__` gives a subclass that adds no
    /// instance storage; `None` when the type cannot be subclassed.
    subclass: Option<TypeFlags>,
}

impl ClassFlags {
    /// The flags of the static type `module.name` when Python code first
    /// reaches it, or `None` for a type CPython lacks.
    pub fn for_static_type(module: &str, name: &str) -> Option<Self> {
        let key = |entry: &StaticType| {
            if module == "__builtin__" {
                return entry.name.cmp(name);
            }
            entry.name.bytes().cmp(module.bytes().chain(iter::once(b'.')).chain(name.bytes()))
        };
        let index = STATIC_TYPES.binary_search_by(key).ok()?;
        let entry = &STATIC_TYPES[index];

        Some(Self { flags: Cell::new(entry.flags), subclass: entry.subclass })
    }

    pub fn get(&self) -> TypeFlags {
        self.flags.get()
    }

    fn insert(&self, flags: TypeFlags) {
        self.flags.set(self.flags.get().with(flags));
    }

    fn remove(&self, flags: TypeFlags) {
        self.flags.set(self.flags.get().without(flags));
    }

    /// The flags `type.__new__` starts a subclass of this class from.
    fn subclass(&self) -> Option<TypeFlags> {
        let flags = self.flags.get();
        if flags.contains(TypeFlags::HEAPTYPE) {
            return Some(flags.without(TypeFlags::VALID_VERSION_TAG).without(TypeFlags::IS_ABSTRACT));
        }

        self.subclass
    }
}

impl Vm {
    /// `type.__flags__` as a C `long`; unknown for a class with an unknown
    /// base or a static type CPython lacks.
    pub fn type_flags_value(&self, data: &ClassData) -> Value {
        match &data.flags {
            Some(flags) => Value::Int(self.config.long_width.wrap(i64::from(flags.get().bits()))),
            None => Value::unknown(format!("{}.__flags__", data.name().to_string_lossy())),
        }
    }
}

/// A static type of CPython 2.7.12 for Windows x64, recorded by
/// `tests/fixtures/interp/generate_type_flags.py`.
struct StaticType {
    /// `__module__` and `__name__` joined by a dot; the bare name for
    /// `__builtin__`.
    name: &'static str,
    /// The flags when Python code first reaches the type: at startup, after
    /// importing its module, or after creating an instance.
    flags: TypeFlags,
    subclass: Option<TypeFlags>,
}

/// Sorted by name.
const STATIC_TYPES: [StaticType; 268] = [
    StaticType { name: "BlockingIOError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "CArgObject", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DB", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBCursor", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBEnv", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBLock", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBLogCursor", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBSequence", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "DBTxn", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "Element", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "EncodingMap", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "MultibyteCodec", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "MultibyteIncrementalDecoder", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "MultibyteIncrementalEncoder", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "MultibyteStreamReader", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "MultibyteStreamWriter", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "NoneType", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "NotImplementedType", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "PyCapsule", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "PyHKEY", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "StgDict", flags: TypeFlags(0x2002_55EB), subclass: Some(TypeFlags(0x2002_57FB)) },
    StaticType { name: "Struct", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "TreeBuilder", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "XMLParser", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "_ast.AST", flags: TypeFlags(0x000E_15EB), subclass: Some(TypeFlags(0x0006_17FB)) },
    StaticType { name: "_csv.Dialect", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_csv.reader", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_csv.writer", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_ctypes.Array", flags: TypeFlags(0x0022_15EB), subclass: None },
    StaticType { name: "_ctypes.CField", flags: TypeFlags(0x0002_51EB), subclass: None },
    StaticType { name: "_ctypes.CThunkObject", flags: TypeFlags(0x0002_51EB), subclass: None },
    StaticType { name: "_ctypes.DictRemover", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "_ctypes.PyCArrayType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes.PyCFuncPtr", flags: TypeFlags(0x0022_15EB), subclass: None },
    StaticType { name: "_ctypes.PyCFuncPtrType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes.PyCPointerType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes.PyCSimpleType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes.PyCStructType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes.Structure", flags: TypeFlags(0x0022_15EB), subclass: Some(TypeFlags(0x0022_57FB)) },
    StaticType { name: "_ctypes.Union", flags: TypeFlags(0x0022_15EB), subclass: Some(TypeFlags(0x0022_57FB)) },
    StaticType { name: "_ctypes.UnionType", flags: TypeFlags(0x8002_55EB), subclass: Some(TypeFlags(0x8002_57FB)) },
    StaticType { name: "_ctypes._CData", flags: TypeFlags(0x0022_15EB), subclass: Some(TypeFlags(0x0022_57FB)) },
    StaticType { name: "_ctypes._Pointer", flags: TypeFlags(0x0022_15EB), subclass: Some(TypeFlags(0x0022_57EB)) },
    StaticType { name: "_ctypes._SimpleCData", flags: TypeFlags(0x0022_15EB), subclass: None },
    StaticType { name: "_hashlib.HASH", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_hotshot.LogReaderType", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_hotshot.ProfilerType", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_io.BufferedRWPair", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.BufferedRandom", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.BufferedReader", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.BufferedWriter", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.BytesIO", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.FileIO", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.IncrementalNewlineDecoder", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.StringIO", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io.TextIOWrapper", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io._BufferedIOBase", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io._IOBase", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io._RawIOBase", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_io._TextIOBase", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_json.Encoder", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "_json.Scanner", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "_lsprof.Profiler", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_lsprof.profiler_entry", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_lsprof.profiler_subentry", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_md5.md5", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_multiprocessing.Connection", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_multiprocessing.PipeConnection", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_multiprocessing.SemLock", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_multiprocessing.win32", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "_random.Random", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "_sha.sha", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_sha256.sha224", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_sha256.sha256", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_sha512.sha384", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_sha512.sha512", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_socket.socket", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_sre.SRE_Match", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_sre.SRE_Pattern", flags: TypeFlags(0x000E_11EB), subclass: None },
    StaticType { name: "_sre.SRE_Scanner", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "_ssl._SSLContext", flags: TypeFlags(0x0002_55EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "_ssl._SSLSocket", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "_subprocess_handle", flags: TypeFlags(0x0000_1000), subclass: None },
    StaticType { name: "_thread._localdummy", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "array.array", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "arrayiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "basestring", flags: TypeFlags(0x000E_15EB), subclass: Some(TypeFlags(0x0006_17FB)) },
    StaticType { name: "bool", flags: TypeFlags(0x0086_11FB), subclass: None },
    StaticType { name: "buffer", flags: TypeFlags(0x0026_11EB), subclass: None },
    StaticType { name: "builtin_function_or_method", flags: TypeFlags(0x000E_51EB), subclass: None },
    StaticType { name: "bytearray", flags: TypeFlags(0x002E_15EB), subclass: Some(TypeFlags(0x0026_57FB)) },
    StaticType { name: "bytearray_iterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "bz2.BZ2Compressor", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "bz2.BZ2Decompressor", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "bz2.BZ2File", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "cPickle.Pickler", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "cPickle.Unpickler", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "cStringIO.StringI", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "cStringIO.StringO", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "callable-iterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "cell", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "classmethod", flags: TypeFlags(0x000E_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "classmethod_descriptor", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "classobj", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "code", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "collections.defaultdict", flags: TypeFlags(0x2006_55EB), subclass: Some(TypeFlags(0x2006_57FB)) },
    StaticType { name: "collections.deque", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "complex", flags: TypeFlags(0x000E_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "datetime.date", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "datetime.datetime", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "datetime.time", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "datetime.timedelta", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "datetime.tzinfo", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_17FB)) },
    StaticType { name: "deque_iterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "deque_reverse_iterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "dict", flags: TypeFlags(0x200E_55EB), subclass: Some(TypeFlags(0x2006_57FB)) },
    StaticType { name: "dict_items", flags: TypeFlags(0x0006_51FB), subclass: None },
    StaticType { name: "dict_keys", flags: TypeFlags(0x0006_51FB), subclass: None },
    StaticType { name: "dict_values", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "dictionary-itemiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "dictionary-keyiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "dictionary-valueiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "dictproxy", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "ellipsis", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "enumerate", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "exceptions.ArithmeticError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.AssertionError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.AttributeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.BaseException", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.BufferError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.BytesWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.DeprecationWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.EOFError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.EnvironmentError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.Exception", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.FloatingPointError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.FutureWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.GeneratorExit", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.IOError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.ImportError", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.ImportWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.IndentationError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.IndexError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.KeyError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.KeyboardInterrupt", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.LookupError", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.MemoryError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.NameError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.NotImplementedError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.OSError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.OverflowError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.PendingDeprecationWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.ReferenceError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.RuntimeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.RuntimeWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.StandardError", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.StopIteration", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.SyntaxError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.SyntaxWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.SystemError", flags: TypeFlags(0x400E_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.SystemExit", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.TabError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.TypeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnboundLocalError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnicodeDecodeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnicodeEncodeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnicodeError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnicodeTranslateError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UnicodeWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.UserWarning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.ValueError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.Warning", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.WindowsError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "exceptions.ZeroDivisionError", flags: TypeFlags(0x4006_55EB), subclass: Some(TypeFlags(0x4006_57FB)) },
    StaticType { name: "fieldnameiterator", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "file", flags: TypeFlags(0x000E_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "float", flags: TypeFlags(0x0006_15FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "formatteriterator", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "frame", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "frozenset", flags: TypeFlags(0x0006_55FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "function", flags: TypeFlags(0x000E_51EB), subclass: None },
    StaticType { name: "functools.partial", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "generator", flags: TypeFlags(0x000E_51EB), subclass: None },
    StaticType { name: "getset_descriptor", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "imp.NullImporter", flags: TypeFlags(0x000E_11EB), subclass: None },
    StaticType { name: "instance", flags: TypeFlags(0x0006_51FB), subclass: None },
    StaticType { name: "instancemethod", flags: TypeFlags(0x000E_51EB), subclass: None },
    StaticType { name: "int", flags: TypeFlags(0x008E_15FB), subclass: Some(TypeFlags(0x0086_57FB)) },
    StaticType { name: "iterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "itertools._grouper", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "itertools.chain", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.combinations", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.combinations_with_replacement", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.compress", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.count", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.cycle", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.dropwhile", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.groupby", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.ifilter", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.ifilterfalse", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.imap", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.islice", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.izip", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.izip_longest", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.permutations", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.product", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.repeat", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.starmap", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.takewhile", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "itertools.tee", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "itertools.tee_dataobject", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "list", flags: TypeFlags(0x020E_55EB), subclass: Some(TypeFlags(0x0206_57FB)) },
    StaticType { name: "listiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "listreverseiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "long", flags: TypeFlags(0x0106_15FB), subclass: Some(TypeFlags(0x0106_57FB)) },
    StaticType { name: "member_descriptor", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "memoryview", flags: TypeFlags(0x0026_51EB), subclass: None },
    StaticType { name: "method-wrapper", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "method_descriptor", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "mmap.mmap", flags: TypeFlags(0x0006_15EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "module", flags: TypeFlags(0x000E_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "nt.stat_result", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "nt.statvfs_result", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "object", flags: TypeFlags(0x000E_15EB), subclass: Some(TypeFlags(0x0006_17FB)) },
    StaticType { name: "operator.attrgetter", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "operator.itemgetter", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "operator.methodcaller", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "parser.st", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "property", flags: TypeFlags(0x000E_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "pyexpat.xmlparser", flags: TypeFlags(0x0002_51EB), subclass: None },
    StaticType { name: "rangeiterator", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "reversed", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "set", flags: TypeFlags(0x000E_55FB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "setiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "slice", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "sqlite3.Cache", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "sqlite3.Connection", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "sqlite3.Cursor", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "sqlite3.PrepareProtocol", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "sqlite3.Row", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "sqlite3.Statement", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "sqlite3Node", flags: TypeFlags(0x0002_15EB), subclass: Some(TypeFlags(0x0002_57FB)) },
    StaticType { name: "staticmethod", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "str", flags: TypeFlags(0x082E_15FB), subclass: Some(TypeFlags(0x0826_57FB)) },
    StaticType { name: "super", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "symtable entry", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "sys.flags", flags: TypeFlags(0x000E_11EB), subclass: None },
    StaticType { name: "sys.float_info", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "sys.getwindowsversion", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "sys.long_info", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "sys.version_info", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "thread._local", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "thread.lock", flags: TypeFlags(0x0000_1040), subclass: None },
    StaticType { name: "time.struct_time", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "traceback", flags: TypeFlags(0x000E_51EB), subclass: None },
    StaticType { name: "tuple", flags: TypeFlags(0x040E_55EB), subclass: Some(TypeFlags(0x0406_57FB)) },
    StaticType { name: "tupleiterator", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "type", flags: TypeFlags(0x800E_55EB), subclass: Some(TypeFlags(0x8006_57FB)) },
    StaticType { name: "unicode", flags: TypeFlags(0x1006_15FB), subclass: Some(TypeFlags(0x1006_57FB)) },
    StaticType { name: "unicodedata.UCD", flags: TypeFlags(0x0002_11EB), subclass: None },
    StaticType { name: "weakcallableproxy", flags: TypeFlags(0x0006_51FB), subclass: None },
    StaticType { name: "weakproxy", flags: TypeFlags(0x0006_51FB), subclass: None },
    StaticType { name: "weakref", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
    StaticType { name: "wrapper_descriptor", flags: TypeFlags(0x0006_51EB), subclass: None },
    StaticType { name: "xrange", flags: TypeFlags(0x0006_11EB), subclass: None },
    StaticType { name: "xxsubtype.spamdict", flags: TypeFlags(0x2006_55EB), subclass: Some(TypeFlags(0x2006_57FB)) },
    StaticType { name: "xxsubtype.spamlist", flags: TypeFlags(0x0206_55EB), subclass: Some(TypeFlags(0x0206_57FB)) },
    StaticType { name: "zipimport.zipimporter", flags: TypeFlags(0x0006_55EB), subclass: Some(TypeFlags(0x0006_57FB)) },
];

/// The flags `type.__new__` gives a class whose solid base is `best_base`
/// (`__base__`) before its MRO is set; `None` when a base is unknown or
/// lacks recorded flags. `adds_storage` is true when the class adds slots,
/// a `__dict__`, or a `__weakref__` list, which makes its instances larger
/// than a bare `object` and so garbage collected.
pub fn heap_type_flags(best_base: &ObjectRef, bases: &[Value], adds_storage: bool) -> Option<ClassFlags> {
    if bases.iter().any(Value::is_unknown) {
        return None;
    }

    let mut flags = class_flags(best_base)?.subclass()?;
    if adds_storage {
        flags = flags.with(TypeFlags::HAVE_GC);
    }

    Some(ClassFlags { flags: Cell::new(flags), subclass: None })
}

/// After an MRO change: a class whose MRO or bases hold a classic class, or
/// a class without `HAVE_VERSION_TAG`, cannot use the method
/// cache.
pub fn mro_modified(class: &ObjectRef) {
    let Some(data) = class.as_class() else {
        return;
    };
    let Some(flags) = &data.flags else {
        return;
    };
    if !flags.get().contains(TypeFlags::HAVE_VERSION_TAG) {
        return;
    }

    let mro = data.mro.borrow().iter().filter_map(|entry| match entry {
        MroEntry::Class(class) => Some(Rc::clone(class)),
        MroEntry::Unknown(_) => None,
    }).collect::<Vec<_>>();
    let bases = data.bases.borrow().iter().filter_map(|base| base.as_object().map(Rc::clone)).collect::<Vec<_>>();
    let cacheable = mro.iter().chain(&bases).all(|entry| class_flags(entry).is_some_and(|entry_flags| entry_flags.get().contains(TypeFlags::HAVE_VERSION_TAG)));
    if !cacheable {
        flags.remove(TypeFlags::HAVE_VERSION_TAG.with(TypeFlags::VALID_VERSION_TAG));
    }
}

/// A lookup of `name` on `class` as the method cache sees it: a cacheable
/// name assigns version tags to `class` and its bases.
pub fn note_lookup(class: &ObjectRef, name: &PyBytes) {
    // A cacheable name is an exact `str` of at most this many bytes.
    const MAX_ATTR_SIZE: usize = 100;

    if !name.is_subclass_name() && name.as_bytes().len() <= MAX_ATTR_SIZE {
        assign_version_tag(class);
    }
}

/// A lookup on `class` of a special method name, an interned
/// `str` constant the method cache always accepts.
pub fn note_special_lookup(class: &ObjectRef) {
    assign_version_tag(class);
}

/// A special method lookup that `found` answered. A heap class defining the
/// method replaces the type slot with a `slot_*` function, which looks the
/// method up on `class`; inherited native slots look up nothing.
pub fn note_slot_lookup(class: &ObjectRef, found: &MroLookup) {
    let MroLookup::Found { owner, .. } = found else {
        return;
    };
    if owner.as_class().is_some_and(|data| !data.builtin) {
        assign_version_tag(class);
    }
}

/// Sets `VALID_VERSION_TAG` on `class` and
/// its bases unless one of them cannot use the method cache.
fn assign_version_tag(class: &ObjectRef) {
    // A class holding a valid tag has bases holding one too, and a class
    // without `HAVE_VERSION_TAG` never gets one.
    let Some(flags) = class_flags(class) else {
        return;
    };
    let current = flags.get();
    if current.contains(TypeFlags::VALID_VERSION_TAG) || !current.contains(TypeFlags::HAVE_VERSION_TAG) {
        return;
    }

    let mut pending = vec![Rc::clone(class)];
    let mut assigned = Vec::new();

    while let Some(next) = pending.pop() {
        let Some(flags) = class_flags(&next) else {
            return;
        };
        let current = flags.get();
        if current.contains(TypeFlags::VALID_VERSION_TAG) {
            continue;
        }
        if !current.contains(TypeFlags::HAVE_VERSION_TAG) {
            return;
        }

        if let Some(data) = next.as_class() {
            for base in data.bases.borrow().iter() {
                let Value::Object(base) = base else {
                    return;
                };
                pending.push(Rc::clone(base));
            }
        }
        assigned.push(next);
    }

    for class in assigned {
        if let Some(flags) = class_flags(&class) {
            flags.insert(TypeFlags::VALID_VERSION_TAG);
        }
    }
}

/// Clears `VALID_VERSION_TAG` on `class` and
/// its subclasses after its attributes, bases, or MRO change.
pub fn type_modified(class: &ObjectRef) {
    if !class_flags(class).is_some_and(|flags| flags.get().contains(TypeFlags::VALID_VERSION_TAG)) {
        return;
    }

    let mut pending = vec![Rc::clone(class)];

    while let Some(next) = pending.pop() {
        let Some(data) = next.as_class() else {
            continue;
        };
        let Some(flags) = &data.flags else {
            continue;
        };
        if !flags.get().contains(TypeFlags::VALID_VERSION_TAG) {
            continue;
        }

        flags.remove(TypeFlags::VALID_VERSION_TAG);
        pending.extend(data.subclasses.borrow().iter().filter_map(std::rc::Weak::upgrade));
    }
}

/// Assignment to `__abstractmethods__`: `IS_ABSTRACT` follows the truth of
/// the assigned `__abstractmethods__`.
pub fn set_abstract(class: &ObjectRef, abstract_methods: bool) {
    type_modified(class);

    let Some(flags) = class_flags(class) else {
        return;
    };
    if abstract_methods {
        flags.insert(TypeFlags::IS_ABSTRACT);
    } else {
        flags.remove(TypeFlags::IS_ABSTRACT);
    }
}

fn class_flags(class: &ObjectRef) -> Option<&ClassFlags> {
    let data = class.as_class()?;
    if data.style == ClassStyle::Classic {
        return None;
    }

    data.flags.as_ref()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::interp::builtins::exec::compile_module;
    use crate::interp::compiler::CompilerFlags;
    use crate::interp::compiler::Mode;
    use crate::interp::compiler::parse;
    use crate::interp::error::PyResult;
    use crate::interp::error::Signal;
    use crate::interp::hash::LongWidth;
    use crate::interp::object::CallArgs;
    use crate::interp::lib_source::LibSource;
    use crate::interp::vm::VmConfig;

    /// The standard library modules of the conformance cases, compiled from
    /// `PYTHON27_LIB` (default: the Windows 2.7.12 `Lib` under Wine), or
    /// `None` when no `Lib` directory is available.
    fn stdlib() -> Option<LibSource> {
        const DEFAULT_LIB: &str = "/var/mnt/build/winpy/prefix/drive_c/py2712/Lib";

        let lib = std::env::var_os("PYTHON27_LIB").map_or_else(|| std::path::PathBuf::from(DEFAULT_LIB), std::path::PathBuf::from);
        if !lib.join("os.py").is_file() {
            return None;
        }
        let list = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/interp/stdlib_modules.txt")).unwrap_or_else(|error| panic!("stdlib_modules.txt: {error}"));
        let modules = list.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect();

        Some(LibSource::new(lib, modules, LongWidth::Bits32))
    }

    /// Discovers static types as `generate_type_flags.py` does, recording
    /// `__flags__` when each first becomes reachable, then the flags of a
    /// slotless subclass of each.
    const PROBE: &str = r#"
SUBCLASSES = type.__dict__['__subclasses__']
seen = {}
order = []

def record(t):
    if t in seen:
        return
    seen[t] = t.__flags__
    order.append(t)

def walk(t):
    record(t)
    for sub in SUBCLASSES(t):
        walk(sub)

def record_static(value):
    for t in CLASSES([value]):
        record(t)

def generator():
    yield 1

def cell():
    value = 1
    return (lambda: value).func_closure[0]

def traceback():
    try:
        raise ValueError
    except ValueError:
        return sys.exc_info()[2]

walk(object)
for name in MODULES:
    module = __import__(name)
    walk(object)
    for t in CLASSES(vars(module).values()):
        record(t)

import _io
import array
import collections
import cStringIO
import itertools
import re
import sys
import thread

# The interpreter lacks `buffer('')`, the `type.__dict__` descriptors, and
# `sys.long_info`; the walk reaches their types. CPython readies the tee type
# when importing itertools, so a single copy keeps `__copy__` from looking
# up attributes of it before it is recorded.
factories = [
    lambda: iter([]), lambda: iter(()), lambda: iter(''), lambda: iter(u''), lambda: iter({}),
    lambda: iter(set()), lambda: iter(bytearray()), lambda: iter(xrange(1)), lambda: iter(lambda: 1, 2),
    lambda: reversed([]), lambda: reversed(xrange(1)), lambda: reversed('a'), lambda: {}.iterkeys(),
    lambda: {}.itervalues(), lambda: {}.iteritems(), lambda: {}.viewkeys(), lambda: {}.viewvalues(),
    lambda: {}.viewitems(), generator, cell, traceback, lambda: sys._getframe(), lambda: enumerate([]),
    lambda: memoryview(''), lambda: NotImplemented, lambda: Ellipsis, lambda: None,
    lambda: slice(1), lambda: property(), lambda: staticmethod(None), lambda: classmethod(None),
    lambda: super(object), lambda: (1).__add__, lambda: [].append, lambda: object.__init__,
    lambda: int.__add__, lambda: dict.fromkeys, lambda: dict.__dict__, lambda: complex.real,
    lambda: iter(collections.deque()), lambda: reversed(collections.deque()),
    lambda: iter(array.array('b')), lambda: re.compile('a'), lambda: re.compile('a').match('a'),
    lambda: re.compile('a').scanner('a'), lambda: cStringIO.StringIO(), lambda: cStringIO.StringIO('a'),
    lambda: thread.allocate_lock(), lambda: itertools.tee([], 1)[0], lambda: next(itertools.groupby('a'))[1],
    lambda: _io.BytesIO(), lambda: _io.StringIO(), lambda: sys.flags, lambda: sys.float_info,
    lambda: sys.version_info, lambda: sys.getwindowsversion(), lambda: list.__dict__['append'],
    lambda: dict.__dict__['fromkeys'],
]
for factory in factories:
    value = factory()
    record_static(type(value))
    record_static(value)
walk(object)

def subclass_flags(t):
    try:
        return type('X', (t,), {'__slots__': ()}).__flags__
    except TypeError:
        return None

RESULT = [(t, seen[t], subclass_flags(t)) for t in order]
"#;

    /// Native types the interpreter defines that CPython lacks.
    const INTERPRETER_ONLY: [&str; 2] = ["sys.StandardStream", "unwind_marker"];

    struct Recorded {
        flags: u32,
        subclass: Option<u32>,
    }

    fn windows_types() -> BTreeMap<String, Recorded> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/interp/win64_type_flags.json");
        let text = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {path}: {error}"));
        let entries: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_else(|error| panic!("parsing {path}: {error}"));

        entries
            .iter()
            .map(|entry| {
                let flags = |field: &str| entry[field].as_u64().map(|bits| u32::try_from(bits).unwrap_or_else(|_| panic!("{field} out of range")));
                let name = entry["name"].as_str().unwrap_or_else(|| panic!("entry without name")).to_owned();
                (name, Recorded { flags: flags("flags").unwrap_or_else(|| panic!("entry without flags")), subclass: flags("subclass") })
            })
            .collect()
    }

    fn run_probe(vm: &Vm, modules: &[&str]) -> Vec<Value> {
        let module = parse(PROBE.as_bytes(), b"<probe>", Mode::Exec, CompilerFlags::default()).unwrap_or_else(|error| panic!("parse: {error:?}"));
        let Ok(Value::Object(code)) = compile_module(vm, &module, b"<probe>", CompilerFlags::default()) else {
            panic!("compile failed");
        };

        let globals = vm.new_dict();
        let names = modules.iter().map(|name| Value::str(name)).collect();
        let setup = vm.dict_set_str(&globals, "MODULES", Value::tuple(names)).and_then(|()| vm.dict_set_str(&globals, "__name__", Value::str("probe"))).and_then(|()| vm.dict_set_str(&globals, "__builtins__", Value::Object(vm.current_builtins()))).and_then(|()| vm.dict_set_str(&globals, "CLASSES", vm.new_native_function("CLASSES", classes)));
        if setup.is_err() {
            panic!("probe setup failed");
        }

        match vm.eval_code(&code, &globals, &globals) {
            Ok(_) => {}
            Err(Signal::Raise(error)) => panic!("probe raised {}", vm.describe_exception(&error)),
            Err(Signal::Halt(halt)) => panic!("probe halted: {halt}"),
        }
        let Ok(Some(result)) = vm.dict_get_str(&globals, "RESULT") else {
            panic!("probe bound no RESULT");
        };

        vm.collect(&result).unwrap_or_else(|_| panic!("RESULT is not iterable"))
    }

    /// `CLASSES(values)`: the new-style classes among `values`, which may
    /// hold unknown values that Python code cannot test without halting.
    fn classes(vm: &Vm, args: CallArgs) -> PyResult<Value> {
        let Some(values) = args.positional.first() else {
            return Err(vm.type_error("CLASSES takes one argument"));
        };
        let classes = vm.collect(values)?.into_iter().filter(|value| value.as_object().and_then(|object| object.as_class()).is_some_and(|data| data.style == ClassStyle::NewStyle)).collect();

        Ok(vm.new_list(classes))
    }

    fn wrap(vm: &Vm, flags: u32) -> i64 {
        vm.config.long_width.wrap(i64::from(flags))
    }

    fn describe(value: &Value) -> String {
        match value {
            Value::Int(bits) => format!("{bits:#X}"),
            Value::None => "None".to_owned(),
            Value::Unknown(unknown) => format!("unknown {}", unknown.origin),
            _ => "?".to_owned(),
        }
    }

    /// Every native type reports the flags CPython 2.7.12 for Windows x64
    /// gives it when Python code first reaches it, and its slotless
    /// subclasses get the flags `type.__new__` gives them there.
    #[test]
    fn static_types_match_windows() {
        // The modules of the Windows build: those built into python27.dll,
        // then the extension modules of DLLs/.
        const MODULES: [&str; 74] = [
            "_ast", "_bisect", "_codecs", "_codecs_cn", "_codecs_hk", "_codecs_iso2022", "_codecs_jp", "_codecs_kr", "_codecs_tw", "_collections", "_csv", "_functools", "_heapq", "_hotshot", "_io", "_json", "_locale",
            "_lsprof", "_md5", "_multibytecodec", "_random", "_sha", "_sha256", "_sha512", "_sre", "_struct", "_subprocess", "_symtable", "_warnings", "_weakref", "_winreg", "array", "audioop", "binascii",
            "cPickle", "cStringIO", "cmath", "datetime", "errno", "exceptions", "future_builtins", "gc", "imageop", "imp", "itertools", "marshal", "math", "mmap", "msvcrt", "nt", "operator", "parser", "signal", "strop",
            "sys", "thread", "time", "xxsubtype", "zipimport", "zlib", "bz2", "pyexpat", "select", "unicodedata", "winsound", "_bsddb", "_ctypes", "_elementtree", "_hashlib", "_msi", "_multiprocessing", "_socket",
            "_sqlite3", "_ssl",
        ];

        let mut config = VmConfig::windows_x64();
        config.long_width = LongWidth::Bits32;
        let Some(stdlib) = stdlib() else {
            eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
            return;
        };
        let Ok(vm) = Vm::new(config, Box::new(stdlib)) else {
            panic!("interpreter bootstrap failed");
        };

        let modules: Vec<&str> = MODULES.into_iter().filter(|name| vm.native_module(name).is_some()).collect();
        let windows = windows_types();

        let mut mismatches = Vec::new();
        let mut absent = Vec::new();
        for entry in run_probe(&vm, &modules) {
            let Value::Tuple(fields) = entry else {
                panic!("RESULT entry is not a tuple");
            };
            let [Value::Object(class), flags, subclass] = &fields[..] else {
                panic!("RESULT entry has the wrong shape");
            };
            let Some(data) = class.as_class() else {
                panic!("RESULT holds a non-class");
            };
            if !data.builtin {
                continue;
            }

            let Ok(Value::Str(module)) = vm.type_module(class, data) else {
                panic!("type module is not a string");
            };
            let name = data.name().to_string_lossy();
            let module = module.to_string_lossy();
            let key = if module == "__builtin__" { name } else { format!("{module}.{name}") };

            let Some(recorded) = windows.get(&key) else {
                absent.push(key);
                continue;
            };
            if !matches!(flags, Value::Int(bits) if *bits == wrap(&vm, recorded.flags)) {
                mismatches.push(format!("{key}: flags {}, Windows {:#X}", describe(flags), recorded.flags));
            }

            // `__flags__` of a slotless subclass, without the version tag
            // its creation assigned.
            let actual = match subclass {
                Value::Int(bits) => Some(wrap(&vm, (*bits as u32) & !TypeFlags::VALID_VERSION_TAG.bits())),
                _ => None,
            };
            if actual != recorded.subclass.map(|bits| wrap(&vm, bits)) {
                mismatches.push(format!("{key}: subclass {}, Windows {:X?}", describe(subclass), recorded.subclass));
            }
        }

        absent.sort();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        assert_eq!(absent, INTERPRETER_ONLY, "native types without Windows flags");
    }
}
