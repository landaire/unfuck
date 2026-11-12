use std::any::Any;
use std::any::TypeId;
use std::cell::Cell;
use std::cell::OnceCell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::activation::Activation;
use crate::interp::builtins::text::codecs::Codec;
use crate::interp::code::CodeObject;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::host::HostAccess;
use crate::interp::lifecycle::FinalizerQueue;
use crate::interp::lifecycle::Lifecycle;
use crate::interp::object::MroEntry;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFn;
use crate::interp::object::NativeFunction;
use crate::interp::traceback::Handled;
use crate::interp::types::BuiltinTypes;
use crate::interp::value::InternTable;
use crate::interp::value::Object;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;

/// Marshalled module code supplied by the host.
pub struct ModuleCode {
    pub code: Vec<u8>,
    pub is_package: bool,
    pub filename: String,
}

/// Whether the embedding executable links a module in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinModule {
    /// Linked in: an emulated native module loads; any other is opaque.
    Present,
    /// Not linked in: importing it raises ImportError unless the module
    /// source has it.
    Absent,
    /// The host cannot tell: emulated native modules load and other names
    /// absent from the module source are opaque.
    Unknown,
}

/// Locates module bytecode by dotted name.
pub trait ModuleSource {
    fn find(&self, name: &str) -> Option<ModuleCode>;

    /// Whether the executable that embeds the interpreter links in the
    /// module `name` (`sys.builtin_module_names`, or engine modules it
    /// registers under dotted names).
    fn builtin(&self, _name: &str) -> BuiltinModule {
        BuiltinModule::Unknown
    }
}

/// A native module the host provides in place of client code.
pub type NativeModuleInit = fn(&Vm, &ObjectRef) -> PyResult<()>;

/// A native type's attribute getter: the attribute `name` of an instance, `None` when
/// it has none.
pub type NativeGetattr = fn(&Vm, &Value, &PyBytes) -> PyResult<Option<Value>>;

/// A native type's attribute setter: stores the attribute `name`, or deletes it on
/// `None`.
pub type NativeSetattr = fn(&Vm, &Value, &PyBytes, Option<Value>) -> PyResult<()>;

/// The size of the unnormalized exception table below which it is not
/// pruned.
const UNNORMALIZED_PRUNE_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct VmConfig {
    pub long_width: LongWidth,
    pub recursion_limit: usize,
    /// Upper bound on executed instructions, guarding against code that
    /// loops forever under emulation.
    pub step_limit: u64,
    pub host: HostFacts,
    /// Whether host operations yield unknown values or are refused.
    pub host_access: HostAccess,
}

impl VmConfig {
    /// CPython 2.7 for Windows x64, the World of Warships client runtime.
    pub fn windows_x64() -> Self {
        Self {
            long_width: LongWidth::Bits32,
            recursion_limit: 1000,
            step_limit: 2_000_000_000,
            host: HostFacts::default(),
            host_access: HostAccess::default(),
        }
    }
}

/// Properties of the client's host installation and executable that native
/// modules report. Each is unknown to client code while `None`, except
/// where a field says otherwise.
#[derive(Clone, Debug, Default)]
pub struct HostFacts {
    /// `sys.version`, such as `2.7.12 (default, Jun 10 2026, 09:13:26)
    /// [MSC v.1934 64 bit (AMD64)]`.
    pub sys_version: Option<String>,
    /// The OpenSSL library `_ssl` is linked with.
    pub openssl: Option<OpensslVersion>,
    /// The certificate locations that library was configured with.
    pub openssl_default_paths: Option<OpensslDefaultPaths>,
    /// The names of the executable's built-in modules, reported (sorted)
    /// as `sys.builtin_module_names`. While `None`, that is the list of the
    /// python.org build.
    pub builtin_module_names: Option<Vec<String>>,
    /// The CRT time zone `time` reads at import.
    pub time_zone: Option<HostTimeZone>,
}

/// The CRT globals after `tzset()`. `time.altzone` is derived from them,
/// since the Windows build has no native `altzone`.
#[derive(Clone, Debug)]
pub struct HostTimeZone {
    /// `_timezone`: seconds west of UTC in standard time.
    pub timezone: i32,
    /// `_daylight`: nonzero when the zone observes daylight saving time.
    pub daylight: i32,
    /// `_tzname`: the standard and daylight names, in the ANSI code page.
    pub tzname: [Vec<u8>; 2],
}

/// What `SSLeay()` and `SSLeay_version(SSLEAY_VERSION)` return. The client
/// compiles `_ssl` against the headers of the library it links, so the
/// number is also `OPENSSL_VERSION_NUMBER`.
#[derive(Clone, Debug)]
pub struct OpensslVersion {
    /// `OPENSSL_VERSION_NUMBER` as `0xMNNFFPPS`.
    pub number: u32,
    /// `OPENSSL_VERSION`, such as `OpenSSL 1.1.1l  24 Aug 2021`.
    pub text: String,
}

/// `X509_get_default_cert_file()` and `X509_get_default_cert_dir()`, which
/// derive from the library's build-time `OPENSSLDIR`.
#[derive(Clone, Debug)]
pub struct OpensslDefaultPaths {
    pub cert_file: String,
    pub cert_dir: String,
}

/// Outcome of importing one module, kept for diagnostics.
#[derive(Debug, Clone)]
pub struct ImportRecord {
    pub module: String,
    pub failure: Option<String>,
}

struct DefaultEncoding {
    name: String,
    codec: Codec,
}

/// The signal a trace belongs to: an exception by address, or a halt.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TraceOwner {
    Exception(u64),
    Halt,
}

#[derive(Default)]
struct Trace {
    owner: Option<TraceOwner>,
    frames: Vec<String>,
}

pub struct Vm {
    pub config: VmConfig,
    next_id: Cell<u64>,
    types: OnceCell<BuiltinTypes>,
    builtins: OnceCell<ObjectRef>,
    modules: OnceCell<ObjectRef>,
    source: Box<dyn ModuleSource>,
    native_modules: RefCell<HashMap<String, NativeModuleInit>>,
    depth: Cell<usize>,
    steps: Cell<u64>,
    /// `sys.exc_info()` and what each executing frame saved of it.
    exc_state: RefCell<ExcState>,
    /// The executing activations, innermost last.
    activations: RefCell<Vec<Rc<Activation>>>,
    pub(crate) import_records: RefCell<Vec<ImportRecord>>,
    /// The frames currently executing, innermost last.
    /// Namespaces that received `import *` from a module whose names cannot
    /// be enumerated; unbound names in them read as unknown.
    opaque_namespaces: RefCell<HashSet<ObjectId>>,
    /// Frames an uncaught signal has propagated out of, innermost first.
    trace: RefCell<Trace>,
    /// Containers whose `repr` is being computed.
    repr_active: RefCell<HashSet<ObjectId>>,
    /// Current `sys.getrecursionlimit()`, initially the configured limit.
    recursion_limit: Cell<usize>,
    /// Classes native modules define (`deque`, `partial`). They are builtin
    /// types, but operators reach their methods through the class dict as
    /// for classes defined in Python, since `ops` has no native support for
    /// them.
    extension_types: RefCell<HashSet<ObjectId>>,
    /// Types no class may derive from.
    final_types: RefCell<HashSet<ObjectId>>,
    /// Old-style attribute getters of native types, which replace the
    /// generic attribute lookup on their instances.
    native_getattr: RefCell<HashMap<ObjectId, NativeGetattr>>,
    /// Old-style attribute setters of native types, which replace the
    /// generic attribute assignment and deletion on their instances.
    native_setattr: RefCell<HashMap<ObjectId, NativeSetattr>>,
    /// Static types that cannot be instantiated.
    null_new_types: RefCell<HashSet<ObjectId>>,
    /// Static types their module never readied, until an
    /// attribute lookup on the type readies them.
    unready_types: RefCell<HashSet<ObjectId>>,
    /// Exceptions that native code raised with a string value
    /// and that no `except` or `with` has normalized.
    /// Several can be pending: a `finally` block saves one while it runs.
    unnormalized: RefCell<HashMap<ObjectId, Weak<Object>>>,
    /// The size of `unnormalized` at which dropped exceptions are pruned.
    unnormalized_limit: Cell<usize>,
    /// The type of each native descriptor.
    descriptors: RefCell<HashMap<ObjectId, Weak<Object>>>,
    /// Modules CPython 2.7 for Windows lacks. Importing them raises
    /// ImportError instead of producing an opaque module.
    absent_modules: RefCell<HashSet<String>>,
    /// Native code that adjusts a module after import creates it, by name.
    import_hooks: RefCell<HashMap<String, NativeModuleInit>>,
    /// State of native modules, one value per Rust type.
    native_state: RefCell<HashMap<TypeId, Rc<dyn Any>>>,
    /// `sys.getdefaultencoding()`: the codec for implicit str/unicode
    /// conversion, and the name it was set by.
    default_encoding: RefCell<DefaultEncoding>,
    /// Objects waiting for weak reference callbacks and `__del__`.
    finalizers: Rc<FinalizerQueue>,
}

/// The thread's handled exception and, per executing frame, the one it
/// saved when it first caught an exception.
#[derive(Default)]
struct ExcState {
    current: Option<Handled>,
    saved: Vec<Option<Option<Handled>>>,
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.finalizers.close();
    }
}

impl Vm {
    pub(crate) fn finalizer_queue(&self) -> &FinalizerQueue {
        &self.finalizers
    }

    pub fn new(config: VmConfig, source: Box<dyn ModuleSource>) -> PyResult<Self> {
        let recursion_limit = config.recursion_limit;
        let vm = Self {
            config,
            next_id: Cell::new(1),
            types: OnceCell::new(),
            builtins: OnceCell::new(),
            modules: OnceCell::new(),
            source,
            native_modules: RefCell::new(HashMap::new()),
            depth: Cell::new(0),
            steps: Cell::new(0),
            exc_state: RefCell::new(ExcState::default()),
            activations: RefCell::new(Vec::new()),
            import_records: RefCell::new(Vec::new()),
            opaque_namespaces: RefCell::new(HashSet::new()),
            trace: RefCell::new(Trace::default()),
            repr_active: RefCell::new(HashSet::new()),
            recursion_limit: Cell::new(recursion_limit),
            extension_types: RefCell::new(HashSet::new()),
            final_types: RefCell::new(HashSet::new()),
            native_getattr: RefCell::new(HashMap::new()),
            native_setattr: RefCell::new(HashMap::new()),
            null_new_types: RefCell::new(HashSet::new()),
            unready_types: RefCell::new(HashSet::new()),
            descriptors: RefCell::new(HashMap::new()),
            unnormalized: RefCell::new(HashMap::new()),
            unnormalized_limit: Cell::new(UNNORMALIZED_PRUNE_SIZE),
            absent_modules: RefCell::new(HashSet::new()),
            import_hooks: RefCell::new(HashMap::new()),
            native_state: RefCell::new(HashMap::new()),
            default_encoding: RefCell::new(DefaultEncoding { name: "ascii".to_owned(), codec: Codec::Ascii }),
            finalizers: FinalizerQueue::register(),
        };

        let types = crate::interp::types::bootstrap(&vm)?;
        if vm.types.set(types).is_err() {
            unreachable!("types are initialized once");
        }
        crate::interp::types::forbid_builtin_subclassing(&vm);

        let modules = vm.new_dict();
        if vm.modules.set(modules).is_err() {
            unreachable!("sys.modules is initialized once");
        }

        let builtins = crate::interp::builtins::create_builtin_module(&vm)?;
        if vm.builtins.set(builtins).is_err() {
            unreachable!("builtins are initialized once");
        }

        crate::interp::builtins::register_native_modules(&vm);

        Ok(vm)
    }

    /// Pushes a frame about to run; its caller becomes its `f_back`.
    pub(crate) fn enter_frame(&self, activation: &Rc<Activation>) {
        let mut activations = self.activations.borrow_mut();
        activation.set_back(activations.last().map(Rc::clone));
        activations.push(Rc::clone(activation));
    }

    /// Pops a frame that stopped running. A generator's frame has no
    /// `f_back` while it is not running.
    pub(crate) fn leave_frame(&self, activation: &Rc<Activation>) {
        self.activations.borrow_mut().pop();
        if activation.is_generator() {
            activation.set_back(None);
        }
    }

    /// Globals of the innermost executing frame.
    pub fn current_globals(&self) -> Option<ObjectRef> {
        self.activations.borrow().last().map(|activation| Rc::clone(&activation.globals))
    }

    /// The code object of the innermost executing frame.
    pub fn current_code_object(&self) -> Option<ObjectRef> {
        self.activations.borrow().last().map(|activation| Rc::clone(&activation.code_object))
    }

    /// The innermost executing frame.
    pub fn current_frame(&self) -> Option<Rc<Activation>> {
        self.activations.borrow().last().map(Rc::clone)
    }

    /// `f_builtins` of the innermost frame when it runs with `globals`,
    /// which a new frame on the same globals shares.
    pub(crate) fn shared_builtins(&self, globals: &ObjectRef) -> Option<ObjectRef> {
        self.activations.borrow().last().filter(|activation| Rc::ptr_eq(&activation.globals, globals)).map(|activation| Rc::clone(&activation.builtins))
    }

    /// The innermost frame's `f_locals` after the fast slots are copied
    /// into it.
    pub fn current_locals(&self) -> PyResult<Option<ObjectRef>> {
        let Some(activation) = self.current_frame() else {
            return Ok(None);
        };

        activation.scope.fast_to_locals(self).map(Some)
    }

    /// The innermost frame's `f_builtins`, or the
    /// interpreter's builtins outside any frame.
    pub fn current_builtins(&self) -> ObjectRef {
        match self.current_frame() {
            Some(activation) => Rc::clone(&activation.builtins),
            None => self.builtins_dict(),
        }
    }

    /// `sys._getframe(depth)`: the frame `depth` calls below the innermost
    /// Python frame.
    pub fn frame_object(&self, depth: usize) -> PyResult<Value> {
        let activation = {
            let activations = self.activations.borrow();
            activations.len().checked_sub(depth + 1).and_then(|index| activations.get(index).map(Rc::clone))
        };
        let Some(activation) = activation else {
            return Err(self.raise(ExceptionKind::ValueError, "call stack is not deep enough"));
        };

        Ok(self.frame_object_of(&activation))
    }

    pub(crate) fn mark_opaque_names(&self, namespace: &ObjectRef) {
        self.opaque_namespaces.borrow_mut().insert(namespace.id);
    }

    pub(crate) fn has_opaque_names(&self, namespace: &ObjectRef) -> bool {
        self.opaque_namespaces.borrow().contains(&namespace.id)
    }

    /// Marks `object` as being rendered; false when it already is.
    pub(crate) fn repr_enter(&self, object: &ObjectRef) -> bool {
        self.repr_active.borrow_mut().insert(object.id)
    }

    pub(crate) fn repr_leave(&self, object: &ObjectRef) {
        self.repr_active.borrow_mut().remove(&object.id);
    }

    /// Opens the exception slot of a frame about to run.
    pub(crate) fn push_handled_slot(&self) {
        self.exc_state.borrow_mut().saved.push(None);
    }

    /// Closes the slot of a frame that stopped running. A frame that caught
    /// an exception restores the one current before.
    pub(crate) fn pop_handled_slot(&self) {
        let restored = {
            let mut state = self.exc_state.borrow_mut();
            let Some(Some(previous)) = state.saved.pop() else {
                return;
            };
            state.current = previous.clone();
            previous
        };
        self.publish_exc_info(restored, false);
    }

    /// Records the exception the innermost frame is handling
    /// and saves the one current before for its return.
    pub(crate) fn set_handled(&self, handled: Handled) {
        {
            let mut state = self.exc_state.borrow_mut();
            let previous = state.current.clone();
            if let Some(slot @ None) = state.saved.last_mut() {
                *slot = Some(previous);
            }
            state.current = Some(handled.clone());
        }
        self.publish_exc_info(Some(handled), false);
    }

    /// The exception being handled, as `sys.exc_info()` reports it.
    pub fn handled_exception(&self) -> Option<Handled> {
        self.exc_state.borrow().current.clone()
    }

    /// `sys.last_type`, `sys.last_value`, and `sys.last_traceback`.
    pub(crate) fn publish_last_exception(&self, exception: Value, traceback: Value) {
        let Ok(Some(sys)) = self.dict_get_str(self.modules(), "sys") else {
            return;
        };
        let Some(dict) = sys.as_object().and_then(|module| module.dict()) else {
            return;
        };

        let class = Value::Object(self.class_of(&exception));
        for (name, value) in [("last_type", class), ("last_value", exception), ("last_traceback", traceback)] {
            let _ = self.dict_set_str(&dict, name, value);
        }
    }

    /// Mirrors the current exception into `sys.exc_type`, `sys.exc_value`,
    /// and `sys.exc_traceback`. Restoring "no exception" sets `exc_type` to
    /// None and removes the other two; clearing sets all three to None.
    fn publish_exc_info(&self, handled: Option<Handled>, cleared: bool) {
        let Ok(Some(sys)) = self.dict_get_str(self.modules(), "sys") else {
            return;
        };
        let Some(dict) = sys.as_object().and_then(|module| module.dict()) else {
            return;
        };

        let fields = match handled {
            Some(handled) => [Some(Value::Object(self.class_of(&handled.exception))), Some(handled.exception), Some(handled.traceback)],
            None if cleared => [Some(Value::None), Some(Value::None), Some(Value::None)],
            None => [Some(Value::None), None, None],
        };
        for (name, value) in ["exc_type", "exc_value", "exc_traceback"].into_iter().zip(fields) {
            let key = Value::str(name);
            let _ = match value {
                Some(value) => self.dict_set(&dict, key, value),
                None => self.dict_delete(&dict, &key).map(|_| ()),
            };
        }
    }

    /// Records that `signal` propagated out of the frame at `location`. A
    /// different exception than the one traced so far starts a new trace,
    /// since native code may have swallowed the earlier one.
    pub(crate) fn push_trace(&self, signal: &Signal, location: String) {
        let owner = match signal {
            Signal::Raise(exception) => TraceOwner::Exception(self.value_address(exception)),
            Signal::Halt(_) => TraceOwner::Halt,
        };

        let mut trace = self.trace.borrow_mut();
        if trace.owner != Some(owner) {
            trace.frames.clear();
            trace.owner = Some(owner);
        }
        trace.frames.push(location);
    }

    pub(crate) fn clear_trace(&self) {
        *self.trace.borrow_mut() = Trace::default();
    }

    /// Frames the last uncaught signal propagated through, innermost first.
    pub fn take_trace(&self) -> Vec<String> {
        std::mem::take(&mut *self.trace.borrow_mut()).frames
    }


    pub fn types(&self) -> &BuiltinTypes {
        self.types.get().expect("builtin types are initialized in Vm::new")
    }

    /// The `__builtin__` module.
    pub fn builtin_module(&self) -> &ObjectRef {
        self.builtins.get().expect("builtins are initialized in Vm::new")
    }

    pub fn builtins_dict(&self) -> ObjectRef {
        self.builtin_module().dict().expect("modules own a dict")
    }

    /// `sys.modules`.
    pub fn modules(&self) -> &ObjectRef {
        self.modules.get().expect("sys.modules is initialized in Vm::new")
    }

    pub fn source(&self) -> &dyn ModuleSource {
        self.source.as_ref()
    }

    pub fn register_native_module(&self, name: &str, init: NativeModuleInit) {
        self.native_modules.borrow_mut().insert(name.to_owned(), init);
    }

    pub(crate) fn native_module(&self, name: &str) -> Option<NativeModuleInit> {
        self.native_modules.borrow().get(name).copied()
    }

    pub fn register_extension_type(&self, class: &ObjectRef) {
        self.extension_types.borrow_mut().insert(class.id);
    }

    pub fn is_extension_type(&self, class: &ObjectRef) -> bool {
        self.extension_types.borrow().contains(&class.id)
    }

    /// Forbids subclassing `class`.
    pub fn forbid_subclassing(&self, class: &ObjectRef) {
        self.final_types.borrow_mut().insert(class.id);
    }

    /// Makes `getattr` for instances of `class` call `getattr`. It returns
    /// `None` for a missing attribute, which
    /// raises `AttributeError(name)`.
    pub fn register_native_getattr(&self, class: &ObjectRef, getattr: NativeGetattr) {
        self.native_getattr.borrow_mut().insert(class.id, getattr);
    }

    pub fn native_getattr(&self, class: &ObjectRef) -> Option<NativeGetattr> {
        self.native_getattr.borrow().get(&class.id).copied()
    }

    /// Makes attribute assignment and deletion on instances of `class` call
    /// `setattr`.
    pub fn register_native_setattr(&self, class: &ObjectRef, setattr: NativeSetattr) {
        self.native_setattr.borrow_mut().insert(class.id, setattr);
    }

    pub fn native_setattr(&self, class: &ObjectRef) -> Option<NativeSetattr> {
        self.native_setattr.borrow().get(&class.id).copied()
    }

    /// Makes the static type `class` impossible to instantiate, which its subclasses
    /// inherit unless they define `__new__`.
    pub fn clear_new(&self, class: &ObjectRef) {
        self.null_new_types.borrow_mut().insert(class.id);
    }

    /// Whether `class` is or derives from a type that cannot be instantiated.
    pub fn inherits_null_new(&self, class: &ObjectRef) -> bool {
        let types = self.null_new_types.borrow();
        if types.is_empty() {
            return false;
        }

        class.as_class().is_some_and(|data| data.mro().iter().any(|entry| matches!(entry, MroEntry::Class(base) if types.contains(&base.id))))
    }

    /// Marks `class` as a static type its module did not ready.
    pub fn mark_type_unready(&self, class: &ObjectRef) {
        self.unready_types.borrow_mut().insert(class.id);
    }

    /// Readies a static type, which an attribute lookup on the type does.
    pub fn ready_type(&self, class: &ObjectRef) {
        self.unready_types.borrow_mut().remove(&class.id);
    }

    pub fn is_type_unready(&self, class: &ObjectRef) -> bool {
        self.unready_types.borrow().contains(&class.id)
    }

    /// Records that native code raised `exception` with a string value.
    pub(crate) fn mark_unnormalized(&self, exception: &ObjectRef) {
        let mut pending = self.unnormalized.borrow_mut();
        pending.insert(exception.id, Rc::downgrade(exception));

        // Native code discards most exceptions it catches; drop those once
        // the table doubles.
        if pending.len() >= self.unnormalized_limit.get() {
            pending.retain(|_, exception| exception.strong_count() > 0);
            self.unnormalized_limit.set((pending.len() * 2).max(UNNORMALIZED_PRUNE_SIZE));
        }
    }

    /// Records that `exception` was normalized.
    pub fn mark_normalized(&self, exception: &Value) {
        if let Some(object) = exception.as_object() {
            self.unnormalized.borrow_mut().remove(&object.id);
        }
    }

    pub(crate) fn is_unnormalized(&self, exception: &ObjectRef) -> bool {
        self.unnormalized.borrow().contains_key(&exception.id)
    }

    /// Records the type that owns a native descriptor (`__objclass__`).
    pub fn set_descriptor_owner(&self, descriptor: &Value, owner: &ObjectRef) {
        if let Value::Object(descriptor) = descriptor {
            self.descriptors.borrow_mut().insert(descriptor.id, Rc::downgrade(owner));
        }
    }

    /// The type a native descriptor belongs to.
    pub fn descriptor_owner(&self, descriptor: &Value) -> Option<ObjectRef> {
        let Value::Object(descriptor) = descriptor else {
            return None;
        };

        self.descriptors.borrow().get(&descriptor.id).and_then(Weak::upgrade)
    }

    /// Whether classes may derive from `class`.
    pub fn is_base_type(&self, class: &ObjectRef) -> bool {
        !self.final_types.borrow().contains(&class.id)
    }

    pub fn register_absent_module(&self, name: &str) {
        self.absent_modules.borrow_mut().insert(name.to_owned());
    }

    pub(crate) fn is_absent_module(&self, name: &str) -> bool {
        self.absent_modules.borrow().contains(name)
    }

    /// Runs `hook` on the module `name` each time import creates it, after
    /// its body has run.
    pub fn register_import_hook(&self, name: &str, hook: NativeModuleInit) {
        self.import_hooks.borrow_mut().insert(name.to_owned(), hook);
    }

    pub(crate) fn import_hook(&self, name: &str) -> Option<NativeModuleInit> {
        self.import_hooks.borrow().get(name).copied()
    }

    /// The state of type `T` that native modules keep per interpreter,
    /// created on first use.
    pub fn native_state<T: Default + 'static>(&self) -> Rc<T> {
        let state = {
            let mut states = self.native_state.borrow_mut();
            let entry = states.entry(TypeId::of::<T>()).or_insert_with(|| Rc::new(T::default()));
            Rc::clone(entry)
        };

        match state.downcast::<T>() {
            Ok(state) => state,
            Err(_) => unreachable!("native state is keyed by its type"),
        }
    }

    /// `sys.exc_clear()`.
    /// `sys.exc_clear()`: clears the current exception; frames still restore
    /// what they saved when they return.
    pub fn clear_handled_exceptions(&self) {
        self.exc_state.borrow_mut().current = None;
        self.publish_exc_info(None, true);
    }

    /// The codec implicit str/unicode conversions use.
    pub fn default_codec(&self) -> Codec {
        self.default_encoding.borrow().codec
    }

    pub fn default_encoding_name(&self) -> String {
        self.default_encoding.borrow().name.clone()
    }

    /// `sys.setdefaultencoding(name)`. Clients set UTF-8 at startup.
    pub fn set_default_encoding(&self, name: &str) -> PyResult<()> {
        let Some(codec) = Codec::lookup(name.as_bytes()).filter(|codec| !codec.is_bytes_codec()) else {
            return Err(self.raise(ExceptionKind::LookupError, &format!("unknown encoding: {name}")));
        };

        *self.default_encoding.borrow_mut() = DefaultEncoding { name: name.to_owned(), codec };

        Ok(())
    }

    pub fn recursion_limit(&self) -> usize {
        self.recursion_limit.get()
    }

    pub fn set_recursion_limit(&self, limit: usize) {
        self.recursion_limit.set(limit);
    }

    pub fn import_records(&self) -> Vec<ImportRecord> {
        self.import_records.borrow().clone()
    }

    pub fn alloc(&self, class: &ObjectRef, payload: Payload, dict: Option<ObjectRef>) -> ObjectRef {
        let object = self.alloc_unclassed(payload, dict);
        object.set_class(class);

        object
    }

    /// Allocates an object whose class is assigned later. Only bootstrap uses
    /// this, for the objects that must exist before `type` does.
    /// An object that takes over the identity `id` of an earlier one that
    /// has been freed.
    pub(crate) fn alloc_as(&self, id: ObjectId, class: &ObjectRef, payload: Payload) -> ObjectRef {
        let object = Rc::new(Object { id, class: RefCell::new(None), dict: RefCell::new(None), slots: RefCell::default(), payload, lifecycle: Cell::new(Lifecycle::default()), owner: self.finalizers.serial() });
        object.set_class(class);

        object
    }

    pub(crate) fn alloc_unclassed(&self, payload: Payload, dict: Option<ObjectRef>) -> ObjectRef {
        let id = self.next_id.get();
        self.next_id.set(id + 1);

        Rc::new(Object { id: ObjectId(id), class: RefCell::new(None), dict: RefCell::new(dict), slots: RefCell::default(), payload, lifecycle: Cell::new(Lifecycle::default()), owner: self.finalizers.serial() })
    }

    /// Fake address of an object, used for `id()` and pointer hashes.
    pub fn address_of(&self, object: &Object) -> u64 {
        object.id.0 << 4
    }

    /// `%p` of the C library: MSVC prints
    /// 16 uppercase digits, glibc a `0x`-prefixed lowercase number.
    pub fn c_pointer_text(&self, address: u64) -> String {
        match self.config.long_width {
            crate::interp::hash::LongWidth::Bits32 => format!("{address:016X}"),
            crate::interp::hash::LongWidth::Bits64 => format!("{address:#x}"),
        }
    }

    /// `%p` in string formatting of error messages: the C library's text,
    /// prefixed with `0x` when it lacks one.
    pub fn pointer_text(&self, address: u64) -> String {
        let text = self.c_pointer_text(address);
        if text.starts_with("0x") {
            return text;
        }

        format!("0x{text}")
    }

    /// Value of a name in `__builtin__`.
    pub fn builtin_value(&self, name: &str) -> PyResult<Value> {
        let dict = self.builtins_dict();

        match self.dict_get_str(&dict, name)? {
            Some(value) => Ok(value),
            None => Err(self.raise(ExceptionKind::NameError, &format!("name '{name}' is not defined"))),
        }
    }

    pub fn new_native_function(&self, name: &'static str, function: NativeFn) -> Value {
        self.new_native(name, function, NativeBinding::Function, None)
    }

    pub fn new_native(&self, name: &'static str, function: NativeFn, binding: NativeBinding, owner: Option<ObjectRef>) -> Value {
        let class = Rc::clone(&self.types().builtin_function);
        let payload = Payload::NativeFunction(NativeFunction { name, function, binding, receiver: None, owner });

        Value::Object(self.alloc(&class, payload, None))
    }

    /// A builtin method bound to `receiver`, as an old-style attribute
    /// getter returns it. Like the
    /// results of `bind_native`, it does not bind again.
    pub fn new_bound_native(&self, name: &'static str, function: NativeFn, receiver: Value, owner: Option<ObjectRef>) -> Value {
        let class = Rc::clone(&self.types().builtin_function);
        let payload = Payload::NativeFunction(NativeFunction { name, function, binding: NativeBinding::Function, receiver: Some(receiver), owner });

        Value::Object(self.alloc(&class, payload, None))
    }

    /// A code object as 2.7.12 creates it: interns the name tuples and the top-level
    /// `str` constants whose C string (up to the first NUL) is made of
    /// identifier characters.
    pub fn new_code(&self, mut code: CodeObject) -> Value {
        const NAME_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

        for names in [&mut code.names, &mut code.varnames, &mut code.freevars, &mut code.cellvars] {
            for name in names.iter_mut() {
                *name = self.intern(name);
            }
        }
        for constant in code.consts.iter_mut() {
            let Value::Str(string) = constant else {
                continue;
            };
            let c_string = string.as_bytes().split(|&byte| byte == 0).next().unwrap_or_default();
            if c_string.iter().all(|byte| NAME_CHARS.contains(byte)) {
                *string = self.intern(string);
            }
        }

        let class = Rc::clone(&self.types().code);

        Value::Object(self.alloc(&class, Payload::Code(Rc::new(code)), None))
    }

    /// The interned string equal to `string`.
    pub fn intern(&self, string: &PyBytes) -> PyBytes {
        self.native_state::<InternTable>().intern(string)
    }

    /// Runs `body` one Python call level deeper, enforcing the recursion
    /// limit with no message suffix.
    pub fn with_depth<T>(&self, body: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
        self.with_depth_in("", body)
    }

    /// `with_depth` with a message suffix: the overflow
    /// message ends with `context`.
    pub fn with_depth_in<T>(&self, context: &str, body: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
        if self.is_recursion_exhausted() {
            return Err(self.raise(ExceptionKind::RuntimeError, &format!("maximum recursion depth exceeded{context}")));
        }

        let depth = self.depth.get();
        self.depth.set(depth + 1);
        let result = ensure_stack(body);
        self.depth.set(depth);

        result
    }

    /// Whether one more recursion level would exceed the limit.
    pub(crate) fn is_recursion_exhausted(&self) -> bool {
        self.depth.get() >= self.recursion_limit.get()
    }

    /// Runs `body` outside the recursion count, for work CPython does in C
    /// without the checks the emulation's calls perform.
    pub(crate) fn without_depth<T>(&self, body: impl FnOnce() -> T) -> T {
        let depth = self.depth.replace(0);
        let result = body();
        self.depth.set(depth);

        result
    }

    pub(crate) fn count_step(&self) -> PyResult<()> {
        let steps = self.steps.get() + 1;
        self.steps.set(steps);

        if steps > self.config.step_limit {
            return Err(Signal::Halt(Halt::StepLimit));
        }

        Ok(())
    }

    pub fn halt_unsupported(&self, feature: impl Into<String>) -> Signal {
        Signal::Halt(Halt::Unsupported { feature: feature.into() })
    }

    pub fn name(&self, text: &str) -> PyBytes {
        PyBytes::from(text)
    }
}

/// Runs `body`, first switching to a new native stack segment when the
/// current one is nearly exhausted. Python recursion recurses on the native
/// stack, so the recursion limit rather than the size of the calling
/// thread's stack bounds how deep evaluation goes. Every recursion check
/// passes through here; `RED_ZONE` covers the most native stack evaluation
/// uses between two checks.
pub(crate) fn ensure_stack<T>(body: impl FnOnce() -> T) -> T {
    const RED_ZONE: usize = 1024 * 1024;
    const SEGMENT_SIZE: usize = 32 * 1024 * 1024;

    stacker::maybe_grow(RED_ZONE, SEGMENT_SIZE, body)
}
