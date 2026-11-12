//! `memoryview` over one-dimensional byte buffers: `str` (read-only),
//! `bytearray` (writable, sharing its storage), and other memoryviews. A
//! view over a `bytearray` holds an export, which forbids resizing the
//! array, until the view is dropped.

use std::cell::Cell;
use std::rc::Rc;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::set_class_attribute;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::containers::buffer_object::buffer_object;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A computed attribute's getter.
type Getter = fn(&Vm, &GetSet, &Value) -> PyResult<Value>;

/// A `memoryview`: `length` bytes of `source` from `start`.
pub struct MemoryView {
    source: Source,
    start: usize,
    length: usize,
}

impl_native_data!(MemoryView, "memoryview");

enum Source {
    Bytes(PyBytes),
    ByteArray(Export),
}

/// One export of a `bytearray`'s storage, released when dropped.
struct Export {
    array: ObjectRef,
    exports: Rc<Cell<usize>>,
}

impl Export {
    fn new(array: &ObjectRef) -> Option<Self> {
        let Payload::ByteArray(data) = &array.payload else {
            return None;
        };
        let exports = Rc::clone(&data.borrow().exports);
        exports.set(exports.get() + 1);

        Some(Self { array: Rc::clone(array), exports })
    }

    fn duplicate(&self) -> Self {
        self.exports.set(self.exports.get() + 1);

        Self { array: Rc::clone(&self.array), exports: Rc::clone(&self.exports) }
    }
}

impl Drop for Export {
    fn drop(&mut self) {
        self.exports.set(self.exports.get().saturating_sub(1));
    }
}

impl MemoryView {
    fn readonly(&self) -> bool {
        matches!(self.source, Source::Bytes(_))
    }

    /// The viewed bytes, `None` when a `bytearray` shrank within its
    /// allocation while exported (`bytearray *= 0`), after which the reference
    /// interpreter reads memory past the array's end.
    fn checked_contents(&self) -> Option<Vec<u8>> {
        if let Source::ByteArray(export) = &self.source
            && let Payload::ByteArray(data) = &export.array.payload
            && data.borrow().bytes.len() < self.start + self.length
        {
            return None;
        }

        Some(self.contents())
    }

    /// `checked_contents`, halting on memory past the array's end.
    fn bytes(&self, vm: &Vm) -> PyResult<Vec<u8>> {
        self.checked_contents().ok_or_else(|| vm.halt_unsupported("memoryview over a bytearray shrunk while exported"))
    }

    /// The viewed bytes, clamped to a `bytearray` that shrank while
    /// exported. Only for conversions that cannot halt.
    pub fn contents(&self) -> Vec<u8> {
        match &self.source {
            Source::Bytes(bytes) => bytes.as_bytes().get(self.start..self.start + self.length).unwrap_or_default().to_vec(),
            Source::ByteArray(export) => match &export.array.payload {
                Payload::ByteArray(data) => {
                    let data = data.borrow();
                    let end = (self.start + self.length).min(data.bytes.len());
                    data.bytes.get(self.start.min(end)..end).unwrap_or_default().to_vec()
                }
                _ => Vec::new(),
            },
        }
    }

    /// A view of `length` bytes from `offset` within this one.
    fn subview(&self, offset: usize, length: usize) -> Self {
        let source = match &self.source {
            Source::Bytes(bytes) => Source::Bytes(bytes.clone()),
            Source::ByteArray(export) => Source::ByteArray(export.duplicate()),
        };

        Self { source, start: self.start + offset, length }
    }
}

/// A writable buffer (`w*`): a `bytearray` or a view over one.
pub struct WritableBuffer {
    array: ObjectRef,
    start: usize,
    length: usize,
    /// Forbids resizing the array while the buffer is in use.
    _export: Export,
}

impl WritableBuffer {
    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Copies `data` to `offset`; bytes past the buffer are dropped.
    pub fn write(&self, offset: usize, data: &[u8]) {
        let Payload::ByteArray(storage) = &self.array.payload else {
            return;
        };
        let mut storage = storage.borrow_mut();
        let begin = self.start + offset;
        let end = (begin + data.len()).min(self.start + self.length).min(storage.bytes.len());
        if begin >= end {
            return;
        }
        storage.bytes[begin..end].copy_from_slice(&data[..end - begin]);
    }

    /// Runs `write` over the buffer's bytes, clamped to an array that
    /// shrank while exported; `None` when the storage is not a `bytearray`.
    pub fn modify<R>(&self, write: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let Payload::ByteArray(storage) = &self.array.payload else {
            return None;
        };
        let mut storage = storage.borrow_mut();
        let end = (self.start + self.length).min(storage.bytes.len());
        let begin = self.start.min(end);

        Some(write(&mut storage.bytes[begin..end]))
    }
}

/// An export of a buffer argument's storage, held while a call that may
/// run Python code reads it (`s*`).
pub struct BufferHold {
    _export: Option<Export>,
}

/// Holds the export of `value` when it is a `bytearray` or a view of one.
pub fn hold_buffer(value: &Value) -> BufferHold {
    let export = match native_data::<MemoryView>(value) {
        Some(view) => match &view.source {
            Source::ByteArray(export) => Some(export.duplicate()),
            Source::Bytes(_) => None,
        },
        None => value.as_object().and_then(Export::new),
    };

    BufferHold { _export: export }
}

/// The writable buffer `value` exports, if any.
pub fn writable_buffer(value: &Value) -> Option<WritableBuffer> {
    let object = value.as_object()?;
    if let Payload::ByteArray(data) = &object.payload {
        let length = data.borrow().bytes.len();
        return Some(WritableBuffer { array: Rc::clone(object), start: 0, length, _export: Export::new(object)? });
    }

    let view = native_data::<MemoryView>(value)?;
    match &view.source {
        Source::ByteArray(export) => Some(WritableBuffer { array: Rc::clone(&export.array), start: view.start, length: view.length, _export: export.duplicate() }),
        Source::Bytes(_) => None,
    }
}

/// Whether `value` is a `memoryview`.
pub fn is_memoryview(value: &Value) -> bool {
    native_data::<MemoryView>(value).is_some()
}

/// The contents of a `memoryview` value.
pub fn view_contents(value: &Value) -> Option<Vec<u8>> {
    native_data::<MemoryView>(value).map(MemoryView::contents)
}

/// A memoryview of an object's buffer.
pub fn new_memoryview(vm: &Vm, base: &Value) -> PyResult<Value> {
    halt_on_unknown(base, "memoryview base")?;

    let view = if let Some(view) = native_data::<MemoryView>(base) {
        view.subview(0, view.length)
    } else if let Some(bytes) = vm.as_str_bytes(base) {
        let length = bytes.as_bytes().len();
        MemoryView { source: Source::Bytes(bytes), start: 0, length }
    } else if let Some(object) = buffer_object(base) {
        // The base's memory is exported without holding it; the view keeps the
        // bytes the base held when it was made.
        let bytes = object.contents(vm)?;
        let length = bytes.as_bytes().len();
        MemoryView { source: Source::Bytes(bytes), start: 0, length }
    } else if let Some(export) = base.as_object().and_then(Export::new) {
        let length = match &export.array.payload {
            Payload::ByteArray(data) => data.borrow().bytes.len(),
            _ => 0,
        };
        MemoryView { source: Source::ByteArray(export), start: 0, length }
    } else {
        return Err(vm.type_error("cannot make memory view because object does not have the buffer interface"));
    };

    Ok(view_value(vm, view))
}

fn view_value(vm: &Vm, view: MemoryView) -> Value {
    let class = Rc::clone(&vm.types().memoryview);

    new_native_object(vm, &class, view)
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().memoryview);
    vm.register_extension_type(&class);

    install(
        vm,
        &class,
        &[
            static_method("__new__", memory_new),
            method("tobytes", memory_tobytes),
            method("tolist", memory_tolist),
            method("__len__", memory_len),
            method("__getitem__", memory_getitem),
            method("__setitem__", memory_setitem),
            method("__delitem__", memory_delitem),
            method("__iter__", memory_iter),
            method("__eq__", |vm, args| memory_compare(vm, args, true)),
            method("__ne__", |vm, args| memory_compare(vm, args, false)),
            method("__repr__", memory_repr),
        ],
    )?;

    let getsets: [(&'static str, Getter); 7] = [
        ("format", |_, _, _| Ok(Value::str("B"))),
        ("itemsize", |_, _, _| Ok(long(1))),
        ("shape", |vm, getset, instance| Ok(Value::tuple(vec![long(receiver_view(vm, getset, instance)?.length)]))),
        ("strides", |_, _, _| Ok(Value::tuple(vec![long(1)]))),
        ("suboffsets", |_, _, _| Ok(Value::None)),
        ("readonly", |vm, getset, instance| Ok(Value::Bool(receiver_view(vm, getset, instance)?.readonly()))),
        ("ndim", |_, _, _| Ok(long(1))),
    ];
    for (name, get) in getsets {
        add_getset(vm, &class, GetSet { name, owner: "memoryview", get, set: None })?;
    }

    set_class_attribute(vm, &class, "__hash__", Value::None)
}

fn long(value: usize) -> Value {
    Value::Long(Rc::new(value.into()))
}

fn receiver_view<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a MemoryView> {
    native_data::<MemoryView>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}

/// The receiver of a `memoryview` method and the arguments after it.
fn bind_view(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of 'memoryview' object needs an argument")));
    };
    halt_on_unknown(receiver, "memoryview receiver")?;
    if native_data::<MemoryView>(receiver).is_none() {
        return Err(vm.type_error(&format!("descriptor '{method}' requires a 'memoryview' object but received a '{}'", vm.type_name(receiver))));
    }

    let rest = CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };

    Ok((receiver.clone(), rest))
}

fn view_of<'a>(vm: &Vm, value: &'a Value) -> PyResult<&'a MemoryView> {
    native_data::<MemoryView>(value).ok_or_else(|| vm.type_error("memoryview required"))
}

fn memory_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let rest = CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords, keyword_dict: args.keyword_dict };
    let slots = parse(vm, rest, "memoryview", &["object"], 0)?;
    let Some(base) = &slots[0] else {
        return Err(vm.type_error("Required argument 'object' (pos 1) not found"));
    };

    new_memoryview(vm, base)
}

fn memory_tobytes(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = bind_view(vm, &args, "tobytes")?;
    method_no_arguments(vm, &args, "tobytes")?;

    Ok(Value::Str(PyBytes::new(view_of(vm, &target)?.bytes(vm)?)))
}

fn memory_tolist(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = bind_view(vm, &args, "tolist")?;
    method_no_arguments(vm, &args, "tolist")?;

    Ok(vm.new_list(view_of(vm, &target)?.bytes(vm)?.into_iter().map(|byte| Value::Int(i64::from(byte))).collect()))
}

fn memory_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = bind_view(vm, &args, "__len__")?;

    Ok(Value::Int(i64::try_from(view_of(vm, &target)?.length).unwrap_or(i64::MAX)))
}

/// The position of an index key within `length`.
fn item_position(vm: &Vm, key: &Value, length: usize) -> PyResult<usize> {
    let length = i64::try_from(length).unwrap_or(i64::MAX);
    let mut position = vm.index_as_ssize(key, None)?;
    if position < 0 {
        position = position.saturating_add(length);
    }
    if position < 0 || position >= length {
        return Err(vm.raise(ExceptionKind::IndexError, "index out of bounds"));
    }

    Ok(usize::try_from(position).unwrap_or(0))
}

/// The start and length of a step-1 slice key; `None` for other steps.
fn slice_range(vm: &Vm, key: &Value, length: usize) -> PyResult<Option<Option<(usize, usize)>>> {
    let Some(slice) = vm.slice_of(key) else {
        return Ok(None);
    };
    let indices = vm.slice_indices(&slice, length)?;
    if indices.step != 1 {
        return Ok(Some(None));
    }

    let start = usize::try_from(indices.start.max(0)).unwrap_or(0);
    let count = usize::try_from((indices.stop - indices.start).max(0)).unwrap_or(0);

    Ok(Some(Some((start, count))))
}

fn cannot_index(vm: &Vm, key: &Value) -> Signal {
    vm.type_error(&format!("cannot index memory using \"{}\"", vm.type_name(key)))
}

fn not_implemented(vm: &Vm) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::NotImplementedError));

    match vm.instantiate_exception(&class, Vec::new()) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

fn memory_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, &args, "__getitem__")?;
    let key = wrapper_operand(vm, rest)?;
    halt_on_unknown(&key, "memoryview index")?;
    let view = view_of(vm, &target)?;

    if vm.is_index(&key)? {
        let position = item_position(vm, &key, view.length)?;
        let byte = view.bytes(vm)?.get(position).copied().unwrap_or(0);
        return Ok(Value::Str(PyBytes::new(vec![byte])));
    }

    match slice_range(vm, &key, view.length)? {
        Some(Some((start, count))) => Ok(view_value(vm, view.subview(start, count))),
        Some(None) => Err(not_implemented(vm)),
        None => Err(cannot_index(vm, &key)),
    }
}

/// The object's contiguous read-only buffer.
pub fn buffer_contents(vm: &Vm, value: &Value) -> PyResult<Vec<u8>> {
    halt_on_unknown(value, "buffer")?;
    if let Some(bytes) = vm.buffer(value, BufferInterface::New)? {
        return Ok(bytes.as_bytes().to_vec());
    }

    Err(vm.type_error(&format!("'{}' does not have the buffer interface", vm.type_name(value))))
}

fn memory_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, &args, "__setitem__")?;
    let (key, value) = wrapper_pair(vm, rest)?;
    assign(vm, &target, &key, Some(&value))?;

    Ok(Value::None)
}

fn memory_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind_view(vm, &args, "__delitem__")?;
    let key = wrapper_operand(vm, rest)?;
    assign(vm, &target, &key, None)?;

    Ok(Value::None)
}

/// Item and slice assignment.
fn assign(vm: &Vm, target: &Value, key: &Value, value: Option<&Value>) -> PyResult<()> {
    let view = view_of(vm, target)?;
    let Source::ByteArray(export) = &view.source else {
        return Err(vm.type_error("cannot modify read-only memory"));
    };
    let Some(value) = value else {
        return Err(vm.type_error("cannot delete memory"));
    };
    halt_on_unknown(key, "memoryview index")?;

    let (start, count) = if vm.is_index(key)? {
        (item_position(vm, key, view.length)?, 1)
    } else {
        match slice_range(vm, key, view.length)? {
            Some(Some(range)) => range,
            Some(None) => return Err(not_implemented(vm)),
            None => return Err(cannot_index(vm, key)),
        }
    };

    let data = buffer_contents(vm, value)?;
    if data.len() != count {
        return Err(vm.raise(ExceptionKind::ValueError, "cannot modify size of memoryview object"));
    }

    let buffer = WritableBuffer { array: Rc::clone(&export.array), start: view.start, length: view.length, _export: export.duplicate() };
    buffer.write(start, &data);

    Ok(())
}

fn memory_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = bind_view(vm, &args, "__iter__")?;

    Ok(vm.new_iterator(NativeIterator::GetItem { target, index: 0 }))
}

/// Equality of the bytes of two buffers.
fn memory_compare(vm: &Vm, args: CallArgs, equal: bool) -> PyResult<Value> {
    let name = if equal { "__eq__" } else { "__ne__" };
    let (target, rest) = bind_view(vm, &args, name)?;
    let other = wrapper_operand(vm, rest)?;
    halt_on_unknown(&other, "memoryview comparison")?;

    let Some(other) = vm.buffer(&other, BufferInterface::New)? else {
        return Ok(Value::NotImplemented);
    };
    let same = view_of(vm, &target)?.bytes(vm)? == other.as_bytes();

    Ok(Value::Bool(same == equal))
}

fn memory_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _) = bind_view(vm, &args, "__repr__")?;

    Ok(Value::str(&format!("<memory at {}>", vm.pointer_text(vm.value_address(&target)))))
}

