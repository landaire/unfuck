//! `buffer`: a view of a slice of another object's old-style buffer. The
//! base is read afresh on every access, so a buffer over a `bytearray`
//! follows its changes, including resizes.

use std::cell::Cell;
use std::rc::Rc;

use crate::interp::buffer::Segment;
use crate::interp::builtins::arguments::cmp_operand_check;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::builtins::text::check_size;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash;
use crate::interp::hash::PyHash;
use crate::interp::object::CallArgs;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A `buffer` over `base`, which is never itself a buffer.
pub struct BufferObject {
    base: Value,
    offset: usize,
    /// The size; `None` reads to the end of the base.
    size: Option<usize>,
    readonly: bool,
    /// The hash, kept once computed even when the base changes.
    hash: Cell<Option<PyHash>>,
}

impl_native_data!(BufferObject, "buffer");

/// The base procedure a request reads through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Segment(Segment),
    /// The read procedure of a read-only buffer, else the write one.
    Any,
}

impl BufferObject {
    pub fn is_readonly(&self) -> bool {
        self.readonly
    }

    /// The bytes of the base within this buffer's bounds.
    fn get_buf(&self, vm: &Vm, access: Access) -> PyResult<PyBytes> {
        let segment = match access {
            Access::Segment(segment) => segment,
            Access::Any if self.readonly => Segment::Read,
            Access::Any => Segment::Write,
        };
        let Some(bytes) = vm.segment(&self.base, segment)? else {
            let name = match access {
                Access::Segment(Segment::Read) => "read",
                Access::Segment(Segment::Write) => "write",
                Access::Segment(Segment::Character) => "char",
                Access::Any => "no",
            };
            return Err(vm.type_error(&format!("{name} buffer type not available")));
        };

        let (start, end) = self.bounds(bytes.as_bytes().len());
        if start == 0 && end == bytes.as_bytes().len() {
            return Ok(bytes);
        }

        Ok(PyBytes::new(&bytes.as_bytes()[start..end]))
    }

    /// The range of a base segment of `count` bytes this buffer covers.
    fn bounds(&self, count: usize) -> (usize, usize) {
        let start = self.offset.min(count);
        let size = self.size.unwrap_or(count).min(count - start);

        (start, start + size)
    }

    /// The bytes every operation of the type reads.
    pub fn contents(&self, vm: &Vm) -> PyResult<PyBytes> {
        self.get_buf(vm, Access::Any)
    }

    /// The type's read, write, and character buffer procedures.
    pub fn segment(&self, vm: &Vm, segment: Segment) -> PyResult<PyBytes> {
        if segment == Segment::Write && self.readonly {
            return Err(read_only(vm));
        }

        self.get_buf(vm, Access::Segment(segment))
    }

    /// Runs `write` over the bytes of a writable buffer; `false` when the
    /// buffer is read-only or its base has no write buffer. Not generic,
    /// as the base's `write_buffer` would instantiate it again.
    pub fn write(&self, vm: &Vm, write: &mut dyn FnMut(&mut [u8])) -> PyResult<bool> {
        if self.readonly {
            return Ok(false);
        }

        let written = vm.write_buffer(&self.base, |bytes| {
            let (start, end) = self.bounds(bytes.len());
            write(&mut bytes[start..end]);
        })?;

        Ok(written.is_some())
    }
}

/// The buffer object `value` is, if any.
pub fn buffer_object(value: &Value) -> Option<&BufferObject> {
    native_data::<BufferObject>(value)
}

/// A buffer of `size` bytes (`None` for the rest) of `base` from
/// `offset`, read-only or writable.
pub fn new_buffer_object(vm: &Vm, base: &Value, offset: i64, size: Option<i64>, readonly: bool) -> PyResult<Value> {
    halt_on_unknown(base, "buffer base")?;
    let segment = if readonly { Segment::Read } else { Segment::Write };
    if !vm.has_segment(base, segment) {
        return Err(vm.type_error("buffer object expected"));
    }

    let Ok(mut offset) = usize::try_from(offset) else {
        return Err(vm.raise(ExceptionKind::ValueError, "offset must be zero or positive"));
    };
    let mut size = match size.map(usize::try_from) {
        None => None,
        Some(Ok(size)) => Some(size),
        Some(Err(_)) => return Err(vm.raise(ExceptionKind::ValueError, "size must be zero or positive")),
    };

    // A buffer of a buffer refers to the inner buffer's base.
    let mut base = base.clone();
    if let Some(inner) = buffer_object(&base) {
        if let Some(inner_size) = inner.size {
            let available = inner_size.saturating_sub(offset);
            size = Some(size.map_or(available, |size| size.min(available)));
        }
        offset = offset.saturating_add(inner.offset);
        base = inner.base.clone();
    }

    let class = Rc::clone(&vm.types().buffer);
    let object = BufferObject { base, offset, size, readonly, hash: Cell::new(None) };

    Ok(new_native_object(vm, &class, object))
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().buffer);
    vm.register_extension_type(&class);

    install(
        vm,
        &class,
        &[
            static_method("__new__", buffer_new),
            method("__cmp__", buffer_cmp),
            method("__repr__", buffer_repr),
            method("__hash__", buffer_hash),
            method("__str__", buffer_str),
            method("__len__", buffer_len),
            method("__add__", buffer_concat),
            method("__mul__", |vm, args| buffer_repeat(vm, args, "__mul__")),
            method("__rmul__", |vm, args| buffer_repeat(vm, args, "__rmul__")),
            method("__getitem__", buffer_getitem),
            method("__getslice__", buffer_getslice),
            method("__setitem__", buffer_setitem),
            method("__delitem__", buffer_delitem),
            method("__setslice__", buffer_setslice),
            method("__delslice__", buffer_delslice),
        ],
    )
}

fn read_only(vm: &Vm) -> Signal {
    vm.type_error("buffer is read-only")
}

fn bad_argument(vm: &Vm) -> Signal {
    vm.type_error("bad argument type for built-in operation")
}

fn length_mismatch(vm: &Vm) -> Signal {
    vm.type_error("right operand length must match slice length")
}

/// The receiver of a `buffer` method and the arguments after it.
fn bind<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a BufferObject, CallArgs)> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of 'buffer' object needs an argument")));
    };
    halt_on_unknown(receiver, "buffer receiver")?;
    let Some(object) = buffer_object(receiver) else {
        return Err(vm.type_error(&format!("descriptor '{method}' requires a 'buffer' object but received a '{}'", vm.type_name(receiver))));
    };

    let rest = CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };

    Ok((object, rest))
}

/// The read buffer of the right operand of a concatenation or assignment,
/// or a bad argument TypeError when it has none.
fn operand_bytes(vm: &Vm, value: &Value) -> PyResult<PyBytes> {
    halt_on_unknown(value, "buffer operand")?;

    vm.segment(value, Segment::Read)?.ok_or_else(|| bad_argument(vm))
}

/// The index of a key that supports `__index__`, raising IndexError when
/// out of range; `None` for other keys.
fn index_key(vm: &Vm, key: &Value) -> PyResult<Option<i64>> {
    if vm.as_integral(key).is_none() && vm.user_override(key, "__index__")?.is_none() {
        return Ok(None);
    }

    match index_value(vm, key) {
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::OverflowError) => {
            Err(vm.raise(ExceptionKind::IndexError, &format!("cannot fit '{}' into an index-sized integer", vm.type_name(key))))
        }
        result => result.map(Some),
    }
}

/// The bounds of a `__getslice__`-style wrapper: two signed sizes and
/// `count - 2` objects.
fn slice_arguments(vm: &Vm, args: CallArgs, count: usize) -> PyResult<(i64, i64, Vec<Value>)> {
    let given = args.positional.len();
    if given != count {
        return Err(vm.type_error(&format!("function takes exactly {count} arguments ({given} given)")));
    }

    let low = ssize_argument(vm, &args.positional[0])?;
    let high = ssize_argument(vm, &args.positional[1])?;

    Ok((low, high, args.positional[2..].to_vec()))
}

fn length_value(vm: &Vm, length: usize) -> Value {
    vm.new_int_from_i64(i64::try_from(length).unwrap_or(i64::MAX))
}

fn buffer_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = new_class(vm, args, &vm.types().buffer)?;
    if rest.has_keywords() {
        return Err(vm.type_error("buffer() does not take keyword arguments"));
    }

    let arguments = positional(vm, rest, "buffer", 1, 3)?;
    let offset = match arguments.get(1) {
        Some(offset) => ssize_argument(vm, offset)?,
        None => 0,
    };
    let size = match arguments.get(2) {
        Some(size) => ssize_argument(vm, size)?,
        None => -1,
    };

    new_buffer_object(vm, &arguments[0], offset, (size != -1).then_some(size), true)
}

/// Comparison behind the `__cmp__` wrapper's operand check.
fn buffer_cmp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__cmp__")?;
    let other = wrapper_operand(vm, rest)?;
    halt_on_unknown(&other, "buffer comparison")?;
    cmp_operand_check(vm, &args.positional[0], &other, buffer_object(&other).is_some())?;
    let Some(other) = buffer_object(&other) else {
        return Err(vm.type_error("buffer comparison with a non-buffer"));
    };

    let left = object.contents(vm)?;
    let right = other.contents(vm)?;
    let ordering = left.as_bytes().cmp(right.as_bytes());

    Ok(Value::Int(ordering as i64))
}

fn buffer_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    let status = if object.readonly { "read-only" } else { "read-write" };
    let base = vm.value_address(&object.base);
    let size = object.size.map_or(-1, |size| i64::try_from(size).unwrap_or(i64::MAX));
    let offset = object.offset;
    let address = vm.value_address(&args.positional[0]);

    Ok(Value::str(&format!("<{status} buffer for {base:#x}, size {size}, offset {offset} at {address:#x}>")))
}

fn buffer_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__hash__")?;
    wrapper_arguments(vm, rest, 0)?;

    if let Some(hash) = object.hash.get() {
        return Ok(Value::Int(hash.value()));
    }
    if !object.readonly {
        return Err(vm.type_error("writable buffers are not hashable"));
    }

    let hash = hash::hash_bytes(vm.config.long_width, object.contents(vm)?.as_bytes());
    object.hash.set(Some(hash));

    Ok(Value::Int(hash.value()))
}

fn buffer_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__str__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(object.contents(vm)?))
}

fn buffer_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(length_value(vm, object.contents(vm)?.as_bytes().len()))
}

/// A `str` of both operands' bytes, or the right operand itself when this
/// buffer is empty.
fn buffer_concat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__add__")?;
    let other = wrapper_operand(vm, rest)?;
    halt_on_unknown(&other, "buffer operand")?;
    if !vm.has_segment(&other, Segment::Read) {
        return Err(bad_argument(vm));
    }

    let head = object.contents(vm)?;
    if head.as_bytes().is_empty() {
        return Ok(other);
    }
    let tail = operand_bytes(vm, &other)?;
    let length = head.as_bytes().len() + tail.as_bytes().len();
    check_size(vm, i64::try_from(length).unwrap_or(i64::MAX))?;

    let mut joined = Vec::with_capacity(length);
    joined.extend_from_slice(head.as_bytes());
    joined.extend_from_slice(tail.as_bytes());

    Ok(Value::Str(PyBytes::new(joined)))
}

/// Repetition behind the sequence repeat wrapper.
fn buffer_repeat(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, method)?;
    let count = wrapper_operand(vm, rest)?;
    let count = index_value(vm, &count)?.max(0);

    let contents = object.contents(vm)?;
    let size = i64::try_from(contents.as_bytes().len()).unwrap_or(i64::MAX);
    if size == 0 {
        return Err(vm.halt_unsupported("repetition of an empty buffer, which divides by zero in CPython"));
    }
    if count > i64::MAX / size {
        return Err(vm.raise(ExceptionKind::MemoryError, "result too large"));
    }
    check_size(vm, size * count)?;

    let count = usize::try_from(count).unwrap_or(0);

    Ok(Value::Str(PyBytes::new(contents.as_bytes().repeat(count))))
}

fn buffer_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__getitem__")?;
    let key = wrapper_operand(vm, rest)?;
    halt_on_unknown(&key, "buffer index")?;
    let contents = object.contents(vm)?;
    let bytes = contents.as_bytes();

    if let Some(position) = index_key(vm, &key)? {
        let length = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        let position = if position < 0 { position.saturating_add(length) } else { position };
        let byte = usize::try_from(position).ok().and_then(|position| bytes.get(position));
        return match byte {
            Some(byte) => Ok(Value::Str(PyBytes::new(vec![*byte]))),
            None => Err(vm.raise(ExceptionKind::IndexError, "buffer index out of range")),
        };
    }

    let Some(slice) = vm.slice_of(&key) else {
        return Err(vm.type_error("sequence index must be integer"));
    };
    let indices = vm.slice_indices(&slice, bytes.len())?;
    let selected = indices.positions().filter_map(|position| bytes.get(position).copied()).collect::<Vec<u8>>();

    Ok(Value::Str(PyBytes::new(selected)))
}

/// Slicing, whose bounds clamp to the buffer.
fn buffer_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__getslice__")?;
    let (low, high, _) = slice_arguments(vm, rest, 2)?;
    let contents = object.contents(vm)?;
    let bytes = contents.as_bytes();

    let length = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    let low = low.max(0);
    let high = high.max(0).min(length).max(low);
    let range = usize::try_from(low).unwrap_or(0)..usize::try_from(high).unwrap_or(0);

    Ok(Value::Str(PyBytes::new(bytes.get(range).unwrap_or_default())))
}

fn buffer_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__setitem__")?;
    let (key, value) = wrapper_pair(vm, rest)?;
    assign_subscript(vm, object, &key, Some(&value))?;

    Ok(Value::None)
}

fn buffer_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__delitem__")?;
    let key = wrapper_operand(vm, rest)?;
    assign_subscript(vm, object, &key, None)?;

    Ok(Value::None)
}

fn buffer_setslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__setslice__")?;
    let (low, high, value) = slice_arguments(vm, rest, 3)?;
    assign_slice(vm, object, low, high, value.first())?;

    Ok(Value::None)
}

fn buffer_delslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (object, rest) = bind(vm, &args, "__delslice__")?;
    let (low, high, _) = slice_arguments(vm, rest, 2)?;
    assign_slice(vm, object, low, high, None)?;

    Ok(Value::None)
}

/// Writes `data` at `positions` of a writable buffer.
fn write_positions(vm: &Vm, object: &BufferObject, positions: impl Iterator<Item = usize>, data: &[u8]) -> PyResult<()> {
    let positions = positions.collect::<Vec<usize>>();
    let written = object.write(vm, &mut |bytes| {
        for (position, byte) in positions.iter().zip(data) {
            if let Some(target) = bytes.get_mut(*position) {
                *target = *byte;
            }
        }
    })?;
    if !written {
        return Err(vm.type_error("no buffer type not available"));
    }

    Ok(())
}

/// Item and slice assignment; `None` deletes, which no buffer allows.
fn assign_subscript(vm: &Vm, object: &BufferObject, key: &Value, value: Option<&Value>) -> PyResult<()> {
    if object.readonly {
        return Err(read_only(vm));
    }
    let Some(value) = value else {
        return Err(bad_argument(vm));
    };
    halt_on_unknown(key, "buffer index")?;
    if !vm.has_segment(value, Segment::Read) {
        return Err(bad_argument(vm));
    }
    let size = object.contents(vm)?.as_bytes().len();

    if let Some(position) = index_key(vm, key)? {
        let length = i64::try_from(size).unwrap_or(i64::MAX);
        let position = if position < 0 { position.saturating_add(length) } else { position };
        let Some(position) = usize::try_from(position).ok().filter(|position| *position < size) else {
            return Err(vm.raise(ExceptionKind::IndexError, "buffer assignment index out of range"));
        };
        let data = operand_bytes(vm, value)?;
        if data.as_bytes().len() != 1 {
            return Err(vm.type_error("right operand must be a single byte"));
        }
        return write_positions(vm, object, std::iter::once(position), data.as_bytes());
    }

    let Some(slice) = vm.slice_of(key) else {
        return Err(vm.type_error("buffer indices must be integers"));
    };
    let indices = vm.slice_indices(&slice, size)?;
    let data = operand_bytes(vm, value)?;
    if data.as_bytes().len() != indices.positions().count() {
        return Err(length_mismatch(vm));
    }

    write_positions(vm, object, indices.positions(), data.as_bytes())
}

/// Slice assignment, whose bounds clamp to the buffer; `None` deletes,
/// which no buffer allows.
fn assign_slice(vm: &Vm, object: &BufferObject, low: i64, high: i64, value: Option<&Value>) -> PyResult<()> {
    if object.readonly {
        return Err(read_only(vm));
    }
    let Some(value) = value else {
        return Err(bad_argument(vm));
    };
    halt_on_unknown(value, "buffer operand")?;
    if !vm.has_segment(value, Segment::Read) {
        return Err(bad_argument(vm));
    }

    let size = i64::try_from(object.contents(vm)?.as_bytes().len()).unwrap_or(i64::MAX);
    let data = operand_bytes(vm, value)?;
    let low = low.clamp(0, size);
    let high = high.clamp(low, size);
    let length = usize::try_from(high - low).unwrap_or(0);
    if data.as_bytes().len() != length {
        return Err(length_mismatch(vm));
    }

    let start = usize::try_from(low).unwrap_or(0);

    write_positions(vm, object, start..start + length, data.as_bytes())
}
