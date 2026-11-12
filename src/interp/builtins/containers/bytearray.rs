//! The `bytearray` type. The class is registered as an
//! extension type, so operators dispatch to these methods rather than to a
//! native path in `ops`. The methods it shares with `str` run the `str`
//! implementation on a copy of the contents.

use std::cell::RefCell;
use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::memory_error;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::set_class_attribute;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::class_method;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::codecs::Direction;
use crate::interp::builtins::modules::codecs::code_with_registry;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::static_method;
use crate::interp::builtins::text::check_size;
use crate::interp::builtins::text::codecs::Codec;
use crate::interp::builtins::text::codecs;
use crate::interp::builtins::text::str_method_body;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::CompareOp;
use crate::interp::sequence::SliceIndices;
use crate::interp::value::ByteArrayData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// How a `str` method shared with `bytearray` reads one positional
/// argument.
#[derive(Clone, Copy)]
enum Slot {
    /// A buffer.
    Buffer,
    /// `None` or a buffer.
    BufferOrNone,
    /// Any value `bytearray()` accepts, converted as it converts it.
    Converted,
}

pub fn register(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().bytearray);
    vm.register_extension_type(&class);

    install(
        vm,
        &class,
        &[
            static_method("__new__", bytearray_new),
            method("__init__", bytearray_init),
            method("__len__", bytearray_len),
            method("__getitem__", bytearray_getitem),
            method("__setitem__", bytearray_setitem),
            method("__delitem__", bytearray_delitem),
            method("__contains__", bytearray_contains),
            method("__iter__", bytearray_iter),
            method("__add__", bytearray_add),
            method("__iadd__", bytearray_iadd),
            method("__mul__", |vm, args| bytearray_repeat(vm, args, "__mul__")),
            method("__rmul__", |vm, args| bytearray_repeat(vm, args, "__rmul__")),
            method("__imul__", bytearray_irepeat),
            method("__eq__", |vm, args| bytearray_compare(vm, args, "__eq__", CompareOp::Equal)),
            method("__ne__", |vm, args| bytearray_compare(vm, args, "__ne__", CompareOp::NotEqual)),
            method("__lt__", |vm, args| bytearray_compare(vm, args, "__lt__", CompareOp::Less)),
            method("__le__", |vm, args| bytearray_compare(vm, args, "__le__", CompareOp::LessEqual)),
            method("__gt__", |vm, args| bytearray_compare(vm, args, "__gt__", CompareOp::Greater)),
            method("__ge__", |vm, args| bytearray_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
            method("__repr__", bytearray_repr),
            method("__str__", bytearray_str),
            method("__alloc__", bytearray_alloc),
            method("__sizeof__", bytearray_sizeof),
            method("__reduce__", bytearray_reduce),
            method("append", bytearray_append),
            method("extend", bytearray_extend),
            method("insert", bytearray_insert),
            method("pop", bytearray_pop),
            method("remove", bytearray_remove),
            method("reverse", bytearray_reverse),
            method("decode", bytearray_decode),
            method("join", bytearray_join),
            class_method("fromhex", bytearray_fromhex),
            method("index", |vm, args| bytearray_index(vm, args, "index", "find")),
            method("rindex", |vm, args| bytearray_index(vm, args, "rindex", "rfind")),
            method("startswith", |vm, args| bytearray_affix(vm, args, "startswith")),
            method("endswith", |vm, args| bytearray_affix(vm, args, "endswith")),
            method("capitalize", |vm, args| shared(vm, args, "capitalize", &[])),
            method("center", |vm, args| shared(vm, args, "center", &[])),
            method("expandtabs", |vm, args| shared(vm, args, "expandtabs", &[])),
            method("isalnum", |vm, args| shared(vm, args, "isalnum", &[])),
            method("isalpha", |vm, args| shared(vm, args, "isalpha", &[])),
            method("isdigit", |vm, args| shared(vm, args, "isdigit", &[])),
            method("islower", |vm, args| shared(vm, args, "islower", &[])),
            method("isspace", |vm, args| shared(vm, args, "isspace", &[])),
            method("istitle", |vm, args| shared(vm, args, "istitle", &[])),
            method("isupper", |vm, args| shared(vm, args, "isupper", &[])),
            method("ljust", |vm, args| shared(vm, args, "ljust", &[])),
            method("lower", |vm, args| shared(vm, args, "lower", &[])),
            method("rjust", |vm, args| shared(vm, args, "rjust", &[])),
            method("splitlines", |vm, args| shared(vm, args, "splitlines", &[])),
            method("swapcase", |vm, args| shared(vm, args, "swapcase", &[])),
            method("title", |vm, args| shared(vm, args, "title", &[])),
            method("upper", |vm, args| shared(vm, args, "upper", &[])),
            method("zfill", |vm, args| shared(vm, args, "zfill", &[])),
            method("count", |vm, args| shared(vm, args, "count", &[Slot::Buffer])),
            method("find", |vm, args| shared(vm, args, "find", &[Slot::Buffer])),
            method("rfind", |vm, args| shared(vm, args, "rfind", &[Slot::Buffer])),
            method("split", |vm, args| shared(vm, args, "split", &[Slot::BufferOrNone])),
            method("rsplit", |vm, args| shared(vm, args, "rsplit", &[Slot::BufferOrNone])),
            method("strip", |vm, args| shared(vm, args, "strip", &[Slot::BufferOrNone])),
            method("lstrip", |vm, args| shared(vm, args, "lstrip", &[Slot::BufferOrNone])),
            method("rstrip", |vm, args| shared(vm, args, "rstrip", &[Slot::BufferOrNone])),
            method("partition", |vm, args| shared(vm, args, "partition", &[Slot::Converted])),
            method("rpartition", |vm, args| shared(vm, args, "rpartition", &[Slot::Converted])),
            method("replace", |vm, args| shared(vm, args, "replace", &[Slot::Buffer, Slot::Buffer])),
            method("translate", |vm, args| shared(vm, args, "translate", &[Slot::BufferOrNone, Slot::Buffer])),
        ],
    )?;

    set_class_attribute(vm, &class, "__hash__", Value::None)
}

/// The receiver of a `bytearray` method; subclasses included.
fn bind_bytearray(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(ObjectRef, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "bytearray")?;
    match &target {
        Value::Object(object) if matches!(object.payload, Payload::ByteArray(_)) => Ok((Rc::clone(object), rest)),
        _ => Err(wrong_receiver(vm, method, "bytearray", &target)),
    }
}

fn storage(object: &ObjectRef) -> &RefCell<ByteArrayData> {
    match &object.payload {
        Payload::ByteArray(data) => data,
        _ => unreachable!("bind_bytearray accepts only bytearray payloads"),
    }
}

fn contents(object: &ObjectRef) -> Vec<u8> {
    storage(object).borrow().bytes.clone()
}

/// The first unknown argument; a method that builds a new value from it
/// is unknown too.
fn unknown_argument(args: &CallArgs) -> Option<Value> {
    args.positional.iter().chain(args.keywords.iter().map(|(_, value)| value)).find(|value| value.is_unknown()).cloned()
}

/// Records the allocation a change of length to `size` leaves, as
/// `__alloc__` reports it; callers then set the contents. A live export
/// forbids any change of length. One byte past the contents is always
/// allocated: a length below half the allocation shrinks it to fit, one
/// still inside it keeps it, one at most an eighth past it grows it by an
/// eighth plus a small constant, and a larger one fits exactly.
fn reserve(vm: &Vm, data: &mut ByteArrayData, size: usize) -> PyResult<()> {
    const SMALL: usize = 9;

    let length = data.bytes.len();
    if size == length {
        return Ok(());
    }
    if data.exports.get() > 0 {
        return Err(vm.raise(ExceptionKind::BufferError, "Existing exports of data: object cannot be re-sized"));
    }
    check_size(vm, i64::try_from(size).unwrap_or(i64::MAX))?;

    let allocated = data.alloc;
    let within_an_eighth = (size as u128) * 8 <= (allocated as u128) * 9;
    let alloc = if size < allocated / 2 {
        size.checked_add(1)
    } else if size < allocated {
        Some(allocated)
    } else if within_an_eighth {
        let slack = if size < SMALL { 3 } else { 6 };
        size.checked_add(size / 8).and_then(|grown| grown.checked_add(slack))
    } else {
        size.checked_add(1)
    };
    let Some(alloc) = alloc else {
        return Err(memory_error(vm));
    };

    data.bytes.try_reserve(size.saturating_sub(length)).map_err(|_| memory_error(vm))?;
    data.alloc = alloc;

    Ok(())
}

/// Growth that keeps the allocation while the new length fits in it, as
/// in-place concatenation and repetition and construction from an
/// iterable do; they never shrink it.
fn reserve_growing(vm: &Vm, data: &mut ByteArrayData, size: usize) -> PyResult<()> {
    if size < data.alloc {
        return Ok(());
    }

    reserve(vm, data, size)
}

/// `_getbytevalue`: an exact one-character `str` or an integer in
/// `range(256)`.
fn byte_value(vm: &Vm, value: &Value) -> PyResult<u8> {
    halt_on_unknown(value, "bytearray item")?;

    if let Value::Str(bytes) = value {
        let [byte] = bytes.as_bytes() else {
            return Err(vm.raise(ExceptionKind::ValueError, "string must be of size 1"));
        };
        return Ok(*byte);
    }

    // Any failure to convert to an index becomes this one error.
    let required = || vm.type_error("an integer or string of size 1 is required");
    let index = match vm.number_index(value) {
        Ok(index) => index,
        Err(Signal::Raise(_)) => return Err(required()),
        Err(halt) => return Err(halt),
    };
    let integral = vm.as_integral(&index).ok_or_else(required)?;

    u8::try_from(integral.saturating_i64()).map_err(|_| vm.raise(ExceptionKind::ValueError, "byte must be in range(0, 256)"))
}

/// `_getbuffer`: the contents of a `str` or `bytearray`.
fn buffer_bytes(vm: &Vm, value: &Value) -> PyResult<PyBytes> {
    vm.buffer(value, BufferInterface::New)?.ok_or_else(|| vm.type_error(&format!("Type {} doesn't support the buffer API", vm.type_name(value))))
}

/// An index operand as a position; one too large raises `IndexError`.
/// `None` when `index` is not an integer.
fn index_operand(vm: &Vm, index: &Value) -> PyResult<Option<i64>> {
    if !vm.is_index(index)? {
        return Ok(None);
    }

    vm.index_as_ssize(index, Some(ExceptionKind::IndexError)).map(Some)
}

/// A position checked against `length`, negative ones counted from the
/// end.
fn checked_position(vm: &Vm, position: i64, length: usize) -> PyResult<usize> {
    let length = length as i64;
    let position = if position < 0 { position + length } else { position };
    if position < 0 || position >= length {
        return Err(vm.raise(ExceptionKind::IndexError, "bytearray index out of range"));
    }

    Ok(position as usize)
}

/// `bytearray.__new__`: an empty array that `__init__` fills.
/// Construction from an unknown argument is unknown.
fn bytearray_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().bytearray);
    let (class, rest) = new_class(vm, args, &base)?;
    if let Some(unknown) = unknown_argument(&rest) {
        return Ok(unknown);
    }

    Ok(new_instance(vm, &class, Payload::ByteArray(RefCell::new(ByteArrayData::new(Vec::new())))))
}

/// `bytearray.__init__`. The previous contents are dropped before the
/// arguments are parsed.
fn bytearray_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__init__")?;
    if let Some(unknown) = unknown_argument(&rest) {
        halt_on_unknown(&unknown, "bytearray() argument")?;
    }

    let target = storage(&array);
    {
        let mut data = target.borrow_mut();
        reserve(vm, &mut data, 0)?;
        data.bytes.clear();
    }

    let slots = parse_with(vm, rest, "bytearray", &["source", "encoding", "errors"], 0, |vm, index, value| match index {
        0 => Ok(value),
        _ => args::c_string(vm, "bytearray", index + 1, &value).map(Value::Str),
    })?;
    fill(vm, target, slots[0].as_ref(), converted_string(&slots[1]), converted_string(&slots[2]))?;

    Ok(Value::None)
}

/// An `s` argument that `parse_with` converted to a `str`.
fn converted_string(slot: &Option<Value>) -> Option<PyBytes> {
    match slot {
        Some(Value::Str(bytes)) => Some(bytes.clone()),
        _ => None,
    }
}

/// The body of `bytearray.__init__` after parsing, on an emptied array.
fn fill(vm: &Vm, target: &RefCell<ByteArrayData>, source: Option<&Value>, encoding: Option<PyBytes>, errors: Option<PyBytes>) -> PyResult<()> {
    let Some(source) = source else {
        if encoding.is_some() || errors.is_some() {
            return Err(vm.type_error("encoding or errors without sequence argument"));
        }
        return Ok(());
    };
    let errors = errors.as_ref().map(PyBytes::as_bytes);

    if let Some(bytes) = vm.as_str_bytes(source) {
        // The codec runs for its errors, but the source itself is appended
        // rather than the encoded result.
        if let Some(encoding) = &encoding {
            match vm.native_codec(Some(encoding.as_bytes())) {
                Some(codec) => {
                    codecs::encode_bytes(vm, codec, bytes.as_bytes(), errors)?;
                }
                None => {
                    code_with_registry(vm, encoding.as_bytes(), Value::Str(bytes.clone()), errors, Direction::Encode)?;
                }
            }
        }
        return append_bytes(vm, target, bytes.as_bytes());
    }

    if let Some(text) = vm.as_text(source) {
        let Some(encoding) = &encoding else {
            return Err(vm.type_error("unicode argument without an encoding"));
        };
        let encoded = match vm.native_codec(Some(encoding.as_bytes())) {
            Some(codec) => codecs::encode(vm, codec, text.units(), errors)?,
            None => code_with_registry(vm, encoding.as_bytes(), Value::Unicode(text.clone()), errors, Direction::Encode)?,
        };
        let Some(bytes) = vm.as_str_bytes(&encoded) else {
            return Err(vm.type_error(&format!("encoder did not return a string object (type={})", vm.type_name(&encoded))));
        };
        return append_bytes(vm, target, bytes.as_bytes());
    }

    if encoding.is_some() || errors.is_some() {
        return Err(vm.type_error("encoding or errors without a string argument"));
    }

    if let Some(count) = count_argument(vm, source)? {
        let Ok(count) = usize::try_from(count) else {
            return Err(vm.raise(ExceptionKind::ValueError, "negative count"));
        };
        let mut data = target.borrow_mut();
        reserve(vm, &mut data, count)?;
        data.bytes.resize(count, 0);
        return Ok(());
    }

    // A source with the new buffer interface, such as a memoryview, is
    // copied whole, so the allocation fits it exactly.
    if let Some(bytes) = vm.buffer(source, BufferInterface::New)? {
        let mut data = target.borrow_mut();
        reserve(vm, &mut data, bytes.as_bytes().len())?;
        data.bytes = bytes.as_bytes().to_vec();
        return Ok(());
    }

    let iterator = vm.iter(source)?;
    while let Some(item) = vm.next(&iterator)? {
        let byte = byte_value(vm, &item)?;
        let mut data = target.borrow_mut();
        let size = data.bytes.len() + 1;
        reserve_growing(vm, &mut data, size)?;
        data.bytes.push(byte);
    }

    Ok(())
}

/// In-place concatenation of known bytes.
fn append_bytes(vm: &Vm, target: &RefCell<ByteArrayData>, bytes: &[u8]) -> PyResult<()> {
    let mut data = target.borrow_mut();
    let size = data.bytes.len() + bytes.len();
    reserve_growing(vm, &mut data, size)?;
    data.bytes.extend_from_slice(bytes);

    Ok(())
}

/// The integer count argument of `bytearray(count)`, too large a value
/// raising `OverflowError`. `None` for a non-integer, whose conversion
/// error is dropped.
fn count_argument(vm: &Vm, source: &Value) -> PyResult<Option<i64>> {
    let integral = match vm.as_integral(source) {
        Some(integral) => integral,
        None => {
            let Some(method) = vm.user_override(source, "__index__")? else {
                return Ok(None);
            };
            let result = match vm.call0(&method) {
                Ok(result) => result,
                Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => return Ok(None),
                Err(signal) => return Err(signal),
            };
            halt_on_unknown(&result, "__index__ result")?;
            let Some(integral) = vm.as_integral(&result) else {
                return Ok(None);
            };
            integral
        }
    };

    match integral {
        Integral::Int(number) => Ok(Some(number)),
        Integral::Long(number) => number.to_i64().map(Some).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, &format!("cannot fit '{}' into an index-sized integer", vm.type_name(source)))),
    }
}

/// The contents `bytearray(source)` would have.
fn from_object(vm: &Vm, source: &Value) -> PyResult<Vec<u8>> {
    let target = RefCell::new(ByteArrayData::new(Vec::new()));
    fill(vm, &target, Some(source), None, None)?;

    Ok(target.into_inner().bytes)
}

fn bytearray_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(storage(&array).borrow().bytes.len() as i64))
}

/// `self[index]`.
fn bytearray_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;
    if index.is_unknown() {
        return Ok(index);
    }

    if let Some(position) = index_operand(vm, &index)? {
        let bytes = contents(&array);
        let position = checked_position(vm, position, bytes.len())?;
        return Ok(Value::Int(i64::from(bytes[position])));
    }

    let Some(slice) = vm.slice_of(&index) else {
        return Err(vm.type_error("bytearray indices must be integers"));
    };
    let bytes = contents(&array);
    let indices = vm.slice_indices(&slice, bytes.len())?;

    Ok(vm.new_bytearray(indices.positions().map(|position| bytes[position]).collect()))
}

fn bytearray_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__setitem__")?;
    let (index, value) = wrapper_pair(vm, rest)?;
    assign(vm, &array, &index, Some(value))?;

    Ok(Value::None)
}

fn bytearray_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__delitem__")?;
    let index = wrapper_operand(vm, rest)?;
    assign(vm, &array, &index, None)?;

    Ok(Value::None)
}

/// The positions `index` selects: one item or a slice.
fn subscript_indices(vm: &Vm, index: &Value, length: usize) -> PyResult<SliceIndices> {
    let Some(slice) = vm.slice_of(index) else {
        return Err(vm.type_error("bytearray indices must be integer"));
    };

    vm.slice_indices(&slice, length)
}

/// `self[index] = values`; `None` deletes.
fn assign(vm: &Vm, array: &ObjectRef, index: &Value, values: Option<Value>) -> PyResult<()> {
    halt_on_unknown(index, "bytearray index")?;
    if let Some(values) = &values {
        halt_on_unknown(values, "bytearray assignment")?;
    }

    let position = index_operand(vm, index)?;
    let target = storage(array);
    let length = target.borrow().bytes.len();
    let mut indices = match position {
        Some(position) => {
            let position = checked_position(vm, position, length)?;
            if let Some(values) = &values {
                let byte = byte_value(vm, values)?;
                if let Some(slot) = target.borrow_mut().bytes.get_mut(position) {
                    *slot = byte;
                }
                return Ok(());
            }
            let position = position as i64;
            SliceIndices { start: position, stop: position + 1, step: 1 }
        }
        None => subscript_indices(vm, index, length)?,
    };

    let needed = match values {
        None => Vec::new(),
        Some(values) => match vm.as_bytearray(&values) {
            Some(bytes) => bytes,
            None => {
                if vm.as_text(&values).is_some() || is_number(vm, &values)? {
                    return Err(vm.type_error("can assign only bytes, buffers, or iterables of ints in range(0, 256)"));
                }
                let bytes = from_object(vm, &values)?;
                // The slice is recomputed against the length after the
                // conversion ran.
                if vm.slice_of(index).is_some() {
                    let length = target.borrow().bytes.len();
                    indices = subscript_indices(vm, index, length)?;
                }
                bytes
            }
        },
    };

    let positions: Vec<usize> = indices.positions().collect();
    let mut data = target.borrow_mut();
    let length = data.bytes.len();
    if positions.iter().any(|position| *position >= length) {
        return Err(vm.halt_unsupported("bytearray resized by Python code while its slice assignment converted arguments"));
    }

    if indices.step == 1 {
        let start = usize::try_from(indices.start).unwrap_or(0).min(length);
        let count = positions.len();
        if count != needed.len() {
            reserve(vm, &mut data, length - count + needed.len())?;
        }
        data.bytes.splice(start..start + count, needed);
        return Ok(());
    }

    if needed.is_empty() {
        reserve(vm, &mut data, length - positions.len())?;
        let mut removed = vec![false; length];
        for &position in &positions {
            removed[position] = true;
        }
        let mut position = 0;
        data.bytes.retain(|_| {
            let keep = !removed[position];
            position += 1;
            keep
        });
        return Ok(());
    }

    if needed.len() != positions.len() {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("attempt to assign bytes of size {} to extended slice of size {}", needed.len(), positions.len())));
    }
    for (position, byte) in positions.into_iter().zip(needed) {
        data.bytes[position] = byte;
    }

    Ok(())
}

/// Whether `value` is a number: numbers and objects converting to `int`
/// or `float`; every classic instance converts.
fn is_number(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.is_number(value) {
        return Ok(true);
    }
    let Value::Object(object) = value else {
        return Ok(false);
    };
    if vm.is_classic_class(&object.class()) {
        return Ok(true);
    }

    Ok(vm.user_override(value, "__int__")?.is_some() || vm.user_override(value, "__float__")?.is_some())
}

/// `item in self`: an integer is a byte; anything else must be a buffer.
fn bytearray_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__contains__")?;
    let item = wrapper_operand(vm, rest)?;
    if item.is_unknown() {
        return Ok(item);
    }

    // Any failure to convert to an index falls back to the buffer.
    let number = match index_operand(vm, &item) {
        Ok(number) => number,
        Err(Signal::Raise(_)) => None,
        Err(signal) => return Err(signal),
    };
    let bytes = contents(&array);

    let Some(number) = number else {
        let needle = buffer_bytes(vm, &item)?;
        let needle = needle.as_bytes();
        let found = needle.is_empty() || bytes.windows(needle.len()).any(|window| window == needle);
        return Ok(Value::Bool(found));
    };
    let Ok(byte) = u8::try_from(number) else {
        return Err(vm.raise(ExceptionKind::ValueError, "byte must be in range(0, 256)"));
    };

    Ok(Value::Bool(bytes.contains(&byte)))
}

fn bytearray_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_iterator(NativeIterator::Sequence { sequence: Value::Object(array), index: 0 }))
}

/// `self + other`.
fn bytearray_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__add__")?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(tail) = vm.buffer(&other, BufferInterface::New)? else {
        let receiver = Value::Object(Rc::clone(&array));
        return Err(vm.type_error(&format!("can't concat {} to {}", vm.type_name(&receiver), vm.type_name(&other))));
    };
    let mut joined = contents(&array);
    joined.extend_from_slice(tail.as_bytes());

    Ok(vm.new_bytearray(joined))
}

/// `self += other`.
fn bytearray_iadd(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__iadd__")?;
    let other = wrapper_operand(vm, rest)?;
    halt_on_unknown(&other, "bytearray +=")?;

    let Some(tail) = vm.buffer(&other, BufferInterface::New)? else {
        let receiver = Value::Object(Rc::clone(&array));
        return Err(vm.type_error(&format!("can't concat {} to {}", vm.type_name(&other), vm.type_name(&receiver))));
    };

    // A buffer export of `other` is held while growing; growing the array
    // into itself past its allocation would invalidate that export.
    let target = storage(&array);
    let exported = other.as_object().is_some_and(|object| Rc::ptr_eq(object, &array));
    if exported {
        let data = target.borrow();
        let size = data.bytes.len() + tail.as_bytes().len();
        if size >= data.alloc && size != data.bytes.len() {
            return Err(vm.raise(ExceptionKind::BufferError, "Existing exports of data: object cannot be re-sized"));
        }
    }
    append_bytes(vm, target, tail.as_bytes())?;

    Ok(Value::Object(array))
}

/// The count of the repetition wrappers, which converts through
/// `__index__`. The `*` operator checks the operand before reaching the
/// wrapper.
fn repeat_count(vm: &Vm, operand: &Value) -> PyResult<usize> {
    Ok(usize::try_from(index_value(vm, operand)?).unwrap_or(0))
}

/// The length of `count` copies of `length` bytes, or `MemoryError`.
fn repeated_size(vm: &Vm, length: usize, count: usize) -> PyResult<usize> {
    let Some(size) = length.checked_mul(count) else {
        return Err(memory_error(vm));
    };
    check_size(vm, i64::try_from(size).unwrap_or(i64::MAX))?;

    Ok(size)
}

/// `self * count`.
fn bytearray_repeat(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, method)?;
    let count = wrapper_operand(vm, rest)?;
    if count.is_unknown() {
        return Ok(count);
    }

    let count = repeat_count(vm, &count)?;
    let bytes = contents(&array);
    repeated_size(vm, bytes.len(), count)?;

    Ok(vm.new_bytearray(bytes.repeat(count)))
}

/// `self *= count`.
fn bytearray_irepeat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__imul__")?;
    let count = wrapper_operand(vm, rest)?;
    halt_on_unknown(&count, "bytearray *=")?;

    let count = repeat_count(vm, &count)?;
    let mut data = storage(&array).borrow_mut();
    let size = repeated_size(vm, data.bytes.len(), count)?;
    reserve_growing(vm, &mut data, size)?;
    data.bytes = data.bytes.repeat(count);
    drop(data);

    Ok(Value::Object(array))
}

/// Rich comparison: buffers compare bytewise; `unicode` and non-buffers
/// are `NotImplemented`.
fn bytearray_compare(vm: &Vm, args: CallArgs, method: &str, operation: CompareOp) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, method)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }
    if vm.as_text(&other).is_some() {
        return Ok(Value::NotImplemented);
    }

    let Some(other) = vm.buffer(&other, BufferInterface::New)? else {
        return Ok(Value::NotImplemented);
    };

    Ok(Value::Bool(operation.holds(contents(&array)[..].cmp(other.as_bytes()))))
}

/// `repr()`: single quotes unless the contents hold `'` and no `"`; a `'`
/// is escaped either way.
fn repr_text(bytes: &[u8]) -> String {
    let mut quote = '\'';
    for &byte in bytes {
        if byte == b'"' {
            quote = '\'';
            break;
        }
        if byte == b'\'' {
            quote = '"';
        }
    }

    let mut output = String::with_capacity(bytes.len() + 14);
    output.push_str("bytearray(b");
    output.push(quote);
    for &byte in bytes {
        match byte {
            b'\'' | b'\\' => {
                output.push('\\');
                output.push(char::from(byte));
            }
            b'\t' => output.push_str("\\t"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            0x20..=0x7e => output.push(char::from(byte)),
            _ => output.push_str(&format!("\\x{byte:02x}")),
        }
    }
    output.push(quote);
    output.push(')');

    output
}

fn bytearray_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::str(&repr_text(&contents(&array))))
}

fn bytearray_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__str__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(contents(&array))))
}

fn bytearray_alloc(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__alloc__")?;
    no_arguments(vm, rest, "__alloc__")?;

    Ok(vm.new_int_from_i64(storage(&array).borrow().alloc as i64))
}

/// `__sizeof__()`: the object header of the 64-bit build plus the
/// allocation.
fn bytearray_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const OBJECT_SIZE: usize = 48;

    let (array, rest) = bind_bytearray(vm, args, "__sizeof__")?;
    no_arguments(vm, rest, "__sizeof__")?;

    Ok(vm.new_int_from_i64((OBJECT_SIZE + storage(&array).borrow().alloc) as i64))
}

/// `__reduce__()`: `(type, (latin-1 text, 'latin-1'), __dict__)`.
fn bytearray_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "__reduce__")?;
    no_arguments(vm, rest, "__reduce__")?;

    let latin1 = contents(&array);
    let text = Value::Unicode(codecs::decoded_text(Codec::Latin1, &latin1, latin1.iter().map(|byte| u16::from(*byte)).collect()));
    let dict = array.dict().map_or(Value::None, Value::Object);

    Ok(Value::tuple(vec![Value::Object(array.class()), Value::tuple(vec![text, Value::str("latin-1")]), dict]))
}

fn bytearray_append(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "append")?;
    let item = one_argument(vm, rest, "append")?;
    let byte = byte_value(vm, &item)?;

    let mut data = storage(&array).borrow_mut();
    let size = data.bytes.len() + 1;
    reserve(vm, &mut data, size)?;
    data.bytes.push(byte);

    Ok(Value::None)
}

/// `extend()`: a buffer is appended whole; an iterable is drained into a
/// temporary array first, so a bad item leaves the array as it was.
fn bytearray_extend(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "extend")?;
    let other = one_argument(vm, rest, "extend")?;
    halt_on_unknown(&other, "bytearray.extend argument")?;

    let extra = match vm.buffer(&other, BufferInterface::New)? {
        Some(bytes) => bytes.as_bytes().to_vec(),
        None => {
            let iterator = vm.iter(&other)?;
            let mut extra = Vec::new();
            while let Some(item) = vm.next(&iterator)? {
                extra.push(byte_value(vm, &item)?);
            }
            extra
        }
    };

    let mut data = storage(&array).borrow_mut();
    let size = data.bytes.len() + extra.len();
    reserve(vm, &mut data, size)?;
    data.bytes.extend_from_slice(&extra);

    Ok(Value::None)
}

/// `insert()`: negative positions count from the end; both ends clamp.
fn bytearray_insert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "insert")?;
    let arguments = positional(vm, rest, "insert", 2, 2)?;
    let position = ssize_argument(vm, &arguments[0])?;
    let byte = byte_value(vm, &arguments[1])?;

    let mut data = storage(&array).borrow_mut();
    let length = data.bytes.len();
    reserve(vm, &mut data, length + 1)?;
    let length = length as i64;
    let position = if position < 0 { (position + length).max(0) } else { position.min(length) };
    data.bytes.insert(position as usize, byte);

    Ok(Value::None)
}

fn bytearray_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "pop")?;
    let arguments = positional(vm, rest, "pop", 0, 1)?;
    let requested = match arguments.first() {
        Some(index) => ssize_argument(vm, index)?,
        None => -1,
    };

    let mut data = storage(&array).borrow_mut();
    let length = data.bytes.len();
    if length == 0 {
        return Err(vm.raise(ExceptionKind::IndexError, "pop from empty bytearray"));
    }
    let position = if requested < 0 { requested + length as i64 } else { requested };
    if position < 0 || position >= length as i64 {
        return Err(vm.raise(ExceptionKind::IndexError, "pop index out of range"));
    }

    reserve(vm, &mut data, length - 1)?;
    let byte = data.bytes.remove(position as usize);

    Ok(Value::Int(i64::from(byte)))
}

fn bytearray_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "remove")?;
    let item = one_argument(vm, rest, "remove")?;
    let byte = byte_value(vm, &item)?;

    let mut data = storage(&array).borrow_mut();
    let Some(position) = data.bytes.iter().position(|candidate| *candidate == byte) else {
        return Err(vm.raise(ExceptionKind::ValueError, "value not found in bytearray"));
    };
    let length = data.bytes.len();
    reserve(vm, &mut data, length - 1)?;
    data.bytes.remove(position);

    Ok(Value::None)
}

fn bytearray_reverse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "reverse")?;
    no_arguments(vm, rest, "reverse")?;
    storage(&array).borrow_mut().bytes.reverse();

    Ok(Value::None)
}

/// `decode()`, which hands the array itself to the codec. The
/// `string_escape` codec refuses a bytearray.
fn bytearray_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "decode")?;
    if let Some(unknown) = unknown_argument(&rest) {
        return Ok(unknown);
    }

    let slots = parse_with(vm, rest, "decode", &["encoding", "errors"], 0, |vm, index, value| args::c_string(vm, "decode", index + 1, &value).map(Value::Str))?;
    let encoding = converted_string(&slots[0]);
    let errors = converted_string(&slots[1]);
    let codec = match &encoding {
        Some(encoding) => match vm.native_codec(Some(encoding.as_bytes())) {
            Some(codec) => codec,
            None => return code_with_registry(vm, encoding.as_bytes(), Value::Object(Rc::clone(&array)), errors.as_ref().map(PyBytes::as_bytes), Direction::Decode),
        },
        None => vm.default_codec(),
    };
    if codec == Codec::StringEscape {
        let receiver = Value::Object(Rc::clone(&array));
        return Err(vm.type_error(&format!("escape_decode() argument 1 must be string or read-only buffer, not {}", vm.type_name(&receiver))));
    }

    codecs::decode(vm, codec, &contents(&array), errors.as_ref().map(PyBytes::as_bytes))
}

/// `join()`: items must be `str` or `bytearray`.
fn bytearray_join(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (array, rest) = bind_bytearray(vm, args, "join")?;
    let iterable = one_argument(vm, rest, "join")?;
    if iterable.is_unknown() {
        return Ok(iterable);
    }

    let iterator = match vm.iter(&iterable) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => return Err(vm.type_error("can only join an iterable")),
        Err(signal) => return Err(signal),
    };
    let items = vm.collect(&iterator)?;
    if let Some(unknown) = items.iter().find(|item| item.is_unknown()) {
        return Ok(unknown.clone());
    }

    let mut parts = Vec::with_capacity(items.len());
    for (position, item) in items.iter().enumerate() {
        let Some(bytes) = vm.buffer(item, BufferInterface::New)? else {
            return Err(vm.type_error(&format!("can only join an iterable of bytes (item {position} has type '{}')", vm.type_name(item))));
        };
        parts.push(bytes);
    }

    let separator = contents(&array);
    let mut joined = Vec::new();
    for (position, part) in parts.iter().enumerate() {
        if position > 0 {
            joined.extend_from_slice(&separator);
        }
        joined.extend_from_slice(part.as_bytes());
    }

    Ok(vm.new_bytearray(joined))
}

/// `bytearray.fromhex(string)`: pairs of hex digits, with spaces allowed
/// before each pair. The result is a `bytearray` even for subclasses.
fn bytearray_fromhex(vm: &Vm, mut call: CallArgs) -> PyResult<Value> {
    if !call.positional.is_empty() {
        call.positional.remove(0);
    }
    let arguments = args::varargs(vm, call, "fromhex", 1, 1)?;
    if let Some(unknown) = arguments.iter().find(|value| value.is_unknown()) {
        return Ok(unknown.clone());
    }

    let hex = args::read_buffer(vm, "fromhex", 1, &arguments[0])?;
    let hex = hex.as_bytes();
    let digit = |position: usize| hex.get(position).and_then(|byte| char::from(*byte).to_digit(16));

    let mut output = Vec::with_capacity(hex.len() / 2);
    let mut position = 0;
    while position < hex.len() {
        while hex.get(position) == Some(&b' ') {
            position += 1;
        }
        if position >= hex.len() {
            break;
        }
        let (Some(top), Some(bottom)) = (digit(position), digit(position + 1)) else {
            return Err(vm.raise(ExceptionKind::ValueError, &format!("non-hexadecimal number found in fromhex() arg at position {position}")));
        };
        output.push(((top << 4) | bottom) as u8);
        position += 2;
    }

    Ok(vm.new_bytearray(output))
}

/// A `str` result of a shared method as a `bytearray`, element-wise for
/// the lists and tuples that splitting and partitioning return.
fn bytearray_result(vm: &Vm, value: Value) -> Value {
    let convert = |item: &Value| match vm.as_str_bytes(item) {
        Some(bytes) => vm.new_bytearray(bytes.as_bytes().to_vec()),
        None => item.clone(),
    };

    if let Some(items) = vm.as_tuple(&value) {
        return Value::tuple(items.iter().map(convert).collect());
    }
    if let Some(items) = vm.as_list(&value) {
        return vm.new_list(items.iter().map(convert).collect());
    }

    convert(&value)
}

/// Runs the `str` method `name` on the contents, after reading the
/// positional arguments `slots` describes as buffers.
fn shared(vm: &Vm, args: CallArgs, name: &str, slots: &[Slot]) -> PyResult<Value> {
    let (array, mut rest) = bind_bytearray(vm, args, name)?;
    if let Some(unknown) = unknown_argument(&rest) {
        return Ok(unknown);
    }

    for (slot, value) in slots.iter().zip(rest.positional.iter_mut()) {
        let bytes = match slot {
            Slot::BufferOrNone if value.is_none() => continue,
            Slot::Buffer | Slot::BufferOrNone => buffer_bytes(vm, value)?,
            Slot::Converted => {
                let converted = vm.call1(&Value::Object(Rc::clone(&vm.types().bytearray)), value.clone())?;
                match &converted {
                    Value::Object(object) if matches!(object.payload, Payload::ByteArray(_)) => PyBytes::new(contents(object)),
                    _ => return Ok(converted),
                }
            }
        };
        *value = Value::Str(bytes);
    }

    let result = run_str_method(vm, name, &contents(&array), rest)?;

    Ok(bytearray_result(vm, result))
}

fn run_str_method(vm: &Vm, name: &str, bytes: &[u8], args: CallArgs) -> PyResult<Value> {
    let Some(body) = str_method_body(name) else {
        return Err(vm.halt_unsupported(format!("bytearray.{name} without a shared str method")));
    };

    body(vm, bytes, args)
}

/// `index` and `rindex`: `find` and `rfind` that raise when the
/// subsection is missing.
fn bytearray_index(vm: &Vm, args: CallArgs, name: &str, search: &str) -> PyResult<Value> {
    let (array, mut rest) = bind_bytearray(vm, args, name)?;
    if let Some(unknown) = unknown_argument(&rest) {
        return Ok(unknown);
    }
    if let Some(needle) = rest.positional.first_mut() {
        *needle = Value::Str(buffer_bytes(vm, needle)?);
    }

    match run_str_method(vm, search, &contents(&array), rest)? {
        Value::Int(-1) => Err(vm.raise(ExceptionKind::ValueError, "subsection not found")),
        found => Ok(found),
    }
}

/// `startswith` and `endswith`. Tuple members are read as buffers one at
/// a time, so a bad member after a match raises nothing.
fn bytearray_affix(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (array, mut rest) = bind_bytearray(vm, args, name)?;
    if let Some(unknown) = unknown_argument(&rest) {
        return Ok(unknown);
    }

    let mut failure = None;
    if let Some(affix) = rest.positional.first_mut() {
        match vm.as_tuple(affix) {
            Some(items) => {
                let mut converted = Vec::with_capacity(items.len());
                for item in items.iter() {
                    if item.is_unknown() {
                        return Ok(item.clone());
                    }
                    match buffer_bytes(vm, item) {
                        Ok(bytes) => converted.push(Value::Str(bytes)),
                        Err(signal) => {
                            failure = Some(signal);
                            break;
                        }
                    }
                }
                *affix = Value::tuple(converted);
            }
            None => *affix = Value::Str(buffer_bytes(vm, affix)?),
        }
    }

    let result = run_str_method(vm, name, &contents(&array), rest)?;
    match failure {
        Some(signal) if matches!(result, Value::Bool(false)) => Err(signal),
        _ => Ok(result),
    }
}
