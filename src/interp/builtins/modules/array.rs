//! `array`. Items are stored as the machine
//! values of the little-endian target; `l` and `L` follow the C `long` of
//! `vm.config.long_width`, and `u` is a 16-bit code unit of the
//! narrow build.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_bigint::Sign;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::registered_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::builtins::text::check_size;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::CompareOp;
use crate::interp::sequence::SliceIndices;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const ARRAY_TYPE: &str = "array.array";
const ITERATOR_TYPE: &str = "arrayiterator";

/// The typecodes `array` supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Typecode {
    Char,
    SignedByte,
    UnsignedByte,
    Unicode,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    Float,
    Double,
}

impl Typecode {
    fn parse(code: u32) -> Option<Self> {
        let typecode = match char::from_u32(code)? {
            'c' => Self::Char,
            'b' => Self::SignedByte,
            'B' => Self::UnsignedByte,
            'u' => Self::Unicode,
            'h' => Self::Short,
            'H' => Self::UnsignedShort,
            'i' => Self::Int,
            'I' => Self::UnsignedInt,
            'l' => Self::Long,
            'L' => Self::UnsignedLong,
            'f' => Self::Float,
            'd' => Self::Double,
            _ => return None,
        };

        Some(typecode)
    }

    fn code(self) -> u8 {
        match self {
            Self::Char => b'c',
            Self::SignedByte => b'b',
            Self::UnsignedByte => b'B',
            Self::Unicode => b'u',
            Self::Short => b'h',
            Self::UnsignedShort => b'H',
            Self::Int => b'i',
            Self::UnsignedInt => b'I',
            Self::Long => b'l',
            Self::UnsignedLong => b'L',
            Self::Float => b'f',
            Self::Double => b'd',
        }
    }

    fn itemsize(self, width: LongWidth) -> usize {
        match self {
            Self::Char | Self::SignedByte | Self::UnsignedByte => 1,
            Self::Unicode | Self::Short | Self::UnsignedShort => 2,
            Self::Int | Self::UnsignedInt | Self::Float => 4,
            Self::Long | Self::UnsignedLong => match width {
                LongWidth::Bits32 => 4,
                LongWidth::Bits64 => 8,
            },
            Self::Double => 8,
        }
    }
}

/// An array: `items` holds `itemsize` bytes per item. `allocated` is the
/// allocated item count, `None` while no storage is allocated.
pub(crate) struct ArrayData {
    typecode: Typecode,
    itemsize: usize,
    items: RefCell<Vec<u8>>,
    allocated: Cell<Option<usize>>,
}

impl_native_data!(ArrayData, "array.array");

impl ArrayData {
    /// A new array with `items` already encoded.
    fn new(typecode: Typecode, itemsize: usize, items: Vec<u8>) -> Self {
        let length = items.len() / itemsize;
        let allocated = (length > 0).then_some(length);

        Self { typecode, itemsize, items: RefCell::new(items), allocated: Cell::new(allocated) }
    }

    fn len(&self) -> usize {
        self.items.borrow().len() / self.itemsize
    }

    fn snapshot(&self) -> Vec<u8> {
        self.items.borrow().clone()
    }

    /// The bookkeeping of a resize to the current length.
    fn fit_allocation(&self) {
        self.allocated.set(Some(self.len()));
    }

    /// Allocation for a change to `size` items; the caller
    /// sets the contents.
    fn reserve(&self, size: usize) {
        let current = self.len();
        if let Some(allocated) = self.allocated.get()
            && allocated >= size
            && current < size + 16
        {
            return;
        }

        self.allocated.set(Some((size >> 4) + if current < 8 { 3 } else { 7 } + size));
    }
}

/// An iterator over an array.
struct ArrayIterator {
    array: Value,
    index: Cell<usize>,
}

impl_native_data!(ArrayIterator, "arrayiterator");

/// Whether `value` is an array.
pub(crate) fn is_array(value: &Value) -> bool {
    native_data::<ArrayData>(value).is_some()
}

/// The machine values of an array.
pub(crate) fn array_bytes(value: &Value) -> Option<Vec<u8>> {
    native_data::<ArrayData>(value).map(ArrayData::snapshot)
}

/// Runs `write` over the machine values of an array, as a write buffer.
pub(crate) fn write_array_bytes<R>(value: &Value, write: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    native_data::<ArrayData>(value).map(|data| write(&mut data.items.borrow_mut()))
}

/// Whether `class` is `array.array`, once the module is loaded.
pub(crate) fn is_array_type(vm: &Vm, class: &ObjectRef) -> bool {
    registered_type(vm, ARRAY_TYPE).is_some_and(|array| Rc::ptr_eq(&array, class))
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let class = array_type(vm)?;
    set_attribute(vm, module, "array", Value::Object(Rc::clone(&class)))?;
    set_attribute(vm, module, "ArrayType", Value::Object(class))?;

    Ok(())
}

fn array_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, ARRAY_TYPE, create_array_type)
}

fn create_array_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "array",
            module: "array",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", array_new),
                method("__len__", array_len),
                method("__getitem__", array_getitem),
                method("__setitem__", array_setitem),
                method("__delitem__", array_delitem),
                method("__getslice__", array_getslice),
                method("__setslice__", array_setslice),
                method("__delslice__", array_delslice),
                method("__contains__", array_contains),
                method("__iter__", array_iter),
                method("__add__", array_concat),
                method("__iadd__", array_inplace_concat),
                method("__mul__", |vm, args| array_repeat(vm, args, "__mul__")),
                method("__rmul__", |vm, args| array_repeat(vm, args, "__rmul__")),
                method("__imul__", array_inplace_repeat),
                method("__eq__", |vm, args| array_compare(vm, args, "__eq__", CompareOp::Equal)),
                method("__ne__", |vm, args| array_compare(vm, args, "__ne__", CompareOp::NotEqual)),
                method("__lt__", |vm, args| array_compare(vm, args, "__lt__", CompareOp::Less)),
                method("__le__", |vm, args| array_compare(vm, args, "__le__", CompareOp::LessEqual)),
                method("__gt__", |vm, args| array_compare(vm, args, "__gt__", CompareOp::Greater)),
                method("__ge__", |vm, args| array_compare(vm, args, "__ge__", CompareOp::GreaterEqual)),
                method("__repr__", array_repr),
                method("append", array_append),
                method("buffer_info", array_buffer_info),
                method("byteswap", array_byteswap),
                method("__copy__", array_copy),
                method("count", array_count),
                method("__deepcopy__", array_deepcopy),
                method("extend", array_extend),
                method("fromfile", |vm, args| array_fromfile(vm, args, "fromfile")),
                method("fromlist", array_fromlist),
                method("fromstring", array_fromstring),
                method("fromunicode", array_fromunicode),
                method("index", array_index),
                method("insert", array_insert),
                method("pop", array_pop),
                method("read", |vm, args| array_fromfile(vm, args, "read")),
                method("__reduce__", array_reduce),
                method("remove", array_remove),
                method("reverse", array_reverse),
                method("tofile", |vm, args| array_tofile(vm, args, "tofile")),
                method("tolist", array_tolist),
                method("tostring", array_tostring),
                method("tounicode", array_tounicode),
                method("write", |vm, args| array_tofile(vm, args, "write")),
                method("__sizeof__", array_sizeof),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "typecode", owner: ARRAY_TYPE, get: array_typecode, set: None })?;
    add_getset(vm, &class, GetSet { name: "itemsize", owner: ARRAY_TYPE, get: array_itemsize, set: None })?;
    crate::interp::builtins::arguments::set_class_attribute(vm, &class, "__hash__", Value::None)?;

    Ok(class)
}

fn create_iterator_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name: "arrayiterator",
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("__iter__", iterator_iter), method("next", iterator_next)],
        },
    )
}

/// The array receiver of a method and the arguments after it.
fn bind<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a ArrayData, CallArgs)> {
    let data = this::<ArrayData>(vm, args, ARRAY_TYPE, method)?;
    let mut rest = args.clone();
    rest.positional.remove(0);

    Ok((data, rest))
}

/// A new exact `array.array` (`newarrayobject(&Arraytype, ...)`).
fn new_array(vm: &Vm, typecode: Typecode, itemsize: usize, items: Vec<u8>) -> PyResult<Value> {
    let class = array_type(vm)?;

    Ok(new_instance(vm, &class, Payload::Native(Box::new(ArrayData::new(typecode, itemsize, items)))))
}

/// Raises unless a buffer of `items` items of `itemsize` bytes fits in
/// the client's memory.
fn check_items(vm: &Vm, items: usize, itemsize: usize) -> PyResult<()> {
    let Some(bytes) = items.checked_mul(itemsize) else {
        return Err(crate::interp::builtins::arguments::memory_error(vm));
    };

    check_size(vm, i64::try_from(bytes).unwrap_or(i64::MAX))
}

/// The TypeError for a bad argument to an internal operation.
fn bad_argument(vm: &Vm) -> Signal {
    vm.type_error("bad argument type for built-in operation")
}

/// Branching on an unknown value that would become array contents.
fn unknown_item(value: &Value) -> PyResult<()> {
    halt_on_unknown(value, "array item")
}

/// The little-endian bytes of a C integer of `size` bytes.
fn integer_bytes(value: i64, size: usize) -> Vec<u8> {
    value.to_le_bytes()[..size].to_vec()
}

/// The `l` conversion followed by a range check with `bounds` messages.
fn ranged(vm: &Vm, value: &Value, low: i64, high: i64, below: &str, above: &str) -> PyResult<i64> {
    let number = long_argument(vm, value)?;
    if number < low {
        return Err(vm.raise(ExceptionKind::OverflowError, below));
    }
    if number > high {
        return Err(vm.raise(ExceptionKind::OverflowError, above));
    }

    Ok(number)
}

/// The `h` format.
fn short_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    ranged(vm, value, i64::from(i16::MIN), i64::from(i16::MAX), "signed short integer is less than minimum", "signed short integer is greater than maximum")
}

/// The `i` format.
fn int_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    ranged(vm, value, i64::from(i32::MIN), i64::from(i32::MAX), "signed integer is less than minimum", "signed integer is greater than maximum")
}

/// Whether the value is a `long` or a subclass.
fn is_long(vm: &Vm, value: &Value) -> bool {
    matches!(value, Value::Long(_)) || value.as_object().is_some_and(|object| matches!(object.payload, Payload::Long(_))) && vm.as_integral(value).is_some()
}

/// The unsigned conversions of the `I` and `L` typecodes, with the C
/// `unsigned long` of the target and the item's own maximum.
fn unsigned_argument(vm: &Vm, value: &Value, maximum: u64, name: &str) -> PyResult<u64> {
    let unsigned_long_max = match vm.config.long_width {
        LongWidth::Bits32 => u64::from(u32::MAX),
        LongWidth::Bits64 => u64::MAX,
    };

    let number = if is_long(vm, value) {
        let Some(integral) = vm.as_integral(value) else {
            return Err(vm.type_error("an integer is required"));
        };
        let number = integral.to_bigint();
        if number.sign() == Sign::Minus {
            return Err(vm.raise(ExceptionKind::OverflowError, "can't convert negative value to unsigned long"));
        }
        match number.to_u64().filter(|number| *number <= unsigned_long_max) {
            Some(number) => number,
            None => return Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert")),
        }
    } else {
        let number = long_argument(vm, value)?;
        let Ok(number) = u64::try_from(number) else {
            return Err(vm.raise(ExceptionKind::OverflowError, &format!("unsigned {name} is less than minimum")));
        };
        number
    };
    if number > maximum {
        return Err(vm.raise(ExceptionKind::OverflowError, &format!("unsigned {name} is greater than maximum")));
    }

    Ok(number)
}

/// Float conversion for the `f` and `d` formats.
fn float_argument(vm: &Vm, value: &Value) -> PyResult<f64> {
    if let Some(number) = vm.as_float(value) {
        return Ok(number);
    }
    if let Some(integral) = vm.as_integral(value) {
        return numbers::bigint_to_f64(&integral.to_bigint()).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"));
    }
    let Some(method) = vm.user_override(value, "__float__")? else {
        return Err(vm.type_error("a float is required"));
    };
    let result = vm.call0(&method)?;
    unknown_item(&result)?;

    vm.as_float(&result).ok_or_else(|| vm.type_error("nb_float should return float object"))
}

/// The item store of `typecode`: `value` as the item's machine bytes.
fn encode_item(vm: &Vm, typecode: Typecode, itemsize: usize, value: &Value) -> PyResult<Vec<u8>> {
    unknown_item(value)?;

    let bytes = match typecode {
        Typecode::Char => {
            match vm.as_str_bytes(value).as_ref().map(PyBytes::as_bytes) {
                Some([byte]) => vec![*byte],
                _ => return Err(vm.type_error("array item must be char")),
            }
        }
        Typecode::Unicode => match vm.as_text(value).as_ref().map(PyText::units) {
            Some([unit]) => unit.to_le_bytes().to_vec(),
            _ => return Err(vm.type_error("array item must be unicode character")),
        },
        Typecode::SignedByte => {
            let number = short_argument(vm, value)?;
            if number < -128 {
                return Err(vm.raise(ExceptionKind::OverflowError, "signed char is less than minimum"));
            }
            if number > 127 {
                return Err(vm.raise(ExceptionKind::OverflowError, "signed char is greater than maximum"));
            }
            integer_bytes(number, 1)
        }
        Typecode::UnsignedByte => integer_bytes(ranged(vm, value, 0, 255, "unsigned byte integer is less than minimum", "unsigned byte integer is greater than maximum")?, 1),
        Typecode::Short => integer_bytes(short_argument(vm, value)?, 2),
        Typecode::UnsignedShort => {
            let number = int_argument(vm, value)?;
            if number < 0 {
                return Err(vm.raise(ExceptionKind::OverflowError, "unsigned short is less than minimum"));
            }
            if number > i64::from(u16::MAX) {
                return Err(vm.raise(ExceptionKind::OverflowError, "unsigned short is greater than maximum"));
            }
            integer_bytes(number, 2)
        }
        Typecode::Int => integer_bytes(int_argument(vm, value)?, 4),
        Typecode::UnsignedInt => (unsigned_argument(vm, value, u64::from(u32::MAX), "int")? as u32).to_le_bytes().to_vec(),
        Typecode::Long => integer_bytes(long_argument(vm, value)?, itemsize),
        Typecode::UnsignedLong => {
            let maximum = if itemsize == 4 { u64::from(u32::MAX) } else { u64::MAX };
            unsigned_argument(vm, value, maximum, "long")?.to_le_bytes()[..itemsize].to_vec()
        }
        Typecode::Float => (float_argument(vm, value)? as f32).to_le_bytes().to_vec(),
        Typecode::Double => float_argument(vm, value)?.to_le_bytes().to_vec(),
    };

    Ok(bytes)
}

/// The item load of `typecode` for one item's machine bytes.
fn decode_item(vm: &Vm, typecode: Typecode, bytes: &[u8]) -> Value {
    let signed = |bytes: &[u8]| {
        let mut buffer = [0; 8];
        buffer[..bytes.len()].copy_from_slice(bytes);
        let shift = 64 - 8 * bytes.len() as u32;
        (i64::from_le_bytes(buffer) << shift) >> shift
    };
    let unsigned = |bytes: &[u8]| {
        let mut buffer = [0; 8];
        buffer[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(buffer)
    };

    match typecode {
        Typecode::Char => Value::Str(PyBytes::new(bytes.to_vec())),
        Typecode::Unicode => Value::Unicode(PyText::new(vec![unsigned(bytes) as u16])),
        Typecode::SignedByte | Typecode::Short | Typecode::Int | Typecode::Long => vm.new_int_from_i64(signed(bytes)),
        Typecode::UnsignedByte | Typecode::UnsignedShort => Value::Int(unsigned(bytes) as i64),
        Typecode::UnsignedInt | Typecode::UnsignedLong => Value::long(BigInt::from(unsigned(bytes))),
        Typecode::Float => Value::Float(f64::from(f32::from_bits(unsigned(bytes) as u32))),
        Typecode::Double => Value::Float(f64::from_bits(unsigned(bytes))),
    }
}

/// The item at `index`, if in range.
fn item(vm: &Vm, data: &ArrayData, index: usize) -> Option<Value> {
    let items = data.items.borrow();
    let bytes = items.get(index * data.itemsize..(index + 1) * data.itemsize)?;

    Some(decode_item(vm, data.typecode, bytes))
}

/// The items of an array as values.
fn values(vm: &Vm, data: &ArrayData) -> Vec<Value> {
    let items = data.snapshot();

    items.chunks(data.itemsize).map(|bytes| decode_item(vm, data.typecode, bytes)).collect()
}

/// `array.__new__`.
fn array_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = array_type(vm)?;
    let (class, rest) = new_class(vm, args, &base)?;
    if Rc::ptr_eq(&class, &base) && rest.has_keywords() {
        return Err(vm.type_error("array.array() does not take keyword arguments"));
    }
    let arguments = args::varargs(vm, CallArgs::new(rest.positional), "array", 1, 2)?;
    if let Some(unknown) = args::first_unknown(&arguments) {
        return Ok(unknown);
    }

    let typecode = &arguments[0];
    let code = match (vm.as_str_bytes(typecode), vm.as_text(typecode)) {
        (Some(bytes), _) if bytes.as_bytes().len() == 1 => u32::from(bytes.as_bytes()[0]),
        (_, Some(text)) if text.units().len() == 1 => u32::from(text.units()[0]),
        _ => {
            return Err(vm.type_error(&format!("array() argument 1 or typecode must be char (string or ascii-unicode with length 1), not {}", vm.type_name(typecode))));
        }
    };
    let initial = arguments.get(1);

    let iterate = initial.filter(|initial| {
        let listed = vm.as_list(initial).is_some() || vm.as_str_bytes(initial).is_some() || vm.as_tuple(initial).is_some();
        let unicode = code == u32::from(b'u') && vm.as_text(initial).is_some();
        !listed && !unicode
    });
    let iterator = iterate.map(|initial| vm.iter(initial)).transpose()?;

    let Some(typecode) = Typecode::parse(code) else {
        return Err(vm.raise(ExceptionKind::ValueError, "bad typecode (must be c, b, B, u, h, H, i, I, l, L, f or d)"));
    };
    let itemsize = typecode.itemsize(vm.config.long_width);

    let mut items = Vec::new();
    if iterator.is_none()
        && let Some(initial) = initial
    {
        let sequence = vm.as_list(initial).or_else(|| vm.as_tuple(initial).map(|items| items.to_vec()));
        if let Some(sequence) = sequence {
            check_items(vm, sequence.len(), itemsize)?;
            for value in &sequence {
                items.extend(encode_item(vm, typecode, itemsize, value)?);
            }
        } else if let Some(bytes) = vm.as_str_bytes(initial) {
            if bytes.as_bytes().len() % itemsize != 0 {
                return Err(vm.raise(ExceptionKind::ValueError, "string length not a multiple of item size"));
            }
            items = bytes.as_bytes().to_vec();
        } else if let Some(text) = vm.as_text(initial) {
            items = text.units().iter().flat_map(|unit| unit.to_le_bytes()).collect();
        }
    }

    let data = ArrayData::new(typecode, itemsize, items);
    let array = new_instance(vm, &class, Payload::Native(Box::new(data)));

    if let Some(iterator) = iterator {
        let Some(data) = native_data::<ArrayData>(&array) else {
            return Err(vm.type_error("array construction failed"));
        };
        extend_from_iterator(vm, data, &iterator)?;
    }

    Ok(array)
}

/// Validates, then inserts an item at `position`.
fn insert_item(vm: &Vm, data: &ArrayData, position: i64, value: &Value) -> PyResult<()> {
    let length = data.len();
    encode_item(vm, data.typecode, data.itemsize, value)?;

    check_items(vm, length + 1, data.itemsize)?;
    data.reserve(length + 1);
    let signed = length as i64;
    let position = if position < 0 { (position + signed).max(0) } else { position.min(signed) } as usize;
    {
        let mut items = data.items.borrow_mut();
        let at = (position * data.itemsize).min(items.len());
        items.splice(at..at, vec![0; data.itemsize]);
    }

    // The slot exists while the value converts again, as in CPython.
    let bytes = encode_item(vm, data.typecode, data.itemsize, value)?;
    if let Some(slot) = data.items.borrow_mut().get_mut(position * data.itemsize..(position + 1) * data.itemsize) {
        slot.copy_from_slice(&bytes);
    }

    Ok(())
}

/// `array.extend` with an arbitrary iterable.
fn extend_from_iterator(vm: &Vm, data: &ArrayData, iterable: &Value) -> PyResult<()> {
    let iterator = vm.iter(iterable)?;
    while let Some(value) = vm.next(&iterator)? {
        insert_item(vm, data, data.len() as i64, &value)?;
    }

    Ok(())
}

fn array_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Int(data.len() as i64))
}

/// An index converted through `__index__`, with overflow reported as
/// IndexError; `None` when `index` is not an integer.
pub(crate) fn index_operand(vm: &Vm, index: &Value) -> PyResult<Option<i64>> {
    if !vm.is_index(index)? {
        return Ok(None);
    }

    vm.index_as_ssize(index, Some(ExceptionKind::IndexError)).map(Some)
}

/// `array.__getitem__`.
fn array_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;
    if index.is_unknown() {
        return Ok(index);
    }

    if let Some(position) = index_operand(vm, &index)? {
        let length = data.len() as i64;
        let position = if position < 0 { position + length } else { position };
        let item = usize::try_from(position).ok().filter(|position| (*position as i64) < length).and_then(|position| item(vm, data, position));
        return item.ok_or_else(|| vm.raise(ExceptionKind::IndexError, "array index out of range"));
    }

    let Some(slice) = vm.slice_of(&index) else {
        return Err(vm.type_error("array indices must be integers"));
    };
    // Converting the bounds may run Python code; they adjust to the length
    // after it ran.
    let bounds = vm.unpack_slice(&slice)?;
    let items = data.snapshot();
    let indices = bounds.adjust((items.len() / data.itemsize) as i64);
    let selected = indices.positions().flat_map(|position| items[position * data.itemsize..(position + 1) * data.itemsize].to_vec()).collect();

    new_array(vm, data.typecode, data.itemsize, selected)
}

fn array_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__setitem__")?;
    let (index, value) = wrapper_pair(vm, rest)?;
    assign(vm, data, &index, Some(value))?;

    Ok(Value::None)
}

fn array_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__delitem__")?;
    let index = wrapper_operand(vm, rest)?;
    assign(vm, data, &index, None)?;

    Ok(Value::None)
}

/// The other array of a slice assignment: same kind as `data`.
fn other_array<'a>(vm: &Vm, data: &ArrayData, value: &'a Value) -> PyResult<&'a ArrayData> {
    let Some(other) = native_data::<ArrayData>(value) else {
        return Err(vm.type_error(&format!("can only assign array (not \"{}\") to array slice", vm.type_name(value))));
    };
    if other.typecode != data.typecode {
        return Err(bad_argument(vm));
    }

    Ok(other)
}

/// `array.__setitem__`; `None` deletes.
fn assign(vm: &Vm, data: &ArrayData, index: &Value, value: Option<Value>) -> PyResult<()> {
    halt_on_unknown(index, "array index")?;
    if let Some(value) = &value {
        unknown_item(value)?;
    }

    let position = index_operand(vm, index)?;
    let length = data.len();
    let indices = if let Some(position) = position {
        let signed = length as i64;
        let position = if position < 0 { position + signed } else { position };
        if position < 0 || position >= signed {
            return Err(vm.raise(ExceptionKind::IndexError, "array assignment index out of range"));
        }
        if let Some(value) = &value {
            let bytes = encode_item(vm, data.typecode, data.itemsize, value)?;
            let at = position as usize * data.itemsize;
            if let Some(slot) = data.items.borrow_mut().get_mut(at..at + data.itemsize) {
                slot.copy_from_slice(&bytes);
            }
            return Ok(());
        }
        SliceIndices { start: position, stop: position + 1, step: 1 }
    } else if let Some(slice) = vm.slice_of(index) {
        let bounds = vm.unpack_slice(&slice)?;
        bounds.adjust(data.len() as i64)
    } else {
        return Err(vm.type_error("array indices must be integer"));
    };

    let needed = match &value {
        None => Vec::new(),
        Some(value) => other_array(vm, data, value)?.snapshot(),
    };
    let count = needed.len() / data.itemsize;
    let positions: Vec<usize> = indices.positions().collect();
    let itemsize = data.itemsize;
    let length = data.len();
    if positions.iter().any(|position| *position >= length) {
        return Err(vm.halt_unsupported("array resized by Python code while its slice assignment converted arguments"));
    }

    if indices.step == 1 {
        let start = usize::try_from(indices.start).unwrap_or(0).min(length);
        let removed = positions.len();
        if removed != count {
            check_items(vm, length - removed + count, itemsize)?;
            data.reserve(length - removed + count);
        }
        data.items.borrow_mut().splice(start * itemsize..(start + removed) * itemsize, needed);
        return Ok(());
    }

    if count == 0 {
        data.reserve(length - positions.len());
        let mut keep = vec![true; length];
        for position in &positions {
            keep[*position] = false;
        }
        let items = data.snapshot();
        let kept = items.chunks(itemsize).zip(keep).filter(|(_, keep)| *keep).flat_map(|(bytes, _)| bytes.to_vec()).collect();
        *data.items.borrow_mut() = kept;
        return Ok(());
    }

    if count != positions.len() {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("attempt to assign array of size {count} to extended slice of size {}", positions.len())));
    }
    let mut items = data.items.borrow_mut();
    for (position, bytes) in positions.into_iter().zip(needed.chunks(itemsize)) {
        items[position * itemsize..(position + 1) * itemsize].copy_from_slice(bytes);
    }

    Ok(())
}

/// The clamped bounds of a slice read or assignment.
fn clamp_bounds(length: usize, low: i64, high: i64) -> (usize, usize) {
    let length = length as i64;
    let low = low.clamp(0, length);
    let high = high.max(0).max(low).min(length);

    (low as usize, high as usize)
}

/// `array.__getslice__`.
fn slice_array(vm: &Vm, data: &ArrayData, low: i64, high: i64) -> PyResult<Value> {
    let (low, high) = clamp_bounds(data.len(), low, high);
    let items = data.items.borrow()[low * data.itemsize..high * data.itemsize].to_vec();

    new_array(vm, data.typecode, data.itemsize, items)
}

/// `array.__setslice__`: replaces items `low..high` with the items of another
/// array of the same kind; `None` deletes them.
fn assign_slice(vm: &Vm, data: &ArrayData, low: i64, high: i64, value: Option<&Value>) -> PyResult<()> {
    let needed = match value {
        None => Vec::new(),
        Some(value) => match native_data::<ArrayData>(value) {
            Some(other) if other.typecode == data.typecode => other.snapshot(),
            Some(_) => return Err(bad_argument(vm)),
            None => return Err(vm.type_error(&format!("can only assign array (not \"{}\") to array slice", vm.type_name(value)))),
        },
    };

    let length = data.len();
    let (low, high) = clamp_bounds(length, low, high);
    let count = needed.len() / data.itemsize;
    if count != high - low {
        check_items(vm, length - (high - low) + count, data.itemsize)?;
    }
    data.items.borrow_mut().splice(low * data.itemsize..high * data.itemsize, needed);
    if count != high - low {
        data.fit_allocation();
    }

    Ok(())
}

fn array_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__getslice__")?;
    let bounds = positional(vm, rest, "__getslice__", 2, 2)?;

    slice_array(vm, data, ssize_argument(vm, &bounds[0])?, ssize_argument(vm, &bounds[1])?)
}

fn array_setslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__setslice__")?;
    let arguments = positional(vm, rest, "__setslice__", 3, 3)?;
    unknown_item(&arguments[2])?;
    assign_slice(vm, data, ssize_argument(vm, &arguments[0])?, ssize_argument(vm, &arguments[1])?, Some(&arguments[2]))?;

    Ok(Value::None)
}

fn array_delslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__delslice__")?;
    let bounds = positional(vm, rest, "__delslice__", 2, 2)?;
    assign_slice(vm, data, ssize_argument(vm, &bounds[0])?, ssize_argument(vm, &bounds[1])?, None)?;

    Ok(Value::None)
}

/// The position of the first item equal to `value`, comparing each item
/// read afresh because comparisons may mutate the array.
fn find(vm: &Vm, data: &ArrayData, value: &Value) -> PyResult<Option<usize>> {
    let mut position = 0;
    while let Some(candidate) = item(vm, data, position) {
        if vm.equals(&candidate, value)? {
            return Ok(Some(position));
        }
        position += 1;
    }

    Ok(None)
}

fn array_contains(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__contains__")?;
    let value = wrapper_operand(vm, rest)?;
    if value.is_unknown() {
        return Ok(value);
    }

    Ok(Value::Bool(find(vm, data, &value)?.is_some()))
}

fn array_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = bind(vm, &args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;
    let class = native_type(vm, ITERATOR_TYPE, create_iterator_type)?;

    Ok(new_instance(vm, &class, Payload::Native(Box::new(ArrayIterator { array: args.positional[0].clone(), index: Cell::new(0) }))))
}

fn iterator_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<ArrayIterator>(vm, &args, ITERATOR_TYPE, "__iter__")?;
    wrapper_arguments(vm, CallArgs::new(args.positional[1..].to_vec()), 0)?;

    Ok(args.positional[0].clone())
}

fn iterator_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let iterator = this::<ArrayIterator>(vm, &args, ITERATOR_TYPE, "next")?;
    wrapper_arguments(vm, CallArgs::new(args.positional[1..].to_vec()), 0)?;
    let Some(data) = native_data::<ArrayData>(&iterator.array) else {
        return Err(vm.type_error("arrayiterator over a non-array"));
    };

    let index = iterator.index.get();
    let Some(value) = item(vm, data, index) else {
        return Err(crate::interp::builtins::arguments::stop_iteration(vm));
    };
    iterator.index.set(index + 1);

    Ok(value)
}

/// `array.__add__`.
fn array_concat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__add__")?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }

    let Some(other) = native_data::<ArrayData>(&other) else {
        return Err(vm.type_error(&format!("can only append array (not \"{}\") to array", vm.type_name(&other))));
    };
    if other.typecode != data.typecode {
        return Err(bad_argument(vm));
    }
    let mut items = data.snapshot();
    items.extend(other.snapshot());
    check_items(vm, items.len() / data.itemsize, data.itemsize)?;

    new_array(vm, data.typecode, data.itemsize, items)
}

/// `array.extend` with another array.
fn extend_array(vm: &Vm, data: &ArrayData, other: &ArrayData) -> PyResult<()> {
    if other.typecode != data.typecode {
        return Err(vm.type_error("can only extend with array of same kind"));
    }
    let extra = other.snapshot();
    check_items(vm, data.len() + extra.len() / data.itemsize, data.itemsize)?;
    data.items.borrow_mut().extend(extra);
    data.fit_allocation();

    Ok(())
}

/// `array.__iadd__`.
fn array_inplace_concat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__iadd__")?;
    let other = wrapper_operand(vm, rest)?;
    unknown_item(&other)?;

    let Some(other) = native_data::<ArrayData>(&other) else {
        return Err(vm.type_error(&format!("can only extend array with array (not \"{}\")", vm.type_name(&other))));
    };
    extend_array(vm, data, other)?;

    Ok(args.positional[0].clone())
}

/// Array repetition, whose count converts through `__index__`.
fn array_repeat(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, name)?;
    let count = wrapper_operand(vm, rest)?;
    if count.is_unknown() {
        return Ok(count);
    }

    let count = usize::try_from(index_value(vm, &count)?).unwrap_or(0);
    let items = data.snapshot();
    check_items(vm, data.len().checked_mul(count).unwrap_or(usize::MAX), data.itemsize)?;

    new_array(vm, data.typecode, data.itemsize, items.repeat(count))
}

/// `array.__imul__`.
fn array_inplace_repeat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__imul__")?;
    let count = wrapper_operand(vm, rest)?;
    halt_on_unknown(&count, "array *= count")?;

    let count = usize::try_from(index_value(vm, &count)?).unwrap_or(0);
    let length = data.len();
    if length > 0 {
        if count == 0 {
            data.items.borrow_mut().clear();
            data.allocated.set(None);
        } else {
            check_items(vm, length.checked_mul(count).unwrap_or(usize::MAX), data.itemsize)?;
            let repeated = data.snapshot().repeat(count);
            *data.items.borrow_mut() = repeated;
            data.fit_allocation();
        }
    }

    Ok(args.positional[0].clone())
}

/// Array comparison: item by item, then by length.
fn array_compare(vm: &Vm, args: CallArgs, name: &str, operation: CompareOp) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, name)?;
    let other = wrapper_operand(vm, rest)?;
    if other.is_unknown() {
        return Ok(other);
    }
    let Some(other) = native_data::<ArrayData>(&other) else {
        return Ok(Value::NotImplemented);
    };

    let (length, other_length) = (data.len(), other.len());
    if length != other_length && matches!(operation, CompareOp::Equal | CompareOp::NotEqual) {
        return Ok(Value::Bool(operation == CompareOp::NotEqual));
    }

    let mut position = 0;
    while position < data.len() && position < other.len() {
        let (Some(left), Some(right)) = (item(vm, data, position), item(vm, other, position)) else {
            break;
        };
        if !vm.equals(&left, &right)? {
            return match operation {
                CompareOp::Equal => Ok(Value::Bool(false)),
                CompareOp::NotEqual => Ok(Value::Bool(true)),
                _ => vm.compare(&left, &right, operation),
            };
        }
        position += 1;
    }

    Ok(Value::Bool(operation.holds(data.len().cmp(&other.len()))))
}

/// `array.__repr__`.
fn array_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    let code = char::from(data.typecode.code());
    if data.len() == 0 {
        return Ok(Value::str(&format!("array('{code}')")));
    }
    let contents = match data.typecode {
        Typecode::Char => Value::Str(PyBytes::new(data.snapshot())),
        Typecode::Unicode => Value::Unicode(PyText::new(units(data))),
        _ => vm.new_list(values(vm, data)),
    };

    Ok(Value::str(&format!("array('{code}', {})", vm.repr_text(&contents)?)))
}

/// The UTF-16 units of a `u` array.
fn units(data: &ArrayData) -> Vec<u16> {
    data.snapshot().chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)])).collect()
}

fn array_append(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "append")?;
    let value = one_argument(vm, rest, "append")?;
    insert_item(vm, data, data.len() as i64, &value)?;

    Ok(Value::None)
}

/// `array.buffer_info`: the address is the host's, so it is unknown.
fn array_buffer_info(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "buffer_info")?;
    no_arguments(vm, rest, "buffer_info")?;

    Ok(Value::tuple(vec![Value::unknown("array buffer address"), Value::Int(data.len() as i64)]))
}

fn array_byteswap(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "byteswap")?;
    no_arguments(vm, rest, "byteswap")?;

    for item in data.items.borrow_mut().chunks_mut(data.itemsize) {
        item.reverse();
    }

    Ok(Value::None)
}

fn array_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__copy__")?;
    no_arguments(vm, rest, "__copy__")?;

    slice_array(vm, data, 0, data.len() as i64)
}

fn array_deepcopy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__deepcopy__")?;
    one_argument(vm, rest, "__deepcopy__")?;

    slice_array(vm, data, 0, data.len() as i64)
}

fn array_count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "count")?;
    let value = one_argument(vm, rest, "count")?;
    if value.is_unknown() {
        return Ok(value);
    }

    let mut count = 0;
    let mut position = 0;
    while let Some(candidate) = item(vm, data, position) {
        if vm.equals(&candidate, &value)? {
            count += 1;
        }
        position += 1;
    }

    Ok(Value::Int(count))
}

/// `array.extend`.
fn array_extend(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "extend")?;
    let other = one_argument(vm, rest, "extend")?;
    halt_on_unknown(&other, "array.extend argument")?;

    match native_data::<ArrayData>(&other) {
        Some(other) => extend_array(vm, data, other)?,
        None => extend_from_iterator(vm, data, &other)?,
    }

    Ok(Value::None)
}

/// `array.fromfile` and `read`. A host file's contents are unknown, so
/// reading one halts; other objects are not open files.
fn array_fromfile(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (_, rest) = bind(vm, &args, name)?;
    let arguments = args::varargs(vm, rest, "fromfile", 2, 2)?;
    ssize_argument(vm, &arguments[1])?;

    if let Value::Unknown(unknown) = &arguments[0] {
        return Err(Signal::Halt(Halt::UnknownCondition { context: "array.fromfile of a host file".to_owned(), origin: unknown.origin.clone() }));
    }

    Err(vm.type_error("arg1 must be open file"))
}

/// `array.tofile` and `write`: writing to a host file has no visible
/// result here.
fn array_tofile(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (_, rest) = bind(vm, &args, name)?;
    let file = one_argument(vm, rest, name)?;
    if file.is_unknown() {
        return Ok(Value::unknown(format!("array.{name} to a host file")));
    }

    Err(vm.type_error("arg must be open file"))
}

/// `array.fromlist`: all or nothing.
fn array_fromlist(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "fromlist")?;
    let list = one_argument(vm, rest, "fromlist")?;
    let Some(values) = vm.as_list(&list) else {
        if list.is_unknown() {
            return Err(Signal::Halt(Halt::UnknownCondition { context: "array.fromlist argument".to_owned(), origin: format!("{list:?}") }));
        }
        return Err(vm.type_error("arg must be list"));
    };
    if values.is_empty() {
        return Ok(Value::None);
    }

    // CPython grows the array first and converts into the new slots.
    let start = data.len();
    check_items(vm, start + values.len(), data.itemsize)?;
    data.items.borrow_mut().resize((start + values.len()) * data.itemsize, 0);
    data.fit_allocation();

    for (offset, value) in values.iter().enumerate() {
        let converted = encode_item(vm, data.typecode, data.itemsize, value);
        let changed = vm.as_list(&list).is_some_and(|current| current.len() != values.len());
        let failure = match converted {
            Err(signal) => Some(signal),
            Ok(_) if changed => Some(vm.raise(ExceptionKind::RuntimeError, "list changed size during iteration")),
            Ok(bytes) => {
                let at = (start + offset) * data.itemsize;
                if let Some(slot) = data.items.borrow_mut().get_mut(at..at + data.itemsize) {
                    slot.copy_from_slice(&bytes);
                }
                None
            }
        };
        if let Some(signal) = failure {
            let length = data.len().saturating_sub(values.len());
            data.items.borrow_mut().truncate(length * data.itemsize);
            data.fit_allocation();
            return Err(signal);
        }
    }

    Ok(Value::None)
}

/// `array.fromstring`.
fn array_fromstring(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "fromstring")?;
    let arguments = args::varargs(vm, rest, "fromstring", 1, 1)?;
    halt_on_unknown(&arguments[0], "array.fromstring argument")?;
    let bytes = args::read_buffer(vm, "fromstring", 1, &arguments[0])?;

    let receiver = &args.positional[0];
    let is_self = matches!((receiver, &arguments[0]), (Value::Object(left), Value::Object(right)) if Rc::ptr_eq(left, right));
    if is_self && data.len() > 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "array.fromstring(x): x cannot be self"));
    }
    if bytes.as_bytes().len() % data.itemsize != 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "string length not a multiple of item size"));
    }
    if !bytes.as_bytes().is_empty() {
        check_items(vm, data.len() + bytes.as_bytes().len() / data.itemsize, data.itemsize)?;
        data.items.borrow_mut().extend_from_slice(bytes.as_bytes());
        data.fit_allocation();
    }

    Ok(Value::None)
}

/// `array.fromunicode`.
fn array_fromunicode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "fromunicode")?;
    let arguments = args::varargs(vm, rest, "fromunicode", 1, 1)?;
    halt_on_unknown(&arguments[0], "array.fromunicode argument")?;
    let Some(text) = vm.as_text(&arguments[0]) else {
        return Err(vm.type_error(&format!("fromunicode() argument 1 must be cannot convert raw buffers, not {}", vm.type_name(&arguments[0]))));
    };
    if data.typecode != Typecode::Unicode {
        return Err(vm.raise(ExceptionKind::ValueError, "fromunicode() may only be called on type 'u' arrays"));
    }
    if !text.units().is_empty() {
        check_items(vm, data.len() + text.units().len(), data.itemsize)?;
        data.items.borrow_mut().extend(text.units().iter().flat_map(|unit| unit.to_le_bytes()));
        data.fit_allocation();
    }

    Ok(Value::None)
}

fn array_index(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "index")?;
    let value = one_argument(vm, rest, "index")?;
    if value.is_unknown() {
        return Ok(value);
    }

    match find(vm, data, &value)? {
        Some(position) => Ok(Value::Int(position as i64)),
        None => Err(vm.raise(ExceptionKind::ValueError, "array.index(x): x not in list")),
    }
}

fn array_insert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "insert")?;
    let arguments = positional(vm, rest, "insert", 2, 2)?;
    let position = ssize_argument(vm, &arguments[0])?;
    insert_item(vm, data, position, &arguments[1])?;

    Ok(Value::None)
}

fn array_pop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "pop")?;
    let arguments = positional(vm, rest, "pop", 0, 1)?;
    let requested = match arguments.first() {
        Some(index) => ssize_argument(vm, index)?,
        None => -1,
    };

    let length = data.len() as i64;
    if length == 0 {
        return Err(vm.raise(ExceptionKind::IndexError, "pop from empty array"));
    }
    let position = if requested < 0 { requested + length } else { requested };
    let Some(value) = usize::try_from(position).ok().filter(|position| (*position as i64) < length).and_then(|position| item(vm, data, position)) else {
        return Err(vm.raise(ExceptionKind::IndexError, "pop index out of range"));
    };
    assign_slice(vm, data, position, position + 1, None)?;

    Ok(value)
}

/// `array.__reduce__`: `(type, (typecode, items), __dict__)`.
fn array_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__reduce__")?;
    no_arguments(vm, rest, "__reduce__")?;

    let receiver = &args.positional[0];
    let dict = receiver.as_object().and_then(|object| object.dict()).map_or(Value::None, Value::Object);
    let typecode = Value::Str(PyBytes::new(vec![data.typecode.code()]));

    Ok(Value::tuple(vec![Value::Object(vm.class_of(receiver)), Value::tuple(vec![typecode, vm.new_list(values(vm, data))]), dict]))
}

fn array_remove(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "remove")?;
    let value = one_argument(vm, rest, "remove")?;
    halt_on_unknown(&value, "array.remove argument")?;

    let Some(position) = find(vm, data, &value)? else {
        return Err(vm.raise(ExceptionKind::ValueError, "array.remove(x): x not in list"));
    };
    assign_slice(vm, data, position as i64, position as i64 + 1, None)?;

    Ok(Value::None)
}

fn array_reverse(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "reverse")?;
    no_arguments(vm, rest, "reverse")?;

    let reversed = data.snapshot().chunks(data.itemsize).rev().flat_map(|item| item.to_vec()).collect();
    *data.items.borrow_mut() = reversed;

    Ok(Value::None)
}

fn array_tolist(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "tolist")?;
    no_arguments(vm, rest, "tolist")?;

    Ok(vm.new_list(values(vm, data)))
}

fn array_tostring(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "tostring")?;
    no_arguments(vm, rest, "tostring")?;

    Ok(Value::Str(PyBytes::new(data.snapshot())))
}

fn array_tounicode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "tounicode")?;
    no_arguments(vm, rest, "tounicode")?;
    if data.typecode != Typecode::Unicode {
        return Err(vm.raise(ExceptionKind::ValueError, "tounicode() may only be called on type 'u' arrays"));
    }

    Ok(Value::Unicode(PyText::new(units(data))))
}

/// `array.__sizeof__`: the object of the 64-bit build, a dict pointer for
/// subclasses with instance dicts, and the allocation.
fn array_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const OBJECT_SIZE: usize = 56;
    const POINTER_SIZE: usize = 8;

    let (data, rest) = bind(vm, &args, "__sizeof__")?;
    no_arguments(vm, rest, "__sizeof__")?;
    let has_dict = args.positional[0].as_object().is_some_and(|object| object.dict().is_some());
    let header = if has_dict { OBJECT_SIZE + POINTER_SIZE } else { OBJECT_SIZE };
    let size = header + data.allocated.get().unwrap_or(0) * data.itemsize;

    Ok(Value::long(BigInt::from(size)))
}

/// The array a getset descriptor reads.
fn getset_array<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a ArrayData> {
    native_data::<ArrayData>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{ARRAY_TYPE}' objects doesn't apply to '{}' object", getset.name, vm.type_name(instance))))
}

fn array_typecode(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let data = getset_array(vm, getset, instance)?;

    Ok(Value::Str(PyBytes::new(vec![data.typecode.code()])))
}

fn array_itemsize(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let data = getset_array(vm, getset, instance)?;

    Ok(Value::Int(data.itemsize as i64))
}
