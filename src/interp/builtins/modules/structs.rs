//! The `_struct` module: packing Python values into C struct layouts and
//! unpacking them again. Native layouts follow the data model
//! `vm.config.long_width` selects (a 32-bit `long` on Windows, 64-bit
//! elsewhere) on a little-endian host.

use std::cell::RefCell;
use std::ops::RangeInclusive;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::memory_error;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::binascii::argument_type_name;
use crate::interp::builtins::modules::binascii::buffer_argument;
use crate::interp::builtins::modules::binascii::raise_class;
use crate::interp::builtins::modules::binascii::ssize_argument;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::math::classic_int;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::warnings::warn_caller;
use crate::interp::builtins::parse;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::builtins::text::codecs::encode_default;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout as ObjectLayout;
use crate::interp::object::MroEntry;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const TYPE_NAME: &str = "Struct";
const TYPE_KEY: &str = "_struct.Struct";

/// `struct.error` and the formats the module-level functions compiled.
#[derive(Default)]
struct ModuleState {
    error: RefCell<Option<ObjectRef>>,
    /// `Struct` objects keyed by the format object the caller passed. A
    /// Python dict, so keys compare with Python equality.
    cache: RefCell<Option<ObjectRef>>,
}

/// Byte order, sizes, and alignment a format's first character selects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `@` or no prefix: native sizes and alignment.
    Native,
    /// `<` and `=`: standard sizes, least significant byte first.
    Little,
    /// `>` and `!`: standard sizes, most significant byte first.
    Big,
}

impl Mode {
    fn is_big_endian(self) -> bool {
        self == Self::Big
    }
}

/// The C integer type a value converts to before it is range checked.
#[derive(Clone, Copy)]
enum Carrier {
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
}

impl Carrier {
    /// The values the carrier type holds.
    fn bounds(self, width: LongWidth) -> RangeInclusive<i128> {
        match (self, width) {
            (Self::Long, LongWidth::Bits32) => i128::from(i32::MIN)..=i128::from(i32::MAX),
            (Self::UnsignedLong, LongWidth::Bits32) => 0..=i128::from(u32::MAX),
            (Self::Long, LongWidth::Bits64) | (Self::LongLong, _) => i128::from(i64::MIN)..=i128::from(i64::MAX),
            (Self::UnsignedLong, LongWidth::Bits64) | (Self::UnsignedLongLong, _) => 0..=i128::from(u64::MAX),
        }
    }
}

/// How a range violation narrower than the carrier is reported.
#[derive(Clone, Copy)]
enum LimitText {
    Fixed(&'static str),
    /// `'<code>' format requires <min> <= number <= <max>`.
    Bounds,
}

/// A range check narrower than the carrier type.
#[derive(Clone, Copy)]
struct Limit {
    min: i128,
    max: i128,
    text: LimitText,
}

/// Packing rules of one integer format code.
#[derive(Clone, Copy)]
struct IntegerRule {
    code: u8,
    signed: bool,
    carrier: Carrier,
    limit: Option<Limit>,
    /// The big-endian 64-bit codes store the low 64 bits of a value that is
    /// out of range (unsigned: only a non-negative one) before raising.
    stores_overflow: bool,
}

#[derive(Clone, Copy)]
enum Kind {
    Pad,
    Char,
    /// `s`: a field of the repeat count's bytes.
    Bytes,
    /// `p`: a length byte followed by the string.
    Pascal,
    Bool,
    Integer(IntegerRule),
    Pointer,
    Single,
    Double,
}

impl Kind {
    fn is_string(self) -> bool {
        matches!(self, Self::Bytes | Self::Pascal)
    }
}

/// A format code's representation in one mode.
struct CodeSpec {
    kind: Kind,
    size: u64,
    align: u64,
}

/// A run of `repeat` items of one code, the first at `offset`. Strings are
/// a single item of `size` bytes.
#[derive(Clone, Copy)]
struct Field {
    kind: Kind,
    offset: usize,
    repeat: usize,
    size: usize,
}

/// A compiled format.
struct Layout {
    mode: Mode,
    fields: Vec<Field>,
    size: usize,
    /// Values `pack` takes and `unpack` returns.
    values: usize,
    /// The units `__sizeof__` counts: one per string field and one per item
    /// of other codes.
    size_units: u64,
}

/// The layout of a `Struct`.
enum Compiled {
    /// `__init__` has not run.
    Missing,
    /// The format is an unknown value.
    Unknown,
    Ready(Rc<Layout>),
}

struct StructData {
    format: RefCell<Value>,
    compiled: RefCell<Compiled>,
}

impl_native_data!(StructData, "Struct");

impl StructData {
    fn new() -> Self {
        Self { format: RefCell::new(Value::None), compiled: RefCell::new(Compiled::Missing) }
    }

    fn layout(&self) -> Option<Rc<Layout>> {
        match &*self.compiled.borrow() {
            Compiled::Ready(layout) => Some(Rc::clone(layout)),
            Compiled::Missing | Compiled::Unknown => None,
        }
    }

    fn is_unknown(&self) -> bool {
        matches!(*self.compiled.borrow(), Compiled::Unknown)
    }
}

/// How a `Struct` method sees its receiver's layout.
enum Receiver {
    Ready(Rc<Layout>),
    Missing,
    Unknown,
}

impl Receiver {
    fn of(data: &StructData) -> Self {
        match &*data.compiled.borrow() {
            Compiled::Ready(layout) => Self::Ready(Rc::clone(layout)),
            Compiled::Missing => Self::Missing,
            Compiled::Unknown => Self::Unknown,
        }
    }
}

/// The value count and size an uninitialized `Struct` reports.
const MISSING_COUNT: i64 = -1;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("_clearcache", clear_cache),
            function("calcsize", calcsize),
            function("pack", pack),
            function("pack_into", pack_into),
            function("unpack", unpack),
            function("unpack_from", unpack_from),
        ],
    )?;

    let state = vm.native_state::<ModuleState>();
    let existing = state.error.borrow().clone();
    let error = match existing {
        Some(error) => error,
        None => {
            let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
            let error = new_exception_class(vm, "struct", "error", &base)?;
            *state.error.borrow_mut() = Some(Rc::clone(&error));
            error
        }
    };
    set_attribute(vm, module, "error", Value::Object(error))?;

    let class = native_type(vm, TYPE_KEY, create_struct_type)?;
    set_attribute(vm, module, "Struct", Value::Object(class))?;
    set_attribute(vm, module, "__version__", Value::str("0.2"))?;
    set_attribute(vm, module, "_PY_STRUCT_RANGE_CHECKING", Value::Int(1))?;
    set_attribute(vm, module, "_PY_STRUCT_FLOAT_COERCE", Value::Int(1))?;

    Ok(())
}

fn create_struct_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: TYPE_NAME,
            module: "__builtin__",
            base: None,
            layout: ObjectLayout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", struct_new),
                method("__init__", struct_init),
                method("pack", struct_pack),
                method("pack_into", struct_pack_into),
                method("unpack", struct_unpack),
                method("unpack_from", struct_unpack_from),
                method("__sizeof__", struct_sizeof),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "format", owner: TYPE_NAME, get: struct_format, set: None })?;
    add_getset(vm, &class, GetSet { name: "size", owner: TYPE_NAME, get: struct_size, set: None })?;

    Ok(class)
}

fn struct_error(vm: &Vm, message: &str) -> Signal {
    raise_class(vm, vm.native_state::<ModuleState>().error.borrow().clone(), message)
}

fn long_bytes(width: LongWidth) -> u64 {
    match width {
        LongWidth::Bits32 => 4,
        LongWidth::Bits64 => 8,
    }
}

/// The representation of `code` in `mode`; `None` for a character that is
/// not a format code there.
fn code_spec(code: u8, mode: Mode, width: LongWidth) -> Option<CodeSpec> {
    let native = mode == Mode::Native;
    let long_size = if native { long_bytes(width) } else { 4 };
    let stores_overflow = mode == Mode::Big && matches!(code, b'q' | b'Q');
    let integer = |signed: bool, carrier: Carrier, limit: Option<Limit>| Kind::Integer(IntegerRule { code, signed, carrier, limit, stores_overflow });
    let bounds = |min: i128, max: i128| Some(Limit { min, max, text: LimitText::Bounds });
    let fixed = |min: i128, max: i128, text: &'static str| Some(Limit { min, max, text: LimitText::Fixed(text) });
    // The native packers of the little-endian host report the C limit names
    // for shorts; big-endian shorts convert through an unsigned carrier.
    let host_order = mode != Mode::Big;

    let (kind, size) = match code {
        b'x' => (Kind::Pad, 1),
        b'c' => (Kind::Char, 1),
        b's' => (Kind::Bytes, 1),
        b'p' => (Kind::Pascal, 1),
        b'?' => (Kind::Bool, 1),
        b'b' => (integer(true, Carrier::Long, fixed(-128, 127, "byte format requires -128 <= number <= 127")), 1),
        b'B' => (integer(false, Carrier::Long, fixed(0, 255, "ubyte format requires 0 <= number <= 255")), 1),
        b'h' if host_order => (integer(true, Carrier::Long, fixed(-32768, 32767, "short format requires SHRT_MIN <= number <= SHRT_MAX")), 2),
        b'h' => (integer(true, Carrier::Long, bounds(-32768, 32767)), 2),
        b'H' if host_order => (integer(false, Carrier::Long, fixed(0, 65535, "ushort format requires 0 <= number <= USHRT_MAX")), 2),
        b'H' => (integer(false, Carrier::UnsignedLong, bounds(0, 65535)), 2),
        b'i' => (integer(true, Carrier::Long, bounds(i128::from(i32::MIN), i128::from(i32::MAX))), 4),
        b'I' => (integer(false, Carrier::UnsignedLong, bounds(0, i128::from(u32::MAX))), 4),
        b'l' if native => (integer(true, Carrier::Long, None), long_size),
        b'l' => (integer(true, Carrier::Long, bounds(i128::from(i32::MIN), i128::from(i32::MAX))), 4),
        b'L' if native => (integer(false, Carrier::UnsignedLong, None), long_size),
        b'L' => (integer(false, Carrier::UnsignedLong, bounds(0, i128::from(u32::MAX))), 4),
        b'q' => (integer(true, Carrier::LongLong, None), 8),
        b'Q' => (integer(false, Carrier::UnsignedLongLong, None), 8),
        b'P' if native => (Kind::Pointer, 8),
        b'f' => (Kind::Single, 4),
        b'd' => (Kind::Double, 8),
        _ => return None,
    };
    let align = if native { size } else { 1 };

    Some(CodeSpec { kind, size, align })
}

/// Compiles a format string; the format ends at its first NUL byte.
fn compile(vm: &Vm, format: &[u8]) -> PyResult<Layout> {
    // A format whose `__sizeof__` would exceed the 128 TiB x64 address
    // space at 24 bytes per size unit raises MemoryError.
    const ADDRESS_SPACE: u64 = 1 << 47;
    const UNIT_BYTES: u64 = 24;
    const MAX_SIZE: u64 = i64::MAX as u64;

    let too_long = || struct_error(vm, "total struct size too long");
    let (mode, body) = match format.split_first() {
        Some((b'@', rest)) => (Mode::Native, rest),
        Some((b'<' | b'=', rest)) => (Mode::Little, rest),
        Some((b'>' | b'!', rest)) => (Mode::Big, rest),
        _ => (Mode::Native, format),
    };
    let body = match body.iter().position(|byte| *byte == 0) {
        Some(end) => &body[..end],
        None => body,
    };

    let mut fields = Vec::new();
    let mut size: u64 = 0;
    let mut values: u64 = 0;
    let mut size_units: u64 = 0;
    let mut position = 0;
    while let Some(&first) = body.get(position) {
        if matches!(first, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            position += 1;
            continue;
        }

        let mut count: u64 = 1;
        if first.is_ascii_digit() {
            count = 0;
            while let Some(digit) = body.get(position).filter(|byte| byte.is_ascii_digit()) {
                count = count.checked_mul(10).and_then(|tens| tens.checked_add(u64::from(digit - b'0'))).filter(|total| *total <= MAX_SIZE).ok_or_else(too_long)?;
                position += 1;
            }
        }
        // A repeat count with nothing after it is ignored.
        let Some(&code) = body.get(position) else {
            break;
        };
        position += 1;

        let Some(spec) = code_spec(code, mode, vm.config.long_width) else {
            return Err(struct_error(vm, "bad char in struct format"));
        };
        size = size.div_ceil(spec.align).checked_mul(spec.align).filter(|aligned| *aligned <= MAX_SIZE).ok_or_else(too_long)?;
        let extent = count.checked_mul(spec.size).ok_or_else(too_long)?;
        let end = size.checked_add(extent).filter(|end| *end <= MAX_SIZE).ok_or_else(too_long)?;

        let offset = usize::try_from(size).map_err(|_| too_long())?;
        let repeat = usize::try_from(count).map_err(|_| too_long())?;
        match spec.kind {
            Kind::Pad => {}
            kind if kind.is_string() => {
                fields.push(Field { kind, offset, repeat: 1, size: repeat });
                values += 1;
                size_units += 1;
            }
            kind => {
                if repeat > 0 {
                    fields.push(Field { kind, offset, repeat, size: spec.size as usize });
                }
                values += count;
                size_units += count;
            }
        }
        size = end;
    }

    let reported = size_units.checked_add(1).and_then(|units| units.checked_mul(UNIT_BYTES));
    if reported.is_none_or(|bytes| bytes > ADDRESS_SPACE) {
        return Err(memory_error(vm));
    }
    let size = usize::try_from(size).map_err(|_| too_long())?;
    let values = usize::try_from(values).map_err(|_| too_long())?;

    Ok(Layout { mode, fields, size, values, size_units })
}

/// The bytes of a format argument and the value `Struct.format` reports:
/// a `str` as given, or a `unicode` in the default encoding.
fn format_source(vm: &Vm, format: &Value) -> PyResult<(Value, PyBytes)> {
    if let Some(bytes) = vm.as_str_bytes(format) {
        return Ok((format.clone(), bytes));
    }
    if let Some(text) = vm.as_text(format) {
        let bytes = encode_default(vm, text.units())?;
        return Ok((Value::Str(bytes.clone()), bytes));
    }

    Err(vm.type_error(&format!("Struct() argument 1 must be string, not {}", vm.type_name(format))))
}

/// Gives `data` the format `format`. The format attribute changes before
/// compiling, so a bad format leaves it beside the previous layout.
fn define(vm: &Vm, data: &StructData, format: &Value) -> PyResult<()> {
    if format.is_unknown() {
        *data.format.borrow_mut() = format.clone();
        *data.compiled.borrow_mut() = Compiled::Unknown;
        return Ok(());
    }

    let (attribute, bytes) = format_source(vm, format)?;
    *data.format.borrow_mut() = attribute;
    let layout = compile(vm, bytes.as_bytes())?;
    *data.compiled.borrow_mut() = Compiled::Ready(Rc::new(layout));

    Ok(())
}

/// The layout the module-level functions use for `format`, through the
/// cache of `Struct` objects; `None` when the format is unknown.
fn cached_layout(vm: &Vm, format: &Value) -> PyResult<Option<Rc<Layout>>> {
    const CACHE_LIMIT: usize = 100;

    if format.is_unknown() {
        return Ok(None);
    }

    let state = vm.native_state::<ModuleState>();
    let cache = {
        let mut slot = state.cache.borrow_mut();
        Rc::clone(slot.get_or_insert_with(|| vm.new_dict()))
    };
    // A lookup failure, such as an unhashable key, counts as a miss.
    let found = match vm.dict_get(&cache, format) {
        Ok(found) => found,
        Err(Signal::Raise(_)) => None,
        Err(signal) => return Err(signal),
    };
    if let Some(data) = found.as_ref().and_then(native_data::<StructData>) {
        return Ok(data.layout());
    }

    let class = native_type(vm, TYPE_KEY, create_struct_type)?;
    let object = new_instance(vm, &class, Payload::Native(Box::new(StructData::new())));
    let Some(data) = native_data::<StructData>(&object) else {
        return Err(vm.halt_unsupported("struct cache entry without a Struct payload"));
    };
    define(vm, data, format)?;
    let layout = data.layout();

    let cache = if vm.dict_len(&cache)? >= CACHE_LIMIT {
        let fresh = vm.new_dict();
        *state.cache.borrow_mut() = Some(Rc::clone(&fresh));
        fresh
    } else {
        cache
    };
    vm.dict_set(&cache, format.clone(), object)?;

    Ok(layout)
}

fn out_of_range(vm: &Vm, code: u8) -> Signal {
    struct_error(vm, &format!("integer out of range for '{}' format code", char::from(code)))
}

fn is_classic_instance(vm: &Vm, value: &Value) -> bool {
    matches!(value, Value::Object(object) if vm.is_classic_class(&object.class()))
}

/// The result of `__index__`, or `None` when the value has no usable one.
/// A `TypeError` from the method, or a non-integer result, falls through
/// to the other conversions.
fn index_operand(vm: &Vm, value: &Value) -> PyResult<Option<Value>> {
    let method = if is_classic_instance(vm, value) { vm.getattr_opt(value, &PyBytes::from("__index__"))? } else { vm.user_override(value, "__index__")? };
    let Some(method) = method else {
        return Ok(None);
    };

    match vm.call0(&method) {
        Ok(result) if result.is_unknown() || vm.as_integral(&result).is_some() => Ok(Some(result)),
        Ok(_) => Ok(None),
        Err(Signal::Raise(exception)) if vm.is_exception(&exception, ExceptionKind::TypeError) => Ok(None),
        Err(signal) => Err(signal),
    }
}

/// The integer an integer or pointer code packs: an int or long, then
/// `__index__`, then a float or `__int__`, both deprecated. `None` when
/// the value is unknown.
fn integer_operand(vm: &Vm, value: &Value) -> PyResult<Option<BigInt>> {
    const INT_WARNING: &str = "integer argument expected, got non-integer (implicit conversion using __int__ is deprecated)";

    if value.is_unknown() {
        return Ok(None);
    }
    if let Some(integral) = vm.as_integral(value) {
        return Ok(Some(integral.to_bigint()));
    }
    if let Some(result) = index_operand(vm, value)? {
        return Ok(vm.as_integral(&result).map(|integral| integral.to_bigint()));
    }

    if let Some(number) = vm.as_float(value) {
        warn_caller(vm, ExceptionKind::DeprecationWarning, "integer argument expected, got float")?;
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        let Some(whole) = BigInt::from_f64(number.trunc()) else {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        };
        return Ok(Some(whole));
    }

    let result = if is_classic_instance(vm, value) {
        warn_caller(vm, ExceptionKind::DeprecationWarning, INT_WARNING)?;
        classic_int(vm, value)?
    } else if let Some(method) = vm.user_override(value, "__int__")? {
        warn_caller(vm, ExceptionKind::DeprecationWarning, INT_WARNING)?;
        vm.call0(&method)?
    } else if vm.as_complex(value).is_some() {
        warn_caller(vm, ExceptionKind::DeprecationWarning, INT_WARNING)?;
        return Err(vm.type_error("can't convert complex to int"));
    } else {
        return Err(struct_error(vm, "cannot convert argument to integer"));
    };
    if result.is_unknown() {
        return Ok(None);
    }

    match vm.as_integral(&result) {
        Some(integral) => Ok(Some(integral.to_bigint())),
        None => Err(vm.type_error("__int__ method returned non-integer")),
    }
}

/// Stores the bits of an integer code into `slot`; `None` when the value
/// is unknown. An `OverflowError` while converting reports as a range
/// error.
fn store_integer(vm: &Vm, rule: &IntegerRule, value: &Value, slot: &mut [u8], big_endian: bool) -> PyResult<Option<()>> {
    let number = match integer_operand(vm, value) {
        Ok(Some(number)) => number,
        Ok(None) => return Ok(None),
        Err(Signal::Raise(exception)) if vm.is_exception(&exception, ExceptionKind::OverflowError) => return Err(out_of_range(vm, rule.code)),
        Err(signal) => return Err(signal),
    };

    let carrier = rule.carrier.bounds(vm.config.long_width);
    let Some(number) = number.to_i128().filter(|number| carrier.contains(number)) else {
        if rule.stores_overflow && (rule.signed || number.sign() != num_bigint::Sign::Minus) {
            store(slot, low_bits(&number), big_endian);
        }
        return Err(out_of_range(vm, rule.code));
    };
    if let Some(limit) = rule.limit
        && !(limit.min..=limit.max).contains(&number)
    {
        let message = match limit.text {
            LimitText::Fixed(text) => text.to_owned(),
            LimitText::Bounds => format!("'{}' format requires {} <= number <= {}", char::from(rule.code), limit.min, limit.max),
        };
        return Err(struct_error(vm, &message));
    }

    // Two's complement truncation to the low 64 bits.
    store(slot, number as u64, big_endian);

    Ok(Some(()))
}

/// The low 64 bits of `number` in two's complement.
fn low_bits(number: &BigInt) -> u64 {
    let bytes = number.to_signed_bytes_le();
    let fill = if number.sign() == num_bigint::Sign::Minus { 0xff } else { 0 };
    let mut low = [fill; 8];
    for (target, byte) in low.iter_mut().zip(bytes) {
        *target = byte;
    }

    u64::from_le_bytes(low)
}

/// The bits of a `P` value; overflow raises `OverflowError` as the
/// pointer conversion reports it.
fn pointer_bits(vm: &Vm, value: &Value) -> PyResult<Option<u64>> {
    let Some(number) = integer_operand(vm, value)? else {
        return Ok(None);
    };

    let bits = if number.sign() == num_bigint::Sign::Minus { number.to_i64().map(|signed| signed as u64) } else { number.to_u64() };
    let Some(bits) = bits else {
        let message = match (vm.config.long_width, number.sign() == num_bigint::Sign::Minus) {
            (LongWidth::Bits32, _) => "long too big to convert",
            (LongWidth::Bits64, true) => "Python int too large to convert to C long",
            (LongWidth::Bits64, false) => "long int too large to convert",
        };
        return Err(vm.raise(ExceptionKind::OverflowError, message));
    };

    Ok(Some(bits))
}

/// The double a float code packs; every conversion failure reports as
/// `struct.error`. `None` when the value is unknown.
fn float_operand(vm: &Vm, value: &Value) -> PyResult<Option<f64>> {
    let converted = (|| -> PyResult<Option<f64>> {
        if value.is_unknown() {
            return Ok(None);
        }
        if let Some(number) = vm.as_float(value) {
            return Ok(Some(number));
        }

        let method = if is_classic_instance(vm, value) { Some(vm.getattr_str(value, "__float__")?) } else { vm.user_override(value, "__float__")? };
        if let Some(method) = method {
            let result = vm.call0(&method)?;
            if result.is_unknown() {
                return Ok(None);
            }
            return vm.as_float(&result).map(Some).ok_or_else(|| vm.type_error("nb_float should return float object"));
        }

        let Some(integral) = vm.as_integral(value) else {
            return Err(vm.type_error("a float is required"));
        };
        crate::interp::numbers::bigint_to_f64(&integral.to_bigint()).map(Some).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"))
    })();

    match converted {
        Err(Signal::Raise(_)) => Err(struct_error(vm, "required argument is not a float")),
        other => other,
    }
}

/// `value` narrowed to single precision as the x64 conversion does: NaNs
/// keep their sign and leading payload bits and become quiet.
fn to_single(value: f64) -> f32 {
    if !value.is_nan() {
        return value as f32;
    }

    let bits = value.to_bits();
    let sign = ((bits >> 63) as u32) << 31;
    let payload = ((bits >> 29) as u32) & 0x007f_ffff;

    f32::from_bits(sign | 0x7fc0_0000 | payload)
}

/// `value` widened to double precision as the x64 conversion does: NaNs
/// keep their sign and payload and become quiet.
fn to_double(value: f32) -> f64 {
    if !value.is_nan() {
        return f64::from(value);
    }

    let bits = value.to_bits();
    let sign = u64::from(bits >> 31) << 63;
    let payload = u64::from(bits & 0x007f_ffff) << 29;

    f64::from_bits(sign | 0x7ff8_0000_0000_0000 | payload)
}

/// Writes the low `target.len()` bytes of `bits` in the layout's order.
fn store(target: &mut [u8], bits: u64, big_endian: bool) {
    let bytes = bits.to_le_bytes();
    let width = target.len();
    for (index, slot) in target.iter_mut().enumerate() {
        let source = if big_endian { width - 1 - index } else { index };
        *slot = bytes.get(source).copied().unwrap_or_default();
    }
}

/// Reads `source` as an unsigned integer in the layout's order.
fn load(source: &[u8], big_endian: bool) -> u64 {
    let fold = |total: u64, byte: &u8| (total << 8) | u64::from(*byte);

    if big_endian { source.iter().fold(0, fold) } else { source.iter().rev().fold(0, fold) }
}

/// The bytes of one item of `kind` from `value`; `None` when the value is
/// unknown. `slot` starts zeroed.
fn pack_item(vm: &Vm, layout: &Layout, kind: Kind, value: &Value, slot: &mut [u8]) -> PyResult<Option<()>> {
    let big_endian = layout.mode.is_big_endian();
    if value.is_unknown() {
        return Ok(None);
    }

    match kind {
        Kind::Pad => {}
        Kind::Char => {
            let byte = vm.as_str_bytes(value).and_then(|bytes| match bytes.as_bytes() {
                [byte] => Some(*byte),
                _ => None,
            });
            let Some(byte) = byte else {
                return Err(struct_error(vm, "char format require string of length 1"));
            };
            slot[0] = byte;
        }
        Kind::Bytes | Kind::Pascal => {
            let code = if matches!(kind, Kind::Bytes) { 's' } else { 'p' };
            let Some(bytes) = vm.as_str_bytes(value) else {
                return Err(struct_error(vm, &format!("argument for '{code}' must be a string")));
            };
            let bytes = bytes.as_bytes();
            if matches!(kind, Kind::Bytes) {
                let length = bytes.len().min(slot.len());
                slot[..length].copy_from_slice(&bytes[..length]);
            } else if let Some((length_byte, text)) = slot.split_first_mut() {
                let length = bytes.len().min(text.len());
                text[..length].copy_from_slice(&bytes[..length]);
                *length_byte = length.min(255) as u8;
            }
        }
        Kind::Bool => {
            slot[0] = u8::from(vm.truthy(value, "struct '?' argument")?);
        }
        Kind::Integer(rule) => {
            if store_integer(vm, &rule, value, slot, big_endian)?.is_none() {
                return Ok(None);
            }
        }
        Kind::Pointer => {
            let Some(bits) = pointer_bits(vm, value)? else {
                return Ok(None);
            };
            store(slot, bits, big_endian);
        }
        Kind::Single => {
            let Some(number) = float_operand(vm, value)? else {
                return Ok(None);
            };
            let single = to_single(number);
            if layout.mode != Mode::Native && single.is_infinite() && number.is_finite() {
                return Err(vm.raise(ExceptionKind::OverflowError, "float too large to pack with f format"));
            }
            store(slot, u64::from(single.to_bits()), big_endian);
        }
        Kind::Double => {
            let Some(number) = float_operand(vm, value)? else {
                return Ok(None);
            };
            store(slot, number.to_bits(), big_endian);
        }
    }

    Ok(Some(()))
}

/// Packs `values` into `target`, which holds `layout.size` zero bytes and
/// one spare byte past them. Items before a failing one stay written.
/// `None` when a value is unknown.
fn pack_values(vm: &Vm, layout: &Layout, values: &[Value], target: &mut [u8]) -> PyResult<Option<()>> {
    let mut values = values.iter();
    for field in &layout.fields {
        let repeat = if field.kind.is_string() { 1 } else { field.repeat };
        for item in 0..repeat {
            let Some(value) = values.next() else {
                return Err(vm.halt_unsupported("struct value count differs from its layout"));
            };
            let start = field.offset + item * field.size;
            let Some(slot) = target.get_mut(start..start + field.size) else {
                return Err(vm.halt_unsupported("struct field beyond its layout"));
            };
            if pack_item(vm, layout, field.kind, value, slot)?.is_none() {
                return Ok(None);
            }
            // An empty `p` field still stores its length byte, clamped from
            // -1, at its offset; it lands in whatever follows.
            if matches!(field.kind, Kind::Pascal)
                && field.size == 0
                && let Some(byte) = target.get_mut(start)
            {
                *byte = 0xff;
            }
        }
    }

    Ok(Some(()))
}

/// A fresh string of `size` zero bytes to pack into, or MemoryError past
/// the address space.
fn zeroed(vm: &Vm, size: usize) -> PyResult<Vec<u8>> {
    const ADDRESS_SPACE: usize = 1 << 47;

    if size > ADDRESS_SPACE {
        return Err(memory_error(vm));
    }

    Ok(vec![0; size])
}

fn pack_layout(vm: &Vm, layout: &Layout, values: &[Value], operation: &str) -> PyResult<Value> {
    if values.len() != layout.values {
        return Err(struct_error(vm, &format!("{operation} expected {} items for packing (got {})", layout.values, values.len())));
    }

    let mut packed = zeroed(vm, layout.size + 1)?;
    if pack_values(vm, layout, values, &mut packed)?.is_none() {
        return Ok(Value::unknown("struct.pack of an unknown value"));
    }
    packed.truncate(layout.size);

    Ok(Value::Str(PyBytes::new_unshared(packed)))
}

/// One unpacked item starting at `source[0]`.
fn unpack_item(vm: &Vm, layout: &Layout, kind: Kind, source: &[u8]) -> PyResult<Value> {
    let big_endian = layout.mode.is_big_endian();

    let value = match kind {
        Kind::Pad => Value::None,
        Kind::Char | Kind::Bytes => Value::Str(PyBytes::new(source)),
        Kind::Pascal => {
            let Some((&length, text)) = source.split_first() else {
                return Err(vm.raise(ExceptionKind::SystemError, "Negative size passed to PyString_FromStringAndSize"));
            };
            let length = usize::from(length).min(text.len());
            Value::Str(PyBytes::new(&text[..length]))
        }
        Kind::Bool => Value::Bool(source.iter().any(|byte| *byte != 0)),
        Kind::Integer(rule) => {
            let bits = load(source, big_endian);
            let shift = 64 - 8 * source.len() as u32;
            if rule.signed {
                vm.new_int_from_i64(((bits << shift) as i64) >> shift)
            } else {
                vm.new_int(BigInt::from(bits))
            }
        }
        Kind::Pointer => {
            let bits = load(source, big_endian);
            match vm.config.long_width {
                // A pointer wider than `long` always comes back as a long.
                LongWidth::Bits32 => Value::long(BigInt::from(bits)),
                LongWidth::Bits64 => vm.new_int(BigInt::from(bits)),
            }
        }
        Kind::Single => {
            let bits = load(source, big_endian) as u32;
            Value::Float(to_double(f32::from_bits(bits)))
        }
        Kind::Double => Value::Float(f64::from_bits(load(source, big_endian))),
    };

    Ok(value)
}

/// Unpacks `data`, which holds at least `layout.size` bytes.
fn unpack_layout(vm: &Vm, layout: &Layout, data: &[u8]) -> PyResult<Value> {
    let mut items = Vec::with_capacity(layout.values);
    for field in &layout.fields {
        let repeat = if field.kind.is_string() { 1 } else { field.repeat };
        for item in 0..repeat {
            let start = field.offset + item * field.size;
            let Some(source) = data.get(start..start + field.size) else {
                return Err(vm.halt_unsupported("struct field beyond the unpacked data"));
            };
            items.push(unpack_item(vm, layout, field.kind, source)?);
        }
    }

    Ok(Value::tuple(items))
}

/// The bytes `unpack` reads from `input`; `None` when the value supplies
/// none, which reports as a length mismatch.
fn unpack_input(vm: &Vm, input: &Value) -> PyResult<Option<PyBytes>> {
    let bytes = match vm.as_text(input) {
        Some(text) => encode_default(vm, text.units()).map(Some),
        None => vm.buffer(input, BufferInterface::Any),
    };

    match bytes {
        Err(Signal::Raise(_)) => Ok(None),
        other => other,
    }
}

fn unpack_receiver(vm: &Vm, receiver: Receiver, input: &Value) -> PyResult<Value> {
    if input.is_unknown() {
        return Ok(Value::unknown("struct.unpack of an unknown value"));
    }
    let layout = match receiver {
        Receiver::Ready(layout) => layout,
        Receiver::Unknown => return Ok(Value::unknown("struct.unpack with an unknown format")),
        Receiver::Missing => return Err(struct_error(vm, &format!("unpack requires a string argument of length {MISSING_COUNT}"))),
    };

    let data = unpack_input(vm, input)?;
    let Some(data) = data.filter(|data| data.as_bytes().len() == layout.size) else {
        return Err(struct_error(vm, &format!("unpack requires a string argument of length {}", layout.size)));
    };

    unpack_layout(vm, &layout, data.as_bytes())
}

/// The `buffer` argument of `unpack_from`: `None` for `None`.
fn unpack_from_buffer(vm: &Vm, value: &Value) -> PyResult<Option<PyBytes>> {
    if value.is_none() {
        return Ok(None);
    }
    if let Some(text) = vm.as_text(value) {
        return encode_default(vm, text.units()).map(Some);
    }

    buffer_argument(vm, value, "unpack_from", BufferInterface::Any).map(Some)
}

/// A converted argument of `unpack_from`.
enum UnpackFromArgument {
    Buffer(Option<PyBytes>),
    /// `None` when the offset is unknown.
    Offset(Option<i64>),
}

fn unpack_from_receiver(vm: &Vm, receiver: Receiver, args: CallArgs) -> PyResult<Value> {
    if args.positional.iter().any(Value::is_unknown) || args.keywords.iter().any(|(_, value)| value.is_unknown()) {
        return Ok(Value::unknown("struct.unpack_from of an unknown value"));
    }

    let slots = parse_with(vm, args, "unpack_from", &["buffer", "offset"], 1, |vm, index, value| {
        if index == 0 {
            return unpack_from_buffer(vm, &value).map(UnpackFromArgument::Buffer);
        }
        ssize_argument(vm, &value).map(UnpackFromArgument::Offset)
    })?;
    let mut buffer = None;
    let mut offset = Some(0);
    for slot in slots.into_iter().flatten() {
        match slot {
            UnpackFromArgument::Buffer(bytes) => buffer = bytes,
            UnpackFromArgument::Offset(value) => offset = value,
        }
    }
    let Some(buffer) = buffer else {
        return Err(struct_error(vm, "unpack_from requires a buffer argument"));
    };
    let Some(offset) = offset else {
        return Ok(Value::unknown("struct.unpack_from at an unknown offset"));
    };

    let (layout, size) = match receiver {
        Receiver::Ready(layout) => {
            let size = layout.size as i64;
            (Some(layout), size)
        }
        Receiver::Missing => (None, MISSING_COUNT),
        Receiver::Unknown => return Ok(Value::unknown("struct.unpack_from with an unknown format")),
    };
    let length = buffer.as_bytes().len() as i64;
    let offset = if offset < 0 { offset + length } else { offset };
    if offset < 0 || length - offset < size {
        return Err(struct_error(vm, &format!("unpack_from requires a buffer of at least {size} bytes")));
    }
    let Some(layout) = layout else {
        return Err(vm.halt_unsupported("unpack_from of an uninitialized Struct"));
    };

    let start = offset as usize;
    unpack_layout(vm, &layout, &buffer.as_bytes()[start..])
}

/// The offset of `pack_into`: a signed 64-bit size, converted through
/// `__int__`; `None` when it is unknown.
fn pack_into_offset(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    let converted_overflow = match vm.config.long_width {
        LongWidth::Bits32 => "long int too large to convert to int",
        LongWidth::Bits64 => "Python int too large to convert to C long",
    };
    let overflow = |message: &str| vm.raise(ExceptionKind::OverflowError, message);

    if let Some(integral) = vm.as_integral(value) {
        return integral.to_i64().map(Some).ok_or_else(|| overflow("long int too large to convert to int"));
    }

    let result = if let Some(number) = vm.as_float(value) {
        if number.is_infinite() {
            return Err(overflow("cannot convert float infinity to integer"));
        }
        let Some(whole) = BigInt::from_f64(number.trunc()) else {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        };
        vm.new_int(whole)
    } else if is_classic_instance(vm, value) {
        classic_int(vm, value)?
    } else if let Some(method) = vm.user_override(value, "__int__")? {
        vm.call0(&method)?
    } else if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to int"));
    } else {
        return Err(vm.type_error("an integer is required"));
    };
    if result.is_unknown() {
        return Ok(None);
    }

    let Some(integral) = vm.as_integral(&result) else {
        return Err(vm.type_error("__int__ method should return an integer"));
    };

    integral.to_i64().map(Some).ok_or_else(|| overflow(converted_overflow))
}

/// The bytes of a writable buffer argument; raises when `value` has none.
fn writable_length(vm: &Vm, value: &Value) -> PyResult<usize> {
    if vm.as_text(value).is_some() {
        return Err(vm.type_error("cannot use unicode as modifiable buffer"));
    }

    match vm.buffer(value, BufferInterface::WritableAny)? {
        Some(bytes) => Ok(bytes.as_bytes().len()),
        None => Err(vm.type_error(&format!("argument must be read-write buffer, not {}", argument_type_name(vm, value)))),
    }
}

/// `pack_into(buffer, offset, *values)` for a receiver with `receiver`.
fn pack_into_receiver(vm: &Vm, receiver: Receiver, arguments: &[Value]) -> PyResult<Value> {
    let (layout, expected) = match receiver {
        Receiver::Ready(layout) => {
            let expected = layout.values as i64;
            (Some(layout), expected)
        }
        Receiver::Missing => (None, MISSING_COUNT),
        Receiver::Unknown => return Ok(Value::unknown("struct.pack_into with an unknown format")),
    };

    let given = arguments.len() as i64;
    if given != expected + 2 {
        return Err(match arguments.len() {
            0 => struct_error(vm, "pack_into expected buffer argument"),
            1 => struct_error(vm, "pack_into expected offset argument"),
            _ => struct_error(vm, &format!("pack_into expected {expected} items for packing (got {})", given - 2)),
        });
    }
    let [target, offset, values @ ..] = arguments else {
        return Err(vm.halt_unsupported("pack_into of an uninitialized Struct"));
    };
    if target.is_unknown() {
        return Ok(Value::unknown("struct.pack_into into an unknown buffer"));
    }

    let length = writable_length(vm, target)?;
    let Some(layout) = layout else {
        return Err(vm.halt_unsupported("pack_into of an uninitialized Struct"));
    };
    halt_on_unknown(offset, "struct.pack_into offset")?;
    let Some(offset) = pack_into_offset(vm, offset)? else {
        return Err(vm.halt_unsupported("struct.pack_into at an unknown offset"));
    };
    let length = length as i64;
    let offset = if offset < 0 { offset + length } else { offset };
    if offset < 0 || length - offset < layout.size as i64 {
        return Err(struct_error(vm, &format!("pack_into requires a buffer of at least {} bytes", layout.size)));
    }

    let mut packed = zeroed(vm, layout.size + 1)?;
    let outcome = pack_values(vm, &layout, values, &mut packed);
    if matches!(outcome, Ok(None)) {
        return Err(vm.halt_unsupported("struct.pack_into of an unknown value"));
    }
    // Only an empty trailing `p` field writes the spare byte.
    let spilled = packed.pop() == Some(0xff);

    // The target region is cleared before packing, so a failing value
    // leaves zeros after the items already written.
    let start = offset as usize;
    let written = vm.write_buffer(target, |bytes| {
        let Some(region) = bytes.get_mut(start..start + packed.len()) else {
            return false;
        };
        region.copy_from_slice(&packed);
        if spilled && let Some(byte) = bytes.get_mut(start + packed.len()) {
            *byte = 0xff;
        }
        true
    })?;
    if written != Some(true) {
        return Err(vm.halt_unsupported("struct.pack_into target changed size"));
    }
    outcome?;

    Ok(Value::None)
}

fn no_keywords(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    Ok(())
}

/// Splits the format from the arguments of a module-level function.
fn split_format(vm: &Vm, mut args: CallArgs) -> PyResult<(Value, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error("missing format argument"));
    }
    let format = args.positional.remove(0);

    Ok((format, args))
}

fn module_receiver(vm: &Vm, format: &Value) -> PyResult<Receiver> {
    match cached_layout(vm, format)? {
        Some(layout) => Ok(Receiver::Ready(layout)),
        None => Ok(Receiver::Unknown),
    }
}

fn clear_cache(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "_clearcache")?;

    *vm.native_state::<ModuleState>().cache.borrow_mut() = None;

    Ok(Value::None)
}

fn calcsize(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_keywords(vm, &args, "calcsize")?;
    let [format] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!("calcsize() takes exactly one argument ({} given)", args.positional.len())));
    };

    match cached_layout(vm, format)? {
        Some(layout) => Ok(vm.new_int_from_i64(layout.size as i64)),
        None => Ok(Value::unknown("struct.calcsize of an unknown format")),
    }
}

fn pack(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_keywords(vm, &args, "pack")?;
    let (format, rest) = split_format(vm, args)?;

    match cached_layout(vm, &format)? {
        Some(layout) => pack_layout(vm, &layout, &rest.positional, "pack"),
        None => Ok(Value::unknown("struct.pack with an unknown format")),
    }
}

fn pack_into(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_keywords(vm, &args, "pack_into")?;
    let (format, rest) = split_format(vm, args)?;
    let receiver = module_receiver(vm, &format)?;

    pack_into_receiver(vm, receiver, &rest.positional)
}

fn unpack(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_keywords(vm, &args, "unpack")?;
    let [format, input] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!("unpack expected 2 arguments, got {}", args.positional.len())));
    };
    let receiver = module_receiver(vm, format)?;

    unpack_receiver(vm, receiver, input)
}

fn unpack_from(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (format, rest) = split_format(vm, args)?;
    let receiver = module_receiver(vm, &format)?;

    unpack_from_receiver(vm, receiver, rest)
}

/// Allocates an uninitialized `Struct`; extra arguments are ignored.
fn struct_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = native_type(vm, TYPE_KEY, create_struct_type)?;
    let (class, _) = new_class(vm, args, &base)?;

    Ok(new_instance(vm, &class, Payload::Native(Box::new(StructData::new()))))
}

/// The call arguments after the receiver of a native method.
fn method_rest(args: &CallArgs) -> CallArgs {
    CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() }
}

fn struct_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<StructData>(vm, &args, TYPE_NAME, "__init__")?;
    let slots = parse(vm, method_rest(&args), "Struct", &["format"], 1)?;
    let Some(Some(format)) = slots.into_iter().next() else {
        return Err(vm.type_error("Required argument 'format' (pos 1) not found"));
    };

    define(vm, data, &format)?;

    Ok(Value::None)
}

fn struct_pack(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<StructData>(vm, &args, TYPE_NAME, "pack")?;
    no_keywords(vm, &args, "pack")?;
    let values = &args.positional[1..];

    match Receiver::of(data) {
        Receiver::Ready(layout) => pack_layout(vm, &layout, values, "pack"),
        Receiver::Unknown => Ok(Value::unknown("Struct.pack with an unknown format")),
        Receiver::Missing => Err(struct_error(vm, &format!("pack expected {MISSING_COUNT} items for packing (got {})", values.len()))),
    }
}

fn struct_pack_into(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<StructData>(vm, &args, TYPE_NAME, "pack_into")?;
    no_keywords(vm, &args, "pack_into")?;

    pack_into_receiver(vm, Receiver::of(data), &args.positional[1..])
}

fn struct_unpack(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<StructData>(vm, &args, TYPE_NAME, "unpack")?;
    let input = method_one_argument(vm, &args, "unpack")?;

    unpack_receiver(vm, Receiver::of(data), &input)
}

fn struct_unpack_from(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<StructData>(vm, &args, TYPE_NAME, "unpack_from")?;

    unpack_from_receiver(vm, Receiver::of(data), method_rest(&args))
}

/// `__sizeof__`: the instance size plus 24 bytes per size unit and 24
/// more.
fn struct_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const UNIT_BYTES: u64 = 24;

    let data = this::<StructData>(vm, &args, TYPE_NAME, "__sizeof__")?;
    method_no_arguments(vm, &args, "__sizeof__")?;
    let layout = match Receiver::of(data) {
        Receiver::Ready(layout) => layout,
        Receiver::Unknown => return Ok(Value::unknown("Struct.__sizeof__ with an unknown format")),
        Receiver::Missing => return Err(vm.halt_unsupported("__sizeof__ of an uninitialized Struct")),
    };

    let instance = instance_size(vm, &vm.class_of(&args.positional[0]))?;

    Ok(Value::long(BigInt::from(instance + UNIT_BYTES * (layout.size_units + 1))))
}

/// The instance size `__sizeof__` starts from: 56 bytes for `Struct`, plus 8
/// per slot a subclass declares and 8 when a subclass without `__slots__`
/// or with a `__dict__` slot is in the hierarchy. `__weakref__` adds nothing.
fn instance_size(vm: &Vm, class: &ObjectRef) -> PyResult<u64> {
    const STRUCT_SIZE: u64 = 56;
    const POINTER_SIZE: u64 = 8;

    let native = native_type(vm, TYPE_KEY, create_struct_type)?;
    let Some(data) = class.as_class() else {
        return Ok(STRUCT_SIZE);
    };

    let mut slots = 0;
    let mut has_dict = false;
    for entry in data.mro() {
        let MroEntry::Class(ancestor) = entry else {
            continue;
        };
        if Rc::ptr_eq(&ancestor, &native) {
            break;
        }
        let Some(ancestor_data) = ancestor.as_class() else {
            continue;
        };
        let Some(declared) = vm.dict_get_str(&ancestor_data.dict, "__slots__")? else {
            has_dict = true;
            continue;
        };

        let names = if vm.as_str_bytes(&declared).is_some() || vm.as_text(&declared).is_some() { vec![declared] } else { vm.collect(&declared)? };
        for name in &names {
            match vm.text_of(name).as_deref() {
                Some("__dict__") => has_dict = true,
                Some("__weakref__") => {}
                _ => slots += 1,
            }
        }
    }

    Ok(STRUCT_SIZE + POINTER_SIZE * (slots + u64::from(has_dict)))
}

fn struct_format(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = native_data::<StructData>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(data.format.borrow().clone())
}

fn struct_size(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = native_data::<StructData>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    if data.is_unknown() {
        return Ok(Value::unknown("Struct.size with an unknown format"));
    }

    match data.layout() {
        Some(layout) => Ok(vm.new_int_from_i64(layout.size as i64)),
        None => Ok(Value::Int(MISSING_COUNT)),
    }
}
