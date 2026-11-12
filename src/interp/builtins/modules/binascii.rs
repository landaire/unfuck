//! The `binascii` module, plus the argument conversions that `binascii`,
//! `zlib`, `_struct`, and other native modules share.

use std::cell::RefCell;
use std::ops::RangeInclusive;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::text::codecs::encode_default;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The exception classes `binascii` raises.
#[derive(Default)]
struct BinasciiState {
    error: RefCell<Option<ObjectRef>>,
    incomplete: RefCell<Option<ObjectRef>>,
}

/// The 64 symbols of the base64 alphabet (RFC 2045).
const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The 64 symbols of the BinHex 4.0 alphabet.
const HQX_ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// The BinHex run-length marker.
const RUN_MARKER: u8 = 0x90;

const fn crc32_table() -> [u32; 256] {
    const POLYNOMIAL: u32 = 0xedb8_8320;

    let mut table = [0; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut remainder = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 1 == 1 { (remainder >> 1) ^ POLYNOMIAL } else { remainder >> 1 };
            bit += 1;
        }
        table[byte] = remainder;
        byte += 1;
    }

    table
}

const fn crc_ccitt_table() -> [u16; 256] {
    const POLYNOMIAL: u16 = 0x1021;

    let mut table = [0; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut remainder = (byte as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            remainder = if remainder & 0x8000 != 0 { (remainder << 1) ^ POLYNOMIAL } else { remainder << 1 };
            bit += 1;
        }
        table[byte] = remainder;
        byte += 1;
    }

    table
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("a2b_uu", a2b_uu),
            function("b2a_uu", b2a_uu),
            function("a2b_base64", a2b_base64),
            function("b2a_base64", b2a_base64),
            function("a2b_hqx", a2b_hqx),
            function("b2a_hqx", b2a_hqx),
            function("b2a_hex", b2a_hex),
            function("a2b_hex", a2b_hex),
            function("hexlify", hexlify),
            function("unhexlify", unhexlify),
            function("rlecode_hqx", rlecode_hqx),
            function("rledecode_hqx", rledecode_hqx),
            function("crc_hqx", crc_hqx),
            function("crc32", crc32),
            function("a2b_qp", a2b_qp),
            function("b2a_qp", b2a_qp),
        ],
    )?;

    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "binascii", "Error", &base)?;
    let incomplete = new_exception_class(vm, "binascii", "Incomplete", &base)?;
    set_attribute(vm, module, "Error", Value::Object(Rc::clone(&error)))?;
    set_attribute(vm, module, "Incomplete", Value::Object(Rc::clone(&incomplete)))?;

    let state = vm.native_state::<BinasciiState>();
    *state.error.borrow_mut() = Some(error);
    *state.incomplete.borrow_mut() = Some(incomplete);

    Ok(())
}

/// Raises an instance of a native module's exception class with `message`.
pub(super) fn raise_class(vm: &Vm, class: Option<ObjectRef>, message: &str) -> Signal {
    let Some(class) = class else {
        return vm.halt_unsupported("exception class of an uninitialized native module");
    };

    vm.raise_string(&class, Value::str(message))
}

fn binascii_error(vm: &Vm, message: &str) -> Signal {
    raise_class(vm, vm.native_state::<BinasciiState>().error.borrow().clone(), message)
}

fn binascii_incomplete(vm: &Vm, message: &str) -> Signal {
    raise_class(vm, vm.native_state::<BinasciiState>().incomplete.borrow().clone(), message)
}

/// Whether any argument is unknown; the result of a pure native function
/// then is unknown too.
pub(super) fn has_unknown(args: &CallArgs) -> bool {
    args.positional.iter().any(Value::is_unknown) || args.keywords.iter().any(|(_, value)| value.is_unknown())
}

/// The type name argument conversion errors report; `None` reads as
/// `None` rather than `NoneType`.
pub(super) fn argument_type_name(vm: &Vm, value: &Value) -> String {
    if value.is_none() {
        return "None".to_owned();
    }

    vm.type_name(value)
}

/// The positional arguments of a function that takes no keywords. Keyword
/// errors name `method`; count errors name `function`.
pub(super) fn varargs(vm: &Vm, args: CallArgs, method: &str, function: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    if count < minimum || count > maximum {
        let quantity = if minimum == maximum {
            "exactly"
        } else if count < minimum {
            "at least"
        } else {
            "at most"
        };
        let bound = if count < minimum { minimum } else { maximum };
        let plural = if bound == 1 { "" } else { "s" };
        return Err(vm.type_error(&format!("{function}() takes {quantity} {bound} argument{plural} ({count} given)")));
    }

    Ok(args.positional)
}

/// ASCII bytes of a unicode value (the default encoding), or `None` when it
/// holds other characters.
pub(super) fn ascii_bytes(units: &[u16]) -> Option<PyBytes> {
    let bytes: Option<Vec<u8>> = units.iter().map(|unit| u8::try_from(*unit).ok().filter(u8::is_ascii)).collect();

    bytes.map(PyBytes::new)
}

/// A read-only buffer argument. The value must not be unknown.
pub(super) fn buffer_argument(vm: &Vm, value: &Value, function: &str, interface: BufferInterface) -> PyResult<PyBytes> {
    if let Some(bytes) = vm.buffer(value, interface)? {
        return Ok(bytes);
    }
    if let Some(text) = vm.as_text(value) {
        return ascii_bytes(text.units()).ok_or_else(|| vm.halt_unsupported("UnicodeEncodeError of a non-ASCII unicode buffer argument"));
    }
    if is_native_object(vm, value) {
        return Err(vm.halt_unsupported(format!("{function}() of a native buffer object")));
    }

    let expected = if interface == BufferInterface::Pinned { "string or read-only buffer" } else { "string or buffer" };
    // A function without a name is not mentioned in the message.
    let prefix = if function.is_empty() { String::new() } else { format!("{function}() ") };

    Err(vm.type_error(&format!("{prefix}argument 1 must be {expected}, not {}", argument_type_name(vm, value))))
}

/// Objects of unemulated native types may implement the buffer protocol;
/// the emulated buffer types declare theirs in `buffer_slots`.
pub(super) fn is_native_object(vm: &Vm, value: &Value) -> bool {
    matches!(value, Value::Object(object) if matches!(object.payload, Payload::Native(_))) && vm.buffer_slots(value).is_none()
}

fn to_bigint(integral: Integral) -> BigInt {
    match integral {
        Integral::Int(number) => BigInt::from(number),
        Integral::Long(number) => number,
    }
}

fn float_argument_error(vm: &Vm, value: &Value) -> Option<Signal> {
    vm.as_float(value).map(|_| vm.type_error("integer argument expected, got float"))
}

/// An integer argument: an int or long, or the result of a user `__int__`.
/// `None` when that result is unknown.
fn integer_or_int_method(vm: &Vm, value: &Value) -> PyResult<Option<BigInt>> {
    if let Some(integral) = vm.as_integral(value) {
        return Ok(Some(to_bigint(integral)));
    }

    let Some(method) = vm.user_override(value, "__int__")? else {
        return Err(vm.type_error("an integer is required"));
    };
    let result = vm.call0(&method)?;
    if result.is_unknown() {
        return Ok(None);
    }

    match vm.as_integral(&result) {
        Some(integral) => Ok(Some(to_bigint(integral))),
        None => Err(vm.type_error("__int__ method should return an integer")),
    }
}

/// The values a C `long` holds.
fn long_range(vm: &Vm) -> RangeInclusive<i64> {
    match vm.config.long_width {
        LongWidth::Bits32 => i64::from(i32::MIN)..=i64::from(i32::MAX),
        LongWidth::Bits64 => i64::MIN..=i64::MAX,
    }
}

/// `number` as a C `long`.
fn c_long(vm: &Vm, number: &BigInt) -> PyResult<i64> {
    let range = long_range(vm);

    number.to_i64().filter(|value| range.contains(value)).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))
}

/// A C `int` argument. `None` when the value is unknown.
pub(super) fn int_argument(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if let Some(error) = float_argument_error(vm, value) {
        return Err(error);
    }

    let Some(number) = integer_or_int_method(vm, value)? else {
        return Ok(None);
    };
    let number = c_long(vm, &number)?;
    if number > i64::from(i32::MAX) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum"));
    }

    i32::try_from(number).map(Some).map_err(|_| vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum"))
}

/// The low 32 bits of an integer argument, without range checking. `None`
/// when the value is unknown.
pub(super) fn unsigned_int_mask_argument(vm: &Vm, value: &Value) -> PyResult<Option<u32>> {
    if let Some(error) = float_argument_error(vm, value) {
        return Err(error);
    }

    let Some(number) = integer_or_int_method(vm, value)? else {
        return Ok(None);
    };
    let bytes = number.to_signed_bytes_le();
    let fill = if number.sign() == num_bigint::Sign::Minus { 0xff } else { 0 };
    let mut low = [fill; 4];
    for (target, byte) in low.iter_mut().zip(bytes) {
        *target = byte;
    }

    Ok(Some(u32::from_le_bytes(low)))
}

/// A `ssize_t` argument (`n` format). `None` when the value is unknown.
pub(super) fn ssize_argument(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    arguments::ssize_argument(vm, value).map(Some)
}

/// The bytes of a data argument: a buffer, or a `unicode` in the default
/// encoding.
fn data_argument(vm: &Vm, value: &Value, function: &str) -> PyResult<PyBytes> {
    if let Some(text) = vm.as_text(value) {
        return encode_default(vm, text.units());
    }

    buffer_argument(vm, value, function, BufferInterface::Any)
}

/// The data of a function of one buffer argument; `None` when it is
/// unknown.
fn single_buffer(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Option<PyBytes>> {
    if has_unknown(&args) {
        return Ok(None);
    }

    let values = varargs(vm, args, name, name, 1, 1)?;
    let Some(value) = values.first() else {
        return Ok(None);
    };

    data_argument(vm, value, name).map(Some)
}

/// The 6-bit value of a uuencoded character: the offset from space,
/// with the grave accent standing for zero.
fn uu_value(byte: u8) -> Option<u32> {
    (b' '..=b'`').contains(&byte).then(|| u32::from(byte - b' ') & 0x3f)
}

fn a2b_uu(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "a2b_uu")? else {
        return Ok(Value::unknown("binascii.a2b_uu"));
    };

    // The length character of an empty line reads as NUL.
    let (length, mut rest) = match data.as_bytes().split_first() {
        Some((first, rest)) => (usize::from(first.wrapping_sub(b' ') & 0x3f), rest.iter()),
        None => (usize::from(0u8.wrapping_sub(b' ') & 0x3f), [].iter()),
    };

    // Characters missing at the end, and line ends, count as zero.
    let mut output = Vec::with_capacity(length);
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    while output.len() < length {
        let value = match rest.next() {
            None | Some(b'\n' | b'\r') => 0,
            Some(&byte) => uu_value(byte).ok_or_else(|| binascii_error(vm, "Illegal char"))?,
        };
        bits = (bits << 6) | value;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    if rest.any(|byte| !matches!(byte, b' ' | b'`' | b'\n' | b'\r')) {
        return Err(binascii_error(vm, "Trailing garbage"));
    }

    Ok(Value::Str(PyBytes::new_unshared(output)))
}

fn b2a_uu(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const LINE_LIMIT: usize = 45;

    let Some(data) = single_buffer(vm, args, "b2a_uu")? else {
        return Ok(Value::unknown("binascii.b2a_uu"));
    };
    let data = data.as_bytes();
    if data.len() > LINE_LIMIT {
        return Err(binascii_error(vm, "At most 45 bytes at once"));
    }

    let mut output = Vec::with_capacity(2 + data.len().div_ceil(3) * 4);
    output.push(b' ' + data.len() as u8);
    for group in data.chunks(3) {
        let word = group.iter().enumerate().fold(0u32, |word, (index, byte)| word | (u32::from(*byte) << (16 - 8 * index)));
        for shift in [18, 12, 6, 0] {
            output.push(b' ' + ((word >> shift) & 0x3f) as u8);
        }
    }
    output.push(b'\n');

    Ok(Value::Str(PyBytes::allocate(output)))
}

fn base64_value(byte: u8) -> Option<u32> {
    BASE64_ALPHABET.iter().position(|symbol| *symbol == byte).map(|index| index as u32)
}

/// Decodes base64, skipping characters outside the alphabet. A pad
/// character ends the data once a quantum holds at least two symbols and
/// the padding is complete.
fn a2b_base64(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "a2b_base64")? else {
        return Ok(Value::unknown("binascii.a2b_base64"));
    };
    let data = data.as_bytes();

    let is_significant = |byte: &u8| *byte == b'=' || base64_value(*byte).is_some();
    let mut output = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut bits: u32 = 0;
    let mut symbols: usize = 0;
    let mut padded = false;
    for (index, &byte) in data.iter().enumerate() {
        if byte == b'=' {
            let in_quantum = symbols % 4;
            let next_is_pad = data[index + 1..].iter().find(|byte| is_significant(byte)) == Some(&b'=');
            if in_quantum == 3 || (in_quantum == 2 && next_is_pad) {
                padded = true;
                break;
            }
            continue;
        }

        let Some(value) = base64_value(byte) else {
            continue;
        };
        bits = (bits << 6) | value;
        symbols += 1;
        let pending = (symbols * 6) % 8;
        if symbols % 4 != 1 {
            output.push((bits >> pending) as u8);
            bits &= (1 << pending) - 1;
        }
    }

    if !padded && !symbols.is_multiple_of(4) {
        return Err(binascii_error(vm, "Incorrect padding"));
    }

    Ok(Value::Str(PyBytes::new_unshared(output)))
}

fn b2a_base64(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "b2a_base64")? else {
        return Ok(Value::unknown("binascii.b2a_base64"));
    };
    let data = data.as_bytes();

    let mut output = Vec::with_capacity(data.len().div_ceil(3) * 4 + 1);
    for group in data.chunks(3) {
        let word = group.iter().enumerate().fold(0u32, |word, (index, byte)| word | (u32::from(*byte) << (16 - 8 * index)));
        for (position, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            let symbol = if position <= group.len() { BASE64_ALPHABET[((word >> shift) & 0x3f) as usize] } else { b'=' };
            output.push(symbol);
        }
    }
    output.push(b'\n');

    Ok(Value::Str(PyBytes::allocate(output)))
}

/// Decodes BinHex 4.0 text up to an optional `:` terminator, skipping line
/// ends. Returns the bytes and whether the terminator was seen.
fn a2b_hqx(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "a2b_hqx")? else {
        return Ok(Value::unknown("binascii.a2b_hqx"));
    };

    let mut output = Vec::with_capacity(data.as_bytes().len() * 3 / 4 + 1);
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    let mut terminated = false;
    for &byte in data.as_bytes() {
        if matches!(byte, b'\n' | b'\r') {
            continue;
        }
        if byte == b':' {
            terminated = true;
            break;
        }
        let Some(value) = HQX_ALPHABET.iter().position(|symbol| *symbol == byte) else {
            return Err(binascii_error(vm, "Illegal char"));
        };

        bits = (bits << 6) | value as u32;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    if bit_count != 0 && !terminated {
        return Err(binascii_incomplete(vm, "String has incomplete number of bytes"));
    }

    Ok(Value::tuple(vec![Value::Str(PyBytes::allocate(output)), Value::Int(i64::from(terminated))]))
}

/// Encodes BinHex 4.0 text; a partial final symbol is padded with zero
/// bits.
fn b2a_hqx(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "b2a_hqx")? else {
        return Ok(Value::unknown("binascii.b2a_hqx"));
    };
    let data = data.as_bytes();

    let total_bits = data.len() * 8;
    let symbol_at = |position: usize| -> u8 {
        let bit_of = |bit: usize| data.get(bit / 8).map_or(0, |byte| (byte >> (7 - bit % 8)) & 1);
        let value = (0..6).fold(0usize, |value, offset| (value << 1) | usize::from(bit_of(position * 6 + offset)));
        HQX_ALPHABET[value]
    };
    let output: Vec<u8> = (0..total_bits.div_ceil(6)).map(symbol_at).collect();

    Ok(Value::Str(PyBytes::allocate(output)))
}

/// BinHex run-length encoding: runs of four or more equal bytes become the
/// byte, the marker, and the run length; the marker itself is escaped.
fn rlecode_hqx(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const MAX_RUN: usize = 255;

    let Some(data) = single_buffer(vm, args, "rlecode_hqx")? else {
        return Ok(Value::unknown("binascii.rlecode_hqx"));
    };
    let data = data.as_bytes();

    let mut output = Vec::with_capacity(data.len() + data.len() / 2);
    let mut position = 0;
    while let Some(&byte) = data.get(position) {
        if byte == RUN_MARKER {
            output.extend_from_slice(&[RUN_MARKER, 0]);
            position += 1;
            continue;
        }

        let run = data[position..].iter().take(MAX_RUN).take_while(|other| **other == byte).count();
        if run >= 4 {
            output.extend_from_slice(&[byte, RUN_MARKER, run as u8]);
            position += run;
        } else {
            output.push(byte);
            position += 1;
        }
    }

    Ok(Value::Str(PyBytes::allocate(output)))
}

fn rledecode_hqx(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(data) = single_buffer(vm, args, "rledecode_hqx")? else {
        return Ok(Value::unknown("binascii.rledecode_hqx"));
    };
    let mut input = data.as_bytes().iter().copied();

    let mut output: Vec<u8> = Vec::with_capacity(data.as_bytes().len() * 2);
    while let Some(byte) = input.next() {
        if byte != RUN_MARKER {
            output.push(byte);
            continue;
        }

        let Some(count) = input.next() else {
            return Err(binascii_incomplete(vm, ""));
        };
        if count == 0 {
            output.push(RUN_MARKER);
            continue;
        }
        let Some(&repeated) = output.last() else {
            return Err(binascii_error(vm, "Orphaned RLE code at start"));
        };
        output.extend(std::iter::repeat_n(repeated, usize::from(count) - 1));
    }

    Ok(Value::Str(PyBytes::new_unshared(output)))
}

/// CRC-CCITT of the data from the start value. The checksum is 16 bits,
/// but empty data returns the start value as given.
fn crc_hqx(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    // CRC-CCITT as XMODEM uses it (polynomial 0x1021, most significant bit
    // first), one entry per byte value.
    const TABLE: [u16; 256] = crc_ccitt_table();

    if has_unknown(&args) {
        return Ok(Value::unknown("binascii.crc_hqx"));
    }

    let values = varargs(vm, args, "crc_hqx", "crc_hqx", 2, 2)?;
    let [data, start] = values.as_slice() else {
        return Ok(Value::unknown("binascii.crc_hqx"));
    };
    let data = data_argument(vm, data, "crc_hqx")?;
    let Some(start) = int_argument(vm, start)? else {
        return Ok(Value::unknown("binascii.crc_hqx"));
    };
    if data.as_bytes().is_empty() {
        return Ok(Value::Int(i64::from(start)));
    }

    let checksum = data.as_bytes().iter().fold(start as u16, |crc, byte| (crc << 8) ^ TABLE[usize::from((crc >> 8) as u8 ^ byte)]);

    Ok(Value::Int(i64::from(checksum)))
}

/// The CRC-32 of zlib and `binascii`, continuing from the checksum
/// `start`.
pub(super) fn crc32_update(start: u32, data: &[u8]) -> u32 {
    // CRC-32 (ISO 3309, ITU-T V.42) in its reflected form, one entry per
    // byte value.
    const TABLE: [u32; 256] = crc32_table();

    let register = data.iter().fold(!start, |register, byte| (register >> 8) ^ TABLE[usize::from(register as u8 ^ byte)]);

    !register
}

/// Arguments `(data[, start])` of a checksum function: the data and the
/// start value masked to 32 bits.
pub(super) fn checksum_arguments(vm: &Vm, args: CallArgs, function: &str, interface: BufferInterface, default: u32) -> PyResult<Option<(PyBytes, u32)>> {
    if has_unknown(&args) {
        return Ok(None);
    }

    let values = varargs(vm, args, function, function, 1, 2)?;
    let Some(data) = values.first() else {
        return Ok(None);
    };
    let data = buffer_argument(vm, data, function, interface)?;
    let start = match values.get(1) {
        Some(value) => unsigned_int_mask_argument(vm, value)?,
        None => Some(default),
    };

    Ok(start.map(|start| (data, start)))
}

/// The CRC-32 as a signed 32-bit integer.
fn crc32(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((data, start)) = checksum_arguments(vm, args, "crc32", BufferInterface::Any, 0)? else {
        return Ok(Value::unknown("binascii.crc32"));
    };

    Ok(Value::Int(i64::from(crc32_update(start, data.as_bytes()) as i32)))
}

/// Lower-case hexadecimal digits of `data`.
pub(crate) fn encode_hex(data: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    data.iter().flat_map(|byte| [DIGITS[usize::from(byte >> 4)], DIGITS[usize::from(byte & 0xf)]]).collect()
}

fn hex_encode(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    if has_unknown(&args) {
        return Ok(Value::unknown("binascii.b2a_hex"));
    }
    let values = varargs(vm, args, method, "b2a_hex", 1, 1)?;
    let Some(value) = values.first() else {
        return Ok(Value::unknown("binascii.b2a_hex"));
    };
    let data = data_argument(vm, value, "b2a_hex")?;

    Ok(Value::Str(PyBytes::new_unshared(encode_hex(data.as_bytes()))))
}

fn hexlify(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    hex_encode(vm, args, "hexlify")
}

fn b2a_hex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    hex_encode(vm, args, "b2a_hex")
}

/// The bytes that pairs of hexadecimal digits in `data` stand for.
pub(crate) fn decode_hex(vm: &Vm, data: &[u8]) -> PyResult<Vec<u8>> {
    if !data.len().is_multiple_of(2) {
        return Err(vm.type_error("Odd-length string"));
    }

    let digit = |byte: u8| char::from(byte).to_digit(16);
    let mut output = Vec::with_capacity(data.len() / 2);
    for pair in data.chunks_exact(2) {
        let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
            return Err(vm.type_error("Non-hexadecimal digit found"));
        };
        output.push(((high << 4) | low) as u8);
    }

    Ok(output)
}

fn hex_decode(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    if has_unknown(&args) {
        return Ok(Value::unknown("binascii.a2b_hex"));
    }
    let values = varargs(vm, args, method, "a2b_hex", 1, 1)?;
    let Some(value) = values.first() else {
        return Ok(Value::unknown("binascii.a2b_hex"));
    };
    let data = data_argument(vm, value, "a2b_hex")?;

    Ok(Value::Str(PyBytes::new_unshared(decode_hex(vm, data.as_bytes())?)))
}

fn unhexlify(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    hex_decode(vm, args, "unhexlify")
}

fn a2b_hex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    hex_decode(vm, args, "a2b_hex")
}

/// A converted argument of the quoted-printable functions.
enum QpArgument {
    Data(PyBytes),
    /// An integer option; `None` when it is unknown.
    Flag(Option<i32>),
}

/// The data and integer options of a quoted-printable function, by keyword
/// or position; options left out read as `defaults`. `None` when an
/// argument is unknown.
fn qp_arguments(vm: &Vm, args: CallArgs, names: &[&str], defaults: &[i32]) -> PyResult<Option<(PyBytes, Vec<i32>)>> {
    if has_unknown(&args) {
        return Ok(None);
    }

    // The argument format has no function name, so errors say `function`.
    let slots = parse_with(vm, args, "", names, 1, |vm, index, value| {
        if index == 0 {
            return Ok(QpArgument::Data(data_argument(vm, &value, "")?));
        }
        int_argument(vm, &value).map(QpArgument::Flag)
    })?;

    let mut data = None;
    let mut flags = defaults.to_vec();
    for (index, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(QpArgument::Data(bytes)) => data = Some(bytes),
            Some(QpArgument::Flag(Some(flag))) => {
                if let Some(target) = flags.get_mut(index - 1) {
                    *target = flag;
                }
            }
            Some(QpArgument::Flag(None)) => return Ok(None),
            None => {}
        }
    }

    Ok(data.map(|data| (data, flags)))
}

/// Decodes quoted-printable text (RFC 2045). `=XX` with two hex digits is
/// a byte, `=` before a line end or at the end is a soft line break, and
/// in headers `_` is a space. Other `=` sequences pass through.
fn a2b_qp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((data, flags)) = qp_arguments(vm, args, &["data", "header"], &[0])? else {
        return Ok(Value::unknown("binascii.a2b_qp"));
    };
    let header = flags.first().is_some_and(|flag| *flag != 0);
    let data = data.as_bytes();

    let hex = |byte: Option<&u8>| byte.and_then(|byte| char::from(*byte).to_digit(16));
    let mut output = Vec::with_capacity(data.len());
    let mut position = 0;
    while let Some(&byte) = data.get(position) {
        position += 1;
        if byte == b'_' && header {
            output.push(b' ');
            continue;
        }
        if byte != b'=' {
            output.push(byte);
            continue;
        }

        match data.get(position) {
            None | Some(b'\n') => position += 1,
            // A carriage return starts a soft break that runs through the
            // next line feed.
            Some(b'\r') => {
                position = match data[position..].iter().position(|byte| *byte == b'\n') {
                    Some(offset) => position + offset + 1,
                    None => data.len(),
                };
            }
            Some(b'=') => {
                output.push(b'=');
                position += 1;
            }
            next => match (hex(next), hex(data.get(position + 1))) {
                (Some(high), Some(low)) => {
                    output.push(((high << 4) | low) as u8);
                    position += 2;
                }
                _ => output.push(b'='),
            },
        }
    }

    Ok(Value::Str(PyBytes::new(output)))
}

/// The quoted-printable encoder's output and line state.
struct QpWriter {
    output: Vec<u8>,
    line_length: usize,
    line_end: &'static [u8],
}

impl QpWriter {
    const LINE_LIMIT: usize = 76;

    fn soft_break(&mut self) {
        self.output.push(b'=');
        self.output.extend_from_slice(self.line_end);
        self.line_length = 0;
    }

    fn escape(&mut self, byte: u8) {
        const DIGITS: &[u8; 16] = b"0123456789ABCDEF";

        self.output.extend_from_slice(&[b'=', DIGITS[usize::from(byte >> 4)], DIGITS[usize::from(byte & 0xf)]]);
    }

    fn hard_break(&mut self) {
        self.output.extend_from_slice(self.line_end);
        self.line_length = 0;
    }
}

/// Encodes quoted-printable text (RFC 2045) with lines of at most 76
/// characters. In text mode line ends stay line ends, in the style of the
/// first one; `quotetabs` escapes all spaces and tabs; `header` writes
/// spaces as `_`.
fn b2a_qp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((data, flags)) = qp_arguments(vm, args, &["data", "quotetabs", "istext", "header"], &[0, 1, 0])? else {
        return Ok(Value::unknown("binascii.b2a_qp"));
    };
    let [quote_tabs, is_text, header] = [0, 1, 2].map(|index| flags.get(index).is_some_and(|flag| *flag != 0));
    let data = data.as_bytes();

    let crlf = data.iter().position(|byte| *byte == b'\n').is_some_and(|index| index > 0 && data[index - 1] == b'\r');
    let mut writer = QpWriter { output: Vec::with_capacity(data.len() * 2), line_length: 0, line_end: if crlf { b"\r\n" } else { b"\n" } };
    let mut position = 0;
    while let Some(&byte) = data.get(position) {
        let next = data.get(position + 1).copied();
        let line_end_length = match (byte, next) {
            (b'\n', _) => Some(1),
            (b'\r', Some(b'\n')) => Some(2),
            _ => None,
        };

        let escaped = byte > 126
            || byte == b'='
            || (header && byte == b'_')
            || (byte == b'.' && writer.line_length == 0 && matches!(next, None | Some(b'\n' | b'\r' | 0)))
            || (!is_text && matches!(byte, b'\r' | b'\n'))
            || (matches!(byte, b'\t' | b' ') && next.is_none())
            || (byte < 33 && !matches!(byte, b'\r' | b'\n') && (quote_tabs || !matches!(byte, b'\t' | b' ')));
        if escaped {
            if writer.line_length + 3 >= QpWriter::LINE_LIMIT {
                writer.soft_break();
            }
            writer.escape(byte);
            writer.line_length += 3;
            position += 1;
            continue;
        }

        if is_text && let Some(length) = line_end_length {
            // Whitespace that would end the line is escaped in place.
            if let Some(&last @ (b' ' | b'\t')) = writer.output.last() {
                writer.output.pop();
                writer.escape(last);
            }
            writer.hard_break();
            position += length;
            continue;
        }

        if next.is_some() && next != Some(b'\n') && writer.line_length + 1 >= QpWriter::LINE_LIMIT {
            writer.soft_break();
        }
        writer.output.push(if header && byte == b' ' { b'_' } else { byte });
        writer.line_length += 1;
        position += 1;
    }

    Ok(Value::Str(PyBytes::new(writer.output)))
}
