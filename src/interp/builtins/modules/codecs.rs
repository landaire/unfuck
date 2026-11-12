//! `_codecs` over the codec registry and the codecs of the narrow Windows
//! build.

pub mod args;
pub mod charmap;
pub mod errors;
pub mod registry;
pub mod unicode;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::codecs::args::first_unknown;
use crate::interp::builtins::modules::codecs::args::index_value;
use crate::interp::builtins::modules::codecs::args::varargs;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::unicode::ByteOrder;
use crate::interp::builtins::modules::codecs::unicode::Decoded;
use crate::interp::builtins::modules::codecs::unicode::Ucs1;
use crate::interp::builtins::text::codecs::Codec;
use crate::interp::builtins::text::codecs::decoded_text;
use crate::interp::builtins::text::codecs::encoded_string;
use crate::interp::builtins::text::codecs::escape_decoded_string;
use crate::interp::builtins::text::codecs::resized_text;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The default encoding.
const DEFAULT_ENCODING: &str = "ascii";

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const FUNCTIONS: &[MethodSpec] = &[
        function("register", codec_register),
        function("lookup", codec_lookup),
        function("encode", codec_encode),
        function("decode", codec_decode),
        function("escape_encode", escape_encode),
        function("escape_decode", escape_decode),
        function("utf_8_encode", utf_8_encode),
        function("utf_8_decode", utf_8_decode),
        function("utf_16_encode", utf_16_encode),
        function("utf_16_le_encode", utf_16_le_encode),
        function("utf_16_be_encode", utf_16_be_encode),
        function("utf_16_decode", utf_16_decode),
        function("utf_16_le_decode", utf_16_le_decode),
        function("utf_16_be_decode", utf_16_be_decode),
        function("utf_16_ex_decode", utf_16_ex_decode),
        function("utf_32_encode", utf_32_encode),
        function("utf_32_le_encode", utf_32_le_encode),
        function("utf_32_be_encode", utf_32_be_encode),
        function("utf_32_decode", utf_32_decode),
        function("utf_32_le_decode", utf_32_le_decode),
        function("utf_32_be_decode", utf_32_be_decode),
        function("utf_32_ex_decode", utf_32_ex_decode),
        function("unicode_escape_encode", unicode_escape_encode),
        function("unicode_escape_decode", unicode_escape_decode),
        function("unicode_internal_encode", unicode_internal_encode),
        function("unicode_internal_decode", unicode_internal_decode),
        function("raw_unicode_escape_encode", raw_unicode_escape_encode),
        function("raw_unicode_escape_decode", raw_unicode_escape_decode),
        function("latin_1_encode", latin_1_encode),
        function("latin_1_decode", latin_1_decode),
        function("ascii_encode", ascii_encode),
        function("ascii_decode", ascii_decode),
        function("charmap_encode", charmap_encode),
        function("charmap_decode", charmap_decode),
        function("charmap_build", charmap_build),
        function("readbuffer_encode", readbuffer_encode),
        function("charbuffer_encode", charbuffer_encode),
        function("mbcs_encode", mbcs_encode),
        function("mbcs_decode", mbcs_decode),
        function("register_error", register_error),
        function("lookup_error", lookup_error),
    ];

    install_functions(vm, module, FUNCTIONS)
}

/// A codec result and the length it consumed.
fn codec_tuple(value: Value, consumed: usize) -> Value {
    Value::tuple(vec![value, index_value(consumed)])
}

/// The unicode object a decoder of `codec` returns for `input`; `None` is
/// a UTF-32 decoder, which allocates a unit per four bytes plus one per
/// surrogate pair before resizing.
fn decoded_value(codec: Option<Codec>, input: &[u8], units: Vec<u16>) -> Value {
    let text = match codec {
        Some(codec) => decoded_text(codec, input, units),
        None => {
            let pairs = units.iter().filter(|unit| (0xD800..0xDC00).contains(*unit)).count();
            resized_text(input.len().div_ceil(4) + pairs, units)
        }
    };

    Value::Unicode(text)
}

/// The `z` errors argument at `index`.
fn errors_argument(vm: &Vm, function: &str, args: &[Value], index: usize) -> PyResult<Option<PyBytes>> {
    args::optional_string(vm, function, index + 1, args.get(index))
}

/// An optional `i` argument at `index`.
fn int_argument(vm: &Vm, args: &[Value], index: usize, default: i32) -> PyResult<i32> {
    match args.get(index) {
        Some(value) => args::c_int(vm, value),
        None => Ok(default),
    }
}

fn codec_register(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let function = args::single(vm, args, "register")?;
    registry::register(vm, function)?;

    Ok(Value::None)
}

fn codec_lookup(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "lookup", 1, 1)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let encoding = args::c_string(vm, "lookup", 1, &args[0])?;

    registry::lookup(vm, encoding.as_bytes())
}

/// Which half of a codec an encode or decode call uses.
#[derive(Clone, Copy)]
pub enum Direction {
    Encode,
    Decode,
}

/// Registry encoding and decoding for `encode(obj[, encoding[, errors]])`
/// and `decode`.
fn registry_codec(vm: &Vm, args: CallArgs, direction: Direction) -> PyResult<Value> {
    let function = match direction {
        Direction::Encode => "encode",
        Direction::Decode => "decode",
    };
    let args = varargs(vm, args, function, 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let encoding = match args.get(1) {
        Some(value) => args::c_string(vm, function, 2, value)?,
        None => PyBytes::from(DEFAULT_ENCODING),
    };
    let errors = args.get(2).map(|value| args::c_string(vm, function, 3, value)).transpose()?;

    code_with_registry(vm, encoding.as_bytes(), args[0].clone(), errors.as_ref().map(PyBytes::as_bytes), direction)
}

/// Runs the registry's codec for `encoding` on `input`. `errors` `None`
/// passes no errors argument.
pub fn code_with_registry(vm: &Vm, encoding: &[u8], input: Value, errors: Option<&[u8]>, direction: Direction) -> PyResult<Value> {
    let (index, message) = match direction {
        Direction::Encode => (0, "encoder must return a tuple (object,integer)"),
        Direction::Decode => (1, "decoder must return a tuple (object,integer)"),
    };

    let codec = registry::lookup(vm, encoding)?;
    let Some(coder) = vm.as_tuple(&codec).and_then(|items| items.get(index).cloned()) else {
        return Ok(codec);
    };

    let mut call_args = vec![input];
    call_args.extend(errors.map(|errors| Value::Str(PyBytes::new(errors))));
    let result = vm.call(&coder, CallArgs::new(call_args))?;
    if result.is_unknown() {
        return Ok(result);
    }

    match vm.as_tuple(&result).as_deref() {
        Some([value, _]) => Ok(value.clone()),
        _ => Err(vm.type_error(message)),
    }
}

fn codec_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    registry_codec(vm, args, Direction::Encode)
}

fn codec_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    registry_codec(vm, args, Direction::Decode)
}

/// `escape_decode(data[, errors])`: the string escape decoder.
fn escape_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "escape_decode", 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::read_buffer(vm, "escape_decode", 1, &args[0])?;
    let errors = Errors::new(vm, errors_argument(vm, "escape_decode", &args, 1)?);
    let decoded = unicode::decode_string_escape(data.as_bytes(), &errors)?;

    Ok(codec_tuple(Value::Str(escape_decoded_string(data.as_bytes().len(), decoded)), data.as_bytes().len()))
}

/// `escape_encode(str[, errors])`: the repr of a `str` without quotes.
fn escape_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "escape_encode", 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::exact_string(vm, "escape_encode", 1, &args[0])?;
    errors_argument(vm, "escape_encode", &args, 1)?;

    Ok(codec_tuple(Value::Str(PyBytes::allocate(unicode::encode_string_escape(data.as_bytes()))), data.as_bytes().len()))
}

type StatefulDecoder = fn(&[u8], bool, &mut Errors<'_>) -> PyResult<Decoded>;

/// The `s*|zi` decoders with a `final` flag. Without it, an incomplete
/// sequence at the end stays unconsumed.
fn decode_stateful(vm: &Vm, args: CallArgs, function: &str, codec: Option<Codec>, decoder: StatefulDecoder) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::string_or_buffer(vm, function, 1, &args[0])?;
    let mut errors = Errors::new(vm, errors_argument(vm, function, &args, 1)?);
    let is_final = int_argument(vm, &args, 2, 0)? != 0;
    let decoded = decoder(data.as_bytes(), is_final, &mut errors)?;

    Ok(codec_tuple(decoded_value(codec, data.as_bytes(), decoded.units), decoded.consumed))
}

type PlainDecoder = fn(&[u8], &mut Errors<'_>) -> PyResult<Vec<u16>>;

/// The `s*|z` decoders, which consume their whole input.
fn decode_plain(vm: &Vm, args: CallArgs, function: &str, codec: Codec, decoder: PlainDecoder) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::string_or_buffer(vm, function, 1, &args[0])?;
    let mut errors = Errors::new(vm, errors_argument(vm, function, &args, 1)?);
    let units = decoder(data.as_bytes(), &mut errors)?;

    Ok(codec_tuple(decoded_value(Some(codec), data.as_bytes(), units), data.as_bytes().len()))
}

type PlainEncoder = fn(&[u16], &mut Errors<'_>) -> PyResult<Vec<u8>>;

/// The `O|z` encoders of text coerced to unicode. `codec` is `None` for the
/// UTF-32 encoders, which fill a string of the exact size.
fn encode_plain(vm: &Vm, args: CallArgs, function: &str, codec: Option<Codec>, encoder: PlainEncoder) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let mut errors = Errors::new(vm, errors_argument(vm, function, &args, 1)?);
    let text = args::to_unicode(vm, &args[0])?;
    let encoded = encoder(text.units(), &mut errors)?;
    let string = match codec {
        Some(codec) => encoded_string(codec, text.units().len(), encoded),
        None => PyBytes::new_unshared(encoded),
    };

    Ok(codec_tuple(Value::Str(string), text.units().len()))
}

/// The `O|zi` encoders taking a byte order.
fn encode_ordered(vm: &Vm, args: CallArgs, function: &str, encoder: fn(&[u16], ByteOrder) -> Vec<u8>) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    errors_argument(vm, function, &args, 1)?;
    let order = ByteOrder(int_argument(vm, &args, 2, 0)?);
    let text = args::to_unicode(vm, &args[0])?;

    Ok(codec_tuple(Value::Str(PyBytes::new_unshared(encoder(text.units(), order))), text.units().len()))
}

type OrderedDecoder = fn(&[u8], ByteOrder, bool, &mut Errors<'_>) -> PyResult<(Decoded, ByteOrder)>;

/// The `s*|zii` decoders that also report the byte order in effect.
fn decode_reporting_order(vm: &Vm, args: CallArgs, function: &str, codec: Option<Codec>, decoder: OrderedDecoder) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 4)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::string_or_buffer(vm, function, 1, &args[0])?;
    let mut errors = Errors::new(vm, errors_argument(vm, function, &args, 1)?);
    let order = ByteOrder(int_argument(vm, &args, 2, 0)?);
    let is_final = int_argument(vm, &args, 3, 0)? != 0;
    let (decoded, order) = decoder(data.as_bytes(), order, is_final, &mut errors)?;

    Ok(Value::tuple(vec![decoded_value(codec, data.as_bytes(), decoded.units), index_value(decoded.consumed), Value::Int(i64::from(order.0))]))
}

fn utf_8_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "utf_8_encode", Some(Codec::Utf8), |input, _| Ok(unicode::encode_utf8(input)))
}

fn utf_8_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_8_decode", Some(Codec::Utf8), unicode::decode_utf8)
}

fn utf_16_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_ordered(vm, args, "utf_16_encode", unicode::encode_utf16)
}

fn utf_16_le_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "utf_16_le_encode", Some(Codec::Utf16Le), |input, _| Ok(unicode::encode_utf16(input, ByteOrder::LITTLE)))
}

fn utf_16_be_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "utf_16_be_encode", Some(Codec::Utf16Be), |input, _| Ok(unicode::encode_utf16(input, ByteOrder::BIG)))
}

fn utf_16_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_16_decode", Some(Codec::Utf16), |input, is_final, errors| Ok(unicode::decode_utf16(input, ByteOrder::NATIVE, is_final, errors)?.0))
}

fn utf_16_le_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_16_le_decode", Some(Codec::Utf16Le), |input, is_final, errors| Ok(unicode::decode_utf16(input, ByteOrder::LITTLE, is_final, errors)?.0))
}

fn utf_16_be_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_16_be_decode", Some(Codec::Utf16Be), |input, is_final, errors| Ok(unicode::decode_utf16(input, ByteOrder::BIG, is_final, errors)?.0))
}

fn utf_16_ex_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_reporting_order(vm, args, "utf_16_ex_decode", Some(Codec::Utf16), unicode::decode_utf16)
}

fn utf_32_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_ordered(vm, args, "utf_32_encode", unicode::encode_utf32)
}

fn utf_32_le_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "utf_32_le_encode", None, |input, _| Ok(unicode::encode_utf32(input, ByteOrder::LITTLE)))
}

fn utf_32_be_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "utf_32_be_encode", None, |input, _| Ok(unicode::encode_utf32(input, ByteOrder::BIG)))
}

fn utf_32_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_32_decode", None, |input, is_final, errors| Ok(unicode::decode_utf32(input, ByteOrder::NATIVE, is_final, errors)?.0))
}

fn utf_32_le_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_32_le_decode", None, |input, is_final, errors| Ok(unicode::decode_utf32(input, ByteOrder::LITTLE, is_final, errors)?.0))
}

fn utf_32_be_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_stateful(vm, args, "utf_32_be_decode", None, |input, is_final, errors| Ok(unicode::decode_utf32(input, ByteOrder::BIG, is_final, errors)?.0))
}

fn utf_32_ex_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_reporting_order(vm, args, "utf_32_ex_decode", None, unicode::decode_utf32)
}

fn unicode_escape_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "unicode_escape_encode", Some(Codec::UnicodeEscape), |input, _| Ok(unicode::encode_unicode_escape(input)))
}

fn unicode_escape_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_plain(vm, args, "unicode_escape_decode", Codec::UnicodeEscape, unicode::decode_unicode_escape)
}

/// `unicode_internal_encode(obj[, errors])`: the UTF-16 units of a
/// `unicode`, or the bytes of a buffer.
fn unicode_internal_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "unicode_internal_encode", 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    errors_argument(vm, "unicode_internal_encode", &args, 1)?;
    if let Some(text) = vm.as_text(&args[0]) {
        return Ok(codec_tuple(Value::Str(PyBytes::new(unicode::encode_unicode_internal(text.units()))), text.units().len()));
    }
    let Some(bytes) = vm.as_str_bytes(&args[0]) else {
        return Err(vm.type_error("expected a readable buffer object"));
    };

    Ok(codec_tuple(Value::Str(PyBytes::new(bytes.as_bytes())), bytes.as_bytes().len()))
}

/// `unicode_internal_decode(obj[, errors])`: a `unicode` passes through.
fn unicode_internal_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "unicode_internal_decode", 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let mut errors = Errors::new(vm, errors_argument(vm, "unicode_internal_decode", &args, 1)?);
    if let Some(text) = vm.as_text(&args[0]) {
        return Ok(codec_tuple(args[0].clone(), text.units().len()));
    }
    let Some(bytes) = vm.as_str_bytes(&args[0]) else {
        return Err(vm.type_error("expected a readable buffer object"));
    };
    let units = unicode::decode_unicode_internal(bytes.as_bytes(), &mut errors)?;

    // The `unicode_internal` decoder allocates a unit per two bytes.
    Ok(codec_tuple(Value::Unicode(resized_text(bytes.as_bytes().len().div_ceil(2), units)), bytes.as_bytes().len()))
}

fn raw_unicode_escape_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "raw_unicode_escape_encode", Some(Codec::RawUnicodeEscape), |input, _| Ok(unicode::encode_raw_unicode_escape(input)))
}

fn raw_unicode_escape_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_plain(vm, args, "raw_unicode_escape_decode", Codec::RawUnicodeEscape, unicode::decode_raw_unicode_escape)
}

fn latin_1_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "latin_1_encode", Some(Codec::Latin1), |input, errors| unicode::encode_ucs1(input, Ucs1::Latin1, errors))
}

fn latin_1_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_plain(vm, args, "latin_1_decode", Codec::Latin1, |input, _| Ok(unicode::decode_latin1(input)))
}

fn ascii_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    encode_plain(vm, args, "ascii_encode", Some(Codec::Ascii), |input, errors| unicode::encode_ucs1(input, Ucs1::Ascii, errors))
}

fn ascii_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    decode_plain(vm, args, "ascii_decode", Codec::Ascii, unicode::decode_ascii)
}

/// `charmap_encode(str[, errors[, mapping]])`; no mapping means Latin-1.
fn charmap_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "charmap_encode", 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let mut errors = Errors::new(vm, errors_argument(vm, "charmap_encode", &args, 1)?);
    let text = args::to_unicode(vm, &args[0])?;
    let encoded = match args.get(2).filter(|mapping| !mapping.is_none()) {
        Some(mapping) => charmap::encode(vm, text.units(), mapping, &mut errors)?,
        None => unicode::encode_ucs1(text.units(), Ucs1::Latin1, &mut errors)?,
    };

    // The charmap encoder resizes its output as the Latin-1 encoder does.
    Ok(codec_tuple(Value::Str(encoded_string(Codec::Latin1, text.units().len(), encoded)), text.units().len()))
}

/// `charmap_decode(data[, errors[, mapping]])`; no mapping means Latin-1.
fn charmap_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "charmap_decode", 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::string_or_buffer(vm, "charmap_decode", 1, &args[0])?;
    let mut errors = Errors::new(vm, errors_argument(vm, "charmap_decode", &args, 1)?);
    // Without a mapping the charmap decoder is the Latin-1 decoder.
    let text = match args.get(2).filter(|mapping| !mapping.is_none()) {
        Some(mapping) => resized_text(data.as_bytes().len(), charmap::decode(vm, data.as_bytes(), mapping, &mut errors)?),
        None => decoded_text(Codec::Latin1, data.as_bytes(), unicode::decode_latin1(data.as_bytes())),
    };

    Ok(codec_tuple(Value::Unicode(text), data.as_bytes().len()))
}

/// `charmap_build(decoding_table)`.
fn charmap_build(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "charmap_build", 1, 1)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let Some(table) = vm.as_text(&args[0]) else {
        return Err(vm.type_error(&format!("charmap_build() argument 1 must be unicode, not {}", args::type_name(vm, &args[0]))));
    };

    charmap::build(vm, table.units())
}

/// The `s#|z` / `t#|z` buffer "encoders", which copy their input.
fn buffer_encode(vm: &Vm, args: CallArgs, function: &str, convert: fn(&Vm, &str, usize, &Value) -> PyResult<PyBytes>) -> PyResult<Value> {
    let args = varargs(vm, args, function, 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let data = convert(vm, function, 1, &args[0])?;
    errors_argument(vm, function, &args, 1)?;
    let length = data.as_bytes().len();

    Ok(codec_tuple(Value::Str(data), length))
}

fn readbuffer_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    buffer_encode(vm, args, "readbuffer_encode", args::read_buffer)
}

fn charbuffer_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    buffer_encode(vm, args, "charbuffer_encode", args::character_buffer)
}

/// `mbcs_encode(str[, errors])`: the result depends on the ANSI code page
/// of the host.
fn mbcs_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "mbcs_encode", 1, 2)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    errors_argument(vm, "mbcs_encode", &args, 1)?;
    args::to_unicode(vm, &args[0])?;

    Ok(Value::unknown("mbcs_encode depends on the host ANSI code page"))
}

/// `mbcs_decode(data[, errors[, final]])`: the result depends on the ANSI
/// code page of the host.
fn mbcs_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "mbcs_decode", 1, 3)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    args::string_or_buffer(vm, "mbcs_decode", 1, &args[0])?;
    errors_argument(vm, "mbcs_decode", &args, 1)?;
    int_argument(vm, &args, 2, 0)?;

    Ok(Value::unknown("mbcs_decode depends on the host ANSI code page"))
}

fn register_error(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "register_error", 2, 2)?;
    if let Some(unknown) = args.first().filter(|name| name.is_unknown()) {
        return Ok(unknown.clone());
    }

    let name = args::c_string(vm, "register_error", 1, &args[0])?;
    registry::register_error(vm, name.as_bytes(), args[1].clone())?;

    Ok(Value::None)
}

fn lookup_error(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = varargs(vm, args, "lookup_error", 1, 1)?;
    if let Some(unknown) = first_unknown(&args) {
        return Ok(unknown);
    }

    let name = args::c_string(vm, "lookup_error", 1, &args[0])?;

    registry::lookup_error(vm, name.as_bytes())
}
