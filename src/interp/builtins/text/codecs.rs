//! The codecs `str.decode`, `unicode.encode`, `unicode(x, encoding)`, and
//! the default encoding reach, resolved by name and run by the `_codecs`
//! implementations.

use std::rc::Rc;

use crate::interp::builtins::modules::binascii;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::unicode;
use crate::interp::builtins::modules::codecs::unicode::ByteOrder;
use crate::interp::builtins::modules::codecs::unicode::Ucs1;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Ascii,
    Latin1,
    Utf8,
    Utf16,
    Utf16Le,
    Utf16Be,
    UnicodeEscape,
    RawUnicodeEscape,
    StringEscape,
    Hex,
}

impl Codec {
    /// Resolves an encoding name as `codecs.lookup` does: lowercase, then
    /// `encodings.normalize_encoding`, then the alias table.
    pub fn lookup(name: &[u8]) -> Option<Self> {
        let mut normalized = String::with_capacity(name.len());
        let mut separated = false;
        for &byte in name {
            let byte = byte.to_ascii_lowercase();
            if !byte.is_ascii_alphanumeric() && byte != b'.' {
                separated = true;
                continue;
            }
            if separated && !normalized.is_empty() {
                normalized.push('_');
            }
            separated = false;
            normalized.push(char::from(byte));
        }

        Self::from_normalized(&normalized).or_else(|| Self::from_normalized(&normalized.replace('.', "_")))
    }

    fn from_normalized(name: &str) -> Option<Self> {
        let codec = match name {
            "ascii" | "646" | "ansi_x3.4_1968" | "ansi_x3_4_1968" | "ansi_x3.4_1986" | "cp367" | "csascii" | "ibm367" | "iso646_us" | "iso_646.irv_1991" | "iso_ir_6" | "us" | "us_ascii" => Self::Ascii,
            "latin_1" | "8859" | "cp819" | "csisolatin1" | "ibm819" | "iso8859" | "iso8859_1" | "iso_8859_1" | "iso_8859_1_1987" | "iso_ir_100" | "l1" | "latin" | "latin1" => Self::Latin1,
            "utf_8" | "u8" | "utf" | "utf8" | "utf8_ucs2" | "utf8_ucs4" => Self::Utf8,
            "utf_16" | "u16" | "utf16" => Self::Utf16,
            "utf_16_le" | "unicodelittleunmarked" | "utf_16le" => Self::Utf16Le,
            "utf_16_be" | "unicodebigunmarked" | "utf_16be" => Self::Utf16Be,
            "unicode_escape" => Self::UnicodeEscape,
            "raw_unicode_escape" => Self::RawUnicodeEscape,
            "string_escape" => Self::StringEscape,
            "hex_codec" | "hex" => Self::Hex,
            _ => return None,
        };

        Some(codec)
    }

    /// Whether the codec maps bytes to bytes rather than between bytes and
    /// unicode.
    pub fn is_bytes_codec(self) -> bool {
        matches!(self, Self::StringEscape | Self::Hex)
    }
}

/// Decodes with the default encoding (`sys.getdefaultencoding()`), raising
/// a fully populated `UnicodeDecodeError`.
pub fn decode_default(vm: &Vm, input: &[u8]) -> PyResult<PyText> {
    crate::interp::builtins::modules::codecs::args::decode_default(vm, &PyBytes::new(input))
}

/// Encodes with the default encoding, raising a fully populated
/// `UnicodeEncodeError`.
pub fn encode_default(vm: &Vm, input: &[u16]) -> PyResult<PyBytes> {
    crate::interp::builtins::modules::codecs::args::encode_default(vm, &PyText::new(input))
}

/// Decodes bytes with a unicode codec, as its `_codecs` decoder does with
/// a final chunk.
pub fn decode_units(vm: &Vm, codec: Codec, input: &[u8], errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    match codec {
        Codec::Ascii => unicode::decode_ascii(input, errors),
        Codec::Latin1 => Ok(unicode::decode_latin1(input)),
        Codec::Utf8 => Ok(unicode::decode_utf8(input, true, errors)?.units),
        Codec::Utf16 => Ok(unicode::decode_utf16(input, ByteOrder::NATIVE, true, errors)?.0.units),
        Codec::Utf16Le => Ok(unicode::decode_utf16(input, ByteOrder::LITTLE, true, errors)?.0.units),
        Codec::Utf16Be => Ok(unicode::decode_utf16(input, ByteOrder::BIG, true, errors)?.0.units),
        Codec::UnicodeEscape => unicode::decode_unicode_escape(input, errors),
        Codec::RawUnicodeEscape => unicode::decode_raw_unicode_escape(input, errors),
        Codec::StringEscape | Codec::Hex => Err(vm.type_error("decoder did not return an unicode object (type=str)")),
    }
}

/// Encodes unicode with a unicode codec.
pub fn encode_units(vm: &Vm, codec: Codec, input: &[u16], errors: &mut Errors<'_>) -> PyResult<Vec<u8>> {
    match codec {
        Codec::Ascii => unicode::encode_ucs1(input, Ucs1::Ascii, errors),
        Codec::Latin1 => unicode::encode_ucs1(input, Ucs1::Latin1, errors),
        Codec::Utf8 => Ok(unicode::encode_utf8(input)),
        Codec::Utf16 => Ok(unicode::encode_utf16(input, ByteOrder::NATIVE)),
        Codec::Utf16Le => Ok(unicode::encode_utf16(input, ByteOrder::LITTLE)),
        Codec::Utf16Be => Ok(unicode::encode_utf16(input, ByteOrder::BIG)),
        Codec::UnicodeEscape => Ok(unicode::encode_unicode_escape(input)),
        Codec::RawUnicodeEscape => Ok(unicode::encode_raw_unicode_escape(input)),
        Codec::StringEscape | Codec::Hex => Err(vm.type_error("encoder did not return a string/unicode object")),
    }
}

/// Decodes bytes with `codec`. Unicode codecs produce `unicode`; bytes
/// codecs produce `str`. `errors` `None` means 'strict'.
pub fn decode(vm: &Vm, codec: Codec, input: &[u8], errors: Option<&[u8]>) -> PyResult<Value> {
    let mut errors = Errors::new(vm, errors.map(PyBytes::new));

    match codec {
        Codec::StringEscape => Ok(Value::Str(escape_decoded_string(input.len(), unicode::decode_string_escape(input, &errors)?))),
        Codec::Hex => {
            require_strict(vm, errors.name())?;
            Ok(Value::Str(PyBytes::new_unshared(binascii::decode_hex(vm, input)?)))
        }
        _ => Ok(Value::Unicode(decoded_text(codec, input, decode_units(vm, codec, input, &mut errors)?))),
    }
}

/// Encodes unicode with `codec`.
pub fn encode(vm: &Vm, codec: Codec, input: &[u16], errors: Option<&[u8]>) -> PyResult<Value> {
    let mut errors = Errors::new(vm, errors.map(PyBytes::new));

    match codec {
        Codec::StringEscape => Err(vm.type_error("escape_encode() argument 1 must be string, not unicode")),
        Codec::Hex => {
            require_strict(vm, errors.name())?;
            let bytes = encode_default(vm, input)?;
            Ok(Value::Str(PyBytes::new_unshared(binascii::encode_hex(bytes.as_bytes()))))
        }
        _ => {
            let encoded = encode_units(vm, codec, input, &mut errors)?;

            Ok(Value::Str(encoded_string(codec, input.len(), encoded)))
        }
    }
}

/// Encodes a byte string with a bytes codec; unicode codecs first decode it
/// with the default encoding, as the codec functions coerce their input.
pub fn encode_bytes(vm: &Vm, codec: Codec, input: &[u8], errors: Option<&[u8]>) -> PyResult<Value> {
    match codec {
        Codec::StringEscape => Ok(Value::Str(PyBytes::allocate(unicode::encode_string_escape(input)))),
        Codec::Hex => {
            require_strict(vm, errors)?;
            Ok(Value::Str(PyBytes::new_unshared(binascii::encode_hex(input))))
        }
        _ => {
            let text = decode_default(vm, input)?;
            encode(vm, codec, text.units(), errors)
        }
    }
}

/// The string object a unicode encoder returns for `input_len` code units:
/// the UTF-8 encoder copies short output from a stack buffer, and the
/// others fill a string they allocate, shrinking or growing it when the
/// output length differs from the estimate.
pub fn encoded_string(codec: Codec, input_len: usize, encoded: Vec<u8>) -> PyBytes {
    const MAX_SHORT_UNICHARS: usize = 300;

    let resized = match codec {
        Codec::Utf8 if input_len <= MAX_SHORT_UNICHARS => return PyBytes::new(encoded),
        Codec::Utf8 | Codec::UnicodeEscape => true,
        Codec::RawUnicodeEscape => input_len > 0,
        Codec::Ascii | Codec::Latin1 => encoded.len() != input_len,
        Codec::Utf16 | Codec::Utf16Le | Codec::Utf16Be | Codec::StringEscape | Codec::Hex => false,
    };

    if resized { PyBytes::allocate(encoded) } else { PyBytes::new_unshared(encoded) }
}

/// The string the escape decoder returns: it shrinks its buffer when
/// escapes collapse.
pub fn escape_decoded_string(input_len: usize, decoded: Vec<u8>) -> PyBytes {
    if decoded.len() < input_len { PyBytes::allocate(decoded) } else { PyBytes::new_unshared(decoded) }
}

/// The unicode object a decoder returns. The ASCII and Latin-1 decoders
/// share a one-byte input's character and Latin-1 fills an exact-size
/// object; the others allocate one unit per input byte and resize.
pub fn decoded_text(codec: Codec, input: &[u8], units: Vec<u16>) -> PyText {
    match (codec, input) {
        (Codec::Ascii, [byte]) if *byte < 0x80 => PyText::new(units),
        (Codec::Latin1, [_]) => PyText::new(units),
        (Codec::Latin1, _) => PyText::new_unshared(units),
        _ => resized_text(input.len(), units),
    }
}

/// A unicode object allocated with `allocated` units and then cut to
/// `units`, which copies the shared empty and one-unit objects instead of
/// resizing them.
pub fn resized_text(allocated: usize, units: Vec<u16>) -> PyText {
    if units.len() == allocated || allocated <= 1 {
        return PyText::new_unshared(units);
    }

    PyText::allocate(units)
}

/// `hex_codec` asserts `errors == 'strict'`.
fn require_strict(vm: &Vm, errors: Option<&[u8]>) -> PyResult<()> {
    if matches!(errors, None | Some(b"strict")) {
        return Ok(());
    }

    let class = Rc::clone(vm.types().exception(ExceptionKind::AssertionError));
    let exception = vm.instantiate_exception(&class, Vec::new())?;

    Err(Signal::Raise(exception))
}
