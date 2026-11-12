//! The builtin unicode codecs and the string escape codec, for the narrow
//! (UTF-16) Windows build. Errors go through the `errors` handler as in
//! CPython.

use crate::interp::builtins::modules::codecs::errors::Builtin;
use crate::interp::builtins::modules::codecs::errors::DecodeFault;
use crate::interp::builtins::modules::codecs::errors::EncodeFault;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::errors::code_points;
use crate::interp::builtins::modules::codecs::errors::encode_error;
use crate::interp::builtins::modules::codecs::errors::xml_character_references;
use crate::interp::builtins::text::unicode_names;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;

/// Decoded text and the number of input bytes it consumed.
pub struct Decoded {
    pub units: Vec<u16>,
    pub consumed: usize,
}

/// The `byteorder` argument of the UTF-16 and UTF-32 codecs. 0 detects a
/// BOM when decoding and writes one when encoding, -1 selects little
/// endian, and 1 big endian. Other values select the native (little
/// endian) order without a BOM, and decoding reports them back unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteOrder(pub i32);

impl ByteOrder {
    pub const NATIVE: Self = Self(0);
    pub const LITTLE: Self = Self(-1);
    pub const BIG: Self = Self(1);

    fn is_big(self) -> bool {
        self == Self::BIG
    }
}

/// The two codecs `encode_ucs1` implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ucs1 {
    Ascii,
    Latin1,
}

impl Ucs1 {
    fn limit(self) -> u16 {
        match self {
            Self::Ascii => 0x80,
            Self::Latin1 => 0x100,
        }
    }

    fn encoding(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Latin1 => "latin-1",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Ascii => "ordinal not in range(128)",
            Self::Latin1 => "ordinal not in range(256)",
        }
    }
}

/// A `\N{name}` escape: where its input ends, and the code point it names
/// or the reason it is invalid.
struct NamedEscape {
    end: usize,
    code: Result<u32, &'static str>,
}

/// Appends a code point, as a surrogate pair beyond the BMP.
pub fn push_code_point(output: &mut Vec<u16>, code: u32) {
    match u16::try_from(code) {
        Ok(unit) => output.push(unit),
        Err(_) => {
            let offset = code - 0x10000;
            output.push(0xd800 | (((offset >> 10) & 0x3ff) as u16));
            output.push(0xdc00 | ((offset & 0x3ff) as u16));
        }
    }
}

/// Reports a decoding error and appends the replacement; returns the
/// position decoding resumes at.
fn decode_failure(errors: &mut Errors<'_>, output: &mut Vec<u16>, fault: &DecodeFault<'_>) -> PyResult<usize> {
    let replacement = errors.decode(fault)?;
    output.extend_from_slice(&replacement.units);

    Ok(replacement.resume)
}

/// The Latin-1 decoder.
pub fn decode_latin1(input: &[u8]) -> Vec<u16> {
    input.iter().map(|&byte| u16::from(byte)).collect()
}

/// The ASCII decoder: each byte above 0x7f is its own error.
pub fn decode_ascii(input: &[u8], errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&byte) = input.get(position) {
        if byte < 0x80 {
            output.push(u16::from(byte));
            position += 1;
            continue;
        }

        let fault = DecodeFault { encoding: "ascii", reason: "ordinal not in range(128)", input, start: position, end: position + 1 };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok(output)
}

/// Encodes to ASCII or Latin-1. A run of
/// unencodable units is one error; 'strict', 'replace', 'ignore', and
/// 'xmlcharrefreplace' are handled by name.
pub fn encode_ucs1(input: &[u16], codec: Ucs1, errors: &mut Errors<'_>) -> PyResult<Vec<u8>> {
    let limit = codec.limit();
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&unit) = input.get(position) {
        if unit < limit {
            output.push(unit as u8);
            position += 1;
            continue;
        }

        let start = position;
        let mut end = position;
        while input.get(end).is_some_and(|&unit| unit >= limit) {
            end += 1;
        }
        let fault = EncodeFault { encoding: codec.encoding(), reason: codec.reason(), input, start, end };

        match errors.named() {
            Some(Builtin::Strict) => return Err(encode_error(errors.vm(), &fault)),
            Some(Builtin::Replace) => {
                output.extend(std::iter::repeat_n(b'?', end - start));
                position = end;
            }
            Some(Builtin::Ignore) => position = end,
            Some(Builtin::XmlCharRefReplace) => {
                output.extend_from_slice(xml_character_references(&input[start..end]).as_bytes());
                position = end;
            }
            Some(Builtin::BackslashReplace) | None => {
                let replacement = errors.encode(&fault)?;
                for &unit in &replacement.units {
                    if unit >= limit {
                        let fault = EncodeFault { encoding: codec.encoding(), reason: codec.reason(), input, start, end: start + 1 };
                        return Err(encode_error(errors.vm(), &fault));
                    }
                    output.push(unit as u8);
                }
                position = replacement.resume;
            }
        }
    }

    Ok(output)
}

/// The length of a UTF-8 sequence by its lead byte; 0 for an invalid lead.
fn utf8_sequence_length(lead: u8) -> usize {
    match lead {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

fn is_continuation(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

/// The code point of a complete UTF-8 sequence, or the length of the
/// invalid prefix to report (the 2.7 UTF-8 decoder accepts encoded
/// surrogates).
fn utf8_sequence(bytes: &[u8]) -> Result<u32, usize> {
    match *bytes {
        [lead, second] => {
            if !is_continuation(second) {
                return Err(1);
            }
            Ok((u32::from(lead & 0x1f) << 6) | u32::from(second & 0x3f))
        }
        [lead, second, third] => {
            if !is_continuation(second) || !is_continuation(third) || (lead == 0xe0 && second < 0xa0) {
                return Err(if is_continuation(second) { 2 } else { 1 });
            }
            Ok((u32::from(lead & 0x0f) << 12) | (u32::from(second & 0x3f) << 6) | u32::from(third & 0x3f))
        }
        [lead, second, third, fourth] => {
            if !is_continuation(second) || !is_continuation(third) || !is_continuation(fourth) || (lead == 0xf0 && second < 0x90) || (lead == 0xf4 && second > 0x8f) {
                let length = match (is_continuation(second), is_continuation(third)) {
                    (false, _) => 1,
                    (true, false) => 2,
                    (true, true) => 3,
                };
                return Err(length);
            }
            Ok((u32::from(lead & 0x07) << 18) | (u32::from(second & 0x3f) << 12) | (u32::from(third & 0x3f) << 6) | u32::from(fourth & 0x3f))
        }
        _ => Err(1),
    }
}

/// The UTF-8 decoder. Without `is_final`, an incomplete sequence at the
/// end is left unconsumed.
pub fn decode_utf8(input: &[u8], is_final: bool, errors: &mut Errors<'_>) -> PyResult<Decoded> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&lead) = input.get(position) {
        if lead < 0x80 {
            output.push(u16::from(lead));
            position += 1;
            continue;
        }

        let length = utf8_sequence_length(lead);
        let (end, reason) = if position + length > input.len() {
            if !is_final {
                break;
            }
            let mut end = position + 1;
            while input.get(end).copied().is_some_and(is_continuation) {
                end += 1;
            }
            (end, "unexpected end of data")
        } else if length == 0 {
            (position + 1, "invalid start byte")
        } else {
            match utf8_sequence(&input[position..position + length]) {
                Ok(code) => {
                    push_code_point(&mut output, code);
                    position += length;
                    continue;
                }
                Err(invalid) => (position + invalid, "invalid continuation byte"),
            }
        };

        let fault = DecodeFault { encoding: "utf8", reason, input, start: position, end };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok(Decoded { units: output, consumed: position })
}

/// The UTF-8 encoder of the narrow build: surrogate pairs combine and
/// lone surrogates encode as three bytes.
pub fn encode_utf8(input: &[u16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for code in code_points(input) {
        match code {
            0..=0x7f => output.push(code as u8),
            0x80..=0x7ff => output.extend_from_slice(&[0xc0 | (code >> 6) as u8, 0x80 | (code & 0x3f) as u8]),
            0x800..=0xffff => output.extend_from_slice(&[0xe0 | (code >> 12) as u8, 0x80 | ((code >> 6) & 0x3f) as u8, 0x80 | (code & 0x3f) as u8]),
            _ => output.extend_from_slice(&[0xf0 | (code >> 18) as u8, 0x80 | ((code >> 12) & 0x3f) as u8, 0x80 | ((code >> 6) & 0x3f) as u8, 0x80 | (code & 0x3f) as u8]),
        }
    }

    output
}

/// The UTF-16 decoder. Returns the byte order in effect at the end, which
/// a leading BOM selects when `order` is native.
pub fn decode_utf16(input: &[u8], order: ByteOrder, is_final: bool, errors: &mut Errors<'_>) -> PyResult<(Decoded, ByteOrder)> {
    if input.is_empty() {
        return Ok((Decoded { units: Vec::new(), consumed: 0 }, order));
    }

    let bom = match *input {
        [first, second, ..] if order == ByteOrder::NATIVE => Some(u16::from_le_bytes([first, second])),
        _ => None,
    };
    let (order, mut position) = match bom {
        Some(0xfeff) => (ByteOrder::LITTLE, 2),
        Some(0xfffe) => (ByteOrder::BIG, 2),
        _ => (order, 0),
    };

    let read = |at: usize| -> u16 {
        let pair = [input[at], input[at + 1]];
        if order.is_big() { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) }
    };

    let mut output = Vec::with_capacity(input.len() / 2);
    while position < input.len() {
        let (start, end, reason) = if input.len() - position < 2 {
            if !is_final {
                break;
            }
            (position, input.len(), "truncated data")
        } else {
            let unit = read(position);
            if !(0xd800..=0xdfff).contains(&unit) {
                output.push(unit);
                position += 2;
                continue;
            }
            if input.len() - position < 4 {
                if !is_final {
                    break;
                }
                (position, input.len(), "unexpected end of data")
            } else if unit <= 0xdbff {
                let low = read(position + 2);
                if (0xdc00..=0xdfff).contains(&low) {
                    output.extend_from_slice(&[unit, low]);
                    position += 4;
                    continue;
                }
                (position, position + 2, "illegal UTF-16 surrogate")
            } else {
                (position, position + 2, "illegal encoding")
            }
        };

        let fault = DecodeFault { encoding: "utf16", reason, input, start, end };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok((Decoded { units: output, consumed: position }, order))
}

/// The UTF-16 encoder.
pub fn encode_utf16(input: &[u16], order: ByteOrder) -> Vec<u8> {
    let mut output = Vec::with_capacity(2 * input.len() + 2);
    if order == ByteOrder::NATIVE {
        output.extend_from_slice(&0xfeff_u16.to_le_bytes());
    }

    for &unit in input {
        let bytes = if order.is_big() { unit.to_be_bytes() } else { unit.to_le_bytes() };
        output.extend_from_slice(&bytes);
    }

    output
}

/// The UTF-32 decoder; code points beyond the BMP become surrogate pairs.
pub fn decode_utf32(input: &[u8], order: ByteOrder, is_final: bool, errors: &mut Errors<'_>) -> PyResult<(Decoded, ByteOrder)> {
    if input.is_empty() {
        return Ok((Decoded { units: Vec::new(), consumed: 0 }, order));
    }

    let bom = match *input {
        [first, second, third, fourth, ..] if order == ByteOrder::NATIVE => Some(u32::from_le_bytes([first, second, third, fourth])),
        _ => None,
    };
    let (order, mut position) = match bom {
        Some(0x0000_feff) => (ByteOrder::LITTLE, 4),
        Some(0xfffe_0000) => (ByteOrder::BIG, 4),
        _ => (order, 0),
    };

    let mut output = Vec::with_capacity(input.len() / 4);
    while position < input.len() {
        let (start, end, reason) = if input.len() - position < 4 {
            if !is_final {
                break;
            }
            (position, input.len(), "truncated data")
        } else {
            let quad = [input[position], input[position + 1], input[position + 2], input[position + 3]];
            let code = if order.is_big() { u32::from_be_bytes(quad) } else { u32::from_le_bytes(quad) };
            if code < 0x110000 {
                push_code_point(&mut output, code);
                position += 4;
                continue;
            }
            (position, position + 4, "code point not in range(0x110000)")
        };

        let fault = DecodeFault { encoding: "utf32", reason, input, start, end };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok((Decoded { units: output, consumed: position }, order))
}

/// The UTF-32 encoder of the narrow build: surrogate pairs combine.
pub fn encode_utf32(input: &[u16], order: ByteOrder) -> Vec<u8> {
    let mut output = Vec::with_capacity(4 * input.len() + 4);
    if order == ByteOrder::NATIVE {
        output.extend_from_slice(&0xfeff_u32.to_le_bytes());
    }

    for code in code_points(input) {
        let bytes = if order.is_big() { code.to_be_bytes() } else { code.to_le_bytes() };
        output.extend_from_slice(&bytes);
    }

    output
}

fn hex_value(byte: u8) -> Option<u32> {
    char::from(byte).to_digit(16)
}

/// The `unicode_escape` decoder.
pub fn decode_unicode_escape(input: &[u8], errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&byte) = input.get(position) {
        if byte != b'\\' {
            output.push(u16::from(byte));
            position += 1;
            continue;
        }

        let start = position;
        position += 1;
        let Some(&escape) = input.get(position) else {
            let fault = DecodeFault { encoding: "unicodeescape", reason: "\\ at end of string", input, start, end: input.len() };
            position = decode_failure(errors, &mut output, &fault)?;
            continue;
        };
        position += 1;

        let digits = match escape {
            b'\n' => continue,
            b'\\' | b'\'' | b'"' => {
                output.push(u16::from(escape));
                continue;
            }
            b'b' | b'f' | b't' | b'n' | b'r' | b'v' | b'a' => {
                output.push(u16::from(simple_escape(escape)));
                continue;
            }
            b'0'..=b'7' => {
                let mut value = u16::from(escape - b'0');
                for _ in 0..2 {
                    match input.get(position) {
                        Some(&digit @ b'0'..=b'7') => {
                            value = (value << 3) + u16::from(digit - b'0');
                            position += 1;
                        }
                        _ => break,
                    }
                }
                output.push(value);
                continue;
            }
            b'x' => 2,
            b'u' => 4,
            b'U' => 8,
            b'N' => {
                let named = named_escape(input, position);
                let reason = match named.code {
                    Ok(code) => {
                        push_code_point(&mut output, code);
                        position = named.end;
                        continue;
                    }
                    Err(reason) => reason,
                };
                let fault = DecodeFault { encoding: "unicodeescape", reason, input, start, end: named.end };
                position = decode_failure(errors, &mut output, &fault)?;
                continue;
            }
            _ => {
                output.extend_from_slice(&[u16::from(b'\\'), u16::from(escape)]);
                continue;
            }
        };

        let truncated = match digits {
            2 => "truncated \\xXX escape",
            4 => "truncated \\uXXXX escape",
            _ => "truncated \\UXXXXXXXX escape",
        };
        let mut code = 0u32;
        let mut valid = true;
        for _ in 0..digits {
            let Some(value) = input.get(position).copied().and_then(hex_value) else {
                valid = false;
                break;
            };
            code = (code << 4) | value;
            position += 1;
        }

        let reason = if !valid {
            truncated
        } else if code <= 0x10ffff {
            push_code_point(&mut output, code);
            continue;
        } else {
            "illegal Unicode character"
        };
        let fault = DecodeFault { encoding: "unicodeescape", reason, input, start, end: position };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok(output)
}

/// The `{name}` part of a `\N` escape, which starts at `position`.
fn named_escape(input: &[u8], position: usize) -> NamedEscape {
    const MALFORMED: &str = "malformed \\N character escape";

    let Some((&b'{', after_brace)) = input.get(position..).and_then(<[u8]>::split_first) else {
        return NamedEscape { end: position, code: Err(MALFORMED) };
    };
    let Some(name_len) = after_brace.iter().position(|&byte| byte == b'}') else {
        return NamedEscape { end: input.len(), code: Err(MALFORMED) };
    };
    let close = position + 1 + name_len;
    if name_len == 0 {
        return NamedEscape { end: close, code: Err(MALFORMED) };
    }

    let (name, _) = after_brace.split_at(name_len);
    let code = unicode_names::lookup(name).ok_or("unknown Unicode character name");

    NamedEscape { end: close + 1, code }
}

/// The byte a one-letter C escape stands for.
fn simple_escape(letter: u8) -> u8 {
    match letter {
        b'b' => 0x08,
        b'f' => 0x0c,
        b't' => b'\t',
        b'n' => b'\n',
        b'r' => b'\r',
        b'v' => 0x0b,
        b'a' => 0x07,
        other => other,
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn push_hex(output: &mut Vec<u8>, value: u32, digits: u32) {
    for shift in (0..digits).rev() {
        output.push(HEX_DIGITS[((value >> (4 * shift)) & 0xf) as usize]);
    }
}

/// `unicode_escape` encoding without quotes, for the narrow build.
pub fn encode_unicode_escape(input: &[u16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for code in code_points(input) {
        match code {
            0x10000.. => {
                output.extend_from_slice(b"\\U");
                push_hex(&mut output, code, 8);
            }
            0x100..=0xffff => {
                output.extend_from_slice(b"\\u");
                push_hex(&mut output, code, 4);
            }
            0x5c => output.extend_from_slice(b"\\\\"),
            0x09 => output.extend_from_slice(b"\\t"),
            0x0a => output.extend_from_slice(b"\\n"),
            0x0d => output.extend_from_slice(b"\\r"),
            0..=0x1f | 0x7f..=0xff => {
                output.extend_from_slice(b"\\x");
                push_hex(&mut output, code, 2);
            }
            _ => output.push(code as u8),
        }
    }

    output
}

/// The `raw_unicode_escape` decoder: `\u` and `\U` are escapes only
/// after an odd number of backslashes.
pub fn decode_raw_unicode_escape(input: &[u8], errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&byte) = input.get(position) {
        if byte != b'\\' {
            output.push(u16::from(byte));
            position += 1;
            continue;
        }

        let start = position;
        while input.get(position) == Some(&b'\\') {
            output.push(u16::from(b'\\'));
            position += 1;
        }
        let digits = match input.get(position) {
            Some(b'u') if (position - start) % 2 == 1 => 4,
            Some(b'U') if (position - start) % 2 == 1 => 8,
            _ => continue,
        };
        output.pop();
        position += 1;

        let mut code = 0u32;
        let mut truncated = false;
        for _ in 0..digits {
            let Some(value) = input.get(position).copied().and_then(hex_value) else {
                truncated = true;
                break;
            };
            code = (code << 4) | value;
            position += 1;
        }

        let reason = if truncated {
            "truncated \\uXXXX"
        } else if code <= 0x10ffff {
            push_code_point(&mut output, code);
            continue;
        } else {
            "\\Uxxxxxxxx out of range"
        };
        let fault = DecodeFault { encoding: "rawunicodeescape", reason, input, start, end: position };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok(output)
}

/// The `raw_unicode_escape` encoder of the narrow build.
pub fn encode_raw_unicode_escape(input: &[u16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for code in code_points(input) {
        match code {
            0x10000.. => {
                output.extend_from_slice(b"\\U");
                push_hex(&mut output, code, 8);
            }
            0x100..=0xffff => {
                output.extend_from_slice(b"\\u");
                push_hex(&mut output, code, 4);
            }
            _ => output.push(code as u8),
        }
    }

    output
}

/// The `unicode_internal` decoder of the narrow build: little endian
/// UTF-16 code units.
pub fn decode_unicode_internal(input: &[u8], errors: &mut Errors<'_>) -> PyResult<Vec<u16>> {
    let mut output = Vec::with_capacity(input.len() / 2);
    let mut position = 0;

    while position < input.len() {
        if let [first, second] = input[position..].get(..2).unwrap_or_default() {
            output.push(u16::from_le_bytes([*first, *second]));
            position += 2;
            continue;
        }

        let fault = DecodeFault { encoding: "unicode_internal", reason: "truncated input", input, start: position, end: input.len() };
        position = decode_failure(errors, &mut output, &fault)?;
    }

    Ok(output)
}

/// The internal representation of unicode: little endian UTF-16 units.
pub fn encode_unicode_internal(input: &[u16]) -> Vec<u8> {
    input.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// The string escape decoder without recoding. Only 'strict', 'replace',
/// and 'ignore' are known, by name; errors raise `ValueError`.
pub fn decode_string_escape(input: &[u8], errors: &Errors<'_>) -> PyResult<Vec<u8>> {
    let vm = errors.vm();
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    while let Some(&byte) = input.get(position) {
        position += 1;
        if byte != b'\\' {
            output.push(byte);
            continue;
        }

        let Some(&escape) = input.get(position) else {
            return Err(vm.raise(ExceptionKind::ValueError, "Trailing \\ in string"));
        };
        position += 1;

        match escape {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => output.push(escape),
            b'b' | b'f' | b't' | b'n' | b'r' | b'v' | b'a' => output.push(simple_escape(escape)),
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                for _ in 0..2 {
                    match input.get(position) {
                        Some(&digit @ b'0'..=b'7') => {
                            value = (value << 3) + u32::from(digit - b'0');
                            position += 1;
                        }
                        _ => break,
                    }
                }
                output.push(value as u8);
            }
            b'x' => {
                let high = input.get(position).copied().and_then(hex_value);
                let low = input.get(position + 1).copied().and_then(hex_value);
                if let (Some(high), Some(low)) = (high, low) {
                    output.push(((high << 4) | low) as u8);
                    position += 2;
                    continue;
                }

                match errors.name() {
                    None | Some(b"strict") => return Err(vm.raise(ExceptionKind::ValueError, "invalid \\x escape")),
                    Some(b"replace") => output.push(b'?'),
                    Some(b"ignore") => {}
                    Some(name) => {
                        let name = String::from_utf8_lossy(name.get(..400).unwrap_or(name));
                        return Err(vm.raise(ExceptionKind::ValueError, &format!("decoding error; unknown error handling code: {name}")));
                    }
                }
                if high.is_some() {
                    position += 1;
                }
            }
            _ => output.extend_from_slice(&[b'\\', escape]),
        }
    }

    Ok(output)
}

/// The `repr` of a string with single quotes, without the quotes.
pub fn encode_string_escape(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());

    for &byte in input {
        match byte {
            b'\'' | b'\\' => output.extend_from_slice(&[b'\\', byte]),
            b'\t' => output.extend_from_slice(b"\\t"),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            0x20..=0x7e => output.push(byte),
            _ => {
                output.extend_from_slice(b"\\x");
                push_hex(&mut output, u32::from(byte), 2);
            }
        }
    }

    output
}
