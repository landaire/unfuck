//! Source decoding as the string tokenizer of CPython 2.7.12 does it:
//! the UTF-8 BOM, coding
//! declarations on the first two lines, and the codecs they name. Unicode
//! text is UTF-16 code units, as in a narrow (Windows) build.

use crate::interp::builtins::modules::codecs::unicode::ByteOrder;
use crate::interp::builtins::modules::codecs::unicode::decode_latin1;
use crate::interp::builtins::modules::codecs::unicode::encode_raw_unicode_escape;
use crate::interp::builtins::modules::codecs::unicode::encode_unicode_escape;
use crate::interp::builtins::modules::codecs::unicode::encode_utf16;
use crate::interp::builtins::modules::codecs::unicode::encode_utf8;
use crate::interp::builtins::modules::codecs::unicode::push_code_point;
use crate::interp::builtins::text::codecs::Codec;
use crate::interp::compiler::literals;
use crate::interp::compiler::tokenizer::PreparedSource;
use crate::interp::compiler::tokenizer::translate_newlines;

/// The source encoding the tokenizer found, which string literals are recoded to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceEncoding {
    /// `utf-8`: from a BOM or a declaration that normalizes to it.
    Utf8,
    /// `iso-8859-1`: from a declaration that normalizes to it.
    Latin1,
    /// Any other declared name, verbatim. The source has been recoded from
    /// it to UTF-8.
    Other(String),
}

impl SourceEncoding {
    pub fn name(&self) -> &str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Latin1 => "iso-8859-1",
            Self::Other(name) => name,
        }
    }
}

/// The exception class a codec raised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecErrorKind {
    /// `UnicodeError` or a subclass.
    Unicode,
    /// `LookupError`, for an unknown encoding.
    Lookup,
    /// Any other exception, by class name.
    Other(String),
}

/// An exception raised by a codec, with `str()` of the exception.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CodecError {
    pub kind: CodecErrorKind,
    pub message: String,
}

/// The `errors` argument passed to an encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeErrors {
    Strict,
    Replace,
}

/// The codec registry as the compiler uses it: decoding and encoding
/// with a declared encoding name.
pub trait SourceCodecs {
    fn decode(&mut self, encoding: &str, input: &[u8]) -> Result<Vec<u16>, CodecError>;

    fn encode(&mut self, encoding: &str, input: &[u16], errors: EncodeErrors) -> Result<Vec<u8>, CodecError>;

    /// Decodes with the default encoding, as conversion to unicode does
    /// for a `str` joined to a `unicode` literal.
    fn decode_default(&mut self, input: &[u8]) -> Result<Vec<u16>, CodecError>;
}

/// The codecs the interpreter implements natively (`text::codecs::Codec`),
/// under every name the `encodings` package resolves to them, with ASCII
/// as the default encoding. Other names fail as an unknown encoding.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinCodecs;

impl SourceCodecs for BuiltinCodecs {
    fn decode(&mut self, encoding: &str, input: &[u8]) -> Result<Vec<u16>, CodecError> {
        let Some(codec) = Codec::lookup(encoding.as_bytes()) else {
            return Err(unknown_encoding(encoding));
        };

        match codec {
            Codec::Ascii => decode_ascii(input),
            Codec::Latin1 => Ok(decode_latin1(input)),
            Codec::Utf8 => decode_utf8(input).map_err(DecodeFailure::into_codec_error),
            Codec::Utf16 => decode_utf16(input, ByteOrder::NATIVE),
            Codec::Utf16Le => decode_utf16(input, ByteOrder::LITTLE),
            Codec::Utf16Be => decode_utf16(input, ByteOrder::BIG),
            Codec::UnicodeEscape => literals::decode_unicode_escape(input).map_err(DecodeFailure::into_codec_error),
            Codec::RawUnicodeEscape => literals::decode_raw_unicode_escape(input).map_err(DecodeFailure::into_codec_error),
            Codec::StringEscape => match literals::decode_string_escape(input) {
                Ok(_) => Err(not_unicode()),
                Err(message) => Err(CodecError { kind: CodecErrorKind::Other("ValueError".to_owned()), message }),
            },
            Codec::Hex => match hex_error(input) {
                Some(message) => Err(CodecError { kind: CodecErrorKind::Other("TypeError".to_owned()), message: message.to_owned() }),
                None => Err(not_unicode()),
            },
        }
    }

    fn encode(&mut self, encoding: &str, input: &[u16], errors: EncodeErrors) -> Result<Vec<u8>, CodecError> {
        let Some(codec) = Codec::lookup(encoding.as_bytes()) else {
            return Err(unknown_encoding(encoding));
        };

        match codec {
            Codec::Ascii => encode_charset(input, errors, "ascii", "ordinal not in range(128)", 0x7f),
            Codec::Latin1 => encode_charset(input, errors, "latin-1", "ordinal not in range(256)", 0xff),
            Codec::Utf8 => Ok(encode_utf8(input)),
            Codec::Utf16 => Ok(encode_utf16(input, ByteOrder::NATIVE)),
            Codec::Utf16Le => Ok(encode_utf16(input, ByteOrder::LITTLE)),
            Codec::Utf16Be => Ok(encode_utf16(input, ByteOrder::BIG)),
            Codec::UnicodeEscape => Ok(encode_unicode_escape(input)),
            Codec::RawUnicodeEscape => Ok(encode_raw_unicode_escape(input)),
            Codec::StringEscape => Err(CodecError {
                kind: CodecErrorKind::Other("TypeError".to_owned()),
                message: "escape_encode() argument 1 must be string, not unicode".to_owned(),
            }),
            // `hex_codec.hex_encode` asserts strict errors, then hexlifies
            // the ASCII encoding of its argument.
            Codec::Hex if errors != EncodeErrors::Strict => Err(CodecError { kind: CodecErrorKind::Other("AssertionError".to_owned()), message: String::new() }),
            Codec::Hex => {
                let bytes = encode_charset(input, errors, "ascii", "ordinal not in range(128)", 0x7f)?;
                Ok(bytes.iter().flat_map(|byte| format!("{byte:02x}").into_bytes()).collect())
            }
        }
    }

    fn decode_default(&mut self, input: &[u8]) -> Result<Vec<u16>, CodecError> {
        decode_ascii(input)
    }
}

/// Whether the `str` a codec's encoder returns for a literal is interned:
/// the shared, interned string objects are returned for an
/// empty result and, when given bytes to copy, for a one-byte result. Only
/// the UTF-8 encoder copies from a buffer.
pub fn encoded_literal_is_interned(encoding: &str, length: usize) -> bool {
    match Codec::lookup(encoding.as_bytes()) {
        Some(Codec::Utf8) => length <= 1,
        Some(Codec::UnicodeEscape | Codec::RawUnicodeEscape) => false,
        _ => length == 0,
    }
}

/// The error for a decoder that returns `str`.
fn not_unicode() -> CodecError {
    CodecError { kind: CodecErrorKind::Other("TypeError".to_owned()), message: "decoder did not return an unicode object (type=str)".to_owned() }
}

/// The `TypeError` `binascii.a2b_hex` raises for `input`, if any.
fn hex_error(input: &[u8]) -> Option<&'static str> {
    if !input.len().is_multiple_of(2) {
        return Some("Odd-length string");
    }
    if !input.iter().all(u8::is_ascii_hexdigit) {
        return Some("Non-hexadecimal digit found");
    }

    None
}

/// The `utf-16` decoder with strict errors and a final block.
/// A native byte order is little-endian, and a leading BOM selects the
/// order and is dropped.
fn decode_utf16(input: &[u8], order: ByteOrder) -> Result<Vec<u16>, CodecError> {
    let failure = |start: usize, end: usize, reason: &'static str| DecodeFailure { codec: "utf16", input: input.to_vec(), start, end, reason }.into_codec_error();

    let mut big_endian = order == ByteOrder::BIG;
    let mut position = 0;
    if order == ByteOrder::NATIVE && input.len() >= 2 {
        match u16::from_le_bytes([input[0], input[1]]) {
            0xfeff => position = 2,
            0xfffe => {
                position = 2;
                big_endian = true;
            }
            _ => {}
        }
    }

    let unit_at = |position: usize| {
        let pair = [input[position], input[position + 1]];
        if big_endian { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) }
    };

    let mut output = Vec::with_capacity(input.len() / 2);
    while position < input.len() {
        if input.len() - position < 2 {
            return Err(failure(position, input.len(), "truncated data"));
        }
        let unit = unit_at(position);
        position += 2;
        if !(0xd800..=0xdfff).contains(&unit) {
            output.push(unit);
            continue;
        }

        if input.len() - position < 2 {
            return Err(failure(position - 2, input.len(), "unexpected end of data"));
        }
        if unit <= 0xdbff {
            let low = unit_at(position);
            position += 2;
            if (0xdc00..=0xdfff).contains(&low) {
                output.push(unit);
                output.push(low);
                continue;
            }
            return Err(failure(position - 4, position - 2, "illegal UTF-16 surrogate"));
        }
        return Err(failure(position - 2, position, "illegal encoding"));
    }

    Ok(output)
}

/// A failed decode: `UnicodeDecodeError(codec, input, start, end, reason)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeFailure {
    pub codec: &'static str,
    pub input: Vec<u8>,
    pub start: usize,
    pub end: usize,
    pub reason: &'static str,
}

impl DecodeFailure {
    /// `str()` of the `UnicodeDecodeError`.
    pub fn message(&self) -> String {
        let codec = self.codec;
        let reason = self.reason;
        if self.end == self.start + 1 {
            let byte = self.input.get(self.start).copied().unwrap_or(0);
            return format!("'{codec}' codec can't decode byte 0x{byte:02x} in position {}: {reason}", self.start);
        }

        format!("'{codec}' codec can't decode bytes in position {}-{}: {reason}", self.start, self.end.saturating_sub(1))
    }

    pub fn into_codec_error(self) -> CodecError {
        CodecError { kind: CodecErrorKind::Unicode, message: self.message() }
    }
}

/// The declared encoding, recoding, and BOM handling of the string
/// tokenizer, on newline-translated input. Errors are the `str()` of the
/// decoding exception the parser reports.
pub fn prepare_source(input: &[u8], exec_input: bool, codecs: &mut dyn SourceCodecs) -> Result<PreparedSource, String> {
    const BOM: &[u8] = b"\xef\xbb\xbf";

    let mut text = translate_newlines(input, exec_input);

    let mut encoding = None;
    if text.starts_with(BOM) {
        text.drain(..BOM.len());
        encoding = Some(SourceEncoding::Utf8);
    }

    let mut first_newlines = text.iter().enumerate().filter(|&(_, &byte)| byte == b'\n').map(|(index, _)| index);
    let first = first_newlines.next();
    let second = first_newlines.next();

    let mut state = CodingState { encoding, recode: None, read_coding_spec: false };
    if let Some(first) = first {
        state.check_coding_spec(&text, 0, first)?;
        if state.recode.is_none() && !state.read_coding_spec
            && let Some(second) = second {
                state.check_coding_spec(&text, first + 1, second - first)?;
            }
    }

    if let Some(name) = &state.recode {
        let decoded = codecs.decode(name, &text).map_err(|error| error.message)?;
        text = encode_utf8(&decoded);
    }

    Ok(PreparedSource { text, encoding: state.encoding })
}

struct CodingState {
    encoding: Option<SourceEncoding>,
    recode: Option<String>,
    read_coding_spec: bool,
}

impl CodingState {
    /// `check_coding_spec` on the `size` bytes of `text` at `line`.
    fn check_coding_spec(&mut self, text: &[u8], line: usize, size: usize) -> Result<(), String> {
        let Some(spec) = coding_spec(text, line, size) else {
            for &byte in text[line..].iter().take(size) {
                if matches!(byte, b'#' | b'\n' | b'\r') {
                    break;
                }
                if !matches!(byte, b' ' | b'\t' | b'\x0c') {
                    self.read_coding_spec = true;
                    break;
                }
            }
            return Ok(());
        };

        self.read_coding_spec = true;
        match &self.encoding {
            None => {
                self.encoding = Some(match spec.as_str() {
                    "utf-8" => SourceEncoding::Utf8,
                    "iso-8859-1" => SourceEncoding::Latin1,
                    _ => {
                        self.recode = Some(spec.clone());
                        SourceEncoding::Other(spec)
                    }
                });
                Ok(())
            }
            Some(existing) if existing.name() == spec => Ok(()),
            Some(_) => Err(format!("encoding problem: {spec} with BOM")),
        }
    }
}

/// The normalized encoding named by a `coding[:=]`
/// comment that is the only thing on the line.
fn coding_spec(text: &[u8], line: usize, size: usize) -> Option<String> {
    let at = |index: usize| text.get(line + index).copied().unwrap_or(0);
    let limit = size as isize - 6;

    let mut index = 0isize;
    while index < limit {
        let byte = at(index as usize);
        if byte == b'#' {
            break;
        }
        if !matches!(byte, b' ' | b'\t' | b'\x0c') {
            return None;
        }
        index += 1;
    }

    while index < limit {
        let position = index as usize;
        index += 1;
        if !(0..6).all(|offset| at(position + offset) == b"coding"[offset]) {
            continue;
        }

        let mut cursor = position + 6;
        if !matches!(at(cursor), b':' | b'=') {
            continue;
        }
        loop {
            cursor += 1;
            if !matches!(at(cursor), b' ' | b'\t') {
                break;
            }
        }

        let begin = cursor;
        while at(cursor).is_ascii_alphanumeric() || matches!(at(cursor), b'-' | b'_' | b'.') {
            cursor += 1;
        }
        if begin < cursor {
            let name = String::from_utf8_lossy(&text[line + begin..line + cursor]).into_owned();
            return Some(normal_name(name));
        }
    }

    None
}

/// Spellings of UTF-8 and Latin-1 become `utf-8` and
/// `iso-8859-1`. Only the first 12 characters are examined.
fn normal_name(name: String) -> String {
    let folded: String = name.bytes().take(12).map(|byte| if byte == b'_' { '-' } else { char::from(byte.to_ascii_lowercase()) }).collect();

    if folded == "utf-8" || folded.starts_with("utf-8-") {
        return "utf-8".to_owned();
    }

    let latin1 = ["latin-1", "iso-8859-1", "iso-latin-1"];
    if latin1.contains(&folded.as_str()) || latin1.iter().any(|prefix| folded.starts_with(&format!("{prefix}-"))) {
        return "iso-8859-1".to_owned();
    }

    name
}

fn unknown_encoding(encoding: &str) -> CodecError {
    CodecError { kind: CodecErrorKind::Lookup, message: format!("unknown encoding: {encoding}") }
}

fn decode_ascii(input: &[u8]) -> Result<Vec<u16>, CodecError> {
    if let Some(start) = input.iter().position(|&byte| byte >= 0x80) {
        let failure = DecodeFailure { codec: "ascii", input: input.to_vec(), start, end: start + 1, reason: "ordinal not in range(128)" };
        return Err(failure.into_codec_error());
    }

    Ok(input.iter().map(|&byte| u16::from(byte)).collect())
}

/// The latin-1 and ascii encoders: characters above `max` fail, in runs.
fn encode_charset(input: &[u16], errors: EncodeErrors, codec: &str, reason: &str, max: u16) -> Result<Vec<u8>, CodecError> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        let unit = input[position];
        if unit <= max {
            output.push(unit as u8);
            position += 1;
            continue;
        }

        let start = position;
        while position < input.len() && input[position] > max {
            position += 1;
        }

        match errors {
            EncodeErrors::Replace => output.extend(std::iter::repeat_n(b'?', position - start)),
            EncodeErrors::Strict => {
                let message = encode_error_message(codec, input, start, position, reason);
                return Err(CodecError { kind: CodecErrorKind::Unicode, message });
            }
        }
    }

    Ok(output)
}

/// `str()` of a `UnicodeEncodeError`.
pub fn encode_error_message(codec: &str, input: &[u16], start: usize, end: usize, reason: &str) -> String {
    if end == start + 1 {
        let unit = input.get(start).copied().unwrap_or(0);
        let character = if unit <= 0xff { format!("x{unit:02x}") } else { format!("u{unit:04x}") };
        return format!("'{codec}' codec can't encode character u'\\{character}' in position {start}: {reason}");
    }

    format!("'{codec}' codec can't encode characters in position {start}-{}: {reason}", end - 1)
}

/// The `utf-8` decoder with strict errors, to UTF-16 code units.
pub fn decode_utf8(input: &[u8]) -> Result<Vec<u16>, DecodeFailure> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        match decode_utf8_step(input, position, &mut output) {
            Ok(next) => position = next,
            Err((start, end, reason)) => return Err(DecodeFailure { codec: "utf8", input: input.to_vec(), start, end, reason }),
        }
    }

    Ok(output)
}

/// The `utf-8` decoder with the `replace` error handler.
pub fn decode_utf8_replace(input: &[u8]) -> Vec<u16> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        match decode_utf8_step(input, position, &mut output) {
            Ok(next) => position = next,
            Err((_, end, _)) => {
                output.push(0xfffd);
                position = end;
            }
        }
    }

    output
}

/// Decodes one character at `position`, returning the next position, or
/// the error range and reason.
fn decode_utf8_step(input: &[u8], position: usize, output: &mut Vec<u16>) -> Result<usize, (usize, usize, &'static str)> {
    let at = |offset: usize| input.get(position + offset).copied().unwrap_or(0);
    let lead = input[position];
    if lead < 0x80 {
        output.push(u16::from(lead));
        return Ok(position + 1);
    }

    let length = match lead {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    };

    if position + length > input.len() {
        let mut end = position + 1;
        let mut offset = 1;
        while offset < input.len() - position && input[position + offset] & 0xc0 == 0x80 {
            end += 1;
            offset += 1;
        }
        return Err((position, end, "unexpected end of data"));
    }

    let continuation = |offset: usize| at(offset) & 0xc0 == 0x80;
    match length {
        2 => {
            if !continuation(1) {
                return Err((position, position + 1, "invalid continuation byte"));
            }
            output.push((u16::from(lead & 0x1f) << 6) | u16::from(at(1) & 0x3f));
        }
        3 => {
            if !continuation(1) || !continuation(2) || (lead == 0xe0 && at(1) < 0xa0) {
                let end = if continuation(1) { position + 2 } else { position + 1 };
                return Err((position, end, "invalid continuation byte"));
            }
            output.push((u16::from(lead & 0x0f) << 12) | (u16::from(at(1) & 0x3f) << 6) | u16::from(at(2) & 0x3f));
        }
        4 => {
            if !continuation(1) || !continuation(2) || !continuation(3) || (lead == 0xf0 && at(1) < 0x90) || (lead == 0xf4 && at(1) > 0x8f) {
                let mut end = position + 1;
                if continuation(1) {
                    end += 1;
                    if continuation(2) {
                        end += 1;
                    }
                }
                return Err((position, end, "invalid continuation byte"));
            }
            let code = (u32::from(lead & 0x07) << 18) | (u32::from(at(1) & 0x3f) << 12) | (u32::from(at(2) & 0x3f) << 6) | u32::from(at(3) & 0x3f);
            push_code_point(output, code);
        }
        _ => return Err((position, position + 1, "invalid start byte")),
    }

    Ok(position + length)
}

/// UTF-16 code units to code points, joining surrogate pairs as the
/// narrow-build encoders do.
pub fn code_points(input: &[u16]) -> impl Iterator<Item = u32> + '_ {
    let mut position = 0;
    std::iter::from_fn(move || {
        let unit = *input.get(position)?;
        position += 1;
        if (0xd800..=0xdbff).contains(&unit)
            && let Some(&low) = input.get(position)
                && (0xdc00..=0xdfff).contains(&low) {
                    position += 1;
                    return Some(0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00));
                }
        Some(u32::from(unit))
    })
}

/// The error line and offset converted back
/// to the declared encoding, when there is one. `None` when the conversion
/// fails, leaving the UTF-8 text in place.
pub fn restore_encoding(encoding: &SourceEncoding, line: &[u8], offset: usize, codecs: &mut dyn SourceCodecs) -> Option<(Vec<u8>, usize)> {
    let mut recode = |text: &[u8]| {
        let decoded = decode_utf8_replace(text);
        codecs.encode(encoding.name(), &decoded, EncodeErrors::Replace).ok()
    };

    let text = recode(line)?;
    let offset = if offset > 1 { recode(&line[..(offset - 1).min(line.len())]).map_or(offset, |prefix| prefix.len() + 1) } else { offset };

    Some((text, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepare(source: &[u8]) -> Result<PreparedSource, String> {
        prepare_source(source, true, &mut BuiltinCodecs)
    }

    #[test]
    fn declarations_normalize_utf8_and_latin1() {
        assert_eq!(prepare(b"# -*- coding: UTF_8 -*-\n").map(|source| source.encoding), Ok(Some(SourceEncoding::Utf8)));
        assert_eq!(prepare(b"#!python\n# vim: set fileencoding=latin-1 :\n").map(|source| source.encoding), Ok(Some(SourceEncoding::Latin1)));
        assert_eq!(prepare(b"x = 1\n# coding: latin-1\n").map(|source| source.encoding), Ok(None));
    }

    #[test]
    fn other_declarations_recode_to_utf8() {
        let prepared = prepare(b"# coding: latin1\nx = '\xe9'\n").map(|source| (source.text, source.encoding));
        assert_eq!(prepared, Ok((b"# coding: latin1\nx = '\xc3\xa9'\n".to_vec(), Some(SourceEncoding::Other("latin1".to_owned())))));
    }

    #[test]
    fn decode_failures_report_the_codec_message() {
        assert_eq!(prepare(b"# coding: bogus\n").err(), Some("unknown encoding: bogus".to_owned()));
        assert_eq!(
            prepare(b"# coding: ascii\nx='\xff'\n").err(),
            Some("'ascii' codec can't decode byte 0xff in position 19: ordinal not in range(128)".to_owned())
        );
        assert_eq!(prepare(b"\xef\xbb\xbf# coding: latin-1\n").err(), Some("encoding problem: iso-8859-1 with BOM".to_owned()));
    }
}
