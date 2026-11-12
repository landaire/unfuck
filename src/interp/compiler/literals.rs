//! Number and string literals as the CPython 2.7 compiler evaluates them:
//! numbers, single string tokens, and adjacent string concatenation, with
//! the `string_escape`, `unicode_escape`, and `raw_unicode_escape`
//! decoders in strict mode.

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::builtins::modules::codecs::unicode::push_code_point;
use crate::interp::builtins::text::unicode_names;
use crate::interp::compiler::ast::Number;
use crate::interp::compiler::ast::StrLiteral;
use crate::interp::compiler::source::CodecError;
use crate::interp::compiler::source::CodecErrorKind;
use crate::interp::compiler::source::DecodeFailure;
use crate::interp::compiler::source::EncodeErrors;
use crate::interp::compiler::source::SourceCodecs;
use crate::interp::compiler::source::SourceEncoding;
use crate::interp::compiler::source::code_points;
use crate::interp::compiler::source::decode_utf8;
use crate::interp::compiler::source::encoded_literal_is_interned;

/// Why a string literal could not be evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiteralError {
    /// A `UnicodeError`, with its `str()`; the compiler reports it as a
    /// `SyntaxError` prefixed with `(unicode error)`.
    Unicode(String),
    /// `ValueError`, from the `string_escape` decoder.
    Value(String),
    /// Another exception from a codec, which propagates unchanged.
    Codec(CodecError),
}

impl From<DecodeFailure> for LiteralError {
    fn from(failure: DecodeFailure) -> Self {
        Self::Unicode(failure.message())
    }
}

impl From<CodecError> for LiteralError {
    fn from(error: CodecError) -> Self {
        match error.kind {
            CodecErrorKind::Unicode => Self::Unicode(error.message),
            _ => Self::Codec(error),
        }
    }
}

/// What string literal evaluation needs from the compilation.
pub struct StringContext<'a> {
    pub encoding: Option<&'a SourceEncoding>,
    pub future_unicode: bool,
    pub codecs: &'a mut dyn SourceCodecs,
}

/// The value of a number literal. `text` is the NUMBER token, preceded by `-` when a unary
/// minus was folded into it. Integers that fit a 64-bit C `long` are `Int`.
pub fn parse_number(text: &[u8]) -> Number {
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, text),
    };

    if let Some((last, body)) = digits.split_last()
        && matches!(last, b'l' | b'L') {
            let value = parse_integer(body).unwrap_or_default();
            return Number::Long(if negative { -value } else { value });
        }

    if let Some(value) = parse_integer(digits) {
        let value = if negative { -value } else { value };
        return match value.to_i64() {
            Some(small) => Number::Int(small),
            None => Number::Long(value),
        };
    }

    if let Some((last, body)) = digits.split_last()
        && matches!(last, b'j' | b'J') {
            let magnitude = parse_float(body);
            return Number::Complex { real: 0.0, imag: if negative { -magnitude } else { magnitude } };
        }

    let magnitude = parse_float(digits);
    Number::Float(if negative { -magnitude } else { magnitude })
}

/// The value of an integer literal without sign or suffix, with the base
/// rules of `int()` and `long()` with base 0. `None` when
/// the text is not entirely an integer.
fn parse_integer(text: &[u8]) -> Option<BigInt> {
    let (radix, digits) = match text {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', b'o' | b'O', rest @ ..] => (8, rest),
        [b'0', b'b' | b'B', rest @ ..] => (2, rest),
        [b'0', rest @ ..] => (8, rest),
        _ => (10, text),
    };

    if digits.is_empty() {
        return (text == b"0").then(BigInt::default);
    }

    BigInt::parse_bytes(digits, radix)
}

/// The value of the decimal float text the tokenizer accepts.
fn parse_float(text: &[u8]) -> f64 {
    std::str::from_utf8(text).ok().and_then(|text| text.parse().ok()).unwrap_or(0.0)
}

/// The value of adjacent STRING tokens.
pub fn parse_strings(tokens: &[&[u8]], context: &mut StringContext<'_>) -> Result<StrLiteral, LiteralError> {
    let mut value: Option<StrLiteral> = None;
    for token in tokens {
        let piece = parse_string(token, context)?;
        value = Some(match value {
            None => piece,
            Some(left) => concatenate(left, piece, &mut *context.codecs)?,
        });
    }

    Ok(value.unwrap_or(StrLiteral::Bytes { value: Vec::new(), interned: true }))
}

/// The concatenation of two adjacent string literals.
fn concatenate(left: StrLiteral, right: StrLiteral, codecs: &mut dyn SourceCodecs) -> Result<StrLiteral, LiteralError> {
    match (left, right) {
        (StrLiteral::Bytes { value: left, interned: left_interned }, StrLiteral::Bytes { value: right, interned: right_interned }) => {
            // `str` concatenation returns the non-empty operand itself.
            if left.is_empty() {
                return Ok(StrLiteral::Bytes { value: right, interned: right_interned });
            }
            if right.is_empty() {
                return Ok(StrLiteral::Bytes { value: left, interned: left_interned });
            }
            let mut value = left;
            value.extend_from_slice(&right);
            Ok(StrLiteral::Bytes { value, interned: false })
        }
        (left, right) => {
            let mut value = unicode_operand(left, codecs)?;
            value.extend(unicode_operand(right, codecs)?);
            Ok(StrLiteral::Unicode(value))
        }
    }
}

/// A literal as unicode: a `str` decodes with the default encoding.
fn unicode_operand(literal: StrLiteral, codecs: &mut dyn SourceCodecs) -> Result<Vec<u16>, LiteralError> {
    match literal {
        StrLiteral::Unicode(value) => Ok(value),
        StrLiteral::Bytes { value, .. } => Ok(codecs.decode_default(&value)?),
    }
}

/// The value of one STRING token, prefix and quotes included.
pub fn parse_string(token: &[u8], context: &mut StringContext<'_>) -> Result<StrLiteral, LiteralError> {
    let mut position = 0;
    let mut unicode = context.future_unicode;
    let mut raw = false;

    if matches!(token.first(), Some(b'u' | b'U')) {
        position += 1;
        unicode = true;
    }
    if matches!(token.get(position), Some(b'b' | b'B')) {
        position += 1;
        unicode = false;
    }
    if matches!(token.get(position), Some(b'r' | b'R')) {
        position += 1;
        raw = true;
    }

    let quote = token.get(position).copied().unwrap_or(b'\'');
    let mut body = &token[(position + 1).min(token.len())..token.len().saturating_sub(1)];
    if body.len() >= 4 && body[0] == quote && body[1] == quote {
        body = &body[2..body.len() - 2];
    }

    if unicode {
        let value = decode_unicode(body, raw, context.encoding)?;
        return Ok(StrLiteral::Unicode(value));
    }

    let recode = match context.encoding {
        Some(SourceEncoding::Other(name)) => Some(name.as_str()),
        _ => None,
    };

    if raw || !body.contains(&b'\\') {
        let Some(name) = recode else {
            return Ok(StrLiteral::Bytes { value: body.to_vec(), interned: body.len() <= 1 });
        };
        let decoded = decode_utf8(body)?;
        let value = context.codecs.encode(name, &decoded, EncodeErrors::Strict)?;
        let interned = encoded_literal_is_interned(name, value.len());
        return Ok(StrLiteral::Bytes { value, interned });
    }

    let value = decode_escape(body, recode, context.codecs)?;
    Ok(StrLiteral::Bytes { value, interned: false })
}

/// The `string_escape` decoder, without recoding.
/// Errors are the `ValueError` message.
pub fn decode_string_escape(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut codecs = crate::interp::compiler::source::BuiltinCodecs;
    match decode_escape(input, None, &mut codecs) {
        Ok(value) => Ok(value),
        Err(LiteralError::Value(message)) => Err(message),
        Err(LiteralError::Unicode(message)) => Err(message),
        Err(LiteralError::Codec(error)) => Err(error.message),
    }
}

/// The `string_escape` decoder with strict errors. With `recode`, runs of
/// non-ASCII bytes are UTF-8 recoded to that encoding.
fn decode_escape(input: &[u8], recode: Option<&str>, codecs: &mut dyn SourceCodecs) -> Result<Vec<u8>, LiteralError> {
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'\\' {
            position = copy_unescaped(input, position, recode, codecs, &mut output)?;
            continue;
        }

        position += 1;
        let Some(&escape) = input.get(position) else {
            return Err(LiteralError::Value("Trailing \\ in string".to_owned()));
        };
        position += 1;

        match escape {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => output.push(escape),
            b'b' => output.push(0x08),
            b'f' => output.push(0x0c),
            b't' => output.push(b'\t'),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b'v' => output.push(0x0b),
            b'a' => output.push(0x07),
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
                let high = input.get(position).and_then(|&digit| char::from(digit).to_digit(16));
                let low = input.get(position + 1).and_then(|&digit| char::from(digit).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(LiteralError::Value("invalid \\x escape".to_owned()));
                };
                output.push((high * 16 + low) as u8);
                position += 2;
            }
            _ => {
                output.push(b'\\');
                position -= 1;
                position = copy_unescaped(input, position, recode, codecs, &mut output)?;
            }
        }
    }

    Ok(output)
}

/// A byte that is not part of an escape: one plain byte, or a
/// recoded run of non-ASCII bytes.
fn copy_unescaped(input: &[u8], position: usize, recode: Option<&str>, codecs: &mut dyn SourceCodecs, output: &mut Vec<u8>) -> Result<usize, LiteralError> {
    let byte = input[position];
    let Some(name) = recode.filter(|_| byte >= 0x80) else {
        output.push(byte);
        return Ok(position + 1);
    };

    let end = input[position..].iter().position(|&byte| byte < 0x80).map_or(input.len(), |offset| position + offset);
    let decoded = decode_utf8(&input[position..end])?;
    output.extend(codecs.encode(name, &decoded, EncodeErrors::Strict)?);

    Ok(end)
}

/// `decode_unicode`: a unicode literal's body. With a declared encoding
/// other than Latin-1 the UTF-8 source characters become `\U` escapes
/// first, so the escape decoder sees them as code points.
fn decode_unicode(body: &[u8], raw: bool, encoding: Option<&SourceEncoding>) -> Result<Vec<u16>, LiteralError> {
    let transformed;
    let input = match encoding {
        Some(SourceEncoding::Latin1) | None => body,
        Some(_) => {
            transformed = escape_non_ascii(body)?;
            &transformed
        }
    };

    let decoded = if raw { decode_raw_unicode_escape(input) } else { decode_unicode_escape(input) };

    Ok(decoded?)
}

fn escape_non_ascii(body: &[u8]) -> Result<Vec<u8>, DecodeFailure> {
    let at = |index: usize| body.get(index).copied().unwrap_or(0);
    let mut output = Vec::with_capacity(body.len() * 6);
    let mut position = 0;
    while position < body.len() {
        if body[position] == b'\\' {
            output.push(b'\\');
            position += 1;
            if at(position) & 0x80 != 0 {
                output.extend_from_slice(b"u005c");
            }
        }

        // A body never ends in an unescaped backslash, so the C read of the
        // closing quote here cannot happen.
        if position >= body.len() {
            break;
        }

        if body[position] & 0x80 == 0 {
            output.push(body[position]);
            position += 1;
            continue;
        }

        let end = body[position..].iter().position(|&byte| byte & 0x80 == 0).map_or(body.len(), |offset| position + offset);
        let decoded = decode_utf8(&body[position..end])?;
        for code in code_points(&decoded) {
            output.extend_from_slice(format!("\\U{code:08x}").as_bytes());
        }
        position = end;
    }

    Ok(output)
}

/// The `unicode_escape` decoder with strict errors. Bytes that are not
/// escapes are Latin-1 code points.
pub fn decode_unicode_escape(input: &[u8]) -> Result<Vec<u16>, DecodeFailure> {
    let failure = |start: usize, end: usize, reason: &'static str| DecodeFailure { codec: "unicodeescape", input: input.to_vec(), start, end, reason };

    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'\\' {
            output.push(u16::from(input[position]));
            position += 1;
            continue;
        }

        let start = position;
        position += 1;
        let Some(&escape) = input.get(position) else {
            return Err(failure(start, input.len(), "\\ at end of string"));
        };
        position += 1;

        let (digits, truncated) = match escape {
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
            b'x' => (2, "truncated \\xXX escape"),
            b'u' => (4, "truncated \\uXXXX escape"),
            b'U' => (8, "truncated \\UXXXXXXXX escape"),
            b'N' => {
                let code = named_escape(input, &mut position);
                let Ok(code) = code else {
                    return Err(failure(start, position, code.err().unwrap_or("malformed \\N character escape")));
                };
                if !store_code_point(&mut output, code) {
                    return Err(failure(start, position, "illegal Unicode character"));
                }
                continue;
            }
            _ => {
                output.push(u16::from(b'\\'));
                output.push(u16::from(escape));
                continue;
            }
        };

        let mut code = 0u32;
        let available = input.len() - position;
        let wanted = digits.min(available);
        for _ in 0..wanted {
            let Some(value) = char::from(input[position]).to_digit(16) else {
                return Err(failure(start, position, truncated));
            };
            code = (code << 4) | value;
            position += 1;
        }
        if available < digits {
            return Err(failure(start, position, truncated));
        }

        if !store_code_point(&mut output, code) {
            return Err(failure(start, position, "illegal Unicode character"));
        }
    }

    Ok(output)
}

/// The `\N{name}` escape after the `N`. On failure `position` is where the
/// error range ends.
fn named_escape(input: &[u8], position: &mut usize) -> Result<u32, &'static str> {
    if input.get(*position) != Some(&b'{') {
        return Err("malformed \\N character escape");
    }

    let name_start = *position + 1;
    while *position < input.len() && input[*position] != b'}' {
        *position += 1;
    }
    if *position <= name_start || *position >= input.len() {
        return Err("malformed \\N character escape");
    }

    let name = &input[name_start..*position];
    *position += 1;

    unicode_names::lookup(name).ok_or("unknown Unicode character name")
}

/// Stores a code point, as a surrogate pair above the BMP. False when it
/// is beyond U+10FFFF.
fn store_code_point(output: &mut Vec<u16>, code: u32) -> bool {
    if code > 0x10ffff {
        return false;
    }

    push_code_point(output, code);
    true
}

fn simple_escape(escape: u8) -> u8 {
    match escape {
        b'b' => 0x08,
        b'f' => 0x0c,
        b't' => b'\t',
        b'n' => b'\n',
        b'r' => b'\r',
        b'v' => 0x0b,
        _ => 0x07,
    }
}

/// The `raw_unicode_escape` decoder with strict errors: only `\u` and
/// `\U` after an odd number of backslashes are escapes.
pub fn decode_raw_unicode_escape(input: &[u8]) -> Result<Vec<u16>, DecodeFailure> {
    let failure = |start: usize, end: usize, reason: &'static str| DecodeFailure { codec: "rawunicodeescape", input: input.to_vec(), start, end, reason };

    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'\\' {
            output.push(u16::from(input[position]));
            position += 1;
            continue;
        }

        let start = position;
        while position < input.len() && input[position] == b'\\' {
            output.push(u16::from(b'\\'));
            position += 1;
        }
        let odd = (position - start) % 2 == 1;
        let Some(&marker) = input.get(position).filter(|&&marker| odd && (marker == b'u' || marker == b'U')) else {
            continue;
        };

        output.pop();
        let count = if marker == b'u' { 4 } else { 8 };
        position += 1;

        let mut code = 0u32;
        for _ in 0..count {
            let Some(value) = input.get(position).and_then(|&digit| char::from(digit).to_digit(16)) else {
                return Err(failure(start, position, "truncated \\uXXXX"));
            };
            code = (code << 4) | value;
            position += 1;
        }

        if !store_code_point(&mut output, code) {
            return Err(failure(start, position, "\\Uxxxxxxxx out of range"));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::compiler::source::BuiltinCodecs;

    fn string(token: &[u8], encoding: Option<SourceEncoding>) -> Result<StrLiteral, LiteralError> {
        let mut codecs = BuiltinCodecs;
        let mut context = StringContext { encoding: encoding.as_ref(), future_unicode: false, codecs: &mut codecs };
        parse_string(token, &mut context)
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn numbers_follow_c_long_and_base_rules() {
        assert_eq!(parse_number(b"0777"), Number::Int(511));
        assert_eq!(parse_number(b"0x1e"), Number::Int(30));
        assert_eq!(parse_number(b"0L"), Number::Long(BigInt::from(0)));
        assert_eq!(parse_number(b"-9223372036854775808"), Number::Int(i64::MIN));
        assert_eq!(parse_number(b"9223372036854775808"), Number::Long(BigInt::from(9223372036854775808u64)));
        assert_eq!(parse_number(b"0777j"), Number::Complex { real: 0.0, imag: 777.0 });
        assert_eq!(parse_number(b"1.e5"), Number::Float(100000.0));
        assert_eq!(parse_number(b"-0.0"), Number::Float(-0.0));
    }

    #[test]
    fn byte_strings_decode_escapes() {
        assert_eq!(string(b"'a\\x41\\101\\q'", None), Ok(StrLiteral::Bytes { value: b"aAA\\q".to_vec(), interned: false }));
        assert_eq!(string(b"r'\\n'", None), Ok(StrLiteral::Bytes { value: b"\\n".to_vec(), interned: false }));
        assert_eq!(string(b"'.'", None), Ok(StrLiteral::Bytes { value: b".".to_vec(), interned: true }));
        assert_eq!(string(b"'\\x4'", None), Err(LiteralError::Value("invalid \\x escape".to_owned())));
    }

    #[test]
    fn unicode_strings_report_codec_errors() {
        assert_eq!(string(b"u'\\u00e9\\N{LATIN SMALL LETTER A}'", None), Ok(StrLiteral::Unicode(units("\u{e9}a"))));
        assert_eq!(
            string(b"u'\\x4'", None),
            Err(LiteralError::Unicode("'unicodeescape' codec can't decode bytes in position 0-2: truncated \\xXX escape".to_owned()))
        );
        assert_eq!(
            string(b"u'\\N{foo}'", None),
            Err(LiteralError::Unicode("'unicodeescape' codec can't decode bytes in position 0-6: unknown Unicode character name".to_owned()))
        );
        assert_eq!(
            string(b"u'\xff'", Some(SourceEncoding::Utf8)),
            Err(LiteralError::Unicode("'utf8' codec can't decode byte 0xff in position 0: invalid start byte".to_owned()))
        );
        assert_eq!(string(b"u'\xc3\xa9\\\xc3\xa9'", Some(SourceEncoding::Utf8)), Ok(StrLiteral::Unicode(units("\u{e9}\\\u{e9}"))));
        assert_eq!(string(b"ur'\\u0041\\\\u0041'", None), Ok(StrLiteral::Unicode(units("A\\\\u0041"))));
    }
}
