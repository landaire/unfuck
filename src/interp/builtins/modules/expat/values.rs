//! Small text rules shared by the prolog and content processors: character
//! references, predefined entities, public identifiers and line ends.

use super::chars::is_xml_char;
use super::encoding::Encoding;

/// The character a well-formed character reference `&#...;` at `start..end`
/// names, or `None` when it is not a legal XML character.
pub(super) fn char_ref_value(buf: &[u8], start: usize, end: usize, enc: &Encoding) -> Option<u32> {
    let unit = enc.unit();
    let mut pos = start + 2 * unit;
    let hex = enc.raw_unit(buf, pos) == u32::from(b'x');
    if hex {
        pos += unit;
    }

    let mut value: u32 = 0;
    while pos + unit < end {
        let digit = char::from_u32(enc.raw_unit(buf, pos)).and_then(|c| c.to_digit(if hex { 16 } else { 10 }))?;
        value = value.saturating_mul(if hex { 16 } else { 10 }).saturating_add(digit);
        if value >= 0x110000 {
            return None;
        }
        pos += unit;
    }

    if is_xml_char(value) { Some(value) } else { None }
}

/// The character a predefined entity name stands for.
pub(super) fn predefined_entity(name: &[u8]) -> Option<u8> {
    match name {
        b"lt" => Some(b'<'),
        b"gt" => Some(b'>'),
        b"amp" => Some(b'&'),
        b"quot" => Some(b'"'),
        b"apos" => Some(b'\''),
        _ => None,
    }
}

/// The position of the first character of `buf[start..end]` that a public
/// identifier may not contain.
pub(super) fn public_id_error(buf: &[u8], start: usize, end: usize, enc: &Encoding) -> Option<usize> {
    const PUNCTUATION: &[u8] = b" \r\n-'()+,./:=?;!*#@$_%";

    let unit = enc.unit();
    let mut pos = start;
    while pos < end {
        let code = enc.raw_unit(buf, pos);
        let allowed = u8::try_from(code).is_ok_and(|byte| byte.is_ascii_alphanumeric() || PUNCTUATION.contains(&byte));
        if !allowed {
            return Some(pos);
        }
        pos += unit;
    }

    None
}

/// Collapses runs of white space in a public identifier to single spaces and
/// trims both ends.
pub(super) fn normalize_public_id(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for &byte in text {
        if matches!(byte, b' ' | b'\r' | b'\n') {
            if out.last().is_some_and(|&last| last != b' ') {
                out.push(b' ');
            }
            continue;
        }
        out.push(byte);
    }
    if out.last() == Some(&b' ') {
        out.pop();
    }

    out
}

/// Turns CR LF pairs and lone CRs into LF.
pub(super) fn normalize_newlines(text: &mut Vec<u8>) {
    let mut write = 0;
    let mut read = 0;
    while read < text.len() {
        let byte = text[read];
        read += 1;
        if byte == b'\r' {
            text[write] = b'\n';
            write += 1;
            if text.get(read) == Some(&b'\n') {
                read += 1;
            }
            continue;
        }
        text[write] = byte;
        write += 1;
    }

    text.truncate(write);
}
