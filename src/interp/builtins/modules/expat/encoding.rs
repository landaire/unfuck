//! Input encodings: decoding one character at a time, conversion to UTF-8 and
//! the byte maps an unknown-encoding handler supplies.

use super::chars::NameClass;
use super::chars::is_xml_char;
use super::chars::name_class;

/// The largest number of converted bytes handed to one character data or
/// default handler call when the input is not UTF-8.
pub(super) const CONVERT_LIMIT: usize = 1024;

/// One decoded unit of input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Unit {
    /// A well-formed character of `len` bytes. It may still be one that XML forbids.
    Char { code: u32, len: usize },
    /// Bytes that can never start a character here.
    Malformed,
    /// The data ends inside a character.
    Truncated,
}

/// A byte map from an unknown-encoding handler, validated and classified.
#[derive(Clone, Debug)]
pub(super) struct ByteMap {
    /// The code point of each byte; `None` for bytes that cannot occur.
    codes: [Option<u32>; 256],
}

impl ByteMap {
    /// Validates a handler's map. ASCII bytes with a role in XML syntax must map
    /// to themselves, no other byte may map to such a character, and every
    /// entry must be a single byte character in the Basic Multilingual Plane.
    pub(super) fn new(map: &[i32; 256]) -> Option<Self> {
        let mut codes = [None; 256];
        for (byte, &code) in map.iter().enumerate() {
            if byte < 0x80 && is_syntax_ascii(byte as u32) && code != byte as i32 {
                return None;
            }
            if !(-1..=0xFFFF).contains(&code) {
                return None;
            }
            if code == -1 {
                continue;
            }

            let code = code as u32;
            if code < 0x80 && is_syntax_ascii(code) && code != byte as u32 {
                return None;
            }
            codes[byte] = Some(code);
        }

        Some(Self { codes })
    }
}

/// ASCII characters that are part of XML syntax: everything except the
/// characters XML forbids and the punctuation that never delimits anything.
fn is_syntax_ascii(code: u32) -> bool {
    if !is_xml_char(code) {
        return false;
    }

    !matches!(code as u8, b'$' | b'@' | b'\\' | b'^' | b'`' | b'{' | b'}' | b'~' | 0x7F)
}

/// The encoding of an input stream.
#[derive(Clone, Debug)]
pub(super) enum Encoding {
    Utf8,
    Utf16 { big_endian: bool },
    Latin1,
    Ascii,
    Mapped(Box<ByteMap>),
}

impl Encoding {
    /// The size of the smallest character.
    pub(super) fn unit(&self) -> usize {
        match self {
            Self::Utf16 { .. } => 2,
            _ => 1,
        }
    }

    /// Whether character data is handed on without conversion.
    pub(super) fn is_utf8(&self) -> bool {
        matches!(self, Self::Utf8 | Self::Ascii)
    }

    /// Whether U+00AA, U+00B5 and U+00BA count as letters in names.
    fn latin1_letters(&self) -> bool {
        matches!(self, Self::Utf16 { .. } | Self::Latin1)
    }

    /// `end` cut back to a whole number of units after `start`.
    pub(super) fn align(&self, start: usize, end: usize) -> usize {
        if self.unit() == 2 && end > start {
            return start + ((end - start) & !1);
        }

        end
    }

    /// Decodes the character at `pos`; `pos < end` and `end` is aligned.
    pub(super) fn decode(&self, buf: &[u8], pos: usize, end: usize) -> Unit {
        let Some(&first) = buf.get(pos) else {
            return Unit::Truncated;
        };

        match self {
            Self::Utf8 => decode_utf8(buf, pos, end),
            Self::Utf16 { big_endian } => decode_utf16(buf, pos, end, *big_endian),
            Self::Latin1 => Unit::Char { code: u32::from(first), len: 1 },
            Self::Ascii if first < 0x80 => Unit::Char { code: u32::from(first), len: 1 },
            Self::Ascii => Unit::Malformed,
            Self::Mapped(map) => match map.codes[usize::from(first)] {
                Some(code) => Unit::Char { code, len: 1 },
                None => Unit::Malformed,
            },
        }
    }

    /// The name class of a decoded character under this encoding.
    pub(super) fn name_class(&self, code: u32) -> NameClass {
        name_class(code, self.latin1_letters())
    }

    /// The number of bytes the position counter steps over at `pos`. It goes by
    /// the first byte or unit alone, as the input may end or be malformed there.
    pub(super) fn step(&self, buf: &[u8], pos: usize) -> usize {
        let first = buf.get(pos).copied().unwrap_or(0);
        match self {
            Self::Utf8 => match first {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => 1,
            },
            Self::Utf16 { big_endian } => {
                let high = if *big_endian { first } else { buf.get(pos + 1).copied().unwrap_or(0) };
                if (0xD8..=0xDB).contains(&high) { 4 } else { 2 }
            }
            _ => 1,
        }
    }

    /// The 16-bit value at `pos` for UTF-16 and the byte for everything else.
    pub(super) fn raw_unit(&self, buf: &[u8], pos: usize) -> u32 {
        let first = u32::from(buf.get(pos).copied().unwrap_or(0));
        match self {
            Self::Utf16 { big_endian } => {
                let second = u32::from(buf.get(pos + 1).copied().unwrap_or(0));
                if *big_endian { (first << 8) | second } else { (second << 8) | first }
            }
            Self::Mapped(map) => map.codes[first as usize].unwrap_or(u32::MAX),
            _ => first,
        }
    }

    /// Appends `buf[start..end]` converted to UTF-8. Bytes that do not decode
    /// are copied as they are; scanning has rejected them before this runs.
    pub(super) fn append_utf8(&self, buf: &[u8], start: usize, end: usize, out: &mut Vec<u8>) {
        if self.is_utf8() {
            out.extend_from_slice(buf.get(start..end).unwrap_or_default());
            return;
        }

        let mut pos = start;
        while pos < end {
            match self.decode(buf, pos, end) {
                Unit::Char { code, len } => {
                    push_utf8(code, out);
                    pos += len;
                }
                Unit::Malformed | Unit::Truncated => {
                    pos += self.unit();
                }
            }
        }
    }

    /// Splits `buf[start..end]` into the pieces delivered to one handler call
    /// each: the whole range for UTF-8, otherwise runs whose UTF-8 form fits
    /// the conversion buffer. Returns the end of the first piece.
    pub(super) fn piece_end(&self, buf: &[u8], start: usize, end: usize) -> usize {
        if self.is_utf8() {
            return end;
        }

        let mut pos = start;
        let mut size = 0;
        while pos < end {
            let (width, len) = match self.decode(buf, pos, end) {
                Unit::Char { code, len } => (utf8_width(code), len),
                Unit::Malformed | Unit::Truncated => (1, self.unit()),
            };
            if size + width > CONVERT_LIMIT {
                break;
            }

            size += width;
            pos += len;
        }

        pos
    }
}

fn decode_utf8(buf: &[u8], pos: usize, end: usize) -> Unit {
    let byte = |offset: usize| buf.get(pos + offset).copied().unwrap_or(0);
    let first = byte(0);
    let len = match first {
        0x00..=0x7F => {
            return Unit::Char { code: u32::from(first), len: 1 };
        }
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return Unit::Malformed,
    };
    if end - pos < len {
        return Unit::Truncated;
    }

    let is_trail = |offset: usize| (0x80..=0xBF).contains(&byte(offset));
    let second = byte(1);
    let valid = match len {
        2 => first >= 0xC2 && is_trail(1),
        3 => {
            let second_ok = match first {
                0xE0 => (0xA0..=0xBF).contains(&second),
                0xED => (0x80..=0x9F).contains(&second),
                _ => is_trail(1),
            };
            second_ok && is_trail(2)
        }
        _ => {
            let second_ok = match first {
                0xF0 => (0x90..=0xBF).contains(&second),
                0xF4 => (0x80..=0x8F).contains(&second),
                _ => is_trail(1),
            };
            second_ok && is_trail(2) && is_trail(3)
        }
    };
    if !valid {
        return Unit::Malformed;
    }

    let mut code = u32::from(first) & (0x7F >> len);
    for offset in 1..len {
        code = (code << 6) | (u32::from(byte(offset)) & 0x3F);
    }

    Unit::Char { code, len }
}

fn decode_utf16(buf: &[u8], pos: usize, end: usize, big_endian: bool) -> Unit {
    let read = |at: usize| {
        let a = u32::from(buf.get(at).copied().unwrap_or(0));
        let b = u32::from(buf.get(at + 1).copied().unwrap_or(0));
        if big_endian { (a << 8) | b } else { (b << 8) | a }
    };
    if end - pos < 2 {
        return Unit::Truncated;
    }

    let first = read(pos);
    match first {
        0xD800..=0xDBFF => {
            if end - pos < 4 {
                return Unit::Truncated;
            }
            // The second unit is not checked; only its low ten bits count.
            let second = read(pos + 2);
            let code = 0x10000 + ((first & 0x3FF) << 10) + (second & 0x3FF);
            Unit::Char { code, len: 4 }
        }
        0xDC00..=0xDFFF => Unit::Malformed,
        _ => Unit::Char { code: first, len: 2 },
    }
}

/// The number of bytes UTF-8 needs for `code`.
pub(super) fn utf8_width(code: u32) -> usize {
    match code {
        0..=0x7F => 1,
        0x80..=0x7FF => 2,
        0x800..=0xFFFF => 3,
        _ => 4,
    }
}

/// Appends the UTF-8 form of `code`.
pub(super) fn push_utf8(code: u32, out: &mut Vec<u8>) {
    let Some(c) = char::from_u32(code) else {
        return;
    };
    let mut bytes = [0; 4];

    out.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes());
}

/// Looks up an encoding the parser knows by name, ignoring ASCII case.
/// `Utf16` stands for "UTF-16" without a byte order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum KnownEncoding {
    Latin1,
    Ascii,
    Utf8,
    Utf16,
    Utf16Be,
    Utf16Le,
}

impl KnownEncoding {
    pub(super) fn from_name(name: &[u8]) -> Option<Self> {
        const NAMES: [(&[u8], KnownEncoding); 6] = [
            (b"ISO-8859-1", KnownEncoding::Latin1),
            (b"US-ASCII", KnownEncoding::Ascii),
            (b"UTF-8", KnownEncoding::Utf8),
            (b"UTF-16", KnownEncoding::Utf16),
            (b"UTF-16BE", KnownEncoding::Utf16Be),
            (b"UTF-16LE", KnownEncoding::Utf16Le),
        ];

        NAMES.iter().find(|(known, _)| known.eq_ignore_ascii_case(name)).map(|&(_, encoding)| encoding)
    }

    pub(super) fn is_utf16(self) -> bool {
        matches!(self, Self::Utf16 | Self::Utf16Be | Self::Utf16Le)
    }

    /// The decoder for a stream in this encoding; plain "UTF-16" means big-endian.
    pub(super) fn encoding(self) -> Encoding {
        match self {
            Self::Latin1 => Encoding::Latin1,
            Self::Ascii => Encoding::Ascii,
            Self::Utf8 => Encoding::Utf8,
            Self::Utf16 | Self::Utf16Be => Encoding::Utf16 { big_endian: true },
            Self::Utf16Le => Encoding::Utf16 { big_endian: false },
        }
    }
}
