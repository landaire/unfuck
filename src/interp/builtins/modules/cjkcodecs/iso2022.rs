//! The ISO 2022 codecs: ISO-2022-JP and its extensions (RFC 1468, 2237,
//! JIS X 0213 annex 2), and ISO-2022-KR (RFC 1557).
//!
//! Decoding follows escape sequences of an intermediate run and a final
//! byte from `@` to `Z`, designating into G0, G1, or G2. Encoding picks the
//! first set of the variant, in its order of preference, that holds a
//! character, and designates it into G0 (ISO-2022-KR: shifts into G1).

use crate::interp::builtins::modules::cjkcodecs::codec::Fault;
use crate::interp::builtins::modules::cjkcodecs::codec::push_code_point;
use crate::interp::builtins::modules::cjkcodecs::codec::push_mapped;
use crate::interp::builtins::modules::cjkcodecs::data::Code;
use crate::interp::builtins::modules::cjkcodecs::data::DecodeTable;
use crate::interp::builtins::modules::cjkcodecs::data::Inverse;
use crate::interp::builtins::modules::cjkcodecs::data::Lookup;
use crate::interp::builtins::modules::cjkcodecs::data::Mapped;
use crate::interp::builtins::modules::cjkcodecs::data::layered;
use crate::interp::builtins::modules::cjkcodecs::sets;
use crate::interp::builtins::modules::cjkcodecs::tables;

const ESC: u8 = 0x1b;
const SO: u8 = 0x0e;
const SI: u8 = 0x0f;
const LF: u8 = 0x0a;

/// The bytes that end an escape sequence.
const FINAL_BYTES: std::ops::RangeInclusive<u8> = b'@'..=b'Z';

/// The longest escape sequence the decoder scans for a final byte.
const MAX_ESCAPE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Jp,
    Jp1,
    Jp2,
    Jp2004,
    Jp3,
    JpExt,
    Kr,
}

/// The character sets the variants designate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    Ascii,
    JisRoman,
    JisKatakana,
    Latin1,
    Greek,
    /// JIS C 6226-1978, decoded as JIS X 0208.
    Jisx0208Old,
    Jisx0208,
    Jisx0212,
    Gb2312,
    Ksx1001,
    Jisx0213Plane1Of2000,
    Jisx0213Plane1,
    Jisx0213Plane2,
}

impl Charset {
    /// The set an escape sequence names: `multibyte` for `$` sequences.
    fn from_final(multibyte: bool, last: u8) -> Option<Self> {
        let charset = match (multibyte, last) {
            (false, b'B') => Self::Ascii,
            (false, b'J') => Self::JisRoman,
            (false, b'I') => Self::JisKatakana,
            (false, b'A') => Self::Latin1,
            (false, b'F') => Self::Greek,
            (true, b'@') => Self::Jisx0208Old,
            (true, b'B') => Self::Jisx0208,
            (true, b'D') => Self::Jisx0212,
            (true, b'A') => Self::Gb2312,
            (true, b'C') => Self::Ksx1001,
            (true, b'O') => Self::Jisx0213Plane1Of2000,
            (true, b'Q') => Self::Jisx0213Plane1,
            (true, b'P') => Self::Jisx0213Plane2,
            _ => return None,
        };

        Some(charset)
    }

    /// What designates the set into G0 when encoding.
    fn designation(self) -> &'static [u8] {
        match self {
            Self::Ascii => b"\x1b(B",
            Self::JisRoman => b"\x1b(J",
            Self::JisKatakana => b"\x1b(I",
            Self::Latin1 => b"\x1b.A",
            Self::Greek => b"\x1b.F",
            Self::Jisx0208Old => b"\x1b$@",
            Self::Jisx0208 => b"\x1b$B",
            Self::Jisx0212 => b"\x1b$(D",
            Self::Gb2312 => b"\x1b$(A",
            Self::Ksx1001 => b"\x1b$(C",
            Self::Jisx0213Plane1Of2000 => b"\x1b$(O",
            Self::Jisx0213Plane1 => b"\x1b$(Q",
            Self::Jisx0213Plane2 => b"\x1b$(P",
        }
    }

    /// The decoding tables of a double-byte set, in lookup order.
    fn tables(self) -> &'static [&'static DecodeTable] {
        static JISX0208: [&DecodeTable; 1] = [&tables::JISX0208];
        static JISX0212: [&DecodeTable; 1] = [&tables::JISX0212];
        static GB2312: [&DecodeTable; 1] = [&tables::GB2312];
        static KSX1001: [&DecodeTable; 1] = [&tables::KSX1001];
        static PLANE1_2000: [&DecodeTable; 3] = [&tables::ISO2022_JP_3, &tables::JISX0208, &tables::JISX0213_1];
        static PLANE1: [&DecodeTable; 4] = [&tables::ISO2022_JP_2004, &tables::JISX0208, &tables::JISX0213_1, &tables::JISX0213_2004];
        static PLANE2: [&DecodeTable; 1] = [&tables::JISX0213_2];

        match self {
            Self::Jisx0208Old | Self::Jisx0208 => &JISX0208,
            Self::Jisx0212 => &JISX0212,
            Self::Gb2312 => &GB2312,
            Self::Ksx1001 => &KSX1001,
            Self::Jisx0213Plane1Of2000 => &PLANE1_2000,
            Self::Jisx0213Plane1 => &PLANE1,
            Self::Jisx0213Plane2 => &PLANE2,
            Self::Ascii | Self::JisRoman | Self::JisKatakana | Self::Latin1 | Self::Greek => &[],
        }
    }

    /// The encoding direction of a double-byte set for `variant`.
    fn inverse(self, variant: Variant) -> Option<&'static Inverse> {
        let inverse: &'static Inverse = match (self, variant) {
            (Self::Jisx0213Plane2, Variant::Jp3) => &sets::JISX0213_2_2000,
            _ => return self.common_inverse(),
        };

        Some(inverse)
    }

    fn common_inverse(self) -> Option<&'static Inverse> {
        let inverse: &'static Inverse = match self {
            Self::Jisx0208Old | Self::Jisx0208 => &sets::JISX0208,
            Self::Jisx0212 => &sets::JISX0212,
            Self::Gb2312 => &sets::GB2312,
            Self::Ksx1001 => &sets::KSX1001,
            Self::Jisx0213Plane1Of2000 => &sets::JISX0213_1_2000,
            Self::Jisx0213Plane1 => &sets::JISX0213_1_2004,
            Self::Jisx0213Plane2 => &sets::JISX0213_2,
            _ => return None,
        };

        Some(inverse)
    }

    /// The bytes that encode `code_point` in a single-byte set.
    fn single_byte(self, code_point: u32) -> Option<u8> {
        match (self, code_point) {
            (Self::JisRoman, 0xa5) => Some(0x5c),
            (Self::JisRoman, 0x203e) => Some(0x7e),
            (Self::JisKatakana, 0xff61..=0xff9f) => Some((code_point - 0xff61) as u8 + 0x21),
            _ => None,
        }
    }
}

impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Self::Jp => "iso2022_jp",
            Self::Jp1 => "iso2022_jp_1",
            Self::Jp2 => "iso2022_jp_2",
            Self::Jp2004 => "iso2022_jp_2004",
            Self::Jp3 => "iso2022_jp_3",
            Self::JpExt => "iso2022_jp_ext",
            Self::Kr => "iso2022_kr",
        }
    }

    /// The sets the decoder accepts designations of.
    fn charsets(self) -> &'static [Charset] {
        use Charset::*;
        match self {
            Self::Jp => &[Ascii, JisRoman, Jisx0208Old, Jisx0208],
            Self::Jp1 => &[Ascii, JisRoman, Jisx0208Old, Jisx0208, Jisx0212],
            Self::Jp2 => &[Ascii, JisRoman, Latin1, Greek, Jisx0208Old, Jisx0208, Jisx0212, Gb2312, Ksx1001],
            Self::Jp2004 => &[Ascii, Jisx0208, Jisx0213Plane1, Jisx0213Plane2],
            Self::Jp3 => &[Ascii, Jisx0208, Jisx0213Plane1Of2000, Jisx0213Plane2],
            Self::JpExt => &[Ascii, JisRoman, JisKatakana, Jisx0208Old, Jisx0208, Jisx0212],
            Self::Kr => &[Ascii, Ksx1001],
        }
    }

    /// The sets the encoder tries after ASCII, in order.
    fn preference(self) -> &'static [Charset] {
        use Charset::*;
        match self {
            Self::Jp => &[JisRoman, Jisx0208],
            Self::Jp1 => &[JisRoman, Jisx0208, Jisx0212],
            Self::Jp2 => &[JisRoman, Jisx0208, Jisx0212, Ksx1001, Gb2312],
            Self::Jp2004 => &[Jisx0208, Jisx0213Plane1, Jisx0213Plane2],
            Self::Jp3 => &[Jisx0208, Jisx0213Plane1Of2000, Jisx0213Plane2],
            Self::JpExt => &[JisRoman, Jisx0208, Jisx0212, JisKatakana],
            Self::Kr => &[Ksx1001],
        }
    }

    /// The plane-1 set whose combining pairs the encoder looks for.
    fn pair_set(self) -> Option<Charset> {
        match self {
            Self::Jp2004 => Some(Charset::Jisx0213Plane1),
            Self::Jp3 => Some(Charset::Jisx0213Plane1Of2000),
            _ => None,
        }
    }

    fn has_single_shift(self) -> bool {
        self == Self::Jp2
    }

    /// Whether `ESC & @` may announce the 1990 revision of JIS X 0208.
    fn has_revision_announcer(self) -> bool {
        self != Self::Kr
    }

    /// ISO-2022-KR shifts its double-byte set in with SO.
    fn shifts(self) -> bool {
        self == Self::Kr
    }
}

/// The graphic set register a designation fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Register {
    G0,
    G1,
    G2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderState {
    g0: Charset,
    /// ISO-2022-KR: shifted into G1.
    shifted: bool,
    /// ISO-2022-KR: the G1 designation was written.
    announced: bool,
}

impl EncoderState {
    pub fn new(_variant: Variant) -> Self {
        Self { g0: Charset::Ascii, shifted: false, announced: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderState {
    g0: Charset,
    /// `None` until designated; shifting in an undesignated G1 reads ASCII.
    g1: Option<Charset>,
    g2: Option<Charset>,
    /// Shifted into G1 (ISO-2022-KR).
    shifted: bool,
    /// Inside an escape that names no designation: bytes pass through
    /// until one in `@`..`Z`.
    literal: bool,
}

impl DecoderState {
    pub fn new(_variant: Variant) -> Self {
        Self { g0: Charset::Ascii, g1: None, g2: None, shifted: false, literal: false }
    }
}

/// Returns the encoder to ASCII without writing anything; ISO-2022-KR
/// remembers that it announced G1.
pub fn reset_encoder(state: &mut EncoderState) {
    state.g0 = Charset::Ascii;
    state.shifted = false;
}

/// Returns the decoder to ASCII in G0, keeping G1, G2, and an escape
/// being passed through.
pub fn reset_decoder(state: &mut DecoderState) {
    state.g0 = Charset::Ascii;
    state.shifted = false;
}

pub fn encode(variant: Variant, state: &mut EncoderState, input: &[u16], position: &mut usize, flush: bool, output: &mut Vec<u8>) -> Result<(), Fault> {
    while let Some(&unit) = input.get(*position) {
        if unit < 0x80 {
            leave_multibyte(variant, state, output);
            output.push(unit as u8);
            *position += 1;
            continue;
        }

        let (code_point, width) = match unit {
            0xd800..=0xdbff => match input.get(*position + 1) {
                None => return Err(Fault::Incomplete),
                Some(&low) if (0xdc00..0xe000).contains(&low) => ((u32::from(unit - 0xd800) << 10 | u32::from(low - 0xdc00)) + 0x10000, 2),
                Some(_) => (u32::from(unit), 1),
            },
            _ => (u32::from(unit), 1),
        };

        if let Some(pairs) = variant.pair_set() {
            let inverse = pairs.inverse(variant);
            if inverse.is_some_and(|inverse| inverse.starts_pair(code_point)) {
                match input.get(*position + width) {
                    None if !flush => return Err(Fault::Incomplete),
                    // A NUL after a character that can start a pair is
                    // dropped, and the character comes from the pair's set.
                    Some(0) => {
                        if let Some(code) = inverse.and_then(|inverse| inverse.single(code_point)) {
                            designate(variant, state, pairs, output);
                            output.extend_from_slice(code.as_bytes());
                            *position += width + 1;
                            continue;
                        }
                    }
                    Some(&next) => {
                        let code = u16::try_from(code_point).ok().and_then(|first| inverse.and_then(|inverse| inverse.pair(first, next)));
                        if let Some(code) = code {
                            designate(variant, state, pairs, output);
                            output.extend_from_slice(code.as_bytes());
                            *position += width + 1;
                            continue;
                        }
                    }
                    None => {}
                }
            }
        }

        let Some((charset, code)) = variant.preference().iter().find_map(|charset| charset_code(variant, *charset, code_point).map(|code| (*charset, code))) else {
            return Err(Fault::Illegal(1));
        };
        designate(variant, state, charset, output);
        output.extend_from_slice(code.as_bytes());
        *position += width;
    }

    Ok(())
}

fn charset_code(variant: Variant, charset: Charset, code_point: u32) -> Option<Code> {
    if let Some(byte) = charset.single_byte(code_point) {
        return Some(Code::single(byte));
    }

    charset.inverse(variant)?.single(code_point)
}

/// Writes what makes `charset` current: a G0 designation, or for
/// ISO-2022-KR the G1 announcement and a shift.
fn designate(variant: Variant, state: &mut EncoderState, charset: Charset, output: &mut Vec<u8>) {
    if variant.shifts() {
        if !state.announced {
            output.extend_from_slice(b"\x1b$)C");
            state.announced = true;
        }
        if !state.shifted {
            output.push(SO);
            state.shifted = true;
        }
        return;
    }

    if state.g0 != charset {
        output.extend_from_slice(charset.designation());
        state.g0 = charset;
    }
}

/// Writes what returns to ASCII before an ASCII character.
fn leave_multibyte(variant: Variant, state: &mut EncoderState, output: &mut Vec<u8>) {
    if variant.shifts() {
        if state.shifted {
            output.push(SI);
            state.shifted = false;
        }
        return;
    }

    if state.g0 != Charset::Ascii {
        output.extend_from_slice(Charset::Ascii.designation());
        state.g0 = Charset::Ascii;
    }
}

/// Appends what returns the output to the initial state.
pub fn reset(variant: Variant, state: &mut EncoderState, output: &mut Vec<u8>) {
    leave_multibyte(variant, state, output);
}

pub fn decode(variant: Variant, state: &mut DecoderState, input: &[u8], position: &mut usize, output: &mut Vec<u16>) -> Result<(), Fault> {
    while let Some(rest) = input.get(*position..).filter(|rest| !rest.is_empty()) {
        let byte = rest[0];

        if state.literal {
            state.literal = !FINAL_BYTES.contains(&byte);
            output.push(u16::from(byte));
            *position += 1;
            continue;
        }

        if byte == ESC {
            *position += escape(variant, state, rest, output)?;
            continue;
        }

        if variant.shifts() && (byte == SO || byte == SI) {
            state.shifted = byte == SO;
            *position += 1;
            continue;
        }

        if byte >= 0x80 {
            return Err(Fault::Illegal(1));
        }

        if byte < 0x20 {
            if variant.shifts() && byte == LF {
                state.shifted = false;
            }
            output.push(u16::from(byte));
            *position += 1;
            continue;
        }

        let charset = if state.shifted { state.g1.unwrap_or(Charset::Ascii) } else { state.g0 };
        *position += decode_graphic(charset, rest, output)?;
    }

    Ok(())
}

/// Decodes one character of `charset` at the start of `input`; returns
/// the bytes it took.
fn decode_graphic(charset: Charset, input: &[u8], output: &mut Vec<u16>) -> Result<usize, Fault> {
    let byte = input[0];

    match charset {
        Charset::Ascii => {
            output.push(u16::from(byte));
            Ok(1)
        }
        Charset::JisRoman => {
            let unit = match byte {
                0x5c => 0xa5,
                0x7e => 0x203e,
                _ => u16::from(byte),
            };
            output.push(unit);
            Ok(1)
        }
        Charset::JisKatakana if (0x21..=0x5f).contains(&byte) => {
            output.push(0xff61 + u16::from(byte - 0x21));
            Ok(1)
        }
        Charset::JisKatakana | Charset::Latin1 | Charset::Greek => Err(Fault::Illegal(1)),
        _ => {
            let Some(&trail) = input.get(1) else {
                return Err(Fault::Incomplete);
            };
            let mapped = layered(charset.tables(), u16::from_be_bytes([byte, trail])).ok_or(Fault::Illegal(2))?;
            push_mapped(output, mapped);
            Ok(2)
        }
    }
}

/// Handles an escape at the start of `input`; returns the bytes it took.
fn escape(variant: Variant, state: &mut DecoderState, input: &[u8], output: &mut Vec<u16>) -> Result<usize, Fault> {
    let Some(&second) = input.get(1) else {
        return Err(Fault::Incomplete);
    };

    if second == b'N' && variant.has_single_shift() {
        return single_shift(state, input, output);
    }
    if !matches!(second, b'$' | b'(' | b')' | b'.' | b'&') {
        output.push(u16::from(ESC));
        state.literal = true;
        return Ok(1);
    }

    let length = scan_escape(variant, input)?;

    let sequence = &input[..length];
    let designation = match sequence {
        // Six bytes ending in `ESC $ B` designate JIS X 0208 whatever the
        // first two after ESC, which covers the `ESC & @` announcer.
        [ESC, _, _, ESC, b'$', b'B'] if variant.has_revision_announcer() => Some((Register::G0, Charset::Jisx0208)),
        [ESC, b'$', last] | [ESC, b'$', b'(', last] => Charset::from_final(true, *last).map(|charset| (Register::G0, charset)),
        [ESC, b'$', b')', last] => Charset::from_final(true, *last).map(|charset| (Register::G1, charset)),
        [ESC, b'(', last] => Charset::from_final(false, *last).map(|charset| (Register::G0, charset)),
        [ESC, b')', last] => Charset::from_final(false, *last).map(|charset| (Register::G1, charset)),
        [ESC, b'.', last] if variant.has_single_shift() => Charset::from_final(false, *last).map(|charset| (Register::G2, charset)),
        _ => None,
    };
    let Some((register, charset)) = designation.filter(|(_, charset)| variant.charsets().contains(charset)) else {
        return Err(Fault::Illegal(length));
    };

    match register {
        Register::G0 => state.g0 = charset,
        Register::G1 => state.g1 = Some(charset),
        Register::G2 => state.g2 = Some(charset),
    }

    Ok(length)
}

/// The length of the escape sequence at the start of `input`, through
/// its final byte: an ESC beyond the longest sequence stands alone as
/// illegal. In the JIS variants `&@` does not end a sequence, so the
/// revision announcer reads on into the designation after it.
fn scan_escape(variant: Variant, input: &[u8]) -> Result<usize, Fault> {
    for index in 2..MAX_ESCAPE {
        let Some(&byte) = input.get(index) else {
            return Err(Fault::Incomplete);
        };
        let announcer = byte == b'@' && input.get(index - 1) == Some(&b'&') && variant.has_revision_announcer();
        if FINAL_BYTES.contains(&byte) && !announcer {
            return Ok(index + 1);
        }
    }

    Err(Fault::Illegal(1))
}

/// `ESC N`: one character of G2 from the next byte.
fn single_shift(state: &DecoderState, input: &[u8], output: &mut Vec<u16>) -> Result<usize, Fault> {
    let Some(&byte) = input.get(2) else {
        return Err(Fault::Incomplete);
    };
    let high = byte >= 0x80;
    match state.g2 {
        None | Some(Charset::Ascii) if !high => output.push(u16::from(byte)),
        Some(Charset::Latin1) if !high => output.push(u16::from(byte | 0x80)),
        None | Some(Charset::Ascii | Charset::Latin1) => return Err(Fault::Illegal(3)),
        // With ISO-8859-7 in G2 a byte with the high bit set reads as the
        // ASCII character of its low seven bits.
        Some(Charset::Greek) if high => output.push(u16::from(byte & 0x7f)),
        Some(Charset::Greek) => {
            let Lookup::Mapped(Mapped::Char(code_point)) = tables::ISO8859_7.lookup(u16::from(byte)) else {
                return Err(Fault::Illegal(3));
            };
            push_code_point(output, code_point);
        }
        Some(_) => return Err(Fault::Internal),
    }

    Ok(3)
}
