//! The codecs without shift state: ASCII plus one- to four-byte codes.
//!
//! Decoding composes the shared character sets with each codec's byte
//! layout. Encoding takes the first byte sequence, in the order single
//! bytes, two-byte codes, three-byte codes, that decodes to a character,
//! after the codec's overrides and before algorithmic forms (gb18030 four
//! bytes, EUC-KR composed syllables).

use std::sync::LazyLock;

use crate::interp::builtins::modules::cjkcodecs::codec::Family;
use crate::interp::builtins::modules::cjkcodecs::codec::Fault;
use crate::interp::builtins::modules::cjkcodecs::codec::char_at;
use crate::interp::builtins::modules::cjkcodecs::codec::push_mapped;
use crate::interp::builtins::modules::cjkcodecs::data::Code;
use crate::interp::builtins::modules::cjkcodecs::data::DecodeTable;
use crate::interp::builtins::modules::cjkcodecs::data::EncodeOverrides;
use crate::interp::builtins::modules::cjkcodecs::data::Inverse;
use crate::interp::builtins::modules::cjkcodecs::data::Lookup;
use crate::interp::builtins::modules::cjkcodecs::data::Mapped;
use crate::interp::builtins::modules::cjkcodecs::data::Override;
use crate::interp::builtins::modules::cjkcodecs::data::layered;
use crate::interp::builtins::modules::cjkcodecs::tables;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stateless {
    Gb2312,
    Gbk,
    Gb18030,
    Big5,
    Cp950,
    Big5HkScs,
    ShiftJis,
    Cp932,
    EucJp,
    ShiftJis2004,
    ShiftJisx0213,
    EucJis2004,
    EucJisx0213,
    EucKr,
    Cp949,
    Johab,
}

impl Stateless {
    pub fn name(self) -> &'static str {
        match self {
            Self::Gb2312 => "gb2312",
            Self::Gbk => "gbk",
            Self::Gb18030 => "gb18030",
            Self::Big5 => "big5",
            Self::Cp950 => "cp950",
            Self::Big5HkScs => "big5hkscs",
            Self::ShiftJis => "shift_jis",
            Self::Cp932 => "cp932",
            Self::EucJp => "euc_jp",
            Self::ShiftJis2004 => "shift_jis_2004",
            Self::ShiftJisx0213 => "shift_jisx0213",
            Self::EucJis2004 => "euc_jis_2004",
            Self::EucJisx0213 => "euc_jisx0213",
            Self::EucKr => "euc_kr",
            Self::Cp949 => "cp949",
            Self::Johab => "johab",
        }
    }

    pub fn family(self) -> Family {
        match self {
            Self::Gb2312 | Self::Gbk | Self::Gb18030 => Family::Chinese,
            Self::Big5 | Self::Cp950 => Family::Taiwanese,
            Self::Big5HkScs => Family::HongKong,
            Self::ShiftJis | Self::Cp932 | Self::EucJp | Self::ShiftJis2004 | Self::ShiftJisx0213 | Self::EucJis2004 | Self::EucJisx0213 => Family::Japanese,
            Self::EucKr | Self::Cp949 | Self::Johab => Family::Korean,
        }
    }

    /// Whether the encoder reads a surrogate pair as one character; the
    /// others reject each surrogate on its own.
    fn combines_surrogates(self) -> bool {
        matches!(self, Self::Gb18030 | Self::Big5HkScs | Self::ShiftJis2004 | Self::ShiftJisx0213 | Self::EucJis2004 | Self::EucJisx0213)
    }

    /// The JIS X 0213 encoders drop a NUL that follows a character that
    /// can start a combining pair.
    fn absorbs_nul_after_pair_start(self) -> bool {
        matches!(self, Self::ShiftJis2004 | Self::ShiftJisx0213 | Self::EucJis2004 | Self::EucJisx0213)
    }

    fn overrides(self) -> &'static EncodeOverrides {
        match self {
            Self::Gb2312 => &tables::GB2312_ENCODE,
            Self::Gbk => &tables::GBK_ENCODE,
            Self::Gb18030 => &tables::GB18030_ENCODE,
            Self::Big5 => &tables::BIG5_ENCODE,
            Self::Cp950 => &tables::CP950_ENCODE,
            Self::Big5HkScs => &tables::BIG5HKSCS_ENCODE,
            Self::ShiftJis => &tables::SHIFT_JIS_ENCODE,
            Self::Cp932 => &tables::CP932_ENCODE,
            Self::EucJp => &tables::EUC_JP_ENCODE,
            Self::ShiftJis2004 => &tables::SHIFT_JIS_2004_ENCODE,
            Self::ShiftJisx0213 => &tables::SHIFT_JISX0213_ENCODE,
            Self::EucJis2004 => &tables::EUC_JIS_2004_ENCODE,
            Self::EucJisx0213 => &tables::EUC_JISX0213_ENCODE,
            Self::EucKr => &tables::EUC_KR_ENCODE,
            Self::Cp949 => &tables::CP949_ENCODE,
            Self::Johab => &tables::JOHAB_ENCODE,
        }
    }

    fn inverse(self) -> &'static Inverse {
        macro_rules! inverse_of {
            ($codec:expr) => {{
                static INVERSE: LazyLock<Inverse> = LazyLock::new(|| build_inverse($codec));
                &INVERSE
            }};
        }

        match self {
            Self::Gb2312 => inverse_of!(Stateless::Gb2312),
            Self::Gbk => inverse_of!(Stateless::Gbk),
            Self::Gb18030 => inverse_of!(Stateless::Gb18030),
            Self::Big5 => inverse_of!(Stateless::Big5),
            Self::Cp950 => inverse_of!(Stateless::Cp950),
            Self::Big5HkScs => inverse_of!(Stateless::Big5HkScs),
            Self::ShiftJis => inverse_of!(Stateless::ShiftJis),
            Self::Cp932 => inverse_of!(Stateless::Cp932),
            Self::EucJp => inverse_of!(Stateless::EucJp),
            Self::ShiftJis2004 => inverse_of!(Stateless::ShiftJis2004),
            Self::ShiftJisx0213 => inverse_of!(Stateless::ShiftJisx0213),
            Self::EucJis2004 => inverse_of!(Stateless::EucJis2004),
            Self::EucJisx0213 => inverse_of!(Stateless::EucJisx0213),
            Self::EucKr => inverse_of!(Stateless::EucKr),
            Self::Cp949 => inverse_of!(Stateless::Cp949),
            Self::Johab => inverse_of!(Stateless::Johab),
        }
    }

    /// The character at the start of `input` and the bytes it takes.
    pub fn decode_char(self, input: &[u8]) -> Result<(Mapped, usize), Fault> {
        let Some(&lead) = input.first() else {
            return Err(Fault::Incomplete);
        };

        match self {
            Self::Gb2312 => euc_double(input, &[&tables::GB2312]),
            Self::Gbk => double(input, |key| layered(&[&tables::GBK], key).or_else(|| euc(key).and_then(|key| layered(&[&tables::GB2312], key)))),
            Self::Gb18030 => gb18030_decode(input),
            Self::Big5 => double(input, |key| layered(&[&tables::BIG5], key)),
            Self::Cp950 => double(input, |key| layered(&[&tables::CP950, &tables::BIG5], key)),
            Self::Big5HkScs => double(input, |key| layered(&[&tables::BIG5HKSCS, &tables::BIG5], key)),
            Self::ShiftJis => match lead {
                0x00..=0x7f => Ok((Mapped::Char(u32::from(lead)), 1)),
                0xa1..=0xdf => Ok((half_width_katakana(lead), 1)),
                0x81..=0x9f | 0xe0..=0xea => double(input, |key| sjis_to_jis(key).and_then(|key| layered(&[&tables::JISX0208], key))),
                _ => Err(Fault::Illegal(2)),
            },
            Self::Cp932 => cp932_decode(input, lead),
            Self::EucJp => euc_jp_decode(input, lead, &[&tables::JISX0208], &[&tables::JISX0212]),
            Self::EucJis2004 => euc_jp_decode(input, lead, &[&tables::JISX0208, &tables::JISX0213_1, &tables::JISX0213_2004], &[&tables::JISX0213_2, &tables::JISX0212]),
            Self::EucJisx0213 => euc_jp_decode(input, lead, &[&tables::JISX0208, &tables::JISX0213_1], &[&tables::JISX0213_2_2000, &tables::JISX0213_2, &tables::JISX0212]),
            Self::ShiftJis2004 => sjis_0213_decode(input, lead, &tables::SHIFT_JIS_2004, &[&tables::JISX0208, &tables::JISX0213_1, &tables::JISX0213_2004], &[&tables::JISX0213_2]),
            Self::ShiftJisx0213 => sjis_0213_decode(input, lead, &tables::SHIFT_JISX0213, &[&tables::JISX0208, &tables::JISX0213_1], &[&tables::JISX0213_2]),
            Self::EucKr => euc_kr_decode(input),
            Self::Cp949 => double(input, |key| layered(&[&tables::CP949], key).or_else(|| euc(key).and_then(|key| layered(&[&tables::KSX1001], key)))),
            Self::Johab => johab_decode(input),
        }
    }

    /// Algorithmic forms tried after the table lookups miss.
    fn fallback(self, code_point: u32) -> Option<Fallback> {
        match self {
            Self::Gb18030 => gb18030_four_bytes(code_point).map(Fallback::Code),
            Self::EucKr => euc_kr_compose(code_point).map(Fallback::Composed),
            _ => None,
        }
    }
}

/// An algorithmic encoding.
enum Fallback {
    Code(Code),
    /// The eight bytes of a composed EUC-KR syllable.
    Composed([u8; 8]),
}

pub fn decode(codec: Stateless, input: &[u8], position: &mut usize, output: &mut Vec<u16>) -> Result<(), Fault> {
    while let Some(rest) = input.get(*position..).filter(|rest| !rest.is_empty()) {
        if let Some(&byte) = rest.first().filter(|byte| **byte < 0x80 && codec_has_ascii(codec, **byte)) {
            output.push(u16::from(byte));
            *position += 1;
            continue;
        }

        let (mapped, length) = codec.decode_char(rest)?;
        push_mapped(output, mapped);
        *position += length;
    }

    Ok(())
}

/// Whether a byte below 0x80 decodes as ASCII; the JIS X 0213 Shift_JIS
/// codecs map two of them elsewhere.
fn codec_has_ascii(codec: Stateless, byte: u8) -> bool {
    !matches!((codec, byte), (Stateless::ShiftJis2004 | Stateless::ShiftJisx0213, 0x5c | 0x7e))
}

pub fn encode(codec: Stateless, input: &[u16], position: &mut usize, flush: bool, output: &mut Vec<u8>) -> Result<(), Fault> {
    let inverse = codec.inverse();
    let overrides = codec.overrides();

    while *position < input.len() {
        let (code_point, width) = if codec.combines_surrogates() { char_at(input, *position)? } else { (u32::from(input[*position]), 1) };

        match overrides.lookup(code_point) {
            Some(Override::Encode(code)) => {
                output.extend_from_slice(code.as_bytes());
                *position += width;
                continue;
            }
            Some(Override::Unencodable) => return Err(Fault::Illegal(width)),
            None => {}
        }

        if inverse.starts_pair(code_point) {
            match input.get(*position + width) {
                None if !flush => return Err(Fault::Incomplete),
                Some(0) if codec.absorbs_nul_after_pair_start() => {
                    if let Some(code) = inverse.single(code_point) {
                        output.extend_from_slice(code.as_bytes());
                        *position += width + 1;
                        continue;
                    }
                }
                Some(&next) => {
                    if let Some(code) = u16::try_from(code_point).ok().and_then(|first| inverse.pair(first, next)) {
                        output.extend_from_slice(code.as_bytes());
                        *position += width + 1;
                        continue;
                    }
                }
                None => {}
            }
        }

        if let Some(code) = inverse.single(code_point) {
            output.extend_from_slice(code.as_bytes());
            *position += width;
            continue;
        }

        match codec.fallback(code_point) {
            Some(Fallback::Code(code)) => output.extend_from_slice(code.as_bytes()),
            Some(Fallback::Composed(bytes)) => output.extend_from_slice(&bytes),
            None => return Err(Fault::Illegal(width)),
        }
        *position += width;
    }

    Ok(())
}

/// The first-match inverse of a codec's decoding.
fn build_inverse(codec: Stateless) -> Inverse {
    let mut inverse = Inverse::default();

    let mut leads = Vec::new();
    for byte in 0..=u8::MAX {
        match codec.decode_char(&[byte]) {
            Ok((mapped, 1)) => inverse.insert(mapped, Code::single(byte)),
            _ => leads.push(byte),
        }
    }

    for lead in leads {
        for trail in 0..=u8::MAX {
            if let Ok((mapped, 2)) = codec.decode_char(&[lead, trail]) {
                inverse.insert(mapped, Code::double(u16::from_be_bytes([lead, trail])));
            }
        }
    }

    // The EUC codecs of JIS X 0213 prefer plane 2 over JIS X 0212.
    let three_byte: &[&DecodeTable] = match codec {
        Stateless::EucJp => &[&tables::JISX0212],
        Stateless::EucJis2004 | Stateless::EucJisx0213 => &[&tables::JISX0213_2, &tables::JISX0212],
        _ => &[],
    };
    for preferred in three_byte {
        for (key, _) in preferred.entries() {
            let [second, third] = (key | 0x8080).to_be_bytes();
            let bytes = [0x8f, second, third];
            if let (Ok((mapped, 3)), Some(code)) = (codec.decode_char(&bytes), Code::new(&bytes)) {
                inverse.insert(mapped, code);
            }
        }
    }

    inverse
}

fn half_width_katakana(byte: u8) -> Mapped {
    Mapped::Char(0xff61 + u32::from(byte - 0xa1))
}

/// A two-byte code looked up by `lookup`; any lead takes a trail byte.
fn double(input: &[u8], lookup: impl Fn(u16) -> Option<Mapped>) -> Result<(Mapped, usize), Fault> {
    let [lead, rest @ ..] = input else {
        return Err(Fault::Incomplete);
    };
    if *lead < 0x80 {
        return Ok((Mapped::Char(u32::from(*lead)), 1));
    }
    let Some(trail) = rest.first() else {
        return Err(Fault::Incomplete);
    };

    lookup(u16::from_be_bytes([*lead, *trail])).map(|mapped| (mapped, 2)).ok_or(Fault::Illegal(2))
}

/// The 7-bit form of a code with both bytes in A1-FE.
fn euc(key: u16) -> Option<u16> {
    let [lead, trail] = key.to_be_bytes();

    ((0xa1..=0xfe).contains(&lead) && (0xa1..=0xfe).contains(&trail)).then(|| key - 0x8080)
}

fn euc_double(input: &[u8], sets: &[&DecodeTable]) -> Result<(Mapped, usize), Fault> {
    double(input, |key| euc(key).and_then(|key| layered(sets, key)))
}

/// The JIS row and cell of a plane-1 Shift_JIS code.
pub fn sjis_to_jis(key: u16) -> Option<u16> {
    let [lead, trail] = key.to_be_bytes();
    if !matches!(lead, 0x81..=0x9f | 0xe0..=0xef) || !(0x40..=0xfc).contains(&trail) || trail == 0x7f {
        return None;
    }

    let row = u16::from(if lead < 0xe0 { lead - 0x81 } else { lead - 0xc1 }) * 2 + 0x21;
    let (row, cell) = match trail {
        0x9f.. => (row + 1, u16::from(trail - 0x9f) + 0x21),
        0x80.. => (row, u16::from(trail - 0x41) + 0x21),
        _ => (row, u16::from(trail - 0x40) + 0x21),
    };

    Some(row << 8 | cell)
}

/// The JIS X 0213 plane-2 row and cell of a Shift_JIS code with lead F0-FC.
fn sjis_plane2(key: u16) -> Option<u16> {
    let [lead, trail] = key.to_be_bytes();
    if !(0xf0..=0xfc).contains(&lead) || !(0x40..=0xfc).contains(&trail) || trail == 0x7f {
        return None;
    }

    // Plane 2 uses rows 1, 3-5, 8, 12-15, and 78-94.
    let high = trail >= 0x9f;
    let row: u16 = match (lead, high) {
        (0xf0, false) => 1,
        (0xf0, true) => 8,
        (0xf1, false) => 3,
        (0xf1, true) => 4,
        (0xf2, false) => 5,
        (0xf2, true) => 12,
        (0xf3, false) => 13,
        (0xf3, true) => 14,
        (0xf4, false) => 15,
        (0xf4, true) => 78,
        (_, false) => 79 + u16::from(lead - 0xf5) * 2,
        (_, true) => 80 + u16::from(lead - 0xf5) * 2,
    };
    let cell = match trail {
        0x9f.. => u16::from(trail - 0x9f) + 0x21,
        0x80.. => u16::from(trail - 0x41) + 0x21,
        _ => u16::from(trail - 0x40) + 0x21,
    };

    Some((row + 0x20) << 8 | cell)
}

fn cp932_decode(input: &[u8], lead: u8) -> Result<(Mapped, usize), Fault> {
    if let Lookup::Mapped(mapped) = tables::CP932.lookup(u16::from(lead)) {
        return Ok((mapped, 1));
    }

    match lead {
        0x00..=0x80 => Ok((Mapped::Char(u32::from(lead)), 1)),
        0xa1..=0xdf => Ok((half_width_katakana(lead), 1)),
        _ => double(input, |key| layered(&[&tables::CP932], key).or_else(|| sjis_to_jis(key).and_then(|key| layered(&[&tables::JISX0208], key)))),
    }
}

fn euc_jp_decode(input: &[u8], lead: u8, plane1: &[&DecodeTable], three_byte: &[&DecodeTable]) -> Result<(Mapped, usize), Fault> {
    match lead {
        0x00..=0x7f => Ok((Mapped::Char(u32::from(lead)), 1)),
        0x8e => {
            let Some(&trail) = input.get(1) else {
                return Err(Fault::Incomplete);
            };
            if (0xa1..=0xdf).contains(&trail) { Ok((half_width_katakana(trail), 2)) } else { Err(Fault::Illegal(2)) }
        }
        0x8f => {
            let [_, second, third, ..] = input else {
                return Err(Fault::Incomplete);
            };
            euc(u16::from_be_bytes([*second, *third])).and_then(|key| layered(three_byte, key)).map(|mapped| (mapped, 3)).ok_or(Fault::Illegal(3))
        }
        _ => euc_double(input, plane1),
    }
}

fn sjis_0213_decode(input: &[u8], lead: u8, deviations: &DecodeTable, plane1: &[&DecodeTable], plane2: &[&DecodeTable]) -> Result<(Mapped, usize), Fault> {
    if let Lookup::Mapped(mapped) = deviations.lookup(u16::from(lead)) {
        return Ok((mapped, 1));
    }

    match lead {
        0x00..=0x7f => Ok((Mapped::Char(u32::from(lead)), 1)),
        0xa1..=0xdf => Ok((half_width_katakana(lead), 1)),
        0x81..=0x9f | 0xe0..=0xfc => double(input, |key| match deviations.lookup(key) {
            Lookup::Mapped(mapped) => Some(mapped),
            Lookup::Removed => None,
            Lookup::Absent => match sjis_to_jis(key) {
                Some(jis) => layered(plane1, jis),
                None => sjis_plane2(key).and_then(|jis| layered(plane2, jis)),
            },
        }),
        _ => Err(Fault::Illegal(2)),
    }
}

/// The four-byte gb18030 index of a code, or `None` when the bytes are
/// out of range.
fn gb18030_index(bytes: &[u8]) -> Option<u32> {
    let [first, second, third, fourth] = bytes else {
        return None;
    };
    if !(0x81..=0xfe).contains(first) || !(0x30..=0x39).contains(second) || *third < 0x81 || !(0x30..=0x39).contains(fourth) {
        return None;
    }

    Some(((u32::from(first - 0x81) * 10 + u32::from(second - 0x30)) * 126 + u32::from(third - 0x81)) * 10 + u32::from(fourth - 0x30))
}

/// The first four-byte index of a code point beyond the BMP.
const GB18030_ASTRAL_BASE: u32 = 189_000;
/// The four-byte indexes that map into the BMP.
const GB18030_BMP_INDEXES: u32 = 39_420;

fn gb18030_decode(input: &[u8]) -> Result<(Mapped, usize), Fault> {
    let [lead, rest @ ..] = input else {
        return Err(Fault::Incomplete);
    };
    if *lead < 0x80 {
        return Ok((Mapped::Char(u32::from(*lead)), 1));
    }
    let Some(&second) = rest.first() else {
        return Err(Fault::Incomplete);
    };

    if (0x30..=0x39).contains(&second) {
        let Some(bytes) = input.get(..4) else {
            return Err(Fault::Incomplete);
        };
        let Some(index) = gb18030_index(bytes) else {
            return Err(Fault::Illegal(4));
        };
        // The first byte selects the BMP (81-84) or the other planes
        // (90-E3); a third byte of FF carries into the next index but not
        // across that split.
        let code_point = match lead {
            0x81..=0x84 => tables::GB18030_RANGES.code_point(index).filter(|_| index < GB18030_BMP_INDEXES),
            0x90..=0xe3 => index.checked_sub(GB18030_ASTRAL_BASE).filter(|offset| *offset < 0x10_0000).map(|offset| offset + 0x10000),
            _ => None,
        };
        return code_point.map(|code_point| (Mapped::Char(code_point), 4)).ok_or(Fault::Illegal(4));
    }

    double(input, |key| layered(&[&tables::GB18030, &tables::GBK], key).or_else(|| euc(key).and_then(|key| layered(&[&tables::GB2312], key))))
}

fn gb18030_four_bytes(code_point: u32) -> Option<Code> {
    let index = if code_point >= 0x10000 { code_point - 0x10000 + GB18030_ASTRAL_BASE } else { tables::GB18030_RANGES.index(code_point)? };
    let bytes = [0x81 + (index / 12600) as u8, 0x30 + (index / 1260 % 10) as u8, 0x81 + (index / 10 % 126) as u8, 0x30 + (index % 10) as u8];

    Code::new(&bytes)
}

/// Compatibility jamo of the initial consonants in syllable order.
const INITIALS: [u16; 19] = [0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145, 0x3146, 0x3147, 0x3148, 0x3149, 0x314a, 0x314b, 0x314c, 0x314d, 0x314e];
/// Compatibility jamo of the final consonants in syllable order, after
/// the absent final.
const FINALS: [u16; 27] = [
    0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313a, 0x313b, 0x313c, 0x313d, 0x313e, 0x313f, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145, 0x3146, 0x3147, 0x3148, 0x314a, 0x314b, 0x314c, 0x314d, 0x314e,
];
const FIRST_VOWEL: u16 = 0x314f;
const VOWELS: u16 = 21;
const FIRST_SYLLABLE: u32 = 0xac00;
const LAST_SYLLABLE: u32 = 0xd7a3;
/// The KS X 1001 Hangul filler, which also starts a composed syllable.
const KS_FILLER: [u8; 2] = [0xa4, 0xd4];

/// The compatibility jamo a KS X 1001 code in row 4 stands for.
fn ks_jamo(bytes: &[u8]) -> Option<u16> {
    let [0xa4, trail] = bytes else {
        return None;
    };
    let Lookup::Mapped(Mapped::Char(code_point)) = tables::KSX1001.lookup(0x2400 | u16::from(trail.wrapping_sub(0x80))) else {
        return None;
    };

    u16::try_from(code_point).ok()
}

fn euc_kr_decode(input: &[u8]) -> Result<(Mapped, usize), Fault> {
    if input.get(..2) != Some(KS_FILLER.as_slice()) {
        return euc_double(input, &[&tables::KSX1001]);
    }

    let Some(bytes) = input.get(..8) else {
        return Err(Fault::Incomplete);
    };
    let initial = ks_jamo(&bytes[2..4]).and_then(|jamo| INITIALS.iter().position(|initial| *initial == jamo));
    let medial = ks_jamo(&bytes[4..6]).and_then(|jamo| jamo.checked_sub(FIRST_VOWEL)).filter(|medial| *medial < VOWELS);
    let last = if bytes[6..8] == KS_FILLER { Some(0) } else { ks_jamo(&bytes[6..8]).and_then(|jamo| FINALS.iter().position(|last| *last == jamo)).map(|index| index + 1) };
    let (Some(initial), Some(medial), Some(last)) = (initial, medial, last) else {
        return Err(Fault::Illegal(8));
    };

    let code_point = FIRST_SYLLABLE + ((initial as u32 * u32::from(VOWELS) + u32::from(medial)) * 28 + last as u32);

    Ok((Mapped::Char(code_point), 8))
}

fn euc_kr_compose(code_point: u32) -> Option<[u8; 8]> {
    if !(FIRST_SYLLABLE..=LAST_SYLLABLE).contains(&code_point) {
        return None;
    }
    let index = code_point - FIRST_SYLLABLE;
    let initial = INITIALS.get((index / 588) as usize)?;
    let medial = FIRST_VOWEL + ((index / 28) % u32::from(VOWELS)) as u16;
    let last = match index % 28 {
        0 => None,
        position => Some(*FINALS.get(position as usize - 1)?),
    };

    let inverse = Stateless::EucKr.inverse();
    let code = |jamo: u16| inverse.single(u32::from(jamo)).map(|code| code.as_bytes().to_vec()).filter(|bytes| bytes.len() == 2);
    let initial = code(*initial)?;
    let medial = code(medial)?;
    let last = match last {
        Some(jamo) => code(jamo)?,
        None => KS_FILLER.to_vec(),
    };

    Some([KS_FILLER[0], KS_FILLER[1], initial[0], initial[1], medial[0], medial[1], last[0], last[1]])
}

/// Johab fills an absent initial, vowel, or final with these field values.
const JOHAB_INITIAL_FILL: u16 = 1;
const JOHAB_VOWEL_FILL: u16 = 2;
const JOHAB_FINAL_FILL: u16 = 1;

/// The vowel index of a Johab vowel field.
fn johab_vowel(field: u16) -> Option<u16> {
    match field {
        3..=7 => Some(field - 3),
        10..=15 => Some(field - 5),
        18..=23 => Some(field - 7),
        26..=29 => Some(field - 9),
        _ => None,
    }
}

/// The final index (1-27) of a Johab final field.
fn johab_final(field: u16) -> Option<u16> {
    match field {
        2..=17 => Some(field - 1),
        19..=29 => Some(field - 2),
        _ => None,
    }
}

fn johab_decode(input: &[u8]) -> Result<(Mapped, usize), Fault> {
    double(input, |key| {
        let [lead, _] = key.to_be_bytes();
        if (0x84..=0xd3).contains(&lead) {
            return johab_hangul(key);
        }
        johab_symbol(key).and_then(|key| layered(&[&tables::KSX1001], key))
    })
}

fn johab_hangul(key: u16) -> Option<Mapped> {
    let initial = key >> 10 & 0x1f;
    let vowel = key >> 5 & 0x1f;
    let last = key & 0x1f;

    let code_point = match (initial, vowel, last) {
        (JOHAB_INITIAL_FILL, JOHAB_VOWEL_FILL, JOHAB_FINAL_FILL) => 0x3000,
        (JOHAB_INITIAL_FILL, JOHAB_VOWEL_FILL, last) => u32::from(*FINALS.get(usize::from(johab_final(last)?) - 1)?),
        (JOHAB_INITIAL_FILL, vowel, JOHAB_FINAL_FILL) => u32::from(FIRST_VOWEL + johab_vowel(vowel)?),
        (initial, JOHAB_VOWEL_FILL, JOHAB_FINAL_FILL) => u32::from(*INITIALS.get(usize::from(initial.checked_sub(2)?))?),
        (initial, vowel, last) => {
            let initial = u32::from(initial.checked_sub(2).filter(|initial| *initial < 19)?);
            let vowel = u32::from(johab_vowel(vowel)?);
            let last = if last == JOHAB_FINAL_FILL { 0 } else { u32::from(johab_final(last)?) };
            FIRST_SYLLABLE + (initial * u32::from(VOWELS) + vowel) * 28 + last
        }
    };

    Some(Mapped::Char(code_point))
}

/// The KS X 1001 row and cell of a Johab symbol or Hanja code.
fn johab_symbol(key: u16) -> Option<u16> {
    let [lead, trail] = key.to_be_bytes();
    let row = match lead {
        0xd9..=0xde => 0x21 + u16::from(lead - 0xd9) * 2,
        0xe0..=0xf9 => 0x4a + u16::from(lead - 0xe0) * 2,
        _ => return None,
    };
    let (row, cell) = match trail {
        0x31..=0x7e => (row, u16::from(trail) - 0x10),
        0x91..=0xa0 => (row, u16::from(trail) - 0x22),
        0xa1..=0xfe => (row + 1, u16::from(trail) - 0x80),
        _ => return None,
    };
    // Johab codes the KS X 1001 jamo in its Hangul area instead.
    if row == 0x24 && cell < 0x54 {
        return None;
    }

    Some(row << 8 | cell)
}
