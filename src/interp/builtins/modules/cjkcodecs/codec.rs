//! The codecs the `_codecs_*` modules provide, as state machines over
//! UTF-16 units and bytes that `_multibytecodec` drives.

use crate::interp::builtins::modules::cjkcodecs::data::Mapped;
use crate::interp::builtins::modules::cjkcodecs::hz;
use crate::interp::builtins::modules::cjkcodecs::iso2022;
use crate::interp::builtins::modules::cjkcodecs::stateless;
use crate::interp::builtins::modules::cjkcodecs::stateless::Stateless;

/// Why a codec stopped before the end of its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// This many units or bytes from the current position are invalid.
    Illegal(usize),
    /// The input ends inside a sequence.
    Incomplete,
    /// The codec reached a state it cannot decode from.
    Internal,
}

/// The module that defines a codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Chinese,
    HongKong,
    Iso2022,
    Japanese,
    Korean,
    Taiwanese,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Stateless(Stateless),
    Hz,
    Iso2022(iso2022::Variant),
}

/// The state an encoder carries between calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderState {
    Stateless,
    Hz(hz::Mode),
    Iso2022(iso2022::EncoderState),
}

/// The state a decoder carries between calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoderState {
    Stateless,
    Hz(hz::Mode),
    Iso2022(iso2022::DecoderState),
}

impl Codec {
    pub const ALL: [Self; 24] = [
        Self::Stateless(Stateless::Gb2312),
        Self::Stateless(Stateless::Gbk),
        Self::Stateless(Stateless::Gb18030),
        Self::Hz,
        Self::Stateless(Stateless::Big5HkScs),
        Self::Iso2022(iso2022::Variant::Kr),
        Self::Iso2022(iso2022::Variant::Jp),
        Self::Iso2022(iso2022::Variant::Jp1),
        Self::Iso2022(iso2022::Variant::Jp2),
        Self::Iso2022(iso2022::Variant::Jp2004),
        Self::Iso2022(iso2022::Variant::Jp3),
        Self::Iso2022(iso2022::Variant::JpExt),
        Self::Stateless(Stateless::ShiftJis),
        Self::Stateless(Stateless::Cp932),
        Self::Stateless(Stateless::EucJp),
        Self::Stateless(Stateless::ShiftJis2004),
        Self::Stateless(Stateless::EucJis2004),
        Self::Stateless(Stateless::EucJisx0213),
        Self::Stateless(Stateless::ShiftJisx0213),
        Self::Stateless(Stateless::EucKr),
        Self::Stateless(Stateless::Cp949),
        Self::Stateless(Stateless::Johab),
        Self::Stateless(Stateless::Big5),
        Self::Stateless(Stateless::Cp950),
    ];

    /// The name `getcodec` accepts and `UnicodeError`s report.
    pub fn name(self) -> &'static str {
        match self {
            Self::Stateless(codec) => codec.name(),
            Self::Hz => "hz",
            Self::Iso2022(variant) => variant.name(),
        }
    }

    pub fn family(self) -> Family {
        match self {
            Self::Stateless(codec) => codec.family(),
            Self::Hz => Family::Chinese,
            Self::Iso2022(_) => Family::Iso2022,
        }
    }

    pub fn encoder_state(self) -> EncoderState {
        match self {
            Self::Stateless(_) => EncoderState::Stateless,
            Self::Hz => EncoderState::Hz(hz::Mode::Ascii),
            Self::Iso2022(variant) => EncoderState::Iso2022(iso2022::EncoderState::new(variant)),
        }
    }

    pub fn decoder_state(self) -> DecoderState {
        match self {
            Self::Stateless(_) => DecoderState::Stateless,
            Self::Hz => DecoderState::Hz(hz::Mode::Ascii),
            Self::Iso2022(variant) => DecoderState::Iso2022(iso2022::DecoderState::new(variant)),
        }
    }

    /// Encodes from `*position` until the input ends or a fault; on a
    /// fault `*position` is where the faulty character starts. Without
    /// `flush`, a character that may combine with the next one stops
    /// encoding as `Incomplete` at the end of the input.
    pub fn encode(self, state: &mut EncoderState, input: &[u16], position: &mut usize, flush: bool, output: &mut Vec<u8>) -> Result<(), Fault> {
        match (self, state) {
            (Self::Stateless(codec), _) => stateless::encode(codec, input, position, flush, output),
            (Self::Hz, EncoderState::Hz(mode)) => hz::encode(mode, input, position, output),
            (Self::Iso2022(variant), EncoderState::Iso2022(state)) => iso2022::encode(variant, state, input, position, flush, output),
            // A state of another codec never reaches here; start afresh.
            (codec, state) => {
                *state = codec.encoder_state();
                codec.encode(state, input, position, flush, output)
            }
        }
    }

    /// Appends what returns the output to the initial state.
    pub fn encode_reset(self, state: &mut EncoderState, output: &mut Vec<u8>) {
        match (self, state) {
            (Self::Hz, EncoderState::Hz(mode)) => hz::reset(mode, output),
            (Self::Iso2022(variant), EncoderState::Iso2022(state)) => iso2022::reset(variant, state, output),
            // Stateless codecs, and states of another codec, have nothing
            // to finish.
            _ => {}
        }
    }

    /// The state `reset()` of an incremental or stream object leaves.
    pub fn reset_encoder(self, state: &mut EncoderState) {
        match state {
            EncoderState::Iso2022(state) => iso2022::reset_encoder(state),
            _ => *state = self.encoder_state(),
        }
    }

    pub fn reset_decoder(self, state: &mut DecoderState) {
        match state {
            DecoderState::Iso2022(state) => iso2022::reset_decoder(state),
            _ => *state = self.decoder_state(),
        }
    }

    /// Decodes from `*position` until the input ends or a fault.
    pub fn decode(self, state: &mut DecoderState, input: &[u8], position: &mut usize, output: &mut Vec<u16>) -> Result<(), Fault> {
        match (self, state) {
            (Self::Stateless(codec), _) => stateless::decode(codec, input, position, output),
            (Self::Hz, DecoderState::Hz(mode)) => hz::decode(mode, input, position, output),
            (Self::Iso2022(variant), DecoderState::Iso2022(state)) => iso2022::decode(variant, state, input, position, output),
            // A state of another codec never reaches here; start afresh.
            (codec, state) => {
                *state = codec.decoder_state();
                codec.decode(state, input, position, output)
            }
        }
    }
}

/// Looks a codec up by the name `getcodec` receives.
pub fn find(family: Family, name: &[u8]) -> Option<Codec> {
    Codec::ALL.into_iter().find(|codec| codec.family() == family && codec.name().as_bytes() == name)
}

/// Appends the UTF-16 form of a decoded value.
pub fn push_mapped(output: &mut Vec<u16>, mapped: Mapped) {
    match mapped {
        Mapped::Char(code_point) => push_code_point(output, code_point),
        Mapped::Pair(first, second) => output.extend([first, second]),
    }
}

pub fn push_code_point(output: &mut Vec<u16>, code_point: u32) {
    match u16::try_from(code_point) {
        Ok(unit) => output.push(unit),
        Err(_) => {
            let offset = code_point - 0x10000;
            output.extend([0xd800 | (offset >> 10) as u16, 0xdc00 | (offset & 0x3ff) as u16]);
        }
    }
}

/// The character at `position` and how many units it takes: a surrogate
/// pair combines, and a high surrogate at the end may still be completed.
pub fn char_at(input: &[u16], position: usize) -> Result<(u32, usize), Fault> {
    let Some(&unit) = input.get(position) else {
        return Err(Fault::Incomplete);
    };
    if !(0xd800..0xdc00).contains(&unit) {
        return Ok((u32::from(unit), 1));
    }

    match input.get(position + 1) {
        None => Err(Fault::Incomplete),
        Some(&low) if (0xdc00..0xe000).contains(&low) => Ok(((u32::from(unit - 0xd800) << 10 | u32::from(low - 0xdc00)) + 0x10000, 2)),
        Some(_) => Ok((u32::from(unit), 1)),
    }
}
