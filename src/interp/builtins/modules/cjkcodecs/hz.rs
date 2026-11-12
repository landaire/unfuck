//! HZ (RFC 1843): ASCII text with GB2312 runs between `~{` and `~}`.
//! The client's build leaves `~` unescaped when encoding.

use crate::interp::builtins::modules::cjkcodecs::codec::Fault;
use crate::interp::builtins::modules::cjkcodecs::codec::push_mapped;
use crate::interp::builtins::modules::cjkcodecs::data::layered;
use crate::interp::builtins::modules::cjkcodecs::sets;
use crate::interp::builtins::modules::cjkcodecs::tables;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Ascii,
    Gb2312,
}

pub fn encode(mode: &mut Mode, input: &[u16], position: &mut usize, output: &mut Vec<u8>) -> Result<(), Fault> {
    while let Some(&unit) = input.get(*position) {
        if let Some(byte) = u8::try_from(unit).ok().filter(|byte| *byte < 0x80) {
            if *mode == Mode::Gb2312 {
                output.extend_from_slice(b"~}");
                *mode = Mode::Ascii;
            }
            output.push(byte);
            *position += 1;
            continue;
        }

        let Some(code) = sets::GB2312.single(u32::from(unit)) else {
            return Err(Fault::Illegal(1));
        };
        if *mode == Mode::Ascii {
            output.extend_from_slice(b"~{");
            *mode = Mode::Gb2312;
        }
        output.extend_from_slice(code.as_bytes());
        *position += 1;
    }

    Ok(())
}

pub fn reset(mode: &mut Mode, output: &mut Vec<u8>) {
    if *mode == Mode::Gb2312 {
        output.extend_from_slice(b"~}");
    }
    *mode = Mode::Ascii;
}

pub fn decode(mode: &mut Mode, input: &[u8], position: &mut usize, output: &mut Vec<u16>) -> Result<(), Fault> {
    while let Some(&byte) = input.get(*position) {
        if byte >= 0x80 {
            return Err(Fault::Illegal(1));
        }

        if byte == b'~' {
            let Some(&next) = input.get(*position + 1) else {
                return Err(Fault::Incomplete);
            };
            match (next, *mode) {
                (b'~', _) => output.push(u16::from(b'~')),
                (b'\n', _) => {}
                (b'{', Mode::Ascii) => *mode = Mode::Gb2312,
                (b'}', Mode::Gb2312) => *mode = Mode::Ascii,
                _ => return Err(Fault::Illegal(2)),
            }
            *position += 2;
            continue;
        }

        if *mode == Mode::Ascii {
            output.push(u16::from(byte));
            *position += 1;
            continue;
        }

        let Some(&trail) = input.get(*position + 1) else {
            return Err(Fault::Incomplete);
        };
        let Some(mapped) = layered(&[&tables::GB2312], u16::from_be_bytes([byte, trail])) else {
            return Err(Fault::Illegal(2));
        };
        push_mapped(output, mapped);
        *position += 2;
    }

    Ok(())
}
