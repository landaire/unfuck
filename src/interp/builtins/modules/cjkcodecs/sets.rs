//! The encoding direction of the 94x94 sets the stateful codecs designate,
//! keyed to 7-bit codes. Where several codes decode to a character, the
//! lowest wins.

use std::sync::LazyLock;

use crate::interp::builtins::modules::cjkcodecs::data::Code;
use crate::interp::builtins::modules::cjkcodecs::data::DecodeTable;
use crate::interp::builtins::modules::cjkcodecs::data::Inverse;
use crate::interp::builtins::modules::cjkcodecs::data::Lookup;
use crate::interp::builtins::modules::cjkcodecs::tables;

/// The first-match inverse of `layers` looked up in order, over every key
/// any of them maps.
fn inverse_of(layers: &[&DecodeTable]) -> Inverse {
    let mut keys: Vec<u16> = layers.iter().flat_map(|table| table.entries().into_iter().map(|(key, _)| key)).collect();
    keys.sort_unstable();
    keys.dedup();

    let mut inverse = Inverse::default();
    for key in keys {
        for table in layers {
            match table.lookup(key) {
                Lookup::Absent => continue,
                Lookup::Removed => break,
                Lookup::Mapped(mapped) => {
                    inverse.insert(mapped, Code::double(key));
                    break;
                }
            }
        }
    }

    inverse
}

pub static GB2312: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::GB2312]));
pub static KSX1001: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::KSX1001]));
pub static JISX0208: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::JISX0208]));
pub static JISX0212: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::JISX0212]));
// The ISO-2022 forms of JIS X 0213, with their deviations.
pub static JISX0213_1_2000: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::ISO2022_JP_3, &tables::JISX0208, &tables::JISX0213_1]));
pub static JISX0213_1_2004: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::ISO2022_JP_2004, &tables::JISX0208, &tables::JISX0213_1, &tables::JISX0213_2004]));
pub static JISX0213_2: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::JISX0213_2]));
pub static JISX0213_2_2000: LazyLock<Inverse> = LazyLock::new(|| inverse_of(&[&tables::JISX0213_2_2000, &tables::JISX0213_2]));
