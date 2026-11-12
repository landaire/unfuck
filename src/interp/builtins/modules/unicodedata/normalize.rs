//! Normalization (UAX #15) over UTF-16 code units, as the narrow build
//! performs it: surrogates neither decompose nor compose, and a mapping
//! to a code point outside the BMP keeps only its low 16 bits.
//!
//! Combining classes always come from the current database, also when
//! the 3.2.0 database normalizes. Hangul composition admits one vowel
//! past the vowel range and a trailing jamo from the trailing base up to
//! one past the trailing range, as the client does.

use crate::interp::builtins::modules::unicodedata::database::Database;
use crate::interp::builtins::modules::unicodedata::database::Form;
use crate::interp::builtins::modules::unicodedata::database::Version;

const SYLLABLE_BASE: u32 = 0xac00;
const LEADING_BASE: u32 = 0x1100;
const VOWEL_BASE: u32 = 0x1161;
const TRAILING_BASE: u32 = 0x11a7;
const LEADING_COUNT: u32 = 19;
const VOWEL_COUNT: u32 = 21;
const TRAILING_COUNT: u32 = 28;
const SYLLABLE_COUNT: u32 = LEADING_COUNT * VOWEL_COUNT * TRAILING_COUNT;

/// Whether `units` is certainly in `form` already: every unit passes the
/// quick check and combining classes do not descend.
pub fn is_normalized(database: &Database, form: Form, units: &[u16]) -> bool {
    let mut previous = 0;
    for &unit in units {
        let Some(properties) = database.properties(Version::Current, u32::from(unit)) else {
            return false;
        };
        if !properties.quick_check(form) {
            return false;
        }
        let class = properties.combining;
        if class != 0 && previous > class {
            return false;
        }
        previous = class;
    }

    true
}

pub fn normalize(database: &Database, version: Version, form: Form, units: &[u16]) -> Vec<u16> {
    let decomposed = decompose(database, version, form.compatibility(), units);
    if !form.composes() {
        return decomposed;
    }

    compose(database, version, &decomposed)
}

fn combining_class(database: &Database, unit: u16) -> u8 {
    database.properties(Version::Current, u32::from(unit)).map_or(0, |properties| properties.combining)
}

/// Full decomposition followed by canonical ordering.
fn decompose(database: &Database, version: Version, compatibility: bool, units: &[u16]) -> Vec<u16> {
    let mut output = Vec::with_capacity(units.len());
    let mut pending = Vec::new();
    for &unit in units {
        pending.push(unit);
        while let Some(unit) = pending.pop() {
            let code = u32::from(unit);
            if let Some(index) = code.checked_sub(SYLLABLE_BASE).filter(|&index| index < SYLLABLE_COUNT) {
                let leading = LEADING_BASE + index / (VOWEL_COUNT * TRAILING_COUNT);
                let vowel = VOWEL_BASE + index % (VOWEL_COUNT * TRAILING_COUNT) / TRAILING_COUNT;
                let trailing = TRAILING_BASE + index % TRAILING_COUNT;
                output.push(leading as u16);
                output.push(vowel as u16);
                if trailing != TRAILING_BASE {
                    output.push(trailing as u16);
                }
                continue;
            }

            match database.decomposition(version, code) {
                Some(mapping) if compatibility || mapping.tag.is_none() => {
                    // Pushed in reverse so the first unit decomposes first.
                    pending.extend(mapping.codes.iter().rev().map(|&code| code as u16));
                }
                _ => output.push(unit),
            }
        }
    }

    order_canonically(database, &mut output);

    output
}

/// Sorts each run of combining characters by class, keeping the order of
/// equal classes.
fn order_canonically(database: &Database, units: &mut [u16]) {
    for index in 1..units.len() {
        let class = combining_class(database, units[index]);
        if class == 0 {
            continue;
        }
        let mut position = index;
        while position > 0 && combining_class(database, units[position - 1]) > class {
            units.swap(position - 1, position);
            position -= 1;
        }
    }
}

/// The syllable a leading and a vowel jamo compose to.
fn hangul_syllable(leading: u16, vowel: u16) -> Option<u16> {
    let leading = u32::from(leading).checked_sub(LEADING_BASE).filter(|&index| index < LEADING_COUNT)?;
    let vowel = u32::from(vowel).checked_sub(VOWEL_BASE).filter(|&index| index <= VOWEL_COUNT)?;

    u16::try_from(SYLLABLE_BASE + (leading * VOWEL_COUNT + vowel) * TRAILING_COUNT).ok()
}

/// The offset a trailing jamo adds to the syllable before it.
fn trailing_offset(trailing: u16) -> Option<u16> {
    let offset = u32::from(trailing).checked_sub(TRAILING_BASE).filter(|&index| index <= TRAILING_COUNT)?;

    u16::try_from(offset).ok()
}

/// Canonical composition of decomposed, ordered units.
fn compose(database: &Database, version: Version, units: &[u16]) -> Vec<u16> {
    let mut output: Vec<u16> = Vec::with_capacity(units.len());
    // The last starter and the class of the last character kept after it.
    let mut starter: Option<usize> = None;
    let mut last_class: Option<u8> = None;
    // A syllable just composed from two jamo, which a trailing jamo right
    // after it completes.
    let mut syllable: Option<usize> = None;

    for &unit in units {
        if let Some(index) = syllable.take()
            && let Some(offset) = trailing_offset(unit)
            && let Some(composed) = output[index].checked_add(offset)
        {
            output[index] = composed;
            continue;
        }

        let class = combining_class(database, unit);
        if let Some(index) = starter {
            if last_class.is_none() && let Some(composed) = hangul_syllable(output[index], unit) {
                output[index] = composed;
                syllable = Some(index);
                continue;
            }
            let blocked = last_class.is_some_and(|previous| previous == 0 || previous >= class);
            let composed = database.compose(version, u32::from(output[index]), u32::from(unit)).and_then(|code| u16::try_from(code).ok());
            if !blocked && let Some(composed) = composed {
                output[index] = composed;
                continue;
            }
        }

        if class == 0 {
            starter = Some(output.len());
            last_class = None;
        } else {
            last_class = Some(class);
        }
        output.push(unit);
    }

    output
}
