//! Character classes and case folding as the matcher applies them. Code
//! points are compared as 32-bit values; Unicode properties come from the
//! interpreter's database, which knows UTF-16 code units only.

use crate::interp::builtins::modules::sre::opcode::Category;
use crate::interp::builtins::modules::sre::opcode::FLAG_LOCALE;
use crate::interp::builtins::modules::sre::opcode::FLAG_UNICODE;
use crate::interp::builtins::text::chars::CodeUnit;

/// The lowercasing a pattern applies under `IGNORECASE`, chosen by its
/// flags. The locale form assumes the C locale; callers check that the
/// host locale is C before matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fold {
    Ascii,
    Locale,
    Unicode,
}

impl Fold {
    pub fn from_flags(flags: i64) -> Self {
        if flags & FLAG_LOCALE != 0 {
            Fold::Locale
        } else if flags & FLAG_UNICODE != 0 {
            Fold::Unicode
        } else {
            Fold::Ascii
        }
    }

    pub fn lower(self, character: u32) -> u32 {
        match self {
            // The C locale lowercases the ASCII letters only.
            Fold::Ascii | Fold::Locale => match u8::try_from(character) {
                Ok(byte) => u32::from(byte.to_ascii_lowercase()),
                Err(_) => character,
            },
            // The narrow build looks up the low 16 bits.
            Fold::Unicode => u32::from((character as u16).to_lower()),
        }
    }
}

/// An ASCII character test that rejects everything at or above 128.
fn ascii(character: u32, test: impl Fn(u8) -> bool) -> bool {
    u8::try_from(character).is_ok_and(|byte| byte < 128 && test(byte))
}

fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

pub fn is_word(character: u32) -> bool {
    ascii(character, |byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// A word character of the C locale.
pub fn is_locale_word(character: u32) -> bool {
    is_word(character)
}

pub fn is_unicode_word(character: u32) -> bool {
    let unit = character as u16;

    unit.is_alnum() || character == u32::from(b'_')
}

pub fn category(category: Category, character: u32) -> bool {
    let unit = character as u16;
    match category {
        Category::Digit => ascii(character, |byte| byte.is_ascii_digit()),
        Category::NotDigit => !ascii(character, |byte| byte.is_ascii_digit()),
        Category::Space => ascii(character, is_ascii_space),
        Category::NotSpace => !ascii(character, is_ascii_space),
        Category::Word => is_word(character),
        Category::NotWord => !is_word(character),
        Category::Linebreak => character == u32::from(b'\n'),
        Category::NotLinebreak => character != u32::from(b'\n'),
        Category::LocaleWord => is_locale_word(character),
        Category::LocaleNotWord => !is_locale_word(character),
        Category::UnicodeDigit => unit.is_decimal(),
        Category::UnicodeNotDigit => !unit.is_decimal(),
        Category::UnicodeSpace => unit.is_space(),
        Category::UnicodeNotSpace => !unit.is_space(),
        Category::UnicodeWord => is_unicode_word(character),
        Category::UnicodeNotWord => !is_unicode_word(character),
        Category::UnicodeLinebreak => unit.is_linebreak(),
        Category::UnicodeNotLinebreak => !unit.is_linebreak(),
    }
}
