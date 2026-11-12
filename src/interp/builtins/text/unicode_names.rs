//! Character names of CPython 2.7's `unicodedata`: lookup by name, which
//! resolves `\N{...}` escapes, and by code point.

use std::cmp::Ordering;

use crate::interp::builtins::text::unicode_name_table::BLOCKS;
use crate::interp::builtins::text::unicode_name_table::CODE_ORDER;
use crate::interp::builtins::text::unicode_name_table::CODE_DIGITS;
use crate::interp::builtins::text::unicode_name_table::DIGIT_BASE;
use crate::interp::builtins::text::unicode_name_table::NAMES;
use crate::interp::builtins::text::unicode_name_table::OFFSET_DIGITS;
use crate::interp::builtins::text::unicode_name_table::RADIX;

const SYLLABLE_BASE: u32 = 0xac00;
const LEADING: [&[u8]; 19] = [
    b"G", b"GG", b"N", b"D", b"DD", b"R", b"M", b"B", b"BB", b"S", b"SS", b"", b"J", b"JJ", b"C", b"K", b"T", b"P", b"H",
];
const VOWELS: [&[u8]; 21] = [
    b"A", b"AE", b"YA", b"YAE", b"EO", b"E", b"YEO", b"YE", b"O", b"WA", b"WAE", b"OE", b"YO", b"U", b"WEO", b"WE", b"WI",
    b"YU", b"EU", b"YI", b"I",
];
const TRAILING: [&[u8]; 28] = [
    b"", b"G", b"GG", b"GS", b"N", b"NJ", b"NH", b"D", b"L", b"LG", b"LM", b"LB", b"LS", b"LT", b"LP", b"LH", b"M", b"B",
    b"BS", b"S", b"SS", b"NG", b"J", b"C", b"K", b"T", b"P", b"H",
];

/// One entry of `NAMES`.
struct Entry<'a> {
    /// Length of the prefix shared with the previous name.
    shared: usize,
    /// The name after the shared prefix.
    suffix: &'a [u8],
    code: u32,
}

/// The code point `_getcode` finds for `name` with no database version
/// selected. Table names match without regard to ASCII case; the Hangul
/// syllable and unified ideograph forms match only in upper case.
pub fn lookup(name: &[u8]) -> Option<u32> {
    if let Some(syllable) = name.strip_prefix(b"HANGUL SYLLABLE ") {
        return hangul_syllable(syllable);
    }

    if let Some(digits) = name.strip_prefix(b"CJK UNIFIED IDEOGRAPH-") {
        return unified_ideograph(digits);
    }

    table_lookup(name)
}

/// Matches each jamo in turn. Each step takes the first longest spelling,
/// without backtracking.
fn hangul_syllable(name: &[u8]) -> Option<u32> {
    let (leading, rest) = longest_spelling(name, &LEADING)?;
    let (vowel, rest) = longest_spelling(rest, &VOWELS)?;
    let (trailing, rest) = longest_spelling(rest, &TRAILING)?;
    if !rest.is_empty() {
        return None;
    }

    let vowel_count = VOWELS.len() as u32;
    let trailing_count = TRAILING.len() as u32;

    Some(SYLLABLE_BASE + (leading * vowel_count + vowel) * trailing_count + trailing)
}

/// Index of the first longest spelling that starts `name`, and the rest of
/// `name`.
fn longest_spelling<'a>(name: &'a [u8], spellings: &[&[u8]]) -> Option<(u32, &'a [u8])> {
    let mut best: Option<(u32, &[u8])> = None;

    for (index, spelling) in (0u32..).zip(spellings) {
        let Some(rest) = name.strip_prefix(*spelling) else {
            continue;
        };
        if best.is_some_and(|(_, best_rest)| best_rest.len() <= rest.len()) {
            continue;
        }
        best = Some((index, rest));
    }

    best
}

/// Four or five upper case hex digits naming a Unicode 5.2 unified
/// ideograph.
fn unified_ideograph(digits: &[u8]) -> Option<u32> {
    if !matches!(digits.len(), 4 | 5) {
        return None;
    }

    let mut code = 0u32;
    for &digit in digits {
        let value = match digit {
            b'0'..=b'9' => digit - b'0',
            b'A'..=b'F' => digit - b'A' + 10,
            _ => return None,
        };
        code = code * 16 + u32::from(value);
    }

    is_unified_ideograph(code).then_some(code)
}

/// The name `_getucname` gives `code` with no database version selected.
pub fn name(code: u32) -> Option<String> {
    let syllable_count = (LEADING.len() * VOWELS.len() * TRAILING.len()) as u32;
    if let Some(syllable) = code.checked_sub(SYLLABLE_BASE).filter(|&index| index < syllable_count) {
        return Some(hangul_syllable_name(syllable));
    }

    if is_unified_ideograph(code) {
        return Some(format!("CJK UNIFIED IDEOGRAPH-{code:X}"));
    }

    table_name(code)
}

/// The name of the syllable at `index` from `SYLLABLE_BASE`.
fn hangul_syllable_name(index: u32) -> String {
    let per_leading = (VOWELS.len() * TRAILING.len()) as u32;
    let per_vowel = TRAILING.len() as u32;
    let spellings = [
        LEADING.get((index / per_leading) as usize),
        VOWELS.get((index % per_leading / per_vowel) as usize),
        TRAILING.get((index % per_vowel) as usize),
    ];

    let mut name = b"HANGUL SYLLABLE ".to_vec();
    for spelling in spellings.into_iter().flatten() {
        name.extend_from_slice(spelling);
    }

    String::from_utf8_lossy(&name).into_owned()
}

fn is_unified_ideograph(code: u32) -> bool {
    matches!(code, 0x3400..=0x4db5 | 0x4e00..=0x9fcb | 0x20000..=0x2a6d6 | 0x2a700..=0x2b734)
}

/// The name of `code` in `NAMES`, found by binary search of `CODE_ORDER`.
fn table_name(code: u32) -> Option<String> {
    let names = NAMES.as_bytes();
    let order = CODE_ORDER.as_bytes();

    let mut low = 0;
    let mut high = order.len() / OFFSET_DIGITS;
    while low < high {
        let middle = low + (high - low) / 2;
        let digits = order.get(middle * OFFSET_DIGITS..(middle + 1) * OFFSET_DIGITS)?;
        let offset = digits_value(digits) as usize;
        let (entry, _) = next_entry(names.get(offset..)?)?;
        match entry.code.cmp(&code) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return entry_name(names, offset),
        }
    }

    None
}

/// The full name of the entry at `target`. Entries of a block extend the
/// previous name, starting from its first.
fn entry_name(names: &[u8], target: usize) -> Option<String> {
    let block = BLOCKS.partition_point(|&offset| offset as usize <= target).checked_sub(1)?;
    let mut offset = *BLOCKS.get(block)? as usize;

    let mut name = Vec::new();
    loop {
        let (entry, rest) = next_entry(names.get(offset..)?)?;
        name.truncate(entry.shared);
        name.extend_from_slice(entry.suffix);
        if offset == target {
            return String::from_utf8(name).ok();
        }
        offset = names.len() - rest.len();
    }
}

fn table_lookup(name: &[u8]) -> Option<u32> {
    let names = NAMES.as_bytes();

    let preceding = BLOCKS.partition_point(|&offset| {
        block_first_name(names, offset).is_some_and(|first| compare_upper(first, name) != Ordering::Greater)
    });
    let block = preceding.checked_sub(1)?;
    let start = *BLOCKS.get(block)? as usize;
    let end = BLOCKS.get(block + 1).map_or(names.len(), |&offset| offset as usize);
    let mut entries = names.get(start..end)?;

    // Length of the prefix the current name shares with `name`.
    let mut matched = 0;
    while let Some((entry, rest)) = next_entry(entries) {
        entries = rest;

        // The name repeats the previous one past where that one left `name`.
        if entry.shared > matched {
            continue;
        }

        let remaining = name.get(entry.shared..)?;
        let extended = entry
            .suffix
            .iter()
            .zip(remaining)
            .take_while(|&(&stored, query)| stored == query.to_ascii_uppercase())
            .count();
        matched = entry.shared + extended;
        if matched == name.len() && entry.shared + entry.suffix.len() == name.len() {
            return Some(entry.code);
        }
    }

    None
}

fn block_first_name(names: &[u8], offset: u32) -> Option<&[u8]> {
    let (entry, _) = next_entry(names.get(offset as usize..)?)?;

    Some(entry.suffix)
}

/// Orders a table name against `query` as `_getcode` matches them, with
/// `query` in ASCII upper case.
fn compare_upper(stored: &[u8], query: &[u8]) -> Ordering {
    stored.iter().copied().cmp(query.iter().map(u8::to_ascii_uppercase))
}

/// Splits the entry at the start of `data` from the entries after it.
fn next_entry(data: &[u8]) -> Option<(Entry<'_>, &[u8])> {
    let (&shared, rest) = data.split_first()?;
    let suffix_len = rest.iter().position(|&byte| byte >= DIGIT_BASE)?;
    let (suffix, rest) = rest.split_at(suffix_len);
    let (code_digits, rest) = rest.split_at_checked(CODE_DIGITS)?;

    let code = digits_value(code_digits);
    let entry = Entry { shared: usize::from(shared - DIGIT_BASE), suffix, code };

    Some((entry, rest))
}

/// The number written in `digits`, most significant first.
fn digits_value(digits: &[u8]) -> u32 {
    digits.iter().fold(0, |value, &digit| value * RADIX + u32::from(digit - DIGIT_BASE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_names() {
        assert_eq!(lookup(b"LATIN SMALL LETTER A"), Some(0x61));
        assert_eq!(lookup(b"latin Small letter a"), Some(0x61));
        assert_eq!(lookup(b"LATIN SMALL LETTER AA"), Some(0xa733));
        assert_eq!(lookup(b"SPACE"), Some(0x20));
        assert_eq!(lookup(b"AC CURRENT"), Some(0x23e6));
        assert_eq!(lookup(b"ZERO WIDTH SPACE"), Some(0x200b));
        assert_eq!(lookup(b"MUSICAL SYMBOL G CLEF"), Some(0x1d11e));
        assert_eq!(lookup(b"TAG SPACE"), Some(0xe0020));
        assert_eq!(lookup(b"VARIATION SELECTOR-256"), Some(0xe01ef));
        assert_eq!(lookup(b"CJK COMPATIBILITY IDEOGRAPH-2FA1D"), Some(0x2fa1d));
    }

    #[test]
    fn unknown_names() {
        assert_eq!(lookup(b""), None);
        assert_eq!(lookup(b"BOGUS"), None);
        assert_eq!(lookup(b"LINE FEED"), None);
        assert_eq!(lookup(b"LATIN SMALL LETTER"), None);
        assert_eq!(lookup(b"LATIN SMALL LETTER AAA"), None);
        assert_eq!(lookup(b" SPACE"), None);
        assert_eq!(lookup(b"SPACE "), None);
        assert_eq!(lookup(b"\xffSPACE"), None);
    }

    #[test]
    fn hangul_syllables() {
        assert_eq!(lookup(b"HANGUL SYLLABLE GA"), Some(0xac00));
        assert_eq!(lookup(b"HANGUL SYLLABLE GAG"), Some(0xac01));
        assert_eq!(lookup(b"HANGUL SYLLABLE GGAEGG"), Some(0xae6a));
        assert_eq!(lookup(b"HANGUL SYLLABLE A"), Some(0xc544));
        assert_eq!(lookup(b"HANGUL SYLLABLE HIH"), Some(0xd7a3));
        assert_eq!(lookup(b"HANGUL SYLLABLE "), None);
        assert_eq!(lookup(b"HANGUL SYLLABLE GX"), None);
        assert_eq!(lookup(b"hangul syllable ga"), None);
        assert_eq!(lookup(b"HANGUL SYLLABLE ga"), None);
    }

    #[test]
    fn unified_ideographs() {
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-3400"), Some(0x3400));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-4DB5"), Some(0x4db5));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-4E00"), Some(0x4e00));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-9FCB"), Some(0x9fcb));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-20000"), Some(0x20000));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-2B734"), Some(0x2b734));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-4DB6"), None);
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-9FCC"), None);
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-2B735"), None);
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-4e00"), None);
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-04E00"), Some(0x4e00));
        assert_eq!(lookup(b"CJK UNIFIED IDEOGRAPH-004E00"), None);
        assert_eq!(lookup(b"cjk unified ideograph-4E00"), None);
    }

    #[test]
    fn every_table_name_resolves() {
        let mut data = NAMES.as_bytes();
        let mut name = Vec::new();
        let mut count = 0;
        while let Some((entry, rest)) = next_entry(data) {
            data = rest;
            name.truncate(entry.shared);
            name.extend_from_slice(entry.suffix);
            count += 1;

            assert_eq!(lookup(&name), Some(entry.code), "{}", String::from_utf8_lossy(&name));
            assert_eq!(lookup(&name.to_ascii_lowercase()), Some(entry.code));
            assert_eq!(super::name(entry.code).map(String::into_bytes), Some(name.clone()));
        }

        assert!(data.is_empty());
        assert_eq!(count, 21742);
    }

    #[test]
    fn derived_names() {
        assert_eq!(name(0xac00).as_deref(), Some("HANGUL SYLLABLE GA"));
        assert_eq!(name(0xae6a).as_deref(), Some("HANGUL SYLLABLE GGAEGG"));
        assert_eq!(name(0xc544).as_deref(), Some("HANGUL SYLLABLE A"));
        assert_eq!(name(0xd7a3).as_deref(), Some("HANGUL SYLLABLE HIH"));
        assert_eq!(name(0x4e00).as_deref(), Some("CJK UNIFIED IDEOGRAPH-4E00"));
        assert_eq!(name(0x2b734).as_deref(), Some("CJK UNIFIED IDEOGRAPH-2B734"));
        assert_eq!(name(0x9fcc), None);
        assert_eq!(name(0xd7a4), None);
        assert_eq!(name(0x0378), None);
        assert_eq!(name(0x110000), None);
    }
}
