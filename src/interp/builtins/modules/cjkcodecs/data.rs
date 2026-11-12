//! Readers for the mapping tables `generate_data.py` writes. The layouts
//! are described there; every read is bounds-checked, so a malformed
//! table reads as unmapped instead of failing.

use std::collections::HashMap;
use std::collections::HashSet;

/// What a code decodes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapped {
    /// One code point, which may lie beyond the BMP.
    Char(u32),
    /// A base character and a combining character.
    Pair(u16, u16),
}

/// The result of looking a key up in one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The table says nothing about the key.
    Absent,
    /// The table hides the key from the tables after it.
    Removed,
    Mapped(Mapped),
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;

    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let quad = bytes.get(offset..offset + 4)?;

    Some(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// The sections of a decoding table, located from its header.
struct Sections {
    runs: usize,
    run_count: usize,
    values: usize,
    astral: usize,
    astral_count: usize,
    pairs: usize,
    pair_count: usize,
    removed: usize,
    removed_count: usize,
}

const RUN_SIZE: usize = 8;
const ASTRAL_SIZE: usize = 6;
const PAIR_SIZE: usize = 6;

/// A table from 16-bit codes to what they decode to (magic "CJKD").
pub struct DecodeTable {
    bytes: &'static [u8],
}

impl DecodeTable {
    pub const fn new(bytes: &'static [u8]) -> Self {
        Self { bytes }
    }

    fn sections(&self) -> Option<Sections> {
        if self.bytes.get(..4) != Some(b"CJKD".as_slice()) {
            return None;
        }

        let run_count = usize::from(read_u16(self.bytes, 4)?);
        let astral_count = usize::from(read_u16(self.bytes, 6)?);
        let pair_count = usize::from(read_u16(self.bytes, 8)?);
        let removed_count = usize::from(read_u16(self.bytes, 10)?);

        let runs = 12;
        let values = runs + run_count * RUN_SIZE;
        let value_count = match run_count.checked_sub(1) {
            Some(last) => {
                let offset = runs + last * RUN_SIZE;
                read_u32(self.bytes, offset + 4)? as usize + usize::from(read_u16(self.bytes, offset + 2)?)
            }
            None => 0,
        };
        let astral = values + value_count * 2;
        let pairs = astral + astral_count * ASTRAL_SIZE;
        let removed = pairs + pair_count * PAIR_SIZE;

        Some(Sections { runs, run_count, values, astral, astral_count, pairs, pair_count, removed, removed_count })
    }

    pub fn lookup(&self, key: u16) -> Lookup {
        let Some(sections) = self.sections() else {
            return Lookup::Absent;
        };

        if let Some(value) = self.run_value(&sections, key) {
            return Lookup::Mapped(Mapped::Char(u32::from(value)));
        }
        if let Some(index) = search(sections.astral_count, |index| read_u16(self.bytes, sections.astral + index * ASTRAL_SIZE), key) {
            let offset = sections.astral + index * ASTRAL_SIZE;
            return read_u32(self.bytes, offset + 2).map_or(Lookup::Absent, |code_point| Lookup::Mapped(Mapped::Char(code_point)));
        }
        if let Some(index) = search(sections.pair_count, |index| read_u16(self.bytes, sections.pairs + index * PAIR_SIZE), key) {
            let offset = sections.pairs + index * PAIR_SIZE;
            let (Some(first), Some(second)) = (read_u16(self.bytes, offset + 2), read_u16(self.bytes, offset + 4)) else {
                return Lookup::Absent;
            };
            return Lookup::Mapped(Mapped::Pair(first, second));
        }
        if search(sections.removed_count, |index| read_u16(self.bytes, sections.removed + index * 2), key).is_some() {
            return Lookup::Removed;
        }

        Lookup::Absent
    }

    fn run_value(&self, sections: &Sections, key: u16) -> Option<u16> {
        // The last run starting at or before `key`.
        let mut low = 0;
        let mut high = sections.run_count;
        while low < high {
            let middle = (low + high) / 2;
            if read_u16(self.bytes, sections.runs + middle * RUN_SIZE)? <= key {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let index = low.checked_sub(1)?;

        let offset = sections.runs + index * RUN_SIZE;
        let first = read_u16(self.bytes, offset)?;
        let length = read_u16(self.bytes, offset + 2)?;
        let start = read_u32(self.bytes, offset + 4)? as usize;
        let position = key - first;
        if position >= length {
            return None;
        }

        read_u16(self.bytes, sections.values + (start + usize::from(position)) * 2)
    }

    /// Every mapped key in ascending order, removals excluded.
    pub fn entries(&self) -> Vec<(u16, Mapped)> {
        let Some(sections) = self.sections() else {
            return Vec::new();
        };
        let mut entries = Vec::new();

        for index in 0..sections.run_count {
            let offset = sections.runs + index * RUN_SIZE;
            let (Some(first), Some(length), Some(start)) = (read_u16(self.bytes, offset), read_u16(self.bytes, offset + 2), read_u32(self.bytes, offset + 4)) else {
                continue;
            };
            for position in 0..length {
                if let Some(value) = read_u16(self.bytes, sections.values + (start as usize + usize::from(position)) * 2) {
                    entries.push((first.wrapping_add(position), Mapped::Char(u32::from(value))));
                }
            }
        }

        for index in 0..sections.astral_count {
            let offset = sections.astral + index * ASTRAL_SIZE;
            if let (Some(key), Some(code_point)) = (read_u16(self.bytes, offset), read_u32(self.bytes, offset + 2)) {
                entries.push((key, Mapped::Char(code_point)));
            }
        }

        for index in 0..sections.pair_count {
            let offset = sections.pairs + index * PAIR_SIZE;
            if let (Some(key), Some(first), Some(second)) = (read_u16(self.bytes, offset), read_u16(self.bytes, offset + 2), read_u16(self.bytes, offset + 4)) {
                entries.push((key, Mapped::Pair(first, second)));
            }
        }

        entries.sort_by_key(|(key, _)| *key);

        entries
    }
}

/// The index of `key` among `count` sorted keys that `key_at` reads.
fn search(count: usize, key_at: impl Fn(usize) -> Option<u16>, key: u16) -> Option<usize> {
    let mut low = 0;
    let mut high = count;
    while low < high {
        let middle = (low + high) / 2;
        let found = key_at(middle)?;
        if found == key {
            return Some(middle);
        }
        if found < key {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    None
}

/// Looks `key` up in `tables` in order; the first table that knows the key
/// decides.
pub fn layered(tables: &[&DecodeTable], key: u16) -> Option<Mapped> {
    for table in tables {
        match table.lookup(key) {
            Lookup::Absent => continue,
            Lookup::Removed => return None,
            Lookup::Mapped(mapped) => return Some(mapped),
        }
    }

    None
}

/// An encoded form of at most four bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    bytes: [u8; 4],
    length: u8,
}

impl Code {
    pub fn new(data: &[u8]) -> Option<Self> {
        let length = u8::try_from(data.len()).ok().filter(|length| (1..=4).contains(length))?;
        let mut bytes = [0; 4];
        bytes[..data.len()].copy_from_slice(data);

        Some(Self { bytes, length })
    }

    pub fn single(byte: u8) -> Self {
        Self { bytes: [byte, 0, 0, 0], length: 1 }
    }

    pub fn double(code: u16) -> Self {
        let [high, low] = code.to_be_bytes();

        Self { bytes: [high, low, 0, 0], length: 2 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// What an encoding override says about a code point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Override {
    Encode(Code),
    Unencodable,
}

const OVERRIDE_SIZE: usize = 9;

/// Code points a codec encodes other than its default rule does (magic
/// "CJKE").
pub struct EncodeOverrides {
    bytes: &'static [u8],
}

impl EncodeOverrides {
    pub const fn new(bytes: &'static [u8]) -> Self {
        Self { bytes }
    }

    pub fn lookup(&self, code_point: u32) -> Option<Override> {
        if self.bytes.get(..4) != Some(b"CJKE".as_slice()) {
            return None;
        }
        let count = read_u32(self.bytes, 4)? as usize;

        let mut low = 0;
        let mut high = count;
        while low < high {
            let middle = (low + high) / 2;
            let offset = 8 + middle * OVERRIDE_SIZE;
            let found = read_u32(self.bytes, offset)?;
            if found == code_point {
                let length = usize::from(*self.bytes.get(offset + 4)?);
                if length == 0 {
                    return Some(Override::Unencodable);
                }
                return Code::new(self.bytes.get(offset + 5..offset + 5 + length)?).map(Override::Encode);
            }
            if found < code_point {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        None
    }
}

/// A run of four-byte gb18030 indexes mapping to consecutive code points.
#[derive(Clone, Copy, Debug)]
pub struct IndexRun {
    pub first_index: u32,
    pub length: u32,
    pub first_code_point: u32,
}

/// Runs of linear mappings (magic "CJKR"), ascending in both index and
/// code point.
pub struct RangeTable {
    bytes: &'static [u8],
}

impl RangeTable {
    pub const fn new(bytes: &'static [u8]) -> Self {
        Self { bytes }
    }

    fn count(&self) -> usize {
        if self.bytes.get(..4) != Some(b"CJKR".as_slice()) {
            return 0;
        }

        read_u16(self.bytes, 4).map_or(0, usize::from)
    }

    fn run(&self, index: usize) -> Option<IndexRun> {
        let offset = 6 + index * 6;

        Some(IndexRun { first_index: u32::from(read_u16(self.bytes, offset)?), length: u32::from(read_u16(self.bytes, offset + 2)?), first_code_point: u32::from(read_u16(self.bytes, offset + 4)?) })
    }

    /// The last run whose `start` is at most `target`.
    fn run_at(&self, target: u32, start: fn(&IndexRun) -> u32) -> Option<IndexRun> {
        let mut low = 0;
        let mut high = self.count();
        while low < high {
            let middle = (low + high) / 2;
            if start(&self.run(middle)?) <= target {
                low = middle + 1;
            } else {
                high = middle;
            }
        }

        self.run(low.checked_sub(1)?)
    }

    pub fn code_point(&self, index: u32) -> Option<u32> {
        let run = self.run_at(index, |run| run.first_index)?;

        (index - run.first_index < run.length).then(|| run.first_code_point + (index - run.first_index))
    }

    pub fn index(&self, code_point: u32) -> Option<u32> {
        let run = self.run_at(code_point, |run| run.first_code_point)?;

        (code_point - run.first_code_point < run.length).then(|| run.first_index + (code_point - run.first_code_point))
    }
}

/// The encoding direction of a codec or character set: code point to
/// code, and base plus combining character to code.
#[derive(Default)]
pub struct Inverse {
    singles: HashMap<u32, Code>,
    pairs: HashMap<(u16, u16), Code>,
    pair_starts: HashSet<u16>,
}

impl Inverse {
    /// Records `code` for `mapped` unless an earlier code claimed it.
    pub fn insert(&mut self, mapped: Mapped, code: Code) {
        match mapped {
            Mapped::Char(code_point) => {
                self.singles.entry(code_point).or_insert(code);
            }
            Mapped::Pair(first, second) => {
                self.pairs.entry((first, second)).or_insert(code);
                self.pair_starts.insert(first);
            }
        }
    }

    pub fn single(&self, code_point: u32) -> Option<Code> {
        self.singles.get(&code_point).copied()
    }

    pub fn pair(&self, first: u16, second: u16) -> Option<Code> {
        self.pairs.get(&(first, second)).copied()
    }

    /// Whether some pair starts with `first`.
    pub fn starts_pair(&self, first: u32) -> bool {
        u16::try_from(first).is_ok_and(|first| self.pair_starts.contains(&first))
    }
}
