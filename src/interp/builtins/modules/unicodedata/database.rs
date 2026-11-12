//! The character data `generate_database.py` records from the client's
//! `unicodedata`: properties of every code point under the current
//! database and under Unicode 3.2.0, decompositions, and the canonical
//! pairs that do not compose.

use std::collections::HashMap;
use std::sync::LazyLock;

const DATA: &[u8] = include_bytes!("database.bin");

static DATABASE: LazyLock<Result<Database, MalformedDatabase>> = LazyLock::new(Database::parse);

/// Which database a query reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Current,
    V320,
}

/// The embedded data does not have the expected layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the unicodedata database is malformed at byte {offset}")]
pub struct MalformedDatabase {
    offset: usize,
}

/// A normalization form, as a bit of the quick-check flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Nfc,
    Nfd,
    Nfkc,
    Nfkd,
}

impl Form {
    pub fn parse(name: &[u8]) -> Option<Self> {
        match name {
            b"NFC" => Some(Form::Nfc),
            b"NFD" => Some(Form::Nfd),
            b"NFKC" => Some(Form::Nfkc),
            b"NFKD" => Some(Form::Nfkd),
            _ => None,
        }
    }

    pub fn composes(self) -> bool {
        matches!(self, Form::Nfc | Form::Nfkc)
    }

    pub fn compatibility(self) -> bool {
        matches!(self, Form::Nfkc | Form::Nfkd)
    }

    fn flag(self) -> u8 {
        match self {
            Form::Nfc => 1 << 2,
            Form::Nfd => 1 << 3,
            Form::Nfkc => 1 << 4,
            Form::Nfkd => 1 << 5,
        }
    }
}

/// The properties of one code point.
#[derive(Clone, Copy, Debug)]
pub struct Properties {
    pub category: &'static str,
    pub bidirectional: &'static str,
    pub combining: u8,
    pub east_asian_width: &'static str,
    pub decimal: Option<u8>,
    pub digit: Option<u8>,
    pub numeric: Option<f64>,
    flags: u8,
}

impl Properties {
    pub fn mirrored(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn named(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Whether `form` leaves the character alone without computing.
    pub fn quick_check(&self, form: Form) -> bool {
        self.flags & form.flag() != 0
    }
}

/// A decomposition mapping: a compatibility tag, or none for a canonical
/// one, and the code points.
#[derive(Clone, Copy, Debug)]
pub struct Decomposition<'a> {
    pub tag: Option<&'static str>,
    pub codes: &'a [u32],
}

/// Record fields as stored, before string lookup.
#[derive(Clone, Copy)]
struct Record {
    category: u8,
    bidirectional: u8,
    combining: u8,
    width: u8,
    flags: u8,
    decimal: u8,
    digit: u8,
    numeric: u16,
}

/// Runs of code points sharing a record, by first code point.
struct Runs {
    starts: Vec<u32>,
    records: Vec<u16>,
}

impl Runs {
    fn record(&self, code: u32) -> Option<u16> {
        let index = self.starts.partition_point(|&start| start <= code).checked_sub(1)?;

        self.records.get(index).copied()
    }
}

/// A stored decomposition: a tag index, or none, and a range of `codes`.
#[derive(Clone, Copy)]
struct Stored {
    tag: Option<u8>,
    start: usize,
    length: usize,
}

pub struct Database {
    categories: Vec<&'static str>,
    bidirectionals: Vec<&'static str>,
    widths: Vec<&'static str>,
    tags: Vec<&'static str>,
    numerics: Vec<f64>,
    records: Vec<Record>,
    current: Runs,
    old: Runs,
    codes: Vec<u32>,
    decompositions: HashMap<u32, Stored>,
    /// Entries of the 3.2.0 database that differ; an empty mapping means
    /// none.
    old_decompositions: HashMap<u32, Stored>,
    compositions: [HashMap<(u32, u32), u32>; 2],
}

/// Reads the embedded data in order.
struct Reader {
    offset: usize,
}

impl Reader {
    fn bytes(&mut self, count: usize) -> Result<&'static [u8], MalformedDatabase> {
        let end = self.offset.checked_add(count).filter(|&end| end <= DATA.len()).ok_or(MalformedDatabase { offset: self.offset })?;
        let bytes = &DATA[self.offset..end];
        self.offset = end;

        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MalformedDatabase> {
        let offset = self.offset;
        self.bytes(N)?.try_into().map_err(|_| MalformedDatabase { offset })
    }

    fn u8(&mut self) -> Result<u8, MalformedDatabase> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, MalformedDatabase> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, MalformedDatabase> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, MalformedDatabase> {
        usize::try_from(self.u32()?).map_err(|_| MalformedDatabase { offset: self.offset })
    }

    fn strings(&mut self) -> Result<Vec<&'static str>, MalformedDatabase> {
        let count = self.u8()?;
        (0..count)
            .map(|_| {
                let length = usize::from(self.u8()?);
                let offset = self.offset;
                std::str::from_utf8(self.bytes(length)?).map_err(|_| MalformedDatabase { offset })
            })
            .collect()
    }

    fn runs(&mut self) -> Result<Runs, MalformedDatabase> {
        let count = self.count()?;
        let mut runs = Runs { starts: Vec::with_capacity(count), records: Vec::with_capacity(count) };
        for _ in 0..count {
            runs.starts.push(self.u32()?);
            runs.records.push(self.u16()?);
        }

        Ok(runs)
    }

    fn decompositions(&mut self, codes: &mut Vec<u32>) -> Result<HashMap<u32, Stored>, MalformedDatabase> {
        let count = self.count()?;
        let mut entries = HashMap::with_capacity(count);
        for _ in 0..count {
            let code = self.u32()?;
            let tag = Some(self.u8()?).filter(|&tag| tag != 0xff);
            let length = usize::from(self.u8()?);
            let start = codes.len();
            for _ in 0..length {
                codes.push(self.u32()?);
            }
            entries.insert(code, Stored { tag, start, length });
        }

        Ok(entries)
    }

    fn exclusions(&mut self) -> Result<Vec<u32>, MalformedDatabase> {
        let count = self.count()?;
        (0..count).map(|_| self.u32()).collect()
    }
}

impl Database {
    /// The parsed embedded database.
    pub fn get() -> Result<&'static Database, MalformedDatabase> {
        DATABASE.as_ref().map_err(|error| *error)
    }

    fn parse() -> Result<Self, MalformedDatabase> {
        let mut reader = Reader { offset: 0 };
        if reader.bytes(4)? != b"UCDB" {
            return Err(MalformedDatabase { offset: 0 });
        }

        let categories = reader.strings()?;
        let bidirectionals = reader.strings()?;
        let widths = reader.strings()?;
        let tags = reader.strings()?;

        let numeric_count = reader.u16()?;
        let numerics = (0..numeric_count).map(|_| Ok(f64::from_le_bytes(reader.array()?))).collect::<Result<Vec<f64>, MalformedDatabase>>()?;

        let record_count = reader.u16()?;
        let mut records = Vec::with_capacity(usize::from(record_count));
        for _ in 0..record_count {
            let [category, bidirectional, combining, width, flags, decimal, digit] = reader.array()?;
            let numeric = reader.u16()?;
            records.push(Record { category, bidirectional, combining, width, flags, decimal, digit, numeric });
        }

        let current = reader.runs()?;
        let old = reader.runs()?;
        let mut codes = Vec::new();
        let decompositions = reader.decompositions(&mut codes)?;
        let old_decompositions = reader.decompositions(&mut codes)?;
        let current_exclusions = reader.exclusions()?;
        let old_exclusions = reader.exclusions()?;
        if reader.offset != DATA.len() {
            return Err(MalformedDatabase { offset: reader.offset });
        }

        let mut database = Self { categories, bidirectionals, widths, tags, numerics, records, current, old, codes, decompositions, old_decompositions, compositions: [HashMap::new(), HashMap::new()] };
        database.compositions = [database.composition_pairs(Version::Current, &current_exclusions), database.composition_pairs(Version::V320, &old_exclusions)];

        Ok(database)
    }

    /// The canonical pairs that compose, keyed by their two code points.
    fn composition_pairs(&self, version: Version, exclusions: &[u32]) -> HashMap<(u32, u32), u32> {
        let mut pairs = HashMap::new();
        for &code in self.decompositions.keys() {
            if exclusions.contains(&code) {
                continue;
            }
            let Some(Decomposition { tag: None, codes: &[first, second] }) = self.decomposition(version, code) else {
                continue;
            };
            pairs.insert((first, second), code);
        }

        pairs
    }

    /// The properties of `code`; a code point past the last plane reads
    /// as the last run.
    pub fn properties(&self, version: Version, code: u32) -> Option<Properties> {
        let runs = match version {
            Version::Current => &self.current,
            Version::V320 => &self.old,
        };
        let record = self.records.get(usize::from(runs.record(code)?))?;
        let numeric = match record.numeric {
            0xffff => None,
            index => Some(*self.numerics.get(usize::from(index))?),
        };

        Some(Properties {
            category: self.categories.get(usize::from(record.category))?,
            bidirectional: self.bidirectionals.get(usize::from(record.bidirectional))?,
            combining: record.combining,
            east_asian_width: self.widths.get(usize::from(record.width))?,
            decimal: Some(record.decimal).filter(|&value| value != 0xff),
            digit: Some(record.digit).filter(|&value| value != 0xff),
            numeric,
            flags: record.flags,
        })
    }

    pub fn decomposition(&self, version: Version, code: u32) -> Option<Decomposition<'_>> {
        let stored = match version {
            Version::V320 => match self.old_decompositions.get(&code) {
                Some(stored) => stored,
                None => self.decompositions.get(&code)?,
            },
            Version::Current => self.decompositions.get(&code)?,
        };
        if stored.length == 0 {
            return None;
        }
        let tag = match stored.tag {
            Some(index) => Some(*self.tags.get(usize::from(index))?),
            None => None,
        };

        Some(Decomposition { tag, codes: self.codes.get(stored.start..stored.start + stored.length)? })
    }

    /// The primary composite of a canonical pair.
    pub fn compose(&self, version: Version, first: u32, second: u32) -> Option<u32> {
        let index = match version {
            Version::Current => 0,
            Version::V320 => 1,
        };

        self.compositions[index].get(&(first, second)).copied()
    }
}
