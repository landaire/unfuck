//! A checked code list with the operation at each position decoded once.
//! Every position is decoded, since a `JUMP` may land anywhere its skip
//! allows, not only on the start of an operation.

use crate::interp::builtins::modules::sre::opcode::Anchor;
use crate::interp::builtins::modules::sre::opcode::Category;
use crate::interp::builtins::modules::sre::opcode::INFO_CHARSET;
use crate::interp::builtins::modules::sre::opcode::INFO_LITERAL;
use crate::interp::builtins::modules::sre::opcode::INFO_PREFIX;
use crate::interp::builtins::modules::sre::opcode::Opcode;
use crate::interp::builtins::modules::sre::validate::InvalidCode;
use crate::interp::builtins::modules::sre::validate::validate;

/// How a literal operation compares the subject character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteralTest {
    Equal,
    NotEqual,
    /// Both sides lowercased.
    EqualFolded,
    NotEqualFolded,
}

/// One decoded operation. Positions are indices into the code list and
/// may lie outside it when the code says so.
#[derive(Clone, Copy, Debug)]
pub enum Inst {
    Failure,
    Success,
    Any,
    AnyAll,
    At(Anchor),
    Literal { character: u32, test: LiteralTest },
    /// A set test; `set` is the position of the first set item.
    In { set: usize, folded: bool, next: usize },
    /// An optimization block met after the start, which matching skips.
    Info { next: usize },
    Mark(usize),
    Jump(usize),
    /// `first` is the skip word of the first alternative.
    Branch { first: usize },
    RepeatOne { minimum: u32, maximum: u32, item: usize, tail: usize, lazy: bool },
    Repeat { minimum: u32, maximum: u32, body: usize, until: usize },
    Until { lazy: bool },
    GroupRef { group: usize, folded: bool },
    GroupRefExists { group: usize, otherwise: usize },
    Assert { negated: bool, behind: usize, body: usize, next: usize },
    /// An unknown operation or one whose operands run off the code.
    Illegal,
}

impl Inst {
    /// The position after an operation that continues in sequence.
    pub fn width(&self) -> usize {
        match self {
            Inst::Literal { .. } | Inst::At(_) | Inst::Mark(_) | Inst::GroupRef { .. } => 2,
            Inst::GroupRefExists { .. } => 3,
            _ => 1,
        }
    }
}

/// What the INFO block at the start of the code tells a search.
#[derive(Clone, Debug, Default)]
pub struct SearchHints {
    /// The shortest subject remainder a match needs.
    pub minimum: usize,
    /// The whole pattern is its literal prefix.
    pub literal: bool,
    /// The positions of the prefix characters in the code.
    pub prefix: Option<Prefix>,
    /// The position of the set items of the first-character set.
    pub first_set: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub struct Prefix {
    pub start: usize,
    pub length: usize,
    /// How many leading literal operations the prefix lets a search skip.
    pub skip: usize,
}

/// A code list that passed the structural check.
pub struct Program {
    code: Box<[u32]>,
    insts: Box<[Inst]>,
    /// The position matching starts at, after any leading INFO block.
    entry: usize,
    hints: SearchHints,
    mark_slots: usize,
}

impl Program {
    /// Checks and decodes `code` for a pattern declaring `groups` groups.
    pub fn parse(code: Vec<u32>, groups: i64) -> Result<Self, InvalidCode> {
        let highest_mark = validate(&code, groups)?;
        let insts = (0..code.len()).map(|position| decode(&code, position)).collect();
        let (entry, hints) = match code.first().copied().and_then(Opcode::from_word) {
            Some(Opcode::Info) => info_hints(&code),
            _ => (0, SearchHints::default()),
        };

        Ok(Self { code: code.into_boxed_slice(), insts, entry, hints, mark_slots: highest_mark.map_or(0, |mark| mark + 1) })
    }

    pub fn inst(&self, position: usize) -> Inst {
        self.insts.get(position).copied().unwrap_or(Inst::Illegal)
    }

    pub fn word(&self, position: usize) -> Option<u32> {
        self.code.get(position).copied()
    }

    pub fn entry(&self) -> usize {
        self.entry
    }

    pub fn hints(&self) -> &SearchHints {
        &self.hints
    }

    pub fn mark_slots(&self) -> usize {
        self.mark_slots
    }

    /// Whether `character` belongs to the set whose items start at
    /// `position`. `None` when the items run off the code or hold an
    /// unknown item.
    pub fn set_contains(&self, mut position: usize, character: u32, classify: impl Fn(Category, u32) -> bool) -> Option<bool> {
        // A NEGATE item flips what a later hit, and the end of the set,
        // report.
        let mut hit = true;
        loop {
            let item = Opcode::from_word(self.word(position)?)?;
            position += 1;
            match item {
                Opcode::Failure => return Some(!hit),
                Opcode::Negate => hit = !hit,
                Opcode::Literal => {
                    if self.word(position)? == character {
                        return Some(hit);
                    }
                    position += 1;
                }
                Opcode::Category => {
                    if classify(Category::from_word(self.word(position)?)?, character) {
                        return Some(hit);
                    }
                    position += 1;
                }
                Opcode::Range => {
                    if self.word(position)? <= character && character <= self.word(position + 1)? {
                        return Some(hit);
                    }
                    position += 2;
                }
                Opcode::Charset => {
                    if character < 256 && bit_set(self.code.get(position..position + 8)?, character) {
                        return Some(hit);
                    }
                    position += 8;
                }
                Opcode::BigCharset => {
                    let blocks = usize::try_from(self.word(position)?).ok()?;
                    let table = position + 1;
                    let bitmaps = table + 64;
                    if let Ok(unit) = u16::try_from(character) {
                        let [high, low] = unit.to_be_bytes();
                        let block = usize::from(self.word(table + usize::from(high) / 4)?.to_le_bytes()[usize::from(high) % 4]);
                        let start = bitmaps + block * 8;
                        if bit_set(self.code.get(start..start + 8)?, u32::from(low)) {
                            return Some(hit);
                        }
                    }
                    position = bitmaps.checked_add(blocks.checked_mul(8)?)?;
                }
                _ => return None,
            }
        }
    }
}

/// Whether bit `index` of a bitmap stored as 32-bit words is set.
fn bit_set(words: &[u32], index: u32) -> bool {
    let word = (index / 32) as usize;
    words.get(word).is_some_and(|bits| bits & (1 << (index % 32)) != 0)
}

/// Decodes the operation that would start at `position`.
fn decode(code: &[u32], position: usize) -> Inst {
    decode_operands(code, position).unwrap_or(Inst::Illegal)
}

fn decode_operands(code: &[u32], position: usize) -> Option<Inst> {
    let word = |offset: usize| code.get(position + offset).copied();
    let index = |offset: usize| word(offset).and_then(|value| usize::try_from(value).ok());
    // A skip word counts from its own position.
    let target = |offset: usize| index(offset)?.checked_add(position + offset);

    let inst = match Opcode::from_word(word(0)?)? {
        Opcode::Failure => Inst::Failure,
        Opcode::Success => Inst::Success,
        Opcode::Any => Inst::Any,
        Opcode::AnyAll => Inst::AnyAll,
        Opcode::At => Inst::At(Anchor::from_word(word(1)?)?),
        Opcode::Literal => Inst::Literal { character: word(1)?, test: LiteralTest::Equal },
        Opcode::NotLiteral => Inst::Literal { character: word(1)?, test: LiteralTest::NotEqual },
        Opcode::LiteralIgnore => Inst::Literal { character: word(1)?, test: LiteralTest::EqualFolded },
        Opcode::NotLiteralIgnore => Inst::Literal { character: word(1)?, test: LiteralTest::NotEqualFolded },
        Opcode::In => Inst::In { set: position + 2, folded: false, next: target(1)? },
        Opcode::InIgnore => Inst::In { set: position + 2, folded: true, next: target(1)? },
        Opcode::Info => Inst::Info { next: target(1)? },
        Opcode::Mark => Inst::Mark(index(1)?),
        Opcode::Jump => Inst::Jump(target(1)?),
        Opcode::Branch => Inst::Branch { first: position + 1 },
        Opcode::RepeatOne | Opcode::MinRepeatOne => Inst::RepeatOne {
            minimum: word(2)?,
            maximum: word(3)?,
            item: position + 4,
            tail: target(1)?,
            lazy: Opcode::from_word(word(0)?) == Some(Opcode::MinRepeatOne),
        },
        Opcode::Repeat => Inst::Repeat { minimum: word(2)?, maximum: word(3)?, body: position + 4, until: target(1)? },
        Opcode::MaxUntil => Inst::Until { lazy: false },
        Opcode::MinUntil => Inst::Until { lazy: true },
        Opcode::GroupRef => Inst::GroupRef { group: index(1)?, folded: false },
        Opcode::GroupRefIgnore => Inst::GroupRef { group: index(1)?, folded: true },
        // The skip of a conditional counts from the group word.
        Opcode::GroupRefExists => Inst::GroupRefExists { group: index(1)?, otherwise: index(2)?.checked_add(position + 1)? },
        Opcode::Assert | Opcode::AssertNot => Inst::Assert {
            negated: Opcode::from_word(word(0)?) == Some(Opcode::AssertNot),
            behind: index(2)?,
            body: position + 3,
            next: target(1)?,
        },
        _ => Inst::Illegal,
    };

    Some(inst)
}

/// The match entry and search hints of a code list that starts with an
/// INFO block.
fn info_hints(code: &[u32]) -> (usize, SearchHints) {
    let word = |position: usize| code.get(position).copied().unwrap_or_default();
    let index = |position: usize| usize::try_from(word(position)).unwrap_or(usize::MAX);
    let entry = 1 + index(1);
    let flags = word(2);

    let mut hints = SearchHints { minimum: index(3), literal: flags & INFO_LITERAL != 0, prefix: None, first_set: None };
    if flags & INFO_PREFIX != 0 {
        hints.prefix = Some(Prefix { start: 7, length: index(5), skip: index(6) });
    } else if flags & INFO_CHARSET != 0 {
        hints.first_set = Some(5);
    }

    (entry, hints)
}
