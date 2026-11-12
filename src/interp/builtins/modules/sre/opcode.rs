//! Numbering of `_sre` code words as the client's `sre_constants.py`
//! assigns it.

/// The repeat count that stands for "no upper bound".
pub const MAXREPEAT: u32 = u32::MAX;

/// `SRE_FLAG_LOCALE`.
pub const FLAG_LOCALE: i64 = 4;
/// `SRE_FLAG_UNICODE`.
pub const FLAG_UNICODE: i64 = 32;

/// `SRE_INFO_PREFIX`: the INFO block carries a literal prefix.
pub const INFO_PREFIX: u32 = 1;
/// `SRE_INFO_LITERAL`: the whole pattern is the prefix.
pub const INFO_LITERAL: u32 = 2;
/// `SRE_INFO_CHARSET`: the INFO block carries the set of first characters.
pub const INFO_CHARSET: u32 = 4;

/// An operation code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Failure,
    Success,
    Any,
    AnyAll,
    Assert,
    AssertNot,
    At,
    Branch,
    Call,
    Category,
    Charset,
    BigCharset,
    GroupRef,
    GroupRefExists,
    GroupRefIgnore,
    In,
    InIgnore,
    Info,
    Jump,
    Literal,
    LiteralIgnore,
    Mark,
    MaxUntil,
    MinUntil,
    NotLiteral,
    NotLiteralIgnore,
    Negate,
    Range,
    Repeat,
    RepeatOne,
    SubPattern,
    MinRepeatOne,
}

impl Opcode {
    pub fn from_word(word: u32) -> Option<Self> {
        const ORDER: [Opcode; 32] = [
            Opcode::Failure,
            Opcode::Success,
            Opcode::Any,
            Opcode::AnyAll,
            Opcode::Assert,
            Opcode::AssertNot,
            Opcode::At,
            Opcode::Branch,
            Opcode::Call,
            Opcode::Category,
            Opcode::Charset,
            Opcode::BigCharset,
            Opcode::GroupRef,
            Opcode::GroupRefExists,
            Opcode::GroupRefIgnore,
            Opcode::In,
            Opcode::InIgnore,
            Opcode::Info,
            Opcode::Jump,
            Opcode::Literal,
            Opcode::LiteralIgnore,
            Opcode::Mark,
            Opcode::MaxUntil,
            Opcode::MinUntil,
            Opcode::NotLiteral,
            Opcode::NotLiteralIgnore,
            Opcode::Negate,
            Opcode::Range,
            Opcode::Repeat,
            Opcode::RepeatOne,
            Opcode::SubPattern,
            Opcode::MinRepeatOne,
        ];

        ORDER.get(usize::try_from(word).ok()?).copied()
    }
}

/// A zero-width position test (`AT` operand).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    Beginning,
    BeginningLine,
    BeginningString,
    Boundary,
    NonBoundary,
    End,
    EndLine,
    EndString,
    LocaleBoundary,
    LocaleNonBoundary,
    UnicodeBoundary,
    UnicodeNonBoundary,
}

impl Anchor {
    pub fn from_word(word: u32) -> Option<Self> {
        const ORDER: [Anchor; 12] = [
            Anchor::Beginning,
            Anchor::BeginningLine,
            Anchor::BeginningString,
            Anchor::Boundary,
            Anchor::NonBoundary,
            Anchor::End,
            Anchor::EndLine,
            Anchor::EndString,
            Anchor::LocaleBoundary,
            Anchor::LocaleNonBoundary,
            Anchor::UnicodeBoundary,
            Anchor::UnicodeNonBoundary,
        ];

        ORDER.get(usize::try_from(word).ok()?).copied()
    }
}

/// A character class (`CATEGORY` operand inside a set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
    Linebreak,
    NotLinebreak,
    LocaleWord,
    LocaleNotWord,
    UnicodeDigit,
    UnicodeNotDigit,
    UnicodeSpace,
    UnicodeNotSpace,
    UnicodeWord,
    UnicodeNotWord,
    UnicodeLinebreak,
    UnicodeNotLinebreak,
}

impl Category {
    pub fn from_word(word: u32) -> Option<Self> {
        const ORDER: [Category; 18] = [
            Category::Digit,
            Category::NotDigit,
            Category::Space,
            Category::NotSpace,
            Category::Word,
            Category::NotWord,
            Category::Linebreak,
            Category::NotLinebreak,
            Category::LocaleWord,
            Category::LocaleNotWord,
            Category::UnicodeDigit,
            Category::UnicodeNotDigit,
            Category::UnicodeSpace,
            Category::UnicodeNotSpace,
            Category::UnicodeWord,
            Category::UnicodeNotWord,
            Category::UnicodeLinebreak,
            Category::UnicodeNotLinebreak,
        ];

        ORDER.get(usize::try_from(word).ok()?).copied()
    }
}
