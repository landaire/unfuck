//! The structural check `_sre.compile` applies to a code list before it
//! builds a pattern. A list either passes or raises `RuntimeError`; the
//! rules here reproduce which lists the client accepts.
//!
//! Each nested region is checked on its own, so regions are queued on a
//! worklist; the order does not change the verdict.

use crate::interp::builtins::modules::sre::opcode::Anchor;
use crate::interp::builtins::modules::sre::opcode::Category;
use crate::interp::builtins::modules::sre::opcode::INFO_CHARSET;
use crate::interp::builtins::modules::sre::opcode::INFO_LITERAL;
use crate::interp::builtins::modules::sre::opcode::INFO_PREFIX;
use crate::interp::builtins::modules::sre::opcode::Opcode;

/// The code list fails the structural check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid SRE code")]
pub struct InvalidCode;

/// A region of the code list still to check.
#[derive(Clone, Copy)]
enum Region {
    /// A sequence of operations.
    Block { start: usize, end: usize },
    /// The items of a character set, without its terminating `FAILURE`.
    Set { start: usize, end: usize },
}

/// Checks `code` for a pattern declaring `groups` groups. Returns the
/// largest mark index a `MARK` operation uses.
pub fn validate(code: &[u32], groups: i64) -> Result<Option<usize>, InvalidCode> {
    /// The largest `groups` value a pattern may declare.
    const MAX_GROUPS: u64 = 100;

    let groups = u64::try_from(groups).map_err(|_| InvalidCode)?;
    if groups > MAX_GROUPS {
        return Err(InvalidCode);
    }
    let Some((&last, body)) = code.split_last() else {
        return Err(InvalidCode);
    };
    if Opcode::from_word(last) != Some(Opcode::Success) {
        return Err(InvalidCode);
    }

    // A pattern that declares no groups may still refer to any group the
    // syntax allows.
    let group_limit = if groups == 0 { MAX_GROUPS } else { groups };
    let mut checker = Checker { code, group_limit, highest_mark: None, pending: vec![Region::Block { start: 0, end: body.len() }] };
    while let Some(region) = checker.pending.pop() {
        match region {
            Region::Block { start, end } => checker.block(start, end)?,
            Region::Set { start, end } => checker.set(start, end)?,
        }
    }

    Ok(checker.highest_mark)
}

struct Checker<'a> {
    code: &'a [u32],
    group_limit: u64,
    highest_mark: Option<usize>,
    pending: Vec<Region>,
}

impl Checker<'_> {
    /// The word at `position`, which must lie before `end`.
    fn word(&self, position: usize, end: usize) -> Result<u32, InvalidCode> {
        if position >= end {
            return Err(InvalidCode);
        }

        self.code.get(position).copied().ok_or(InvalidCode)
    }

    /// The position a skip word at `position` with the given value leads
    /// to, which must not pass `end`.
    fn skip_target(&self, position: usize, end: usize) -> Result<usize, InvalidCode> {
        let skip = self.word(position, end)?;
        let target = position.checked_add(usize::try_from(skip).map_err(|_| InvalidCode)?).ok_or(InvalidCode)?;
        if target > end {
            return Err(InvalidCode);
        }

        Ok(target)
    }

    /// Queues a nested block. A block that would end before it starts is
    /// malformed.
    fn queue_block(&mut self, start: usize, end: usize) -> Result<(), InvalidCode> {
        if end < start {
            return Err(InvalidCode);
        }
        self.pending.push(Region::Block { start, end });

        Ok(())
    }

    fn block(&mut self, start: usize, end: usize) -> Result<(), InvalidCode> {
        let mut position = start;
        while position < end {
            let operation = Opcode::from_word(self.word(position, end)?).ok_or(InvalidCode)?;
            position += 1;
            position = match operation {
                Opcode::Failure | Opcode::Success | Opcode::Any | Opcode::AnyAll => position,
                Opcode::At => {
                    let anchor = self.word(position, end)?;
                    if Anchor::from_word(anchor).is_none() {
                        return Err(InvalidCode);
                    }
                    position + 1
                }
                Opcode::Literal | Opcode::NotLiteral | Opcode::LiteralIgnore | Opcode::NotLiteralIgnore => {
                    self.word(position, end)?;
                    position + 1
                }
                Opcode::Mark => {
                    let mark = u64::from(self.word(position, end)?);
                    if mark > 2 * self.group_limit + 1 {
                        return Err(InvalidCode);
                    }
                    let mark = usize::try_from(mark).map_err(|_| InvalidCode)?;
                    self.highest_mark = Some(self.highest_mark.map_or(mark, |highest| highest.max(mark)));
                    position + 1
                }
                Opcode::GroupRef | Opcode::GroupRefIgnore => {
                    if u64::from(self.word(position, end)?) >= self.group_limit {
                        return Err(InvalidCode);
                    }
                    position + 1
                }
                Opcode::In | Opcode::InIgnore => self.set_operation(position, end)?,
                Opcode::Info => self.info(position, end)?,
                Opcode::Branch => self.branch(position, end)?,
                Opcode::RepeatOne | Opcode::MinRepeatOne => {
                    let next = self.skip_target(position, end)?;
                    self.counts(position, end)?;
                    let item_end = next.checked_sub(1).ok_or(InvalidCode)?;
                    self.queue_block(position + 3, item_end)?;
                    if Opcode::from_word(self.word(item_end, end)?) != Some(Opcode::Success) {
                        return Err(InvalidCode);
                    }
                    next
                }
                Opcode::Repeat => {
                    let until = self.skip_target(position, end)?;
                    self.counts(position, end)?;
                    self.queue_block(position + 3, until)?;
                    match Opcode::from_word(self.word(until, end)?) {
                        Some(Opcode::MaxUntil | Opcode::MinUntil) => until + 1,
                        _ => return Err(InvalidCode),
                    }
                }
                Opcode::Assert | Opcode::AssertNot => {
                    let next = self.skip_target(position, end)?;
                    if self.word(position + 1, end)? & 0x8000_0000 != 0 {
                        return Err(InvalidCode);
                    }
                    let body_end = next.checked_sub(1).ok_or(InvalidCode)?;
                    self.queue_block(position + 2, body_end)?;
                    if Opcode::from_word(self.word(body_end, end)?) != Some(Opcode::Success) {
                        return Err(InvalidCode);
                    }
                    next
                }
                Opcode::GroupRefExists => self.conditional(position, end)?,
                _ => return Err(InvalidCode),
            };
        }

        Ok(())
    }

    /// The minimum and maximum after a repeat's skip word: the minimum may
    /// not exceed the maximum.
    fn counts(&self, skip_position: usize, end: usize) -> Result<(), InvalidCode> {
        let minimum = self.word(skip_position + 1, end)?;
        let maximum = self.word(skip_position + 2, end)?;
        if minimum > maximum {
            return Err(InvalidCode);
        }

        Ok(())
    }

    /// `IN`: a skip word, set items, and a terminating `FAILURE` just
    /// before the skip target.
    fn set_operation(&mut self, skip_position: usize, end: usize) -> Result<usize, InvalidCode> {
        let next = self.skip_target(skip_position, end)?;
        if next < skip_position + 2 {
            return Err(InvalidCode);
        }
        self.pending.push(Region::Set { start: skip_position + 1, end: next - 1 });
        if Opcode::from_word(self.word(next - 1, end)?) != Some(Opcode::Failure) {
            return Err(InvalidCode);
        }

        Ok(next)
    }

    /// `INFO`: flags, length bounds, then a literal prefix or a set of
    /// first characters.
    fn info(&mut self, skip_position: usize, end: usize) -> Result<usize, InvalidCode> {
        let next = self.skip_target(skip_position, end)?;
        let flags = self.word(skip_position + 1, end)?;
        self.word(skip_position + 2, end)?;
        self.word(skip_position + 3, end)?;
        if flags & !(INFO_PREFIX | INFO_LITERAL | INFO_CHARSET) != 0 {
            return Err(InvalidCode);
        }
        if flags & INFO_PREFIX != 0 && flags & INFO_CHARSET != 0 {
            return Err(InvalidCode);
        }
        if flags & INFO_LITERAL != 0 && flags & INFO_PREFIX == 0 {
            return Err(InvalidCode);
        }

        let mut cursor = skip_position + 4;
        if flags & INFO_PREFIX != 0 {
            let length = self.word(cursor, end)?;
            self.word(cursor + 1, end)?;
            cursor += 2;
            let length = usize::try_from(length).map_err(|_| InvalidCode)?;
            let remaining = |cursor: usize| next.checked_sub(cursor).ok_or(InvalidCode);
            if length > remaining(cursor)? {
                return Err(InvalidCode);
            }
            cursor += length;
            if length > remaining(cursor)? {
                return Err(InvalidCode);
            }
            let overlap = self.code.get(cursor..cursor + length).ok_or(InvalidCode)?;
            if overlap.iter().any(|&entry| usize::try_from(entry).map_or(true, |entry| entry >= length)) {
                return Err(InvalidCode);
            }
            cursor += length;
        }

        if flags & INFO_CHARSET != 0 {
            let terminator = next.checked_sub(1).ok_or(InvalidCode)?;
            self.pending.push(Region::Set { start: cursor, end: terminator });
            if Opcode::from_word(self.code.get(terminator).copied().ok_or(InvalidCode)?) != Some(Opcode::Failure) {
                return Err(InvalidCode);
            }
        } else if cursor != next {
            return Err(InvalidCode);
        }

        Ok(next)
    }

    /// `BRANCH`: alternatives, each ending in a `JUMP` to one common
    /// target, closed by a zero skip.
    fn branch(&mut self, mut position: usize, end: usize) -> Result<usize, InvalidCode> {
        let mut common_target = None;
        loop {
            if self.word(position, end)? == 0 {
                return Ok(position + 1);
            }
            let next = self.skip_target(position, end)?;
            let jump = next.checked_sub(2).ok_or(InvalidCode)?;
            self.queue_block(position + 1, jump)?;
            if Opcode::from_word(self.word(jump, end)?) != Some(Opcode::Jump) {
                return Err(InvalidCode);
            }
            let target = self.skip_target(jump + 1, end)?;
            if common_target.is_some_and(|common| common != target) {
                return Err(InvalidCode);
            }
            common_target = Some(target);
            position = next;
        }
    }

    /// `GROUPREF_EXISTS`: a group, then a "then" part, optionally followed
    /// by a `JUMP` over an "else" part. The skip counts from the group
    /// word.
    fn conditional(&mut self, group_position: usize, end: usize) -> Result<usize, InvalidCode> {
        if u64::from(self.word(group_position, end)?) >= self.group_limit {
            return Err(InvalidCode);
        }
        let skip_position = group_position + 1;
        let skip = usize::try_from(self.word(skip_position, end)?).map_err(|_| InvalidCode)?;
        let target = group_position.checked_add(skip).ok_or(InvalidCode)?;
        if skip == 0 || target > end {
            return Err(InvalidCode);
        }

        let jump = (skip >= 3).then(|| skip_position + skip - 3);
        let Some(jump) = jump.filter(|&jump| self.code.get(jump).copied().and_then(Opcode::from_word) == Some(Opcode::Jump)) else {
            self.queue_block(skip_position + 1, target)?;
            return Ok(target);
        };

        self.queue_block(skip_position + 1, jump)?;
        let otherwise_end = self.skip_target(jump + 1, end)?;
        self.queue_block(jump + 2, otherwise_end)?;

        Ok(otherwise_end)
    }

    /// The items of a set. A region that ends before it starts holds no
    /// items.
    fn set(&self, start: usize, end: usize) -> Result<(), InvalidCode> {
        let mut position = start;
        while position < end {
            let item = Opcode::from_word(self.word(position, end)?).ok_or(InvalidCode)?;
            position += 1;
            position = match item {
                Opcode::Negate => position,
                Opcode::Literal => {
                    self.word(position, end)?;
                    position + 1
                }
                Opcode::Range => {
                    self.word(position + 1, end)?;
                    position + 2
                }
                Opcode::Charset => {
                    let next = position + 8;
                    if next > end {
                        return Err(InvalidCode);
                    }
                    next
                }
                Opcode::BigCharset => {
                    let blocks = u64::from(self.word(position, end)?);
                    let table_start = position + 1;
                    let table_end = table_start + 64;
                    if table_end > end {
                        return Err(InvalidCode);
                    }
                    let table = &self.code[table_start..table_end];
                    if table.iter().flat_map(|word| word.to_le_bytes()).any(|block| u64::from(block) >= blocks) {
                        return Err(InvalidCode);
                    }
                    let bitmaps = blocks.checked_mul(8).and_then(|words| usize::try_from(words).ok()).ok_or(InvalidCode)?;
                    let next = table_end.checked_add(bitmaps).ok_or(InvalidCode)?;
                    if next > end {
                        return Err(InvalidCode);
                    }
                    next
                }
                Opcode::Category => {
                    if Category::from_word(self.word(position, end)?).is_none() {
                        return Err(InvalidCode);
                    }
                    position + 1
                }
                _ => return Err(InvalidCode),
            };
        }

        Ok(())
    }
}
