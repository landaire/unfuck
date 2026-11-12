//! The backtracking matcher. Control state lives on an explicit stack of
//! frames, so the native stack stays flat however long the subject is.
//!
//! Matching state follows the client's observable rules: group marks,
//! the count of marks in force, and the last closed group survive a failed
//! path unless a construct saved them; a failed alternative restores only
//! the mark count and last group unless it runs inside a repeat; a repeat
//! iteration saves and restores the marks themselves, except when the
//! first mark is the only one in force. A failed negative lookahead keeps
//! the marks it set.

use crate::interp::builtins::modules::sre::classify::Fold;
use crate::interp::builtins::modules::sre::classify::category;
use crate::interp::builtins::modules::sre::classify::is_locale_word;
use crate::interp::builtins::modules::sre::classify::is_unicode_word;
use crate::interp::builtins::modules::sre::classify::is_word;
use crate::interp::builtins::modules::sre::opcode::Anchor;
use crate::interp::builtins::modules::sre::opcode::MAXREPEAT;
use crate::interp::builtins::modules::sre::program::Inst;
use crate::interp::builtins::modules::sre::program::LiteralTest;
use crate::interp::builtins::modules::sre::program::Program;

/// The code reached an operation it cannot run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("internal error in regular expression engine")]
pub struct EngineError;

/// A subject code unit: a byte of a `str` or buffer, or a UTF-16 unit.
pub trait Unit: Copy {
    fn code(self) -> u32;
}

impl Unit for u8 {
    fn code(self) -> u32 {
        u32::from(self)
    }
}

impl Unit for u16 {
    fn code(self) -> u32 {
        u32::from(self)
    }
}

/// The extent of a group in the subject. `end` may precede `start` when
/// marks were set out of order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A successful match.
#[derive(Clone, Debug)]
pub struct Found {
    pub whole: Span,
    /// Groups 1 and up; `None` for a group that did not take part.
    pub groups: Vec<Option<Span>>,
    pub last_index: Option<usize>,
}

/// One activation of a `REPEAT`.
struct RepeatContext {
    /// Iterations begun so far.
    entered: u64,
    minimum: u32,
    maximum: u32,
    body: usize,
    /// Where the latest optional iteration began; an iteration may not
    /// begin twice at one position.
    last_position: Option<usize>,
    outer: Option<usize>,
}

/// The mark count and last closed group, saved to undo a failed path.
#[derive(Clone, Copy)]
struct MarkState {
    count: usize,
    last_index: Option<usize>,
}

/// What a nested match decides once it ends.
#[derive(Clone, Copy)]
enum Nested {
    Assert { negated: bool, next: usize },
    /// Matching an item of a single-item repeat that is not a single
    /// character test, repeatedly from `origin`; `reached` is where the
    /// last successful round ended.
    Count { origin: usize, reached: usize, limit: usize, item: usize, then: Counted },
}

/// What happens with the number of characters a single-item repeat
/// counted.
#[derive(Clone, Copy)]
enum Counted {
    Greedy { tail: usize, origin: usize, minimum: usize },
    LazyStart { tail: usize, item: usize, origin: usize, minimum: usize, maximum: u32 },
    LazyStep(Lazy),
}

#[derive(Clone, Copy)]
struct Greedy {
    tail: usize,
    origin: usize,
    count: usize,
    minimum: usize,
    /// The tail starts with this literal, so only positions holding it
    /// are worth trying.
    literal: Option<u32>,
    marks: MarkState,
}

#[derive(Clone, Copy)]
struct Lazy {
    tail: usize,
    item: usize,
    position: usize,
    count: u64,
    maximum: u32,
    marks: MarkState,
}

/// A pending decision on the backtracking stack.
#[derive(Clone, Copy)]
enum Frame {
    /// Alternatives of a `BRANCH` from the skip word at `next`. `saved`
    /// is the offset of a mark snapshot, taken inside a repeat.
    Branch { next: usize, position: usize, marks: MarkState, saved: Option<usize> },
    Greedy(Greedy),
    Lazy(Lazy),
    Repeat { context: usize },
    /// A required iteration; failure takes back its count.
    Forced { context: usize, count: u64 },
    /// An optional greedy iteration; failure restores the marks and tries
    /// the tail instead.
    Iteration { context: usize, count: u64, position: usize, until: usize, previous: Option<usize>, marks: MarkState, saved: usize },
    /// The tail after a repeat; failure re-enters the repeat.
    Tail { context: usize },
    /// The tail after a lazy repeat; failure tries one more iteration.
    LazyTail { context: usize, count: u64, position: usize, marks: MarkState },
    LazyIteration { context: usize, count: u64, previous: Option<usize> },
    /// A nested match, whose success ends at the innermost such frame.
    Nested { nested: Nested, position: usize, repeat: Option<usize>, repeats: usize, saved: usize },
}

/// Where execution goes next.
enum Flow {
    Run { pc: usize, position: usize },
    Fail,
    Succeed { position: usize },
}

/// Matches one program against one subject. State persists between the
/// start positions a search tries and is cleared by each `match_at` and
/// `search` call.
pub struct Matcher<'a, T: Unit> {
    program: &'a Program,
    text: &'a [T],
    end: usize,
    fold: Fold,

    marks: Vec<Option<usize>>,
    mark_count: usize,
    last_index: Option<usize>,

    repeat: Option<usize>,
    repeats: Vec<RepeatContext>,
    frames: Vec<Frame>,
    saved: Vec<Option<usize>>,
    nested: Vec<usize>,
}

impl<'a, T: Unit> Matcher<'a, T> {
    /// A matcher over `text[..end]`.
    pub fn new(program: &'a Program, text: &'a [T], end: usize, fold: Fold) -> Self {
        Self {
            program,
            text,
            end: end.min(text.len()),
            fold,
            marks: vec![None; program.mark_slots()],
            mark_count: 0,
            last_index: None,
            repeat: None,
            repeats: Vec::new(),
            frames: Vec::new(),
            saved: Vec::new(),
            nested: Vec::new(),
        }
    }

    pub fn end(&self) -> usize {
        self.end
    }

    fn reset(&mut self) {
        self.marks.fill(None);
        self.mark_count = 0;
        self.last_index = None;
        self.repeat = None;
        self.repeats.clear();
        self.frames.clear();
        self.saved.clear();
        self.nested.clear();
    }

    /// A match starting exactly at `start`, which may lie past the end:
    /// a pattern that needs no characters still matches there.
    pub fn match_at(&mut self, start: usize, groups: usize) -> Result<Option<Found>, EngineError> {
        self.reset();

        let minimum = self.program.hints().minimum;
        if minimum > 0 && self.end.saturating_sub(start) < minimum {
            return Ok(None);
        }

        let found = self.attempt(self.program.entry(), start)?;

        Ok(found.map(|stop| self.found(start, stop, groups)))
    }

    /// The first match starting at or after `start`.
    pub fn search(&mut self, start: usize, groups: usize) -> Result<Option<Found>, EngineError> {
        self.reset();
        if start > self.end {
            return Ok(None);
        }

        let hints = self.program.hints();
        let minimum = hints.minimum;
        if minimum > 0 && self.end - start < minimum {
            return Ok(None);
        }

        let entry = self.program.entry();
        if let Some(prefix) = hints.prefix.filter(|prefix| prefix.length > 1) {
            let Some(last) = self.end.checked_sub(prefix.length) else {
                return Ok(None);
            };
            for candidate in start..=last {
                if !self.prefix_at(candidate, prefix.start, prefix.length) {
                    continue;
                }
                // The prefix may claim to cover more than the subject holds.
                let resume = candidate.saturating_add(prefix.skip);
                if hints.literal {
                    return Ok(Some(self.found(candidate, resume, groups)));
                }
                // The skipped prefix operations are two words each.
                let Some(pc) = prefix.skip.checked_mul(2).and_then(|words| words.checked_add(entry)) else {
                    continue;
                };
                if let Some(stop) = self.attempt(pc, resume)? {
                    return Ok(Some(self.found(candidate, stop, groups)));
                }
            }
            return Ok(None);
        }

        if let Inst::Literal { character, test: LiteralTest::Equal } = self.program.inst(entry) {
            for candidate in start..self.end {
                if self.text[candidate].code() != character {
                    continue;
                }
                if hints.literal {
                    return Ok(Some(self.found(candidate, candidate + 1, groups)));
                }
                if let Some(stop) = self.attempt(entry + 2, candidate + 1)? {
                    return Ok(Some(self.found(candidate, stop, groups)));
                }
            }
            return Ok(None);
        }

        if let Some(set) = hints.first_set {
            for candidate in start..self.end {
                if !self.in_set(set, self.text[candidate].code())? {
                    continue;
                }
                if let Some(stop) = self.attempt(entry, candidate)? {
                    return Ok(Some(self.found(candidate, stop, groups)));
                }
            }
            return Ok(None);
        }

        // Starts too close to the end for the shortest match are not
        // tried, give or take one.
        let last = if minimum > 1 { self.end - (minimum - 1) } else { self.end };
        for candidate in start..=last {
            if let Some(stop) = self.attempt(entry, candidate)? {
                return Ok(Some(self.found(candidate, stop, groups)));
            }
        }

        Ok(None)
    }

    fn prefix_at(&self, candidate: usize, prefix_start: usize, length: usize) -> bool {
        (0..length).all(|offset| self.program.word(prefix_start + offset) == Some(self.text[candidate + offset].code()))
    }

    fn found(&self, start: usize, stop: usize, groups: usize) -> Found {
        let groups = (0..groups)
            .map(|group| {
                let first = 2 * group;
                if first + 1 >= self.mark_count {
                    return None;
                }
                let start = self.marks.get(first).copied().flatten()?;
                let end = self.marks.get(first + 1).copied().flatten()?;
                Some(Span { start, end })
            })
            .collect();

        Found { whole: Span { start, end: stop }, groups, last_index: self.last_index }
    }

    /// Runs from `pc` at `position` until the match ends or every path
    /// failed. Returns where the match ended.
    fn attempt(&mut self, pc: usize, position: usize) -> Result<Option<usize>, EngineError> {
        self.frames.clear();
        self.nested.clear();

        let mut flow = Flow::Run { pc, position };
        loop {
            flow = match flow {
                Flow::Run { pc, position } => self.step(pc, position)?,
                Flow::Fail => match self.frames.pop() {
                    Some(frame) => self.backtrack(frame)?,
                    None => return Ok(None),
                },
                Flow::Succeed { position } => match self.nested.last() {
                    Some(&frame) => self.nested_succeeded(frame, position)?,
                    None => return Ok(Some(position)),
                },
            };
        }
    }

    fn character(&self, position: usize) -> Option<u32> {
        (position < self.end).then(|| self.text[position].code())
    }

    fn marks_now(&self) -> MarkState {
        MarkState { count: self.mark_count, last_index: self.last_index }
    }

    fn restore_marks(&mut self, marks: MarkState) {
        self.mark_count = marks.count;
        self.last_index = marks.last_index;
    }

    /// How many marks a snapshot of `count` marks in force keeps. A lone
    /// first mark is not kept, so a failed path can leave it changed.
    fn kept(count: usize) -> usize {
        if count > 1 { count } else { 0 }
    }

    /// Saves the marks in force and returns the snapshot's offset.
    fn snapshot(&mut self) -> usize {
        let offset = self.saved.len();
        let kept = Self::kept(self.mark_count);
        self.saved.extend_from_slice(&self.marks[..kept]);

        offset
    }

    /// Puts back the marks of the snapshot at `offset`, taken with `count`
    /// marks in force, keeping the snapshot.
    fn reload(&mut self, offset: usize, count: usize) {
        let kept = Self::kept(count);
        self.marks[..kept].copy_from_slice(&self.saved[offset..offset + kept]);
    }

    fn set_mark(&mut self, index: usize, position: usize) {
        if index % 2 == 1 {
            self.last_index = Some(index / 2 + 1);
        }
        if index >= self.marks.len() {
            self.marks.resize(index + 1, None);
        }
        // Marks between the old count and the new one were set on a path
        // since abandoned.
        if index >= self.mark_count {
            self.marks[self.mark_count..index].fill(None);
            self.mark_count = index + 1;
        }
        self.marks[index] = Some(position);
    }

    /// The extent of `group` if it took part on the current path.
    fn group_span(&self, group: usize) -> Option<Span> {
        let first = group.checked_mul(2)?;
        if first + 1 >= self.mark_count {
            return None;
        }
        let start = self.marks.get(first).copied().flatten()?;
        let end = self.marks.get(first + 1).copied().flatten()?;

        (end >= start).then_some(Span { start, end })
    }

    fn in_set(&self, set: usize, character: u32) -> Result<bool, EngineError> {
        self.program.set_contains(set, character, category).ok_or(EngineError)
    }

    fn literal_matches(&self, test: LiteralTest, expected: u32, character: u32) -> bool {
        match test {
            LiteralTest::Equal => character == expected,
            LiteralTest::NotEqual => character != expected,
            LiteralTest::EqualFolded => self.fold.lower(character) == self.fold.lower(expected),
            LiteralTest::NotEqualFolded => self.fold.lower(character) != self.fold.lower(expected),
        }
    }

    /// Whether the single-character test `inst` accepts `character`.
    /// `None` for an operation that is not such a test.
    fn single(&self, inst: Inst, character: u32) -> Result<Option<bool>, EngineError> {
        let accepted = match inst {
            Inst::Any => character != u32::from(b'\n'),
            Inst::AnyAll => true,
            Inst::Literal { character: expected, test } => self.literal_matches(test, expected, character),
            Inst::In { set, folded, .. } => {
                let character = if folded { self.fold.lower(character) } else { character };
                self.in_set(set, character)?
            }
            _ => return Ok(None),
        };

        Ok(Some(accepted))
    }

    /// The subject unit at `position` regardless of the end, which the
    /// line anchors read past.
    fn unit(&self, position: usize) -> Option<u32> {
        self.text.get(position).map(|unit| unit.code())
    }

    fn anchor(&self, anchor: Anchor, position: usize) -> bool {
        let before = position.checked_sub(1).and_then(|previous| self.unit(previous));
        let here = self.character(position);
        let newline = u32::from(b'\n');
        let boundary = |word: fn(u32) -> bool| (before.is_some_and(word), here.is_some_and(word));
        match anchor {
            Anchor::Beginning | Anchor::BeginningString => position == 0,
            Anchor::BeginningLine => position == 0 || before == Some(newline),
            Anchor::End => position == self.end || (position + 1 == self.end && here == Some(newline)),
            Anchor::EndLine => position == self.end || self.unit(position) == Some(newline),
            Anchor::EndString => position == self.end,
            // An empty subject has no word boundaries and no non-boundaries.
            Anchor::Boundary | Anchor::LocaleBoundary | Anchor::UnicodeBoundary if self.end == 0 => false,
            Anchor::NonBoundary | Anchor::LocaleNonBoundary | Anchor::UnicodeNonBoundary if self.end == 0 => false,
            Anchor::Boundary => {
                let (left, right) = boundary(is_word);
                left != right
            }
            Anchor::NonBoundary => {
                let (left, right) = boundary(is_word);
                left == right
            }
            Anchor::LocaleBoundary => {
                let (left, right) = boundary(is_locale_word);
                left != right
            }
            Anchor::LocaleNonBoundary => {
                let (left, right) = boundary(is_locale_word);
                left == right
            }
            Anchor::UnicodeBoundary => {
                let (left, right) = boundary(is_unicode_word);
                left != right
            }
            Anchor::UnicodeNonBoundary => {
                let (left, right) = boundary(is_unicode_word);
                left == right
            }
        }
    }

    fn step(&mut self, pc: usize, position: usize) -> Result<Flow, EngineError> {
        let inst = self.program.inst(pc);
        let advance = |accepted: bool, width: usize| if accepted { Flow::Run { pc: pc + width, position: position + 1 } } else { Flow::Fail };

        let flow = match inst {
            Inst::Failure => Flow::Fail,
            Inst::Success => Flow::Succeed { position },
            Inst::Any | Inst::AnyAll | Inst::Literal { .. } => {
                let accepted = match self.character(position) {
                    Some(character) => self.single(inst, character)?.unwrap_or(false),
                    None => false,
                };
                advance(accepted, inst.width())
            }
            Inst::In { next, .. } => {
                let accepted = match self.character(position) {
                    Some(character) => self.single(inst, character)?.unwrap_or(false),
                    None => false,
                };
                if accepted { Flow::Run { pc: next, position: position + 1 } } else { Flow::Fail }
            }
            Inst::At(anchor) => {
                if self.anchor(anchor, position) {
                    Flow::Run { pc: pc + 2, position }
                } else {
                    Flow::Fail
                }
            }
            Inst::Info { next } => Flow::Run { pc: next, position },
            Inst::Jump(target) => Flow::Run { pc: target, position },
            Inst::Mark(index) => {
                self.set_mark(index, position);
                Flow::Run { pc: pc + 2, position }
            }
            Inst::Branch { first } => {
                let saved = self.repeat.is_some().then(|| self.snapshot());
                self.resume_branch(first, position, self.marks_now(), saved)?
            }
            Inst::RepeatOne { minimum, maximum, item, tail, lazy } => self.repeat_one(minimum, maximum, item, tail, lazy, position)?,
            Inst::Repeat { minimum, maximum, body, until } => {
                let context = self.repeats.len();
                self.repeats.push(RepeatContext { entered: 0, minimum, maximum, body, last_position: None, outer: self.repeat });
                self.repeat = Some(context);
                self.frames.push(Frame::Repeat { context });
                Flow::Run { pc: until, position }
            }
            Inst::Until { lazy } => self.until(pc, lazy, position)?,
            Inst::GroupRef { group, folded } => self.group_ref(pc, group, folded, position),
            Inst::GroupRefExists { group, otherwise } => {
                if self.group_span(group).is_some() {
                    Flow::Run { pc: pc + 3, position }
                } else {
                    Flow::Run { pc: otherwise, position }
                }
            }
            Inst::Assert { negated, behind, body, next } => {
                let Some(start) = position.checked_sub(behind) else {
                    return Ok(if negated { Flow::Run { pc: next, position } } else { Flow::Fail });
                };
                self.begin_nested(Nested::Assert { negated, next }, position);
                Flow::Run { pc: body, position: start }
            }
            Inst::Illegal => return Err(EngineError),
        };

        Ok(flow)
    }

    fn begin_nested(&mut self, nested: Nested, position: usize) {
        self.nested.push(self.frames.len());
        self.frames.push(Frame::Nested { nested, position, repeat: self.repeat, repeats: self.repeats.len(), saved: self.saved.len() });
    }

    fn group_ref(&self, pc: usize, group: usize, folded: bool, position: usize) -> Flow {
        let Some(span) = self.group_span(group) else {
            return Flow::Fail;
        };
        let length = span.end - span.start;
        if length > self.end.saturating_sub(position) {
            return Flow::Fail;
        }

        let fold = self.fold;
        let same = (0..length).all(|offset| {
            let expected = self.text[span.start + offset].code();
            let actual = self.text[position + offset].code();
            if folded { fold.lower(expected) == fold.lower(actual) } else { expected == actual }
        });

        if same { Flow::Run { pc: pc + 2, position: position + length } } else { Flow::Fail }
    }

    /// Tries the alternatives from the skip word at `next`.
    fn resume_branch(&mut self, mut next: usize, position: usize, marks: MarkState, saved: Option<usize>) -> Result<Flow, EngineError> {
        loop {
            let skip = self.program.word(next).ok_or(EngineError)?;
            if skip == 0 {
                if let Some(offset) = saved {
                    self.saved.truncate(offset);
                }
                return Ok(Flow::Fail);
            }
            let alternative = next + 1;
            next = next.checked_add(usize::try_from(skip).map_err(|_| EngineError)?).ok_or(EngineError)?;

            // An alternative that opens with a literal or set the next
            // character fails at once.
            let opening = self.program.inst(alternative);
            let hopeless = match opening {
                Inst::Literal { test: LiteralTest::Equal, .. } | Inst::In { folded: false, .. } => match self.character(position) {
                    Some(character) => !self.single(opening, character)?.unwrap_or(false),
                    None => true,
                },
                _ => false,
            };
            if hopeless {
                continue;
            }

            self.frames.push(Frame::Branch { next, position, marks, saved });
            return Ok(Flow::Run { pc: alternative, position });
        }
    }

    fn repeat_one(&mut self, minimum: u32, maximum: u32, item: usize, tail: usize, lazy: bool, position: usize) -> Result<Flow, EngineError> {
        let minimum = usize::try_from(minimum).map_err(|_| EngineError)?;
        // Past the end even an empty repeat fails.
        if position > self.end || minimum > self.end - position {
            return Ok(Flow::Fail);
        }

        if lazy {
            let then = Counted::LazyStart { tail, item, origin: position, minimum, maximum };
            if minimum == 0 {
                return self.counted(then, 0);
            }
            return self.count(item, position, minimum, then);
        }

        let limit = usize::try_from(maximum).unwrap_or(usize::MAX);
        self.count(item, position, limit, Counted::Greedy { tail, origin: position, minimum })
    }

    /// Counts how many characters repeated matches of `item` cover from
    /// `position`, up to `limit` characters, then continues with `then`.
    fn count(&mut self, item: usize, position: usize, limit: usize, then: Counted) -> Result<Flow, EngineError> {
        let limit = position + limit.min(self.end.saturating_sub(position));
        let inst = self.program.inst(item);

        // These tests stand for one character whatever follows them; a
        // folded set does too when it is the whole item.
        let single = match inst {
            Inst::Any | Inst::AnyAll | Inst::Literal { .. } | Inst::In { folded: false, .. } => true,
            Inst::In { folded: true, next, .. } => matches!(self.program.inst(next), Inst::Success),
            _ => false,
        };
        if single {
            let mut reached = position;
            while reached < limit && self.single(inst, self.text[reached].code())?.unwrap_or(false) {
                reached += 1;
            }
            return self.counted(then, reached - position);
        }

        if position >= limit {
            return self.counted(then, 0);
        }
        self.begin_nested(Nested::Count { origin: position, reached: position, limit, item, then }, position);

        Ok(Flow::Run { pc: item, position })
    }

    fn counted(&mut self, then: Counted, count: usize) -> Result<Flow, EngineError> {
        match then {
            Counted::Greedy { tail, origin, minimum } => {
                if count < minimum {
                    return Ok(Flow::Fail);
                }
                if matches!(self.program.inst(tail), Inst::Success) {
                    return Ok(Flow::Succeed { position: origin + count });
                }
                let literal = match self.program.inst(tail) {
                    Inst::Literal { character, test: LiteralTest::Equal } => Some(character),
                    _ => None,
                };
                Ok(self.resume_greedy(Greedy { tail, origin, count, minimum, literal, marks: self.marks_now() }))
            }
            Counted::LazyStart { tail, item, origin, minimum, maximum } => {
                if count < minimum {
                    return Ok(Flow::Fail);
                }
                let position = origin + count;
                if matches!(self.program.inst(tail), Inst::Success) {
                    return Ok(Flow::Succeed { position });
                }
                let lazy = Lazy { tail, item, position, count: count as u64, maximum, marks: self.marks_now() };
                self.frames.push(Frame::Lazy(lazy));
                Ok(Flow::Run { pc: tail, position })
            }
            Counted::LazyStep(mut lazy) => {
                if count == 0 {
                    return Ok(Flow::Fail);
                }
                lazy.position += 1;
                lazy.count += 1;
                self.restore_marks(lazy.marks);
                if lazy.maximum != MAXREPEAT && lazy.count > u64::from(lazy.maximum) {
                    return Ok(Flow::Fail);
                }
                self.frames.push(Frame::Lazy(lazy));
                Ok(Flow::Run { pc: lazy.tail, position: lazy.position })
            }
        }
    }

    /// Tries the tail of a greedy single-item repeat after `count`
    /// characters, backing off one character at a time.
    fn resume_greedy(&mut self, mut greedy: Greedy) -> Flow {
        loop {
            if greedy.count < greedy.minimum {
                return Flow::Fail;
            }
            let position = greedy.origin + greedy.count;
            let wanted = match greedy.literal {
                Some(literal) => self.character(position) == Some(literal),
                None => true,
            };
            if wanted {
                self.frames.push(Frame::Greedy(greedy));
                return Flow::Run { pc: greedy.tail, position };
            }
            let Some(fewer) = greedy.count.checked_sub(1) else {
                return Flow::Fail;
            };
            greedy.count = fewer;
        }
    }

    fn until(&mut self, pc: usize, lazy: bool, position: usize) -> Result<Flow, EngineError> {
        let context = self.repeat.ok_or(EngineError)?;
        let marks = self.marks_now();
        let repeat = self.repeats.get_mut(context).ok_or(EngineError)?;
        let count = repeat.entered;

        if count < u64::from(repeat.minimum) {
            repeat.entered = count + 1;
            let body = repeat.body;
            self.frames.push(Frame::Forced { context, count });
            return Ok(Flow::Run { pc: body, position });
        }

        if lazy {
            self.repeat = repeat.outer;
            self.frames.push(Frame::LazyTail { context, count, position, marks });
            return Ok(Flow::Run { pc: pc + 1, position });
        }

        let more_allowed = repeat.maximum == MAXREPEAT || count < u64::from(repeat.maximum);
        if more_allowed && repeat.last_position != Some(position) {
            let previous = repeat.last_position;
            repeat.entered = count + 1;
            repeat.last_position = Some(position);
            let body = repeat.body;
            let saved = self.snapshot();
            self.frames.push(Frame::Iteration { context, count, position, until: pc, previous, marks, saved });
            return Ok(Flow::Run { pc: body, position });
        }

        Ok(self.until_tail(context, pc, position))
    }

    fn until_tail(&mut self, context: usize, until: usize, position: usize) -> Flow {
        self.repeat = self.repeats[context].outer;
        self.frames.push(Frame::Tail { context });

        Flow::Run { pc: until + 1, position }
    }

    /// Undoes `frame` after the path past it failed, and picks the next
    /// path to try.
    fn backtrack(&mut self, frame: Frame) -> Result<Flow, EngineError> {
        let flow = match frame {
            Frame::Branch { next, position, marks, saved } => {
                if let Some(offset) = saved {
                    self.reload(offset, marks.count);
                }
                self.restore_marks(marks);
                self.resume_branch(next, position, marks, saved)?
            }
            Frame::Greedy(mut greedy) => {
                self.restore_marks(greedy.marks);
                let Some(fewer) = greedy.count.checked_sub(1) else {
                    return Ok(Flow::Fail);
                };
                greedy.count = fewer;
                self.resume_greedy(greedy)
            }
            Frame::Lazy(lazy) => self.count(lazy.item, lazy.position, 1, Counted::LazyStep(lazy))?,
            Frame::Repeat { context } => {
                self.repeat = self.repeats[context].outer;
                self.repeats.truncate(context);
                Flow::Fail
            }
            Frame::Forced { context, count } => {
                self.repeats[context].entered = count;
                Flow::Fail
            }
            Frame::Iteration { context, count, position, until, previous, marks, saved } => {
                let repeat = &mut self.repeats[context];
                repeat.last_position = previous;
                repeat.entered = count;
                self.reload(saved, marks.count);
                self.saved.truncate(saved);
                self.restore_marks(marks);
                self.until_tail(context, until, position)
            }
            Frame::Tail { context } => {
                self.repeat = Some(context);
                Flow::Fail
            }
            Frame::LazyTail { context, count, position, marks } => {
                self.repeat = Some(context);
                self.restore_marks(marks);
                let repeat = &mut self.repeats[context];
                let exhausted = repeat.maximum != MAXREPEAT && count >= u64::from(repeat.maximum);
                if exhausted || repeat.last_position == Some(position) {
                    return Ok(Flow::Fail);
                }
                let previous = repeat.last_position;
                repeat.entered = count + 1;
                repeat.last_position = Some(position);
                let body = repeat.body;
                self.frames.push(Frame::LazyIteration { context, count, previous });
                Flow::Run { pc: body, position }
            }
            Frame::LazyIteration { context, count, previous } => {
                let repeat = &mut self.repeats[context];
                repeat.last_position = previous;
                repeat.entered = count;
                Flow::Fail
            }
            Frame::Nested { nested, position, repeat, .. } => {
                self.nested.pop();
                self.repeat = repeat;
                match nested {
                    Nested::Assert { negated: true, next } => Flow::Run { pc: next, position },
                    Nested::Assert { negated: false, .. } => Flow::Fail,
                    Nested::Count { origin, reached, then, .. } => self.counted(then, reached - origin)?,
                }
            }
        };

        Ok(flow)
    }

    /// A nested match whose frame is at `index` reached its `SUCCESS` at
    /// `position`. Paths still open inside it are dropped.
    fn nested_succeeded(&mut self, index: usize, position: usize) -> Result<Flow, EngineError> {
        self.frames.truncate(index + 1);
        let Some(Frame::Nested { nested, position: start, repeat, repeats, saved }) = self.frames.pop() else {
            return Err(EngineError);
        };
        self.nested.pop();
        self.repeat = repeat;
        self.repeats.truncate(repeats);
        self.saved.truncate(saved);

        let flow = match nested {
            Nested::Assert { negated: false, next } => Flow::Run { pc: next, position: start },
            Nested::Assert { negated: true, .. } => Flow::Fail,
            Nested::Count { origin, reached, limit, item, then } => {
                // A round that consumed nothing would repeat forever.
                if position < limit && position > reached {
                    self.begin_nested(Nested::Count { origin, reached: position, limit, item, then }, position);
                    Flow::Run { pc: item, position }
                } else {
                    self.counted(then, position.max(reached) - origin)?
                }
            }
        };

        Ok(flow)
    }
}
