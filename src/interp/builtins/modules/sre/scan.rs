//! The repeated searches behind `findall`, `sub`, and `split`, and the
//! single steps of a scanner. Each search starts from cleared state; the
//! loops differ in how they step past an empty match.

use crate::interp::builtins::modules::sre::classify::Fold;
use crate::interp::builtins::modules::sre::engine::EngineError;
use crate::interp::builtins::modules::sre::engine::Found;
use crate::interp::builtins::modules::sre::engine::Matcher;
use crate::interp::builtins::modules::sre::engine::Unit;
use crate::interp::builtins::modules::sre::program::Program;
use crate::interp::builtins::modules::sre::subject::Units;

/// Where and how far a pattern runs over a subject.
#[derive(Clone, Copy)]
pub struct Run<'a> {
    pub program: &'a Program,
    pub fold: Fold,
    pub start: usize,
    pub end: usize,
    pub groups: usize,
}

/// Which repeated search to perform.
#[derive(Clone, Copy)]
pub enum Repeated {
    /// Every match, an empty one stepping one character on.
    FindAll,
    /// Matches to replace; `limit` caps how many, `None` for no cap. An
    /// empty match right after the previous replacement is passed over.
    Sub { limit: Option<usize> },
    /// Non-empty matches to split at; `limit` caps how many.
    Split { limit: Option<usize> },
}

/// One match, `anchored` at the start position or searched for.
pub fn single(units: Units<'_>, run: Run<'_>, anchored: bool) -> Result<Option<Found>, EngineError> {
    match units {
        Units::Narrow(text) => single_over(text, run, anchored),
        Units::Wide(text) => single_over(text, run, anchored),
    }
}

fn single_over<T: Unit>(text: &[T], run: Run<'_>, anchored: bool) -> Result<Option<Found>, EngineError> {
    let mut matcher = Matcher::new(run.program, text, run.end, run.fold);
    if anchored { matcher.match_at(run.start, run.groups) } else { matcher.search(run.start, run.groups) }
}

/// The matches a repeated search produces, in order.
pub fn repeated(units: Units<'_>, run: Run<'_>, kind: Repeated) -> Result<Vec<Found>, EngineError> {
    match units {
        Units::Narrow(text) => repeated_over(text, run, kind),
        Units::Wide(text) => repeated_over(text, run, kind),
    }
}

fn repeated_over<T: Unit>(text: &[T], run: Run<'_>, kind: Repeated) -> Result<Vec<Found>, EngineError> {
    let mut matcher = Matcher::new(run.program, text, run.end, run.fold);
    let end = matcher.end();
    let mut found = Vec::new();
    let mut start = run.start;
    // End of the latest replacement or split.
    let mut last = run.start;

    loop {
        let reached_limit = match kind {
            Repeated::FindAll => start > end,
            Repeated::Sub { limit } | Repeated::Split { limit } => limit.is_some_and(|limit| found.len() >= limit),
        };
        if reached_limit {
            break;
        }
        let Some(next) = matcher.search(start, run.groups)? else {
            break;
        };

        let span = next.whole;
        let empty = span.start == span.end;
        match kind {
            Repeated::FindAll => found.push(next),
            Repeated::Sub { .. } => {
                let adjacent = empty && span.start == last && !found.is_empty();
                if !adjacent {
                    last = span.end;
                    found.push(next);
                }
            }
            Repeated::Split { .. } => {
                if empty {
                    if last == end {
                        break;
                    }
                    start = span.end + 1;
                    continue;
                }
                last = span.end;
                found.push(next);
            }
        }

        start = if empty { span.end + 1 } else { span.end };
    }

    Ok(found)
}
