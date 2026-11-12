//! Concatenation, repetition, and indexing of `str`, `unicode`, and
//! `tuple`.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::fold::MAX_FOLDED_SIZE;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::object::StrObject;

/// An integer index or count operand. `None` when the operand is not an
/// integer or does not fit 64 bits, both of which raise.
pub(super) fn index(object: &Object) -> Option<i64> {
    match object {
        Object::Int(value) => Some(*value),
        Object::Long(value) => value.to_i64(),
        _ => None,
    }
}

/// A `unicode` operand as is, or a `str` operand decoded with the default
/// encoding.
pub(super) fn coerce_unicode(object: &Object, context: &dyn CompileContext) -> Option<Rc<[u16]>> {
    match object {
        Object::Unicode(units) => Some(Rc::clone(units)),
        Object::Str(object) if object.value.is_empty() => Some(Rc::from(Vec::new())),
        Object::Str(object) => Some(Rc::from(context.decode_default(&object.value)?)),
        _ => None,
    }
}

/// `left + right` for sequences.
pub(super) fn concat(left: &Object, right: &Object, context: &dyn CompileContext) -> Option<Object> {
    match (left, right) {
        (Object::Str(left), Object::Str(right)) => concat_str(left, right),
        (Object::Str(_) | Object::Unicode(_), Object::Str(_) | Object::Unicode(_)) => concat_unicode(left, right, context),
        (Object::Tuple(left), Object::Tuple(right)) => {
            if left.len() + right.len() > MAX_FOLDED_SIZE {
                return None;
            }

            Some(Object::Tuple(left.iter().chain(right.iter()).cloned().collect()))
        }
        _ => None,
    }
}

/// An empty operand yields the other operand itself.
fn concat_str(left: &Rc<StrObject>, right: &Rc<StrObject>) -> Option<Object> {
    if left.value.is_empty() {
        return Some(Object::Str(Rc::clone(right)));
    }

    if right.value.is_empty() {
        return Some(Object::Str(Rc::clone(left)));
    }

    if left.value.len() + right.value.len() > MAX_FOLDED_SIZE {
        return None;
    }

    Some(Object::str([left.value.as_slice(), right.value.as_slice()].concat(), false))
}

/// Decodes `str` operands with the default encoding. An empty operand
/// yields the other operand itself.
fn concat_unicode(left: &Object, right: &Object, context: &dyn CompileContext) -> Option<Object> {
    let left = coerce_unicode(left, context)?;
    let right = coerce_unicode(right, context)?;

    if right.is_empty() {
        return Some(Object::Unicode(left));
    }

    if left.is_empty() {
        return Some(Object::Unicode(right));
    }

    if left.len() + right.len() > MAX_FOLDED_SIZE {
        return None;
    }

    Some(Object::Unicode([&left[..], &right[..]].concat().into()))
}

/// `sequence * count`.
pub(super) fn repeat(sequence: &Object, count: &Object) -> Option<Object> {
    let count = index(count)?.max(0);
    let count = usize::try_from(count).ok()?;

    match sequence {
        Object::Str(object) => {
            let length = object.value.len();
            if count != 0 && length > isize::MAX as usize / count {
                return None;
            }

            if length * count == length {
                return Some(Object::Str(Rc::clone(object)));
            }

            if length * count > MAX_FOLDED_SIZE {
                return None;
            }

            // A fresh allocation, never the interned empty string.
            Some(Object::str(object.value.repeat(count), false))
        }
        Object::Unicode(units) => {
            if count == 1 {
                return Some(Object::Unicode(Rc::clone(units)));
            }

            if count != 0 && units.len() > isize::MAX as usize / count {
                return None;
            }

            if units.len() * count > MAX_FOLDED_SIZE {
                return None;
            }

            Some(Object::Unicode(units.repeat(count).into()))
        }
        Object::Tuple(items) => {
            if items.is_empty() || count == 1 {
                return Some(Object::Tuple(Rc::clone(items)));
            }

            if items.len() > isize::MAX as usize / count.max(1) {
                return None;
            }

            if items.len() * count > MAX_FOLDED_SIZE {
                return None;
            }

            Some(Object::Tuple(items.iter().cycle().take(items.len() * count).cloned().collect()))
        }
        _ => None,
    }
}

/// `sequence[item]` for a `str` or `tuple` and an integer index. `unicode`
/// is never folded: wide and narrow builds disagree.
pub(super) fn subscript(sequence: &Object, item: &Object) -> Option<Object> {
    let position = |length: usize| -> Option<usize> {
        let index = index(item)?;
        let length = i64::try_from(length).ok()?;
        let index = if index < 0 { index.checked_add(length)? } else { index };

        usize::try_from(index).ok()
    };

    match sequence {
        Object::Str(object) => {
            let byte = *object.value.get(position(object.value.len())?)?;

            // Indexing yields the shared, interned one-character string.
            Some(Object::str(vec![byte], true))
        }
        Object::Tuple(items) => items.get(position(items.len())?).cloned(),
        _ => None,
    }
}
