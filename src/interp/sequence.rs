use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::attr::MroLookup;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::is_classic_instance;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::GeneratorState;
use crate::interp::object::NativeIterator;
use crate::interp::types::IteratorKind;
use crate::interp::value::ByteArrayData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::SliceData;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Resolved `start:stop:step` over a sequence of known length.
#[derive(Clone, Copy, Debug)]
pub struct SliceIndices {
    pub start: i64,
    pub stop: i64,
    pub step: i64,
}

impl SliceIndices {
    /// Item positions, computed in 128 bits so that extreme steps and
    /// bounds cannot overflow.
    pub fn positions(self) -> impl Iterator<Item = usize> {
        let (start, stop, step) = (i128::from(self.start), i128::from(self.stop), i128::from(self.step));
        let count = if step > 0 {
            if stop > start { (stop - start + step - 1) / step } else { 0 }
        } else if start > stop {
            (start - stop - step - 1) / -step
        } else {
            0
        };

        (0..count).map(move |index| (start + index * step) as usize)
    }
}

/// The bounds of a slice as integers, before they are resolved against a
/// length. An absent bound takes a default by the direction of the step.
#[derive(Clone, Copy, Debug)]
pub struct SliceBounds {
    start: Option<i64>,
    stop: Option<i64>,
    step: i64,
}

impl SliceBounds {
    /// The bounds resolved against `length`, which `slice.indices` may pass
    /// negative. A given bound counts from the end when negative and then
    /// clamps to the sequence, or to one before it when the step is
    /// negative; absent bounds cover the whole sequence in the step's
    /// direction. The arithmetic wraps as the reference build's does.
    pub fn adjust(self, length: i64) -> SliceIndices {
        let backward = self.step < 0;
        let last = length.wrapping_sub(1);

        let resolve = |bound: Option<i64>, default: i64| {
            let Some(mut position) = bound else {
                return default;
            };

            if position < 0 {
                position = position.wrapping_add(length);
                if position < 0 {
                    position = if backward { -1 } else { 0 };
                }
            }
            if position >= length {
                position = if backward { last } else { length };
            }

            position
        };

        let start = resolve(self.start, if backward { last } else { 0 });
        let stop = resolve(self.stop, if backward { -1 } else { length });

        SliceIndices { start, stop, step: self.step }
    }
}

impl Vm {
    pub fn new_list(&self, items: Vec<Value>) -> Value {
        let class = Rc::clone(&self.types().list);

        Value::Object(self.alloc(&class, Payload::List(RefCell::new(items)), None))
    }

    pub fn new_bytearray(&self, bytes: Vec<u8>) -> Value {
        let class = Rc::clone(&self.types().bytearray);

        Value::Object(self.alloc(&class, Payload::ByteArray(RefCell::new(ByteArrayData::new(bytes))), None))
    }

    pub fn list_append(&self, list: &Value, item: Value) -> PyResult<()> {
        let Some(Payload::List(items)) = list.as_object().map(|object| &object.payload) else {
            return Err(self.type_error("LIST_APPEND target is not a list"));
        };

        items.borrow_mut().push(item);

        Ok(())
    }

    pub fn new_slice(&self, start: Value, stop: Value, step: Value) -> Value {
        let class = Rc::clone(&self.types().slice);

        Value::Object(self.alloc(&class, Payload::Slice(SliceData { start, stop, step }), None))
    }

    pub fn new_iterator(&self, iterator: NativeIterator) -> Value {
        let types = self.types();
        let is_list = |value: &Value| matches!(value.as_object().map(|object| &object.payload), Some(Payload::List(_)));
        let kind = match &iterator {
            NativeIterator::Sequence { sequence, .. } if is_list(sequence) => IteratorKind::List,
            NativeIterator::Sequence { sequence, .. } if self.as_tuple(sequence).is_some() => IteratorKind::Tuple,
            NativeIterator::Sequence { sequence, .. } if matches!(sequence.as_object().map(|object| &object.payload), Some(Payload::ByteArray(_))) => IteratorKind::ByteArray,
            NativeIterator::Reversed { sequence, .. } if is_list(sequence) => IteratorKind::ListReverse,
            NativeIterator::Reversed { .. } => return Value::Object(self.alloc(&types.reversed, Payload::Iterator(RefCell::new(iterator)), None)),
            NativeIterator::Enumerate { .. } => return Value::Object(self.alloc(&types.enumerate, Payload::Iterator(RefCell::new(iterator)), None)),
            NativeIterator::DictKeys { .. } => IteratorKind::DictKeys,
            NativeIterator::DictValues { .. } => IteratorKind::DictValues,
            NativeIterator::DictItems { .. } => IteratorKind::DictItems,
            NativeIterator::Set { .. } => IteratorKind::Set,
            NativeIterator::Range { .. } => IteratorKind::Range,
            NativeIterator::Callable { .. } => IteratorKind::Callable,
            _ => IteratorKind::Sequence,
        };
        let class = Rc::clone(types.iterator_type(kind));

        Value::Object(self.alloc(&class, Payload::Iterator(RefCell::new(iterator)), None))
    }

    /// `__length_hint__` of a native iterator; `None` for an iterator type
    /// without one.
    pub fn native_length_hint(&self, iterator: &ObjectRef) -> PyResult<Option<Value>> {
        let Payload::Iterator(state) = &iterator.payload else {
            return Ok(None);
        };
        let class = iterator.class();
        let is_kind = |kind: IteratorKind| Rc::ptr_eq(&class, self.types().iterator_type(kind));

        // The state is copied out first: `__len__` may run Python code.
        let source = match &*state.borrow() {
            NativeIterator::Exhausted => HintSource::Remaining(0),
            NativeIterator::Sequence { sequence, index } => HintSource::Sized { sequence: sequence.clone(), consumed: *index as i64 },
            NativeIterator::GetItem { target, index } => HintSource::Sized { sequence: target.clone(), consumed: *index },
            NativeIterator::Reversed { sequence, index } => HintSource::Reversed { sequence: sequence.clone(), position: index.map_or(0, |index| index as i64 + 1) },
            NativeIterator::DictKeys { dict, length, remaining, .. } | NativeIterator::DictValues { dict, length, remaining, .. } | NativeIterator::DictItems { dict, length, remaining, .. } => HintSource::Dict { dict: Rc::clone(dict), length: *length, remaining: *remaining },
            NativeIterator::Set { set, length, remaining, .. } => HintSource::Set { set: Rc::clone(set), length: *length, remaining: *remaining },
            NativeIterator::Range { remaining, .. } => HintSource::Remaining(*remaining),
            _ => return Ok(None),
        };

        let hint = match source {
            HintSource::Remaining(remaining) => remaining,
            HintSource::Sized { sequence, consumed } => {
                let Some(length) = self.storage_length(&sequence).map_or_else(|| self.len(&sequence), |length| Ok(Some(length)))? else {
                    return Ok(Some(Value::unknown("__length_hint__")));
                };
                let remaining = length as i64 - consumed;
                // A bytearray iterator does not clamp a shrunk array.
                if is_kind(IteratorKind::ByteArray) { remaining } else { remaining.max(0) }
            }
            HintSource::Reversed { sequence, position } => {
                let length = if is_kind(IteratorKind::ListReverse) { self.storage_length(&sequence) } else { self.len(&sequence)? };
                let Some(length) = length else {
                    return Ok(Some(Value::unknown("__length_hint__")));
                };
                if (length as i64) < position { 0 } else { position }
            }
            HintSource::Dict { dict, length, remaining } => {
                if self.dict_len(&dict)? == length { remaining as i64 } else { 0 }
            }
            HintSource::Set { set, length, remaining } => {
                if self.set_len(&set) == length { remaining as i64 } else { 0 }
            }
        };

        // A reversed list iterator's hint is a long.
        if is_kind(IteratorKind::ListReverse) {
            return Ok(Some(Value::long(BigInt::from(hint))));
        }

        Ok(Some(Value::Int(hint)))
    }

    /// Whether `value` can serve as an index: int, long, and bool, an
    /// instance of a class defining `__index__`, and every classic
    /// instance. Only the method's presence counts; nothing is bound.
    pub fn is_index(&self, value: &Value) -> PyResult<bool> {
        if self.as_integral(value).is_some() || is_classic_instance(self, value) {
            return Ok(true);
        }
        let Value::Object(object) = value else {
            return Ok(false);
        };

        Ok(match self.lookup_mro(&object.class(), "__index__")? {
            MroLookup::Found { owner, .. } => !self.is_builtin_type(&owner),
            MroLookup::Unknown(_) => true,
            MroLookup::Missing => false,
        })
    }

    /// `value` as an index: the int or long itself, or what `__index__`
    /// returned.
    pub fn number_index(&self, value: &Value) -> PyResult<Value> {
        halt_on_unknown(value, "__index__")?;
        if self.as_integral(value).is_some() {
            return Ok(value.clone());
        }

        let Some(method) = self.user_override(value, "__index__")? else {
            // A classic instance reports without its type name.
            if is_classic_instance(self, value) {
                return Err(self.type_error("object cannot be interpreted as an index"));
            }
            return Err(self.type_error(&format!("'{}' object cannot be interpreted as an index", self.type_name(value))));
        };
        let result = self.call0(&method)?;
        halt_on_unknown(&result, "__index__ result")?;
        if self.as_integral(&result).is_none() {
            return Err(self.type_error(&format!("__index__ returned non-(int,long) (type {})", self.type_name(&result))));
        }

        Ok(result)
    }

    /// `value` as a 64-bit index. With no overflow error, values beyond the
    /// range clamp to it.
    pub fn index_as_ssize(&self, value: &Value, overflow: Option<ExceptionKind>) -> PyResult<i64> {
        let index = self.number_index(value)?;
        let Some(integral) = self.as_integral(&index) else {
            return Err(self.type_error(&format!("__index__ returned non-(int,long) (type {})", self.type_name(&index))));
        };
        if let Some(number) = integral.to_i64() {
            return Ok(number);
        }

        match overflow {
            None => Ok(integral.saturating_i64()),
            Some(kind) => Err(self.raise(kind, &format!("cannot fit '{}' into an index-sized integer", self.type_name(value)))),
        }
    }

    /// A slice bound as an integer; longs beyond the 64-bit range clamp to
    /// it.
    fn slice_bound(&self, value: &Value) -> PyResult<Option<i64>> {
        if value.is_none() {
            return Ok(None);
        }
        halt_on_unknown(value, "slice index")?;
        if !self.is_index(value)? {
            return Err(self.type_error("slice indices must be integers or None or have an __index__ method"));
        }

        self.index_as_ssize(value, None).map(Some)
    }

    /// The positions `slice` selects in a sequence of `length` items.
    pub fn slice_indices(&self, slice: &SliceData, length: usize) -> PyResult<SliceIndices> {
        self.slice_indices_signed(slice, length as i64)
    }

    /// The bounds of `slice` resolved against `length`, which may be
    /// negative, as `slice.indices` passes it through.
    pub(crate) fn slice_indices_signed(&self, slice: &SliceData, length: i64) -> PyResult<SliceIndices> {
        Ok(self.unpack_slice(slice)?.adjust(length))
    }

    /// The bounds of `slice` as integers: the step first, which must not be
    /// zero, then the start and the stop. Converting them may run Python
    /// code.
    pub(crate) fn unpack_slice(&self, slice: &SliceData) -> PyResult<SliceBounds> {
        let step = self.slice_bound(&slice.step)?.unwrap_or(1);
        if step == 0 {
            return Err(self.raise(ExceptionKind::ValueError, "slice step cannot be zero"));
        }

        let start = self.slice_bound(&slice.start)?;
        let stop = self.slice_bound(&slice.stop)?;

        Ok(SliceBounds { start, stop, step })
    }

    /// The position `index` names in a sequence of `length` items, as the
    /// subscripts and subscript assignments of `str`, `unicode`, `tuple`,
    /// and `list` compute it. `kind` names the sequence in the errors.
    pub(crate) fn normalize_index(&self, index: &Value, length: usize, kind: &str) -> PyResult<usize> {
        halt_on_unknown(index, &format!("{kind} index"))?;
        if !self.is_index(index)? {
            let type_kind = kind.strip_suffix(" assignment").unwrap_or(kind);
            return Err(self.type_error(&format!("{type_kind} indices must be integers, not {}", self.type_name(index))));
        }
        let position = self.index_as_ssize(index, Some(ExceptionKind::IndexError))?;

        self.adjust_index(position, length, kind)
    }

    /// A position counted from the end when negative, which must name one
    /// of `length` items.
    fn adjust_index(&self, position: i64, length: usize, kind: &str) -> PyResult<usize> {
        let length = length as i64;
        let adjusted = if position < 0 { position + length } else { position };
        if adjusted < 0 || adjusted >= length {
            return Err(self.raise(ExceptionKind::IndexError, &format!("{kind} index out of range")));
        }

        Ok(adjusted as usize)
    }

    pub(crate) fn slice_of(&self, index: &Value) -> Option<SliceData> {
        match index.as_object().map(|object| &object.payload) {
            Some(Payload::Slice(slice)) => Some(SliceData { start: slice.start.clone(), stop: slice.stop.clone(), step: slice.step.clone() }),
            _ => None,
        }
    }

    /// `container[index]`.
    pub fn getitem(&self, container: &Value, index: &Value) -> PyResult<Value> {
        if container.is_unknown() {
            return Ok(container.clone());
        }

        if let Some(method) = self.user_override(container, "__getitem__")? {
            return self.call1(&method, index.clone());
        }

        let slice = self.slice_of(index);

        if let Some(bytes) = self.as_str_bytes(container) {
            if let Some(slice) = slice {
                return self.str_slice(&bytes, matches!(container, Value::Str(_)), &slice);
            }
            let position = self.normalize_index(index, bytes.as_bytes().len(), "string")?;
            return Ok(Value::Str(PyBytes::new([bytes.as_bytes()[position]])));
        }

        if let Some(text) = self.as_text(container) {
            if let Some(slice) = slice {
                return self.unicode_slice(&text, matches!(container, Value::Unicode(_)), &slice);
            }
            let units = text.units();
            // Unlike `str`, `unicode` does not name the index type.
            if !index.is_unknown() && !self.is_index(index)? {
                return Err(self.type_error("string indices must be integers"));
            }
            let position = self.normalize_index(index, units.len(), "string")?;
            return Ok(Value::Unicode(PyText::new(vec![units[position]])));
        }

        if let Some(items) = self.as_tuple(container) {
            if let Some(slice) = slice {
                let indices = self.slice_indices(&slice, items.len())?;
                return Ok(Value::tuple(indices.positions().map(|position| items[position].clone()).collect()));
            }
            let position = self.normalize_index(index, items.len(), "tuple")?;
            return Ok(items[position].clone());
        }

        let Value::Object(object) = container else {
            return Err(self.type_error(&format!("'{}' object has no attribute '__getitem__'", self.type_name(container))));
        };

        match &object.payload {
            Payload::List(items) => {
                if let Some(slice) = slice {
                    let length = items.borrow().len();
                    let indices = self.slice_indices(&slice, length)?;
                    let items = items.borrow();
                    let selected = indices.positions().filter_map(|position| items.get(position).cloned()).collect();
                    drop(items);
                    return Ok(self.new_list(selected));
                }
                let items = items.borrow();
                let position = self.normalize_index(index, items.len(), "list")?;
                Ok(items[position].clone())
            }
            Payload::Dict(_) => {
                if let Some(value) = self.dict_get(object, index)? {
                    return Ok(value);
                }
                if let Some(missing) = self.user_override(container, "__missing__")? {
                    return self.call1(&missing, index.clone());
                }
                if let Some(result) = crate::interp::builtins::collections::defaultdict_missing(self, object, index)? {
                    return Ok(result);
                }
                Err(self.key_error(index.clone()))
            }
            Payload::DictProxy(dict) => match self.dict_get(dict, index)? {
                Some(value) => Ok(value),
                None => Err(self.key_error(index.clone())),
            },
            Payload::XRange(range) => {
                halt_on_unknown(index, "xrange index")?;
                // `xrange` subscripts only through its item slot.
                if !self.is_index(index)? {
                    return Err(self.type_error(&format!("sequence index must be integer, not '{}'", self.type_name(index))));
                }
                let position = self.index_as_ssize(index, Some(ExceptionKind::IndexError))?;
                let position = self.adjust_index(position, range.length as usize, "xrange object")?;
                // The item is in the 64-bit range, so wrapping arithmetic is
                // exact.
                Ok(self.new_int_from_i64(range.start.wrapping_add((position as i64).wrapping_mul(range.step))))
            }
            Payload::Native(_) => match crate::interp::builtins::native_getitem(self, object, index)? {
                Some(value) => Ok(value),
                None => Err(self.no_getitem(container, index)?),
            },
            _ => Err(self.no_getitem(container, index)?),
        }
    }

    /// The error for subscripting a value that supports no item access.
    /// A type with sequence slots but no item slot reports an integer
    /// index as unsupported indexing; classes defined in Python have
    /// sequence slots.
    fn no_getitem(&self, container: &Value, index: &Value) -> PyResult<Signal> {
        if crate::interp::builtins::arguments::is_classic_instance(self, container) {
            let class = self.class_of(container);
            return Ok(self.raise(ExceptionKind::AttributeError, &format!("{} instance has no attribute '__getitem__'", self.class_name(&class))));
        }

        let class = self.type_of(container);
        let types = self.types();
        let sequence_slots = class.as_class().is_some_and(|data| !data.builtin) || [&types.set, &types.frozenset, &types.dict_keys, &types.dict_items, &types.dict_values].iter().any(|candidate| Rc::ptr_eq(candidate, &class));
        if sequence_slots && self.is_index(index)? {
            return Ok(self.type_error(&format!("'{}' object does not support indexing", self.type_name(container))));
        }

        Ok(self.type_error(&format!("'{}' object has no attribute '__getitem__'", self.type_name(container))))
    }

    pub fn key_error(&self, key: Value) -> Signal {
        let class = Rc::clone(self.types().exception(ExceptionKind::KeyError));
        match self.instantiate_exception(&class, vec![key]) {
            Ok(exception) => Signal::Raise(exception),
            Err(signal) => signal,
        }
    }

    /// `container[index] = value`.
    pub fn setitem(&self, container: &Value, index: &Value, value: Value) -> PyResult<()> {
        if container.is_unknown() {
            return Ok(());
        }

        if let Some(method) = self.user_override(container, "__setitem__")? {
            self.call(&method, CallArgs::new(vec![index.clone(), value]))?;
            return Ok(());
        }

        let Value::Object(object) = container else {
            return Err(self.type_error(&format!("'{}' object does not support item assignment", self.type_name(container))));
        };

        match &object.payload {
            Payload::List(items) => {
                if let Some(slice) = self.slice_of(index) {
                    return self.list_assign_slice(object, &slice, Some(value));
                }
                let length = items.borrow().len();
                let position = self.normalize_index(index, length, "list assignment")?;
                items.borrow_mut()[position] = value;
                Ok(())
            }
            Payload::Dict(_) => self.dict_set(object, index.clone(), value),
            Payload::Native(_) => {
                if crate::interp::builtins::native_setitem(self, object, index, Some(value))? {
                    return Ok(());
                }
                Err(self.type_error(&format!("'{}' object does not support item assignment", self.type_name(container))))
            }
            _ => Err(self.type_error(&format!("'{}' object does not support item assignment", self.type_name(container)))),
        }
    }

    pub fn delitem(&self, container: &Value, index: &Value) -> PyResult<()> {
        if container.is_unknown() {
            return Ok(());
        }

        if let Some(method) = self.user_override(container, "__delitem__")? {
            self.call1(&method, index.clone())?;
            return Ok(());
        }

        let Value::Object(object) = container else {
            return Err(self.type_error(&format!("'{}' object does not support item deletion", self.type_name(container))));
        };

        match &object.payload {
            Payload::List(items) => {
                if let Some(slice) = self.slice_of(index) {
                    return self.list_assign_slice(object, &slice, None);
                }
                let length = items.borrow().len();
                let position = self.normalize_index(index, length, "list assignment")?;
                items.borrow_mut().remove(position);
                Ok(())
            }
            Payload::Dict(_) => {
                if !self.dict_delete(object, index)? {
                    return Err(self.key_error(index.clone()));
                }
                Ok(())
            }
            Payload::Native(_) => {
                if crate::interp::builtins::native_setitem(self, object, index, None)? {
                    return Ok(());
                }
                Err(self.type_error(&format!("'{}' object does not support item deletion", self.type_name(container))))
            }
            _ => Err(self.type_error(&format!("'{}' object does not support item deletion", self.type_name(container)))),
        }
    }

    pub(crate) fn list_assign_slice(&self, list: &ObjectRef, slice: &SliceData, value: Option<Value>) -> PyResult<()> {
        let Payload::List(items) = &list.payload else {
            return Err(self.type_error("expected a list"));
        };

        let replacement = match &value {
            Some(value) => Some(self.collect(value)?),
            None => None,
        };

        let length = items.borrow().len();
        let indices = self.slice_indices(slice, length)?;

        if indices.step == 1 {
            let start = indices.start.clamp(0, length as i64) as usize;
            let stop = (indices.stop.max(indices.start)).clamp(0, length as i64) as usize;
            items.borrow_mut().splice(start..stop, replacement.unwrap_or_default());
            return Ok(());
        }

        let positions: Vec<usize> = indices.positions().collect();
        match replacement {
            Some(replacement) => {
                if replacement.len() != positions.len() {
                    return Err(self.raise(ExceptionKind::ValueError, &format!("attempt to assign sequence of size {} to extended slice of size {}", replacement.len(), positions.len())));
                }
                let mut items = items.borrow_mut();
                for (position, item) in positions.into_iter().zip(replacement) {
                    items[position] = item;
                }
            }
            None => {
                let mut sorted = positions;
                sorted.sort_unstable();
                let mut items = items.borrow_mut();
                for position in sorted.into_iter().rev() {
                    items.remove(position);
                }
            }
        }

        Ok(())
    }

    /// `container[start:stop]` in its two-bound form. Types with a
    /// sequence slice slot (`__getslice__`, or a list, tuple, or string
    /// layout) take integer bounds without consulting `__getitem__`.
    pub fn get_slice(&self, container: &Value, start: &Value, stop: &Value) -> PyResult<Value> {
        if container.is_unknown() {
            return Ok(container.clone());
        }

        if self.is_slice_index(start)? && self.is_slice_index(stop)? {
            if let Some(method) = self.user_override(container, "__getslice__")? {
                let (low, high) = self.legacy_slice_bounds(container, start, stop)?;
                return self.call(&method, CallArgs::new(vec![self.new_int_from_i64(low), self.new_int_from_i64(high)]));
            }
            match container.as_object().map(|object| &object.payload) {
                Some(Payload::Str(bytes)) => return self.str_slice(bytes, false, &SliceData { start: start.clone(), stop: stop.clone(), step: Value::None }),
                Some(Payload::Unicode(text)) => return self.unicode_slice(text, false, &SliceData { start: start.clone(), stop: stop.clone(), step: Value::None }),
                _ => {}
            }
            if let Some(plain) = self.plain_sequence(container) {
                return self.getitem(&plain, &self.new_slice(start.clone(), stop.clone(), Value::None));
            }
            if let Some(Payload::List(items)) = container.as_object().map(|object| &object.payload) {
                let items = items.borrow().clone();
                let indices = self.slice_indices(&SliceData { start: start.clone(), stop: stop.clone(), step: Value::None }, items.len())?;
                return Ok(self.new_list(indices.positions().map(|position| items[position].clone()).collect()));
            }
        }

        let slice = self.new_slice(start.clone(), stop.clone(), Value::None);

        self.getitem(container, &slice)
    }

    /// A slice of a `str`: an exact `str` sliced whole is returned itself.
    fn str_slice(&self, bytes: &PyBytes, exact: bool, slice: &SliceData) -> PyResult<Value> {
        let data = bytes.as_bytes();
        let indices = self.slice_indices(slice, data.len())?;
        let from_start = indices.start == 0 && indices.step == 1;
        let sliced: Vec<u8> = indices.positions().map(|position| data[position]).collect();
        if exact && from_start && sliced.len() == data.len() {
            return Ok(Value::Str(bytes.clone()));
        }

        Ok(Value::Str(PyBytes::new(sliced)))
    }

    /// A slice of a `unicode`: an exact `unicode` sliced whole is returned
    /// itself.
    fn unicode_slice(&self, text: &PyText, exact: bool, slice: &SliceData) -> PyResult<Value> {
        let units = text.units();
        let indices = self.slice_indices(slice, units.len())?;
        let from_start = indices.start == 0 && indices.step == 1;
        let sliced: Vec<u16> = indices.positions().map(|position| units[position]).collect();
        if exact && from_start && sliced.len() == units.len() {
            return Ok(Value::Unicode(text.clone()));
        }

        Ok(Value::Unicode(PyText::new(sliced)))
    }

    /// `ISINDEX`: a bound the sequence slice slots accept.
    fn is_slice_index(&self, bound: &Value) -> PyResult<bool> {
        Ok(bound.is_none() || self.is_index(bound)?)
    }

    /// The tuple, str, or unicode storage of a subclass instance as a plain
    /// value, whose slicing ignores the subclass's `__getitem__`.
    fn plain_sequence(&self, container: &Value) -> Option<Value> {
        match container.as_object().map(|object| &object.payload)? {
            Payload::Tuple(items) => Some(Value::Tuple(items.clone())),
            Payload::Str(bytes) => Some(Value::Str(bytes.clone())),
            Payload::Unicode(text) => Some(Value::Unicode(text.clone())),
            _ => None,
        }
    }

    /// Both bounds of a two-bound slice as integers; negative ones count
    /// from the end once.
    fn legacy_slice_bounds(&self, container: &Value, start: &Value, stop: &Value) -> PyResult<(i64, i64)> {
        let mut low = self.slice_bound(start)?.unwrap_or(0);
        let mut high = self.slice_bound(stop)?.unwrap_or(i64::MAX);

        if low < 0 || high < 0 {
            let Some(length) = self.len(container)? else {
                return Err(Signal::Halt(Halt::UnknownCondition { context: "slice of a sequence with unknown length".to_owned(), origin: format!("{container:?}") }));
            };
            if low < 0 {
                low += length as i64;
            }
            if high < 0 {
                high += length as i64;
            }
        }

        Ok((low, high))
    }

    /// `container[start:stop] = value` and `del container[start:stop]` in
    /// their two-bound form.
    pub fn set_slice(&self, container: &Value, start: &Value, stop: &Value, value: Option<Value>) -> PyResult<()> {
        if container.is_unknown() {
            return Ok(());
        }

        if self.is_slice_index(start)? && self.is_slice_index(stop)? {
            let hook = if value.is_some() { "__setslice__" } else { "__delslice__" };
            if let Some(method) = self.user_override(container, hook)? {
                let (low, high) = self.legacy_slice_bounds(container, start, stop)?;
                let mut arguments = vec![self.new_int_from_i64(low), self.new_int_from_i64(high)];
                arguments.extend(value);
                self.call(&method, CallArgs::new(arguments))?;
                return Ok(());
            }
            if let Some(list) = container.as_object().filter(|object| matches!(object.payload, Payload::List(_))) {
                return self.list_assign_slice(list, &SliceData { start: start.clone(), stop: stop.clone(), step: Value::None }, value);
            }
        }

        let slice = self.new_slice(start.clone(), stop.clone(), Value::None);

        match value {
            Some(value) => self.setitem(container, &slice, value),
            None => self.delitem(container, &slice),
        }
    }

    /// `item in container`; unknown when either side is unknown.
    pub fn contains(&self, container: &Value, item: &Value) -> PyResult<Value> {
        if container.is_unknown() {
            return Ok(container.clone());
        }

        if let Some(method) = self.user_override(container, "__contains__")? {
            let result = self.call1(&method, item.clone())?;
            if result.is_unknown() {
                return Ok(result);
            }
            return Ok(Value::Bool(self.truthy(&result, "__contains__")?));
        }

        if let Some(haystack) = self.as_str_bytes(container) {
            if let Some(needle) = self.as_str_bytes(item) {
                return Ok(Value::Bool(contains_subslice(haystack.as_bytes(), needle.as_bytes())));
            }
            if let Some(needle) = self.as_text(item) {
                let Some(haystack) = self.coerce_text(container)? else {
                    return Ok(Value::Bool(false));
                };
                return Ok(Value::Bool(contains_subslice(haystack.units(), needle.units())));
            }
            if item.is_unknown() {
                return Ok(item.clone());
            }
            return Err(self.type_error(&format!("'in <string>' requires string as left operand, not {}", self.type_name(item))));
        }

        if let Some(haystack) = self.as_text(container) {
            let Some(needle) = self.coerce_text(item)? else {
                if item.is_unknown() {
                    return Ok(item.clone());
                }
                return Err(self.type_error("'in <string>' requires string as left operand"));
            };
            return Ok(Value::Bool(contains_subslice(haystack.units(), needle.units())));
        }

        if item.is_unknown() {
            return Ok(item.clone());
        }

        if let Value::Object(object) = container {
            match &object.payload {
                Payload::Dict(_) => return Ok(Value::Bool(self.dict_get(object, item)?.is_some())),
                Payload::DictProxy(dict) => return Ok(Value::Bool(self.dict_get(dict, item)?.is_some())),
                Payload::Set(table) => {
                    let snapshot = table.borrow().clone();
                    return Ok(Value::Bool(self.set_contains(&snapshot, item)?));
                }
                Payload::FrozenSet(table) => return Ok(Value::Bool(self.set_contains(table, item)?)),
                Payload::Native(_) => {
                    if let Some(result) = crate::interp::builtins::native_contains(self, object, item)? {
                        return Ok(Value::Bool(result));
                    }
                }
                _ => {}
            }
        }

        let iterator = self.iter(container)?;
        while let Some(candidate) = self.next(&iterator)? {
            if self.is_same(&candidate, item) || self.equals(&candidate, item)? {
                return Ok(Value::Bool(true));
            }
        }

        Ok(Value::Bool(false))
    }

    /// `len(value)`; `None` for unknown values.
    pub fn len(&self, value: &Value) -> PyResult<Option<usize>> {
        if value.is_unknown() {
            return Ok(None);
        }

        if let Some(method) = self.user_override(value, "__len__")? {
            let result = self.call0(&method)?;
            if result.is_unknown() {
                return Ok(None);
            }
            let Some(length) = self.as_index(&result) else {
                return Err(self.type_error("an integer is required"));
            };
            if length < 0 {
                return Err(self.raise(ExceptionKind::ValueError, "__len__() should return >= 0"));
            }
            return Ok(Some(length as usize));
        }

        if let Some(bytes) = self.as_str_bytes(value) {
            return Ok(Some(bytes.as_bytes().len()));
        }
        if let Some(text) = self.as_text(value) {
            return Ok(Some(text.units().len()));
        }
        if let Some(items) = self.as_tuple(value) {
            return Ok(Some(items.len()));
        }

        let Value::Object(object) = value else {
            return Err(self.type_error(&format!("object of type '{}' has no len()", self.type_name(value))));
        };

        // A classic instance looks `__len__` up as an attribute, which
        // raises the instance's AttributeError when it is missing.
        if Rc::ptr_eq(&self.type_of(value), &self.types().instance) {
            self.getattr_str(value, "__len__")?;
        }

        let length = match &object.payload {
            Payload::List(items) => items.borrow().len(),
            Payload::Dict(table) => table.borrow().len(),
            Payload::Set(table) => table.borrow().len(),
            Payload::FrozenSet(table) => table.len(),
            Payload::DictProxy(dict) => self.dict_len(dict)?,
            Payload::XRange(range) => range.length as usize,
            Payload::Native(_) => match self.native_len(value)? {
                Some(length) => length,
                None => return Err(self.type_error(&format!("object of type '{}' has no len()", self.type_name(value)))),
            },
            _ => return Err(self.type_error(&format!("object of type '{}' has no len()", self.type_name(value)))),
        };

        Ok(Some(length))
    }

    pub fn native_len(&self, value: &Value) -> PyResult<Option<usize>> {
        let Value::Object(object) = value else {
            return Ok(None);
        };

        crate::interp::builtins::native_len(self, object)
    }

    /// `iter(value)`.
    pub fn iter(&self, value: &Value) -> PyResult<Value> {
        if let Value::Unknown(unknown) = value {
            return Err(Signal::Halt(Halt::UnknownIteration { origin: unknown.origin.clone() }));
        }

        if let Some(method) = self.user_override(value, "__iter__")? {
            let iterator = self.call0(&method)?;
            let is_iterator = match &iterator {
                Value::Unknown(_) => true,
                Value::Object(object) => matches!(object.payload, Payload::Iterator(_) | Payload::Generator(_)) || self.has_special(&iterator, "next")?,
                _ => false,
            };
            if !is_iterator {
                return Err(self.type_error(&format!("iter() returned non-iterator of type '{}'", self.type_name(&iterator))));
            }
            return Ok(iterator);
        }

        if self.as_str_bytes(value).is_some() || self.as_text(value).is_some() || self.as_tuple(value).is_some() {
            return Ok(self.new_iterator(NativeIterator::Sequence { sequence: value.clone(), index: 0 }));
        }

        let Value::Object(object) = value else {
            return Err(self.type_error(&format!("'{}' object is not iterable", self.type_name(value))));
        };

        let iterator = match &object.payload {
            Payload::List(_) => NativeIterator::Sequence { sequence: value.clone(), index: 0 },
            Payload::Dict(table) => {
                let length = table.borrow().len();
                NativeIterator::DictKeys { dict: Rc::clone(object), position: 0, length, remaining: length }
            }
            Payload::DictProxy(dict) => {
                let length = self.dict_len(dict)?;
                NativeIterator::DictKeys { dict: Rc::clone(dict), position: 0, length, remaining: length }
            }
            Payload::Set(_) | Payload::FrozenSet(_) => {
                let length = self.set_len(object);
                NativeIterator::Set { set: Rc::clone(object), position: 0, length, remaining: length }
            }
            Payload::XRange(range) => NativeIterator::Range { next: range.start, remaining: range.length, step: range.step },
            Payload::Iterator(_) | Payload::Generator(_) => return Ok(value.clone()),
            Payload::Native(_) => match crate::interp::builtins::native_iter(self, object)? {
                Some(iterator) => return Ok(iterator),
                // An extension type with only `__getitem__` iterates by index.
                None if self.user_override(value, "__getitem__")?.is_some() => NativeIterator::GetItem { target: value.clone(), index: 0 },
                None => return Err(self.type_error(&format!("'{}' object is not iterable", self.type_name(value)))),
            },
            _ => {
                if self.user_override(value, "__getitem__")?.is_some() {
                    NativeIterator::GetItem { target: value.clone(), index: 0 }
                } else {
                    return Err(self.type_error(&format!("'{}' object is not iterable", self.type_name(value))));
                }
            }
        };

        Ok(self.new_iterator(iterator))
    }

    /// Advances an iterator; `None` when exhausted (`StopIteration`).
    pub fn next(&self, iterator: &Value) -> PyResult<Option<Value>> {
        let Value::Object(object) = iterator else {
            if let Value::Unknown(unknown) = iterator {
                return Err(Signal::Halt(Halt::UnknownIteration { origin: unknown.origin.clone() }));
            }
            return Err(self.type_error(&format!("'{}' object is not an iterator", self.type_name(iterator))));
        };

        match &object.payload {
            Payload::Iterator(state) => self.advance_native(state),
            Payload::Generator(_) => self.generator_send(object, Value::None),
            _ => {
                let Some(method) = self.lookup_special(iterator, "next")? else {
                    return Err(self.type_error(&format!("'{}' object is not an iterator", self.type_name(iterator))));
                };
                match self.call0(&method) {
                    Ok(value) => Ok(Some(value)),
                    Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::StopIteration) => Ok(None),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn advance_native(&self, state: &RefCell<NativeIterator>) -> PyResult<Option<Value>> {
        let mut current = std::mem::replace(&mut *state.borrow_mut(), NativeIterator::Exhausted);
        let result = self.advance_state(&mut current);
        *state.borrow_mut() = current;

        result
    }

    fn advance_state(&self, state: &mut NativeIterator) -> PyResult<Option<Value>> {
        let changed = |vm: &Vm, kind: &str| vm.raise(ExceptionKind::RuntimeError, &format!("{kind} changed size during iteration"));

        let item = match state {
            NativeIterator::Exhausted => None,
            NativeIterator::Sequence { sequence, index } => {
                let item = self.sequence_item(sequence, *index);
                *index += 1;
                item
            }
            NativeIterator::GetItem { target, index } => {
                match self.getitem(target, &Value::Int(*index)) {
                    Ok(value) => {
                        *index += 1;
                        Some(value)
                    }
                    Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::IndexError) || self.is_exception(&error, ExceptionKind::StopIteration) => None,
                    Err(error) => return Err(error),
                }
            }
            NativeIterator::DictKeys { dict, position, length, remaining } | NativeIterator::DictValues { dict, position, length, remaining } | NativeIterator::DictItems { dict, position, length, remaining } => {
                if self.dict_len(dict)? != *length {
                    *length = usize::MAX;
                    return Err(changed(self, "dictionary"));
                }
                match self.dict_next_entry(dict, *position)? {
                    None => None,
                    Some((slot, key, value)) => {
                        *position = slot + 1;
                        *remaining = remaining.saturating_sub(1);
                        Some((key, value))
                    }
                }
                .map(|(key, value)| (key, value))
                .map(|pair| pair)
                .map(|(key, value)| match state {
                    NativeIterator::DictKeys { .. } => key,
                    NativeIterator::DictValues { .. } => value,
                    _ => Value::tuple(vec![key, value]),
                })
            }
            NativeIterator::Set { set, position, length, remaining } => {
                if self.set_len(set) != *length {
                    *length = usize::MAX;
                    return Err(changed(self, "Set"));
                }
                match self.set_next_entry(set, *position) {
                    None => None,
                    Some((slot, key)) => {
                        *position = slot + 1;
                        *remaining = remaining.saturating_sub(1);
                        Some(key)
                    }
                }
            }
            NativeIterator::Range { next, remaining, step } => {
                if *remaining <= 0 {
                    None
                } else {
                    let value = *next;
                    *remaining -= 1;
                    // Advance only toward an item that exists. Its value is
                    // in the 64-bit range, so wrapping arithmetic is exact
                    // even for a step whose magnitude does not fit.
                    if *remaining > 0 {
                        *next = next.wrapping_add(*step);
                    }
                    Some(self.new_int_from_i64(value))
                }
            }
            NativeIterator::Reversed { sequence, index } => match index {
                None => None,
                Some(position) => {
                    let item = self.getitem(sequence, &Value::Int(*position as i64))?;
                    *index = position.checked_sub(1);
                    Some(item)
                }
            },
            NativeIterator::Enumerate { iterator, count } => match self.next(iterator)? {
                None => None,
                Some(item) => {
                    let index = count.clone();
                    *count = self.binary_op(crate::interp::ops::BinaryOp::Add, count, &Value::Int(1))?;
                    Some(Value::tuple(vec![index, item]))
                }
            },
            NativeIterator::Zip { iterators } => {
                let mut items = Vec::with_capacity(iterators.len());
                let mut done = iterators.is_empty();
                for iterator in iterators.iter() {
                    match self.next(iterator)? {
                        Some(item) => items.push(item),
                        None => {
                            done = true;
                            break;
                        }
                    }
                }
                if done { None } else { Some(Value::tuple(items)) }
            }
            NativeIterator::Map { function, iterators } => {
                let mut items = Vec::with_capacity(iterators.len());
                for iterator in iterators.iter() {
                    match self.next(iterator)? {
                        Some(item) => items.push(item),
                        None => {
                            *state = NativeIterator::Exhausted;
                            return Ok(None);
                        }
                    }
                }
                if function.is_none() {
                    Some(if items.len() == 1 { items.remove(0) } else { Value::tuple(items) })
                } else {
                    Some(self.call(function, CallArgs::new(items))?)
                }
            }
            NativeIterator::Filter { function, iterator, invert } => loop {
                let Some(item) = self.next(iterator)? else {
                    break None;
                };
                let keep = if function.is_none() { self.truthy(&item, "filter")? } else { self.truthy(&self.call1(function, item.clone())?, "filter")? };
                if keep != *invert {
                    break Some(item);
                }
            },
            NativeIterator::Callable { function, sentinel } => {
                let value = self.call0(function)?;
                if self.equals(&value, sentinel)? { None } else { Some(value) }
            }
            NativeIterator::Chain { iterables, current, index } => loop {
                if let Some(iterator) = current {
                    if let Some(item) = self.next(iterator)? {
                        break Some(item);
                    }
                }
                let Some(next_iterable) = iterables.get(*index) else {
                    break None;
                };
                *index += 1;
                *current = Some(self.iter(next_iterable)?);
            },
            NativeIterator::Count { next, step } => {
                let value = next.clone();
                *next = self.binary_op(crate::interp::ops::BinaryOp::Add, next, step)?;
                Some(value)
            }
            NativeIterator::Repeat { value, remaining } => match remaining {
                Some(0) => None,
                Some(count) => {
                    *count -= 1;
                    Some(value.clone())
                }
                None => Some(value.clone()),
            },
        };

        if item.is_none() {
            *state = NativeIterator::Exhausted;
        }

        Ok(item)
    }

    fn sequence_item(&self, sequence: &Value, index: usize) -> Option<Value> {
        if let Some(bytes) = self.as_str_bytes(sequence) {
            return bytes.as_bytes().get(index).map(|byte| Value::Str(PyBytes::new(vec![*byte])));
        }
        if let Some(text) = self.as_text(sequence) {
            return text.units().get(index).map(|unit| Value::Unicode(PyText::new(vec![*unit])));
        }
        if let Some(items) = self.as_tuple(sequence) {
            return items.get(index).cloned();
        }

        match sequence.as_object().map(|object| &object.payload) {
            Some(Payload::List(items)) => items.borrow().get(index).cloned(),
            Some(Payload::ByteArray(data)) => data.borrow().bytes.get(index).map(|byte| Value::Int(i64::from(*byte))),
            _ => None,
        }
    }

    /// Drains an iterable into a vector.
    pub fn collect(&self, iterable: &Value) -> PyResult<Vec<Value>> {
        if let Some(items) = self.as_tuple(iterable) {
            if !matches!(iterable, Value::Object(_)) || self.user_override(iterable, "__iter__")?.is_none() {
                return Ok(items.to_vec());
            }
        }

        let iterator = self.iter(iterable)?;
        let mut items = Vec::new();

        while let Some(item) = self.next(&iterator)? {
            items.push(item);
        }

        Ok(items)
    }

    /// `UNPACK_SEQUENCE`. An unknown value unpacks into unknown items: the
    /// bytecode fixes the count, and native client code returns the shape
    /// its Python callers unpack, as for any other call into native code
    /// whose result is unknown.
    pub fn unpack(&self, sequence: &Value, count: usize) -> PyResult<Vec<Value>> {
        if sequence.is_unknown() {
            return Ok(vec![sequence.clone(); count]);
        }

        let items = self.collect(sequence)?;

        if items.len() < count {
            let message = if items.len() == 1 { "need more than 1 value to unpack".to_owned() } else { format!("need more than {} values to unpack", items.len()) };
            return Err(self.raise(ExceptionKind::ValueError, &message));
        }
        if items.len() > count {
            return Err(self.raise(ExceptionKind::ValueError, "too many values to unpack"));
        }

        Ok(items)
    }

    /// Resumes a generator with a sent value.
    pub fn generator_send(&self, generator: &ObjectRef, value: Value) -> PyResult<Option<Value>> {
        self.generator_resume(generator, Resume::Send(value))
    }

    /// Resumes a generator with a sent value or a thrown exception. `None`
    /// when the generator finishes.
    pub fn generator_resume(&self, generator: &ObjectRef, resume: Resume) -> PyResult<Option<Value>> {
        let Payload::Generator(data) = &generator.payload else {
            return Err(self.type_error("expected a generator"));
        };

        let state = std::mem::replace(&mut data.borrow_mut().state, GeneratorState::Running);
        let (mut frame, pending) = match (state, resume) {
            (GeneratorState::Created(frame), Resume::Send(value)) => {
                if !value.is_none() {
                    data.borrow_mut().state = GeneratorState::Created(frame);
                    return Err(self.type_error("can't send non-None value to a just-started generator"));
                }
                (frame, None)
            }
            // The exception enters the unstarted frame, which adds itself to
            // the traceback before the exception leaves it.
            (GeneratorState::Created(frame), Resume::Throw(signal)) => (frame, Some(signal)),
            (GeneratorState::Suspended(mut frame), Resume::Send(value)) => {
                frame.push(value);
                (frame, None)
            }
            (GeneratorState::Suspended(frame), Resume::Throw(signal)) => (frame, Some(signal)),
            (GeneratorState::Running, _) => return Err(self.raise(ExceptionKind::ValueError, "generator already executing")),
            (GeneratorState::Finished, Resume::Send(_)) => {
                data.borrow_mut().finish();
                return Ok(None);
            }
            (GeneratorState::Finished, Resume::Throw(signal)) => {
                data.borrow_mut().finish();
                return Err(signal);
            }
        };

        self.push_handled_slot();
        let result = self.with_depth(|| match pending {
            None => crate::interp::frame::run_frame(self, &mut frame),
            Some(signal) => crate::interp::frame::resume_raising(self, &mut frame, signal),
        });
        self.pop_handled_slot();

        match result {
            Ok(crate::interp::frame::FrameExit::Yield(item)) => {
                data.borrow_mut().state = GeneratorState::Suspended(frame);
                Ok(Some(item))
            }
            Ok(crate::interp::frame::FrameExit::Return(_)) => {
                data.borrow_mut().finish();
                Ok(None)
            }
            Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::StopIteration) => {
                data.borrow_mut().finish();
                Ok(None)
            }
            Err(error) => {
                data.borrow_mut().finish();
                Err(error)
            }
        }
    }
}

/// How a suspended generator continues.
pub enum Resume {
    Send(Value),
    Throw(Signal),
}

fn contains_subslice<T: PartialEq>(haystack: &[T], needle: &[T]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window == needle)
}

pub fn find_subslice<T: PartialEq>(haystack: &[T], needle: &[T], start: usize) -> Option<usize> {
    if start > haystack.len() {
        return None;
    }
    if needle.is_empty() {
        return Some(start);
    }

    haystack[start..].windows(needle.len()).position(|window| window == needle).map(|position| position + start)
}

impl Vm {
    /// The item count of a `list`, `tuple`, or `bytearray` read from its
    /// storage, without calling an overridden `__len__`.
    fn storage_length(&self, sequence: &Value) -> Option<usize> {
        if let Some(items) = self.as_tuple(sequence) {
            return Some(items.len());
        }

        match &sequence.as_object()?.payload {
            Payload::List(items) => Some(items.borrow().len()),
            Payload::ByteArray(data) => Some(data.borrow().bytes.len()),
            _ => None,
        }
    }
}

/// The state a `__length_hint__` reads, copied out of a native iterator.
enum HintSource {
    Remaining(i64),
    Sized { sequence: Value, consumed: i64 },
    Reversed { sequence: Value, position: i64 },
    Dict { dict: ObjectRef, length: usize, remaining: usize },
    Set { set: ObjectRef, length: usize, remaining: usize },
}
