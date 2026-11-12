//! Methods of the builtin container types: `tuple`, `list`, `bytearray`,
//! `buffer`, `memoryview`, `dict` and its views, `dictproxy`, `set`,
//! `frozenset`, and the lazy sequences `slice`, `xrange`, `enumerate`, and
//! `reversed`.

pub mod buffer_object;
mod bytearray;
mod dict;
mod lazy;
mod list;
pub mod memoryview;
mod set;
mod tuple;
mod views;

use crate::interp::error::PyResult;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub use set::set_binary;
pub use views::view_compare;
pub use views::view_contains;
pub use views::view_iter;
pub use views::view_len;
pub use views::view_repr;

pub fn install(vm: &Vm) -> PyResult<()> {
    tuple::register(vm)?;
    list::register(vm)?;
    dict::register(vm)?;
    bytearray::register(vm)?;
    memoryview::register(vm)?;
    buffer_object::register(vm)?;
    views::register(vm)?;
    set::register(vm)?;
    lazy::register(vm)
}

/// Whether `candidate` matches `item` as the `in` operator decides it:
/// identity first, then `==`.
fn same_item(vm: &Vm, candidate: &Value, item: &Value) -> PyResult<bool> {
    if vm.is_same(candidate, item) {
        return Ok(true);
    }

    vm.equals(candidate, item)
}

/// Counts items equal to `item`, reading each one from the live sequence
/// through `item_at` because comparisons may mutate it.
fn count_item(vm: &Vm, item_at: impl Fn(usize) -> Option<Value>, item: &Value) -> PyResult<usize> {
    let mut count = 0;
    let mut position = 0;
    while let Some(candidate) = item_at(position) {
        if same_item(vm, &candidate, item)? {
            count += 1;
        }
        position += 1;
    }

    Ok(count)
}

/// Resolves the optional `start` and `stop` of `list.index()` and
/// `tuple.index()` against a length.
fn index_bounds(vm: &Vm, bounds: &[Value], length: usize) -> PyResult<(usize, usize)> {
    let length = length as i64;
    let resolve = |value: Option<&Value>, default: i64| -> PyResult<i64> {
        let Some(value) = value else {
            return Ok(default);
        };
        let bound = crate::interp::builtins::arguments::slice_index(vm, value)?;
        let bound = if bound < 0 { bound.saturating_add(length) } else { bound };

        Ok(bound.max(0))
    };

    let start = resolve(bounds.first(), 0)?;
    let stop = resolve(bounds.get(1), length)?;

    Ok((start as usize, stop as usize))
}

/// Position of the first item equal to `item` within `start..stop`,
/// reading each item from the live sequence through `item_at`.
fn find_item(vm: &Vm, item_at: impl Fn(usize) -> Option<Value>, item: &Value, start: usize, stop: usize) -> PyResult<Option<usize>> {
    for position in start..stop {
        let Some(candidate) = item_at(position) else {
            break;
        };
        if same_item(vm, &candidate, item)? {
            return Ok(Some(position));
        }
    }

    Ok(None)
}

/// `count` concatenated copies of `items`; MemoryError when the result
/// cannot be allocated.
fn repeat_items(vm: &Vm, items: &[Value], count: usize) -> PyResult<Vec<Value>> {
    let mut repeated = Vec::new();
    let reserved = items.len().checked_mul(count).map(|total| repeated.try_reserve_exact(total));
    if !matches!(reserved, Some(Ok(()))) {
        return Err(crate::interp::builtins::arguments::memory_error(vm));
    }

    for _ in 0..count {
        repeated.extend_from_slice(items);
    }

    Ok(repeated)
}
