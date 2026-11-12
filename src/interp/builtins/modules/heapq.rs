//! `_heapq`: heap queue operations on lists.

use std::cell::RefCell;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::operator::IntFormat;
use crate::interp::builtins::modules::operator::has_attribute;
use crate::interp::builtins::modules::operator::integer_arg;
use crate::interp::builtins::modules::operator::parse_exact;
use crate::interp::builtins::modules::operator::single;
use crate::interp::builtins::modules::operator::unpack;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The heap a selection keeps: `nlargest` keeps the largest items in a
/// min-heap, `nsmallest` the smallest in a max-heap.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Largest,
    Smallest,
}

const FUNCTIONS: &[MethodSpec] = &[
    function("heappush", heappush),
    function("heappushpop", heappushpop),
    function("heappop", heappop),
    function("heapreplace", heapreplace),
    function("heapify", heapify),
    function("nlargest", |vm, args| select(vm, args, "nlargest", Keep::Largest)),
    function("nsmallest", |vm, args| select(vm, args, "nsmallest", Keep::Smallest)),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)?;

    set_attribute(vm, module, "__about__", Value::unknown("heapq.__about__ text"))
}

/// The items of a list (or list subclass) heap argument.
fn heap_items<'a>(vm: &Vm, heap: &'a Value) -> PyResult<&'a RefCell<Vec<Value>>> {
    if let Value::Object(object) = heap
        && let Payload::List(items) = &object.payload
    {
        return Ok(items);
    }

    Err(vm.type_error("heap argument must be a list"))
}

fn index_error(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::IndexError, "index out of range")
}

fn size_changed(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::RuntimeError, "list changed size during iteration")
}

fn item_at(vm: &Vm, heap: &RefCell<Vec<Value>>, position: usize) -> PyResult<Value> {
    heap.borrow().get(position).cloned().ok_or_else(|| index_error(vm))
}

fn swap(vm: &Vm, heap: &RefCell<Vec<Value>>, first: usize, second: usize) -> PyResult<()> {
    let mut items = heap.borrow_mut();
    if first >= items.len() || second >= items.len() {
        return Err(index_error(vm));
    }

    items.swap(first, second);

    Ok(())
}

/// `x < y`, or `not y <= x` when `x` has no `__lt__`.
fn item_less_than(vm: &Vm, x: &Value, y: &Value) -> PyResult<bool> {
    if has_attribute(vm, x, "__lt__")? {
        return vm.less_than(x, y);
    }

    let result = vm.compare(y, x, CompareOp::LessEqual)?;

    Ok(!vm.truthy(&result, "<=")?)
}

/// `_siftdown`. Comparisons may run Python code that mutates the heap, so
/// no borrow is held across them.
fn sift_down(vm: &Vm, heap: &RefCell<Vec<Value>>, start: usize, mut position: usize) -> PyResult<()> {
    let size = heap.borrow().len();
    if position >= size {
        return Err(index_error(vm));
    }

    let mut new_item = item_at(vm, heap, position)?;
    while position > start {
        let parent_position = (position - 1) >> 1;
        let parent = item_at(vm, heap, parent_position)?;
        let less = item_less_than(vm, &new_item, &parent)?;
        if size != heap.borrow().len() {
            return Err(size_changed(vm));
        }
        if !less {
            break;
        }

        swap(vm, heap, parent_position, position)?;
        new_item = item_at(vm, heap, parent_position)?;
        position = parent_position;
    }

    Ok(())
}

/// `_siftup`.
fn sift_up(vm: &Vm, heap: &RefCell<Vec<Value>>, mut position: usize) -> PyResult<()> {
    let end = heap.borrow().len();
    let start = position;
    if position >= end {
        return Err(index_error(vm));
    }

    // Bubble the smaller child up until hitting a leaf.
    let limit = end / 2;
    while position < limit {
        let mut child = 2 * position + 1;
        let right = child + 1;
        if right < end {
            let (left_item, right_item) = (item_at(vm, heap, child)?, item_at(vm, heap, right)?);
            if !item_less_than(vm, &left_item, &right_item)? {
                child = right;
            }
            if end != heap.borrow().len() {
                return Err(size_changed(vm));
            }
        }

        swap(vm, heap, child, position)?;
        position = child;
    }

    sift_down(vm, heap, start, position)
}

/// `_siftdownmax`, on a heap private to `nsmallest`.
fn sift_down_max(vm: &Vm, heap: &mut [Value], start: usize, mut position: usize) -> PyResult<()> {
    let Some(new_item) = heap.get(position).cloned() else {
        return Err(index_error(vm));
    };

    while position > start {
        let parent_position = (position - 1) >> 1;
        let parent = heap[parent_position].clone();
        if !item_less_than(vm, &parent, &new_item)? {
            break;
        }

        heap[position] = parent;
        position = parent_position;
    }

    heap[position] = new_item;

    Ok(())
}

/// `_siftupmax`, on a heap private to `nsmallest`.
fn sift_up_max(vm: &Vm, heap: &mut [Value], mut position: usize) -> PyResult<()> {
    let end = heap.len();
    let start = position;
    let Some(new_item) = heap.get(position).cloned() else {
        return Err(index_error(vm));
    };

    let limit = end / 2;
    while position < limit {
        let mut child = 2 * position + 1;
        let right = child + 1;
        if right < end && !item_less_than(vm, &heap[right], &heap[child])? {
            child = right;
        }

        heap[position] = heap[child].clone();
        position = child;
    }

    heap[position] = new_item;

    sift_down_max(vm, heap, start, position)
}

/// `heappush`.
fn heappush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut operands = unpack(vm, args, "heappush", "heappush", 2)?;
    let Some(item) = operands.pop() else {
        return Err(vm.type_error("heappush expected 2 arguments, got 0"));
    };
    let heap = heap_items(vm, &operands[0])?;

    let last = {
        let mut items = heap.borrow_mut();
        items.push(item);
        items.len() - 1
    };
    sift_down(vm, heap, 0, last)?;

    Ok(Value::None)
}

/// `heappop`.
fn heappop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "heappop")?;
    let heap = heap_items(vm, &argument)?;

    let returned = {
        let mut items = heap.borrow_mut();
        let Some(last) = items.pop() else {
            return Err(index_error(vm));
        };
        let Some(first) = items.first_mut() else {
            return Ok(last);
        };
        std::mem::replace(first, last)
    };
    sift_up(vm, heap, 0)?;

    Ok(returned)
}

/// Replaces the root of a nonempty heap with `item` and restores the
/// invariant, returning the old root.
fn replace_root(vm: &Vm, heap: &RefCell<Vec<Value>>, item: Value) -> PyResult<Value> {
    let returned = {
        let mut items = heap.borrow_mut();
        let Some(first) = items.first_mut() else {
            return Err(index_error(vm));
        };
        std::mem::replace(first, item)
    };
    sift_up(vm, heap, 0)?;

    Ok(returned)
}

/// `heapreplace`.
fn heapreplace(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut operands = unpack(vm, args, "heapreplace", "heapreplace", 2)?;
    let Some(item) = operands.pop() else {
        return Err(vm.type_error("heapreplace expected 2 arguments, got 0"));
    };
    let heap = heap_items(vm, &operands[0])?;

    replace_root(vm, heap, item)
}

/// `heappushpop`.
fn heappushpop(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut operands = unpack(vm, args, "heappushpop", "heappushpop", 2)?;
    let Some(item) = operands.pop() else {
        return Err(vm.type_error("heappushpop expected 2 arguments, got 0"));
    };
    let heap = heap_items(vm, &operands[0])?;

    let Some(root) = heap.borrow().first().cloned() else {
        return Ok(item);
    };
    if !item_less_than(vm, &root, &item)? {
        return Ok(item);
    }

    replace_root(vm, heap, item)
}

/// `heapify`.
fn heapify(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = single(vm, args, "heapify")?;
    let heap = heap_items(vm, &argument)?;

    let size = heap.borrow().len();
    for position in (0..size / 2).rev() {
        sift_up(vm, heap, position)?;
    }

    Ok(Value::None)
}

/// `nlargest` and `nsmallest`: keeps the `n` most extreme items of the
/// iterable in a heap, then sorts them.
fn select(vm: &Vm, args: CallArgs, name: &str, keep: Keep) -> PyResult<Value> {
    let operands = parse_exact(vm, args, name, name, 2)?;
    let count = integer_arg(vm, &operands[0], IntFormat::SSize)?;
    let iterator = vm.iter(&operands[1])?;

    let mut items = Vec::new();
    let mut exhausted = false;
    while (items.len() as i64) < count {
        let Some(item) = vm.next(&iterator)? else {
            exhausted = true;
            break;
        };
        items.push(item);
    }

    if !exhausted && !items.is_empty() {
        items = match keep {
            Keep::Largest => keep_largest(vm, &iterator, items)?,
            Keep::Smallest => keep_smallest(vm, &iterator, items)?,
        };
    }

    vm.sort_values(&mut items, None, None, false)?;
    if keep == Keep::Largest {
        items.reverse();
    }

    Ok(vm.new_list(items))
}

/// The main loop of `nlargest`: a min-heap whose root is the smallest item
/// kept.
fn keep_largest(vm: &Vm, iterator: &Value, items: Vec<Value>) -> PyResult<Vec<Value>> {
    let heap = RefCell::new(items);

    let size = heap.borrow().len();
    for position in (0..size / 2).rev() {
        sift_up(vm, &heap, position)?;
    }

    let mut floor = item_at(vm, &heap, 0)?;
    while let Some(item) = vm.next(iterator)? {
        if !item_less_than(vm, &floor, &item)? {
            continue;
        }

        replace_root(vm, &heap, item)?;
        floor = item_at(vm, &heap, 0)?;
    }

    Ok(heap.into_inner())
}

/// The main loop of `nsmallest`: a max-heap whose root is the largest item
/// kept.
fn keep_smallest(vm: &Vm, iterator: &Value, mut heap: Vec<Value>) -> PyResult<Vec<Value>> {
    for position in (0..heap.len() / 2).rev() {
        sift_up_max(vm, &mut heap, position)?;
    }

    let Some(mut ceiling) = heap.first().cloned() else {
        return Ok(heap);
    };
    while let Some(item) = vm.next(iterator)? {
        if !item_less_than(vm, &item, &ceiling)? {
            continue;
        }

        if let Some(root) = heap.first_mut() {
            *root = item;
        }
        sift_up_max(vm, &mut heap, 0)?;
        ceiling = heap[0].clone();
    }

    Ok(heap)
}
