//! `slice`, `xrange`, `enumerate`, and `reversed`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::one_argument;
use crate::interp::builtins::arguments::stop_iteration;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::SliceData;
use crate::interp::value::Value;
use crate::interp::value::XRangeData;
use crate::interp::vm::Vm;

pub fn register(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install(vm, &types.slice, &[static_method("__new__", slice_new), method("indices", slice_indices)])?;

    install(
        vm,
        &types.xrange,
        &[
            static_method("__new__", xrange_new),
            method("__len__", xrange_len),
            method("__getitem__", xrange_getitem),
            method("__iter__", xrange_iter),
            method("__reversed__", xrange_reversed),
            method("__repr__", xrange_repr),
        ],
    )?;

    install(vm, &types.enumerate, &[static_method("__new__", enumerate_new), method("next", iterator_next), method("__iter__", iterator_self)])?;
    install(vm, &types.reversed, &[static_method("__new__", reversed_new), method("next", iterator_next), method("__iter__", iterator_self), method("__length_hint__", reversed_length_hint)])
}

/// `slice(stop)` or `slice(start, stop[, step])`.
fn slice_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().slice);
    let (_, rest) = new_class(vm, args, &base)?;
    if rest.has_keywords() {
        return Err(vm.type_error("slice() does not take keyword arguments"));
    }

    let mut parts = unpack(vm, rest, "slice", 1, 3)?.into_iter();
    let first = parts.next().unwrap_or(Value::None);
    let slice = match (parts.next(), parts.next()) {
        (None, _) => vm.new_slice(Value::None, first, Value::None),
        (Some(stop), step) => vm.new_slice(first, stop, step.unwrap_or(Value::None)),
    };

    Ok(slice)
}

/// The normalized `(start, stop, step)` for a length.
fn slice_indices(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "indices", "slice")?;
    let length = one_argument(vm, rest, "indices")?;
    let length = index_value(vm, &length)?;

    let Some(Payload::Slice(slice)) = target.as_object().map(|object| &object.payload) else {
        return Err(wrong_receiver(vm, "indices", "slice", &target));
    };
    let slice = SliceData { start: slice.start.clone(), stop: slice.stop.clone(), step: slice.step.clone() };
    let indices = vm.slice_indices_signed(&slice, length)?;

    Ok(Value::tuple(vec![vm.new_int_from_i64(indices.start), vm.new_int_from_i64(indices.stop), vm.new_int_from_i64(indices.step)]))
}

/// C `long` bounds, a nonzero step, and a length that fits a C `long`.
fn xrange_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const USAGE: &str = "xrange() requires 1-3 int arguments";

    let base = Rc::clone(&vm.types().xrange);
    let (_, rest) = new_class(vm, args, &base)?;
    if rest.has_keywords() {
        return Err(vm.type_error("xrange() does not take keyword arguments"));
    }

    let bounds = rest.positional;
    let (start, stop, step) = match bounds.as_slice() {
        [stop] => (0, long_argument(vm, stop)?, 1),
        [start, stop] => (long_argument(vm, start)?, long_argument(vm, stop)?, 1),
        [start, stop, step] => (long_argument(vm, start)?, long_argument(vm, stop)?, long_argument(vm, step)?),
        _ => return Err(vm.type_error(USAGE)),
    };

    if step == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "xrange() arg 3 must not be zero"));
    }

    let (start_wide, stop_wide, step_wide) = (i128::from(start), i128::from(stop), i128::from(step));
    let length = if step > 0 && start < stop {
        1 + (stop_wide - start_wide - 1) / step_wide
    } else if step < 0 && start > stop {
        1 + (start_wide - stop_wide - 1) / -step_wide
    } else {
        0
    };

    let (_, long_max) = numbers::int_bounds(vm.config.long_width);
    let Some(length) = i64::try_from(length).ok().filter(|length| *length <= long_max) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "xrange() result has too many items"));
    };

    Ok(Value::Object(vm.alloc(&base, Payload::XRange(XRangeData { start, length, step }), None)))
}

fn bind_xrange(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, XRangeData, CallArgs)> {
    let (target, rest) = bind(vm, args, method, "xrange")?;
    let Some(Payload::XRange(range)) = target.as_object().map(|object| &object.payload) else {
        return Err(wrong_receiver(vm, method, "xrange", &target));
    };
    let range = *range;

    Ok((target, range, rest))
}

fn xrange_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, range, rest) = bind_xrange(vm, args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_int_from_i64(range.length))
}

fn xrange_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _, rest) = bind_xrange(vm, args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;

    vm.getitem(&target, &index)
}

fn xrange_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, range, rest) = bind_xrange(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(vm.new_iterator(NativeIterator::Range { next: range.start, remaining: range.length, step: range.step }))
}

/// Counts down from the last item.
fn xrange_reversed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, range, rest) = bind_xrange(vm, args, "__reversed__")?;
    no_arguments(vm, rest, "__reversed__")?;

    // Every item lies in the C long range, so wrapping arithmetic gives the
    // exact values even when the distance or the negated step does not fit.
    let last = range.start.wrapping_add((range.length - 1).max(0).wrapping_mul(range.step));

    Ok(vm.new_iterator(NativeIterator::Range { next: last, remaining: range.length, step: range.step.wrapping_neg() }))
}

fn xrange_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, _, rest) = bind_xrange(vm, args, "__repr__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Str(PyBytes::new(vm.builtin_repr(&target)?.into_bytes())))
}

/// `enumerate(sequence, start=0)`.
fn enumerate_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().enumerate);
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse(vm, rest, "enumerate", &["sequence", "start"], 1)?;
    let sequence = slots[0].clone().unwrap_or(Value::None);
    let count = match &slots[1] {
        None => Value::Int(0),
        Some(start) => match vm.as_integral(start) {
            Some(integral) => vm.new_int(integral.to_bigint()),
            None => vm.new_int_from_i64(index_value(vm, start)?),
        },
    };
    let iterator = vm.iter(&sequence)?;

    Ok(new_instance(vm, &class, Payload::Iterator(RefCell::new(NativeIterator::Enumerate { iterator, count }))))
}

/// `__reversed__` when the type has one, otherwise the sequence protocol
/// from the last index down.
fn reversed_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = Rc::clone(&vm.types().reversed);
    let (class, rest) = new_class(vm, args, &base)?;
    if rest.has_keywords() {
        return Err(vm.type_error("reversed() does not take keyword arguments"));
    }

    let mut arguments = unpack(vm, rest, "reversed", 1, 1)?.into_iter();
    let Some(sequence) = arguments.next() else {
        return Err(vm.type_error("reversed expected 1 arguments, got 0"));
    };
    if sequence.is_unknown() {
        return Ok(sequence);
    }

    if let Some(method) = vm.lookup_special(&sequence, "__reversed__")? {
        return vm.call0(&method);
    }

    if !is_sequence(vm, &sequence)? {
        return Err(vm.type_error("argument to reversed() must be a sequence"));
    }

    let Some(length) = vm.len(&sequence)? else {
        return Ok(Value::unknown("reversed() of a sequence with unknown length"));
    };

    Ok(new_instance(vm, &class, Payload::Iterator(RefCell::new(NativeIterator::Reversed { sequence, index: length.checked_sub(1) }))))
}

/// Whether the value is a sequence: an item slot that is not a dict's.
fn is_sequence(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some() || vm.as_tuple(value).is_some() {
        return Ok(true);
    }

    let Value::Object(object) = value else {
        return Ok(false);
    };

    match &object.payload {
        Payload::List(_) | Payload::XRange(_) => Ok(true),
        Payload::Dict(_) => Ok(false),
        _ => Ok(vm.user_override(value, "__getitem__")?.is_some()),
    }
}

fn iterator_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "next", "iterator")?;
    no_arguments(vm, rest, "next")?;

    match vm.next(&target)? {
        Some(item) => Ok(item),
        None => Err(stop_iteration(vm)),
    }
}

fn reversed_length_hint(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__length_hint__", "reversed")?;
    let object = match &target {
        Value::Object(object) if vm.is_instance_of(&target, &vm.types().reversed)? => Rc::clone(object),
        _ => return Err(wrong_receiver(vm, "__length_hint__", "reversed", &target)),
    };
    no_arguments(vm, rest, "__length_hint__")?;

    vm.native_length_hint(&object)?.ok_or_else(|| wrong_receiver(vm, "__length_hint__", "reversed", &target))
}

fn iterator_self(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = bind(vm, args, "__iter__", "iterator")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(target)
}
