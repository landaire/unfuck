//! `_bisect`: binary search and insertion on sorted sequences.

use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::operator::IntFormat;
use crate::interp::builtins::modules::operator::integer_arg;
use crate::interp::builtins::parse_with;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Which end of a run of equal items a search returns.
#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// The parsed `(a, x, lo, hi)` arguments.
struct SearchArgs {
    list: Value,
    item: Value,
    lo: i64,
    /// `None` searches to the end of the sequence.
    hi: Option<i64>,
}

const FUNCTIONS: &[MethodSpec] = &[
    function("bisect_right", |vm, args| bisect(vm, args, "bisect_right", Side::Right)),
    function("insort_right", |vm, args| insort(vm, args, "insort_right", Side::Right)),
    function("bisect_left", |vm, args| bisect(vm, args, "bisect_left", Side::Left)),
    function("insort_left", |vm, args| insort(vm, args, "insort_left", Side::Left)),
    function("bisect", |vm, args| bisect(vm, args, "bisect_right", Side::Right)),
    function("insort", |vm, args| insort(vm, args, "insort_right", Side::Right)),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)
}

/// Arguments `a`, `x`, and optional `lo` and `hi`, by position or keyword.
fn search_args(vm: &Vm, args: CallArgs, name: &str) -> PyResult<SearchArgs> {
    let slots = parse_with(vm, args, name, &["a", "x", "lo", "hi"], 2, |vm, index, value| match index {
        2 | 3 => integer_arg(vm, &value, IntFormat::SSize).map(Value::Int),
        _ => Ok(value),
    })?;
    let mut slots = slots.into_iter();
    let (Some(Some(list)), Some(Some(item)), Some(lo), Some(hi)) = (slots.next(), slots.next(), slots.next(), slots.next()) else {
        return Err(vm.type_error(&format!("{name}() requires its first two arguments")));
    };

    let lo = match lo {
        Some(Value::Int(lo)) => lo,
        _ => 0,
    };
    // CPython uses -1 as the "no bound" default, so an explicit -1 also
    // searches to the end.
    let hi = match hi {
        Some(Value::Int(hi)) if hi != -1 => Some(hi),
        _ => None,
    };

    Ok(SearchArgs { list, item, lo, hi })
}

/// `bisect.bisect_right` and `bisect.bisect_left`.
fn search(vm: &Vm, args: &SearchArgs, side: Side) -> PyResult<i64> {
    if args.lo < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "lo must be non-negative"));
    }

    let mut lo = args.lo;
    let mut hi = match args.hi {
        Some(hi) => hi,
        None => {
            let Some(length) = vm.len(&args.list)? else {
                return Err(Signal::Halt(Halt::UnknownCondition { context: "bisect length".to_owned(), origin: format!("{:?}", args.list) }));
            };
            length as i64
        }
    };

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let probe = vm.getitem(&args.list, &Value::Int(mid))?;
        let goes_left = match side {
            Side::Right => vm.less_than(&args.item, &probe)?,
            Side::Left => !vm.less_than(&probe, &args.item)?,
        };
        if goes_left {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    Ok(lo)
}

fn bisect(vm: &Vm, args: CallArgs, name: &str, side: Side) -> PyResult<Value> {
    let args = search_args(vm, args, name)?;
    if args.list.is_unknown() {
        return Ok(args.list);
    }

    Ok(Value::Int(search(vm, &args, side)?))
}

/// `insort_right` and `insort_left`: inserts into an exact list directly,
/// otherwise through the sequence's `insert` method.
fn insort(vm: &Vm, args: CallArgs, name: &str, side: Side) -> PyResult<Value> {
    let args = search_args(vm, args, name)?;
    if args.list.is_unknown() {
        return Ok(args.list);
    }

    let index = search(vm, &args, side)?;

    if let Value::Object(object) = &args.list
        && let Payload::List(items) = &object.payload
        && Rc::ptr_eq(&object.class(), &vm.types().list)
    {
        let mut items = items.borrow_mut();
        let position = usize::try_from(index).unwrap_or(0).min(items.len());
        items.insert(position, args.item);
        return Ok(Value::None);
    }

    vm.call_method(&args.list, "insert", vec![Value::Int(index), args.item])?;

    Ok(Value::None)
}
