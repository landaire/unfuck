//! `SRE_Scanner`: successive matches over one subject. After a call that
//! finds nothing, or an empty match at the end, every later call finds
//! nothing.

use std::cell::Cell;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::sre::matches::new_match;
use crate::interp::builtins::modules::sre::pattern::Bounded;
use crate::interp::builtins::modules::sre::pattern::PatternData;
use crate::interp::builtins::modules::sre::pattern::engine_error;
use crate::interp::builtins::modules::sre::scan::single;
use crate::interp::builtins::modules::this;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const SCANNER_TYPE: &str = "_sre.SRE_Scanner";

/// A scanner (`ScannerObject`).
struct ScannerData {
    pattern: Value,
    string: Value,
    bounded: Bounded,
    /// Where the next call starts; `None` once a call found nothing.
    next: Cell<Option<usize>>,
}

impl_native_data!(ScannerData, "_sre.SRE_Scanner");

/// A scanner over `string` from `start` to `end`, or an unknown value when
/// the subject is unknown.
pub fn new_scanner(vm: &Vm, pattern: &Value, string: Value, start: i64, end: i64) -> PyResult<Value> {
    let Some(bounded) = Bounded::new(vm, &string, start, end)? else {
        return Ok(Value::unknown("_sre.SRE_Pattern.scanner of an unknown subject"));
    };
    let class = native_type(vm, SCANNER_TYPE, create_scanner_type)?;
    let next = Cell::new(Some(bounded.start));
    let data = ScannerData { pattern: pattern.clone(), string, bounded, next };

    Ok(new_native_object(vm, &class, data))
}

fn create_scanner_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "SRE_Scanner",
            module: "_sre",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("match", scanner_match), method("search", scanner_search)],
        },
    )?;

    add_member(vm, &class, GetSet { name: "pattern", owner: SCANNER_TYPE, get: member_pattern, set: None })?;

    Ok(class)
}

fn member_pattern(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    match native_data::<ScannerData>(instance) {
        Some(data) => Ok(data.pattern.clone()),
        None => Err(descriptor_mismatch(vm, getset, instance)),
    }
}

fn scanner_match(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    step(vm, args, "match", true)
}

fn scanner_search(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    step(vm, args, "search", false)
}

fn step(vm: &Vm, args: CallArgs, method: &str, anchored: bool) -> PyResult<Value> {
    let data = this::<ScannerData>(vm, &args, SCANNER_TYPE, method)?;
    method_no_arguments(vm, &args, method)?;

    let Some(start) = data.next.get() else {
        return Ok(Value::None);
    };
    let Some((compiled, fold)) = native_data::<PatternData>(&data.pattern).and_then(|pattern| pattern.runnable(vm)) else {
        return Ok(Value::unknown(format!("_sre.SRE_Scanner.{method} of an unknown pattern")));
    };

    let found = single(data.bounded.subject.units(), data.bounded.run(compiled, fold, start), anchored).map_err(|error| engine_error(vm, error))?;
    let Some(found) = found else {
        data.next.set(None);
        return Ok(Value::None);
    };

    // An empty match moves the next start one character on, unless it
    // sits at the end.
    let whole = found.whole;
    let next = if whole.start != whole.end {
        Some(whole.end)
    } else if whole.end != data.bounded.end {
        Some(whole.end + 1)
    } else {
        None
    };
    data.next.set(next);

    new_match(vm, &data.pattern, &data.string, found, data.bounded.start, data.bounded.end)
}
