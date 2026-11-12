//! Methods of the native iterator types (`listiterator`, `setiterator`, ...).

use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::stop_iteration;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::install;
use crate::interp::builtins::method;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::types::IteratorKind;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn install_iterator_types(vm: &Vm) -> PyResult<()> {
    for kind in IteratorKind::ALL {
        let methods: Vec<MethodSpec> = match kind {
            IteratorKind::Sequence => methods::<{ IteratorKind::Sequence as usize }>(),
            IteratorKind::List => methods::<{ IteratorKind::List as usize }>(),
            IteratorKind::ListReverse => methods::<{ IteratorKind::ListReverse as usize }>(),
            IteratorKind::Tuple => methods::<{ IteratorKind::Tuple as usize }>(),
            IteratorKind::ByteArray => methods::<{ IteratorKind::ByteArray as usize }>(),
            IteratorKind::Range => methods::<{ IteratorKind::Range as usize }>(),
            IteratorKind::Set => methods::<{ IteratorKind::Set as usize }>(),
            IteratorKind::DictKeys => methods::<{ IteratorKind::DictKeys as usize }>(),
            IteratorKind::DictValues => methods::<{ IteratorKind::DictValues as usize }>(),
            IteratorKind::DictItems => methods::<{ IteratorKind::DictItems as usize }>(),
            IteratorKind::Callable => methods::<{ IteratorKind::Callable as usize }>(),
        };
        install(vm, vm.types().iterator_type(kind), &methods)?;
    }

    Ok(())
}

/// `KIND` indexes `IteratorKind::ALL`; `callable-iterator` has no
/// `__length_hint__`.
fn methods<const KIND: usize>() -> Vec<MethodSpec> {
    let mut methods = vec![method("next", next::<KIND>), method("__iter__", iter_self::<KIND>)];
    if IteratorKind::ALL[KIND] != IteratorKind::Callable {
        methods.push(method("__length_hint__", length_hint::<KIND>));
    }

    methods
}

/// The receiver of a method of the `KIND` iterator type.
fn receiver<const KIND: usize>(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    let kind = IteratorKind::ALL[KIND];
    let (target, rest) = bind(vm, args, method, kind.name())?;
    if !Rc::ptr_eq(&vm.type_of(&target), vm.types().iterator_type(kind)) {
        return Err(wrong_receiver(vm, method, kind.name(), &target));
    }

    Ok((target, rest))
}

/// The `next` slot wrapper.
fn next<const KIND: usize>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver::<KIND>(vm, args, "next")?;
    wrapper_arguments(vm, rest, 0)?;

    match vm.next(&target)? {
        Some(item) => Ok(item),
        None => Err(stop_iteration(vm)),
    }
}

fn iter_self<const KIND: usize>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver::<KIND>(vm, args, "__iter__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(target)
}

fn length_hint<const KIND: usize>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, rest) = receiver::<KIND>(vm, args, "__length_hint__")?;
    no_arguments(vm, rest, "__length_hint__")?;

    let Value::Object(iterator) = &target else {
        return Err(wrong_receiver(vm, "__length_hint__", IteratorKind::ALL[KIND].name(), &target));
    };
    let Some(hint) = vm.native_length_hint(iterator)? else {
        return Err(wrong_receiver(vm, "__length_hint__", IteratorKind::ALL[KIND].name(), &target));
    };

    Ok(hint)
}
