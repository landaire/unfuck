//! `itertools`.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments;
use crate::interp::builtins::class_method;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::parse;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::iterator_result;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::BinaryOp;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

type TypeFactory = fn(&Vm) -> PyResult<ObjectRef>;

/// `count` state. `Fast` is a machine-sized counter, which reprs without
/// the long suffix; `Slow` holds arbitrary numbers.
enum CountState {
    Fast(i64),
    Slow { count: Value, step: Value },
}

struct Count {
    state: RefCell<CountState>,
}

impl_native_data!(Count, "itertools.count");

struct Cycle {
    iterator: Value,
    saved: RefCell<Vec<Value>>,
    /// Position in `saved` once the input is exhausted.
    replay: Cell<Option<usize>>,
}

impl_native_data!(Cycle, "itertools.cycle");

struct Repeat {
    element: Value,
    /// `None` repeats forever.
    remaining: Cell<Option<i64>>,
}

impl_native_data!(Repeat, "itertools.repeat");

struct Chain {
    source: RefCell<Option<Value>>,
    active: RefCell<Option<Value>>,
}

impl_native_data!(Chain, "itertools.chain");

struct Compress {
    data: Value,
    selectors: Value,
}

impl_native_data!(Compress, "itertools.compress");

struct DropWhile {
    predicate: Value,
    iterator: Value,
    dropped: Cell<bool>,
}

impl_native_data!(DropWhile, "itertools.dropwhile");

struct TakeWhile {
    predicate: Value,
    iterator: Value,
    stopped: Cell<bool>,
}

impl_native_data!(TakeWhile, "itertools.takewhile");

/// `ifilter` keeps true items, `ifilterfalse` (`KEEP == false`) false ones.
struct Filter<const KEEP: bool> {
    function: Value,
    iterator: Value,
}

impl_native_data!(Filter<true>, "itertools.ifilter");
impl_native_data!(Filter<false>, "itertools.ifilterfalse");

struct GroupBy {
    iterator: Value,
    key: Value,
    target_key: RefCell<Option<Value>>,
    current_key: RefCell<Option<Value>>,
    current_value: RefCell<Option<Value>>,
}

impl_native_data!(GroupBy, "itertools.groupby");

struct Grouper {
    parent: Value,
    target_key: Value,
}

impl_native_data!(Grouper, "itertools._grouper");

struct Imap {
    function: Value,
    iterators: Vec<Value>,
}

impl_native_data!(Imap, "itertools.imap");

struct Islice {
    iterator: Value,
    next: Cell<i64>,
    stop: Option<i64>,
    step: i64,
    count: Cell<i64>,
}

impl_native_data!(Islice, "itertools.islice");

struct Izip {
    iterators: Vec<Value>,
}

impl_native_data!(Izip, "itertools.izip");

struct IzipLongest {
    /// `None` for exhausted inputs.
    iterators: RefCell<Vec<Option<Value>>>,
    active: Cell<usize>,
    fill_value: Value,
}

impl_native_data!(IzipLongest, "itertools.izip_longest");

struct Starmap {
    function: Value,
    iterator: Value,
}

impl_native_data!(Starmap, "itertools.starmap");

/// Items a group of `tee` iterators read from their shared input.
struct TeeBuffer {
    iterator: Value,
    values: RefCell<Vec<Value>>,
    running: Cell<bool>,
}

struct Tee {
    buffer: Rc<TeeBuffer>,
    index: Cell<usize>,
}

impl_native_data!(Tee, "itertools.tee");

struct Product {
    pools: Vec<Vec<Value>>,
    indices: RefCell<Vec<usize>>,
    result: RefCell<Option<Vec<Value>>>,
    stopped: Cell<bool>,
}

impl_native_data!(Product, "itertools.product");

struct Combinations {
    pool: Vec<Value>,
    indices: RefCell<Vec<usize>>,
    result: RefCell<Option<Vec<Value>>>,
    stopped: Cell<bool>,
}

impl_native_data!(Combinations, "itertools.combinations");

struct CombinationsWithReplacement {
    pool: Vec<Value>,
    r: usize,
    indices: RefCell<Vec<usize>>,
    result: RefCell<Option<Vec<Value>>>,
    stopped: Cell<bool>,
}

impl_native_data!(CombinationsWithReplacement, "itertools.combinations_with_replacement");

struct Permutations {
    pool: Vec<Value>,
    r: usize,
    indices: RefCell<Vec<usize>>,
    cycles: RefCell<Vec<usize>>,
    result: RefCell<Option<Vec<Value>>>,
    stopped: Cell<bool>,
}

impl_native_data!(Permutations, "itertools.permutations");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let types: [(&str, &'static str, TypeFactory); 18] = [
        ("count", "itertools.count", count_type),
        ("cycle", "itertools.cycle", cycle_type),
        ("repeat", "itertools.repeat", repeat_type),
        ("chain", "itertools.chain", chain_type),
        ("compress", "itertools.compress", compress_type),
        ("dropwhile", "itertools.dropwhile", dropwhile_type),
        ("takewhile", "itertools.takewhile", takewhile_type),
        ("groupby", "itertools.groupby", groupby_type),
        ("ifilter", "itertools.ifilter", ifilter_type),
        ("ifilterfalse", "itertools.ifilterfalse", ifilterfalse_type),
        ("imap", "itertools.imap", imap_type),
        ("islice", "itertools.islice", islice_type),
        ("izip", "itertools.izip", izip_type),
        ("izip_longest", "itertools.izip_longest", izip_longest_type),
        ("starmap", "itertools.starmap", starmap_type),
        ("product", "itertools.product", product_type),
        ("combinations", "itertools.combinations", combinations_type),
        ("permutations", "itertools.permutations", permutations_type),
    ];
    for (name, key, create) in types {
        set_attribute(vm, module, name, Value::Object(native_type(vm, key, create)?))?;
    }

    let cwr = native_type(vm, "itertools.combinations_with_replacement", combinations_with_replacement_type)?;
    set_attribute(vm, module, "combinations_with_replacement", Value::Object(cwr))?;

    install_functions(vm, module, &[function("tee", tee)])
}

fn iterator_type(vm: &Vm, name: &'static str, new: fn(&Vm, CallArgs) -> PyResult<Value>, next: fn(&Vm, CallArgs) -> PyResult<Value>, extra: &[MethodSpec]) -> PyResult<ObjectRef> {
    let mut methods = vec![static_method("__new__", new), method("__iter__", iter_self), method("next", next)];
    methods.extend(extra.iter().map(|spec| MethodSpec { name: spec.name, function: spec.function, binding: spec.binding }));

    new_type(vm, TypeSpec { name, module: "itertools", base: None, layout: Layout::Native, instance_dict: false, methods: &methods })
}

fn count_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "count", count_new, count_next, &[method("__repr__", count_repr)])
}

fn cycle_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "cycle", cycle_new, cycle_next, &[])
}

fn repeat_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "repeat", repeat_new, repeat_next, &[method("__repr__", repeat_repr), method("__length_hint__", repeat_length_hint)])
}

fn chain_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "chain", chain_new, chain_next, &[class_method("from_iterable", chain_from_iterable)])
}

fn compress_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "compress", compress_new, compress_next, &[])
}

fn dropwhile_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "dropwhile", dropwhile_new, dropwhile_next, &[])
}

fn takewhile_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "takewhile", takewhile_new, takewhile_next, &[])
}

fn groupby_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "groupby", groupby_new, groupby_next, &[])
}

fn grouper_type(vm: &Vm) -> PyResult<ObjectRef> {
    let methods = [method("__iter__", iter_self), method("next", grouper_next)];

    new_final_type(vm, TypeSpec { name: "_grouper", module: "itertools", base: None, layout: Layout::Native, instance_dict: false, methods: &methods })
}

fn ifilter_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "ifilter", filter_new::<true>, filter_next::<true>, &[])
}

fn ifilterfalse_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "ifilterfalse", filter_new::<false>, filter_next::<false>, &[])
}

fn imap_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "imap", imap_new, imap_next, &[])
}

fn islice_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "islice", islice_new, islice_next, &[])
}

fn izip_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "izip", izip_new, izip_next, &[])
}

fn izip_longest_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "izip_longest", izip_longest_new, izip_longest_next, &[])
}

fn starmap_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "starmap", starmap_new, starmap_next, &[])
}

fn tee_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = iterator_type(vm, "tee", tee_new, tee_next, &[method("__copy__", tee_copy)])?;
    vm.forbid_subclassing(&class);

    Ok(class)
}

fn product_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "product", product_new, product_next, &[])
}

fn combinations_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "combinations", combinations_new, combinations_next, &[])
}

fn combinations_with_replacement_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "combinations_with_replacement", cwr_new, cwr_next, &[])
}

fn permutations_type(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, "permutations", permutations_new, permutations_next, &[])
}

fn iter_self(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    args.positional.first().cloned().ok_or_else(|| vm.type_error("descriptor '__iter__' needs an argument"))
}

/// Splits the class argument off a `__new__` call.
fn class_argument(vm: &Vm, mut args: CallArgs, name: &str) -> PyResult<(ObjectRef, CallArgs)> {
    if args.positional.is_empty() {
        return Err(vm.type_error(&format!("{name}.__new__(): not enough arguments")));
    }

    match args.positional.remove(0) {
        Value::Object(class) if class.as_class().is_some() => Ok((class, args)),
        other => Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(&other)))),
    }
}

/// Rejects keywords, which CPython does only for the exact type.
fn reject_keywords(vm: &Vm, class: &ObjectRef, key: &'static str, create: TypeFactory, args: &CallArgs, name: &str) -> PyResult<()> {
    if !args.has_keywords() || !Rc::ptr_eq(class, &native_type(vm, key, create)?) {
        return Ok(());
    }

    Err(vm.type_error(&format!("{name}() does not take keyword arguments")))
}

/// Positional arguments unpacked by count.
fn unpack_tuple(vm: &Vm, args: CallArgs, name: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    let count = args.positional.len();
    if count < minimum {
        let qualifier = if minimum == maximum { "" } else { "at least " };
        return Err(vm.type_error(&format!("{name} expected {qualifier}{minimum} arguments, got {count}")));
    }
    if count > maximum {
        let qualifier = if minimum == maximum { "" } else { "at most " };
        return Err(vm.type_error(&format!("{name} expected {qualifier}{maximum} arguments, got {count}")));
    }

    Ok(args.positional)
}

/// The `n` format unit.
fn ssize_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    arguments::ssize_argument(vm, value)
}

/// A `ssize_t` conversion: integers, and anything with `__int__`.
fn as_ssize(vm: &Vm, value: &Value) -> PyResult<i64> {
    let overflow = || vm.raise(ExceptionKind::OverflowError, "long int too large to convert to int");

    if let Some(number) = vm.as_float(value) {
        if number.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        }
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        return number.trunc().to_i64().ok_or_else(overflow);
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(number),
        Some(Integral::Long(number)) => number.to_i64().ok_or_else(overflow),
        None => {
            let Some(conversion) = vm.user_override(value, "__int__")? else {
                return Err(vm.type_error("an integer is required"));
            };
            let result = vm.call0(&conversion)?;
            match vm.as_integral(&result) {
                Some(Integral::Int(number)) => Ok(number),
                Some(Integral::Long(number)) => number.to_i64().ok_or_else(overflow),
                None => Err(vm.type_error("an integer is required")),
            }
        }
    }
}

/// A `ssize_t` conversion where CPython clears a raised error and reports -1.
fn as_ssize_or_minus_one(vm: &Vm, value: &Value) -> PyResult<i64> {
    match as_ssize(vm, value) {
        Ok(number) => Ok(number),
        Err(Signal::Raise(_)) => Ok(-1),
        Err(signal) => Err(signal),
    }
}

/// Converts an iterable to a tuple.
fn tuple_items(vm: &Vm, iterable: &Value) -> PyResult<Vec<Value>> {
    vm.collect(iterable)
}

/// Equality comparison as a truth value, which treats identical objects
/// as equal.
fn same_or_equal(vm: &Vm, left: &Value, right: &Value) -> PyResult<bool> {
    if vm.is_same(left, right) {
        return Ok(true);
    }

    vm.equals(left, right)
}

/// Whether a value is a number.
fn is_number(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.is_number(value) || value.is_unknown() {
        return Ok(true);
    }

    Ok(vm.user_override(value, "__int__")?.is_some() || vm.user_override(value, "__float__")?.is_some())
}

/// `itertools.count.__new__`.
fn count_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "count")?;
    let slots = parse(vm, args, "count", &["start", "step"], 0)?;
    let mut slots = slots.into_iter();
    let start = slots.next().flatten();
    let step = slots.next().flatten();

    for value in [&start, &step].into_iter().flatten() {
        if !is_number(vm, value)? {
            return Err(vm.type_error("a number is required"));
        }
    }

    let fast_start = match &start {
        None => Some(0),
        Some(value) => match vm.as_integral(value) {
            Some(Integral::Int(number)) => Some(number),
            _ => None,
        },
    };
    let unit_step = match &step {
        None => true,
        Some(value) => matches!(vm.as_integral(value), Some(Integral::Int(1))),
    };

    let state = match (fast_start, unit_step) {
        (Some(number), true) => CountState::Fast(number),
        _ => CountState::Slow { count: start.unwrap_or(Value::Int(0)), step: step.unwrap_or(Value::Int(1)) },
    };

    Ok(new_native_object(vm, &class, Count { state: RefCell::new(state) }))
}

fn count_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let count = this::<Count>(vm, &args, "itertools.count", "next")?;

    let (current, step) = {
        let mut state = count.state.borrow_mut();
        match &mut *state {
            CountState::Fast(number) => {
                if let Some(following) = number.checked_add(1) {
                    let current = *number;
                    *number = following;
                    return Ok(vm.new_int_from_i64(current));
                }
                (vm.new_int_from_i64(*number), Value::Int(1))
            }
            CountState::Slow { count, step } => (count.clone(), step.clone()),
        }
    };

    let following = vm.binary_op(BinaryOp::Add, &current, &step)?;
    *count.state.borrow_mut() = CountState::Slow { count: following, step };

    Ok(current)
}

fn count_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let count = this::<Count>(vm, &args, "itertools.count", "__repr__")?;

    let (current, step) = match &*count.state.borrow() {
        CountState::Fast(number) => return Ok(Value::str(&format!("count({number})"))),
        CountState::Slow { count, step } => (count.clone(), step.clone()),
    };

    let current = vm.repr_text(&current)?;
    let text = if matches!(vm.as_integral(&step), Some(Integral::Int(1))) && vm.as_float(&step).is_none() {
        format!("count({current})")
    } else {
        format!("count({current}, {})", vm.repr_text(&step)?)
    };

    Ok(Value::str(&text))
}

/// `itertools.cycle.__new__`.
fn cycle_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "cycle")?;
    reject_keywords(vm, &class, "itertools.cycle", cycle_type, &args, "cycle")?;
    let arguments = unpack_tuple(vm, args, "cycle", 1, 1)?;
    let Some(iterable) = arguments.first() else {
        return Err(vm.type_error("cycle expected 1 arguments, got 0"));
    };

    let iterator = vm.iter(iterable)?;

    Ok(new_native_object(vm, &class, Cycle { iterator, saved: RefCell::new(Vec::new()), replay: Cell::new(None) }))
}

fn cycle_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let cycle = this::<Cycle>(vm, &args, "itertools.cycle", "next")?;

    if let Some(position) = cycle.replay.get() {
        let saved = cycle.saved.borrow();
        let index = position % saved.len().max(1);
        let item = saved.get(index).cloned();
        cycle.replay.set(Some(index + 1));
        return iterator_result(vm, item);
    }

    if let Some(item) = vm.next(&cycle.iterator)? {
        cycle.saved.borrow_mut().push(item.clone());
        return Ok(item);
    }

    let first = cycle.saved.borrow().first().cloned();
    if first.is_some() {
        cycle.replay.set(Some(1));
    }

    iterator_result(vm, first)
}

/// `itertools.repeat.__new__`.
fn repeat_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "repeat")?;
    let slots = parse(vm, args, "repeat", &["object", "times"], 1)?;
    let mut slots = slots.into_iter();
    let element = slots.next().flatten().unwrap_or(Value::None);

    let remaining = match slots.next().flatten() {
        None => None,
        Some(Value::Unknown(unknown)) => return Ok(Value::Unknown(unknown)),
        Some(times) => Some(ssize_argument(vm, &times)?.max(0)),
    };

    Ok(new_native_object(vm, &class, Repeat { element, remaining: Cell::new(remaining) }))
}

fn repeat_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let repeat = this::<Repeat>(vm, &args, "itertools.repeat", "next")?;

    match repeat.remaining.get() {
        None => Ok(repeat.element.clone()),
        Some(0) => Err(stop_iteration(vm)),
        Some(count) => {
            repeat.remaining.set(Some(count - 1));
            Ok(repeat.element.clone())
        }
    }
}

fn repeat_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let repeat = this::<Repeat>(vm, &args, "itertools.repeat", "__repr__")?;

    let element = vm.repr_text(&repeat.element)?;
    let text = match repeat.remaining.get() {
        None => format!("repeat({element})"),
        Some(count) => format!("repeat({element}, {count})"),
    };

    Ok(Value::str(&text))
}

fn repeat_length_hint(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let repeat = this::<Repeat>(vm, &args, "itertools.repeat", "__length_hint__")?;

    match repeat.remaining.get() {
        None => Err(vm.type_error("len() of unsized object")),
        Some(count) => Ok(vm.new_int_from_i64(count)),
    }
}

/// `itertools.chain.__new__`.
fn chain_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "chain")?;
    reject_keywords(vm, &class, "itertools.chain", chain_type, &args, "chain")?;

    let source = vm.iter(&Value::tuple(args.positional))?;

    Ok(new_native_object(vm, &class, Chain { source: RefCell::new(Some(source)), active: RefCell::new(None) }))
}

/// `chain.from_iterable`.
fn chain_from_iterable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "chain")?;
    let [iterable] = <[Value; 1]>::try_from(args.positional).map_err(|given| vm.type_error(&format!("from_iterable() takes exactly one argument ({} given)", given.len())))?;

    let source = vm.iter(&iterable)?;

    Ok(new_native_object(vm, &class, Chain { source: RefCell::new(Some(source)), active: RefCell::new(None) }))
}

fn chain_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let chain = this::<Chain>(vm, &args, "itertools.chain", "next")?;

    loop {
        let active = chain.active.borrow().clone();
        let active = match active {
            Some(active) => active,
            None => {
                let Some(source) = chain.source.borrow().clone() else {
                    return Err(stop_iteration(vm));
                };
                let Some(iterable) = vm.next(&source)? else {
                    *chain.source.borrow_mut() = None;
                    return Err(stop_iteration(vm));
                };
                let active = match vm.iter(&iterable) {
                    Ok(active) => active,
                    Err(error) => {
                        *chain.source.borrow_mut() = None;
                        return Err(error);
                    }
                };
                *chain.active.borrow_mut() = Some(active.clone());
                active
            }
        };

        if let Some(item) = vm.next(&active)? {
            return Ok(item);
        }
        *chain.active.borrow_mut() = None;
    }
}

/// `itertools.compress.__new__`.
fn compress_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "compress")?;
    let slots = parse(vm, args, "compress", &["data", "selectors"], 2)?;
    let [Some(data), Some(selectors)] = <[Option<Value>; 2]>::try_from(slots).map_err(|_| vm.type_error("compress() argument binding failed"))? else {
        return Err(vm.type_error("compress() argument binding failed"));
    };

    let data = vm.iter(&data)?;
    let selectors = vm.iter(&selectors)?;

    Ok(new_native_object(vm, &class, Compress { data, selectors }))
}

fn compress_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let compress = this::<Compress>(vm, &args, "itertools.compress", "next")?;

    loop {
        let Some(datum) = vm.next(&compress.data)? else {
            return Err(stop_iteration(vm));
        };
        let Some(selector) = vm.next(&compress.selectors)? else {
            return Err(stop_iteration(vm));
        };
        if vm.truthy(&selector, "itertools.compress selector")? {
            return Ok(datum);
        }
    }
}

/// The predicate and iterator of `dropwhile`, `takewhile`, `ifilter`,
/// `ifilterfalse`, and `starmap`.
fn function_and_iterator(vm: &Vm, class: &ObjectRef, key: &'static str, create: TypeFactory, args: CallArgs, name: &str) -> PyResult<(Value, Value)> {
    reject_keywords(vm, class, key, create, &args, name)?;
    let arguments = unpack_tuple(vm, args, name, 2, 2)?;
    let [function, iterable] = <[Value; 2]>::try_from(arguments).map_err(|_| vm.type_error(&format!("{name} expected 2 arguments")))?;

    let iterator = vm.iter(&iterable)?;

    Ok((function, iterator))
}

fn dropwhile_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "dropwhile")?;
    let (predicate, iterator) = function_and_iterator(vm, &class, "itertools.dropwhile", dropwhile_type, args, "dropwhile")?;

    Ok(new_native_object(vm, &class, DropWhile { predicate, iterator, dropped: Cell::new(false) }))
}

fn dropwhile_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let dropwhile = this::<DropWhile>(vm, &args, "itertools.dropwhile", "next")?;

    loop {
        let Some(item) = vm.next(&dropwhile.iterator)? else {
            return Err(stop_iteration(vm));
        };
        if dropwhile.dropped.get() {
            return Ok(item);
        }

        let verdict = vm.call1(&dropwhile.predicate, item.clone())?;
        if !vm.truthy(&verdict, "itertools.dropwhile predicate")? {
            dropwhile.dropped.set(true);
            return Ok(item);
        }
    }
}

fn takewhile_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "takewhile")?;
    let (predicate, iterator) = function_and_iterator(vm, &class, "itertools.takewhile", takewhile_type, args, "takewhile")?;

    Ok(new_native_object(vm, &class, TakeWhile { predicate, iterator, stopped: Cell::new(false) }))
}

fn takewhile_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let takewhile = this::<TakeWhile>(vm, &args, "itertools.takewhile", "next")?;

    if takewhile.stopped.get() {
        return Err(stop_iteration(vm));
    }

    let Some(item) = vm.next(&takewhile.iterator)? else {
        return Err(stop_iteration(vm));
    };

    let verdict = vm.call1(&takewhile.predicate, item.clone())?;
    if vm.truthy(&verdict, "itertools.takewhile predicate")? {
        return Ok(item);
    }
    takewhile.stopped.set(true);

    Err(stop_iteration(vm))
}

/// `ifilter.__new__` and `ifilterfalse.__new__`.
fn filter_new<const KEEP: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    Filter<KEEP>: NativeData,
{
    let (name, key, create): (&str, &'static str, TypeFactory) = if KEEP { ("ifilter", "itertools.ifilter", ifilter_type) } else { ("ifilterfalse", "itertools.ifilterfalse", ifilterfalse_type) };
    let (class, args) = class_argument(vm, args, name)?;
    let (function, iterator) = function_and_iterator(vm, &class, key, create, args, name)?;

    Ok(new_native_object(vm, &class, Filter::<KEEP> { function, iterator }))
}

fn filter_next<const KEEP: bool>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    Filter<KEEP>: NativeData,
{
    let type_name = if KEEP { "itertools.ifilter" } else { "itertools.ifilterfalse" };
    let filter = this::<Filter<KEEP>>(vm, &args, type_name, "next")?;

    // CPython tests items directly for None and for `bool` itself.
    let direct = filter.function.is_none() || matches!(&filter.function, Value::Object(object) if Rc::ptr_eq(object, &vm.types().bool));

    loop {
        let Some(item) = vm.next(&filter.iterator)? else {
            return Err(stop_iteration(vm));
        };

        let verdict = if direct { item.clone() } else { vm.call1(&filter.function, item.clone())? };
        if vm.truthy(&verdict, type_name)? == KEEP {
            return Ok(item);
        }
    }
}

/// `itertools.groupby.__new__`.
fn groupby_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "groupby")?;
    let slots = parse(vm, args, "groupby", &["iterable", "key"], 1)?;
    let mut slots = slots.into_iter();
    let iterable = slots.next().flatten().unwrap_or(Value::None);
    let key = slots.next().flatten().unwrap_or(Value::None);

    let iterator = vm.iter(&iterable)?;
    let data = GroupBy { iterator, key, target_key: RefCell::new(None), current_key: RefCell::new(None), current_value: RefCell::new(None) };

    Ok(new_native_object(vm, &class, data))
}

impl GroupBy {
    /// Reads the next input item into `current_key` and `current_value`;
    /// `false` when the input is exhausted.
    fn advance(&self, vm: &Vm) -> PyResult<bool> {
        let Some(value) = vm.next(&self.iterator)? else {
            return Ok(false);
        };

        let key = if self.key.is_none() { value.clone() } else { vm.call1(&self.key, value.clone())? };
        *self.current_key.borrow_mut() = Some(key);
        *self.current_value.borrow_mut() = Some(value);

        Ok(true)
    }
}

fn groupby_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let receiver = args.positional.first().cloned().unwrap_or(Value::None);
    let groupby = this::<GroupBy>(vm, &args, "itertools.groupby", "next")?;

    // Skip to the next group.
    loop {
        let current = groupby.current_key.borrow().clone();
        let target = groupby.target_key.borrow().clone();
        if let Some(current) = current {
            let Some(target) = target else {
                break;
            };
            if !same_or_equal(vm, &target, &current)? {
                break;
            }
        }
        if !groupby.advance(vm)? {
            return Err(stop_iteration(vm));
        }
    }

    let key = groupby.current_key.borrow().clone().unwrap_or(Value::None);
    *groupby.target_key.borrow_mut() = Some(key.clone());

    let class = native_type(vm, "itertools._grouper", grouper_type)?;
    let grouper = new_native_object(vm, &class, Grouper { parent: receiver, target_key: key.clone() });

    Ok(Value::tuple(vec![key, grouper]))
}

fn grouper_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let grouper = this::<Grouper>(vm, &args, "itertools._grouper", "next")?;
    let Some(groupby) = native_data::<GroupBy>(&grouper.parent) else {
        return Err(vm.type_error("_grouper parent is not a groupby object"));
    };

    if groupby.current_value.borrow().is_none() && !groupby.advance(vm)? {
        return Err(stop_iteration(vm));
    }

    let current = groupby.current_key.borrow().clone().unwrap_or(Value::None);
    if !same_or_equal(vm, &grouper.target_key, &current)? {
        return Err(stop_iteration(vm));
    }

    *groupby.current_key.borrow_mut() = None;
    let value = groupby.current_value.borrow_mut().take();

    iterator_result(vm, value)
}

/// `itertools.imap.__new__`.
fn imap_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "imap")?;
    reject_keywords(vm, &class, "itertools.imap", imap_type, &args, "imap")?;
    if args.positional.len() < 2 {
        return Err(vm.type_error("imap() must have at least two arguments."));
    }

    let mut arguments = args.positional.into_iter();
    let function = arguments.next().unwrap_or(Value::None);
    let iterators = arguments.map(|iterable| vm.iter(&iterable)).collect::<PyResult<Vec<_>>>()?;

    Ok(new_native_object(vm, &class, Imap { function, iterators }))
}

fn imap_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let imap = this::<Imap>(vm, &args, "itertools.imap", "next")?;

    let mut items = Vec::with_capacity(imap.iterators.len());
    for iterator in &imap.iterators {
        let Some(item) = vm.next(iterator)? else {
            return Err(stop_iteration(vm));
        };
        items.push(item);
    }

    if imap.function.is_none() {
        return Ok(Value::tuple(items));
    }

    vm.call(&imap.function, CallArgs::new(items))
}

/// `itertools.islice.__new__`.
fn islice_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const STOP_MESSAGE: &str = "Stop argument for islice() must be None or an integer: 0 <= x <= maxint.";

    let (class, args) = class_argument(vm, args, "islice")?;
    reject_keywords(vm, &class, "itertools.islice", islice_type, &args, "islice")?;
    let arguments = unpack_tuple(vm, args, "islice", 2, 4)?;
    if let Some(Value::Unknown(unknown)) = arguments.iter().skip(1).find(|value| value.is_unknown()) {
        return Ok(Value::Unknown(Rc::clone(unknown)));
    }

    let mut arguments = arguments.into_iter();
    let iterable = arguments.next().unwrap_or(Value::None);
    let first = arguments.next().unwrap_or(Value::None);
    let second = arguments.next();
    let third = arguments.next();

    // CPython marks an absent stop with -1, so an explicit -1 is rejected.
    let parse_stop = |value: &Value| -> PyResult<i64> {
        if value.is_none() {
            return Ok(-1);
        }
        match as_ssize_or_minus_one(vm, value)? {
            -1 => Err(vm.raise(ExceptionKind::ValueError, STOP_MESSAGE)),
            stop => Ok(stop),
        }
    };

    let (start, stop) = match &second {
        None => (0, parse_stop(&first)?),
        Some(second) => {
            let start = if first.is_none() { 0 } else { as_ssize_or_minus_one(vm, &first)? };
            (start, parse_stop(second)?)
        }
    };
    if start < 0 || stop < -1 {
        return Err(vm.raise(ExceptionKind::ValueError, "Indices for islice() must be None or an integer: 0 <= x <= maxint."));
    }

    let step = match &third {
        Some(value) if !value.is_none() => as_ssize_or_minus_one(vm, value)?,
        _ => 1,
    };
    if step < 1 {
        return Err(vm.raise(ExceptionKind::ValueError, "Step for islice() must be a positive integer or None."));
    }

    let iterator = vm.iter(&iterable)?;
    let stop = if stop == -1 { None } else { Some(stop) };

    Ok(new_native_object(vm, &class, Islice { iterator, next: Cell::new(start), stop, step, count: Cell::new(0) }))
}

fn islice_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let islice = this::<Islice>(vm, &args, "itertools.islice", "next")?;

    while islice.count.get() < islice.next.get() {
        if vm.next(&islice.iterator)?.is_none() {
            return Err(stop_iteration(vm));
        }
        islice.count.set(islice.count.get() + 1);
    }

    if islice.stop.is_some_and(|stop| islice.count.get() >= stop) {
        return Err(stop_iteration(vm));
    }

    let Some(item) = vm.next(&islice.iterator)? else {
        return Err(stop_iteration(vm));
    };
    islice.count.set(islice.count.get() + 1);

    let following = match (islice.next.get().checked_add(islice.step), islice.stop) {
        (Some(following), Some(stop)) if following > stop => stop,
        (None, Some(stop)) => stop,
        (Some(following), _) => following,
        (None, None) => i64::MAX,
    };
    islice.next.set(following);

    Ok(item)
}

/// The iterators of `izip` and `izip_longest` arguments.
fn argument_iterators(vm: &Vm, arguments: &[Value], name: &str) -> PyResult<Vec<Value>> {
    let mut iterators = Vec::with_capacity(arguments.len());
    for (index, iterable) in arguments.iter().enumerate() {
        match vm.iter(iterable) {
            Ok(iterator) => iterators.push(iterator),
            Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => {
                return Err(vm.type_error(&format!("{name} argument #{} must support iteration", index + 1)));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(iterators)
}

/// `itertools.izip.__new__`.
fn izip_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "izip")?;
    reject_keywords(vm, &class, "itertools.izip", izip_type, &args, "izip")?;

    let iterators = argument_iterators(vm, &args.positional, "izip")?;

    Ok(new_native_object(vm, &class, Izip { iterators }))
}

fn izip_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let izip = this::<Izip>(vm, &args, "itertools.izip", "next")?;

    if izip.iterators.is_empty() {
        return Err(stop_iteration(vm));
    }

    let mut items = Vec::with_capacity(izip.iterators.len());
    for iterator in &izip.iterators {
        let Some(item) = vm.next(iterator)? else {
            return Err(stop_iteration(vm));
        };
        items.push(item);
    }

    Ok(Value::tuple(items))
}

/// `itertools.izip_longest.__new__`.
fn izip_longest_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "izip_longest")?;

    let fill_value = if !args.has_keywords() {
        Value::None
    } else {
        match args.keyword("fillvalue") {
            Some(value) if args.keywords.len() == 1 => value.clone(),
            _ => return Err(vm.type_error("izip_longest() got an unexpected keyword argument")),
        }
    };

    let iterators = argument_iterators(vm, &args.positional, "izip_longest")?;
    let active = iterators.len();
    let data = IzipLongest { iterators: RefCell::new(iterators.into_iter().map(Some).collect()), active: Cell::new(active), fill_value };

    Ok(new_native_object(vm, &class, data))
}

fn izip_longest_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let izip = this::<IzipLongest>(vm, &args, "itertools.izip_longest", "next")?;

    let count = izip.iterators.borrow().len();
    if count == 0 || izip.active.get() == 0 {
        return Err(stop_iteration(vm));
    }

    let mut items = Vec::with_capacity(count);
    for index in 0..count {
        let iterator = izip.iterators.borrow().get(index).cloned().flatten();
        let Some(iterator) = iterator else {
            items.push(izip.fill_value.clone());
            continue;
        };

        let item = match vm.next(&iterator) {
            Ok(item) => item,
            Err(error) => {
                izip.active.set(0);
                return Err(error);
            }
        };
        match item {
            Some(item) => items.push(item),
            None => {
                let active = izip.active.get() - 1;
                izip.active.set(active);
                if active == 0 {
                    return Err(stop_iteration(vm));
                }
                if let Some(slot) = izip.iterators.borrow_mut().get_mut(index) {
                    *slot = None;
                }
                items.push(izip.fill_value.clone());
            }
        }
    }

    Ok(Value::tuple(items))
}

/// `itertools.starmap.__new__`.
fn starmap_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "starmap")?;
    let (function, iterator) = function_and_iterator(vm, &class, "itertools.starmap", starmap_type, args, "starmap")?;

    Ok(new_native_object(vm, &class, Starmap { function, iterator }))
}

fn starmap_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let starmap = this::<Starmap>(vm, &args, "itertools.starmap", "next")?;

    let Some(arguments) = vm.next(&starmap.iterator)? else {
        return Err(stop_iteration(vm));
    };

    let arguments = match &arguments {
        Value::Tuple(items) => items.to_vec(),
        _ => tuple_items(vm, &arguments)?,
    };

    vm.call(&starmap.function, CallArgs::new(arguments))
}

/// `tee` of an arbitrary iterable.
fn tee_from_iterable(vm: &Vm, iterable: &Value) -> PyResult<Value> {
    let iterator = vm.iter(iterable)?;
    if let Some(tee) = native_data::<Tee>(&iterator) {
        return new_tee(vm, Rc::clone(&tee.buffer), tee.index.get());
    }

    let buffer = TeeBuffer { iterator, values: RefCell::new(Vec::new()), running: Cell::new(false) };

    new_tee(vm, Rc::new(buffer), 0)
}

fn new_tee(vm: &Vm, buffer: Rc<TeeBuffer>, index: usize) -> PyResult<Value> {
    let class = native_type(vm, "itertools.tee", tee_type)?;

    Ok(new_native_object(vm, &class, Tee { buffer, index: Cell::new(index) }))
}

/// `itertools.tee.__new__`.
fn tee_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_class, args) = class_argument(vm, args, "tee")?;
    let count = args.positional.len();
    let [iterable] = <[Value; 1]>::try_from(args.positional).map_err(|_| vm.type_error(&format!("tee() takes exactly 1 argument ({count} given)")))?;

    tee_from_iterable(vm, &iterable)
}

fn tee_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let tee = this::<Tee>(vm, &args, "itertools.tee", "next")?;
    let buffer = &tee.buffer;
    let index = tee.index.get();

    let buffered = buffer.values.borrow().get(index).cloned();
    let item = match buffered {
        Some(item) => item,
        None => {
            if buffer.running.get() {
                return Err(vm.raise(ExceptionKind::RuntimeError, "cannot re-enter the tee iterator"));
            }
            buffer.running.set(true);
            let item = vm.next(&buffer.iterator);
            buffer.running.set(false);
            let Some(item) = item? else {
                return Err(stop_iteration(vm));
            };
            buffer.values.borrow_mut().push(item.clone());
            item
        }
    };
    tee.index.set(index + 1);

    Ok(item)
}

fn tee_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let tee = this::<Tee>(vm, &args, "itertools.tee", "__copy__")?;

    new_tee(vm, Rc::clone(&tee.buffer), tee.index.get())
}

/// `tee(iterable, n=2)`.
fn tee(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("tee() takes no keyword arguments"));
    }

    let count = args.positional.len();
    if count == 0 {
        return Err(vm.type_error("function takes at least 1 argument (0 given)"));
    }
    if count > 2 {
        return Err(vm.type_error(&format!("function takes at most 2 arguments ({count} given)")));
    }

    let mut arguments = args.positional.into_iter();
    let iterable = arguments.next().unwrap_or(Value::None);
    let copies = match arguments.next() {
        None => 2,
        Some(Value::Unknown(unknown)) => return Ok(Value::Unknown(unknown)),
        Some(value) => ssize_argument(vm, &value)?,
    };
    if copies < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "n must be >= 0"));
    }
    if copies == 0 {
        return Ok(Value::tuple(Vec::new()));
    }

    let iterator = vm.iter(&iterable)?;
    let mut copyable = match vm.lookup_special(&iterator, "__copy__")? {
        Some(_) => iterator,
        None => tee_from_iterable(vm, &iterator)?,
    };

    let mut result = vec![copyable.clone()];
    for _ in 1..copies {
        copyable = vm.call_method(&copyable, "__copy__", Vec::new())?;
        result.push(copyable.clone());
    }

    Ok(Value::tuple(result))
}

/// `itertools.product.__new__`.
fn product_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "product")?;

    let repeat = if !args.has_keywords() {
        1
    } else {
        let keywords = CallArgs { positional: Vec::new(), keywords: args.keywords, keyword_dict: args.keyword_dict };
        match parse(vm, keywords, "product", &["repeat"], 0)?.into_iter().next().flatten() {
            None => 1,
            Some(Value::Unknown(unknown)) => return Ok(Value::Unknown(unknown)),
            Some(value) => ssize_argument(vm, &value)?,
        }
    };
    let Ok(repeat) = usize::try_from(repeat) else {
        return Err(vm.raise(ExceptionKind::ValueError, "repeat argument cannot be negative"));
    };

    let mut pools = Vec::with_capacity(args.positional.len());
    for iterable in &args.positional {
        pools.push(tuple_items(vm, iterable)?);
    }
    let pools: Vec<Vec<Value>> = (0..repeat).flat_map(|_| pools.iter().cloned()).collect();

    let indices = vec![0; pools.len()];
    let data = Product { pools, indices: RefCell::new(indices), result: RefCell::new(None), stopped: Cell::new(false) };

    Ok(new_native_object(vm, &class, data))
}

fn product_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let product = this::<Product>(vm, &args, "itertools.product", "next")?;

    if product.stopped.get() {
        return Err(stop_iteration(vm));
    }

    let mut result = product.result.borrow_mut();
    let mut indices = product.indices.borrow_mut();
    let Some(current) = result.as_mut() else {
        let first: Option<Vec<Value>> = product.pools.iter().map(|pool| pool.first().cloned()).collect();
        let Some(first) = first else {
            product.stopped.set(true);
            return Err(stop_iteration(vm));
        };
        *result = Some(first.clone());
        return Ok(Value::tuple(first));
    };

    // Advance the indices right to left, like an odometer.
    let mut advanced = false;
    for position in (0..product.pools.len()).rev() {
        let (Some(pool), Some(index), Some(slot)) = (product.pools.get(position), indices.get_mut(position), current.get_mut(position)) else {
            break;
        };
        *index += 1;
        if let Some(item) = pool.get(*index) {
            *slot = item.clone();
            advanced = true;
            break;
        }
        *index = 0;
        if let Some(item) = pool.first() {
            *slot = item.clone();
        }
    }

    if !advanced {
        product.stopped.set(true);
        return Err(stop_iteration(vm));
    }

    Ok(Value::tuple(current.clone()))
}

/// The pool and length of `combinations` and
/// `combinations_with_replacement`.
fn pool_and_length(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Option<(Vec<Value>, usize)>> {
    let slots = parse(vm, args, name, &["iterable", "r"], 2)?;
    let [Some(iterable), Some(length)] = <[Option<Value>; 2]>::try_from(slots).map_err(|_| vm.type_error(&format!("{name}() argument binding failed")))? else {
        return Err(vm.type_error(&format!("{name}() argument binding failed")));
    };
    if length.is_unknown() {
        return Ok(None);
    }

    let length = ssize_argument(vm, &length)?;
    let pool = tuple_items(vm, &iterable)?;
    let Ok(length) = usize::try_from(length) else {
        return Err(vm.raise(ExceptionKind::ValueError, "r must be non-negative"));
    };

    Ok(Some((pool, length)))
}

/// `itertools.combinations.__new__`.
fn combinations_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "combinations")?;
    let Some((pool, r)) = pool_and_length(vm, args, "combinations")? else {
        return Ok(Value::unknown("itertools.combinations"));
    };

    let stopped = r > pool.len();
    let data = Combinations { pool, indices: RefCell::new((0..r).collect()), result: RefCell::new(None), stopped: Cell::new(stopped) };

    Ok(new_native_object(vm, &class, data))
}

/// The pool items at `indices`.
fn select(pool: &[Value], indices: &[usize]) -> Vec<Value> {
    indices.iter().filter_map(|&index| pool.get(index).cloned()).collect()
}

fn combinations_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let combinations = this::<Combinations>(vm, &args, "itertools.combinations", "next")?;

    if combinations.stopped.get() {
        return Err(stop_iteration(vm));
    }

    let mut result = combinations.result.borrow_mut();
    let mut indices = combinations.indices.borrow_mut();
    if result.is_none() {
        let first = select(&combinations.pool, &indices);
        *result = Some(first.clone());
        return Ok(Value::tuple(first));
    }

    // Find the rightmost index not at its maximum, `i + n - r`.
    let n = combinations.pool.len();
    let r = indices.len();
    let Some(position) = (0..r).rev().find(|&position| indices.get(position).is_some_and(|&index| index != position + n - r)) else {
        combinations.stopped.set(true);
        return Err(stop_iteration(vm));
    };

    if let Some(index) = indices.get_mut(position) {
        *index += 1;
    }
    for following in position + 1..r {
        let previous = indices.get(following - 1).copied().unwrap_or(0);
        if let Some(index) = indices.get_mut(following) {
            *index = previous + 1;
        }
    }

    let current = select(&combinations.pool, &indices);
    *result = Some(current.clone());

    Ok(Value::tuple(current))
}

/// `itertools.combinations_with_replacement.__new__`.
fn cwr_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "combinations_with_replacement")?;
    let Some((pool, r)) = pool_and_length(vm, args, "combinations_with_replacement")? else {
        return Ok(Value::unknown("itertools.combinations_with_replacement"));
    };

    let stopped = pool.is_empty() && r > 0;
    let data = CombinationsWithReplacement { pool, r, indices: RefCell::new(vec![0; r]), result: RefCell::new(None), stopped: Cell::new(stopped) };

    Ok(new_native_object(vm, &class, data))
}

fn cwr_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let cwr = this::<CombinationsWithReplacement>(vm, &args, "itertools.combinations_with_replacement", "next")?;

    if cwr.stopped.get() {
        return Err(stop_iteration(vm));
    }

    let mut result = cwr.result.borrow_mut();
    let mut indices = cwr.indices.borrow_mut();
    if result.is_none() {
        let first = select(&cwr.pool, &indices);
        *result = Some(first.clone());
        return Ok(Value::tuple(first));
    }

    // Find the rightmost index not at its maximum, `n - 1`.
    let n = cwr.pool.len();
    let Some(position) = (0..cwr.r).rev().find(|&position| indices.get(position).is_some_and(|&index| index + 1 != n)) else {
        cwr.stopped.set(true);
        return Err(stop_iteration(vm));
    };

    let value = indices.get(position).copied().unwrap_or(0) + 1;
    for index in indices.iter_mut().skip(position) {
        *index = value;
    }

    let current = select(&cwr.pool, &indices);
    *result = Some(current.clone());

    Ok(Value::tuple(current))
}

/// `itertools.permutations.__new__`.
fn permutations_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (class, args) = class_argument(vm, args, "permutations")?;
    let slots = parse(vm, args, "permutations", &["iterable", "r"], 1)?;
    let mut slots = slots.into_iter();
    let iterable = slots.next().flatten().unwrap_or(Value::None);
    let length = slots.next().flatten().unwrap_or(Value::None);

    let pool = tuple_items(vm, &iterable)?;
    let n = pool.len();
    let r = match &length {
        Value::None => n,
        Value::Unknown(unknown) => return Ok(Value::Unknown(Rc::clone(unknown))),
        value => {
            let Ok(r) = usize::try_from(as_ssize(vm, value)?) else {
                return Err(vm.raise(ExceptionKind::ValueError, "r must be non-negative"));
            };
            r
        }
    };

    let cycles = (0..r.min(n)).map(|index| n - index).collect();
    let data = Permutations { pool, r, indices: RefCell::new((0..n).collect()), cycles: RefCell::new(cycles), result: RefCell::new(None), stopped: Cell::new(r > n) };

    Ok(new_native_object(vm, &class, data))
}

fn permutations_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let permutations = this::<Permutations>(vm, &args, "itertools.permutations", "next")?;

    if permutations.stopped.get() {
        return Err(stop_iteration(vm));
    }

    let r = permutations.r;
    let mut result = permutations.result.borrow_mut();
    let mut indices = permutations.indices.borrow_mut();
    let mut cycles = permutations.cycles.borrow_mut();
    if result.is_none() {
        let first = select(&permutations.pool, indices.get(..r).unwrap_or_default());
        *result = Some(first.clone());
        return Ok(Value::tuple(first));
    }

    let n = permutations.pool.len();
    let mut advanced = false;
    for position in (0..r).rev() {
        let Some(cycle) = cycles.get_mut(position) else {
            break;
        };
        *cycle -= 1;
        if *cycle == 0 {
            // Rotate `indices[position..]` left by one.
            if let Some(tail) = indices.get_mut(position..) {
                tail.rotate_left(1);
            }
            *cycle = n - position;
            continue;
        }

        let swap_with = n - *cycle;
        indices.swap(position, swap_with);
        advanced = true;
        break;
    }

    if !advanced {
        permutations.stopped.set(true);
        return Err(stop_iteration(vm));
    }

    let current = select(&permutations.pool, indices.get(..r).unwrap_or_default());
    *result = Some(current.clone());

    Ok(Value::tuple(current))
}
