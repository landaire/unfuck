use std::rc::Rc;

use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeIterator;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Installs methods of the builtin value types.
pub fn install_type_methods(vm: &Vm) -> PyResult<()> {
    crate::interp::builtins::text::install(vm)?;
    crate::interp::builtins::containers::install(vm)?;
    crate::interp::builtins::numeric::install(vm)?;
    crate::interp::builtins::collections::install_types(vm)
}

pub fn repr_bytes(bytes: &[u8]) -> String {
    crate::interp::builtins::text::repr_bytes(bytes)
}

pub fn repr_unicode(units: &[u16]) -> String {
    crate::interp::builtins::text::repr_unicode(units)
}

pub fn populate(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let types = vm.types();

    install_functions(
        vm,
        module,
        &[
            function("__import__", builtin_import),
            function("abs", builtin_abs),
            function("all", builtin_all),
            function("any", builtin_any),
            function("apply", builtin_apply),
            function("bin", builtin_bin),
            function("callable", builtin_callable),
            function("chr", builtin_chr),
            function("cmp", builtin_cmp),
            function("coerce", builtin_coerce),
            function("compile", crate::interp::builtins::compile::builtin_compile),
            function("delattr", builtin_delattr),
            function("dir", builtin_dir),
            function("divmod", builtin_divmod),
            function("eval", crate::interp::builtins::exec::builtin_eval),
            function("execfile", crate::interp::builtins::exec::builtin_execfile),
            function("filter", builtin_filter),
            function("format", builtin_format),
            function("getattr", builtin_getattr),
            function("globals", builtin_globals),
            function("hasattr", builtin_hasattr),
            function("hash", builtin_hash),
            function("hex", builtin_hex),
            function("id", builtin_id),
            function("input", builtin_unsupported_input),
            function("intern", builtin_intern),
            function("isinstance", builtin_isinstance),
            function("issubclass", builtin_issubclass),
            function("iter", builtin_iter),
            function("len", builtin_len),
            function("locals", crate::interp::builtins::exec::builtin_locals),
            function("map", builtin_map),
            function("max", builtin_max),
            function("min", builtin_min),
            function("next", builtin_next),
            function("oct", builtin_oct),
            function("open", builtin_open),
            function("ord", builtin_ord),
            function("print", builtin_print),
            function("pow", builtin_pow),
            function("range", builtin_range),
            function("raw_input", builtin_unsupported_input),
            function("reduce", builtin_reduce),
            function("reload", builtin_reload),
            function("repr", builtin_repr),
            function("round", builtin_round),
            function("setattr", builtin_setattr),
            function("sorted", builtin_sorted),
            function("sum", builtin_sum),
            function("unichr", builtin_unichr),
            function("vars", builtin_vars),
            function("zip", builtin_zip),
        ],
    )?;

    let classes: [(&str, &ObjectRef); 30] = [
        ("object", &types.object),
        ("type", &types.type_),
        ("dict", &types.dict),
        ("int", &types.int),
        ("long", &types.long),
        ("float", &types.float),
        ("complex", &types.complex),
        ("bool", &types.bool),
        ("basestring", &types.basestring),
        ("str", &types.str),
        ("unicode", &types.unicode),
        ("bytearray", &types.bytearray),
        ("bytes", &types.str),
        ("tuple", &types.tuple),
        ("list", &types.list),
        ("set", &types.set),
        ("frozenset", &types.frozenset),
        ("property", &types.property),
        ("staticmethod", &types.staticmethod),
        ("classmethod", &types.classmethod),
        ("super", &types.super_),
        ("slice", &types.slice),
        ("xrange", &types.xrange),
        ("enumerate", &types.enumerate),
        ("reversed", &types.reversed),
        ("file", &types.file),
        ("buffer", &types.buffer),
        ("memoryview", &types.memoryview),
        ("classobj", &types.classobj),
        ("module", &types.module),
    ];
    for (name, class) in classes {
        if name == "classobj" || name == "module" {
            continue;
        }
        set_attribute(vm, module, name, Value::Object(Rc::clone(class)))?;
    }

    for kind in crate::interp::exceptions::ExceptionKind::ALL {
        set_attribute(vm, module, kind.name(), Value::Object(Rc::clone(types.exception(*kind))))?;
    }

    set_attribute(vm, module, "None", Value::None)?;
    set_attribute(vm, module, "True", Value::Bool(true))?;
    set_attribute(vm, module, "False", Value::Bool(false))?;
    set_attribute(vm, module, "NotImplemented", Value::NotImplemented)?;
    set_attribute(vm, module, "Ellipsis", Value::Ellipsis)?;
    set_attribute(vm, module, "__debug__", Value::Bool(false))?;

    Ok(())
}

fn builtin_import(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "__import__", &["name", "globals", "locals", "fromlist", "level"], 1, |vm, index, value| match index {
        0 if vm.text_of(&value).is_none() => Err(vm.type_error(&format!("__import__() argument 1 must be string, not {}", vm.type_name(&value)))),
        4 => vm.import_level(&value).map(Value::Int),
        _ => Ok(value),
    })?;
    let Some(name) = slots[0].as_ref().and_then(|value| vm.text_of(value)) else {
        return Err(vm.type_error("__import__() argument 1 must be string"));
    };

    let globals = match &slots[1] {
        Some(Value::Object(dict)) if dict.as_dict().is_some() => Rc::clone(dict),
        _ => vm.new_dict(),
    };
    let fromlist = slots[3].clone().unwrap_or(Value::None);
    let level = match slots[4] {
        Some(Value::Int(level)) => level,
        _ => -1,
    };

    vm.import_name_level(&name, &globals, &fromlist, level)
}

fn builtin_unsupported_input(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::Console, Denial::Native, None)?;
    Err(vm.halt_unsupported("reading standard input"))
}

fn builtin_open(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    vm.host_operation_on(HostCapability::FileSystem, "open()", Denial::Crt, args.positional.first())
}

fn builtin_abs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "abs", 1, 1)?;
    let value = &args[0];

    if value.is_unknown() {
        return Ok(value.clone());
    }
    if let Some(method) = vm.user_override(value, "__abs__")? {
        return vm.call0(&method);
    }
    if let Some(number) = vm.as_float(value) {
        return Ok(Value::Float(number.abs()));
    }
    if let Some(number) = vm.as_complex(value) {
        return crate::interp::builtins::numeric::complex::complex_abs(vm, number);
    }

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(vm.new_int(num_bigint::BigInt::from(number).magnitude().clone().into())),
        Some(Integral::Long(number)) => Ok(Value::long(number.magnitude().clone().into())),
        None => Err(vm.type_error(&format!("bad operand type for abs(): '{}'", vm.type_name(value)))),
    }
}

fn truth_scan(vm: &Vm, args: CallArgs, name: &str, stop_on: bool) -> PyResult<Value> {
    let args = positional(vm, args, name, 1, 1)?;
    let iterator = vm.iter(&args[0])?;

    while let Some(item) = vm.next(&iterator)? {
        if item.is_unknown() {
            return Ok(item);
        }
        if vm.truthy(&item, name)? == stop_on {
            return Ok(Value::Bool(stop_on));
        }
    }

    Ok(Value::Bool(!stop_on))
}

fn builtin_all(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    truth_scan(vm, args, "all", false)
}

fn builtin_any(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    truth_scan(vm, args, "any", true)
}

fn builtin_apply(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "apply", 1, 3)?;
    let positional_args = match args.get(1) {
        Some(value) => vm.collect(value)?,
        None => Vec::new(),
    };

    match args.get(2) {
        Some(mapping) => {
            let call_args = vm.merge_star_kwargs(&args[0], Vec::new(), Some(mapping), positional_args)?;
            vm.call(&args[0], call_args)
        }
        None => vm.call(&args[0], CallArgs::new(positional_args)),
    }
}

fn builtin_callable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "callable", 1, 1)?;
    let value = &args[0];

    let callable = match value {
        Value::Unknown(_) => return Ok(value.clone()),
        Value::Object(object) => match &object.payload {
            Payload::Function(_) | Payload::NativeFunction(_) | Payload::Method(_) | Payload::Class(_) => true,
            _ => vm.lookup_special(value, "__call__")?.is_some(),
        },
        _ => false,
    };

    Ok(Value::Bool(callable))
}

fn builtin_chr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "chr", 1, 1)?;
    let code = long_argument(vm, &args[0])?;
    let Ok(byte) = u8::try_from(code) else {
        return Err(vm.raise(ExceptionKind::ValueError, "chr() arg not in range(256)"));
    };

    Ok(Value::Str(PyBytes::new(vec![byte])))
}

fn builtin_unichr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "unichr", 1, 1)?;
    let code = long_argument(vm, &args[0])?;
    let Ok(unit) = u16::try_from(code) else {
        return Err(vm.raise(ExceptionKind::ValueError, "unichr() arg not in range(0x10000) (narrow Python build)"));
    };

    Ok(Value::Unicode(PyText::new(vec![unit])))
}

fn builtin_cmp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "cmp", 2, 2)?;

    vm.three_way_compare(&args[0], &args[1])
}

impl Vm {
    /// `cmp(left, right)`: -1, 0, or 1.
    pub fn three_way_compare(&self, left: &Value, right: &Value) -> PyResult<Value> {
        if left.is_unknown() {
            return Ok(left.clone());
        }
        if right.is_unknown() {
            return Ok(right.clone());
        }

        // The three-way comparison checks the recursion limit once, then
        // compares through the types' slots without the rich comparison's check.
        self.with_depth_in(" in cmp", || {
            if self.truthy(&self.rich_compare(left, right, CompareOp::Equal)?, "==")? {
                return Ok(Value::Int(0));
            }
            if self.truthy(&self.rich_compare(left, right, CompareOp::Less)?, "<")? {
                return Ok(Value::Int(-1));
            }

            Ok(Value::Int(1))
        })
    }

    /// Sorts in place with Python's stable ordering, honoring `key`, `cmp`,
    /// and `reverse` like `list.sort`.
    pub fn sort_values(&self, items: &mut Vec<Value>, key: Option<&Value>, comparator: Option<&Value>, reverse: bool) -> PyResult<()> {
        let keys = match key {
            Some(function) if !function.is_none() => items.iter().map(|item| self.call1(function, item.clone())).collect::<PyResult<Vec<_>>>()?,
            _ => items.clone(),
        };

        let mut order: Vec<usize> = (0..items.len()).collect();
        if reverse {
            order.reverse();
        }

        let comparator = comparator.filter(|function| !function.is_none());
        let mut failure: Option<Signal> = None;
        let mut less = |left: usize, right: usize| -> bool {
            if failure.is_some() {
                return false;
            }
            let result = match comparator {
                Some(function) => self.call(function, CallArgs::new(vec![keys[left].clone(), keys[right].clone()])).and_then(|result| match self.as_index(&result) {
                    Some(number) => Ok(number < 0),
                    None if result.is_unknown() => Err(Signal::Halt(Halt::UnknownCondition { context: "sort comparison".to_owned(), origin: format!("{result:?}") })),
                    None => Err(self.type_error("comparison function must return int")),
                }),
                None => self.less_than(&keys[left], &keys[right]),
            };
            match result {
                Ok(flag) => flag,
                Err(signal) => {
                    failure = Some(signal);
                    false
                }
            }
        };

        merge_sort(&mut order, &mut less);

        if let Some(signal) = failure {
            return Err(signal);
        }

        if reverse {
            order.reverse();
        }

        let original = items.clone();
        *items = order.into_iter().map(|index| original[index].clone()).collect();

        Ok(())
    }
}

/// Stable merge sort calling `less(a, b)` only as `a < b`, the comparison
/// the reference interpreter's sort issues.
fn merge_sort(order: &mut Vec<usize>, less: &mut impl FnMut(usize, usize) -> bool) {
    let length = order.len();
    let mut width = 1;
    let mut buffer = order.clone();

    while width < length {
        let mut start = 0;
        while start < length {
            let middle = (start + width).min(length);
            let end = (start + 2 * width).min(length);
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle && right < end {
                if less(order[right], order[left]) {
                    buffer[output] = order[right];
                    right += 1;
                } else {
                    buffer[output] = order[left];
                    left += 1;
                }
                output += 1;
            }
            buffer[output..output + (middle - left)].copy_from_slice(&order[left..middle]);
            output += middle - left;
            buffer[output..output + (end - right)].copy_from_slice(&order[right..end]);
            start = end;
        }
        std::mem::swap(order, &mut buffer);
        width *= 2;
    }
}

fn builtin_delattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "delattr", 2, 2)?;
    let name = crate::interp::builtins::core::name_arg(vm, &args[1])?;
    vm.delattr(&args[0], &name)?;

    Ok(Value::None)
}

fn builtin_dir(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "dir", 0, 1)?;
    let Some(target) = args.first() else {
        return local_names(vm);
    };

    let names = vm.attribute_names(target)?;

    Ok(vm.new_list(names))
}

/// The sorted keys of the innermost frame's locals.
fn local_names(vm: &Vm) -> PyResult<Value> {
    let Some(locals) = vm.current_locals()? else {
        return Err(vm.raise(ExceptionKind::SystemError, "frame does not exist"));
    };

    let is_exact_dict = Rc::ptr_eq(&locals.class(), &vm.types().dict);
    let mut keys = if is_exact_dict { vm.dict_keys(&locals)? } else { list_keys(vm, &vm.call_method(&Value::Object(locals), "keys", Vec::new())?)? };
    vm.sort_values(&mut keys, None, None, false)?;

    Ok(vm.new_list(keys))
}

/// The items of the list `keys()` returned for `dir()`.
fn list_keys(vm: &Vm, keys: &Value) -> PyResult<Vec<Value>> {
    match vm.as_list(keys) {
        Some(items) => Ok(items),
        None => Err(vm.type_error(&format!("dir(): expected keys() of locals to be a list, not '{}'", vm.type_name(keys)))),
    }
}

impl Vm {
    /// `dir(target)`: sorted attribute names of an object, its class, and
    /// the class's bases.
    pub fn attribute_names(&self, target: &Value) -> PyResult<Vec<Value>> {
        if target.is_unknown() {
            return Err(Signal::Halt(Halt::UnknownIteration { origin: format!("dir({target:?})") }));
        }

        let names_dict = self.new_dict();

        match target {
            Value::Object(object) if object.as_class().is_some() => self.merge_class_dict(&names_dict, target.clone())?,
            Value::Object(object) if object.as_module().is_some() => {
                // For a module without a dict, reading the module name fails first.
                let Some(dict) = object.dict() else {
                    return Err(self.raise(ExceptionKind::SystemError, "nameless module"));
                };
                self.dict_merge(&names_dict, &Value::Object(dict), true)?;
            }
            Value::Object(object) => {
                if self.native_getattr(&object.class()).is_some() {
                    // A type with its own attribute hook exposes `__dict__` only through
                    // it; a failure or a non-dict is ignored.
                    match self.getattr_opt(target, &PyBytes::from("__dict__")) {
                        Ok(Some(dict)) if dict.as_object().is_some_and(|object| matches!(object.payload, Payload::Dict(_))) => self.dict_merge(&names_dict, &dict, true)?,
                        Ok(_) | Err(Signal::Raise(_)) => {}
                        Err(halt) => return Err(halt),
                    }
                } else if let Some(dict) = object.dict() {
                    self.dict_merge(&names_dict, &Value::Object(dict), true)?;
                }
                self.merge_list_attribute(&names_dict, target, "__members__")?;
                self.merge_list_attribute(&names_dict, target, "__methods__")?;

                // `__class__` is read as an attribute and any failure cleared; an
                // object whose attribute hook lacks it contributes no class names.
                match self.getattr_opt(target, &PyBytes::from("__class__")) {
                    Ok(Some(class)) => self.merge_class_dict(&names_dict, class)?,
                    Ok(None) | Err(Signal::Raise(_)) => {}
                    Err(halt) => return Err(halt),
                }
            }
            _ => self.merge_class_dict(&names_dict, Value::Object(self.type_of(target)))?,
        }

        let mut names = self.dict_keys(&names_dict)?;
        self.sort_values(&mut names, None, None, false)?;

        Ok(names)
    }

    /// The keys of `class.__dict__` and, recursively, of its `__bases__`.
    /// `class` may be any object; a missing `__dict__` or `__bases__`, or
    /// bases that are no sequence, add nothing.
    fn merge_class_dict(&self, names: &ObjectRef, class: Value) -> PyResult<()> {
        // C recurses without a depth check; a cyclic `__bases__` chain
        // overflows its stack.
        let depth_limit = self.recursion_limit();
        let mut pending = vec![(class, 0usize)];

        while let Some((class, depth)) = pending.pop() {
            if let Value::Unknown(unknown) = &class {
                return Err(Signal::Halt(Halt::UnknownIteration { origin: unknown.origin.clone() }));
            }
            if depth > depth_limit {
                return Err(self.halt_unsupported("dir() over a cyclic __bases__ chain"));
            }

            // A real class contributes its own dict and bases; its dict is
            // complete once the type is ready.
            let bases = if let Value::Object(object) = &class
                && let Some(data) = object.as_class()
            {
                self.ready_type(object);
                self.dict_merge(names, &Value::Object(Rc::clone(&data.dict)), true)?;
                data.bases()
            } else {
                match self.getattr_opt(&class, &PyBytes::from("__dict__")) {
                    Ok(Some(dict)) => self.dict_merge(names, &dict, true)?,
                    Ok(None) | Err(Signal::Raise(_)) => {}
                    Err(halt) => return Err(halt),
                }
                let bases = match self.getattr_opt(&class, &PyBytes::from("__bases__")) {
                    Ok(Some(bases)) => bases,
                    Ok(None) | Err(Signal::Raise(_)) => continue,
                    Err(halt) => return Err(halt),
                };
                match self.collect(&bases) {
                    Ok(items) => items,
                    Err(Signal::Raise(_)) => continue,
                    Err(halt) => return Err(halt),
                }
            };

            // Bases merge in order, as the C recursion does.
            pending.extend(bases.into_iter().rev().map(|base| (base, depth + 1)));
        }

        Ok(())
    }

    /// The `str` items of attribute `name` when it is a list. A missing
    /// attribute or a non-list value adds nothing.
    fn merge_list_attribute(&self, names: &ObjectRef, target: &Value, name: &str) -> PyResult<()> {
        let list = match self.getattr_opt(target, &PyBytes::from(name)) {
            Ok(Some(list)) => list,
            Ok(None) | Err(Signal::Raise(_)) => return Ok(()),
            Err(halt) => return Err(halt),
        };
        let Some(items) = self.as_list(&list) else {
            return Ok(());
        };

        for item in items {
            if self.as_str_bytes(&item).is_some() {
                self.dict_set(names, item, Value::None)?;
            }
        }

        Ok(())
    }
}

fn builtin_divmod(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "divmod", 2, 2)?;
    if let Some(method) = vm.user_override(&args[0], "__divmod__")? {
        return vm.call1(&method, args[1].clone());
    }

    if let Some(method) = vm.user_override(&args[1], "__rdivmod__")? {
        let result = vm.call1(&method, args[0].clone())?;
        if !matches!(result, Value::NotImplemented) {
            return Ok(result);
        }
    }
    if let Some(unknown) = args.iter().find(|value| value.is_unknown()) {
        return Ok(unknown.clone());
    }

    if let Some(result) = vm.number_divmod(&args[0], &args[1])? {
        return Ok(result);
    }

    Err(vm.type_error(&format!("unsupported operand type(s) for divmod(): '{}' and '{}'", vm.type_name(&args[0]), vm.type_name(&args[1]))))
}

fn builtin_filter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "filter", 2, 2)?;
    let function = &args[0];
    let sequence = &args[1];

    let mut kept = Vec::new();
    for item in vm.collect(sequence)? {
        let keep = if function.is_none() { vm.truthy(&item, "filter")? } else { vm.truthy(&vm.call1(function, item.clone())?, "filter")? };
        if keep {
            kept.push(item);
        }
    }

    if let Some(bytes) = vm.as_str_bytes(sequence) {
        // `filter(None, s)` returns an exact string itself, as no character is false.
        if function.is_none() && matches!(sequence, Value::Str(_)) {
            return Ok(sequence.clone());
        }
        let joined: Vec<u8> = kept.iter().filter_map(|item| item.as_bytes().map(<[u8]>::to_vec)).flatten().collect();

        // The output buffer starts at the input length and is resized when that differs.
        if joined.len() != bytes.as_bytes().len() {
            return Ok(Value::Str(PyBytes::allocate(joined)));
        }
        return Ok(Value::Str(PyBytes::new_unshared(joined)));
    }
    if let Some(text) = vm.as_text(sequence) {
        // `filter(None, u)` returns an exact unicode itself, as no character is false.
        if function.is_none() && matches!(sequence, Value::Unicode(_)) {
            return Ok(sequence.clone());
        }
        let joined: Vec<u16> = kept.iter().filter_map(|item| vm.as_text(item)).flat_map(|text| text.units().to_vec()).collect();
        return Ok(Value::Unicode(crate::interp::builtins::text::codecs::resized_text(text.units().len(), joined)));
    }
    if vm.as_tuple(sequence).is_some() {
        return Ok(Value::tuple(kept));
    }

    Ok(vm.new_list(kept))
}

fn builtin_format(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "format", 1, 2)?;
    let spec = args.get(1).cloned().unwrap_or_else(|| Value::str(""));

    vm.format_object(&args[0], &spec)
}

fn builtin_getattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "getattr", 2, 3)?;
    if args[1].is_unknown() {
        return Ok(args[1].clone());
    }
    let name = crate::interp::builtins::core::name_arg(vm, &args[1])?;

    match args.get(2) {
        None => vm.getattr(&args[0], &name),
        Some(default) => match vm.getattr(&args[0], &name) {
            Ok(value) => Ok(value),
            Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::AttributeError) => Ok(default.clone()),
            Err(error) => Err(error),
        },
    }
}

fn builtin_hasattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "hasattr", 2, 2)?;
    if args[0].is_unknown() || args[1].is_unknown() {
        return Ok(Value::unknown("hasattr on an unknown value"));
    }
    let name = crate::interp::builtins::core::name_arg(vm, &args[1])?;

    match vm.getattr(&args[0], &name) {
        Ok(value) if value.is_unknown() => Ok(value),
        Ok(_) => Ok(Value::Bool(true)),
        Err(Signal::Raise(_)) => Ok(Value::Bool(false)),
        Err(error) => Err(error),
    }
}

fn builtin_globals(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    match vm.current_globals() {
        Some(globals) => Ok(Value::Object(globals)),
        None => Ok(Value::Object(vm.new_dict())),
    }
}

fn builtin_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "hash", 1, 1)?;

    Ok(Value::Int(vm.hash(&args[0])?.value()))
}

fn builtin_hex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "hex", 1, 1)?;

    match vm.as_integral(&args[0]) {
        Some(Integral::Int(number)) => Ok(Value::str(&if number < 0 { format!("-0x{:x}", number.unsigned_abs()) } else { format!("0x{number:x}") })),
        Some(Integral::Long(number)) => {
            let text = if number.sign() == num_bigint::Sign::Minus { format!("-0x{:x}L", number.magnitude()) } else { format!("0x{:x}L", number.magnitude()) };
            Ok(Value::str(&text))
        }
        None if args[0].is_unknown() => Ok(args[0].clone()),
        None => match vm.lookup_special(&args[0], "__hex__")? {
            Some(method) => vm.call0(&method),
            None => Err(vm.type_error("hex() argument can't be converted to hex")),
        },
    }
}

fn builtin_oct(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "oct", 1, 1)?;

    match vm.as_integral(&args[0]) {
        Some(integral) => {
            let number = integral.to_bigint();
            let suffix = if integral.is_long() { "L" } else { "" };
            let text = if number.sign() == num_bigint::Sign::NoSign {
                format!("0{suffix}")
            } else if number.sign() == num_bigint::Sign::Minus {
                format!("-0{:o}{suffix}", number.magnitude())
            } else {
                format!("0{:o}{suffix}", number.magnitude())
            };
            Ok(Value::str(&text))
        }
        None if args[0].is_unknown() => Ok(args[0].clone()),
        None => match vm.lookup_special(&args[0], "__oct__")? {
            Some(method) => vm.call0(&method),
            None => Err(vm.type_error("oct() argument can't be converted to oct")),
        },
    }
}

fn builtin_id(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "id", 1, 1)?;
    if args[0].is_unknown() {
        return Ok(args[0].clone());
    }

    Ok(vm.new_int_from_i64(vm.value_address(&args[0]) as i64))
}

/// `intern(string)`: only exact `str` objects intern.
fn builtin_intern(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "intern", 1, 1)?;

    match &args[0] {
        Value::Unknown(_) => Ok(args[0].clone()),
        Value::Str(string) => Ok(Value::Str(vm.intern(string))),
        value if value.as_bytes().is_some() => Err(vm.type_error("can't intern subclass of string")),
        value => Err(vm.type_error(&format!("intern() argument 1 must be string, not {}", vm.type_name(value)))),
    }
}

fn builtin_isinstance(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "isinstance", 2, 2)?;
    if args[0].is_unknown() || args[1].is_unknown() {
        return Ok(Value::unknown("isinstance on an unknown value"));
    }

    match vm.isinstance(&args[0], &args[1]) {
        Ok(result) => Ok(Value::Bool(result)),
        Err(Signal::Halt(Halt::UnknownCondition { origin, .. })) => {
            vm.clear_trace();
            Ok(Value::unknown(origin))
        }
        Err(error) => Err(error),
    }
}

fn builtin_issubclass(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "issubclass", 2, 2)?;
    if args[0].is_unknown() || args[1].is_unknown() {
        return Ok(Value::unknown("issubclass on an unknown value"));
    }

    match vm.issubclass(&args[0], &args[1]) {
        Ok(result) => Ok(Value::Bool(result)),
        Err(Signal::Halt(Halt::UnknownCondition { origin, .. })) => {
            vm.clear_trace();
            Ok(Value::unknown(origin))
        }
        Err(error) => Err(error),
    }
}

fn builtin_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "iter", 1, 2)?;

    match args.get(1) {
        None => vm.iter(&args[0]),
        Some(sentinel) => Ok(vm.new_iterator(NativeIterator::Callable { function: args[0].clone(), sentinel: sentinel.clone() })),
    }
}

fn builtin_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "len", 1, 1)?;

    match vm.len(&args[0])? {
        Some(length) => Ok(vm.new_int_from_i64(length as i64)),
        None => Ok(Value::unknown(format!("len({:?})", args[0]))),
    }
}

/// `map` advances every iterator in lockstep, padding exhausted ones with
/// None until all are exhausted.
fn builtin_map(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "map", 2, usize::MAX)?;
    let function = &args[0];
    let iterators: Vec<Value> = args[1..].iter().map(|sequence| vm.iter(sequence)).collect::<PyResult<_>>()?;
    let mut exhausted = vec![false; iterators.len()];

    let mut results = Vec::new();
    loop {
        let mut items = Vec::with_capacity(iterators.len());
        for (index, iterator) in iterators.iter().enumerate() {
            let item = if exhausted[index] { None } else { vm.next(iterator)? };
            if item.is_none() {
                exhausted[index] = true;
            }
            items.push(item.unwrap_or(Value::None));
        }
        if exhausted.iter().all(|done| *done) {
            break;
        }

        let result = if function.is_none() {
            if items.len() == 1 { items.remove(0) } else { Value::tuple(items) }
        } else {
            vm.call(function, CallArgs::new(items))?
        };
        results.push(result);
    }

    Ok(vm.new_list(results))
}

fn extreme(vm: &Vm, args: CallArgs, name: &str, want_greater: bool) -> PyResult<Value> {
    let key = args.keyword("key").cloned();
    // `min` and `max` accept exactly one keyword, `key`.
    if args.has_keywords() && (key.is_none() || args.keywords.len() != 1 || args.keyword_dict.is_some()) {
        return Err(vm.type_error(&format!("{name}() got an unexpected keyword argument")));
    }
    let CallArgs { positional, .. } = args;

    let items = match positional.len() {
        0 => return Err(vm.type_error(&format!("{name} expected 1 arguments, got 0"))),
        1 => vm.collect(&positional[0])?,
        _ => positional,
    };

    let mut best: Option<(Value, Value)> = None;
    for item in items {
        let item_key = match &key {
            Some(function) => vm.call1(function, item.clone())?,
            None => item.clone(),
        };
        let replace = match &best {
            None => true,
            Some((best_key, _)) => {
                if want_greater {
                    vm.less_than(best_key, &item_key)?
                } else {
                    vm.less_than(&item_key, best_key)?
                }
            }
        };
        if replace {
            best = Some((item_key, item));
        }
    }

    match best {
        Some((_, item)) => Ok(item),
        None => Err(vm.raise(ExceptionKind::ValueError, &format!("{name}() arg is an empty sequence"))),
    }
}

fn builtin_max(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    extreme(vm, args, "max", true)
}

fn builtin_min(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    extreme(vm, args, "min", false)
}

fn builtin_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "next", 1, 2)?;

    match vm.next(&args[0])? {
        Some(value) => Ok(value),
        None => match args.get(1) {
            Some(default) => Ok(default.clone()),
            None => Err(Signal::Raise(vm.instantiate_exception(&Rc::clone(vm.types().exception(ExceptionKind::StopIteration)), Vec::new())?)),
        },
    }
}

fn builtin_ord(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "ord", 1, 1)?;

    if let Some(bytes) = vm.as_str_bytes(&args[0]) {
        if bytes.as_bytes().len() == 1 {
            return Ok(Value::Int(i64::from(bytes.as_bytes()[0])));
        }
        return Err(vm.type_error(&format!("ord() expected a character, but string of length {} found", bytes.as_bytes().len())));
    }
    if let Some(text) = vm.as_text(&args[0]) {
        if text.units().len() == 1 {
            return Ok(Value::Int(i64::from(text.units()[0])));
        }
        return Err(vm.type_error(&format!("ord() expected a character, but string of length {} found", text.units().len())));
    }
    if args[0].is_unknown() {
        return Ok(args[0].clone());
    }

    Err(vm.type_error(&format!("ord() expected string of length 1, but {} found", vm.type_name(&args[0]))))
}

/// `pow(base, exponent[, modulus])`.
fn builtin_pow(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "pow", 2, 3)?;
    let modulus = match args.get(2) {
        None => return vm.binary_op(BinaryOp::Power, &args[0], &args[1]),
        Some(modulus) if modulus.is_none() => return vm.binary_op(BinaryOp::Power, &args[0], &args[1]),
        Some(modulus) => modulus,
    };

    if let Some(value) = args.iter().find(|value| value.is_unknown()) {
        return Ok(value.clone());
    }
    if let Some(method) = vm.user_override(&args[0], "__pow__")? {
        return vm.call(&method, CallArgs::new(vec![args[1].clone(), modulus.clone()]));
    }
    if let Some(error) = ternary_power_error(vm, &args[0], &args[1], modulus) {
        return Err(error);
    }

    let (Some(base), Some(exponent), Some(modulus_value)) = (vm.as_integral(&args[0]), vm.as_integral(&args[1]), vm.as_integral(modulus)) else {
        return Err(vm.type_error("pow() 3rd argument not allowed unless all arguments are integers"));
    };
    let long_result = base.is_long() || exponent.is_long() || modulus_value.is_long();
    let (base, exponent, modulus_value) = (base.to_bigint(), exponent.to_bigint(), modulus_value.to_bigint());

    if exponent.sign() == num_bigint::Sign::Minus {
        return Err(vm.type_error("pow() 2nd argument cannot be negative when 3rd argument specified"));
    }
    if modulus_value.sign() == num_bigint::Sign::NoSign {
        return Err(vm.raise(ExceptionKind::ValueError, "pow() 3rd argument cannot be 0"));
    }

    let magnitude = num_bigint::BigInt::from(modulus_value.magnitude().clone());
    let mut result = base.modpow(&exponent, &magnitude);
    if modulus_value.sign() == num_bigint::Sign::Minus && result.sign() != num_bigint::Sign::NoSign {
        result += &modulus_value;
    }

    if long_result {
        return Ok(Value::long(result));
    }

    Ok(vm.new_int(result))
}

/// `range()` builds the list eagerly, so its length must fit a C long.
fn builtin_range(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    /// Lists beyond this length exceed what a constants extraction can hold
    /// in memory; evaluation stops instead of allocating them.
    const MAX_EMULATED_LENGTH: u64 = 1 << 26;

    let args = positional(vm, args, "range", 1, 3)?;
    if args.iter().any(Value::is_unknown) {
        return Err(Signal::Halt(Halt::UnknownIteration { origin: "range() with an unknown bound".to_owned() }));
    }

    let bound = |value: &Value| match vm.as_integral(value) {
        Some(integral) => Ok(integral.to_bigint()),
        None if vm.as_float(value).is_some() => Err(vm.type_error("range() integer end argument expected, got float.")),
        None if vm.as_complex(value).is_some() => match vm.user_override(value, "__int__")? {
            Some(method) => vm.as_integral(&vm.call0(&method)?).map(|integral| integral.to_bigint()).ok_or_else(|| vm.type_error("__int__ should return int object")),
            None => Err(vm.type_error("can't convert complex to int")),
        },
        None => Err(vm.type_error(&format!("range() integer end argument expected, got {}.", vm.type_name(value)))),
    };

    let (start, stop, step) = match args.len() {
        1 => (num_bigint::BigInt::from(0), bound(&args[0])?, num_bigint::BigInt::from(1)),
        2 => (bound(&args[0])?, bound(&args[1])?, num_bigint::BigInt::from(1)),
        _ => (bound(&args[0])?, bound(&args[1])?, bound(&args[2])?),
    };

    if step.sign() == num_bigint::Sign::NoSign {
        return Err(vm.raise(ExceptionKind::ValueError, "range() step argument must not be zero"));
    }

    let span = if step.sign() == num_bigint::Sign::Plus { &stop - &start } else { &start - &stop };
    let step_magnitude = num_bigint::BigInt::from(step.magnitude().clone());
    let length = if span.sign() == num_bigint::Sign::Plus { (span - 1) / &step_magnitude + 1 } else { num_bigint::BigInt::from(0) };

    let (_, long_max) = crate::interp::numbers::int_bounds(vm.config.long_width);
    if length > num_bigint::BigInt::from(long_max) {
        return Err(vm.raise(ExceptionKind::OverflowError, "range() result has too many items"));
    }
    let Some(length) = num_traits::ToPrimitive::to_u64(&length) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "range() result has too many items"));
    };
    if length > MAX_EMULATED_LENGTH {
        return Err(vm.halt_unsupported(format!("range() of {length} items")));
    }

    let mut items = Vec::with_capacity(length as usize);
    let mut current = start;
    for _ in 0..length {
        items.push(vm.new_int(current.clone()));
        current += &step;
    }

    Ok(vm.new_list(items))
}

fn builtin_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "reduce", 2, 3)?;
    let iterator = vm.iter(&args[1])?;

    let mut accumulator = match args.get(2) {
        Some(initial) => initial.clone(),
        None => match vm.next(&iterator)? {
            Some(first) => first,
            None => return Err(vm.type_error("reduce() of empty sequence with no initial value")),
        },
    };

    while let Some(item) = vm.next(&iterator)? {
        accumulator = vm.call(&args[0], CallArgs::new(vec![accumulator, item]))?;
    }

    Ok(accumulator)
}

fn builtin_reload(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "reload", 1, 1)?;

    Ok(args[0].clone())
}

fn builtin_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "repr", 1, 1)?;

    vm.repr(&args[0])
}

/// The `d` argument of `round`.
fn round_number(vm: &Vm, number: &Value) -> PyResult<f64> {
    if let Some(value) = vm.as_float(number) {
        return Ok(value);
    }

    match vm.as_integral(number) {
        Some(Integral::Int(value)) => Ok(value as f64),
        Some(Integral::Long(value)) => crate::interp::numbers::bigint_to_f64(&value).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float")),
        None => crate::interp::builtins::numeric::float::float_as_double(vm, number),
    }
}

fn builtin_round(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "round", &["number", "ndigits"], 1, |vm, index, value| match index {
        _ if value.is_unknown() => Ok(value),
        0 => round_number(vm, &value).map(Value::Float),
        _ => int_argument(vm, &value).map(Value::Int),
    })?;
    let value = match &slots[0] {
        Some(Value::Float(value)) => *value,
        Some(unknown) if unknown.is_unknown() => return Ok(unknown.clone()),
        _ => return Err(vm.type_error("a float is required")),
    };

    let digits = match &slots[1] {
        None => 0,
        Some(Value::Int(digits)) => *digits,
        Some(unknown) => return Ok(unknown.clone()),
    };

    Ok(Value::Float(round_half_away(value, digits)))
}

/// `round()` in Python 2: round half away from zero, computed through the
/// decimal string to avoid binary rounding error.
fn round_half_away(value: f64, digits: i64) -> f64 {
    if !value.is_finite() {
        return value;
    }

    if digits > 22 || digits < -22 {
        return if digits > 0 { value } else { 0.0f64.copysign(value) };
    }

    let precision = usize::try_from(digits.max(0)).unwrap_or(0) + 1;
    let scaled = if digits >= 0 { value * 10f64.powi(digits as i32) } else { value / 10f64.powi((-digits) as i32) };
    let text = format!("{scaled:.precision$}");
    let parsed: f64 = text.parse().unwrap_or(scaled);
    let rounded = if parsed.fract().abs() == 0.5 { parsed.trunc() + parsed.signum() } else { parsed.round() };

    if digits >= 0 { rounded / 10f64.powi(digits as i32) } else { rounded * 10f64.powi((-digits) as i32) }
}

fn builtin_setattr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "setattr", 3, 3)?;
    if args[1].is_unknown() {
        return Ok(Value::None);
    }
    let name = crate::interp::builtins::core::name_arg(vm, &args[1])?;
    vm.setattr(&args[0], &name, args[2].clone())?;

    Ok(Value::None)
}

fn builtin_sorted(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "sorted", &["iterable", "cmp", "key", "reverse"], 1, |vm, index, value| match index {
        3 => int_argument(vm, &value).map(|reverse| Value::Bool(reverse != 0)),
        _ => Ok(value),
    })?;
    let iterable = slots[0].clone().unwrap_or(Value::None);
    let mut items = vm.collect(&iterable)?;
    let reverse = matches!(slots[3], Some(Value::Bool(true)));

    vm.sort_values(&mut items, slots[2].as_ref(), slots[1].as_ref(), reverse)?;

    Ok(vm.new_list(items))
}

/// `pow(v, w, z)` with a complex among the operands: the power slots of
/// the operands' types run in order, and the first that accepts `v` and
/// `w` refuses the modulus. Integer slots decline.
fn ternary_power_error(vm: &Vm, base: &Value, exponent: &Value, modulus: &Value) -> Option<Signal> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Slot {
        Integer,
        Float,
        Complex,
    }

    let slot = |value: &Value| {
        if vm.as_complex(value).is_some() {
            Some(Slot::Complex)
        } else if vm.as_float(value).is_some() {
            Some(Slot::Float)
        } else if vm.as_integral(value).is_some() {
            Some(Slot::Integer)
        } else {
            None
        }
    };

    let slots = [slot(base), slot(exponent), slot(modulus)];
    if !slots.contains(&Some(Slot::Complex)) {
        return None;
    }

    // `float` refuses a modulus before converting its operands; `complex`
    // converts them first.
    let accepts = |kind: Slot, value: Option<Slot>| matches!((kind, value), (Slot::Float, _) | (Slot::Complex, Some(_)));
    let mut tried = Vec::new();
    for kind in slots.into_iter().flatten() {
        if tried.contains(&kind) {
            continue;
        }
        tried.push(kind);
        if !(accepts(kind, slots[0]) && accepts(kind, slots[1])) {
            continue;
        }
        return Some(match kind {
            Slot::Complex => vm.raise(ExceptionKind::ValueError, "complex modulo"),
            _ => vm.type_error("pow() 3rd argument not allowed unless all arguments are integers"),
        });
    }

    None
}

fn builtin_sum(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "sum", 1, 2)?;
    let mut total = args.get(1).cloned().unwrap_or(Value::Int(0));
    if vm.as_str_bytes(&total).is_some() {
        return Err(vm.type_error("sum() can't sum strings [use ''.join(seq) instead]"));
    }

    let iterator = vm.iter(&args[0])?;
    while let Some(item) = vm.next(&iterator)? {
        total = vm.binary_op(BinaryOp::Add, &total, &item)?;
    }

    Ok(total)
}

fn builtin_vars(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "vars", 0, 1)?;
    let Some(target) = args.first() else {
        return match vm.current_locals()? {
            Some(locals) => Ok(Value::Object(locals)),
            None => Err(vm.raise(ExceptionKind::SystemError, "vars(): no locals!?")),
        };
    };

    match vm.getattr_opt(target, &PyBytes::from("__dict__"))? {
        Some(dict) => Ok(dict),
        None => Err(vm.type_error("vars() argument must have __dict__ attribute")),
    }
}

fn builtin_zip(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "zip", 0, usize::MAX)?;
    if args.is_empty() {
        return Ok(vm.new_list(Vec::new()));
    }

    let iterators: Vec<Value> = args.iter().map(|sequence| vm.iter(sequence)).collect::<PyResult<_>>()?;
    let mut rows = Vec::new();

    'outer: loop {
        let mut row = Vec::with_capacity(iterators.len());
        for iterator in &iterators {
            match vm.next(iterator)? {
                Some(item) => row.push(item),
                None => break 'outer,
            }
        }
        rows.push(Value::tuple(row));
    }

    Ok(vm.new_list(rows))
}

/// Writes `str()` of each value (a `unicode` as is) to `file`,
/// `sys.stdout` by default, through its `write`.
fn builtin_print(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let keywords = CallArgs { positional: Vec::new(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    let slots = crate::interp::builtins::parse(vm, keywords, "print", &["sep", "end", "file"], 0)?;
    let [sep, end, file] = <[Option<Value>; 3]>::try_from(slots).unwrap_or([None, None, None]);
    let values = args.positional;

    let file = match file.filter(|file| !file.is_none()) {
        Some(file) => Some(file),
        None => {
            let sys = vm.import_module("sys")?;
            match vm.getattr_opt(&sys, &PyBytes::from("stdout"))? {
                Some(stdout) if stdout.is_none() => return Ok(Value::None),
                stdout => stdout,
            }
        }
    };

    let mut use_unicode = false;
    let mut separator = |value: Option<Value>, role: &str| -> PyResult<Option<Value>> {
        match value {
            None => Ok(None),
            Some(value) if value.is_none() => Ok(None),
            Some(value) if vm.as_text(&value).is_some() => {
                use_unicode = true;
                Ok(Some(value))
            }
            Some(value) if vm.as_str_bytes(&value).is_some() || value.is_unknown() => Ok(Some(value)),
            Some(value) => Err(vm.type_error(&format!("{role} must be None, str or unicode, not {}", vm.type_name(&value)))),
        }
    };
    let sep = separator(sep, "sep")?;
    let end = separator(end, "end")?;
    if values.iter().any(|value| vm.as_text(value).is_some()) {
        use_unicode = true;
    }

    let (space, newline) = if use_unicode { (Value::Unicode(PyText::new(vec![u16::from(b' ')])), Value::Unicode(PyText::new(vec![u16::from(b'\n')]))) } else { (Value::str(" "), Value::str("\n")) };

    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            write_object(vm, sep.as_ref().unwrap_or(&space), file.as_ref())?;
        }
        write_object(vm, value, file.as_ref())?;
    }
    write_object(vm, end.as_ref().unwrap_or(&newline), file.as_ref())?;

    Ok(Value::None)
}

/// `file.write` of the value, which `str()` converts unless it is
/// `unicode`.
fn write_object(vm: &Vm, value: &Value, file: Option<&Value>) -> PyResult<()> {
    let Some(file) = file else {
        return Err(vm.type_error("writeobject with NULL file"));
    };

    let writer = vm.getattr_str(file, "write")?;
    let text = if vm.as_text(value).is_some() || value.is_unknown() { value.clone() } else { vm.to_str(value)? };
    vm.call(&writer, CallArgs::new(vec![text]))?;

    Ok(())
}

/// `bin(value)`: the value in base 2.
fn builtin_bin(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let value = crate::interp::builtins::modules::codecs::args::single(vm, args, "bin")?;
    if value.is_unknown() {
        return Ok(value);
    }

    let integral = match vm.as_integral(&value) {
        Some(integral) => integral,
        None => {
            let Some(method) = vm.lookup_special(&value, "__index__")? else {
                return Err(vm.type_error(&format!("'{}' object cannot be interpreted as an index", vm.type_name(&value))));
            };
            let result = vm.call0(&method)?;
            if result.is_unknown() {
                return Ok(result);
            }
            vm.as_integral(&result).ok_or_else(|| vm.type_error(&format!("__index__ returned non-(int,long) (type {})", vm.type_name(&result))))?
        }
    };

    let number = integral.to_bigint();
    let text = match number.sign() {
        num_bigint::Sign::Minus => format!("-0b{:b}", number.magnitude()),
        _ => format!("0b{:b}", number.magnitude()),
    };

    Ok(Value::str(&text))
}

/// `coerce(x, y)`.
fn builtin_coerce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = crate::interp::builtins::modules::codecs::args::unpack(vm, args, "coerce", 2, 2)?;
    let (left, right) = (&args[0], &args[1]);
    if let Some(unknown) = [left, right].into_iter().find(|value| value.is_unknown()) {
        return Ok(unknown.clone());
    }

    // Coercion returns operands of one type unchanged unless the type opts
    // into mixed-type numeric operations, as heap types and the builtin
    // numbers, strings, and sets do.
    let class = vm.class_of(left);
    if Rc::ptr_eq(&class, &vm.class_of(right)) && !checks_types(vm, &class) {
        return Ok(Value::tuple(vec![left.clone(), right.clone()]));
    }

    if let Some(pair) = coerce_with(vm, left, right)? {
        return Ok(pair);
    }
    if let Some(pair) = coerce_with(vm, right, left)? {
        let Some(items) = vm.as_tuple(&pair) else {
            return Err(vm.type_error("__coerce__ didn't return a 2-tuple"));
        };
        return Ok(Value::tuple(vec![items[1].clone(), items[0].clone()]));
    }

    Err(vm.type_error("number coercion failed"))
}

/// `value.__coerce__(other)`: the pair, or `None` when it declines.
fn coerce_with(vm: &Vm, value: &Value, other: &Value) -> PyResult<Option<Value>> {
    let Some(method) = vm.lookup_special(value, "__coerce__")? else {
        return Ok(None);
    };

    let result = vm.call(&method, CallArgs::new(vec![other.clone()]))?;
    if matches!(result, Value::NotImplemented) || result.is_none() {
        return Ok(None);
    }
    match vm.as_tuple(&result).as_deref() {
        Some([_, _]) => Ok(Some(result)),
        _ => Err(vm.type_error("__coerce__ didn't return a 2-tuple")),
    }
}

/// Whether `class` takes operands of other types in its numeric methods
/// without coercion.
fn checks_types(vm: &Vm, class: &ObjectRef) -> bool {
    let types = vm.types();
    let Some(data) = class.as_class() else {
        return false;
    };
    if !data.builtin || vm.is_classic_class(class) || Rc::ptr_eq(class, &types.instance) {
        return true;
    }

    [&types.int, &types.long, &types.float, &types.complex, &types.bool, &types.str, &types.unicode, &types.set, &types.frozenset].into_iter().any(|checked| Rc::ptr_eq(class, checked))
}
