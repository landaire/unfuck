//! `SRE_Match`: the outcome of a successful match.

use std::rc::Rc;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::sre::engine::Found;
use crate::interp::builtins::modules::sre::engine::Span;
use crate::interp::builtins::modules::sre::pattern::PatternData;
use crate::interp::builtins::modules::sre::pattern::slice;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const MATCH_TYPE: &str = "_sre.SRE_Match";

/// A successful match (`MatchObject`).
pub struct MatchData {
    pattern: Value,
    string: Value,
    pos: usize,
    endpos: usize,
    /// Group 0 first; `None` for a group that did not take part.
    spans: Box<[Option<Span>]>,
    last_index: Option<usize>,
}

impl_native_data!(MatchData, "_sre.SRE_Match");

pub fn new_match(vm: &Vm, pattern: &Value, string: &Value, found: Found, pos: usize, endpos: usize) -> PyResult<Value> {
    let class = native_type(vm, MATCH_TYPE, create_match_type)?;
    let spans = std::iter::once(Some(found.whole)).chain(found.groups).collect();
    let data = MatchData { pattern: pattern.clone(), string: string.clone(), pos, endpos, spans, last_index: found.last_index };

    Ok(new_native_object(vm, &class, data))
}

fn create_match_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "SRE_Match",
            module: "_sre",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("group", match_group),
                method("start", match_start),
                method("end", match_end),
                method("span", match_span),
                method("groups", match_groups),
                method("groupdict", match_groupdict),
                method("expand", match_expand),
                method("__copy__", match_copy),
                method("__deepcopy__", match_deepcopy),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "string", owner: MATCH_TYPE, get: member_string, set: None })?;
    add_member(vm, &class, GetSet { name: "re", owner: MATCH_TYPE, get: member_re, set: None })?;
    add_member(vm, &class, GetSet { name: "pos", owner: MATCH_TYPE, get: member_pos, set: None })?;
    add_member(vm, &class, GetSet { name: "endpos", owner: MATCH_TYPE, get: member_endpos, set: None })?;
    add_getset(vm, &class, GetSet { name: "lastindex", owner: MATCH_TYPE, get: getset_lastindex, set: None })?;
    add_getset(vm, &class, GetSet { name: "lastgroup", owner: MATCH_TYPE, get: getset_lastgroup, set: None })?;
    add_getset(vm, &class, GetSet { name: "regs", owner: MATCH_TYPE, get: getset_regs, set: None })?;

    Ok(class)
}

impl MatchData {
    fn pattern_data(&self) -> Option<&PatternData> {
        native_data::<PatternData>(&self.pattern)
    }

    /// The group `key` names: an integer, or a name looked up in the
    /// pattern's `groupindex`. `None` for no such group.
    fn index(&self, vm: &Vm, key: &Value) -> PyResult<Option<usize>> {
        let number = match vm.as_integral(key) {
            Some(_) => vm.as_index(key),
            None => {
                let Some(groupindex) = self.pattern_data().and_then(|pattern| pattern.groupindex.as_ref()) else {
                    return Ok(None);
                };
                match vm.getitem(groupindex, key) {
                    Ok(found) if vm.as_integral(&found).is_some() => vm.as_index(&found),
                    Ok(_) | Err(Signal::Raise(_)) => None,
                    Err(halt) => return Err(halt),
                }
            }
        };

        Ok(number.and_then(|number| usize::try_from(number).ok()).filter(|&index| index < self.spans.len()))
    }

    fn checked_index(&self, vm: &Vm, key: &Value) -> PyResult<usize> {
        self.index(vm, key)?.ok_or_else(|| vm.raise(ExceptionKind::IndexError, "no such group"))
    }

    /// The text of group `index`, or `default` when it did not take part.
    fn text(&self, vm: &Vm, index: usize, default: &Value) -> PyResult<Value> {
        match self.spans.get(index).copied().flatten() {
            Some(span) => slice(vm, &self.string, span.start, span.end),
            None => Ok(default.clone()),
        }
    }

    fn bounds(&self, index: usize) -> (i64, i64) {
        match self.spans.get(index).copied().flatten() {
            Some(span) => (span.start as i64, span.end as i64),
            None => (-1, -1),
        }
    }
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a MatchData> {
    this::<MatchData>(vm, args, MATCH_TYPE, method)
}

fn match_of<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a MatchData> {
    native_data::<MatchData>(instance).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

fn member_string(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(match_of(vm, getset, instance)?.string.clone())
}

fn member_re(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(match_of(vm, getset, instance)?.pattern.clone())
}

fn member_pos(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(vm.new_int_from_i64(match_of(vm, getset, instance)?.pos as i64))
}

fn member_endpos(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(vm.new_int_from_i64(match_of(vm, getset, instance)?.endpos as i64))
}

fn getset_lastindex(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(match match_of(vm, getset, instance)?.last_index {
        Some(index) => vm.new_int_from_i64(index as i64),
        None => Value::None,
    })
}

/// The name `indexgroup` gives the last closed group. Lookup failures give
/// `None`, as does an exact `dict`, which is no sequence; a subclass
/// indexes through `__getitem__`.
fn getset_lastgroup(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let data = match_of(vm, getset, instance)?;
    let (Some(index), Some(indexgroup)) = (data.last_index, data.pattern_data().and_then(|pattern| pattern.indexgroup.as_ref())) else {
        return Ok(Value::None);
    };
    if indexgroup.as_object().is_some_and(|object| Rc::ptr_eq(&object.class(), &vm.types().dict)) {
        return Ok(Value::None);
    }

    match vm.getitem(indexgroup, &vm.new_int_from_i64(index as i64)) {
        Ok(name) => Ok(name),
        Err(Signal::Raise(_)) => Ok(Value::None),
        Err(halt) => Err(halt),
    }
}

fn getset_regs(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let data = match_of(vm, getset, instance)?;
    let regs = (0..data.spans.len())
        .map(|index| {
            let (start, end) = data.bounds(index);
            Value::tuple(vec![vm.new_int_from_i64(start), vm.new_int_from_i64(end)])
        })
        .collect();

    Ok(Value::tuple(regs))
}

fn match_group(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = receiver(vm, &args, "group")?;
    if args.has_keywords() {
        return Err(vm.type_error("group() takes no keyword arguments"));
    }

    let keys = &args.positional[1..];
    match keys {
        [] => data.text(vm, 0, &Value::None),
        [key] => {
            let index = data.checked_index(vm, key)?;
            data.text(vm, index, &Value::None)
        }
        keys => {
            let mut texts = Vec::with_capacity(keys.len());
            for key in keys {
                let index = data.checked_index(vm, key)?;
                texts.push(data.text(vm, index, &Value::None)?);
            }
            Ok(Value::tuple(texts))
        }
    }
}

/// The optional group argument of `start`, `end`, and `span`.
fn group_argument(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<usize> {
    let data = receiver(vm, args, method)?;
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method}() takes no keyword arguments")));
    }

    match &args.positional[1..] {
        [] => Ok(0),
        [key] => data.checked_index(vm, key),
        given => Err(vm.type_error(&format!("{method} expected at most 1 arguments, got {}", given.len()))),
    }
}

fn match_start(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let index = group_argument(vm, &args, "start")?;
    let data = receiver(vm, &args, "start")?;

    Ok(vm.new_int_from_i64(data.bounds(index).0))
}

fn match_end(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let index = group_argument(vm, &args, "end")?;
    let data = receiver(vm, &args, "end")?;

    Ok(vm.new_int_from_i64(data.bounds(index).1))
}

fn match_span(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let index = group_argument(vm, &args, "span")?;
    let data = receiver(vm, &args, "span")?;
    let (start, end) = data.bounds(index);

    Ok(Value::tuple(vec![vm.new_int_from_i64(start), vm.new_int_from_i64(end)]))
}

/// The `default` argument of `groups` and `groupdict`.
fn default_argument(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<Value> {
    let rest = CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    let slots = parse(vm, rest, method, &["default"], 0)?;

    Ok(slots.into_iter().next().flatten().unwrap_or(Value::None))
}

fn match_groups(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = receiver(vm, &args, "groups")?;
    let default = default_argument(vm, &args, "groups")?;

    let mut texts = Vec::with_capacity(data.spans.len().saturating_sub(1));
    for index in 1..data.spans.len() {
        texts.push(data.text(vm, index, &default)?);
    }

    Ok(Value::tuple(texts))
}

/// `groupdict`: each key `groupindex.keys()` lists with the text of its
/// group.
fn match_groupdict(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = receiver(vm, &args, "groupdict")?;
    let default = default_argument(vm, &args, "groupdict")?;
    let result = vm.new_dict();
    let Some(groupindex) = data.pattern_data().and_then(|pattern| pattern.groupindex.as_ref()) else {
        return Ok(Value::Object(result));
    };

    let listed = vm.call_method(groupindex, "keys", Vec::new())?;
    let iterator = vm.iter(&listed)?;
    let mut keys = Vec::new();
    while let Some(key) = vm.next(&iterator)? {
        keys.push(key);
    }
    for key in keys {
        let index = data.checked_index(vm, &key)?;
        let text = data.text(vm, index, &default)?;
        vm.dict_set(&result, key, text)?;
    }

    Ok(Value::Object(result))
}

/// `expand(template)`, through `re._expand`.
fn match_expand(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = receiver(vm, &args, "expand")?;
    let template = method_one_argument(vm, &args, "expand")?;
    let receiver = args.positional[0].clone();

    let module = vm.import_module("re")?;
    let expand = vm.getattr_str(&module, "_expand")?;

    vm.call(&expand, CallArgs::new(vec![data.pattern.clone(), receiver, template]))
}

fn match_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "__copy__")?;
    method_no_arguments(vm, &args, "__copy__")?;

    Err(vm.type_error("cannot copy this match object"))
}

fn match_deepcopy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receiver(vm, &args, "__deepcopy__")?;
    method_one_argument(vm, &args, "__deepcopy__")?;

    Err(vm.type_error("cannot deepcopy this match object"))
}
