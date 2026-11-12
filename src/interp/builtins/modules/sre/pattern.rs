//! `SRE_Pattern`: the compiled pattern and its search methods.

use std::rc::Rc;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::locale::ctype_is_c;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::sre::classify::Fold;
use crate::interp::builtins::modules::sre::engine::EngineError;
use crate::interp::builtins::modules::sre::engine::Span;
use crate::interp::builtins::modules::sre::matches::new_match;
use crate::interp::builtins::modules::sre::opcode::FLAG_LOCALE;
use crate::interp::builtins::modules::sre::program::Program;
use crate::interp::builtins::modules::sre::scan::Repeated;
use crate::interp::builtins::modules::sre::scan::Run;
use crate::interp::builtins::modules::sre::scan::repeated;
use crate::interp::builtins::modules::sre::scan::single;
use crate::interp::builtins::modules::sre::scanner::new_scanner;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::modules::sre::subject::Subject;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::warnings::warn_caller;
use crate::interp::builtins::parse_with;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub const PATTERN_TYPE: &str = "_sre.SRE_Pattern";

/// The part of a pattern the matcher runs, present when every argument of
/// `_sre.compile` was known.
pub struct Compiled {
    pub program: Rc<Program>,
    pub flags: i64,
    pub groups: usize,
}

/// A compiled pattern (`PatternObject`). Absent optional arguments of
/// `_sre.compile` are `None`, which reads as Python `None`.
pub struct PatternData {
    pub pattern: Value,
    pub flags: Value,
    pub groups: Value,
    pub groupindex: Option<Value>,
    pub indexgroup: Option<Value>,
    pub compiled: Option<Compiled>,
}

impl_native_data!(PatternData, "_sre.SRE_Pattern");

impl PatternData {
    /// What the matcher needs, or `None` when the outcome is unknown: the
    /// code was not known, or it folds case by a host locale other than C.
    pub fn runnable(&self, vm: &Vm) -> Option<(&Compiled, Fold)> {
        let compiled = self.compiled.as_ref()?;
        if compiled.flags & FLAG_LOCALE != 0 && !ctype_is_c(vm) {
            return None;
        }

        Some((compiled, Fold::from_flags(compiled.flags)))
    }
}

pub fn new_pattern(vm: &Vm, data: PatternData) -> PyResult<Value> {
    let class = native_type(vm, PATTERN_TYPE, create_pattern_type)?;

    Ok(new_native_object(vm, &class, data))
}

fn create_pattern_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "SRE_Pattern",
            module: "_sre",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("match", pattern_match),
                method("search", pattern_search),
                method("sub", pattern_sub),
                method("subn", pattern_subn),
                method("split", pattern_split),
                method("findall", pattern_findall),
                method("finditer", pattern_finditer),
                method("scanner", pattern_scanner),
                method("__copy__", pattern_copy),
                method("__deepcopy__", pattern_deepcopy),
            ],
        },
    )?;

    add_member(vm, &class, GetSet { name: "pattern", owner: PATTERN_TYPE, get: member_pattern, set: None })?;
    add_member(vm, &class, GetSet { name: "flags", owner: PATTERN_TYPE, get: member_flags, set: None })?;
    add_member(vm, &class, GetSet { name: "groups", owner: PATTERN_TYPE, get: member_groups, set: None })?;
    add_member(vm, &class, GetSet { name: "groupindex", owner: PATTERN_TYPE, get: member_groupindex, set: None })?;

    Ok(class)
}

fn pattern_of<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a PatternData> {
    native_data::<PatternData>(instance).ok_or_else(|| crate::interp::builtins::modules::descriptor_mismatch(vm, getset, instance))
}

fn member_pattern(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(pattern_of(vm, getset, instance)?.pattern.clone())
}

fn member_flags(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(pattern_of(vm, getset, instance)?.flags.clone())
}

fn member_groups(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(pattern_of(vm, getset, instance)?.groups.clone())
}

fn member_groupindex(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(pattern_of(vm, getset, instance)?.groupindex.clone().unwrap_or(Value::None))
}

/// Splits off the pattern a method is called on.
fn receiver(vm: &Vm, mut args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    this::<PatternData>(vm, &args, PATTERN_TYPE, method)?;
    let receiver = args.positional.remove(0);

    Ok((receiver, args))
}

/// The pattern data of a receiver `receiver` already checked.
fn data<'a>(vm: &Vm, value: &'a Value) -> PyResult<&'a PatternData> {
    native_data::<PatternData>(value).ok_or_else(|| vm.type_error("receiver is not a compiled pattern"))
}

/// A parsed argument: an object, or an index.
enum Argument {
    Object(Value),
    Size(i64),
}

impl Argument {
    fn object(self) -> Option<Value> {
        match self {
            Argument::Object(value) => Some(value),
            Argument::Size(_) => None,
        }
    }

    fn size(self) -> Option<i64> {
        match self {
            Argument::Size(size) => Some(size),
            Argument::Object(_) => None,
        }
    }
}

/// Binds the arguments of a method that takes the subject as `string`,
/// or under the deprecated name `old_name` as the last keyword, followed
/// by `sizes` size arguments. At most `limit` arguments may be given in
/// all.
fn subject_arguments(vm: &Vm, args: CallArgs, method: &str, sizes: &[&str], old_name: &str) -> PyResult<(Value, Vec<Option<i64>>)> {
    let limit = sizes.len() + 1;
    let keyword_count = match &args.keyword_dict {
        Some(dict) => vm.dict_len(dict)?,
        None => args.keywords.len(),
    };
    let given = args.positional.len() + keyword_count;
    if given > limit {
        return Err(vm.type_error(&format!("{method}() takes at most {limit} positional arguments ({given} given)")));
    }

    let mut names = vec!["string"];
    names.extend_from_slice(sizes);
    names.push(old_name);
    let last = names.len() - 1;
    let mut slots = parse_with(vm, args, method, &names, 0, |vm, index, value| {
        if index == 0 || index == last { Ok(Argument::Object(value)) } else { Ok(Argument::Size(ssize_argument(vm, &value)?)) }
    })?
    .into_iter();

    let string = slots.next().flatten().and_then(Argument::object);
    let sizes: Vec<Option<i64>> = slots.by_ref().take(sizes.len()).map(|slot| slot.and_then(Argument::size)).collect();
    let old = slots.next().flatten().and_then(Argument::object);

    let string = match (string, old) {
        (Some(_), Some(_)) => return Err(vm.type_error(&format!("Argument given by name ('{old_name}') and position (1)"))),
        (None, Some(old)) => {
            warn_caller(vm, ExceptionKind::DeprecationWarning, &format!("The '{old_name}' keyword parameter name is deprecated.  Use 'string' instead."))?;
            old
        }
        (Some(string), None) => string,
        (None, None) => return Err(vm.type_error("Required argument 'string' (pos 1) not found")),
    };

    Ok((string, sizes))
}

/// The subject with its start and end clamped to it.
pub struct Bounded {
    pub subject: Subject,
    pub start: usize,
    pub end: usize,
}

impl Bounded {
    /// `None` when the subject is unknown.
    pub fn new(vm: &Vm, string: &Value, start: i64, end: i64) -> PyResult<Option<Self>> {
        let Some(subject) = Subject::from_value(vm, string)? else {
            return Ok(None);
        };
        let length = subject.len();
        let clamp = |bound: i64| usize::try_from(bound.max(0)).map_or(length, |bound| bound.min(length));

        Ok(Some(Self { start: clamp(start), end: clamp(end), subject }))
    }

    pub fn run<'a>(&self, compiled: &'a Compiled, fold: Fold, start: usize) -> Run<'a> {
        Run { program: &compiled.program, fold, start, end: self.end, groups: compiled.groups }
    }
}

pub fn engine_error(vm: &Vm, error: EngineError) -> Signal {
    vm.raise(ExceptionKind::RuntimeError, &error.to_string())
}

fn unknown(method: &str) -> Value {
    Value::unknown(format!("_sre.SRE_Pattern.{method} with an unknown pattern or subject"))
}

fn pattern_match(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    single_match(vm, args, "match", true)
}

fn pattern_search(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    single_match(vm, args, "search", false)
}

fn single_match(vm: &Vm, args: CallArgs, method: &str, anchored: bool) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, method)?;
    let (string, sizes) = subject_arguments(vm, args, method, &["pos", "endpos"], "pattern")?;
    let pattern = data(vm, &receiver)?;

    let start = sizes[0].unwrap_or(0);
    let end = sizes[1].unwrap_or(i64::MAX);
    let Some(bounded) = Bounded::new(vm, &string, start, end)? else {
        return Ok(unknown(method));
    };
    let Some((compiled, fold)) = pattern.runnable(vm) else {
        return Ok(unknown(method));
    };

    let found = single(bounded.subject.units(), bounded.run(compiled, fold, bounded.start), anchored).map_err(|error| engine_error(vm, error))?;
    match found {
        Some(found) => new_match(vm, &receiver, &string, found, bounded.start, bounded.end),
        None => Ok(Value::None),
    }
}

/// A slice of the subject, taken as the `[start:end]` operator takes it.
pub fn slice(vm: &Vm, string: &Value, start: usize, end: usize) -> PyResult<Value> {
    vm.get_slice(string, &vm.new_int_from_i64(start as i64), &vm.new_int_from_i64(end as i64))
}

/// A group of a match for `findall` and `split`: its text, or `missing`
/// when it did not take part.
fn group_text(vm: &Vm, string: &Value, span: Option<Span>, missing: impl FnOnce() -> PyResult<Value>) -> PyResult<Value> {
    match span {
        Some(span) => slice(vm, string, span.start, span.end),
        None => missing(),
    }
}

fn pattern_findall(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, "findall")?;
    let (string, sizes) = subject_arguments(vm, args, "findall", &["pos", "endpos"], "source")?;
    let pattern = data(vm, &receiver)?;

    let Some(bounded) = Bounded::new(vm, &string, sizes[0].unwrap_or(0), sizes[1].unwrap_or(i64::MAX))? else {
        return Ok(unknown("findall"));
    };
    let Some((compiled, fold)) = pattern.runnable(vm) else {
        return Ok(unknown("findall"));
    };

    let found = repeated(bounded.subject.units(), bounded.run(compiled, fold, bounded.start), Repeated::FindAll).map_err(|error| engine_error(vm, error))?;
    let empty = || slice(vm, &string, 0, 0);
    let mut items = Vec::with_capacity(found.len());
    for found in found {
        let item = match compiled.groups {
            0 => slice(vm, &string, found.whole.start, found.whole.end)?,
            1 => group_text(vm, &string, found.groups[0], empty)?,
            _ => {
                let mut fields = Vec::with_capacity(compiled.groups);
                for span in &found.groups {
                    fields.push(group_text(vm, &string, *span, empty)?);
                }
                Value::tuple(fields)
            }
        };
        items.push(item);
    }

    Ok(vm.new_list(items))
}

fn pattern_split(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, "split")?;
    let (string, sizes) = subject_arguments(vm, args, "split", &["maxsplit"], "source")?;
    let pattern = data(vm, &receiver)?;

    let Some(bounded) = Bounded::new(vm, &string, 0, i64::MAX)? else {
        return Ok(unknown("split"));
    };
    let Some((compiled, fold)) = pattern.runnable(vm) else {
        return Ok(unknown("split"));
    };

    // A negative maxsplit allows no split at all.
    let limit = match sizes[0].unwrap_or(0) {
        0 => None,
        limit => Some(usize::try_from(limit).unwrap_or(0)),
    };
    let found = repeated(bounded.subject.units(), bounded.run(compiled, fold, 0), Repeated::Split { limit }).map_err(|error| engine_error(vm, error))?;

    let mut items = Vec::new();
    let mut last = 0;
    for found in found {
        items.push(slice(vm, &string, last, found.whole.start)?);
        for span in &found.groups {
            items.push(group_text(vm, &string, *span, || Ok(Value::None))?);
        }
        last = found.whole.end;
    }
    items.push(slice(vm, &string, last, bounded.end)?);

    Ok(vm.new_list(items))
}

fn pattern_sub(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    substitute(vm, args, "sub").map(|(result, _)| result)
}

fn pattern_subn(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (result, count) = substitute(vm, args, "subn")?;
    if result.is_unknown() {
        return Ok(result);
    }

    Ok(Value::tuple(vec![result, vm.new_int_from_i64(count as i64)]))
}

/// How each match is replaced.
enum Replacement {
    /// Called with the match object; `None` results are dropped.
    Call(Value),
    /// Inserted as is.
    Literal(Value),
}

/// `sub` and `subn`: the result and the number of replacements.
fn substitute(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, usize)> {
    let (receiver, args) = receiver(vm, args, method)?;
    let mut slots = parse_with(vm, args, method, &["repl", "string", "count"], 2, |vm, index, value| {
        if index == 2 { Ok(Argument::Size(ssize_argument(vm, &value)?)) } else { Ok(Argument::Object(value)) }
    })?
    .into_iter();
    let (Some(Some(template)), Some(Some(string))) = (slots.next().map(|slot| slot.and_then(Argument::object)), slots.next().map(|slot| slot.and_then(Argument::object))) else {
        return Err(vm.type_error(&format!("{method}() missing required arguments")));
    };
    let count = slots.next().flatten().and_then(Argument::size).unwrap_or(0);
    let pattern = data(vm, &receiver)?;

    if template.is_unknown() {
        return Ok((unknown(method), 0));
    }
    let replacement = replacement(vm, &receiver, template)?;

    let Some(bounded) = Bounded::new(vm, &string, 0, i64::MAX)? else {
        return Ok((unknown(method), 0));
    };
    let Some((compiled, fold)) = pattern.runnable(vm) else {
        return Ok((unknown(method), 0));
    };

    // A negative count allows no replacement at all.
    let limit = match count {
        0 => None,
        count => Some(usize::try_from(count).unwrap_or(0)),
    };
    let found = repeated(bounded.subject.units(), bounded.run(compiled, fold, 0), Repeated::Sub { limit }).map_err(|error| engine_error(vm, error))?;

    let mut pieces = Vec::new();
    let mut last = 0;
    let replaced = found.len();
    for found in found {
        let whole = found.whole;
        if last < whole.start {
            pieces.push(slice(vm, &string, last, whole.start)?);
        }
        let piece = match &replacement {
            Replacement::Call(function) => {
                let matched = new_match(vm, &receiver, &string, found, 0, bounded.end)?;
                vm.call1(function, matched)?
            }
            Replacement::Literal(text) => text.clone(),
        };
        if !piece.is_none() {
            pieces.push(piece);
        }
        last = whole.end;
    }
    if last < bounded.end {
        pieces.push(slice(vm, &string, last, bounded.end)?);
    }

    Ok((join(vm, &string, pieces)?, replaced))
}

/// Decides how `template` replaces matches: a callable is called, a
/// string without backslashes is inserted as is, and anything else goes
/// through `re._subx`.
fn replacement(vm: &Vm, pattern: &Value, template: Value) -> PyResult<Replacement> {
    if is_callable(vm, &template)? {
        return Ok(Replacement::Call(template));
    }

    let literal = match Subject::from_value(vm, &template) {
        Ok(Some(units)) => units.units().is_literal_template(),
        Ok(None) | Err(Signal::Raise(_)) => false,
        Err(halt) => return Err(halt),
    };
    if literal {
        return Ok(Replacement::Literal(template));
    }

    let module = vm.import_module("re")?;
    let subx = vm.getattr_str(&module, "_subx")?;
    let filter = vm.call(&subx, CallArgs::new(vec![pattern.clone(), template]))?;
    if is_callable(vm, &filter)? { Ok(Replacement::Call(filter)) } else { Ok(Replacement::Literal(filter)) }
}

/// Joins the pieces with an empty slice of the subject, so the result has
/// the subject's type.
fn join(vm: &Vm, string: &Value, pieces: Vec<Value>) -> PyResult<Value> {
    let joiner = slice(vm, string, 0, 0)?;
    if pieces.is_empty() {
        return Ok(joiner);
    }

    vm.call_method(&joiner, "join", vec![vm.new_list(pieces)])
}

/// The positional arguments of `scanner` and `finditer`.
fn scanner_arguments(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, i64, i64)> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{method}() takes no keyword arguments")));
    }
    let count = args.positional.len();
    if count == 0 {
        return Err(vm.type_error("scanner() takes at least 1 argument (0 given)"));
    }
    if count > 3 {
        return Err(vm.type_error(&format!("scanner() takes at most 3 arguments ({count} given)")));
    }

    let mut positional = args.positional.into_iter();
    let string = positional.next().unwrap_or(Value::None);
    let start = positional.next().map(|value| ssize_argument(vm, &value)).transpose()?.unwrap_or(0);
    let end = positional.next().map(|value| ssize_argument(vm, &value)).transpose()?.unwrap_or(i64::MAX);

    Ok((string, start, end))
}

fn pattern_scanner(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, "scanner")?;
    let (string, start, end) = scanner_arguments(vm, args, "scanner")?;

    new_scanner(vm, &receiver, string, start, end)
}

/// `finditer`: an iterator calling the scanner's `search` until it
/// returns `None`.
fn pattern_finditer(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, args) = receiver(vm, args, "finditer")?;
    let (string, start, end) = scanner_arguments(vm, args, "finditer")?;
    let scanner = new_scanner(vm, &receiver, string, start, end)?;
    if scanner.is_unknown() {
        return Ok(scanner);
    }

    let search = vm.getattr_str(&scanner, "search")?;

    Ok(vm.new_iterator(crate::interp::object::NativeIterator::Callable { function: search, sentinel: Value::None }))
}

fn pattern_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<PatternData>(vm, &args, PATTERN_TYPE, "__copy__")?;
    method_no_arguments(vm, &args, "__copy__")?;

    Err(vm.type_error("cannot copy this pattern object"))
}

fn pattern_deepcopy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<PatternData>(vm, &args, PATTERN_TYPE, "__deepcopy__")?;
    method_one_argument(vm, &args, "__deepcopy__")?;

    Err(vm.type_error("cannot deepcopy this pattern object"))
}
