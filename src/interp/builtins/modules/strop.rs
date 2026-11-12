//! `strop`: the string constants `string.py` imports and the deprecated
//! byte string functions. Character classes follow the C locale; under
//! another `LC_CTYPE` they depend on the host.

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::locale;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The characters of the C locale's `isspace`.
const C_WHITESPACE: &str = "\t\n\x0b\x0c\r ";

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const FUNCTIONS: &[MethodSpec] = &[
        function("capitalize", capitalize),
        function("count", count),
        function("expandtabs", expandtabs),
        function("find", find),
        function("join", join),
        function("joinfields", joinfields),
        function("lstrip", lstrip),
        function("lower", lower),
        function("maketrans", maketrans),
        function("replace", replace),
        function("rfind", rfind),
        function("rstrip", rstrip),
        function("split", split),
        function("splitfields", split),
        function("strip", strip),
        function("swapcase", swapcase),
        function("translate", translate),
        function("upper", upper),
    ];
    install_functions(vm, module, FUNCTIONS)?;

    let known = locale::ctype_is_c(vm);
    for (name, text) in [("whitespace", C_WHITESPACE), ("lowercase", locale::C_LOWERCASE), ("uppercase", locale::C_UPPERCASE)] {
        let value = if known { Value::str(text) } else { Value::unknown("character classes of the host locale") };
        set_attribute(vm, module, name, value)?;
    }

    Ok(())
}

/// C locale `isspace`.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Str(PyBytes::new(bytes))
}

/// The string data of a single-argument function's argument, or the
/// unknown result when the argument or the character classes are unknown.
fn single_string(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Result<(Value, PyBytes), Value>> {
    let value = args::single(vm, args, function)?;
    if value.is_unknown() {
        return Ok(Err(value));
    }

    let bytes = args::string_or_unicode(vm, &value)?;
    if !locale::ctype_is_c(vm) {
        return Ok(Err(Value::unknown("character classes of the host locale")));
    }

    Ok(Ok((value, bytes)))
}

/// Applies a per-byte case mapping; an unchanged string returns the
/// argument itself.
fn map_case(vm: &Vm, args: CallArgs, function: &str, mapping: fn(usize, u8) -> u8) -> PyResult<Value> {
    let (value, bytes) = match single_string(vm, args, function)? {
        Ok(found) => found,
        Err(unknown) => return Ok(unknown),
    };

    let mapped: Vec<u8> = bytes.as_bytes().iter().enumerate().map(|(index, &byte)| mapping(index, byte)).collect();
    if mapped == bytes.as_bytes() {
        return Ok(value);
    }

    Ok(Value::Str(PyBytes::new_unshared(mapped)))
}

fn lower(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    map_case(vm, args, "lower", |_, byte| byte.to_ascii_lowercase())
}

fn upper(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    map_case(vm, args, "upper", |_, byte| byte.to_ascii_uppercase())
}

fn swapcase(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    map_case(vm, args, "swapcase", |_, byte| if byte.is_ascii_lowercase() { byte.to_ascii_uppercase() } else { byte.to_ascii_lowercase() })
}

fn capitalize(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    map_case(vm, args, "capitalize", |index, byte| if index == 0 { byte.to_ascii_uppercase() } else { byte.to_ascii_lowercase() })
}

/// Which ends a strip function strips.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Strip {
    Left,
    Right,
    Both,
}

/// Removes whitespace; an unchanged string returns the argument
/// itself.
fn do_strip(vm: &Vm, args: CallArgs, function: &str, strip: Strip) -> PyResult<Value> {
    let (value, bytes) = match single_string(vm, args, function)? {
        Ok(found) => found,
        Err(unknown) => return Ok(unknown),
    };

    let data = bytes.as_bytes();
    let start = if strip == Strip::Right { 0 } else { data.iter().position(|&byte| !is_space(byte)).unwrap_or(data.len()) };
    let end = if strip == Strip::Left { data.len() } else { data.iter().rposition(|&byte| !is_space(byte)).map_or(start, |last| (last + 1).max(start)) };
    if start == 0 && end == data.len() {
        return Ok(value);
    }

    Ok(bytes_value(data[start..end].to_vec()))
}

fn strip(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    do_strip(vm, args, "strip", Strip::Both)
}

fn lstrip(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    do_strip(vm, args, "lstrip", Strip::Left)
}

fn rstrip(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    do_strip(vm, args, "rstrip", Strip::Right)
}

/// Words separated by runs of whitespace; with
/// `maxsplit`, the rest after that many words is the last item.
fn split_whitespace(data: &[u8], maxsplit: i64) -> Vec<Value> {
    let mut words = Vec::new();
    let mut position = 0;
    let mut count = 0i64;

    while position < data.len() {
        while data.get(position).copied().is_some_and(is_space) {
            position += 1;
        }
        let start = position;
        while data.get(position).is_some_and(|&byte| !is_space(byte)) {
            position += 1;
        }
        if start == position {
            continue;
        }

        words.push(bytes_value(data[start..position].to_vec()));
        count += 1;
        while data.get(position).copied().is_some_and(is_space) {
            position += 1;
        }
        if maxsplit != 0 && count >= maxsplit && position < data.len() {
            words.push(bytes_value(data[position..].to_vec()));
            position = data.len();
        }
    }

    words
}

/// `split(s[, sep[, maxsplit]])` and `splitfields`.
fn split(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "split", 1, 3)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::character_buffer(vm, "split", 1, &args[0])?;
    let separator = args::optional_read_buffer(vm, "split", 2, args.get(1))?;
    let maxsplit = args.get(2).map(|value| args::ssize(vm, value)).transpose()?.unwrap_or(0);
    let data = data.as_bytes();

    let Some(separator) = separator else {
        if !locale::ctype_is_c(vm) {
            return Ok(Value::unknown("character classes of the host locale"));
        }
        return Ok(vm.new_list(split_whitespace(data, maxsplit)));
    };
    let separator = separator.as_bytes();
    if separator.is_empty() {
        return Err(vm.raise(ExceptionKind::ValueError, "empty separator"));
    }

    let mut fields = Vec::new();
    let mut start = 0;
    let mut position = 0;
    let mut count = 0i64;
    while position + separator.len() <= data.len() {
        if !data[position..].starts_with(separator) {
            position += 1;
            continue;
        }
        fields.push(bytes_value(data[start..position].to_vec()));
        position += separator.len();
        start = position;
        count += 1;
        if maxsplit != 0 && count >= maxsplit {
            break;
        }
    }
    fields.push(bytes_value(data[start..].to_vec()));

    Ok(vm.new_list(fields))
}

/// The bytes of a `str` item of a joined sequence.
fn joined_item(vm: &Vm, item: &Value) -> PyResult<PyBytes> {
    vm.as_str_bytes(item).ok_or_else(|| vm.type_error("first argument must be sequence of strings"))
}

/// `join(list[, sep])`: the strings of a sequence with `sep` (a space by
/// default) between them.
fn join_strings(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "join", 1, 2)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let sequence = &args[0];
    let separator = match args.get(1) {
        Some(value) => args::character_buffer(vm, "join", 2, value)?,
        None => PyBytes::from(" "),
    };

    let is_mapping = matches!(sequence, Value::Object(object) if matches!(object.payload, Payload::Dict(_)));
    let length = if is_mapping { None } else { vm.len(sequence)? };
    let Some(length) = length else {
        return Err(vm.type_error(&format!("object of type '{}' has no len()", args::type_name(vm, sequence))));
    };
    let is_set = matches!(sequence, Value::Object(object) if matches!(object.payload, Payload::Set(_) | Payload::FrozenSet(_)));

    if length == 1 {
        if is_set {
            return Err(vm.type_error(&format!("'{}' object does not support indexing", args::type_name(vm, sequence))));
        }
        let item = vm.getitem(sequence, &Value::Int(0))?;
        if item.is_unknown() {
            return Ok(item);
        }
        joined_item(vm, &item)?;
        return Ok(item);
    }
    if is_set {
        return Err(vm.type_error("first argument must be a sequence"));
    }

    let items = match vm.as_list(sequence) {
        Some(items) => items,
        None => (0..length).map(|index| vm.getitem(sequence, &args::index_value(index))).collect::<PyResult<Vec<Value>>>()?,
    };
    let mut joined = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if item.is_unknown() {
            return Ok(item.clone());
        }
        let bytes = joined_item(vm, item)?;
        if index > 0 {
            joined.extend_from_slice(separator.as_bytes());
        }
        joined.extend_from_slice(bytes.as_bytes());
    }

    Ok(Value::Str(PyBytes::allocate(joined)))
}

fn join(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    join_strings(vm, args)
}

fn joinfields(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    join_strings(vm, args)
}

/// The string, substring, and slice bounds of `find`, `rfind`, and
/// `count`, with the bounds adjusted as slice indices.
struct Search {
    data: PyBytes,
    pattern: PyBytes,
    start: i64,
    last: i64,
}

fn search_arguments(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Result<Search, Value>> {
    let args = args::varargs(vm, args, function, 2, 4)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(Err(unknown));
    }

    let data = args::character_buffer(vm, function, 1, &args[0])?;
    let pattern = args::character_buffer(vm, function, 2, &args[1])?;
    let start = args.get(2).map(|value| args::ssize(vm, value)).transpose()?.unwrap_or(0);
    let last = args.get(3).map(|value| args::ssize(vm, value)).transpose()?.unwrap_or(i64::MAX);

    let length = i64::try_from(data.as_bytes().len()).unwrap_or(i64::MAX);
    let mut last = last.min(length);
    if last < 0 {
        last += length;
    }
    let last = last.max(0);
    let start = if start < 0 { (start + length).max(0) } else { start };

    Ok(Ok(Search { data, pattern, start, last }))
}

impl Search {
    /// Whether the pattern occurs at `position`.
    fn matches_at(&self, position: i64) -> bool {
        let Ok(position) = usize::try_from(position) else {
            return false;
        };

        self.data.as_bytes().get(position..).is_some_and(|rest| rest.starts_with(self.pattern.as_bytes()))
    }

    fn pattern_length(&self) -> i64 {
        i64::try_from(self.pattern.as_bytes().len()).unwrap_or(i64::MAX)
    }
}

/// `find(s, sub[, start[, end]])`.
fn find(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let search = match search_arguments(vm, args, "find")? {
        Ok(search) => search,
        Err(unknown) => return Ok(unknown),
    };

    let length = search.pattern_length();
    if length == 0 && search.start <= search.last {
        return Ok(Value::Int(search.start));
    }

    let found = (search.start..=search.last - length).find(|&position| search.matches_at(position));

    Ok(Value::Int(found.unwrap_or(-1)))
}

/// `rfind(s, sub[, start[, end]])`.
fn rfind(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let search = match search_arguments(vm, args, "rfind")? {
        Ok(search) => search,
        Err(unknown) => return Ok(unknown),
    };

    let length = search.pattern_length();
    if length == 0 && search.start <= search.last {
        return Ok(Value::Int(search.last));
    }

    let found = (search.start..=search.last - length).rev().find(|&position| search.matches_at(position));

    Ok(Value::Int(found.unwrap_or(-1)))
}

/// `count(s, sub[, start[, end]])`: non-overlapping occurrences.
fn count(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let search = match search_arguments(vm, args, "count")? {
        Ok(search) => search,
        Err(unknown) => return Ok(unknown),
    };

    let length = search.pattern_length();
    let limit = search.last + 1 - length;
    if length == 0 {
        return Ok(Value::Int(limit - search.start));
    }

    let mut occurrences = 0;
    let mut position = search.start;
    while position < limit {
        if search.matches_at(position) {
            occurrences += 1;
            position += length;
        } else {
            position += 1;
        }
    }

    Ok(Value::Int(occurrences))
}

/// `replace(str, old, new[, maxsplit])`: a count of 0 replaces every
/// occurrence; without a replacement the argument itself returns.
fn replace(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "replace", 3, 4)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::character_buffer(vm, "replace", 1, &args[0])?;
    let pattern = args::character_buffer(vm, "replace", 2, &args[1])?;
    let substitute = args::character_buffer(vm, "replace", 3, &args[2])?;
    let limit = args.get(3).map(|value| args::ssize(vm, value)).transpose()?.unwrap_or(-1);
    let (data, pattern, substitute) = (data.as_bytes(), pattern.as_bytes(), substitute.as_bytes());
    if pattern.is_empty() {
        return Err(vm.raise(ExceptionKind::ValueError, "empty pattern string"));
    }

    let limit = usize::try_from(limit).ok().filter(|limit| *limit != 0);
    let mut replaced = Vec::with_capacity(data.len());
    let mut position = 0;
    let mut replacements = 0;
    while limit.is_none_or(|limit| replacements < limit) {
        let Some(offset) = data[position..].windows(pattern.len()).position(|window| window == pattern) else {
            break;
        };
        replaced.extend_from_slice(&data[position..position + offset]);
        replaced.extend_from_slice(substitute);
        position += offset + pattern.len();
        replacements += 1;
    }
    if replacements == 0 {
        return Ok(args[0].clone());
    }
    replaced.extend_from_slice(&data[position..]);

    Ok(bytes_value(replaced))
}

/// `expandtabs(string[, tabsize])`.
fn expandtabs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "expandtabs", 1, 2)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let data = args::read_buffer(vm, "expandtabs", 1, &args[0])?;
    let tab_size = args.get(1).map(|value| args::c_int(vm, value)).transpose()?.unwrap_or(8);
    let Some(tab_size) = usize::try_from(tab_size).ok().filter(|size| *size >= 1) else {
        return Err(vm.raise(ExceptionKind::ValueError, "tabsize must be at least 1"));
    };

    let mut expanded = Vec::with_capacity(data.as_bytes().len());
    let mut column = 0;
    for &byte in data.as_bytes() {
        if byte == b'\t' {
            let spaces = tab_size - column % tab_size;
            expanded.extend(std::iter::repeat_n(b' ', spaces));
            column += spaces;
            continue;
        }
        expanded.push(byte);
        column = if byte == b'\n' { 0 } else { column + 1 };
    }

    Ok(Value::Str(PyBytes::new_unshared(expanded)))
}

/// `maketrans(frm, to)`: a 256 byte table mapping `frm` to `to`.
fn maketrans(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "maketrans", 2, 2)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let from = args::character_buffer(vm, "maketrans", 1, &args[0])?;
    let to = args::character_buffer(vm, "maketrans", 2, &args[1])?;
    if from.as_bytes().len() != to.as_bytes().len() {
        return Err(vm.raise(ExceptionKind::ValueError, "maketrans arguments must have same length"));
    }

    let mut table: Vec<u8> = (0..=255).collect();
    for (&source, &target) in from.as_bytes().iter().zip(to.as_bytes()) {
        table[usize::from(source)] = target;
    }

    Ok(Value::Str(PyBytes::new_unshared(table)))
}

/// `translate(s, table[, deletechars])`: an unchanged string returns the
/// argument itself.
fn translate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "translate", 2, 3)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let input = args::exact_string(vm, "translate", 1, &args[0])?;
    let table = args::character_buffer(vm, "translate", 2, &args[1])?;
    let deletions = args.get(2).map(|value| args::character_buffer(vm, "translate", 3, value)).transpose()?;
    let Ok(table) = <&[u8; 256]>::try_from(table.as_bytes()) else {
        return Err(vm.raise(ExceptionKind::ValueError, "translation table must be 256 characters long"));
    };

    let mut deleted = [false; 256];
    for &byte in deletions.as_ref().map(PyBytes::as_bytes).unwrap_or_default() {
        deleted[usize::from(byte)] = true;
    }

    let translated: Vec<u8> = input.as_bytes().iter().filter(|&&byte| !deleted[usize::from(byte)]).map(|&byte| table[usize::from(byte)]).collect();
    if translated == input.as_bytes() {
        return Ok(args[0].clone());
    }

    // Deletions shrink the output.
    if deletions.is_some_and(|deletions| !deletions.as_bytes().is_empty()) {
        return Ok(Value::Str(PyBytes::allocate(translated)));
    }

    Ok(Value::Str(PyBytes::new_unshared(translated)))
}
