//! `_json`: the scanner, encoder, and string helpers the `json` package
//! uses in place of its pure-Python ones.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::NativeFn;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const SCANNER_TYPE: &str = "_json.Scanner";
const ENCODER_TYPE: &str = "_json.Encoder";

/// A scanner object. It holds no settings until `__init__` succeeds; a
/// failed `__init__` clears them.
#[derive(Default)]
struct Scanner {
    settings: RefCell<Option<Rc<ScannerSettings>>>,
}

impl_native_data!(Scanner, "_json.Scanner");

/// What a scanner reads from its context object.
struct ScannerSettings {
    encoding: PyBytes,
    strict: Value,
    object_hook: Value,
    pairs_hook: Value,
    parse_float: Value,
    parse_int: Value,
    parse_constant: Value,
}

/// An encoder object. It holds no settings until `__init__` succeeds; a
/// failed `__init__` keeps the previous ones.
#[derive(Default)]
struct Encoder {
    settings: RefCell<Option<Rc<EncoderSettings>>>,
}

impl_native_data!(Encoder, "_json.Encoder");

struct EncoderSettings {
    markers: Value,
    default: Value,
    encoder: Value,
    indent: Value,
    key_separator: Value,
    item_separator: Value,
    sort_keys: Value,
    skipkeys: Value,

    allows_nan: bool,
}

/// String objects the module hands out repeatedly as the same object.
#[derive(Default)]
struct JsonState {
    shared: RefCell<HashMap<&'static str, Value>>,
}

/// Which scanner a document gets: `str` documents and `unicode` ones
/// differ in some messages and in how string contents are decoded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    Bytes,
    Text,
}

impl DocumentKind {
    fn array_depth_context(self) -> &'static str {
        match self {
            Self::Bytes => " while decoding a JSON array from a byte string",
            Self::Text => " while decoding a JSON array from a unicode string",
        }
    }

    fn object_depth_context(self) -> &'static str {
        match self {
            Self::Bytes => " while decoding a JSON object from a byte string",
            Self::Text => " while decoding a JSON object from a unicode string",
        }
    }

    fn colon_message(self) -> &'static str {
        match self {
            Self::Bytes => "Expecting : delimiter",
            Self::Text => "Expecting ':' delimiter",
        }
    }

    fn comma_message(self) -> &'static str {
        match self {
            Self::Bytes => "Expecting , delimiter",
            Self::Text => "Expecting ',' delimiter",
        }
    }

    /// A decoded string. Strings of a `str` document are always new
    /// objects; those of a `unicode` document share the interpreter's
    /// one-character strings.
    fn text_value(self, units: Vec<u16>) -> Value {
        match self {
            Self::Bytes => Value::Unicode(PyText::new_unshared(units)),
            Self::Text => Value::Unicode(PyText::new(units)),
        }
    }

    fn name_message(self) -> &'static str {
        match self {
            Self::Bytes => "Expecting property name",
            Self::Text => "Expecting property name enclosed in double quotes",
        }
    }
}

/// A code unit of a document: a byte of a `str`, or a UTF-16 unit of a
/// `unicode`.
trait DocumentUnit: Copy {
    fn code(self) -> u32;
}

impl DocumentUnit for u8 {
    fn code(self) -> u32 {
        u32::from(self)
    }
}

impl DocumentUnit for u16 {
    fn code(self) -> u32 {
        u32::from(self)
    }
}

/// A document being scanned.
struct Document<'a, U> {
    source: &'a Value,
    units: &'a [U],
    kind: DocumentKind,
}

impl<U> Document<'_, U>
where
    U: DocumentUnit,
{
    fn code_at(&self, index: usize) -> Option<u32> {
        self.units.get(index).map(|unit| unit.code())
    }

    fn is_at(&self, index: usize, character: u8) -> bool {
        self.code_at(index) == Some(u32::from(character))
    }

    fn matches(&self, index: usize, text: &str) -> bool {
        let bytes = text.as_bytes();

        index.checked_add(bytes.len()).is_some_and(|end| end <= self.units.len()) && bytes.iter().enumerate().all(|(offset, byte)| self.is_at(index + offset, *byte))
    }

    fn skip_whitespace(&self, mut index: usize) -> usize {
        while self.code_at(index).is_some_and(|code| matches!(code, 0x20 | 0x09 | 0x0A | 0x0D)) {
            index += 1;
        }

        index
    }

    /// The units in `start..end` as a `str` or `unicode` object.
    fn slice_value(&self, start: usize, end: usize) -> Value {
        let units = &self.units[start..end];
        match self.kind {
            DocumentKind::Bytes => Value::Str(PyBytes::new(units.iter().map(|unit| unit.code() as u8).collect::<Vec<u8>>())),
            DocumentKind::Text => Value::Unicode(PyText::new(units.iter().map(|unit| unit.code() as u16).collect::<Vec<u16>>())),
        }
    }
}

/// How the contents of a string literal become text.
enum RunDecoding<'a> {
    /// Runs of a `str` document decode with this codec.
    Codec(&'a PyBytes),
    /// Runs of a `unicode` document are its own units.
    Units,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("encode_basestring_ascii", encode_basestring_ascii), function("scanstring", scanstring)])?;

    set_attribute(vm, module, "make_scanner", Value::Object(native_type(vm, SCANNER_TYPE, create_scanner_type)?))?;

    set_attribute(vm, module, "make_encoder", Value::Object(native_type(vm, ENCODER_TYPE, create_encoder_type)?))
}

fn create_scanner_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "Scanner",
            module: "_json",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[static_method("__new__", scanner_new), method("__init__", scanner_init), method("__call__", scanner_call)],
        },
    )?;

    for name in ["encoding", "strict", "object_hook", "object_pairs_hook", "parse_float", "parse_int", "parse_constant"] {
        add_member(vm, &class, GetSet { name, owner: SCANNER_TYPE, get: scanner_member, set: None })?;
    }

    Ok(class)
}

fn create_encoder_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "Encoder",
            module: "_json",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[static_method("__new__", encoder_new), method("__init__", encoder_init), method("__call__", encoder_call)],
        },
    )?;

    for name in ["markers", "default", "encoder", "indent", "key_separator", "item_separator", "sort_keys", "skipkeys"] {
        add_member(vm, &class, GetSet { name, owner: ENCODER_TYPE, get: encoder_member, set: None })?;
    }

    Ok(class)
}

/// A string object the module hands out as one object per interpreter.
fn shared_string(vm: &Vm, text: &'static str) -> Value {
    let state = vm.native_state::<JsonState>();
    let mut shared = state.shared.borrow_mut();

    shared.entry(text).or_insert_with(|| Value::Str(vm.intern(&PyBytes::from(text)))).clone()
}

fn scanner_member(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(scanner) = native_data::<Scanner>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    let settings = scanner.settings.borrow();
    let Some(settings) = settings.as_ref() else {
        return Ok(Value::None);
    };

    let value = match getset.name {
        "encoding" => Value::Str(settings.encoding.clone()),
        "strict" => settings.strict.clone(),
        "object_hook" => settings.object_hook.clone(),
        "object_pairs_hook" => settings.pairs_hook.clone(),
        "parse_float" => settings.parse_float.clone(),
        "parse_int" => settings.parse_int.clone(),
        _ => settings.parse_constant.clone(),
    };

    Ok(value)
}

fn encoder_member(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(encoder) = native_data::<Encoder>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    let settings = encoder.settings.borrow();
    let Some(settings) = settings.as_ref() else {
        return Ok(Value::None);
    };

    let value = match getset.name {
        "markers" => settings.markers.clone(),
        "default" => settings.default.clone(),
        "encoder" => settings.encoder.clone(),
        "indent" => settings.indent.clone(),
        "key_separator" => settings.key_separator.clone(),
        "item_separator" => settings.item_separator.clone(),
        "sort_keys" => settings.sort_keys.clone(),
        _ => settings.skipkeys.clone(),
    };

    Ok(value)
}

/// `T.__new__(cls, ...)` for the two types, which allow no subclasses: an
/// object without settings, whatever the other arguments.
fn new_object<T>(vm: &Vm, args: &CallArgs, key: &'static str, create: fn(&Vm) -> PyResult<ObjectRef>) -> PyResult<Value>
where
    T: crate::interp::value::NativeData + Default,
{
    let class = native_type(vm, key, create)?;
    let name = vm.class_name(&class);
    let Some(first) = args.positional.first() else {
        return Err(vm.type_error(&format!("{name}.__new__(): not enough arguments")));
    };
    let Value::Object(given) = first else {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    };
    if given.as_class().is_none() {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    }
    if !Rc::ptr_eq(given, &class) {
        let given_name = vm.class_name(given);
        return Err(vm.type_error(&format!("{name}.__new__({given_name}): {given_name} is not a subtype of {name}")));
    }

    Ok(new_native_object(vm, &class, T::default()))
}

fn scanner_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    new_object::<Scanner>(vm, &args, SCANNER_TYPE, create_scanner_type)
}

fn encoder_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    new_object::<Encoder>(vm, &args, ENCODER_TYPE, create_encoder_type)
}

/// The arguments after the receiver of a native method.
fn after_receiver(args: &CallArgs) -> CallArgs {
    CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() }
}

/// `Scanner.__init__(context)`: reads the settings from the context.
fn scanner_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let scanner = this::<Scanner>(vm, &args, SCANNER_TYPE, "__init__")?;
    let values = parse(vm, after_receiver(&args), "make_scanner", &["context"], 1)?;
    let Some(Some(context)) = values.into_iter().next() else {
        return Err(vm.type_error("Required argument 'context' (pos 1) not found"));
    };

    match read_scanner_settings(vm, &context) {
        Ok(settings) => {
            *scanner.settings.borrow_mut() = Some(Rc::new(settings));
            Ok(Value::None)
        }
        Err(signal) => {
            *scanner.settings.borrow_mut() = None;
            Err(signal)
        }
    }
}

fn read_scanner_settings(vm: &Vm, context: &Value) -> PyResult<ScannerSettings> {
    let encoding = vm.getattr_str(context, "encoding")?;
    let encoding = if encoding.is_none() {
        PyBytes::from("utf-8")
    } else if let Some(bytes) = vm.as_str_bytes(&encoding) {
        bytes
    } else if let Some(text) = vm.as_text(&encoding) {
        crate::interp::builtins::modules::codecs::args::encode_default(vm, &text)?
    } else {
        return Err(vm.type_error(&format!("encoding must be a string, not {}", vm.type_name(&encoding))));
    };

    Ok(ScannerSettings {
        encoding,
        strict: vm.getattr_str(context, "strict")?,
        object_hook: vm.getattr_str(context, "object_hook")?,
        pairs_hook: vm.getattr_str(context, "object_pairs_hook")?,
        parse_float: vm.getattr_str(context, "parse_float")?,
        parse_int: vm.getattr_str(context, "parse_int")?,
        parse_constant: vm.getattr_str(context, "parse_constant")?,
    })
}

/// `ssize_t` conversion of an index argument: ints and longs, else through
/// `__int__`.
fn index_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let converted = match vm.lookup_special(value, "__long__")? {
                Some(method) => vm.call0(&method)?,
                None => match vm.lookup_special(value, "__int__")? {
                    Some(method) => vm.call0(&method)?,
                    None => return Err(vm.type_error("an integer is required")),
                },
            };
            let Some(integral) = vm.as_integral(&converted) else {
                return Err(vm.type_error("an integer is required"));
            };
            integral
        }
    };

    match integral {
        Integral::Int(number) => Ok(number),
        Integral::Long(number) => i64::try_from(&number).map_err(|_| vm.raise(ExceptionKind::OverflowError, "long int too large to convert to int")),
    }
}

/// `scanner(string, idx)`: `(value, end)` for the JSON value at `idx`, or
/// `StopIteration` when none starts there.
fn scanner_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let scanner = this::<Scanner>(vm, &args, SCANNER_TYPE, "__call__")?;
    let slots = parse_with(vm, after_receiver(&args), "scan_once", &["string", "idx"], 2, |vm, index, value| if index == 1 { index_argument(vm, &value).map(|index| (value, Some(index))) } else { Ok((value, None)) })?;
    let (Some((source, _)), Some((_, Some(index)))) = (slots.first().cloned().flatten(), slots.get(1).cloned().flatten()) else {
        return Err(vm.type_error("scan_once() requires a string and an index"));
    };
    if source.is_unknown() {
        return Ok(source);
    }

    let settings = scanner.settings.borrow().clone();
    let Some(settings) = settings else {
        return Err(vm.raise(ExceptionKind::SystemError, "null argument to internal routine"));
    };

    let (value, end) = if let Some(bytes) = vm.as_str_bytes(&source) {
        let document = Document { source: &source, units: bytes.as_bytes(), kind: DocumentKind::Bytes };
        scan_document(vm, &settings, &document, index)?
    } else if let Some(text) = vm.as_text(&source) {
        let document = Document { source: &source, units: text.units(), kind: DocumentKind::Text };
        scan_document(vm, &settings, &document, index)?
    } else {
        return Err(vm.type_error(&format!("first argument must be a string, not {}", vm.type_name(&source))));
    };

    Ok(Value::tuple(vec![value, vm.new_int_from_i64(end as i64)]))
}

fn scan_document<U>(vm: &Vm, settings: &ScannerSettings, document: &Document<'_, U>, index: i64) -> PyResult<(Value, usize)>
where
    U: DocumentUnit,
{
    if index < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "idx cannot be negative"));
    }
    let start = usize::try_from(index).unwrap_or(usize::MAX);

    let mut scan = Scan { vm, settings, document };
    match scan.value_at(start)? {
        Some(found) => Ok(found),
        None => Err(stop_iteration(vm)),
    }
}

/// One `scanner(...)` call.
struct Scan<'a, 'd, U> {
    vm: &'a Vm,
    settings: &'a ScannerSettings,
    document: &'a Document<'d, U>,
}

/// The value at an index and the index after it.
type Scanned = (Value, usize);

impl<U> Scan<'_, '_, U>
where
    U: DocumentUnit,
{
    /// The value starting at `index`; `None` when nothing that starts a
    /// value is there.
    fn value_at(&mut self, index: usize) -> PyResult<Option<Scanned>> {
        let document = self.document;
        let Some(code) = document.code_at(index) else {
            return Ok(None);
        };

        let found = match code {
            0x22 => {
                let (text, end) = self.string_at(index + 1)?;
                (document.kind.text_value(text), end)
            }
            0x7B => self.object_at(index + 1)?,
            0x5B => self.vm.with_depth_in(document.kind.array_depth_context(), || self.array_at(index + 1))?,
            0x6E if document.matches(index, "null") => (Value::None, index + 4),
            0x74 if document.matches(index, "true") => (Value::Bool(true), index + 4),
            0x66 if document.matches(index, "false") => (Value::Bool(false), index + 5),
            0x4E if document.matches(index, "NaN") => (self.constant("NaN")?, index + 3),
            0x49 if document.matches(index, "Infinity") => (self.constant("Infinity")?, index + 8),
            0x2D if document.matches(index, "-Infinity") => (self.constant("-Infinity")?, index + 9),
            _ => return self.number_at(index),
        };

        Ok(Some(found))
    }

    fn constant(&self, name: &'static str) -> PyResult<Value> {
        self.vm.call(&self.settings.parse_constant, CallArgs::new(vec![shared_string(self.vm, name)]))
    }

    /// A number: `-? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][-+]?[0-9]+)?`.
    fn number_at(&mut self, start: usize) -> PyResult<Option<Scanned>> {
        let document = self.document;
        let is_digit = |index: usize| document.code_at(index).is_some_and(|code| (0x30..=0x39).contains(&code));

        let mut index = start;
        if document.is_at(index, b'-') {
            index += 1;
        }
        if document.is_at(index, b'0') {
            index += 1;
        } else if is_digit(index) {
            while is_digit(index) {
                index += 1;
            }
        } else {
            return Ok(None);
        }

        let mut is_float = false;
        if document.is_at(index, b'.') && is_digit(index + 1) {
            is_float = true;
            index += 1;
            while is_digit(index) {
                index += 1;
            }
        }
        if document.is_at(index, b'e') || document.is_at(index, b'E') {
            let mut exponent = index + 1;
            if document.is_at(exponent, b'-') || document.is_at(exponent, b'+') {
                exponent += 1;
            }
            if is_digit(exponent) {
                is_float = true;
                index = exponent;
                while is_digit(index) {
                    index += 1;
                }
            }
        }

        let text = document.slice_value(start, index);
        let hook = if is_float { &self.settings.parse_float } else { &self.settings.parse_int };
        let value = self.vm.call(hook, CallArgs::new(vec![text]))?;

        Ok(Some((value, index)))
    }

    /// A string literal whose opening quote precedes `start`.
    fn string_at(&mut self, start: usize) -> PyResult<(Vec<u16>, usize)> {
        let strict = self.vm.truthy(&self.settings.strict, "scanner strict")?;
        let decoding = match self.document.kind {
            DocumentKind::Bytes => RunDecoding::Codec(&self.settings.encoding),
            DocumentKind::Text => RunDecoding::Units,
        };

        scan_string(self.vm, self.document, start, strict, &decoding)
    }

    /// An array whose `[` precedes `start`.
    fn array_at(&mut self, start: usize) -> PyResult<Scanned> {
        let vm = self.vm;
        let document = self.document;
        let last = document.units.len().saturating_sub(1);

        let mut items = Vec::new();
        let mut index = document.skip_whitespace(start);
        if document.is_at(index, b']') {
            return Ok((vm.new_list(items), index + 1));
        }
        loop {
            if index > last || document.units.is_empty() {
                return Err(decode_error(vm, "Expecting object", document.source, last));
            }
            let Some((item, end)) = self.value_at(index)? else {
                return Err(stop_iteration(vm));
            };
            items.push(item);

            index = document.skip_whitespace(end);
            if index > last {
                return Err(decode_error(vm, "Expecting object", document.source, last));
            }
            if document.is_at(index, b']') {
                return Ok((vm.new_list(items), index + 1));
            }
            if !document.is_at(index, b',') {
                return Err(decode_error(vm, document.kind.comma_message(), document.source, index));
            }
            index = document.skip_whitespace(index + 1);
        }
    }

    /// An object whose `{` precedes `start`. Each object level also takes
    /// the depth of one Python call, which runs out first when objects nest
    /// directly.
    fn object_at(&mut self, start: usize) -> PyResult<Scanned> {
        let vm = self.vm;
        vm.with_depth_in(self.document.kind.object_depth_context(), || {
            vm.with_depth_in(" while calling a Python object", || Ok(()))?;
            self.object_members(start)
        })
    }

    fn object_members(&mut self, start: usize) -> PyResult<Scanned> {
        let vm = self.vm;
        let document = self.document;
        let last = document.units.len().saturating_sub(1);

        let mut pairs: Vec<(Value, Value)> = Vec::new();
        let mut index = document.skip_whitespace(start);
        if !document.is_at(index, b'}') {
            loop {
                if index > last || document.units.is_empty() {
                    return Err(decode_error(vm, "Expecting object", document.source, last));
                }
                if !document.is_at(index, b'"') {
                    return Err(decode_error(vm, document.kind.name_message(), document.source, index));
                }
                let (key_units, end) = self.string_at(index + 1)?;
                let key = self.document.kind.text_value(key_units);

                index = document.skip_whitespace(end);
                if !document.is_at(index, b':') {
                    return Err(decode_error(vm, document.kind.colon_message(), document.source, index));
                }
                index = document.skip_whitespace(index + 1);
                if index > last {
                    return Err(decode_error(vm, "Expecting object", document.source, last));
                }
                let Some((value, end)) = self.value_at(index)? else {
                    return Err(stop_iteration(vm));
                };
                pairs.push((key, value));

                index = document.skip_whitespace(end);
                if index > last {
                    return Err(decode_error(vm, "Expecting object", document.source, last));
                }
                if document.is_at(index, b'}') {
                    break;
                }
                if !document.is_at(index, b',') {
                    return Err(decode_error(vm, document.kind.comma_message(), document.source, index));
                }
                index = document.skip_whitespace(index + 1);
            }
        }
        let end = index + 1;

        let settings = self.settings;
        if !settings.pairs_hook.is_none() {
            let pairs = pairs.into_iter().map(|(key, value)| Value::tuple(vec![key, value])).collect();
            return Ok((vm.call(&settings.pairs_hook, CallArgs::new(vec![vm.new_list(pairs)]))?, end));
        }

        let dict = vm.new_dict();
        for (key, value) in pairs {
            vm.dict_set(&dict, key, value)?;
        }
        let mut object = Value::Object(dict);
        if !settings.object_hook.is_none() {
            object = vm.call(&settings.object_hook, CallArgs::new(vec![object]))?;
        }

        Ok((object, end))
    }
}

/// The text of a string literal starting at `start`, after its opening
/// quote, and the index after its closing quote. Escapes give single
/// UTF-16 units.
fn scan_string<U>(vm: &Vm, document: &Document<'_, U>, start: usize, strict: bool, decoding: &RunDecoding<'_>) -> PyResult<(Vec<u16>, usize)>
where
    U: DocumentUnit,
{
    let units = document.units;
    if start >= units.len() {
        return Err(vm.raise(ExceptionKind::ValueError, "end is out of bounds"));
    }
    let quote = start.saturating_sub(1);
    let unterminated = || decode_error(vm, "Unterminated string starting at", document.source, quote);

    let mut text: Vec<u16> = Vec::new();
    let mut index = start;
    loop {
        let mut run_end = index;
        loop {
            let Some(code) = document.code_at(run_end) else {
                return Err(unterminated());
            };
            if code == 0x22 || code == 0x5C {
                break;
            }
            if strict && code < 0x20 {
                return Err(decode_error(vm, "Invalid control character at", document.source, run_end));
            }
            run_end += 1;
        }
        if run_end > index {
            append_run(vm, &mut text, &units[index..run_end], decoding)?;
        }

        if document.is_at(run_end, b'"') {
            return Ok((text, run_end + 1));
        }

        let escape = run_end + 1;
        let Some(code) = document.code_at(escape) else {
            return Err(unterminated());
        };
        let unit = match code {
            0x22 => 0x22,
            0x5C => 0x5C,
            0x2F => 0x2F,
            0x62 => 0x08,
            0x66 => 0x0C,
            0x6E => 0x0A,
            0x72 => 0x0D,
            0x74 => 0x09,
            0x75 => {
                // Four digits must leave room for a closing quote.
                let digits = if escape + 5 < units.len() { hex_unit(document, escape + 1) } else { None };
                let Some(unit) = digits else {
                    return Err(decode_error(vm, "Invalid \\uXXXX escape", document.source, escape));
                };
                text.push(unit);
                index = escape + 5;
                continue;
            }
            _ => return Err(decode_error(vm, "Invalid \\escape", document.source, run_end)),
        };
        text.push(unit);
        index = escape + 1;
    }
}

/// The unit four hexadecimal digits at `start` spell.
fn hex_unit<U>(document: &Document<'_, U>, start: usize) -> Option<u16>
where
    U: DocumentUnit,
{
    let mut unit: u16 = 0;
    for offset in 0..4 {
        let digit = char::from_u32(document.code_at(start + offset)?)?.to_digit(16)?;
        unit = (unit << 4) | digit as u16;
    }

    Some(unit)
}

/// Appends the text of a run of literal characters.
fn append_run<U>(vm: &Vm, text: &mut Vec<u16>, run: &[U], decoding: &RunDecoding<'_>) -> PyResult<()>
where
    U: DocumentUnit,
{
    let RunDecoding::Codec(encoding) = decoding else {
        text.extend(run.iter().map(|unit| unit.code() as u16));
        return Ok(());
    };

    let bytes = Value::Str(PyBytes::new(run.iter().map(|unit| unit.code() as u8).collect::<Vec<u8>>()));
    let decoded = vm.call_method(&bytes, "decode", vec![Value::Str((*encoding).clone())])?;
    let Some(decoded) = vm.as_text(&decoded) else {
        return Err(vm.type_error(&format!("decoder did not return an unicode object (type={})", vm.type_name(&decoded))));
    };
    text.extend_from_slice(decoded.units());

    Ok(())
}

/// A `ValueError` whose message `json.decoder.errmsg` builds for
/// `position` in `source`.
fn decode_error(vm: &Vm, message: &str, source: &Value, position: usize) -> Signal {
    let built = (|| {
        let decoder = vm.import_module("json.decoder")?;
        let errmsg = vm.getattr_str(&decoder, "errmsg")?;
        vm.call(&errmsg, CallArgs::new(vec![Value::str(message), source.clone(), vm.new_int_from_i64(position as i64)]))
    })();

    match built {
        Ok(text) => match vm.instantiate_exception(vm.types().exception(ExceptionKind::ValueError), vec![text]) {
            Ok(exception) => Signal::Raise(exception),
            Err(signal) => signal,
        },
        Err(signal) => signal,
    }
}

/// `scanstring(string, end, encoding=None, strict=True)`: the text of the
/// string literal whose opening quote precedes `end`, and the index after
/// it.
fn scanstring(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("scanstring() takes no keyword arguments"));
    }
    let count = args.positional.len();
    if count < 2 {
        return Err(vm.type_error(&format!("scanstring() takes at least 2 arguments ({count} given)")));
    }
    if count > 4 {
        return Err(vm.type_error(&format!("scanstring() takes at most 4 arguments ({count} given)")));
    }
    let source = args.positional[0].clone();
    let end = index_argument(vm, &args.positional[1])?;
    let encoding = match args.positional.get(2) {
        Some(value) => optional_encoding(vm, value)?,
        None => None,
    };
    let strict = match args.positional.get(3) {
        Some(value) => int_argument(vm, value)? != 0,
        None => true,
    };
    if source.is_unknown() {
        return Ok(source);
    }
    let encoding = encoding.unwrap_or_else(|| PyBytes::from("utf-8"));

    let (text, after) = if let Some(bytes) = vm.as_str_bytes(&source) {
        let document = Document { source: &source, units: bytes.as_bytes(), kind: DocumentKind::Bytes };
        scan_from(vm, &document, end, strict, &RunDecoding::Codec(&encoding))?
    } else if let Some(text) = vm.as_text(&source) {
        let document = Document { source: &source, units: text.units(), kind: DocumentKind::Text };
        scan_from(vm, &document, end, strict, &RunDecoding::Units)?
    } else {
        return Err(vm.type_error(&format!("first argument must be a string, not {}", vm.type_name(&source))));
    };

    Ok(Value::tuple(vec![Value::Unicode(PyText::new(text)), vm.new_int_from_i64(after as i64)]))
}

fn scan_from<U>(vm: &Vm, document: &Document<'_, U>, end: i64, strict: bool, decoding: &RunDecoding<'_>) -> PyResult<(Vec<u16>, usize)>
where
    U: DocumentUnit,
{
    let Ok(start) = usize::try_from(end) else {
        return Err(vm.raise(ExceptionKind::ValueError, "end is out of bounds"));
    };

    scan_string(vm, document, start, strict, decoding)
}

/// The optional encoding argument of `scanstring`: `None`, or a string
/// without NUL bytes.
fn optional_encoding(vm: &Vm, value: &Value) -> PyResult<Option<PyBytes>> {
    if value.is_none() {
        return Ok(None);
    }
    let bytes = if let Some(bytes) = vm.as_str_bytes(value) {
        bytes
    } else if let Some(text) = vm.as_text(value) {
        crate::interp::builtins::modules::codecs::args::encode_default(vm, &text)?
    } else {
        return Err(vm.type_error(&format!("scanstring() argument 3 must be string or None, not {}", vm.type_name(value))));
    };
    if bytes.as_bytes().contains(&0) {
        return Err(vm.type_error(&format!("scanstring() argument 3 must be string without null bytes or None, not {}", vm.type_name(value))));
    }

    Ok(Some(bytes))
}

/// `Encoder.__init__(markers, default, encoder, indent, key_separator,
/// item_separator, sort_keys, skipkeys, allow_nan)`.
fn encoder_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const NAMES: [&str; 9] = ["markers", "default", "encoder", "indent", "key_separator", "item_separator", "sort_keys", "skipkeys", "allow_nan"];

    let encoder = this::<Encoder>(vm, &args, ENCODER_TYPE, "__init__")?;
    let values = parse(vm, after_receiver(&args), "make_encoder", &NAMES, NAMES.len())?;
    let values: Vec<Value> = values.into_iter().map(|value| value.unwrap_or(Value::None)).collect();
    let Ok([markers, default, string_encoder, indent, key_separator, item_separator, sort_keys, skipkeys, allow_nan]) = <[Value; 9]>::try_from(values) else {
        return Err(vm.type_error("make_encoder() requires 9 arguments"));
    };

    if !markers.is_none() && dict_of(&markers).is_none() {
        return Err(vm.type_error(&format!("make_encoder() argument 1 must be dict or None, not {}", vm.type_name(&markers))));
    }
    let allows_nan = vm.truthy(&allow_nan, "make_encoder allow_nan")?;

    let settings = EncoderSettings { markers, default, encoder: string_encoder, indent, key_separator, item_separator, sort_keys, skipkeys, allows_nan };
    *encoder.settings.borrow_mut() = Some(Rc::new(settings));

    Ok(Value::None)
}

/// `encoder(obj, _current_indent_level)`: the list of chunks that spell
/// `obj` as JSON. The indent level is checked but not used.
fn encoder_call(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let encoder = this::<Encoder>(vm, &args, ENCODER_TYPE, "__call__")?;
    let slots = parse_with(vm, after_receiver(&args), "_iterencode", &["obj", "_current_indent_level"], 2, |vm, index, value| {
        if index == 1 {
            index_argument(vm, &value)?;
        }
        Ok(value)
    })?;
    let Some(Some(value)) = slots.into_iter().next() else {
        return Err(vm.type_error("_iterencode() requires an object"));
    };

    let settings = encoder.settings.borrow().clone();
    let Some(settings) = settings else {
        return Err(vm.raise(ExceptionKind::SystemError, "null argument to internal routine"));
    };

    let mut encoding = Encoding { vm, settings: &settings, chunks: Vec::new() };
    encoding.value(&value)?;

    Ok(vm.new_list(encoding.chunks))
}

/// The dict object of a dict or dict subclass instance.
fn dict_of(value: &Value) -> Option<&ObjectRef> {
    match value {
        Value::Object(object) if object.as_dict().is_some() => Some(object),
        _ => None,
    }
}

fn is_list_or_tuple(vm: &Vm, value: &Value) -> bool {
    match value {
        Value::Tuple(_) => true,
        Value::Object(object) => matches!(object.payload, Payload::List(_) | Payload::Tuple(_)) || vm.as_tuple(value).is_some(),
        _ => false,
    }
}

/// Whether `function` is this module's `encode_basestring_ascii`.
fn is_ascii_escaper(value: &Value) -> bool {
    match value {
        Value::Object(object) => matches!(&object.payload, Payload::NativeFunction(native) if native.function as usize == encode_basestring_ascii as NativeFn as usize),
        _ => false,
    }
}

/// One encoder call, collecting chunks.
struct Encoding<'a> {
    vm: &'a Vm,
    settings: &'a EncoderSettings,
    chunks: Vec<Value>,
}

impl Encoding<'_> {
    fn push_shared(&mut self, text: &'static str) {
        let chunk = shared_string(self.vm, text);
        self.chunks.push(chunk);
    }

    fn value(&mut self, value: &Value) -> PyResult<()> {
        let vm = self.vm;
        match value {
            Value::Unknown(_) => self.chunks.push(value.clone()),
            Value::None => self.push_shared("null"),
            Value::Bool(true) => self.push_shared("true"),
            Value::Bool(false) => self.push_shared("false"),
            _ if vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some() => {
                let chunk = self.string(value)?;
                self.chunks.push(chunk);
            }
            _ if vm.as_integral(value).is_some() => {
                let chunk = vm.to_str(value)?;
                self.chunks.push(chunk);
            }
            _ if vm.as_float(value).is_some() => {
                let chunk = self.float(value)?;
                self.chunks.push(chunk);
            }
            _ if is_list_or_tuple(vm, value) => vm.with_depth_in(" while encoding a JSON object", || self.list(value))?,
            _ if dict_of(value).is_some() => vm.with_depth_in(" while encoding a JSON object", || self.dict(value))?,
            _ => {
                let marker = self.mark(value)?;
                let replacement = vm.call(&self.settings.default, CallArgs::new(vec![value.clone()]))?;
                vm.with_depth_in(" while encoding a JSON object", || self.value(&replacement))?;
                self.unmark(marker)?;
            }
        }

        Ok(())
    }

    /// A string chunk, through the configured string encoder.
    fn string(&self, value: &Value) -> PyResult<Value> {
        if is_ascii_escaper(&self.settings.encoder) {
            return escape_ascii(self.vm, value);
        }

        self.vm.call(&self.settings.encoder, CallArgs::new(vec![value.clone()]))
    }

    /// A float chunk: its `repr`, or a constant for infinities and NaN when
    /// they are allowed.
    fn float(&self, value: &Value) -> PyResult<Value> {
        let vm = self.vm;
        let Some(number) = vm.as_float(value) else {
            return vm.repr(value);
        };
        if number.is_finite() {
            return vm.repr(value);
        }
        if !self.settings.allows_nan {
            return Err(vm.raise(ExceptionKind::ValueError, "Out of range float values are not JSON compliant"));
        }

        let text = if number.is_nan() {
            "NaN"
        } else if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        };

        Ok(Value::str(text))
    }

    /// Records `value` as being encoded; fails when it already is.
    fn mark(&self, value: &Value) -> PyResult<Option<Value>> {
        let vm = self.vm;
        let Some(markers) = dict_of(&self.settings.markers) else {
            return Ok(None);
        };

        let identity = vm.new_int_from_i64(vm.value_address(value) as i64);
        if vm.dict_get(markers, &identity)?.is_some() {
            return Err(vm.raise(ExceptionKind::ValueError, "Circular reference detected"));
        }
        vm.dict_set(markers, identity.clone(), value.clone())?;

        Ok(Some(identity))
    }

    fn unmark(&self, marker: Option<Value>) -> PyResult<()> {
        let (Some(markers), Some(identity)) = (dict_of(&self.settings.markers), marker) else {
            return Ok(());
        };
        self.vm.dict_delete(markers, &identity)?;

        Ok(())
    }

    fn list(&mut self, value: &Value) -> PyResult<()> {
        let vm = self.vm;
        let is_exact_list = matches!(value, Value::Object(object) if Rc::ptr_eq(&object.class(), &vm.types().list));
        let snapshot = if is_exact_list || vm.as_tuple(value).is_some() { None } else { Some(materialize(vm, value)?) };

        let length = |encoding: &Self| -> PyResult<usize> {
            match &snapshot {
                Some(items) => Ok(items.len()),
                None => Ok(encoding.vm.len(value)?.unwrap_or(0)),
            }
        };
        if length(self)? == 0 {
            self.push_shared("[]");
            return Ok(());
        }

        let marker = self.mark(value)?;
        self.push_shared("[");
        let mut index = 0;
        while index < length(self)? {
            let item = match &snapshot {
                Some(items) => items[index].clone(),
                None => vm.getitem(value, &vm.new_int_from_i64(index as i64))?,
            };
            if index > 0 {
                self.chunks.push(self.settings.item_separator.clone());
            }
            self.value(&item)?;
            index += 1;
        }
        self.push_shared("]");
        self.unmark(marker)
    }

    fn dict(&mut self, value: &Value) -> PyResult<()> {
        let vm = self.vm;
        let Some(dict) = dict_of(value) else {
            return Ok(());
        };
        if vm.dict_cell(dict)?.borrow().fill() == 0 {
            self.push_shared("{}");
            return Ok(());
        }

        // The flag is read for every nonempty dict; the items keep their
        // order either way.
        vm.truthy(&self.settings.sort_keys, "encoder sort_keys")?;
        let marker = self.mark(value)?;
        self.push_shared("{");

        let is_exact = Rc::ptr_eq(&dict.class(), &vm.types().dict);
        let items: Vec<(Value, Value)> = if is_exact {
            vm.dict_items(dict)?
        } else {
            let mut items = Vec::new();
            for key in materialize(vm, value)? {
                let item = vm.getitem(value, &key)?;
                items.push((key, item));
            }
            items
        };

        let mut first = true;
        for (key, item) in items {
            let Some(key) = self.key_text(&key)? else {
                continue;
            };
            if !first {
                self.chunks.push(self.settings.item_separator.clone());
            }
            first = false;

            let key_chunk = self.string(&key)?;
            self.chunks.push(key_chunk);
            self.chunks.push(self.settings.key_separator.clone());
            self.value(&item)?;
        }

        self.push_shared("}");
        self.unmark(marker)
    }

    /// The string a key is written as; `None` for a key `skipkeys` drops.
    /// Bools count as ints here, so they are written as `str()` gives them.
    fn key_text(&self, key: &Value) -> PyResult<Option<Value>> {
        let vm = self.vm;
        if vm.as_str_bytes(key).is_some() || vm.as_text(key).is_some() || key.is_unknown() {
            return Ok(Some(key.clone()));
        }
        if vm.as_float(key).is_some() {
            return self.float(key).map(Some);
        }
        if vm.as_integral(key).is_some() {
            return vm.to_str(key).map(Some);
        }
        if key.is_none() {
            return Ok(Some(shared_string(vm, "null")));
        }
        if vm.truthy(&self.settings.skipkeys, "encoder skipkeys")? {
            return Ok(None);
        }

        Err(vm.type_error("keys must be a string"))
    }
}

/// The items of an iterable as a vector.
fn materialize(vm: &Vm, value: &Value) -> PyResult<Vec<Value>> {
    let iterator = vm.iter(value)?;
    let mut items = Vec::new();
    while let Some(item) = vm.next(&iterator)? {
        items.push(item);
    }

    Ok(items)
}

/// `encode_basestring_ascii(string)`: a quoted JSON string using ASCII
/// only.
fn encode_basestring_ascii(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut with_module = args.positional.clone();
    with_module.insert(0, Value::None);
    let call = CallArgs { positional: with_module, keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    let text = method_one_argument(vm, &call, "encode_basestring_ascii")?;

    escape_ascii(vm, &text)
}

/// A quoted, ASCII-only JSON string. A `str` with non-ASCII bytes is
/// decoded as UTF-8 first.
fn escape_ascii(vm: &Vm, value: &Value) -> PyResult<Value> {
    if value.is_unknown() {
        return Ok(value.clone());
    }

    let escaped = if let Some(bytes) = vm.as_str_bytes(value) {
        if bytes.as_bytes().is_ascii() {
            escape_units(bytes.as_bytes().iter().map(|byte| u16::from(*byte)))
        } else {
            let decoded = vm.call_method(&Value::Str(bytes), "decode", vec![Value::str("utf-8")])?;
            let Some(text) = vm.as_text(&decoded) else {
                return Err(vm.type_error("decoder did not return an unicode object"));
            };
            escape_units(text.units().iter().copied())
        }
    } else if let Some(text) = vm.as_text(value) {
        escape_units(text.units().iter().copied())
    } else {
        return Err(vm.type_error(&format!("first argument must be a string, not {}", vm.type_name(value))));
    };

    Ok(Value::Str(PyBytes::new(escaped)))
}

/// Escapes UTF-16 units into a quoted JSON string of printable ASCII.
fn escape_units(units: impl Iterator<Item = u16>) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = vec![b'"'];
    for unit in units {
        match unit {
            0x22 => output.extend_from_slice(b"\\\""),
            0x5C => output.extend_from_slice(b"\\\\"),
            0x08 => output.extend_from_slice(b"\\b"),
            0x0C => output.extend_from_slice(b"\\f"),
            0x0A => output.extend_from_slice(b"\\n"),
            0x0D => output.extend_from_slice(b"\\r"),
            0x09 => output.extend_from_slice(b"\\t"),
            0x20..=0x7E => output.push(unit as u8),
            _ => {
                output.extend_from_slice(b"\\u");
                for shift in [12, 8, 4, 0] {
                    output.push(HEX[usize::from((unit >> shift) & 0xF)]);
                }
            }
        }
    }
    output.push(b'"');

    output
}

