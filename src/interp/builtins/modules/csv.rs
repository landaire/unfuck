//! `_csv`: dialect objects, a record reader over an iterable of lines, and
//! a record writer over an object with a `write` method.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::operator::is_number_type;
use crate::interp::builtins::modules::operator::is_sequence;
use crate::interp::builtins::modules::stop_iteration;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const DIALECT_TYPE: &str = "_csv.Dialect";
const READER_TYPE: &str = "_csv.reader";
const WRITER_TYPE: &str = "_csv.writer";

/// The exception class, the dialect registry, and the field size limit,
/// shared by every import of the module.
struct CsvState {
    error: RefCell<Option<ObjectRef>>,
    dialects: RefCell<Option<ObjectRef>>,
    field_limit: Cell<i64>,
}

impl Default for CsvState {
    fn default() -> Self {
        Self { error: RefCell::new(None), dialects: RefCell::new(None), field_limit: Cell::new(128 * 1024) }
    }
}

/// When the writer quotes fields; the values are the `QUOTE_*` constants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteStyle {
    Minimal,
    All,
    NonNumeric,
    Never,
}

impl QuoteStyle {
    fn from_code(code: i64) -> Option<Self> {
        let style = match code {
            0 => Self::Minimal,
            1 => Self::All,
            2 => Self::NonNumeric,
            3 => Self::Never,
            _ => return None,
        };

        Some(style)
    }

    fn code(self) -> i64 {
        match self {
            Self::Minimal => 0,
            Self::All => 1,
            Self::NonNumeric => 2,
            Self::Never => 3,
        }
    }
}

/// The single-byte settings of a dialect. An unset character is `None`.
#[derive(Clone, Copy)]
struct Format {
    delimiter: u8,
    quotechar: Option<u8>,
    escapechar: Option<u8>,
    doublequote: bool,
    skipinitialspace: bool,
    strict: bool,
    quoting: QuoteStyle,
}

struct DialectData {
    format: Format,
    /// The `str` or `unicode` the dialect was given.
    lineterminator: Value,
}

impl_native_data!(DialectData, "_csv.Dialect");

/// Where the reader is within a record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing of the record read yet.
    RecordStart,
    /// After a delimiter, or at the first character of a record.
    FieldStart,
    Unquoted,
    UnquotedEscape,
    Quoted,
    QuotedEscape,
    /// A quote character inside a quoted field: the field's end, or the first
    /// half of a doubled quote.
    QuoteInQuoted,
    /// After the newline that ended the record.
    LineEnd,
}

/// One input event: a character of a line, or the end of the line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    Char(u8),
    EndOfLine,
}

/// The record a reader is assembling.
struct RecordBuilder {
    phase: Phase,
    fields: Vec<Value>,
    field: Vec<u8>,
    /// Whether the current field is an unquoted one that `QUOTE_NONNUMERIC`
    /// turns into a float.
    numeric: bool,
}

impl RecordBuilder {
    fn new() -> Self {
        Self { phase: Phase::RecordStart, fields: Vec::new(), field: Vec::new(), numeric: false }
    }
}

struct ReaderData {
    lines: Value,
    dialect: Value,
    format: Format,
    record: RefCell<RecordBuilder>,
    line_num: Cell<u64>,
}

impl_native_data!(ReaderData, "_csv.reader");

struct WriterData {
    write: Value,
    dialect: Value,
    /// Whether any record has held a byte. Until then an empty record
    /// reaches `write` as `None`.
    has_written: Cell<bool>,
}

impl_native_data!(WriterData, "_csv.writer");

/// What a dialect setting was given: nothing, or a value that may be
/// `None`.
type Setting = Option<Value>;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("reader", csv_reader),
            function("writer", csv_writer),
            function("list_dialects", csv_list_dialects),
            function("register_dialect", csv_register_dialect),
            function("unregister_dialect", csv_unregister_dialect),
            function("get_dialect", csv_get_dialect),
            function("field_size_limit", csv_field_size_limit),
        ],
    )?;

    set_attribute(vm, module, "__version__", Value::str("1.0"))?;
    set_attribute(vm, module, "_dialects", Value::Object(dialect_registry(vm)?))?;
    for style in [QuoteStyle::Minimal, QuoteStyle::All, QuoteStyle::NonNumeric, QuoteStyle::Never] {
        let name = match style {
            QuoteStyle::Minimal => "QUOTE_MINIMAL",
            QuoteStyle::All => "QUOTE_ALL",
            QuoteStyle::NonNumeric => "QUOTE_NONNUMERIC",
            QuoteStyle::Never => "QUOTE_NONE",
        };
        set_attribute(vm, module, name, Value::Int(style.code()))?;
    }
    set_attribute(vm, module, "Dialect", Value::Object(native_type(vm, DIALECT_TYPE, create_dialect_type)?))?;
    set_attribute(vm, module, "Error", Value::Object(error_class(vm)?))?;

    Ok(())
}

fn create_dialect_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(vm, TypeSpec { name: "Dialect", module: "_csv", base: None, layout: Layout::Native, instance_dict: false, methods: &[static_method("__new__", dialect_new)] })?;

    for name in ["delimiter", "skipinitialspace", "doublequote", "strict"] {
        add_member(vm, &class, GetSet { name, owner: DIALECT_TYPE, get: dialect_attribute, set: None })?;
    }
    for name in ["escapechar", "lineterminator", "quotechar", "quoting"] {
        add_getset(vm, &class, GetSet { name, owner: DIALECT_TYPE, get: dialect_attribute, set: None })?;
    }

    Ok(class)
}

fn create_reader_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(vm, TypeSpec { name: "reader", module: "_csv", base: None, layout: Layout::Native, instance_dict: false, methods: &[method("__iter__", reader_iter), method("next", reader_next)] })?;

    add_member(vm, &class, GetSet { name: "dialect", owner: READER_TYPE, get: reader_attribute, set: None })?;
    add_member(vm, &class, GetSet { name: "line_num", owner: READER_TYPE, get: reader_attribute, set: None })?;

    Ok(class)
}

fn create_writer_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(vm, TypeSpec { name: "writer", module: "_csv", base: None, layout: Layout::Native, instance_dict: false, methods: &[method("writerow", writer_writerow), method("writerows", writer_writerows)] })?;

    add_member(vm, &class, GetSet { name: "dialect", owner: WRITER_TYPE, get: writer_dialect, set: None })?;

    Ok(class)
}

/// `_csv.Error`, created once per interpreter.
fn error_class(vm: &Vm) -> PyResult<ObjectRef> {
    let state = vm.native_state::<CsvState>();
    if let Some(error) = state.error.borrow().as_ref() {
        return Ok(Rc::clone(error));
    }

    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "_csv", "Error", &base)?;
    *state.error.borrow_mut() = Some(Rc::clone(&error));

    Ok(error)
}

/// The dialect registry dict, created once per interpreter.
fn dialect_registry(vm: &Vm) -> PyResult<ObjectRef> {
    let state = vm.native_state::<CsvState>();
    if let Some(dialects) = state.dialects.borrow().as_ref() {
        return Ok(Rc::clone(dialects));
    }

    let dialects = vm.new_dict();
    *state.dialects.borrow_mut() = Some(Rc::clone(&dialects));

    Ok(dialects)
}

/// `_csv.Error(message)`.
fn csv_error(vm: &Vm, message: &[u8]) -> Signal {
    let class = match error_class(vm) {
        Ok(class) => class,
        Err(signal) => return signal,
    };

    match vm.instantiate_exception(&class, vec![Value::Str(PyBytes::new(message.to_vec()))]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

fn is_text(vm: &Vm, value: &Value) -> bool {
    vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some()
}

/// The dialect registered under `name`; any failure of the lookup reads
/// as an unknown name.
fn registered_dialect(vm: &Vm, name: &Value) -> PyResult<Value> {
    let registry = dialect_registry(vm)?;

    match vm.dict_get(&registry, name) {
        Ok(Some(dialect)) => Ok(dialect),
        Ok(None) | Err(Signal::Raise(_)) => Err(csv_error(vm, b"unknown dialect")),
        Err(halt) => Err(halt),
    }
}

/// `Dialect(dialect=None, **settings)`: the base dialect itself when it is
/// a `Dialect` and no setting is given, else a new dialect whose settings
/// come from the keywords, then from the base's attributes, then from the
/// defaults.
fn dialect_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    /// The dialect settings in the order they are read and checked.
    const SETTING_NAMES: [&str; 8] = ["delimiter", "doublequote", "escapechar", "lineterminator", "quotechar", "quoting", "skipinitialspace", "strict"];

    let dialect_class = native_type(vm, DIALECT_TYPE, create_dialect_type)?;
    let (class, args) = new_class(vm, args, &dialect_class)?;

    let mut names = vec!["dialect"];
    names.extend(SETTING_NAMES);
    let values = parse(vm, args, "", &names, 0)?;
    let Some((base, given)) = values.split_first() else {
        return Err(vm.type_error("dialect arguments are missing"));
    };

    let mut base = base.clone();
    if let Some(name) = base.as_ref().filter(|name| is_text(vm, name)) {
        base = Some(registered_dialect(vm, name)?);
    }
    if let Some(base) = &base
        && native_data::<DialectData>(base).is_some()
        && given.iter().all(Option::is_none)
    {
        return Ok(base.clone());
    }

    let mut settings: Vec<Setting> = Vec::with_capacity(SETTING_NAMES.len());
    for (name, value) in SETTING_NAMES.iter().zip(given) {
        let setting = match (value, &base) {
            (Some(value), _) => Some(value.clone()),
            (None, Some(base)) => base_attribute(vm, base, name)?,
            (None, None) => None,
        };
        settings.push(setting);
    }
    let [delimiter, doublequote, escapechar, lineterminator, quotechar, quoting, skipinitialspace, strict] = <[Setting; 8]>::try_from(settings).map_err(|_| vm.type_error("dialect settings are missing"))?;

    let delimiter_char = char_setting(vm, "delimiter", delimiter.as_ref(), Some(b','))?;
    let doublequote = bool_setting(vm, doublequote.as_ref(), true)?;
    let escapechar = char_setting(vm, "escapechar", escapechar.as_ref(), None)?;
    let lineterminator = terminator_setting(vm, lineterminator)?;
    let quotechar_char = char_setting(vm, "quotechar", quotechar.as_ref(), Some(b'"'))?;
    let mut quoting_style = quoting_setting(vm, quoting.as_ref())?;
    let skipinitialspace = bool_setting(vm, skipinitialspace.as_ref(), false)?;
    let strict = bool_setting(vm, strict.as_ref(), false)?;

    // A quote character of `None` without an explicit quoting style turns
    // quoting off.
    if quoting.is_none() && quotechar.as_ref().is_some_and(Value::is_none) {
        quoting_style = QuoteStyle::Never;
    }

    let Some(delimiter) = delimiter_char else {
        return Err(vm.type_error("\"delimiter\" must be an 1-character string"));
    };
    if quotechar_char.is_none() && quoting_style != QuoteStyle::Never {
        return Err(vm.type_error("quotechar must be set if quoting enabled"));
    }
    let Some(lineterminator) = lineterminator else {
        return Err(vm.type_error("lineterminator must be set"));
    };

    let format = Format { delimiter, quotechar: quotechar_char, escapechar, doublequote, skipinitialspace, strict, quoting: quoting_style };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(DialectData { format, lineterminator }))))
}

/// Attribute `name` of a base dialect; any exception reads as absent.
fn base_attribute(vm: &Vm, base: &Value, name: &str) -> PyResult<Setting> {
    match vm.getattr_opt(base, &PyBytes::from(name)) {
        Ok(found) => Ok(found),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

/// A one-character setting: a `str` of at most one byte. `None`, an empty
/// string, and NUL leave it unset.
fn char_setting(vm: &Vm, name: &str, value: Option<&Value>, default: Option<u8>) -> PyResult<Option<u8>> {
    let Some(value) = value else {
        return Ok(default);
    };
    if value.is_none() {
        return Ok(None);
    }
    let Some(bytes) = vm.as_str_bytes(value) else {
        return Err(vm.type_error(&format!("\"{name}\" must be string, not {}", vm.type_name(value))));
    };

    match bytes.as_bytes() {
        [] | [0] => Ok(None),
        [byte] => Ok(Some(*byte)),
        _ => Err(vm.type_error(&format!("\"{name}\" must be an 1-character string"))),
    }
}

fn bool_setting(vm: &Vm, value: Option<&Value>, default: bool) -> PyResult<bool> {
    match value {
        Some(value) => vm.truthy(value, "csv dialect setting"),
        None => Ok(default),
    }
}

/// The line terminator: a `str` or `unicode`; `None` when given as `None`.
fn terminator_setting(vm: &Vm, value: Setting) -> PyResult<Option<Value>> {
    let Some(value) = value else {
        return Ok(Some(Value::str("\r\n")));
    };
    if value.is_none() {
        return Ok(None);
    }
    if !is_text(vm, &value) {
        return Err(vm.type_error("\"lineterminator\" must be a string"));
    }

    Ok(Some(value))
}

/// The quoting style: a plain `int` naming one of the styles.
fn quoting_setting(vm: &Vm, value: Option<&Value>) -> PyResult<QuoteStyle> {
    let Some(value) = value else {
        return Ok(QuoteStyle::Minimal);
    };
    let Some(Integral::Int(code)) = vm.as_integral(value) else {
        return Err(vm.type_error("\"quoting\" must be an integer"));
    };

    QuoteStyle::from_code(code).ok_or_else(|| vm.type_error("bad \"quoting\" value"))
}

fn dialect_attribute(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = native_data::<DialectData>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };
    let format = data.format;

    let value = match getset.name {
        "delimiter" => char_value(Some(format.delimiter)),
        "quotechar" => char_value(format.quotechar),
        "escapechar" => char_value(format.escapechar),
        "doublequote" => Value::Int(i64::from(format.doublequote)),
        "skipinitialspace" => Value::Int(i64::from(format.skipinitialspace)),
        "strict" => Value::Int(i64::from(format.strict)),
        "quoting" => Value::Int(format.quoting.code()),
        _ => data.lineterminator.clone(),
    };

    Ok(value)
}

fn char_value(character: Option<u8>) -> Value {
    match character {
        Some(byte) => Value::Str(PyBytes::new(vec![byte])),
        None => Value::None,
    }
}

/// The settings of a dialect object.
fn dialect_format(vm: &Vm, dialect: &Value) -> PyResult<Format> {
    native_data::<DialectData>(dialect).map(|data| data.format).ok_or_else(|| vm.type_error("csv dialect is not a _csv.Dialect"))
}

/// Calls `Dialect` with the optional base dialect and the caller's
/// keywords.
fn make_dialect(vm: &Vm, base: Option<Value>, keywords: &CallArgs) -> PyResult<Value> {
    let class = native_type(vm, DIALECT_TYPE, create_dialect_type)?;
    let call = CallArgs { positional: base.into_iter().collect(), keywords: keywords.keywords.clone(), keyword_dict: keywords.keyword_dict.clone() };

    vm.call(&Value::Object(class), call)
}

/// The leading object and optional dialect of `reader` and `writer`, whose
/// keywords go on to `Dialect`.
fn target_and_dialect(vm: &Vm, args: &CallArgs) -> PyResult<(Value, Option<Value>)> {
    let positional = unpack(vm, CallArgs::new(args.positional.clone()), "", 1, 2)?;
    let mut values = positional.into_iter();
    let Some(target) = values.next() else {
        return Err(vm.type_error(" expected at least 1 arguments, got 0"));
    };

    Ok((target, values.next()))
}

/// `reader(lines, dialect='excel', **settings)`.
fn csv_reader(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (lines, base) = target_and_dialect(vm, &args)?;
    let lines = match vm.iter(&lines) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(_)) => return Err(vm.type_error("argument 1 must be an iterator")),
        Err(halt) => return Err(halt),
    };
    let dialect = make_dialect(vm, base, &args)?;
    let format = dialect_format(vm, &dialect)?;

    let class = native_type(vm, READER_TYPE, create_reader_type)?;
    let data = ReaderData { lines, dialect, format, record: RefCell::new(RecordBuilder::new()), line_num: Cell::new(0) };

    Ok(new_native_object(vm, &class, data))
}

fn reader_attribute(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = native_data::<ReaderData>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    if getset.name == "dialect" {
        return Ok(data.dialect.clone());
    }

    Ok(Value::long(BigInt::from(data.line_num.get())))
}

fn reader_iter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<ReaderData>(vm, &args, READER_TYPE, "__iter__")?;
    let mut args = args;
    let receiver = args.positional.remove(0);
    wrapper_arguments(vm, args, 0)?;

    Ok(receiver)
}

/// `next()`: reads lines until a record is complete.
fn reader_next(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reader = this::<ReaderData>(vm, &args, READER_TYPE, "next")?;
    wrapper_arguments(vm, CallArgs::new(args.positional[1..].to_vec()), 0)?;

    let mut record = reader.record.borrow_mut();
    *record = RecordBuilder::new();
    loop {
        let Some(line) = vm.next(&reader.lines)? else {
            return end_of_input(vm, reader, &mut record);
        };
        reader.line_num.set(reader.line_num.get() + 1);
        if line.is_unknown() {
            *record = RecordBuilder::new();
            return Ok(line);
        }

        // A NUL is an error where parsing reaches it, after any error the
        // characters before it raise.
        let bytes = line_bytes(vm, &line)?;
        for byte in bytes.as_bytes() {
            if *byte == 0 {
                return Err(csv_error(vm, b"line contains NULL byte"));
            }
            feed(vm, &reader.format, &mut record, Input::Char(*byte))?;
        }
        feed(vm, &reader.format, &mut record, Input::EndOfLine)?;

        if record.phase == Phase::RecordStart {
            let fields = std::mem::take(&mut record.fields);
            return Ok(vm.new_list(fields));
        }
    }
}

/// The input ran out: no record, or the unfinished one.
fn end_of_input(vm: &Vm, reader: &ReaderData, record: &mut RecordBuilder) -> PyResult<Value> {
    if record.phase == Phase::RecordStart && record.field.is_empty() && record.fields.is_empty() {
        return Err(stop_iteration(vm));
    }
    if reader.format.strict {
        return Err(csv_error(vm, b"unexpected end of data"));
    }

    save_field(vm, &reader.format, record)?;
    let fields = std::mem::take(&mut record.fields);
    *record = RecordBuilder::new();

    Ok(vm.new_list(fields))
}

/// The bytes of an input line: a `str`, or a `unicode` in the default
/// encoding.
fn line_bytes(vm: &Vm, line: &Value) -> PyResult<PyBytes> {
    if let Some(bytes) = vm.as_str_bytes(line) {
        return Ok(bytes);
    }
    if let Some(text) = vm.as_text(line) {
        return crate::interp::builtins::modules::codecs::args::encode_default(vm, &text);
    }

    Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(line))))
}

/// Ends the current field and adds it to the record.
fn save_field(vm: &Vm, format: &Format, record: &mut RecordBuilder) -> PyResult<()> {
    let text = Value::Str(PyBytes::new(std::mem::take(&mut record.field)));
    let numeric = std::mem::replace(&mut record.numeric, false);

    let field = if numeric && format.quoting == QuoteStyle::NonNumeric {
        let float = vm.builtin_value("float")?;
        vm.call(&float, CallArgs::new(vec![text]))?
    } else {
        text
    };
    record.fields.push(field);

    Ok(())
}

/// Appends a character to the current field within the size limit.
fn push_char(vm: &Vm, record: &mut RecordBuilder, byte: u8) -> PyResult<()> {
    let limit = vm.native_state::<CsvState>().field_limit.get();
    if i64::try_from(record.field.len()).is_ok_and(|length| length >= limit) {
        return Err(csv_error(vm, format!("field larger than field limit ({limit})").as_bytes()));
    }
    record.field.push(byte);

    Ok(())
}

fn is_newline(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

/// Advances the record by one input event.
fn feed(vm: &Vm, format: &Format, record: &mut RecordBuilder, input: Input) -> PyResult<()> {
    let quoting = format.quoting != QuoteStyle::Never;
    let is_quote = |byte: u8| quoting && format.quotechar == Some(byte);
    let is_escape = |byte: u8| format.escapechar == Some(byte);

    match record.phase {
        Phase::RecordStart => {
            match input {
                Input::EndOfLine => {
                    // An empty line is an empty record.
                }
                Input::Char(byte) if is_newline(byte) => record.phase = Phase::LineEnd,
                Input::Char(_) => {
                    record.phase = Phase::FieldStart;
                    feed(vm, format, record, input)?;
                }
            }
        }
        Phase::FieldStart => match input {
            Input::EndOfLine => {
                save_field(vm, format, record)?;
                record.phase = Phase::RecordStart;
            }
            Input::Char(byte) if is_newline(byte) => {
                save_field(vm, format, record)?;
                record.phase = Phase::LineEnd;
            }
            Input::Char(byte) if is_quote(byte) => record.phase = Phase::Quoted,
            Input::Char(byte) if is_escape(byte) => record.phase = Phase::UnquotedEscape,
            Input::Char(b' ') if format.skipinitialspace => {
                // Spaces before a field are dropped.
            }
            Input::Char(byte) if byte == format.delimiter => save_field(vm, format, record)?,
            Input::Char(byte) => {
                push_char(vm, record, byte)?;
                record.numeric = true;
                record.phase = Phase::Unquoted;
            }
        },
        Phase::Unquoted => match input {
            Input::EndOfLine => {
                save_field(vm, format, record)?;
                record.phase = Phase::RecordStart;
            }
            Input::Char(byte) if is_newline(byte) => {
                save_field(vm, format, record)?;
                record.phase = Phase::LineEnd;
            }
            Input::Char(byte) if is_escape(byte) => record.phase = Phase::UnquotedEscape,
            Input::Char(byte) if byte == format.delimiter => {
                save_field(vm, format, record)?;
                record.phase = Phase::FieldStart;
            }
            Input::Char(byte) => push_char(vm, record, byte)?,
        },
        Phase::UnquotedEscape => {
            let byte = match input {
                Input::Char(byte) => byte,
                Input::EndOfLine => b'\n',
            };
            push_char(vm, record, byte)?;
            record.phase = Phase::Unquoted;
        }
        Phase::Quoted => match input {
            Input::EndOfLine => {
                // The line's own newline characters are already in the field.
            }
            Input::Char(byte) if is_escape(byte) => record.phase = Phase::QuotedEscape,
            Input::Char(byte) if is_quote(byte) => {
                record.phase = if format.doublequote { Phase::QuoteInQuoted } else { Phase::Unquoted };
            }
            Input::Char(byte) => push_char(vm, record, byte)?,
        },
        Phase::QuotedEscape => {
            let byte = match input {
                Input::Char(byte) => byte,
                Input::EndOfLine => b'\n',
            };
            push_char(vm, record, byte)?;
            record.phase = Phase::Quoted;
        }
        Phase::QuoteInQuoted => match input {
            Input::EndOfLine => {
                save_field(vm, format, record)?;
                record.phase = Phase::RecordStart;
            }
            Input::Char(byte) if is_quote(byte) => {
                push_char(vm, record, byte)?;
                record.phase = Phase::Quoted;
            }
            Input::Char(byte) if byte == format.delimiter => {
                save_field(vm, format, record)?;
                record.phase = Phase::FieldStart;
            }
            Input::Char(byte) if is_newline(byte) => {
                save_field(vm, format, record)?;
                record.phase = Phase::LineEnd;
            }
            Input::Char(_) if format.strict => {
                let mut message = vec![b'\'', format.delimiter];
                message.extend_from_slice(b"' expected after '");
                message.extend(format.quotechar);
                message.push(b'\'');
                return Err(csv_error(vm, &message));
            }
            Input::Char(byte) => {
                push_char(vm, record, byte)?;
                record.phase = Phase::Unquoted;
            }
        },
        Phase::LineEnd => match input {
            Input::EndOfLine => record.phase = Phase::RecordStart,
            Input::Char(byte) if is_newline(byte) => {
                // Further newline characters close the same record.
            }
            Input::Char(_) => return Err(csv_error(vm, b"new-line character seen in unquoted field - do you need to open the file in universal-newline mode?")),
        },
    }

    Ok(())
}

/// `writer(file, dialect='excel', **settings)`.
fn csv_writer(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (target, base) = target_and_dialect(vm, &args)?;
    let write = match vm.getattr_opt(&target, &PyBytes::from("write")) {
        Ok(found) => found,
        Err(Signal::Raise(_)) => None,
        Err(halt) => return Err(halt),
    };
    let Some(write) = write.filter(|write| is_callable(vm, write).unwrap_or(false)) else {
        return Err(vm.type_error("argument 1 must have a \"write\" method"));
    };
    let dialect = make_dialect(vm, base, &args)?;
    dialect_format(vm, &dialect)?;

    let class = native_type(vm, WRITER_TYPE, create_writer_type)?;

    Ok(new_native_object(vm, &class, WriterData { write, dialect, has_written: Cell::new(false) }))
}

fn writer_dialect(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(data) = native_data::<WriterData>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(data.dialect.clone())
}

fn writer_writerow(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let writer = this::<WriterData>(vm, &args, WRITER_TYPE, "writerow")?;
    let row = method_one_argument(vm, &args, "writerow")?;

    write_row(vm, writer, &row)
}

fn writer_writerows(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let writer = this::<WriterData>(vm, &args, WRITER_TYPE, "writerows")?;
    let rows = method_one_argument(vm, &args, "writerows")?;

    let rows = match vm.iter(&rows) {
        Ok(iterator) => iterator,
        Err(Signal::Raise(_)) => return Err(vm.type_error("writerows() argument must be iterable")),
        Err(halt) => return Err(halt),
    };
    while let Some(row) = vm.next(&rows)? {
        write_row(vm, writer, &row)?;
    }

    Ok(Value::None)
}

/// One field of a row as the writer sees it.
struct FieldText {
    bytes: Vec<u8>,
    /// Quoted whatever its characters, as the quoting style asks.
    force_quotes: bool,
}

/// Formats `row` as one record and passes it to the file's `write`,
/// returning what that returns. A row with an unknown field writes an
/// unknown string.
fn write_row(vm: &Vm, writer: &WriterData, row: &Value) -> PyResult<Value> {
    let format = dialect_format(vm, &writer.dialect)?;
    let Some(dialect) = native_data::<DialectData>(&writer.dialect) else {
        return Err(vm.type_error("csv dialect is not a _csv.Dialect"));
    };
    if !is_sequence(vm, row)? {
        return Err(csv_error(vm, b"sequence expected"));
    }
    let Some(length) = vm.len(row)? else {
        return vm.call(&writer.write, CallArgs::new(vec![Value::unknown("csv row of unknown length")]));
    };
    let terminator = line_bytes(vm, &dialect.lineterminator)?;
    let terminator = terminator.as_bytes();

    let mut record = Vec::new();
    for index in 0..length {
        let item = vm.getitem(row, &vm.new_int_from_i64(index as i64))?;
        if item.is_unknown() {
            return vm.call(&writer.write, CallArgs::new(vec![Value::unknown("csv row with an unknown field")]));
        }
        let field = field_text(vm, &format, &item)?;

        let lone_empty = length == 1 && field.bytes.is_empty();
        if lone_empty && format.quoting == QuoteStyle::Never {
            return Err(csv_error(vm, b"single empty field record must be quoted"));
        }
        let encoded = encode_field(vm, &format, terminator, &field.bytes, field.force_quotes || lone_empty)?;
        if index > 0 {
            record.push(format.delimiter);
        }
        record.extend_from_slice(&encoded);
        if !record.is_empty() {
            writer.has_written.set(true);
        }
    }
    record.extend_from_slice(terminator);
    if !record.is_empty() {
        writer.has_written.set(true);
    }

    let line = if writer.has_written.get() { Value::Str(PyBytes::new(record)) } else { Value::None };

    vm.call(&writer.write, CallArgs::new(vec![line]))
}

/// The text of a field: empty for `None`, `repr` for a float, else `str`;
/// it ends at a NUL byte.
fn field_text(vm: &Vm, format: &Format, item: &Value) -> PyResult<FieldText> {
    let force_quotes = match format.quoting {
        QuoteStyle::All => true,
        QuoteStyle::NonNumeric => item.is_none() || !is_number_type(vm, item)?,
        QuoteStyle::Minimal | QuoteStyle::Never => false,
    };

    let text = if item.is_none() {
        PyBytes::new(Vec::new())
    } else if vm.as_float(item).is_some() {
        line_bytes(vm, &vm.repr(item)?)?
    } else if is_text(vm, item) {
        line_bytes(vm, item)?
    } else {
        line_bytes(vm, &vm.to_str(item)?)?
    };
    let bytes = text.as_bytes();
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());

    Ok(FieldText { bytes: bytes[..end].to_vec(), force_quotes })
}

/// The written form of one field, quoted when a special character needs it
/// and with escapes for what quoting cannot protect. The line terminator
/// counts up to its first NUL byte.
fn encode_field(vm: &Vm, format: &Format, terminator: &[u8], field: &[u8], force_quotes: bool) -> PyResult<Vec<u8>> {
    let terminator_end = terminator.iter().position(|byte| *byte == 0).unwrap_or(terminator.len());
    let terminator = &terminator[..terminator_end];
    let is_special = |byte: u8| byte == format.delimiter || format.escapechar == Some(byte) || format.quotechar == Some(byte) || terminator.contains(&byte);

    let mut body = Vec::with_capacity(field.len());
    let mut quoted = force_quotes;
    for &byte in field {
        if is_special(byte) {
            let escape = if format.quoting == QuoteStyle::Never {
                true
            } else if format.quotechar == Some(byte) {
                if format.doublequote {
                    body.push(byte);
                    false
                } else {
                    true
                }
            } else {
                false
            };

            if escape {
                let Some(escapechar) = format.escapechar else {
                    return Err(csv_error(vm, b"need to escape, but no escapechar set"));
                };
                body.push(escapechar);
            } else {
                quoted = true;
            }
        }
        body.push(byte);
    }

    let encoded = match (quoted, format.quotechar) {
        (true, Some(quote)) => {
            let mut encoded = Vec::with_capacity(body.len() + 2);
            encoded.push(quote);
            encoded.extend_from_slice(&body);
            encoded.push(quote);
            encoded
        }
        _ => body,
    };

    Ok(encoded)
}

fn csv_list_dialects(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    crate::interp::builtins::modules::no_arguments(vm, &args, "list_dialects")?;

    Ok(vm.new_list(vm.dict_keys(&dialect_registry(vm)?)?))
}

/// `register_dialect(name, dialect=None, **settings)`.
fn csv_register_dialect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (name, base) = target_and_dialect(vm, &args)?;
    if !is_text(vm, &name) {
        return Err(vm.type_error("dialect name must be a string or unicode"));
    }

    let dialect = make_dialect(vm, base, &args)?;
    vm.dict_set(&dialect_registry(vm)?, name, dialect)?;

    Ok(Value::None)
}

fn csv_unregister_dialect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let name = one_function_argument(vm, &args, "unregister_dialect")?;

    match vm.dict_delete(&dialect_registry(vm)?, &name) {
        Ok(true) => Ok(Value::None),
        Ok(false) | Err(Signal::Raise(_)) => Err(csv_error(vm, b"unknown dialect")),
        Err(halt) => Err(halt),
    }
}

fn csv_get_dialect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let name = one_function_argument(vm, &args, "get_dialect")?;

    registered_dialect(vm, &name)
}

/// The single argument of a module function that takes exactly one.
fn one_function_argument(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    let mut with_module = args.positional.clone();
    with_module.insert(0, Value::None);
    let call = CallArgs { positional: with_module, keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };

    method_one_argument(vm, &call, name)
}

/// `field_size_limit([limit])`: the previous limit, after setting a new
/// one when given.
fn csv_field_size_limit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("field_size_limit() takes no keyword arguments"));
    }
    let values = unpack(vm, args, "field_size_limit", 0, 1)?;

    let state = vm.native_state::<CsvState>();
    let previous = state.field_limit.get();
    if let Some(limit) = values.first() {
        let Some(Integral::Int(limit)) = vm.as_integral(limit) else {
            return Err(vm.type_error("limit must be an integer"));
        };
        state.field_limit.set(limit);
    }

    Ok(vm.new_int_from_i64(previous))
}
