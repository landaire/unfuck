//! `unicodedata`: the Unicode 5.2.0 character database and the
//! `ucd_3_2_0` object for Unicode 3.2.0. Arguments are UTF-16 code units,
//! as on the narrow Windows build: a surrogate pair counts as one
//! character.

mod database;
mod normalize;

use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::capsule::new_capsule;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::args::read_buffer;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::unicodedata::database::Database;
use crate::interp::builtins::modules::unicodedata::database::Form;
use crate::interp::builtins::modules::unicodedata::database::Properties;
use crate::interp::builtins::modules::unicodedata::database::Version;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::text::unicode_names;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const UCD_TYPE: &str = "unicodedata.UCD";

/// A `unicodedata.UCD` object: a previous version of the database.
struct Ucd {
    version: Version,
}

impl_native_data!(Ucd, "unicodedata.UCD");

/// A database function, run with the version its caller selects.
type Query = fn(&Vm, Version, &str, Vec<Value>) -> PyResult<Value>;

/// Each database function as a module function on the current database
/// and as a `UCD` method on the receiver's.
macro_rules! database_functions {
    ($($name:literal => $query:ident, $module:ident, $method:ident, $minimum:literal, $maximum:literal;)*) => {
        $(
            fn $module(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let arguments = positional(vm, args, $name, $minimum, $maximum)?;
                run($query, vm, Version::Current, $name, arguments)
            }

            fn $method(vm: &Vm, args: CallArgs) -> PyResult<Value> {
                let version = this::<Ucd>(vm, &args, UCD_TYPE, $name)?.version;
                let mut args = args;
                args.positional.remove(0);
                let arguments = positional(vm, args, $name, $minimum, $maximum)?;
                run($query, vm, version, $name, arguments)
            }
        )*

        const MODULE_FUNCTIONS: &[MethodSpec] = &[$(function($name, $module)),*];
        const UCD_METHODS: &[MethodSpec] = &[$(method($name, $method)),*];
    };
}

database_functions! {
    "decimal" => decimal, module_decimal, ucd_decimal, 1, 2;
    "digit" => digit, module_digit, ucd_digit, 1, 2;
    "numeric" => numeric, module_numeric, ucd_numeric, 1, 2;
    "category" => category, module_category, ucd_category, 1, 1;
    "bidirectional" => bidirectional, module_bidirectional, ucd_bidirectional, 1, 1;
    "combining" => combining, module_combining, ucd_combining, 1, 1;
    "mirrored" => mirrored, module_mirrored, ucd_mirrored, 1, 1;
    "east_asian_width" => east_asian_width, module_east_asian_width, ucd_east_asian_width, 1, 1;
    "decomposition" => decomposition, module_decomposition, ucd_decomposition, 1, 1;
    "name" => name, module_name, ucd_name, 1, 2;
    "lookup" => lookup, module_lookup, ucd_lookup, 1, 1;
    "normalize" => normalize, module_normalize, ucd_normalize, 2, 2;
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, MODULE_FUNCTIONS)?;

    let class = native_type(vm, UCD_TYPE, create_ucd_type)?;
    set_attribute(vm, module, "UCD", Value::Object(Rc::clone(&class)))?;
    set_attribute(vm, module, "unidata_version", Value::str("5.2.0"))?;
    set_attribute(vm, module, "ucd_3_2_0", new_native_object(vm, &class, Ucd { version: Version::V320 }))?;
    set_attribute(vm, module, "ucnhash_CAPI", new_capsule(vm, "unicodedata.ucnhash_CAPI")?)?;

    Ok(())
}

fn create_ucd_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(vm, TypeSpec { name: "UCD", module: "unicodedata", base: None, layout: Layout::Native, instance_dict: false, methods: UCD_METHODS })?;
    add_member(vm, &class, GetSet { name: "unidata_version", owner: UCD_TYPE, get: unidata_version, set: None })?;

    Ok(class)
}

fn unidata_version(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(ucd) = native_data::<Ucd>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::str(match ucd.version {
        Version::Current => "5.2.0",
        Version::V320 => "3.2.0",
    }))
}

/// Runs a query, or answers unknown for an unknown argument.
fn run(query: Query, vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    if let Some(unknown) = arguments.iter().find(|argument| argument.is_unknown()) {
        return Ok(Value::unknown(format!("unicodedata.{name} of an unknown argument ({})", unknown_origin(unknown))));
    }

    query(vm, version, name, arguments)
}

fn unknown_origin(value: &Value) -> String {
    match value {
        Value::Unknown(unknown) => unknown.origin.clone(),
        _ => String::new(),
    }
}

fn database(vm: &Vm) -> PyResult<&'static Database> {
    Database::get().map_err(|error| vm.halt_unsupported(error.to_string()))
}

/// The `O!` unicode argument at `position`.
fn text_argument(vm: &Vm, function: &str, position: usize, value: &Value) -> PyResult<PyText> {
    vm.as_text(value).ok_or_else(|| {
        let shown = if value.is_none() { "None".to_owned() } else { vm.type_name(value) };
        vm.type_error(&format!("{function}() argument {position} must be unicode, not {shown}"))
    })
}

/// The one character a unicode argument holds: one code unit, or a high
/// and a low surrogate.
fn character(vm: &Vm, function: &str, value: &Value) -> PyResult<u32> {
    let text = text_argument(vm, function, 1, value)?;
    match text.units() {
        &[unit] => Ok(u32::from(unit)),
        &[high @ 0xd800..=0xdbff, low @ 0xdc00..=0xdfff] => Ok(0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00)),
        _ => Err(vm.type_error("need a single Unicode character as parameter")),
    }
}

fn record(vm: &Vm, version: Version, code: u32) -> PyResult<Properties> {
    database(vm)?.properties(version, code).ok_or_else(|| vm.halt_unsupported(format!("unicodedata has no record of U+{code:04X}")))
}

fn properties(vm: &Vm, version: Version, function: &str, value: &Value) -> PyResult<Properties> {
    let code = character(vm, function, value)?;

    record(vm, version, code)
}

/// The `default` argument, or `ValueError` with `message` without one.
fn default_or(vm: &Vm, default: Option<&Value>, message: &str) -> PyResult<Value> {
    default.cloned().ok_or_else(|| vm.raise(ExceptionKind::ValueError, message))
}

fn decimal(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let properties = properties(vm, version, name, &arguments[0])?;
    match properties.decimal {
        Some(value) => Ok(Value::Int(i64::from(value))),
        None => default_or(vm, arguments.get(1), "not a decimal"),
    }
}

fn digit(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let properties = properties(vm, version, name, &arguments[0])?;
    match properties.digit {
        Some(value) => Ok(Value::Int(i64::from(value))),
        None => default_or(vm, arguments.get(1), "not a digit"),
    }
}

fn numeric(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let properties = properties(vm, version, name, &arguments[0])?;
    match properties.numeric {
        Some(value) => Ok(Value::Float(value)),
        None => default_or(vm, arguments.get(1), "not a numeric character"),
    }
}

fn category(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    Ok(Value::str(properties(vm, version, name, &arguments[0])?.category))
}

fn bidirectional(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    Ok(Value::str(properties(vm, version, name, &arguments[0])?.bidirectional))
}

fn combining(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    Ok(Value::Int(i64::from(properties(vm, version, name, &arguments[0])?.combining)))
}

fn mirrored(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    Ok(Value::Int(i64::from(properties(vm, version, name, &arguments[0])?.mirrored())))
}

fn east_asian_width(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    Ok(Value::str(properties(vm, version, name, &arguments[0])?.east_asian_width))
}

/// The decomposition mapping as text: the tag, then each code point in
/// at least four upper case hex digits.
fn decomposition(vm: &Vm, version: Version, name: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let code = character(vm, name, &arguments[0])?;
    let Some(mapping) = database(vm)?.decomposition(version, code) else {
        return Ok(Value::str(""));
    };

    let fields: Vec<String> = mapping.tag.map(str::to_owned).into_iter().chain(mapping.codes.iter().map(|code| format!("{code:04X}"))).collect();

    Ok(Value::str(&fields.join(" ")))
}

fn name(vm: &Vm, version: Version, function: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let code = character(vm, function, &arguments[0])?;
    let found = if record(vm, version, code)?.named() { unicode_names::name(code) } else { None };
    match found {
        Some(text) => Ok(Value::str(&text)),
        None => default_or(vm, arguments.get(1), "no such name"),
    }
}

/// The character a name names. The 3.2.0 database finds only names of
/// characters it assigns, apart from the names derived from code points.
fn lookup(vm: &Vm, version: Version, function: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let name = read_buffer(vm, function, 1, &arguments[0])?;
    let bytes = name.as_bytes();
    let derived = bytes.starts_with(b"HANGUL SYLLABLE ") || bytes.starts_with(b"CJK UNIFIED IDEOGRAPH-");
    let found = match unicode_names::lookup(bytes) {
        Some(code) if derived || version == Version::Current || record(vm, version, code)?.named() => Some(code),
        _ => None,
    };

    let Some(code) = found else {
        // The message ends at a null byte, as a C string would.
        let shown = bytes.split(|&byte| byte == 0).next().unwrap_or_default();
        let mut message = b"undefined character name '".to_vec();
        message.extend_from_slice(shown);
        message.push(b'\'');
        let class = Rc::clone(vm.types().exception(ExceptionKind::KeyError));
        return Err(vm.raise_string(&class, Value::Str(PyBytes::new(message))));
    };

    Ok(Value::Unicode(PyText::new(utf16(code))))
}

/// UTF-16 units of a code point below 0x110000.
fn utf16(code: u32) -> Vec<u16> {
    match code.checked_sub(0x10000) {
        Some(offset) => vec![(0xd800 + (offset >> 10)) as u16, (0xdc00 + (offset & 0x3ff)) as u16],
        None => vec![code as u16],
    }
}

/// `normalize(form, unistr)`. Empty input, and input the current
/// database's quick check accepts, come back as the same object.
fn normalize(vm: &Vm, version: Version, function: &str, arguments: Vec<Value>) -> PyResult<Value> {
    let form_name = c_string(vm, function, 1, &arguments[0])?;
    let input = &arguments[1];
    let text = text_argument(vm, function, 2, input)?;
    if text.units().is_empty() {
        return Ok(input.clone());
    }
    let Some(form) = Form::parse(form_name.as_bytes()) else {
        return Err(vm.raise(ExceptionKind::ValueError, "invalid normalization form"));
    };

    let database = database(vm)?;
    if version == Version::Current && normalize::is_normalized(database, form, text.units()) {
        return Ok(input.clone());
    }

    Ok(Value::Unicode(PyText::new(normalize::normalize(database, version, form, text.units()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_database_parses() {
        let database = Database::get().expect("database parses");
        let properties = database.properties(Version::Current, 0x41).expect("U+0041 has a record");

        assert_eq!((properties.category, properties.bidirectional, properties.east_asian_width), ("Lu", "L", "Na"));
        assert_eq!(database.compose(Version::Current, 0x41, 0x30a), Some(0xc5));
    }

    /// Results of the Windows 2.7.12 build that the Linux reference does
    /// not share, so no conformance case can hold them.
    #[test]
    fn narrow_build_normalization() {
        let database = Database::get().expect("database parses");
        let normalized = |version: Version, form: Form, units: &[u16]| normalize::normalize(database, version, form, units);

        // A vowel one past the jamo range composes once composition runs;
        // a lone pair passes the quick check unchanged.
        assert!(normalize::is_normalized(database, Form::Nfc, &[0x1100, 0x1176]));
        assert_eq!(normalized(Version::Current, Form::Nfc, &[0x1100, 0x1176, 0x11a8]), [0xae4d]);
        assert_eq!(normalized(Version::V320, Form::Nfc, &[0x1100, 0x1176]), [0xae4c]);
        // The trailing base is absorbed.
        assert_eq!(normalized(Version::Current, Form::Nfc, &[0x1100, 0x1161, 0x11a7]), [0xac00]);
        // A decomposition outside the BMP keeps its low 16 bits.
        assert_eq!(normalized(Version::Current, Form::Nfd, &[0xfa6c]), [0x42ee]);
        assert_eq!(normalized(Version::Current, Form::Nfkd, &[0xd834, 0xdd5e]), [0xd834, 0xdd5e]);
    }
}
