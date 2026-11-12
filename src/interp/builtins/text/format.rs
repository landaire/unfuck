//! `format()`, the `__format__` methods of strings and numbers, and
//! `str.format` with its replacement field syntax.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::Signed;
use num_traits::ToPrimitive;

use crate::interp::attr::MroLookup;
use crate::interp::builtins::arguments::is_classic_instance;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::core::name_arg;
use crate::interp::builtins::install as install_methods;
use crate::interp::builtins::modules::warnings::warn_caller;
use crate::interp::builtins::method;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::text::chars::CodeUnit;
use crate::interp::builtins::text::check_size;
use crate::interp::builtins::text::codecs;
use crate::interp::builtins::text::raise_bytes;
use crate::interp::builtins::text::spec::Align;
use crate::interp::builtins::text::spec::FloatForm;
use crate::interp::builtins::text::spec::FormatSpec;
use crate::interp::builtins::text::spec::NumberText;
use crate::interp::builtins::text::spec::Sign;
use crate::interp::builtins::text::spec::SpecError;
use crate::interp::builtins::text::spec::decimal_digit;
use crate::interp::builtins::text::spec::float_length_bound;
use crate::interp::builtins::text::spec::pad;
use crate::interp::builtins::text::spec::render_float;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub fn install(vm: &Vm) -> PyResult<()> {
    let types = vm.types();

    install_methods(vm, &types.int, &[method("__format__", |vm, args| number_format(vm, args, NumberKind::Int))])?;
    install_methods(vm, &types.long, &[method("__format__", |vm, args| number_format(vm, args, NumberKind::Long))])?;
    install_methods(vm, &types.float, &[method("__format__", |vm, args| number_format(vm, args, NumberKind::Float))])?;

    install_methods(vm, &types.complex, &[method("__format__", |vm, args| number_format(vm, args, NumberKind::Complex))])
}

impl Vm {
    /// `format(value, spec)`: calls `value.__format__(spec)`. A `unicode`
    /// spec makes the result `unicode`.
    pub fn format_object(&self, value: &Value, spec: &Value) -> PyResult<Value> {
        if value.is_unknown() {
            return Ok(value.clone());
        }
        if spec.is_unknown() {
            return Ok(spec.clone());
        }

        let spec_is_unicode = self.as_text(spec).is_some();
        if !spec_is_unicode && self.as_str_bytes(spec).is_none() {
            return Err(self.type_error(&format!("format expects arg 2 to be string or unicode, not {}", self.type_name(spec))));
        }

        let result = match self.lookup_special(value, "__format__")? {
            Some(method) => self.call1(&method, spec.clone())?,
            // A classic instance without `__format__` formats as
            // `object.__format__` would.
            None => return self.format_string_form(value, spec),
        };
        if result.is_unknown() || self.as_text(&result).is_some() {
            return Ok(result);
        }
        let Some(bytes) = self.as_str_bytes(&result) else {
            return Err(self.type_error(&format!("{}.__format__ must return string or unicode, not {}", self.type_name(value), self.type_name(&result))));
        };

        if spec_is_unicode {
            return Ok(Value::Unicode(codecs::decode_default(self, bytes.as_bytes())?));
        }

        Ok(result)
    }

    /// `object.__format__`: formats `str(value)`, or `unicode(value)` for
    /// a `unicode` spec. A non-empty spec draws a deprecation warning.
    pub(crate) fn format_string_form(&self, value: &Value, spec: &Value) -> PyResult<Value> {
        let (text, spec_length) = if let Some(spec) = self.as_text(spec) {
            (self.to_unicode(value)?, spec.units().len())
        } else if let Some(spec) = self.as_str_bytes(spec) {
            (self.to_str(value)?, spec.as_bytes().len())
        } else {
            return Err(self.type_error("argument to __format__ must be unicode or str"));
        };

        if spec_length > 0 {
            warn_caller(self, ExceptionKind::PendingDeprecationWarning, "object.__format__ with a non-empty format string is deprecated")?;
        }

        self.format_object(&text, spec)
    }
}

/// Raises a spec error that has no type-specific wording.
fn spec_error<T: CodeUnit>(vm: &Vm, error: SpecError) -> Signal {
    let SpecError::ThousandsWith { kind } = error else {
        return vm.raise(ExceptionKind::ValueError, &error.to_string());
    };

    let mut message = b"Cannot specify ',' with '".to_vec();
    message.extend(code_text::<T>(kind));
    message.extend_from_slice(b"'.");

    raise_bytes(vm, ExceptionKind::ValueError, message)
}

/// A presentation type in an error message: a `str` spec shows the byte
/// itself, a `unicode` spec shows printable ASCII or a `\x` escape.
fn code_text<T: CodeUnit>(kind: u32) -> Vec<u8> {
    if !T::UNICODE {
        return vec![kind as u8];
    }

    escaped_code(kind, 33..128)
}

/// `code` as itself when in `shown`, else as `\x` and lowercase hex.
fn escaped_code(code: u32, shown: std::ops::Range<u32>) -> Vec<u8> {
    if shown.contains(&code) {
        return vec![code as u8];
    }

    format!("\\x{code:x}").into_bytes()
}

fn unknown_code<T: CodeUnit>(vm: &Vm, kind: u32, type_name: &str) -> Signal {
    let mut message = b"Unknown format code '".to_vec();
    message.extend(code_text::<T>(kind));
    message.extend_from_slice(format!("' for object of type '{type_name}'").as_bytes());

    raise_bytes(vm, ExceptionKind::ValueError, message)
}

/// `str.__format__` and `unicode.__format__` with a non-empty spec. The
/// spec converts to the receiver's kind of string.
pub fn string_format_spec<T: CodeUnit>(vm: &Vm, receiver: &Value, units: &[T], spec: &Value) -> PyResult<Value> {
    if spec.is_unknown() {
        return Ok(spec.clone());
    }

    let spec_units: Vec<T> = if let Some(bytes) = vm.as_str_bytes(spec) {
        if T::UNICODE { codecs::decode_default(vm, bytes.as_bytes())?.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect() } else { bytes.as_bytes().iter().map(|byte| T::truncate(u32::from(*byte))).collect() }
    } else if let Some(text) = vm.as_text(spec) {
        if T::UNICODE { text.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect() } else { codecs::encode_default(vm, text.units())?.as_bytes().iter().map(|byte| T::truncate(u32::from(*byte))).collect() }
    } else {
        return Err(vm.type_error(&format!("__format__ arg must be str or unicode, not {}", vm.type_name(spec))));
    };

    let parsed = FormatSpec::parse(&spec_units, Some(b's')).map_err(|error| spec_error::<T>(vm, error))?;
    let kind = parsed.kind_or(b's');
    if kind != u32::from(b's') {
        return Err(unknown_code::<T>(vm, kind, &vm.type_name(receiver)));
    }
    if parsed.sign.is_some() {
        return Err(vm.raise(ExceptionKind::ValueError, "Sign not allowed in string format specifier"));
    }
    if parsed.alternate {
        return Err(vm.raise(ExceptionKind::ValueError, "Alternate form (#) not allowed in string format specifier"));
    }
    if parsed.align == Some(Align::AfterSign) {
        return Err(vm.raise(ExceptionKind::ValueError, "'=' alignment not allowed in string format specifier"));
    }

    let mut text = units.to_vec();
    if let Some(precision) = parsed.precision {
        text.truncate(usize::try_from(precision).unwrap_or(usize::MAX));
    }

    let width = parsed.width.unwrap_or(0);
    check_size(vm, width)?;

    Ok(T::new_unshared_value(pad(text, width, parsed.align.unwrap_or(Align::Left), parsed.fill_or_space(), 0)))
}

/// The numeric types with their own `__format__`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NumberKind {
    Int,
    Long,
    Float,
    Complex,
}

impl NumberKind {
    fn owner(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Complex => "complex",
        }
    }
}

/// `__format__` of `int`, `long`, `float`, and `complex`. The result is
/// always `str`; a `unicode` spec is encoded first.
fn number_format(vm: &Vm, args: CallArgs, kind: NumberKind) -> PyResult<Value> {
    let (target, rest) = receiver(vm, args, "__format__")?;
    let spec = positional(vm, rest, "__format__", 1, 1)?.remove(0);
    if target.is_unknown() {
        return Ok(target);
    }

    let accepted = match kind {
        NumberKind::Int => vm.as_integral(&target).is_some_and(|integral| !integral.is_long()),
        NumberKind::Long => vm.as_integral(&target).is_some_and(|integral| integral.is_long()),
        NumberKind::Float => vm.as_float(&target).is_some(),
        NumberKind::Complex => vm.as_complex(&target).is_some(),
    };
    if !accepted {
        return Err(wrong_receiver(vm, "__format__", kind.owner(), &target));
    }
    if spec.is_unknown() {
        return Ok(spec);
    }

    let spec_bytes = if let Some(bytes) = vm.as_str_bytes(&spec) {
        bytes
    } else if let Some(text) = vm.as_text(&spec) {
        codecs::encode_default(vm, text.units())?
    } else {
        return Err(vm.type_error("__format__ requires str or unicode"));
    };
    if spec_bytes.as_bytes().is_empty() {
        return vm.to_str(&target);
    }

    let type_name = vm.type_name(&target);
    let text = if let Some(integral) = vm.as_integral(&target) {
        format_integral(vm, &integral, spec_bytes.as_bytes(), &type_name)?
    } else if let Some(number) = vm.as_float(&target) {
        let parsed = FormatSpec::parse(spec_bytes.as_bytes(), None).map_err(|error| spec_error::<u8>(vm, error))?;
        format_float(vm, number, &parsed, &type_name)?
    } else {
        let number = vm.as_complex(&target).ok_or_else(|| wrong_receiver(vm, "__format__", kind.owner(), &target))?;
        format_complex(vm, number.real, number.imag, spec_bytes.as_bytes(), &type_name)?
    };

    Ok(Value::Str(PyBytes::new_unshared(text)))
}

/// An integer with an integer presentation type, or converted to a float
/// for a float type.
fn format_integral(vm: &Vm, integral: &Integral, spec: &[u8], type_name: &str) -> PyResult<Vec<u8>> {
    let parsed = FormatSpec::parse(spec, Some(b'd')).map_err(|error| spec_error::<u8>(vm, error))?;
    let kind = parsed.kind_or(b'd');
    let Some(kind) = u8::try_from(kind).ok().filter(|kind| b"bcdoxXneEfFgG%".contains(kind)) else {
        return Err(unknown_code::<u8>(vm, kind, type_name));
    };

    let value = integral.to_bigint();
    if b"eEfFgG%".contains(&kind) {
        let Some(number) = numbers::bigint_to_f64(&value) else {
            return Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert to float"));
        };
        return format_float(vm, number, &parsed, type_name);
    }

    if parsed.precision.is_some() {
        return Err(vm.raise(ExceptionKind::ValueError, "Precision not allowed in integer format specifier"));
    }

    let number = if kind == b'c' {
        if parsed.sign.is_some() {
            return Err(vm.raise(ExceptionKind::ValueError, "Sign not allowed with integer format specifier 'c'"));
        }
        let fits_long = value.to_i64().is_some_and(|code| numbers::fits_int(vm.config.long_width, code));
        if !fits_long {
            return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
        }
        let Some(byte) = value.to_u8() else {
            return Err(vm.raise(ExceptionKind::OverflowError, "%c arg not in range(0x100)"));
        };
        NumberText { negative: false, prefix: b"", digits: Vec::new(), tail: vec![byte] }
    } else {
        let (radix, prefix): (u32, &'static [u8]) = match kind {
            b'b' => (2, b"0b"),
            b'o' => (8, b"0o"),
            b'x' => (16, b"0x"),
            b'X' => (16, b"0X"),
            _ => (10, b""),
        };
        let mut digits = value.magnitude().to_str_radix(radix).into_bytes();
        if kind == b'X' {
            digits.make_ascii_uppercase();
        }
        let prefix = if parsed.alternate { prefix } else { b"" };
        NumberText { negative: value.is_negative(), prefix, digits, tail: Vec::new() }
    };

    let width = parsed.width.unwrap_or(0);
    check_size(vm, width)?;

    Ok(number.layout(&parsed, parsed.sign, width, parsed.align.unwrap_or(Align::Right)))
}

/// A float presentation type and its default precision.
fn float_form(kind: u8, plain_precision: usize) -> Option<(FloatForm, usize)> {
    match kind.to_ascii_lowercase() {
        b'e' => Some((FloatForm::Exponent, 6)),
        b'f' | b'%' => Some((FloatForm::Fixed, 6)),
        b'g' | b'n' => Some((FloatForm::General, 6)),
        0 => Some((FloatForm::Plain, plain_precision)),
        _ => None,
    }
}

/// The largest precision a float format accepts.
fn float_precision(vm: &Vm, parsed: &FormatSpec<u8>, default: usize) -> PyResult<usize> {
    let Some(precision) = parsed.precision else {
        return Ok(default);
    };
    if i32::try_from(precision).is_err() {
        return Err(vm.raise(ExceptionKind::ValueError, "precision too big"));
    }

    Ok(usize::try_from(precision).unwrap_or(0))
}

/// Default significant digits of a float formatted without a type, as
/// `str()` shows it.
const PLAIN_PRECISION: usize = 12;

fn format_float(vm: &Vm, value: f64, parsed: &FormatSpec<u8>, type_name: &str) -> PyResult<Vec<u8>> {
    let kind = parsed.kind.unwrap_or(0);
    let Some((form, default_precision)) = float_form(kind, PLAIN_PRECISION) else {
        return Err(unknown_code::<u8>(vm, u32::from(kind), type_name));
    };
    let precision = float_precision(vm, parsed, default_precision)?;
    if parsed.alternate {
        return Err(vm.raise(ExceptionKind::ValueError, "Alternate form (#) not allowed in float format specifier"));
    }

    let width = parsed.width.unwrap_or(0);
    check_size(vm, width)?;
    check_size(vm, float_length_bound(form, precision, false))?;

    let percent = kind == b'%';
    let scaled = if percent { value * 100.0 } else { value };
    let (negative, text) = render_float(scaled, form, precision, false, kind.is_ascii_uppercase());
    let mut number = NumberText::from_magnitude(negative, b"", text.as_bytes());
    if percent {
        number.tail.push(b'%');
    }

    Ok(number.layout(parsed, parsed.sign, width, parsed.align.unwrap_or(Align::Right)))
}

fn format_complex(vm: &Vm, real: f64, imag: f64, spec: &[u8], type_name: &str) -> PyResult<Vec<u8>> {
    let parsed = FormatSpec::parse(spec, None).map_err(|error| spec_error::<u8>(vm, error))?;
    let kind = parsed.kind.unwrap_or(0);
    let form = match kind {
        0 => Some((FloatForm::General, PLAIN_PRECISION)),
        b'%' => None,
        _ => float_form(kind, PLAIN_PRECISION),
    };
    let Some((form, default_precision)) = form else {
        return Err(unknown_code::<u8>(vm, u32::from(kind), type_name));
    };
    let precision = float_precision(vm, &parsed, default_precision)?;
    if parsed.alternate {
        return Err(vm.raise(ExceptionKind::ValueError, "Alternate form (#) not allowed in complex format specifier"));
    }
    if parsed.fill == Some(b'0') {
        return Err(vm.raise(ExceptionKind::ValueError, "Zero padding is not allowed in complex format specifier"));
    }
    if parsed.align == Some(Align::AfterSign) {
        return Err(vm.raise(ExceptionKind::ValueError, "'=' alignment flag is not allowed in complex format specifier"));
    }

    let width = parsed.width.unwrap_or(0);
    check_size(vm, width)?;
    check_size(vm, 2 * float_length_bound(form, precision, false))?;

    // Without a type, a positive-zero real part is left out and a shown
    // one is wrapped in parentheses with the imaginary part.
    let plain = kind == 0;
    let show_real = !plain || real != 0.0 || real.is_sign_negative();
    let upper = kind.is_ascii_uppercase();

    let mut body = Vec::new();
    if show_real && plain {
        body.push(b'(');
    }
    if show_real {
        let (negative, text) = render_float(real, form, precision, false, upper);
        let part = NumberText::from_magnitude(negative, b"", text.as_bytes());
        body.extend(part.layout(&parsed, parsed.sign, 0, Align::Right));
    }

    let imag_sign = if show_real { Some(Sign::Plus) } else { parsed.sign };
    let (negative, text) = render_float(imag, form, precision, false, upper);
    let part = NumberText::from_magnitude(negative, b"", text.as_bytes());
    body.extend(part.layout(&parsed, imag_sign, 0, Align::Right));
    body.push(b'j');
    if show_real && plain {
        body.push(b')');
    }

    Ok(pad(body, width, parsed.align.unwrap_or(Align::Right), parsed.fill_or_space(), 0))
}

/// One replacement field of a format string, as written:
/// `{name!conversion:spec}`.
pub(crate) struct FieldText<'a, T> {
    pub name: &'a [T],
    pub conversion: Option<T>,
    pub spec: &'a [T],
    /// The field held a nested `{`, so the spec may name further fields.
    pub spec_has_fields: bool,
}

/// Literal text and the replacement field that follows it, if any.
pub(crate) struct Markup<'a, T> {
    pub literal: &'a [T],
    pub field: Option<FieldText<'a, T>>,
}

fn is_ascii<T: CodeUnit>(unit: T, byte: u8) -> bool {
    unit.into() == u32::from(byte)
}

/// Reads the next literal and field of `format` from `position`, which
/// moves past what was read. A doubled brace ends the literal after its
/// first brace. `None` at the end of the format.
pub(crate) fn next_markup<'a, T: CodeUnit>(vm: &Vm, format: &'a [T], position: &mut usize) -> PyResult<Option<Markup<'a, T>>> {
    let start = *position;
    if start >= format.len() {
        return Ok(None);
    }

    let mut cursor = start;
    while cursor < format.len() {
        let unit = format[cursor];
        let open = is_ascii(unit, b'{');
        if !open && !is_ascii(unit, b'}') {
            cursor += 1;
            continue;
        }

        if format.get(cursor + 1) == Some(&unit) {
            *position = cursor + 2;
            return Ok(Some(Markup { literal: &format[start..=cursor], field: None }));
        }
        if !open {
            *position = cursor + 1;
            return Err(vm.raise(ExceptionKind::ValueError, "Single '}' encountered in format string"));
        }
        if cursor + 1 >= format.len() {
            *position = cursor + 1;
            return Err(vm.raise(ExceptionKind::ValueError, "Single '{' encountered in format string"));
        }

        let literal = &format[start..cursor];
        let field_start = cursor + 1;
        let mut depth = 1usize;
        let mut nested = false;
        let mut end = field_start;
        while end < format.len() {
            if is_ascii(format[end], b'{') {
                depth += 1;
                nested = true;
            } else if is_ascii(format[end], b'}') {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            end += 1;
        }
        if depth > 0 {
            *position = format.len();
            return Err(vm.raise(ExceptionKind::ValueError, "unmatched '{' in format"));
        }

        *position = end + 1;
        let field = split_field(vm, &format[field_start..end], nested)?;
        return Ok(Some(Markup { literal, field: Some(field) }));
    }

    *position = format.len();

    Ok(Some(Markup { literal: &format[start..], field: None }))
}

/// Splits the text between a field's braces at the first `!` or `:`.
fn split_field<'a, T: CodeUnit>(vm: &Vm, field: &'a [T], nested: bool) -> PyResult<FieldText<'a, T>> {
    let Some(split) = field.iter().position(|unit| is_ascii(*unit, b'!') || is_ascii(*unit, b':')) else {
        return Ok(FieldText { name: field, conversion: None, spec: &[], spec_has_fields: nested });
    };
    let name = &field[..split];

    if is_ascii(field[split], b':') {
        return Ok(FieldText { name, conversion: None, spec: &field[split + 1..], spec_has_fields: nested });
    }

    let Some(&conversion) = field.get(split + 1) else {
        return Err(vm.raise(ExceptionKind::ValueError, "end of format while looking for conversion specifier"));
    };
    let spec = match field.get(split + 2) {
        None => &[][..],
        Some(colon) if is_ascii(*colon, b':') => &field[split + 3..],
        Some(_) => return Err(vm.raise(ExceptionKind::ValueError, "expected ':' after format specifier")),
    };

    Ok(FieldText { name, conversion: Some(conversion), spec, spec_has_fields: nested })
}

/// The end of the first part of a field name, before any `.` or `[`.
pub(crate) fn first_part_end<T: CodeUnit>(name: &[T]) -> usize {
    name.iter().position(|unit| is_ascii(*unit, b'.') || is_ascii(*unit, b'[')).unwrap_or(name.len())
}

/// An attribute (`.name`) or item (`[key]`) access in a field name.
pub(crate) struct FieldPart<'a, T> {
    pub is_attribute: bool,
    pub key: &'a [T],
}

/// Reads the access at `position` in `name`, after the first part.
/// `position` moves past what was read. `None` at the end of the name.
pub(crate) fn next_field_part<'a, T: CodeUnit>(vm: &Vm, name: &'a [T], position: &mut usize) -> PyResult<Option<FieldPart<'a, T>>> {
    let Some(&marker) = name.get(*position) else {
        return Ok(None);
    };
    let key_start = *position + 1;

    if is_ascii(marker, b'.') {
        let key_end = name[key_start..].iter().position(|unit| is_ascii(*unit, b'.') || is_ascii(*unit, b'[')).map_or(name.len(), |offset| key_start + offset);
        *position = key_end;
        if key_end == key_start {
            return Err(vm.raise(ExceptionKind::ValueError, "Empty attribute in format string"));
        }
        return Ok(Some(FieldPart { is_attribute: true, key: &name[key_start..key_end] }));
    }

    if is_ascii(marker, b'[') {
        let Some(offset) = name[key_start..].iter().position(|unit| is_ascii(*unit, b']')) else {
            *position = name.len();
            return Err(vm.raise(ExceptionKind::ValueError, "Missing ']' in format string"));
        };
        let key_end = key_start + offset;
        *position = key_end + 1;
        if key_end == key_start {
            return Err(vm.raise(ExceptionKind::ValueError, "Empty attribute in format string"));
        }
        return Ok(Some(FieldPart { is_attribute: false, key: &name[key_start..key_end] }));
    }

    *position = name.len();

    Err(vm.raise(ExceptionKind::ValueError, "Only '.' or '[' may follow ']' in format field specifier"))
}

/// The value of a field name part made only of decimal digits; `None`
/// for any other text.
pub(crate) fn field_index<T: CodeUnit>(vm: &Vm, text: &[T]) -> PyResult<Option<i64>> {
    if text.is_empty() {
        return Ok(None);
    }

    let mut value: i64 = 0;
    for unit in text {
        let Some(digit) = decimal_digit(*unit) else {
            return Ok(None);
        };
        value = value.checked_mul(10).and_then(|value| value.checked_add(i64::from(digit))).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "Too many decimal digits in format string"))?;
    }

    Ok(Some(value))
}

/// An index into a field's object, which `str.format` passes as a `long`.
pub(crate) fn index_key(index: i64) -> Value {
    Value::Long(Rc::new(BigInt::from(index)))
}

/// How fields without a name get their argument position.
enum Numbering {
    Unset,
    Automatic { next: i64 },
    Manual,
}

/// The arguments of a `str.format` call.
struct FormatArguments {
    positional: Vec<Value>,
    keywords: Option<ObjectRef>,
}

impl FormatArguments {
    fn new(vm: &Vm, args: CallArgs) -> PyResult<Self> {
        let keywords = if let Some(dict) = args.keyword_dict {
            Some(dict)
        } else if args.keywords.is_empty() {
            None
        } else {
            let dict = vm.new_dict();
            for (key, value) in args.keywords {
                vm.dict_set(&dict, Value::Str(key), value)?;
            }
            Some(dict)
        };

        Ok(Self { positional: args.positional, keywords })
    }
}

/// Text built by `str.format`, or the unknown value that decides it.
enum Rendered<T> {
    Text(Vec<T>),
    Unknown(Value),
}

/// `str.format(*args, **kwargs)` and `unicode.format`.
pub fn format_method<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    // A format nests replacement fields in specs one level deep.
    const MAX_DEPTH: u32 = 2;

    let arguments = FormatArguments::new(vm, args)?;
    let mut numbering = Numbering::Unset;

    match build::<T>(vm, units, &arguments, MAX_DEPTH, &mut numbering)? {
        Rendered::Text(text) => Ok(T::allocated_value(text)),
        Rendered::Unknown(value) => Ok(value),
    }
}

fn build<T: CodeUnit>(vm: &Vm, format: &[T], arguments: &FormatArguments, depth: u32, numbering: &mut Numbering) -> PyResult<Rendered<T>> {
    if depth == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "Max string recursion exceeded"));
    }

    let mut output = Vec::with_capacity(format.len());
    let mut position = 0;
    while let Some(markup) = next_markup(vm, format, &mut position)? {
        output.extend_from_slice(markup.literal);
        let Some(field) = markup.field else {
            continue;
        };

        match render_field(vm, &field, arguments, depth, numbering)? {
            Rendered::Text(text) => output.extend(text),
            unknown @ Rendered::Unknown(_) => return Ok(unknown),
        }
    }

    Ok(Rendered::Text(output))
}

/// Looks up, converts, and formats one field.
fn render_field<T: CodeUnit>(vm: &Vm, field: &FieldText<'_, T>, arguments: &FormatArguments, depth: u32, numbering: &mut Numbering) -> PyResult<Rendered<T>> {
    let object = field_object(vm, field.name, arguments, numbering)?;
    if object.is_unknown() {
        return Ok(Rendered::Unknown(object));
    }

    let object = match field.conversion.map(Into::into) {
        None => object,
        Some(code) if code == u32::from(b'r') => vm.repr(&object)?,
        Some(code) if code == u32::from(b's') => {
            if T::UNICODE {
                vm.to_unicode(&object)?
            } else {
                vm.to_str(&object)?
            }
        }
        Some(code) => {
            // A `str` format sign-extends a byte above 0x7f.
            let shown = if !T::UNICODE && code >= 0x80 { code | 0xffff_ff00 } else { code };
            let mut message = b"Unknown conversion specifier ".to_vec();
            message.extend(escaped_code(shown, 33..127));
            return Err(raise_bytes(vm, ExceptionKind::ValueError, message));
        }
    };
    if object.is_unknown() {
        return Ok(Rendered::Unknown(object));
    }

    let spec = if field.spec_has_fields {
        match build::<T>(vm, field.spec, arguments, depth - 1, numbering)? {
            Rendered::Text(spec) => spec,
            unknown @ Rendered::Unknown(_) => return Ok(unknown),
        }
    } else {
        field.spec.to_vec()
    };

    let formatted = vm.format_object(&object, &T::new_value(spec))?;
    if formatted.is_unknown() {
        return Ok(Rendered::Unknown(formatted));
    }

    let units = if let Some(text) = vm.as_text(&formatted) {
        if T::UNICODE { text.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect() } else { codecs::encode_default(vm, text.units())?.as_bytes().iter().map(|byte| T::truncate(u32::from(*byte))).collect() }
    } else if let Some(bytes) = vm.as_str_bytes(&formatted) {
        if T::UNICODE { codecs::decode_default(vm, bytes.as_bytes())?.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect() } else { bytes.as_bytes().iter().map(|byte| T::truncate(u32::from(*byte))).collect() }
    } else {
        return Err(vm.type_error("format() did not return a string"));
    };

    Ok(Rendered::Text(units))
}

/// The object a field name refers to: an argument chosen by the first
/// part, then each attribute and item access.
fn field_object<T: CodeUnit>(vm: &Vm, name: &[T], arguments: &FormatArguments, numbering: &mut Numbering) -> PyResult<Value> {
    let first_end = first_part_end(name);
    let first = &name[..first_end];

    let index = if first.is_empty() {
        match numbering {
            Numbering::Manual => return Err(vm.raise(ExceptionKind::ValueError, "cannot switch from manual field specification to automatic field numbering")),
            Numbering::Unset => {
                *numbering = Numbering::Automatic { next: 1 };
                Some(0)
            }
            Numbering::Automatic { next } => {
                let index = *next;
                *next += 1;
                Some(index)
            }
        }
    } else {
        let index = field_index(vm, first)?;
        if index.is_some() {
            if matches!(numbering, Numbering::Automatic { .. }) {
                return Err(vm.raise(ExceptionKind::ValueError, "cannot switch from automatic field numbering to manual field specification"));
            }
            *numbering = Numbering::Manual;
        }
        index
    };

    let mut object = match index {
        Some(index) => match usize::try_from(index).ok().and_then(|index| arguments.positional.get(index)) {
            Some(value) => value.clone(),
            None => return Err(vm.raise(ExceptionKind::IndexError, "tuple index out of range")),
        },
        None => {
            let key = T::new_value(first.to_vec());
            let found = match &arguments.keywords {
                Some(dict) => vm.dict_get(dict, &key)?,
                None => None,
            };
            match found {
                Some(value) => value,
                None => return Err(vm.raise_string(vm.types().exception(ExceptionKind::KeyError), key)),
            }
        }
    };

    let mut position = first_end;
    while let Some(part) = next_field_part(vm, name, &mut position)? {
        if object.is_unknown() {
            return Ok(object);
        }
        object = if part.is_attribute {
            let attribute = name_arg(vm, &T::new_value(part.key.to_vec()))?;
            vm.getattr(&object, &attribute)?
        } else {
            let key = match field_index(vm, part.key)? {
                Some(index) => item_index(vm, &object, index)?,
                None => T::new_value(part.key.to_vec()),
            };
            vm.getitem(&object, &key)?
        };
    }

    Ok(object)
}

/// The key a digit item access passes. A `__getitem__` defined in Python
/// receives the position as an `int`, as sequence indexing passes it;
/// other containers receive a `long`.
fn item_index(vm: &Vm, object: &Value, index: i64) -> PyResult<Value> {
    if is_classic_instance(vm, object) {
        return Ok(vm.new_int_from_i64(index));
    }

    let defined_in_python = match vm.lookup_mro(&vm.type_of(object), "__getitem__")? {
        MroLookup::Found { owner, .. } => !vm.is_builtin_type(&owner),
        MroLookup::Unknown(_) | MroLookup::Missing => false,
    };

    Ok(if defined_in_python { vm.new_int_from_i64(index) } else { index_key(index) })
}
