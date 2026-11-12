//! The `%` operator of `str` and `unicode`. Each conversion specifier is
//! `%[(key)][flags][width][.precision][length]type`.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::Signed;
use num_traits::Zero;

use crate::interp::attr::MroLookup;
use crate::interp::builtins::arguments::is_classic_instance;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::modules::registered_type;
use crate::interp::builtins::numeric::float::float_as_double;
use crate::interp::builtins::text::chars::CodeUnit;
use crate::interp::builtins::text::check_size;
use crate::interp::builtins::text::codecs;
use crate::interp::builtins::text::raise_bytes;
use crate::interp::builtins::text::spec::FloatForm;
use crate::interp::builtins::text::spec::float_length_bound;
use crate::interp::builtins::text::spec::render_float;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

impl Vm {
    /// `format % args` for a `str` or `unicode` format. A `str` format
    /// continues as `unicode` from the first conversion that yields
    /// `unicode`.
    pub fn format_percent(&self, format: &Value, args: &Value) -> PyResult<Value> {
        if format.is_unknown() {
            return Ok(format.clone());
        }
        if args.is_unknown() {
            return Ok(args.clone());
        }

        if let Some(text) = self.as_text(format) {
            return match interpolate::<u16>(self, text.units(), args)? {
                Outcome::Text(units) => Ok(u16::allocated_value(units)),
                Outcome::Unknown(value) => Ok(value),
                Outcome::Widen { .. } => Err(self.halt_unsupported("unicode format widened again")),
            };
        }
        let Some(bytes) = self.as_str_bytes(format) else {
            return Err(self.type_error(&format!("unsupported operand type(s) for %: '{}' and '{}'", self.type_name(format), self.type_name(args))));
        };

        let (done, restart, arguments) = match interpolate::<u8>(self, bytes.as_bytes(), args)? {
            Outcome::Text(bytes) => return Ok(u8::allocated_value(bytes)),
            Outcome::Unknown(value) => return Ok(value),
            Outcome::Widen { done, restart, arguments } => (done, restart, arguments),
        };

        // The rest of the format is decoded and formatted first; the text
        // produced so far is decoded when the two are joined.
        let rest = codecs::decode_default(self, &bytes.as_bytes()[restart..])?;
        let tail = match interpolate::<u16>(self, rest.units(), &arguments)? {
            Outcome::Text(units) => units,
            Outcome::Unknown(value) => return Ok(value),
            Outcome::Widen { .. } => return Err(self.halt_unsupported("unicode format widened again")),
        };
        let head = codecs::decode_default(self, &done)?;

        let mut units = head.units().to_vec();
        units.extend_from_slice(&tail);

        Ok(Value::Unicode(PyText::allocate(units)))
    }
}

/// How formatting one string ended.
enum Outcome<T> {
    Text(Vec<T>),
    /// An unknown value decides the result.
    Unknown(Value),
    /// A `str` format met `unicode` at the specifier starting at `restart`.
    /// The format from there on is formatted as `unicode` with
    /// `arguments`, and appended to `done`.
    Widen { done: Vec<T>, restart: usize, arguments: Value },
}

/// The text of one conversion.
enum Piece<T> {
    Text(Vec<T>),
    Unknown(Value),
    /// The conversion produced `unicode` in a `str` format.
    Widen,
}

/// A converted argument, or the unknown value it depends on.
enum Converted<X> {
    Known(X),
    Unknown(Value),
}

/// The arguments conversions consume: the items of a tuple, or a single
/// value. A mapping argument also serves `%(key)` lookups.
struct Arguments {
    original: Value,
    items: Vec<Value>,
    is_tuple: bool,
    next: usize,
    mapping: Option<Value>,
    /// Set by the first `%(key)`: from then on the only argument is the
    /// value of the latest key, until something consumes it.
    keyed: bool,
    pending: Option<Value>,
}

impl Arguments {
    fn new(vm: &Vm, args: &Value) -> PyResult<Self> {
        let mapping = if is_mapping(vm, args)? { Some(args.clone()) } else { None };
        let (items, is_tuple) = match vm.as_tuple(args) {
            Some(items) => (items.to_vec(), true),
            None => (vec![args.clone()], false),
        };

        Ok(Self { original: args.clone(), items, is_tuple, next: 0, mapping, keyed: false, pending: None })
    }

    fn next(&mut self, vm: &Vm) -> PyResult<Value> {
        if let Some(value) = self.pending.take() {
            return Ok(value);
        }
        let available = if self.keyed { None } else { self.items.get(self.next) };
        let Some(item) = available.cloned() else {
            return Err(vm.type_error("not enough arguments for format string"));
        };
        self.next += 1;

        Ok(item)
    }

    /// Whether positional arguments were left unused where that is an
    /// error.
    fn has_leftover(&self) -> bool {
        self.mapping.is_none() && self.next < self.items.len()
    }

    /// The arguments from position `index` on, for a restarted format.
    fn from_index(&self, index: usize) -> Value {
        if self.is_tuple {
            return Value::tuple(self.items[index..].to_vec());
        }

        self.original.clone()
    }
}

/// The options of one conversion specifier.
#[derive(Default)]
struct Options {
    left: bool,
    plus: bool,
    space: bool,
    alternate: bool,
    zero: bool,
    width: i64,
    precision: Option<i64>,
}

impl Options {
    fn sign(&self, negative: bool) -> &'static [u8] {
        if negative {
            b"-"
        } else if self.plus {
            b"+"
        } else if self.space {
            b" "
        } else {
            b""
        }
    }
}

/// Whether `%(key)` lookups go to `value`: anything that supports
/// subscripting by key, other than tuples and strings. `xrange` and
/// `deque` index items by position only.
fn is_mapping(vm: &Vm, value: &Value) -> PyResult<bool> {
    if vm.as_tuple(value).is_some() || vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some() {
        return Ok(false);
    }
    if is_classic_instance(vm, value) {
        return Ok(true);
    }

    let owner = match vm.lookup_mro(&vm.type_of(value), "__getitem__")? {
        MroLookup::Found { owner, .. } => owner,
        MroLookup::Unknown(_) => return Ok(true),
        MroLookup::Missing => return Ok(false),
    };
    let positional_only = Rc::ptr_eq(&owner, &vm.types().xrange) || registered_type(vm, "collections.deque").is_some_and(|deque| Rc::ptr_eq(&owner, &deque));

    Ok(!positional_only)
}

fn is_unit<T: CodeUnit>(unit: Option<&T>, byte: u8) -> bool {
    unit.is_some_and(|unit| (*unit).into() == u32::from(byte))
}

fn ascii_digit<T: CodeUnit>(unit: Option<&T>) -> Option<u8> {
    let code: u32 = (*unit?).into();

    (u32::from(b'0')..=u32::from(b'9')).contains(&code).then(|| (code - u32::from(b'0')) as u8)
}

fn widen_bytes<T: CodeUnit>(bytes: &[u8]) -> Vec<T> {
    bytes.iter().map(|byte| T::truncate(u32::from(*byte))).collect()
}

fn incomplete(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "incomplete format")
}

/// Formats `format` with `args`.
fn interpolate<T: CodeUnit>(vm: &Vm, format: &[T], args: &Value) -> PyResult<Outcome<T>> {
    let mut arguments = Arguments::new(vm, args)?;
    let mut output: Vec<T> = Vec::with_capacity(format.len());
    let mut position = 0;

    while position < format.len() {
        let Some(offset) = format[position..].iter().position(|unit| is_unit(Some(unit), b'%')) else {
            output.extend_from_slice(&format[position..]);
            break;
        };
        output.extend_from_slice(&format[position..position + offset]);

        let start = position + offset;
        let first_argument = arguments.next;
        let mut cursor = start + 1;

        if is_unit(format.get(cursor), b'(') {
            let Some(mapping) = arguments.mapping.clone() else {
                return Err(vm.type_error("format requires a mapping"));
            };
            let key_start = cursor + 1;
            let key_end = matching_paren(format, key_start).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "incomplete format key"))?;
            let value = vm.getitem(&mapping, &T::new_value(format[key_start..key_end].to_vec()))?;
            if value.is_unknown() {
                return Ok(Outcome::Unknown(value));
            }
            arguments.keyed = true;
            arguments.pending = Some(value);
            cursor = key_end + 1;
        }

        let mut options = Options::default();
        // Where the last width or precision digit ended, if any.
        let mut digits_end = None;
        loop {
            let Some(unit) = format.get(cursor) else {
                break;
            };
            match char::from_u32((*unit).into()) {
                Some('-') => options.left = true,
                Some('+') => options.plus = true,
                Some(' ') => options.space = true,
                Some('#') => options.alternate = true,
                Some('0') => options.zero = true,
                _ => break,
            }
            cursor += 1;
        }

        if is_unit(format.get(cursor), b'*') {
            let width = match star_argument(vm, &mut arguments)? {
                Converted::Known(width) => width,
                Converted::Unknown(value) => return Ok(Outcome::Unknown(value)),
            };
            if width < 0 {
                options.left = true;
            }
            options.width = width.saturating_abs();
            cursor += 1;
        } else {
            let digits_start = cursor;
            while let Some(digit) = ascii_digit(format.get(cursor)) {
                options.width = options.width.checked_mul(10).and_then(|width| width.checked_add(i64::from(digit))).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "width too big"))?;
                cursor += 1;
            }
            if cursor > digits_start {
                digits_end = Some(cursor);
            }
        }

        if is_unit(format.get(cursor), b'.') {
            cursor += 1;
            if is_unit(format.get(cursor), b'*') {
                let precision = match star_argument(vm, &mut arguments)? {
                    Converted::Known(precision) => precision,
                    Converted::Unknown(value) => return Ok(Outcome::Unknown(value)),
                };
                if i32::try_from(precision).is_err() {
                    return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C int"));
                }
                options.precision = Some(precision.max(0));
                cursor += 1;
            } else {
                let digits_start = cursor;
                let mut precision: i32 = 0;
                while let Some(digit) = ascii_digit(format.get(cursor)) {
                    precision = precision.checked_mul(10).and_then(|precision| precision.checked_add(i32::from(digit))).ok_or_else(|| vm.raise(ExceptionKind::ValueError, "prec too big"))?;
                    cursor += 1;
                }
                if cursor > digits_start {
                    digits_end = Some(cursor);
                }
                options.precision = Some(i64::from(precision));
            }
        }

        if format.get(cursor).is_some_and(|unit| matches!(char::from_u32((*unit).into()), Some('h' | 'l' | 'L'))) {
            cursor += 1;
        }

        let Some(kind) = format.get(cursor).map(|unit| (*unit).into()) else {
            return Err(incomplete(vm));
        };
        let kind_index = cursor;
        position = cursor + 1;

        if kind == u32::from(b'%') {
            check_size(vm, options.width)?;
            pad_text(&mut output, &[T::from_ascii(b'%')], &options);
            continue;
        }

        let argument = arguments.next(vm)?;
        if argument.is_unknown() {
            return Ok(Outcome::Unknown(argument));
        }

        let piece = match char::from_u32(kind) {
            Some(conversion @ ('s' | 'r')) => text_piece::<T>(vm, &argument, conversion == 'r', &options)?,
            Some(conversion @ ('d' | 'i' | 'u' | 'o' | 'x' | 'X')) => integer_piece::<T>(vm, &argument, conversion, &options)?,
            Some(conversion @ ('e' | 'E' | 'f' | 'F' | 'g' | 'G')) => float_piece::<T>(vm, &argument, conversion, &options)?,
            Some('c') => char_piece::<T>(vm, &argument, &options)?,
            _ => return Err(unsupported_character::<T>(vm, kind, kind_index, digits_end != Some(kind_index))),
        };

        match piece {
            Piece::Text(units) => output.extend(units),
            Piece::Unknown(value) => return Ok(Outcome::Unknown(value)),
            Piece::Widen => return Ok(Outcome::Widen { done: output, restart: start, arguments: arguments.from_index(first_argument) }),
        }
    }

    if arguments.has_leftover() {
        return Err(vm.type_error("not all arguments converted during string formatting"));
    }

    Ok(Outcome::Text(output))
}

/// The index of the `)` closing a key that starts at `start`; keys may
/// hold balanced parentheses.
fn matching_paren<T: CodeUnit>(format: &[T], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    for (index, unit) in format.iter().enumerate().skip(start) {
        match char::from_u32((*unit).into()) {
            Some('(') => depth += 1,
            Some(')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }

    None
}

/// A width or precision given as `*`: the next argument, which must be
/// an `int`.
fn star_argument(vm: &Vm, arguments: &mut Arguments) -> PyResult<Converted<i64>> {
    let value = arguments.next(vm)?;
    if value.is_unknown() {
        return Ok(Converted::Unknown(value));
    }

    match vm.as_integral(&value) {
        Some(Integral::Int(number)) => Ok(Converted::Known(number)),
        _ => Err(vm.type_error("* wants int")),
    }
}

/// Appends `body` padded with spaces to the width of `options`.
fn pad_text<T: CodeUnit>(output: &mut Vec<T>, body: &[T], options: &Options) {
    let padding = usize::try_from(options.width - body.len() as i64).unwrap_or(0);
    let space = T::from_ascii(b' ');

    if !options.left {
        output.extend(std::iter::repeat_n(space, padding));
    }
    output.extend_from_slice(body);
    if options.left {
        output.extend(std::iter::repeat_n(space, padding));
    }
}

/// A signed number padded to the width of `options`: zero padding goes
/// between the sign and prefix and the digits.
fn number_field<T: CodeUnit>(sign: &[u8], prefix: &[u8], digits: &[u8], options: &Options) -> Vec<T> {
    let length = sign.len() + prefix.len() + digits.len();
    let padding = usize::try_from(options.width - length as i64).unwrap_or(0);

    let mut field = Vec::with_capacity(length + padding);
    if options.left {
        field.extend_from_slice(sign);
        field.extend_from_slice(prefix);
        field.extend_from_slice(digits);
        field.extend(std::iter::repeat_n(b' ', padding));
    } else if options.zero {
        field.extend_from_slice(sign);
        field.extend_from_slice(prefix);
        field.extend(std::iter::repeat_n(b'0', padding));
        field.extend_from_slice(digits);
    } else {
        field.extend(std::iter::repeat_n(b' ', padding));
        field.extend_from_slice(sign);
        field.extend_from_slice(prefix);
        field.extend_from_slice(digits);
    }

    widen_bytes(&field)
}

/// `%s` and `%r`.
fn text_piece<T: CodeUnit>(vm: &Vm, argument: &Value, repr: bool, options: &Options) -> PyResult<Piece<T>> {
    let mut units: Vec<T> = if T::UNICODE {
        let text = if repr { vm.repr(argument)? } else { vm.to_unicode(argument)? };
        if text.is_unknown() {
            return Ok(Piece::Unknown(text));
        }
        if let Some(bytes) = vm.as_str_bytes(&text) {
            codecs::decode_default(vm, bytes.as_bytes())?.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect()
        } else if let Some(text) = vm.as_text(&text) {
            text.units().iter().map(|unit| T::truncate(u32::from(*unit))).collect()
        } else {
            return Err(vm.type_error("conversion did not return a string"));
        }
    } else {
        if !repr && vm.as_text(argument).is_some() {
            return Ok(Piece::Widen);
        }
        let text = if repr { vm.repr(argument)? } else { vm.object_str(argument)? };
        if text.is_unknown() {
            return Ok(Piece::Unknown(text));
        }
        if vm.as_text(&text).is_some() {
            return Ok(Piece::Widen);
        }
        let Some(bytes) = vm.as_str_bytes(&text) else {
            return Err(vm.type_error("conversion did not return a string"));
        };
        widen_bytes(bytes.as_bytes())
    };

    if let Some(precision) = options.precision {
        units.truncate(usize::try_from(precision).unwrap_or(0));
    }

    check_size(vm, options.width)?;
    let mut field = Vec::new();
    pad_text(&mut field, &units, options);

    Ok(Piece::Text(field))
}

/// The integer of `%d` and friends: `int` and `long` values as they are,
/// other numbers through `int()`, or `long()` when that fails.
fn integer_argument(vm: &Vm, argument: &Value, conversion: char) -> PyResult<Converted<Integral>> {
    if let Some(integral) = vm.as_integral(argument) {
        return Ok(Converted::Known(integral));
    }

    // `%i` reports itself as `%d`.
    let shown = if conversion == 'i' { 'd' } else { conversion };
    let not_a_number = || vm.type_error(&format!("%{shown} format: a number is required, not {}", vm.type_name(argument)));
    let is_number = is_classic_instance(vm, argument) || vm.has_special(argument, "__int__")? || vm.has_special(argument, "__float__")?;
    if !is_number {
        return Err(not_a_number());
    }

    let types = vm.types();
    let mut converted = None;
    for class in [&types.int, &types.long] {
        match vm.call_class(class, CallArgs::new(vec![argument.clone()])) {
            Ok(value) => {
                converted = Some(value);
                break;
            }
            Err(Signal::Raise(_)) => {}
            Err(halt) => return Err(halt),
        }
    }
    let Some(converted) = converted else {
        return Err(not_a_number());
    };
    if converted.is_unknown() {
        return Ok(Converted::Unknown(converted));
    }

    vm.as_integral(&converted).map(Converted::Known).ok_or_else(not_a_number)
}

/// `%d`, `%i`, `%u`, `%o`, `%x`, and `%X`.
fn integer_piece<T: CodeUnit>(vm: &Vm, argument: &Value, conversion: char, options: &Options) -> PyResult<Piece<T>> {
    // A plain `int` is rendered into a fixed-size buffer.
    const INT_PRECISION_LIMIT: i64 = 116;

    let integral = match integer_argument(vm, argument, conversion)? {
        Converted::Known(integral) => integral,
        Converted::Unknown(value) => return Ok(Piece::Unknown(value)),
    };
    if !integral.is_long() && options.precision.is_some_and(|precision| precision > INT_PRECISION_LIMIT) {
        return Err(vm.raise(ExceptionKind::OverflowError, "formatted integer is too long (precision too large?)"));
    }
    let value: BigInt = integral.to_bigint();

    // A plain `int` zero with precision zero prints no digits; a `long`
    // zero always prints one.
    let mut digits = match conversion {
        _ if !integral.is_long() && options.precision == Some(0) && value.is_zero() => String::new(),
        'o' => value.magnitude().to_str_radix(8),
        'x' => value.magnitude().to_str_radix(16),
        'X' => value.magnitude().to_str_radix(16).to_ascii_uppercase(),
        _ => value.magnitude().to_str_radix(10),
    };

    if let Some(precision) = options.precision {
        check_size(vm, precision)?;
        let wanted = usize::try_from(precision).unwrap_or(0);
        if digits.len() < wanted {
            digits.insert_str(0, &"0".repeat(wanted - digits.len()));
        }
    }

    let prefix: &[u8] = match conversion {
        'o' if options.alternate && !digits.is_empty() && !digits.starts_with('0') => b"0",
        'x' if options.alternate => b"0x",
        'X' if options.alternate => b"0X",
        _ => b"",
    };

    check_size(vm, options.width)?;

    Ok(Piece::Text(number_field(options.sign(value.is_negative()), prefix, digits.as_bytes(), options)))
}

/// `%e`, `%f`, `%g`, and their uppercase forms.
fn float_piece<T: CodeUnit>(vm: &Vm, argument: &Value, conversion: char, options: &Options) -> PyResult<Piece<T>> {
    // A `str` format reports any conversion failure the same way; a
    // `unicode` format passes the failure on.
    let value = match float_as_double(vm, argument) {
        Ok(value) => value,
        Err(Signal::Raise(_)) if !T::UNICODE => return Err(vm.type_error(&format!("float argument required, not {}", vm.type_name(argument)))),
        Err(signal) => return Err(signal),
    };

    let form = match conversion.to_ascii_lowercase() {
        'e' => FloatForm::Exponent,
        'f' => FloatForm::Fixed,
        _ => FloatForm::General,
    };
    let precision = usize::try_from(options.precision.unwrap_or(6)).unwrap_or(0);
    check_size(vm, float_length_bound(form, precision, options.alternate))?;
    check_size(vm, options.width)?;

    let (negative, text) = render_float(value, form, precision, options.alternate, conversion.is_ascii_uppercase());

    Ok(Piece::Text(number_field(options.sign(negative), b"", text.as_bytes(), options)))
}

/// `%c`: one character from a one-character string or a code.
fn char_piece<T: CodeUnit>(vm: &Vm, argument: &Value, options: &Options) -> PyResult<Piece<T>> {
    let unit = if T::UNICODE { unicode_char(vm, argument)? } else {
        if vm.as_text(argument).is_some() {
            return Ok(Piece::Widen);
        }
        u32::from(byte_char(vm, argument)?)
    };

    check_size(vm, options.width)?;
    let mut field = Vec::new();
    pad_text(&mut field, &[T::truncate(unit)], options);

    Ok(Piece::Text(field))
}

/// The byte of `%c` in a `str` format.
fn byte_char(vm: &Vm, argument: &Value) -> PyResult<u8> {
    if let Some(bytes) = vm.as_str_bytes(argument) {
        let [byte] = bytes.as_bytes()[..] else {
            return Err(vm.type_error("%c requires int or char"));
        };
        return Ok(byte);
    }

    let code = long_argument(vm, argument)?;
    if code > i64::from(u8::MAX) {
        return Err(vm.raise(ExceptionKind::OverflowError, "unsigned byte integer is greater than maximum"));
    }

    u8::try_from(code).map_err(|_| vm.raise(ExceptionKind::OverflowError, "unsigned byte integer is less than minimum"))
}

/// The code unit of `%c` in a `unicode` format.
fn unicode_char(vm: &Vm, argument: &Value) -> PyResult<u32> {
    let invalid = || vm.type_error("%c requires int or char");

    if let Some(text) = vm.as_text(argument) {
        let [unit] = text.units()[..] else {
            return Err(invalid());
        };
        return Ok(u32::from(unit));
    }
    if let Some(bytes) = vm.as_str_bytes(argument) {
        let [_] = bytes.as_bytes()[..] else {
            return Err(invalid());
        };
        let decoded = codecs::decode_default(vm, bytes.as_bytes())?;
        return decoded.units().first().map(|unit| u32::from(*unit)).ok_or_else(invalid);
    }

    // A float converts through `int()`, which a subclass may override.
    let converted = if vm.as_float(argument).is_some() {
        match vm.call_class(&vm.types().int, CallArgs::new(vec![argument.clone()])) {
            Ok(value) => value,
            Err(Signal::Raise(_)) => return Err(invalid()),
            Err(halt) => return Err(halt),
        }
    } else {
        argument.clone()
    };
    let code = match long_argument(vm, &converted) {
        Ok(code) => code,
        Err(Signal::Raise(_)) => return Err(invalid()),
        Err(halt) => return Err(halt),
    };

    match u16::try_from(code) {
        Ok(unit) => Ok(u32::from(unit)),
        Err(_) => Err(vm.raise(ExceptionKind::OverflowError, "%c arg not in range(0x10000) (narrow Python build)")),
    }
}

/// The error for a conversion type outside the language. A `str` format
/// shows the byte as is, with its code sign-extended to 32 bits unless
/// it directly follows width or precision digits; a `unicode` format
/// shows printable ASCII and `?` otherwise.
fn unsupported_character<T: CodeUnit>(vm: &Vm, unit: u32, index: usize, sign_extend: bool) -> Signal {
    if T::UNICODE {
        let shown = char::from_u32(unit).filter(|_| (31..=126).contains(&unit)).unwrap_or('?');
        return vm.raise(ExceptionKind::ValueError, &format!("unsupported format character '{shown}' (0x{unit:x}) at index {index}"));
    }

    let code = if sign_extend && unit >= 0x80 { 0xffff_ff00 | unit } else { unit };
    let mut message = b"unsupported format character '".to_vec();
    message.push(unit as u8);
    message.extend_from_slice(format!("' (0x{code:x}) at index {index}").as_bytes());

    raise_bytes(vm, ExceptionKind::ValueError, message)
}
