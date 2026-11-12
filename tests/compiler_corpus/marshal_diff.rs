//! A structural decoder for marshal version 2 data and a report of the first
//! place where two marshalled code objects differ.

use std::fmt::Write;

use num_bigint::BigInt;

const RED_ZONE: usize = 64 * 1024;
const STACK_GROWTH: usize = 2 * 1024 * 1024;
const HAVE_ARGUMENT: u8 = 90;
const EXTENDED_ARG: u8 = 145;
const REPR_LIMIT: usize = 120;

#[derive(Debug, thiserror::Error)]
#[error("marshal data offset {offset}: {kind}")]
pub struct DecodeError {
    pub offset: usize,
    pub kind: DecodeErrorKind,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeErrorKind {
    #[error("truncated")]
    Truncated,
    #[error("unknown type code {code:#04x}")]
    UnknownType { code: u8 },
    #[error("string reference {index} out of range")]
    BadReference { index: u32 },
    #[error("negative length {len}")]
    NegativeLength { len: i32 },
    #[error("{trailing} trailing bytes")]
    Trailing { trailing: usize },
}

/// How a `str` was written: `s`, `t`, or `R` with its index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrForm {
    Plain,
    Interned,
    Reference(u32),
}

impl StrForm {
    fn is_interned(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    None,
    Ellipsis,
    StopIteration,
    True,
    False,
    Int(i64),
    Long(BigInt),
    Float(u64),
    Complex { real: u64, imag: u64 },
    Str { value: Vec<u8>, form: StrForm },
    Unicode(Vec<u8>),
    Tuple(Vec<Value>),
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
    Set(Vec<Value>),
    FrozenSet(Vec<Value>),
    Code(Box<Code>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Code {
    pub argcount: i32,
    pub nlocals: i32,
    pub stacksize: i32,
    pub flags: i32,
    pub code: Value,
    pub consts: Value,
    pub names: Value,
    pub varnames: Value,
    pub freevars: Value,
    pub cellvars: Value,
    pub filename: Value,
    pub name: Value,
    pub firstlineno: i32,
    pub lnotab: Value,
}

impl Code {
    fn display_name(&self) -> String {
        let name = match &self.name {
            Value::Str { value, .. } => String::from_utf8_lossy(value).into_owned(),
            other => repr(other),
        };

        if name.starts_with('<') { name } else { format!("<{name}>") }
    }
}

/// `marshal.loads` of a complete byte string.
pub fn decode(data: &[u8]) -> Result<Value, DecodeError> {
    let mut decoder = Decoder { data, position: 0, interned: Vec::new() };
    let value = decoder.value()?;

    let trailing = data.len() - decoder.position;
    if trailing != 0 {
        return Err(DecodeError { offset: decoder.position, kind: DecodeErrorKind::Trailing { trailing } });
    }

    Ok(value)
}

struct Decoder<'a> {
    data: &'a [u8],
    position: usize,
    interned: Vec<Vec<u8>>,
}

impl Decoder<'_> {
    fn error(&self, kind: DecodeErrorKind) -> DecodeError {
        DecodeError { offset: self.position, kind }
    }

    fn bytes(&mut self, len: usize) -> Result<&[u8], DecodeError> {
        let Some(bytes) = self.data.get(self.position..self.position + len) else {
            return Err(self.error(DecodeErrorKind::Truncated));
        };
        self.position += len;

        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    fn i32(&mut self) -> Result<i32, DecodeError> {
        let bytes = self.bytes(4)?;

        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.bytes(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);

        Ok(u64::from_le_bytes(array))
    }

    fn len(&mut self) -> Result<usize, DecodeError> {
        let len = self.i32()?;

        usize::try_from(len).map_err(|_| self.error(DecodeErrorKind::NegativeLength { len }))
    }

    fn sized_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.len()?;

        Ok(self.bytes(len)?.to_vec())
    }

    fn values(&mut self) -> Result<Vec<Value>, DecodeError> {
        let len = self.len()?;

        (0..len).map(|_| self.value()).collect()
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.value_inner())
    }

    fn value_inner(&mut self) -> Result<Value, DecodeError> {
        let code = self.byte()?;

        let value = match code {
            b'0' => Value::Null,
            b'N' => Value::None,
            b'.' => Value::Ellipsis,
            b'S' => Value::StopIteration,
            b'T' => Value::True,
            b'F' => Value::False,
            b'i' => Value::Int(i64::from(self.i32()?)),
            b'I' => Value::Int(self.u64()? as i64),
            b'l' => self.long()?,
            b'g' => Value::Float(self.u64()?),
            b'y' => Value::Complex { real: self.u64()?, imag: self.u64()? },
            b's' => Value::Str { value: self.sized_bytes()?, form: StrForm::Plain },
            b't' => {
                let value = self.sized_bytes()?;
                self.interned.push(value.clone());

                Value::Str { value, form: StrForm::Interned }
            }
            b'R' => {
                let index = self.i32()? as u32;
                let Some(value) = self.interned.get(index as usize) else {
                    return Err(self.error(DecodeErrorKind::BadReference { index }));
                };

                Value::Str { value: value.clone(), form: StrForm::Reference(index) }
            }
            b'u' => Value::Unicode(self.sized_bytes()?),
            b'(' => Value::Tuple(self.values()?),
            b'[' => Value::List(self.values()?),
            b'<' => Value::Set(self.values()?),
            b'>' => Value::FrozenSet(self.values()?),
            b'{' => {
                let mut items = Vec::new();
                loop {
                    let key = self.value()?;
                    if key == Value::Null {
                        break;
                    }
                    items.push((key, self.value()?));
                }

                Value::Dict(items)
            }
            b'c' => Value::Code(Box::new(Code {
                argcount: self.i32()?,
                nlocals: self.i32()?,
                stacksize: self.i32()?,
                flags: self.i32()?,
                code: self.value()?,
                consts: self.value()?,
                names: self.value()?,
                varnames: self.value()?,
                freevars: self.value()?,
                cellvars: self.value()?,
                filename: self.value()?,
                name: self.value()?,
                firstlineno: self.i32()?,
                lnotab: self.value()?,
            })),
            other => {
                self.position -= 1;

                return Err(self.error(DecodeErrorKind::UnknownType { code: other }));
            }
        };

        Ok(value)
    }

    /// `r_PyLong`: a signed digit count, then 15-bit digits.
    fn long(&mut self) -> Result<Value, DecodeError> {
        let size = self.i32()?;
        let mut magnitude = BigInt::from(0);

        let digits = (0..size.unsigned_abs()).map(|_| -> Result<u16, DecodeError> {
            let bytes = self.bytes(2)?;

            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        });
        let digits = digits.collect::<Result<Vec<_>, _>>()?;
        for digit in digits.iter().rev() {
            magnitude = (magnitude << 15) + BigInt::from(*digit);
        }

        let value = if size < 0 { -magnitude } else { magnitude };

        Ok(Value::Long(value))
    }
}

/// Describes the first difference between the marshalled code objects
/// `expected` and `actual`, or `None` when the bytes are identical.
pub fn describe_difference(expected: &[u8], actual: &[u8]) -> Option<String> {
    if expected == actual {
        return None;
    }

    let expected_value = match decode(expected) {
        Ok(value) => value,
        Err(error) => return Some(format!("expected bytes do not decode: {error}")),
    };
    let actual_value = match decode(actual) {
        Ok(value) => value,
        Err(error) => return Some(format!("actual bytes do not decode: {error}")),
    };

    let root = match &expected_value {
        Value::Code(code) => code.display_name(),
        _ => String::from("<root>"),
    };

    // Compare with t and R treated alike first: an interning difference
    // shifts every later R index, so the first t/s mismatch is the cause.
    for mode in [Mode::Structure, Mode::Exact] {
        let differ = Differ { mode };
        if let Some(report) = differ.value(&root, &expected_value, &actual_value) {
            return Some(report);
        }
    }

    let offset = expected.iter().zip(actual).position(|(left, right)| left != right).unwrap_or(expected.len().min(actual.len()));

    Some(format!("marshal bytes differ at offset {offset} (expected {} bytes, got {})", expected.len(), actual.len()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `t` and `R` compare equal; only interned versus not matters.
    Structure,
    /// String forms and reference indices must match.
    Exact,
}

struct Differ {
    mode: Mode,
}

impl Differ {
    fn same(&self, expected: &Value, actual: &Value) -> bool {
        match self.mode {
            Mode::Exact => expected == actual,
            Mode::Structure => self.structure_equal(expected, actual),
        }
    }

    fn structure_equal(&self, expected: &Value, actual: &Value) -> bool {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || match (expected, actual) {
            (Value::Str { value: left, form: left_form }, Value::Str { value: right, form: right_form }) => left == right && left_form.is_interned() == right_form.is_interned(),
            (Value::Tuple(left), Value::Tuple(right)) | (Value::List(left), Value::List(right)) | (Value::Set(left), Value::Set(right)) | (Value::FrozenSet(left), Value::FrozenSet(right)) => {
                left.len() == right.len() && left.iter().zip(right).all(|(left, right)| self.structure_equal(left, right))
            }
            (Value::Dict(left), Value::Dict(right)) => {
                left.len() == right.len() && left.iter().zip(right).all(|((left_key, left_value), (right_key, right_value))| self.structure_equal(left_key, right_key) && self.structure_equal(left_value, right_value))
            }
            (Value::Code(left), Value::Code(right)) => self.code(left, right, "").is_none(),
            _ => expected == actual,
        })
    }

    fn value(&self, path: &str, expected: &Value, actual: &Value) -> Option<String> {
        if self.same(expected, actual) {
            return None;
        }

        match (expected, actual) {
            (Value::Code(expected), Value::Code(actual)) => self.code(expected, actual, path),
            (Value::Tuple(expected_items), Value::Tuple(actual_items)) if expected_items.len() == actual_items.len() => {
                let (index, (expected_item, actual_item)) = expected_items.iter().zip(actual_items).enumerate().find(|(_, (left, right))| !self.same(left, right))?;

                self.value(&format!("{path}[{index}]"), expected_item, actual_item)
            }
            _ => Some(format!("{path}: expected {}, got {}", repr(expected), repr(actual))),
        }
    }

    fn code(&self, expected: &Code, actual: &Code, path: &str) -> Option<String> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.code_inner(expected, actual, path))
    }

    fn code_inner(&self, expected: &Code, actual: &Code, path: &str) -> Option<String> {
        if !self.same(&expected.code, &actual.code) {
            return Some(code_difference(path, expected, actual));
        }

        if let Some(report) = self.consts(path, expected, actual) {
            return Some(report);
        }

        let tuples = [
            ("co_names", &expected.names, &actual.names),
            ("co_varnames", &expected.varnames, &actual.varnames),
            ("co_freevars", &expected.freevars, &actual.freevars),
            ("co_cellvars", &expected.cellvars, &actual.cellvars),
        ];
        for (field, expected_value, actual_value) in tuples {
            if let Some(report) = self.value(&format!("{path}/{field}"), expected_value, actual_value) {
                return Some(report);
            }
        }

        let integers = [
            ("co_argcount", expected.argcount, actual.argcount),
            ("co_nlocals", expected.nlocals, actual.nlocals),
            ("co_stacksize", expected.stacksize, actual.stacksize),
            ("co_firstlineno", expected.firstlineno, actual.firstlineno),
        ];
        for (field, expected_value, actual_value) in integers {
            if expected_value != actual_value {
                return Some(format!("{path}/{field}: expected {expected_value}, got {actual_value}"));
            }
        }

        if expected.flags != actual.flags {
            return Some(format!("{path}/co_flags: expected {:#07x}, got {:#07x}", expected.flags, actual.flags));
        }

        let others = [("co_filename", &expected.filename, &actual.filename), ("co_name", &expected.name, &actual.name)];
        for (field, expected_value, actual_value) in others {
            if let Some(report) = self.value(&format!("{path}/{field}"), expected_value, actual_value) {
                return Some(report);
            }
        }

        if !self.same(&expected.lnotab, &actual.lnotab) {
            return Some(lnotab_difference(path, &expected.lnotab, &actual.lnotab));
        }

        None
    }

    fn consts(&self, path: &str, expected: &Code, actual: &Code) -> Option<String> {
        let (Value::Tuple(expected_items), Value::Tuple(actual_items)) = (&expected.consts, &actual.consts) else {
            return self.value(&format!("{path}/co_consts"), &expected.consts, &actual.consts);
        };

        if expected_items.len() != actual_items.len() {
            return Some(format!(
                "{path}/co_consts: expected {} items, got {}\n  expected: {}\n  actual:   {}",
                expected_items.len(),
                actual_items.len(),
                repr(&expected.consts),
                repr(&actual.consts)
            ));
        }

        let (index, (expected_item, actual_item)) = expected_items.iter().zip(actual_items).enumerate().find(|(_, (left, right))| !self.same(left, right))?;
        let item_path = match expected_item {
            Value::Code(code) => format!("{path}/co_consts[{index}]{}", code.display_name()),
            _ => format!("{path}/co_consts[{index}]"),
        };

        self.value(&item_path, expected_item, actual_item)
    }
}

struct Instruction {
    offset: usize,
    opcode: u8,
    arg: Option<u32>,
}

fn instructions(code: &[u8]) -> Vec<Instruction> {
    let mut result = Vec::new();
    let mut offset = 0;

    while let Some(&opcode) = code.get(offset) {
        let arg = if opcode >= HAVE_ARGUMENT {
            match code.get(offset + 1..offset + 3) {
                Some(bytes) => Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
                None => None,
            }
        } else {
            None
        };
        result.push(Instruction { offset, opcode, arg });
        offset += if opcode >= HAVE_ARGUMENT { 3 } else { 1 };
    }

    result
}

fn code_bytes(value: &Value) -> &[u8] {
    match value {
        Value::Str { value, .. } => value,
        _ => &[],
    }
}

fn tuple_item(tuple: &Value, index: u32) -> Option<&Value> {
    match tuple {
        Value::Tuple(items) => items.get(index as usize),
        _ => None,
    }
}

fn format_instruction(instruction: &Instruction, code: &Code) -> String {
    let name = opcode_name(instruction.opcode);
    let Some(arg) = instruction.arg else {
        return format!("{:>6} {name}", instruction.offset);
    };

    let annotation = match instruction.opcode {
        100 => tuple_item(&code.consts, arg).map(repr),
        90 | 91 | 95 | 96 | 97 | 98 | 101 | 106 | 108 | 109 | 116 => tuple_item(&code.names, arg).map(repr),
        124..=126 => tuple_item(&code.varnames, arg).map(repr),
        135..=137 => {
            let cell_count = match &code.cellvars {
                Value::Tuple(items) => items.len() as u32,
                _ => 0,
            };
            if arg < cell_count { tuple_item(&code.cellvars, arg).map(repr) } else { tuple_item(&code.freevars, arg - cell_count).map(repr) }
        }
        93 | 110 | 120 | 121 | 122 | 143 => Some(format!("to {}", instruction.offset + 3 + arg as usize)),
        107 => COMPARE_OPS.get(arg as usize).map(|name| (*name).to_owned()),
        _ => None,
    };

    match annotation {
        Some(annotation) => format!("{:>6} {name} {arg} ({annotation})", instruction.offset),
        None => format!("{:>6} {name} {arg}", instruction.offset),
    }
}

fn short_instruction(instruction: Option<&Instruction>) -> String {
    match instruction {
        Some(Instruction { opcode, arg: Some(arg), .. }) => format!("{} {arg}", opcode_name(*opcode)),
        Some(Instruction { opcode, arg: None, .. }) => opcode_name(*opcode).to_owned(),
        None => String::from("end of code"),
    }
}

fn code_difference(path: &str, expected: &Code, actual: &Code) -> String {
    const BEFORE: usize = 4;
    const AFTER: usize = 6;

    let expected_code = code_bytes(&expected.code);
    let actual_code = code_bytes(&actual.code);
    let expected_instructions = instructions(expected_code);
    let actual_instructions = instructions(actual_code);

    let index = expected_instructions
        .iter()
        .zip(&actual_instructions)
        .position(|(left, right)| left.offset != right.offset || left.opcode != right.opcode || left.arg != right.arg)
        .unwrap_or(expected_instructions.len().min(actual_instructions.len()));
    let offset = expected_instructions.get(index).or(actual_instructions.get(index)).map_or(expected_code.len(), |instruction| instruction.offset);

    let mut report = format!(
        "{path}/co_code @ offset {offset}: expected {}, got {}",
        short_instruction(expected_instructions.get(index)),
        short_instruction(actual_instructions.get(index))
    );
    if expected_code.len() != actual_code.len() {
        let _ = write!(report, " (code length expected {}, got {})", expected_code.len(), actual_code.len());
    }

    let start = index.saturating_sub(BEFORE);
    for (label, instructions, code) in [("expected", &expected_instructions, expected), ("actual", &actual_instructions, actual)] {
        let _ = write!(report, "\n  {label}:");
        for (position, instruction) in instructions.iter().enumerate().skip(start).take(BEFORE + AFTER) {
            let marker = if position == index { "-->" } else { "   " };
            let _ = write!(report, "\n  {marker}{}", format_instruction(instruction, code));
        }
    }

    report
}

/// `(address, line)` pairs of the line number table, relative to
/// `co_firstlineno`.
fn lnotab_rows(lnotab: &Value) -> Vec<(usize, usize)> {
    let bytes = code_bytes(lnotab);
    let mut address = 0;
    let mut line = 0;

    bytes
        .chunks(2)
        .map(|pair| {
            address += usize::from(pair[0]);
            line += pair.get(1).copied().map_or(0, usize::from);

            (address, line)
        })
        .collect()
}

fn lnotab_difference(path: &str, expected: &Value, actual: &Value) -> String {
    let expected_bytes = code_bytes(expected);
    let actual_bytes = code_bytes(actual);
    let pair = expected_bytes.chunks(2).zip(actual_bytes.chunks(2)).position(|(left, right)| left != right).unwrap_or(expected_bytes.len().min(actual_bytes.len()) / 2);
    let expected_rows = lnotab_rows(expected);
    let actual_rows = lnotab_rows(actual);

    let start = pair.saturating_sub(2);
    let window = |rows: &[(usize, usize)]| rows.iter().skip(start).take(6).map(|(address, line)| format!("{address}:+{line}")).collect::<Vec<_>>().join(" ");

    format!(
        "{path}/co_lnotab: first difference in pair {pair} ({} vs {} bytes); address:+line from pair {start}\n  expected: {}\n  actual:   {}",
        expected_bytes.len(),
        actual_bytes.len(),
        window(&expected_rows),
        window(&actual_rows)
    )
}

fn escape_bytes(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => text.push_str("\\\\"),
            b'\'' => text.push_str("\\'"),
            b'\n' => text.push_str("\\n"),
            b'\t' => text.push_str("\\t"),
            0x20..=0x7e => text.push(char::from(byte)),
            _ => {
                let _ = write!(text, "\\x{byte:02x}");
            }
        }
    }

    text
}

/// A short Python-like representation, with `s`, `t`, or `R<index>` before
/// each `str`.
pub fn repr(value: &Value) -> String {
    let mut text = String::new();
    write_repr(&mut text, value);

    if text.len() > REPR_LIMIT {
        let mut end = REPR_LIMIT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }

    text
}

fn write_items(text: &mut String, open: &str, items: &[Value], close: &str) {
    text.push_str(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        if text.len() > REPR_LIMIT {
            text.push_str("...");
            break;
        }
        write_repr(text, item);
    }
    if items.len() == 1 && open == "(" {
        text.push(',');
    }
    text.push_str(close);
}

fn write_repr(text: &mut String, value: &Value) {
    stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || match value {
        Value::Null => text.push_str("<null>"),
        Value::None => text.push_str("None"),
        Value::Ellipsis => text.push_str("Ellipsis"),
        Value::StopIteration => text.push_str("StopIteration"),
        Value::True => text.push_str("True"),
        Value::False => text.push_str("False"),
        Value::Int(value) => {
            let _ = write!(text, "{value}");
        }
        Value::Long(value) => {
            let _ = write!(text, "{value}L");
        }
        Value::Float(bits) => {
            let _ = write!(text, "{:?}", f64::from_bits(*bits));
        }
        Value::Complex { real, imag } => {
            let _ = write!(text, "({:?}+{:?}j)", f64::from_bits(*real), f64::from_bits(*imag));
        }
        Value::Str { value, form } => {
            let prefix = match form {
                StrForm::Plain => String::from("s"),
                StrForm::Interned => String::from("t"),
                StrForm::Reference(index) => format!("R{index}"),
            };
            let _ = write!(text, "{prefix}'{}'", escape_bytes(value));
        }
        Value::Unicode(value) => {
            let _ = write!(text, "u'{}'", escape_bytes(value));
        }
        Value::Tuple(items) => write_items(text, "(", items, ")"),
        Value::List(items) => write_items(text, "[", items, "]"),
        Value::Set(items) => write_items(text, "set([", items, "])"),
        Value::FrozenSet(items) => write_items(text, "frozenset([", items, "])"),
        Value::Dict(items) => {
            let _ = write!(text, "<dict of {}>", items.len());
        }
        Value::Code(code) => {
            let _ = write!(text, "<code {}>", code.display_name());
        }
    });
}

const COMPARE_OPS: [&str; 12] = ["<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD"];

/// `opname` of `Lib/opcode.py`.
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "STOP_CODE",
        1 => "POP_TOP",
        2 => "ROT_TWO",
        3 => "ROT_THREE",
        4 => "DUP_TOP",
        5 => "ROT_FOUR",
        9 => "NOP",
        10 => "UNARY_POSITIVE",
        11 => "UNARY_NEGATIVE",
        12 => "UNARY_NOT",
        13 => "UNARY_CONVERT",
        15 => "UNARY_INVERT",
        19 => "BINARY_POWER",
        20 => "BINARY_MULTIPLY",
        21 => "BINARY_DIVIDE",
        22 => "BINARY_MODULO",
        23 => "BINARY_ADD",
        24 => "BINARY_SUBTRACT",
        25 => "BINARY_SUBSCR",
        26 => "BINARY_FLOOR_DIVIDE",
        27 => "BINARY_TRUE_DIVIDE",
        28 => "INPLACE_FLOOR_DIVIDE",
        29 => "INPLACE_TRUE_DIVIDE",
        30 => "SLICE+0",
        31 => "SLICE+1",
        32 => "SLICE+2",
        33 => "SLICE+3",
        40 => "STORE_SLICE+0",
        41 => "STORE_SLICE+1",
        42 => "STORE_SLICE+2",
        43 => "STORE_SLICE+3",
        50 => "DELETE_SLICE+0",
        51 => "DELETE_SLICE+1",
        52 => "DELETE_SLICE+2",
        53 => "DELETE_SLICE+3",
        54 => "STORE_MAP",
        55 => "INPLACE_ADD",
        56 => "INPLACE_SUBTRACT",
        57 => "INPLACE_MULTIPLY",
        58 => "INPLACE_DIVIDE",
        59 => "INPLACE_MODULO",
        60 => "STORE_SUBSCR",
        61 => "DELETE_SUBSCR",
        62 => "BINARY_LSHIFT",
        63 => "BINARY_RSHIFT",
        64 => "BINARY_AND",
        65 => "BINARY_XOR",
        66 => "BINARY_OR",
        67 => "INPLACE_POWER",
        68 => "GET_ITER",
        70 => "PRINT_EXPR",
        71 => "PRINT_ITEM",
        72 => "PRINT_NEWLINE",
        73 => "PRINT_ITEM_TO",
        74 => "PRINT_NEWLINE_TO",
        75 => "INPLACE_LSHIFT",
        76 => "INPLACE_RSHIFT",
        77 => "INPLACE_AND",
        78 => "INPLACE_XOR",
        79 => "INPLACE_OR",
        80 => "BREAK_LOOP",
        81 => "WITH_CLEANUP",
        82 => "LOAD_LOCALS",
        83 => "RETURN_VALUE",
        84 => "IMPORT_STAR",
        85 => "EXEC_STMT",
        86 => "YIELD_VALUE",
        87 => "POP_BLOCK",
        88 => "END_FINALLY",
        89 => "BUILD_CLASS",
        90 => "STORE_NAME",
        91 => "DELETE_NAME",
        92 => "UNPACK_SEQUENCE",
        93 => "FOR_ITER",
        94 => "LIST_APPEND",
        95 => "STORE_ATTR",
        96 => "DELETE_ATTR",
        97 => "STORE_GLOBAL",
        98 => "DELETE_GLOBAL",
        99 => "DUP_TOPX",
        100 => "LOAD_CONST",
        101 => "LOAD_NAME",
        102 => "BUILD_TUPLE",
        103 => "BUILD_LIST",
        104 => "BUILD_SET",
        105 => "BUILD_MAP",
        106 => "LOAD_ATTR",
        107 => "COMPARE_OP",
        108 => "IMPORT_NAME",
        109 => "IMPORT_FROM",
        110 => "JUMP_FORWARD",
        111 => "JUMP_IF_FALSE_OR_POP",
        112 => "JUMP_IF_TRUE_OR_POP",
        113 => "JUMP_ABSOLUTE",
        114 => "POP_JUMP_IF_FALSE",
        115 => "POP_JUMP_IF_TRUE",
        116 => "LOAD_GLOBAL",
        119 => "CONTINUE_LOOP",
        120 => "SETUP_LOOP",
        121 => "SETUP_EXCEPT",
        122 => "SETUP_FINALLY",
        124 => "LOAD_FAST",
        125 => "STORE_FAST",
        126 => "DELETE_FAST",
        130 => "RAISE_VARARGS",
        131 => "CALL_FUNCTION",
        132 => "MAKE_FUNCTION",
        133 => "BUILD_SLICE",
        134 => "MAKE_CLOSURE",
        135 => "LOAD_CLOSURE",
        136 => "LOAD_DEREF",
        137 => "STORE_DEREF",
        140 => "CALL_FUNCTION_VAR",
        141 => "CALL_FUNCTION_KW",
        142 => "CALL_FUNCTION_VAR_KW",
        143 => "SETUP_WITH",
        EXTENDED_ARG => "EXTENDED_ARG",
        146 => "SET_ADD",
        147 => "MAP_ADD",
        _ => "<unknown>",
    }
}
