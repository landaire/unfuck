//! The marshal object reader. Containers are read with an explicit
//! stack. A Python error is kept pending as CPython keeps it in the
//! thread state: reading a dict goes on after one, and the last one set is
//! the one raised.

use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::unicode::decode_utf8;
use crate::interp::code::CodeFlags;
use crate::interp::code::CodeObject;
use crate::interp::complex::Complex;
use crate::interp::error::MarshalError;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::marshal::MAX_DEPTH;
use crate::interp::marshal::types;
use crate::interp::numbers::PY_NAN;
use crate::interp::pyset::PySet;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The object `marshal.loads` reads from `bytes`.
pub fn loads(vm: &Vm, bytes: &[u8]) -> PyResult<Value> {
    let mut reader = Reader { vm, bytes, position: 0, strings: Vec::new(), error: None };
    let value = reader.read_object()?;

    if let Some(error) = reader.error {
        return Err(error);
    }

    value.ok_or_else(|| vm.raise(ExceptionKind::TypeError, "NULL object in marshal data for object"))
}

/// Reads the code object of a `.pyc` body (after its 8-byte header).
pub fn load_code(vm: &Vm, bytes: &[u8]) -> Result<ObjectRef, MarshalError> {
    let value = match loads(vm, bytes) {
        Ok(value) => value,
        Err(Signal::Raise(exception)) => return Err(MarshalError::Raised { rendered: vm.describe_exception(&exception) }),
        Err(Signal::Halt(halt)) => return Err(MarshalError::Halted(halt)),
    };

    match value {
        Value::Object(object) if matches!(object.payload, Payload::Code(_)) => Ok(object),
        _ => Err(MarshalError::NotCode),
    }
}

/// A container whose items are still being read.
enum Partial {
    Sequence { list: bool, items: Vec<Value>, count: usize },
    Set { set: Value, remaining: usize, frozen: bool },
    /// `key` holds a key whose value comes next.
    Dict { dict: ObjectRef, key: Option<Value> },
    Code { header: [i32; 4], fields: Vec<Value>, firstlineno: Option<i32> },
}

/// What reading the start of an object produced.
enum Step {
    /// A finished object, or `NULL` (with or without a pending error).
    Done(Option<Value>),
    Open(Partial),
}

/// What a container needs after receiving a child.
enum Progress {
    NeedChild,
    Done(Option<Value>),
}

struct Reader<'a> {
    vm: &'a Vm,
    bytes: &'a [u8],
    position: usize,
    /// The interned strings read so far, for `types::STRINGREF`.
    strings: Vec<PyBytes>,
    /// The pending Python exception.
    error: Option<Signal>,
}

impl Reader<'_> {
    /// Sets the pending error, replacing any earlier one.
    fn fail(&mut self, kind: ExceptionKind, message: &str) -> Option<Value> {
        self.error = Some(self.vm.raise(kind, message));

        None
    }

    /// Keeps a raised exception pending; halts end the read at once.
    fn pend(&mut self, signal: Signal) -> PyResult<()> {
        match signal {
            Signal::Raise(_) => {
                self.error = Some(signal);
                Ok(())
            }
            Signal::Halt(_) => Err(signal),
        }
    }

    fn eof(&mut self) -> Option<Value> {
        self.fail(ExceptionKind::EOFError, "EOF read where object expected")
    }

    /// The next byte: `-1` at the end of the data.
    fn byte(&mut self) -> i32 {
        let Some(&byte) = self.bytes.get(self.position) else {
            return -1;
        };
        self.position += 1;

        i32::from(byte)
    }

    /// A sign-extended 16-bit value; missing bytes read as -1.
    fn short(&mut self) -> i32 {
        let low = self.byte();
        let high = self.byte();

        i32::from((low | (high << 8)) as i16)
    }

    /// A 32-bit value; missing bytes read as -1, as `byte` returns.
    fn long(&mut self) -> i32 {
        let mut value = i64::from(self.byte());
        value |= i64::from(self.byte()) << 8;
        value |= i64::from(self.byte()) << 16;
        value |= i64::from(self.byte()) << 24;

        value as i32
    }

    /// Up to `count` bytes, fewer at the end of the data.
    fn string(&mut self, count: usize) -> &[u8] {
        let start = self.position.min(self.bytes.len());
        let end = start.saturating_add(count).min(self.bytes.len());
        self.position = end;

        &self.bytes[start..end]
    }

    fn exact(&mut self, count: usize) -> Option<Vec<u8>> {
        let bytes = self.string(count);

        (bytes.len() == count).then(|| bytes.to_vec())
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn read_object(&mut self) -> PyResult<Option<Value>> {
        let mut stack: Vec<Partial> = Vec::new();
        let mut step = self.start(1)?;

        loop {
            let value = match step {
                Step::Open(mut partial) => match self.advance(&mut partial, None)? {
                    Progress::NeedChild => {
                        stack.push(partial);
                        step = self.start(stack.len() + 1)?;
                        continue;
                    }
                    Progress::Done(value) => value,
                },
                Step::Done(value) => value,
            };

            let Some(mut parent) = stack.pop() else {
                return Ok(value);
            };

            step = match self.advance(&mut parent, Some(value))? {
                Progress::NeedChild => {
                    stack.push(parent);
                    self.start(stack.len() + 1)?
                }
                Progress::Done(value) => Step::Done(value),
            };
        }
    }

    /// The part of reading an object before any child object is read.
    fn start(&mut self, depth: usize) -> PyResult<Step> {
        let code = self.byte();

        if depth > MAX_DEPTH {
            return Ok(Step::Done(self.fail(ExceptionKind::ValueError, "recursion limit exceeded")));
        }

        let Ok(code) = u8::try_from(code) else {
            return Ok(Step::Done(self.eof()));
        };

        let value = match code {
            types::NULL => None,
            types::NONE => Some(Value::None),
            types::STOPITER => Some(Value::Object(Rc::clone(self.vm.types().exception(ExceptionKind::StopIteration)))),
            types::ELLIPSIS => Some(Value::Ellipsis),
            types::FALSE => Some(Value::Bool(false)),
            types::TRUE => Some(Value::Bool(true)),
            types::INT => Some(Value::Int(i64::from(self.long()))),
            types::INT64 => Some(self.int64()),
            types::LONG => self.py_long(),
            types::FLOAT => self.float_text().map(Value::Float),
            types::BINARY_FLOAT => self.binary_float().map(Value::Float),
            types::COMPLEX => self.float_text().and_then(|real| Some(Complex::new(real, self.float_text()?))).map(|number| self.vm.new_complex(number)),
            types::BINARY_COMPLEX => self.binary_float().and_then(|real| Some(Complex::new(real, self.binary_float()?))).map(|number| self.vm.new_complex(number)),
            types::STRING | types::INTERNED => self.str(code == types::INTERNED),
            types::STRINGREF => {
                let index = self.long();
                match usize::try_from(index).ok().and_then(|index| self.strings.get(index)) {
                    Some(string) => Some(Value::Str(string.clone())),
                    None => self.fail(ExceptionKind::ValueError, "bad marshal data (string ref out of range)"),
                }
            }
            types::UNICODE => self.unicode()?,
            types::TUPLE | types::LIST => {
                let list = code == types::LIST;
                let Some(count) = self.size(if list { "list" } else { "tuple" }) else {
                    return Ok(Step::Done(None));
                };
                // CPython allocates every slot of a tuple or list first;
                // past what the data can hold, whether that succeeds before
                // the read runs out depends on host memory.
                if count > self.remaining() && count > 1 << 29 {
                    return Err(self.vm.halt_unsupported(format!("marshal data declaring a sequence of {count} items")));
                }
                return Ok(Step::Open(Partial::Sequence { list, items: Vec::with_capacity(count.min(self.remaining())), count }));
            }
            types::DICT => return Ok(Step::Open(Partial::Dict { dict: self.vm.new_dict(), key: None })),
            types::SET | types::FROZENSET => {
                let Some(count) = self.size("set") else {
                    return Ok(Step::Done(None));
                };
                let set = self.vm.new_set(PySet::new());
                return Ok(Step::Open(Partial::Set { set, remaining: count, frozen: code == types::FROZENSET }));
            }
            types::CODE => {
                let header = [self.long(), self.long(), self.long(), self.long()];
                return Ok(Step::Open(Partial::Code { header, fields: Vec::with_capacity(8), firstlineno: None }));
            }
            _ => self.fail(ExceptionKind::ValueError, "bad marshal data (unknown type code)"),
        };

        Ok(Step::Done(value))
    }

    /// A container's size field; `None` with the error pending when it is
    /// negative.
    fn size(&mut self, what: &str) -> Option<usize> {
        let count = self.long();
        let Ok(count) = usize::try_from(count) else {
            self.fail(ExceptionKind::ValueError, &format!("bad marshal data ({what} size out of range)"));
            return None;
        };

        Some(count)
    }

    /// Feeds `child` (`None` before the first one) to `partial`.
    fn advance(&mut self, partial: &mut Partial, child: Option<Option<Value>>) -> PyResult<Progress> {
        match partial {
            Partial::Sequence { list, items, count } => {
                if let Some(child) = child {
                    let Some(item) = child else {
                        return Ok(Progress::Done(self.null_item(if *list { "list" } else { "tuple" })));
                    };
                    items.push(item);
                }
                if items.len() < *count {
                    return Ok(Progress::NeedChild);
                }

                let items = std::mem::take(items);
                let value = if *list { self.vm.new_list(items) } else { Value::tuple(items) };

                Ok(Progress::Done(Some(value)))
            }
            Partial::Set { set, remaining, frozen } => {
                if let Some(child) = child {
                    let Some(item) = child else {
                        return Ok(Progress::Done(self.null_item("set")));
                    };
                    if let Err(signal) = self.vm.set_add(set, item) {
                        self.pend(signal)?;
                        return Ok(Progress::Done(None));
                    }
                    *remaining -= 1;
                }
                if *remaining > 0 {
                    return Ok(Progress::NeedChild);
                }

                let value = match frozen {
                    true => self.vm.new_frozenset(self.vm.set_snapshot(set).unwrap_or_default()),
                    false => set.clone(),
                };

                Ok(Progress::Done(Some(value)))
            }
            Partial::Dict { dict, key } => {
                let Some(child) = child else {
                    return Ok(Progress::NeedChild);
                };
                let Some(pending_key) = key.take() else {
                    // A `NULL` key ends the dict.
                    if child.is_some() {
                        *key = child;
                        return Ok(Progress::NeedChild);
                    }
                    let value = if self.error.is_some() { None } else { Some(Value::Object(Rc::clone(dict))) };
                    return Ok(Progress::Done(value));
                };
                if let Some(value) = child
                    && let Err(signal) = self.vm.dict_set(dict, pending_key, value)
                {
                    self.pend(signal)?;
                }

                Ok(Progress::NeedChild)
            }
            Partial::Code { header, fields, firstlineno } => {
                if let Some(child) = child {
                    let Some(field) = child else {
                        return Ok(Progress::Done(None));
                    };
                    fields.push(field);
                }
                if fields.len() == 8 && firstlineno.is_none() {
                    *firstlineno = Some(self.long());
                }
                if fields.len() < 9 {
                    return Ok(Progress::NeedChild);
                }

                let fields = std::mem::take(fields);
                let header = *header;
                let firstlineno = firstlineno.unwrap_or_default();

                self.code(header, fields, firstlineno)
            }
        }
    }

    /// A `NULL` item of a sequence or set.
    fn null_item(&mut self, what: &str) -> Option<Value> {
        if self.error.is_none() {
            self.fail(ExceptionKind::TypeError, &format!("NULL object in marshal data for {what}"));
        }

        None
    }

    /// A 64-bit value: an `int` where C `long` has 64 bits, else a `long`.
    fn int64(&mut self) -> Value {
        let low = self.long();
        let high = self.long();
        let value = (i64::from(high) << 32) | i64::from(low as u32);

        match self.vm.config.long_width {
            LongWidth::Bits64 => Value::Int(value),
            LongWidth::Bits32 => Value::long(BigInt::from(value)),
        }
    }

    /// A `long` written as a signed digit count and 15-bit digits.
    fn py_long(&mut self) -> Option<Value> {
        let count = self.long();
        if count == i32::MIN {
            return self.fail(ExceptionKind::ValueError, "bad marshal data (long size out of range)");
        }

        let digits = count.unsigned_abs() as usize;
        let mut magnitude = BigInt::from(0);
        for index in 0..digits {
            let digit = self.short();
            if !(0..=0x7fff).contains(&digit) {
                return self.fail(ExceptionKind::ValueError, "bad marshal data (digit out of range in long)");
            }
            if digit == 0 && index + 1 == digits {
                return self.fail(ExceptionKind::ValueError, "bad marshal data (unnormalized long data)");
            }
            magnitude += BigInt::from(digit) << (15 * index);
        }

        let value = if count < 0 { -magnitude } else { magnitude };

        Some(Value::long(value))
    }

    /// A float written as a length byte and text, parsed by
    /// CPython's float parser up to the first NUL.
    fn float_text(&mut self) -> Option<f64> {
        let length = self.byte();
        let Ok(length) = usize::try_from(length) else {
            self.eof();
            return None;
        };
        let Some(text) = self.exact(length) else {
            self.eof();
            return None;
        };

        let text = text.split(|&byte| byte == 0).next().unwrap_or_default();
        if let Some(value) = parse_double(text) {
            return Some(value);
        }

        let mut message = b"could not convert string to float: ".to_vec();
        message.extend(text.iter().take(200));
        let class = std::rc::Rc::clone(self.vm.types().exception(ExceptionKind::ValueError));
        self.error = Some(self.vm.raise_string(&class, Value::Str(PyBytes::new_unshared(message))));

        None
    }

    fn binary_float(&mut self) -> Option<f64> {
        let Some(bytes) = self.exact(8) else {
            self.eof();
            return None;
        };
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(&bytes);

        Some(f64::from_le_bytes(buffer))
    }

    /// `types::STRING` and `types::INTERNED`. The string is allocated before
    /// its bytes are read, so only the empty one is shared.
    fn str(&mut self, interned: bool) -> Option<Value> {
        let length = self.long();
        let Ok(length) = usize::try_from(length) else {
            return self.fail(ExceptionKind::ValueError, "bad marshal data (string size out of range)");
        };
        let Some(bytes) = self.exact(length) else {
            return self.eof();
        };

        let mut string = PyBytes::new_unshared(bytes);
        if interned {
            string = self.vm.intern(&string);
            self.strings.push(string.clone());
        }

        Some(Value::Str(string))
    }

    fn unicode(&mut self) -> PyResult<Option<Value>> {
        let length = self.long();
        let Ok(length) = usize::try_from(length) else {
            return Ok(self.fail(ExceptionKind::ValueError, "bad marshal data (unicode size out of range)"));
        };
        let Some(bytes) = self.exact(length) else {
            return Ok(self.eof());
        };

        match decode_utf8(&bytes, true, &mut Errors::new(self.vm, None)) {
            Ok(decoded) => Ok(Some(Value::Unicode(PyText::new_unshared(decoded.units)))),
            Err(signal) => {
                self.pend(signal)?;
                Ok(None)
            }
        }
    }

    /// Builds a code object from the fields read, validating them as CPython does.
    fn code(&mut self, header: [i32; 4], fields: Vec<Value>, firstlineno: i32) -> PyResult<Progress> {
        let [argcount, nlocals, stacksize, flags] = header;
        let mut fields = fields.into_iter();
        let mut next = || fields.next().unwrap_or(Value::None);
        let (code, consts, names, varnames, freevars, cellvars, filename, name, lnotab) = (next(), next(), next(), next(), next(), next(), next(), next(), next());

        let code = code_bytes(self.vm, &code)?;
        let consts = tuple_items(&consts);
        let name_tuples = [&names, &varnames, &freevars, &cellvars].map(tuple_items);
        let strings = [&filename, &name, &lnotab].map(str_object);
        let (Some(code), Some(consts), [Some(names), Some(varnames), Some(freevars), Some(cellvars)], [Some(filename), Some(name), Some(lnotab)]) = (code, consts, name_tuples, strings) else {
            return Ok(Progress::Done(self.bad_internal_call()));
        };
        if argcount < 0 || nlocals < 0 {
            return Ok(Progress::Done(self.bad_internal_call()));
        }

        let names = name_strings(self.vm, names)?;
        let varnames = name_strings(self.vm, varnames)?;
        let freevars = name_strings(self.vm, freevars)?;
        let cellvars = name_strings(self.vm, cellvars)?;

        let code = CodeObject {
            argcount: argcount as u32,
            nlocals: nlocals as u32,
            stacksize: stacksize as u32,
            flags: CodeFlags(flags as u32),
            code: code.into(),
            consts,
            names,
            varnames,
            freevars,
            cellvars,
            filename,
            name,
            firstlineno: firstlineno as u32,
            lnotab,
        };

        Ok(Progress::Done(Some(self.vm.new_code(code))))
    }

    /// The `SystemError` the 2.7.12 Windows build raises for invalid code object fields.
    fn bad_internal_call(&mut self) -> Option<Value> {
        self.fail(ExceptionKind::SystemError, "..\\Objects\\codeobject.c:64: bad argument to internal function")
    }
}

/// The string object of a `str` field, kept as the same object
/// so its identity and interning carry over.
fn str_object(value: &Value) -> Option<PyBytes> {
    match value {
        Value::Str(string) => Some(string.clone()),
        Value::Object(object) => match &object.payload {
            Payload::Str(string) => Some(string.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The bytes of a `co_code` field that supports the read buffer interface.
fn code_bytes(vm: &Vm, value: &Value) -> PyResult<Option<Vec<u8>>> {
    if let Some(bytes) = value.as_bytes() {
        return Ok(Some(bytes.to_vec()));
    }
    if let Value::Object(object) = value
        && let Payload::Unicode(text) = &object.payload
    {
        return Ok(Some(text.units().iter().flat_map(|unit| unit.to_le_bytes()).collect()));
    }
    if let Value::Unicode(text) = value {
        return Ok(Some(text.units().iter().flat_map(|unit| unit.to_le_bytes()).collect()));
    }
    if !vm.buffer_slots(value).is_some_and(|slots| slots.read) {
        return Ok(None);
    }

    Ok(vm.buffer(value, BufferInterface::Any)?.map(|bytes| bytes.as_bytes().to_vec()))
}

/// The items of a `tuple` object.
fn tuple_items(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Tuple(items) => Some(items.to_vec()),
        Value::Object(object) => match &object.payload {
            Payload::Tuple(items) => Some(items.to_vec()),
            _ => None,
        },
        _ => None,
    }
}

/// The names of a code object: every item must be an exact `str`, which CPython
/// checks with a fatal error.
fn name_strings(vm: &Vm, items: Vec<Value>) -> PyResult<Vec<PyBytes>> {
    items
        .into_iter()
        .map(|item| match item {
            Value::Str(string) => Ok(string),
            _ => Err(vm.halt_unsupported("Py_FatalError: non-string found in code slot")),
        })
        .collect()
}

/// CPython's float parser: the whole text must be a
/// float literal; overflow gives an infinity.
fn parse_double(text: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(text).ok()?;
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let negative = text.starts_with('-');

    let lowered = unsigned.to_ascii_lowercase();
    if lowered == "inf" || lowered == "infinity" {
        return Some(if negative { f64::NEG_INFINITY } else { f64::INFINITY });
    }
    if lowered == "nan" {
        return Some(if negative { -PY_NAN } else { PY_NAN });
    }

    let valid = unsigned.bytes().next().is_some_and(|byte| byte.is_ascii_digit() || byte == b'.') && unsigned.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-'));
    if !valid {
        return None;
    }

    text.parse::<f64>().ok()
}
