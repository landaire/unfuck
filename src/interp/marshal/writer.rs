//! The marshal object writer, over any object model that can
//! describe its objects as `Shape`s.

use std::borrow::Cow;
use std::collections::HashMap;

use num_bigint::BigInt;
use num_bigint::Sign;

use crate::interp::builtins::modules::codecs::unicode::encode_utf8;
use crate::interp::marshal::MAX_DEPTH;
use crate::interp::marshal::types;
use crate::interp::numbers;

/// How the writer encodes one object.
pub enum Shape<'o, O> {
    None,
    StopIteration,
    Ellipsis,
    False,
    True,
    /// An exact `int`.
    Int(i64),
    Long(&'o BigInt),
    Float(f64),
    Complex { real: f64, imag: f64 },
    /// An exact `str`; interned ones share the `strings` table.
    Str { bytes: &'o [u8], interned: bool },
    Unicode(&'o [u16]),
    Tuple(Vec<O>),
    List(Vec<O>),
    /// The entries in dict iteration order.
    Dict(Vec<(O, O)>),
    Set(Vec<O>),
    FrozenSet(Vec<O>),
    Code(Box<CodeShape<O>>),
    /// Any other object with a single-segment read buffer, written as a
    /// `str`.
    Buffer(Cow<'o, [u8]>),
    Unmarshallable,
}

/// The fields of a code object in the order the writer writes them.
pub struct CodeShape<O> {
    pub argcount: u32,
    pub nlocals: u32,
    pub stacksize: u32,
    pub flags: u32,
    pub code: O,
    pub consts: O,
    pub names: O,
    pub varnames: O,
    pub freevars: O,
    pub cellvars: O,
    pub filename: O,
    pub name: O,
    pub firstlineno: u32,
    pub lnotab: O,
}

/// An object model the writer can walk.
pub trait MarshalSource {
    type Object;
    type Error;

    fn shape<'o>(&self, object: &'o Self::Object) -> Result<Shape<'o, Self::Object>, Self::Error>;
}

/// Why a write failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    Unmarshallable,
    NestedTooDeep,
}

/// The outcome of writing an object.
pub enum Marshalled {
    Written(Vec<u8>),
    /// `bytes` is what the writer wrote before and after the error; a file
    /// receives it, a string result is discarded.
    Failed { bytes: Vec<u8>, error: WriteError },
}

/// A pending object write, or a field written as a 32-bit integer.
enum Task<O> {
    Object { object: O, depth: usize },
    /// The null marker, which ends a dict.
    Null { depth: usize },
    Long(u32),
}

/// The marshal encoding of `root` in format `version`.
pub fn write<S: MarshalSource>(source: &S, root: S::Object, version: i64) -> Result<Marshalled, S::Error> {
    let mut writer = Writer { out: Vec::new(), strings: (version > 0).then(HashMap::new), version, error: None };
    let mut stack = vec![Task::Object { object: root, depth: 1 }];

    while let Some(task) = stack.pop() {
        let (object, depth) = match task {
            Task::Long(value) => {
                writer.long(value);
                continue;
            }
            Task::Null { depth } => {
                if depth > MAX_DEPTH {
                    writer.error = Some(WriteError::NestedTooDeep);
                } else {
                    writer.out.push(types::NULL);
                }
                continue;
            }
            Task::Object { object, depth } => (object, depth),
        };

        if depth > MAX_DEPTH {
            writer.error = Some(WriteError::NestedTooDeep);
            continue;
        }

        let child = depth + 1;
        match source.shape(&object)? {
            Shape::Tuple(items) => writer.sequence(types::TUPLE, items, child, &mut stack),
            Shape::List(items) => writer.sequence(types::LIST, items, child, &mut stack),
            Shape::Set(items) => writer.sequence(types::SET, items, child, &mut stack),
            Shape::FrozenSet(items) => writer.sequence(types::FROZENSET, items, child, &mut stack),
            Shape::Dict(entries) => {
                writer.out.push(types::DICT);
                stack.push(Task::Null { depth: child });
                for (key, value) in entries.into_iter().rev() {
                    stack.push(Task::Object { object: value, depth: child });
                    stack.push(Task::Object { object: key, depth: child });
                }
            }
            Shape::Code(code) => {
                let code = *code;
                writer.out.push(types::CODE);
                writer.long(code.argcount);
                writer.long(code.nlocals);
                writer.long(code.stacksize);
                writer.long(code.flags);

                stack.push(Task::Object { object: code.lnotab, depth: child });
                stack.push(Task::Long(code.firstlineno));
                for field in [code.name, code.filename, code.cellvars, code.freevars, code.varnames, code.names, code.consts, code.code] {
                    stack.push(Task::Object { object: field, depth: child });
                }
            }
            shape => writer.scalar(shape),
        }
    }

    Ok(match writer.error {
        None => Marshalled::Written(writer.out),
        Some(error) => Marshalled::Failed { bytes: writer.out, error },
    })
}

/// The `WFILE` of a string target.
struct Writer {
    out: Vec<u8>,
    /// The `strings` dict: interned strings written so far, by value.
    strings: Option<HashMap<Vec<u8>, u32>>,
    version: i64,
    error: Option<WriteError>,
}

impl Writer {
    /// A little-endian 32-bit value.
    fn long(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 32-bit length: `false` (with the error set) when `len` does not fit.
    fn size(&mut self, len: usize) -> bool {
        let Ok(len) = i32::try_from(len) else {
            self.error = Some(WriteError::Unmarshallable);
            return false;
        };

        self.long(len as u32);

        true
    }

    fn sequence<O>(&mut self, code: u8, items: Vec<O>, depth: usize, stack: &mut Vec<Task<O>>) {
        self.out.push(code);
        if !self.size(items.len()) {
            return;
        }

        stack.extend(items.into_iter().rev().map(|object| Task::Object { object, depth }));
    }

    /// Writes an object without children.
    fn scalar<O>(&mut self, shape: Shape<'_, O>) {
        match shape {
            Shape::None => self.out.push(types::NONE),
            Shape::StopIteration => self.out.push(types::STOPITER),
            Shape::Ellipsis => self.out.push(types::ELLIPSIS),
            Shape::False => self.out.push(types::FALSE),
            Shape::True => self.out.push(types::TRUE),
            Shape::Int(value) => self.int(value),
            Shape::Long(value) => self.py_long(value),
            Shape::Float(value) => {
                if self.version > 1 {
                    self.out.push(types::BINARY_FLOAT);
                    self.out.extend_from_slice(&value.to_le_bytes());
                } else {
                    self.out.push(types::FLOAT);
                    self.float_text(value);
                }
            }
            Shape::Complex { real, imag } => {
                if self.version > 1 {
                    self.out.push(types::BINARY_COMPLEX);
                    self.out.extend_from_slice(&real.to_le_bytes());
                    self.out.extend_from_slice(&imag.to_le_bytes());
                } else {
                    self.out.push(types::COMPLEX);
                    self.float_text(real);
                    self.float_text(imag);
                }
            }
            Shape::Str { bytes, interned } => self.string(bytes, interned),
            Shape::Unicode(units) => {
                self.out.push(types::UNICODE);
                self.counted(&encode_utf8(units));
            }
            Shape::Buffer(bytes) => {
                self.out.push(types::STRING);
                self.counted(&bytes);
            }
            Shape::Unmarshallable => {
                self.out.push(types::UNKNOWN);
                self.error = Some(WriteError::Unmarshallable);
            }
            Shape::Tuple(_) | Shape::List(_) | Shape::Dict(_) | Shape::Set(_) | Shape::FrozenSet(_) | Shape::Code(_) => {
                // Containers are handled by `write`.
            }
        }
    }

    /// A 32-bit length followed by `bytes`.
    fn counted(&mut self, bytes: &[u8]) {
        if self.size(bytes.len()) {
            self.out.extend_from_slice(bytes);
        }
    }

    /// An exact `int`: `types::INT64` only for values a 32-bit
    /// field cannot hold, which a C `long` of 32 bits never is.
    fn int(&mut self, value: i64) {
        let high = value >> 31;
        if high != 0 && high != -1 {
            self.out.push(types::INT64);
            self.out.extend_from_slice(&value.to_le_bytes());

            return;
        }

        self.out.push(types::INT);
        self.out.extend_from_slice(&(value as i32).to_le_bytes());
    }

    /// `repr`-style text with 17 significant digits after a length
    /// byte.
    fn float_text(&mut self, value: f64) {
        let text = numbers::format_general(value, 17, false, false);
        self.out.push(text.len() as u8);
        self.out.extend_from_slice(text.as_bytes());
    }

    /// The magnitude in 15-bit digits, least significant first,
    /// after the digit count negated for negative values.
    fn py_long(&mut self, value: &BigInt) {
        const SHIFT: u64 = 15;
        const MASK: u64 = (1 << SHIFT) - 1;

        self.out.push(types::LONG);

        let (sign, words) = value.to_u64_digits();
        let count = value.bits().div_ceil(SHIFT);
        let Ok(count32) = i32::try_from(count) else {
            self.error = Some(WriteError::Unmarshallable);
            return;
        };
        let signed_count = if sign == Sign::Minus { count32.wrapping_neg() } else { count32 };
        self.long(signed_count as u32);

        for digit in 0..count {
            let bit = digit * SHIFT;
            let word = (bit / 64) as usize;
            let offset = bit % 64;
            let low = words.get(word).map_or(0, |&value| value >> offset);
            let high = match offset {
                0 => 0,
                _ => words.get(word + 1).map_or(0, |&value| value << (64 - offset)),
            };
            self.out.extend_from_slice(&(((low | high) & MASK) as u16).to_le_bytes());
        }
    }

    /// An exact `str`: with a `strings` table, interned
    /// strings are written as `t` on first sight and `R <index>` after.
    fn string(&mut self, bytes: &[u8], interned: bool) {
        let Some(strings) = self.strings.as_mut().filter(|_| interned) else {
            self.out.push(types::STRING);
            self.counted(bytes);
            return;
        };

        if let Some(&index) = strings.get(bytes) {
            self.out.push(types::STRINGREF);
            self.long(index);
            return;
        }

        let index = strings.len() as u32;
        strings.insert(bytes.to_vec(), index);
        self.out.push(types::INTERNED);
        self.counted(bytes);
    }
}
