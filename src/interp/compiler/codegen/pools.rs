//! The indexed tables a code object refers to: `co_consts` and the name
//! tuples.

use std::collections::HashMap;

use num_bigint::BigInt;

use crate::interp::compiler::object::Object;
use crate::interp::compiler::unit::CodeUnit;
use crate::interp::compiler::unit::Constant;

/// What decides whether two constants share a `co_consts` slot: the exact
/// type and the value, with `0.0` and `-0.0` kept apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ConstantKey {
    None,
    Ellipsis,
    Int(i64),
    Long(BigInt),
    Float(u64),
    Complex { real: u64, imag: u64 },
    Str(Vec<u8>),
    Unicode(Vec<u16>),
    Tuple(Vec<ConstantKey>),
    Code(Box<CodeKey>),
}

impl ConstantKey {
    fn of_object(object: &Object) -> Self {
        match object {
            Object::None => Self::None,
            Object::Ellipsis => Self::Ellipsis,
            Object::Int(value) => Self::Int(*value),
            Object::Long(value) => Self::Long(BigInt::clone(value)),
            Object::Float(value) => Self::Float(value.to_bits()),
            Object::Complex(value) => Self::Complex { real: value.real.to_bits(), imag: value.imag.to_bits() },
            Object::Str(object) => Self::Str(object.value.clone()),
            Object::Unicode(units) => Self::Unicode(units.to_vec()),
            Object::Tuple(items) => Self::Tuple(items.iter().map(Self::of_object).collect()),
            Object::Code(code) => Self::Code(Box::new(CodeKey::of_unit(code))),
        }
    }

    fn of_constant(constant: &Constant) -> Self {
        match constant {
            Constant::None => Self::None,
            Constant::Ellipsis => Self::Ellipsis,
            Constant::Int(value) => Self::Int(*value),
            Constant::Long(value) => Self::Long(value.clone()),
            Constant::Float(value) => Self::Float(value.to_bits()),
            Constant::Complex { real, imag } => Self::Complex { real: real.to_bits(), imag: imag.to_bits() },
            Constant::Str { value, .. } => Self::Str(value.clone()),
            Constant::Unicode(units) => Self::Unicode(units.clone()),
            Constant::Tuple(items) => Self::Tuple(items.iter().map(Self::of_constant).collect()),
            Constant::Code(code) => Self::Code(Box::new(CodeKey::of_unit(code))),
        }
    }
}

/// The code object attributes that code object equality compares.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CodeKey {
    name: Vec<u8>,
    argcount: u32,
    nlocals: u32,
    flags: u32,
    firstlineno: i32,
    code: Vec<u8>,
    consts: Vec<ConstantKey>,
    names: Vec<Vec<u8>>,
    varnames: Vec<Vec<u8>>,
    freevars: Vec<Vec<u8>>,
    cellvars: Vec<Vec<u8>>,
}

impl CodeKey {
    fn of_unit(code: &CodeUnit) -> Self {
        Self {
            name: code.name.clone(),
            argcount: code.argcount,
            nlocals: code.nlocals,
            flags: code.flags,
            firstlineno: code.firstlineno,
            code: code.code.clone(),
            consts: code.consts.iter().map(ConstantKey::of_constant).collect(),
            names: code.names.clone(),
            varnames: code.varnames.clone(),
            freevars: code.freevars.clone(),
            cellvars: code.cellvars.clone(),
        }
    }
}

/// `co_consts` in order of first use, without duplicates.
#[derive(Default)]
pub(super) struct ConstantPool {
    objects: Vec<Object>,
    positions: HashMap<ConstantKey, i32>,
}

impl ConstantPool {
    /// The index of `object`, adding it if no equal constant is present.
    pub(super) fn index_of(&mut self, object: Object) -> i32 {
        let key = ConstantKey::of_object(&object);
        if let Some(&index) = self.positions.get(&key) {
            return index;
        }

        let index = self.objects.len() as i32;
        self.objects.push(object);
        self.positions.insert(key, index);

        index
    }

    pub(super) fn objects(&self) -> &[Object] {
        &self.objects
    }
}

/// One of the name tuples, in order of first use. Indices start at
/// `first_index`: free variables are numbered after the cell variables.
#[derive(Default)]
pub(super) struct NamePool {
    first_index: i32,
    names: Vec<Vec<u8>>,
    positions: HashMap<Vec<u8>, i32>,
}

impl NamePool {
    pub(super) fn starting_at(first_index: i32) -> Self {
        Self { first_index, names: Vec::new(), positions: HashMap::new() }
    }

    pub(super) fn position(&self, name: &[u8]) -> Option<i32> {
        self.positions.get(name).copied()
    }

    /// The index of `name`, adding it if absent.
    pub(super) fn index_of(&mut self, name: &[u8]) -> i32 {
        if let Some(index) = self.position(name) {
            return index;
        }

        let index = self.first_index + self.names.len() as i32;
        self.names.push(name.to_vec());
        self.positions.insert(name.to_vec(), index);

        index
    }

    pub(super) fn names(&self) -> &[Vec<u8>] {
        &self.names
    }

    pub(super) fn len(&self) -> usize {
        self.names.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl FromIterator<Vec<u8>> for NamePool {
    fn from_iter<I>(names: I) -> Self
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let mut pool = Self::default();
        for name in names {
            pool.index_of(&name);
        }

        pool
    }
}

/// Interns every `str` constant made only of ASCII letters, digits, and
/// underscores, including those inside tuples. Marshal then writes them
/// as interned strings.
pub(super) fn intern_identifier_like(consts: &[Object]) {
    let mut pending: Vec<&Object> = consts.iter().collect();

    while let Some(object) = pending.pop() {
        match object {
            Object::Str(string) if string.value.iter().all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_') => string.interned.set(true),
            Object::Tuple(items) => pending.extend(items.iter()),
            _ => {}
        }
    }
}
