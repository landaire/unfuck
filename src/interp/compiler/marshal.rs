//! Compiler output as the marshal writer sees it, for `marshal.dumps` of a
//! compiled code object (version 2).

use std::convert::Infallible;
use std::marker::PhantomData;

use crate::interp::compiler::unit::CodeUnit;
use crate::interp::compiler::unit::Constant;
use crate::interp::marshal::writer;
use crate::interp::marshal::writer::CodeShape;
use crate::interp::marshal::writer::Marshalled;
use crate::interp::marshal::writer::MarshalSource;
use crate::interp::marshal::writer::Shape;
use crate::interp::marshal::writer::WriteError;

/// `marshal.dumps(code)`. Fails only for constants nested deeper than the
/// writer allows, as CPython's does.
pub fn dump(code: &CodeUnit) -> Result<Vec<u8>, WriteError> {
    let Ok(marshalled) = writer::write(&UnitSource(PhantomData), Item::Code(code), 2);

    match marshalled {
        Marshalled::Written(bytes) => Ok(bytes),
        Marshalled::Failed { error, .. } => Err(error),
    }
}

/// An object of a compiled code object.
enum Item<'a> {
    Constant(&'a Constant),
    Code(&'a CodeUnit),
    Str { bytes: &'a [u8], interned: bool },
    /// A name tuple, whose strings code object creation interns.
    Names(&'a [Vec<u8>]),
    Consts(&'a [Constant]),
}

struct UnitSource<'a>(PhantomData<&'a CodeUnit>);

impl<'a> MarshalSource for UnitSource<'a> {
    type Object = Item<'a>;
    type Error = Infallible;

    fn shape<'o>(&self, item: &'o Item<'a>) -> Result<Shape<'o, Item<'a>>, Infallible> {
        Ok(shape_of(item))
    }
}

fn shape_of<'a>(item: &Item<'a>) -> Shape<'a, Item<'a>> {
    match *item {
        Item::Constant(constant) => constant_shape(constant),
        Item::Code(code) => code_shape(code),
        Item::Str { bytes, interned } => Shape::Str { bytes, interned },
        Item::Names(names) => Shape::Tuple(names.iter().map(|name| Item::Str { bytes: name, interned: true }).collect()),
        Item::Consts(consts) => Shape::Tuple(consts.iter().map(Item::Constant).collect()),
    }
}

fn constant_shape(constant: &Constant) -> Shape<'_, Item<'_>> {
    match constant {
        Constant::None => Shape::None,
        Constant::Ellipsis => Shape::Ellipsis,
        Constant::Int(value) => Shape::Int(*value),
        Constant::Long(value) => Shape::Long(value),
        Constant::Float(value) => Shape::Float(*value),
        Constant::Complex { real, imag } => Shape::Complex { real: *real, imag: *imag },
        Constant::Str { value, interned } => Shape::Str { bytes: value, interned: *interned },
        Constant::Unicode(units) => Shape::Unicode(units),
        Constant::Tuple(items) => Shape::Tuple(items.iter().map(Item::Constant).collect()),
        Constant::Code(code) => code_shape(code),
    }
}

fn code_shape(code: &CodeUnit) -> Shape<'_, Item<'_>> {
    Shape::Code(Box::new(CodeShape {
        argcount: code.argcount,
        nlocals: code.nlocals,
        stacksize: code.stacksize,
        flags: code.flags,
        code: Item::Str { bytes: &code.code, interned: false },
        consts: Item::Consts(&code.consts),
        names: Item::Names(&code.names),
        varnames: Item::Names(&code.varnames),
        freevars: Item::Names(&code.freevars),
        cellvars: Item::Names(&code.cellvars),
        // `co_filename` is a fresh string per code object, so only the
        // shared empty and one-byte strings are interned.
        filename: Item::Str { bytes: &code.filename, interned: code.filename.len() <= 1 },
        name: Item::Str { bytes: &code.name, interned: code.name_interned },
        firstlineno: code.firstlineno as u32,
        // An empty line number table is the interned empty string.
        lnotab: Item::Str { bytes: &code.lnotab, interned: code.lnotab.is_empty() },
    }))
}
