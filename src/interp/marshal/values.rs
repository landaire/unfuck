//! Interpreter values as the marshal writer sees them.

use std::borrow::Cow;
use std::rc::Rc;

use crate::interp::buffer::BufferInterface;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::marshal::writer;
use crate::interp::marshal::writer::CodeShape;
use crate::interp::marshal::writer::Marshalled;
use crate::interp::marshal::writer::MarshalSource;
use crate::interp::marshal::writer::Shape;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Why writing stopped before producing bytes.
pub enum DumpStop {
    Signal(Signal),
    /// The value contains an unknown value, so the output is unknown.
    Unknown { origin: String },
}

impl From<Signal> for DumpStop {
    fn from(signal: Signal) -> Self {
        Self::Signal(signal)
    }
}

/// `marshal.dumps(value, version)`.
pub fn dumps(vm: &Vm, value: &Value, version: i64) -> Result<Marshalled, DumpStop> {
    writer::write(&VmSource { vm }, value.clone(), version)
}

struct VmSource<'a> {
    vm: &'a Vm,
}

impl MarshalSource for VmSource<'_> {
    type Object = Value;
    type Error = DumpStop;

    fn shape<'o>(&self, value: &'o Value) -> Result<Shape<'o, Value>, DumpStop> {
        let object = match value {
            Value::None => return Ok(Shape::None),
            Value::NotImplemented => return Ok(Shape::Unmarshallable),
            Value::Ellipsis => return Ok(Shape::Ellipsis),
            Value::Bool(false) => return Ok(Shape::False),
            Value::Bool(true) => return Ok(Shape::True),
            Value::Int(number) => return Ok(Shape::Int(*number)),
            Value::Long(number) => return Ok(Shape::Long(number)),
            Value::Float(number) => return Ok(Shape::Float(*number)),
            Value::Str(bytes) => return Ok(Shape::Str { bytes: bytes.as_bytes(), interned: bytes.is_interned() }),
            Value::Unicode(text) => return Ok(Shape::Unicode(text.units())),
            Value::Tuple(items) => return Ok(Shape::Tuple(items.to_vec())),
            Value::Unknown(unknown) => return Err(DumpStop::Unknown { origin: unknown.origin.clone() }),
            Value::Object(object) => object,
        };

        let vm = self.vm;
        let types = vm.types();
        if Rc::ptr_eq(object, types.exception(ExceptionKind::StopIteration)) {
            return Ok(Shape::StopIteration);
        }

        let class = object.class();
        let exact = |expected| Rc::ptr_eq(&class, expected);
        let shape = match &object.payload {
            Payload::Int(number) if exact(&types.int) => Shape::Int(*number),
            Payload::Long(number) if exact(&types.long) => Shape::Long(number),
            Payload::Float(number) if exact(&types.float) => Shape::Float(*number),
            Payload::Complex(number) if exact(&types.complex) => Shape::Complex { real: number.real, imag: number.imag },
            Payload::Str(bytes) if exact(&types.str) => Shape::Str { bytes: bytes.as_bytes(), interned: bytes.is_interned() },
            Payload::Unicode(text) if exact(&types.unicode) => Shape::Unicode(text.units()),
            Payload::Tuple(items) if exact(&types.tuple) => Shape::Tuple(items.to_vec()),
            Payload::List(items) if exact(&types.list) => Shape::List(items.borrow().clone()),
            Payload::Dict(_) if exact(&types.dict) => Shape::Dict(vm.dict_items(object)?),
            Payload::Set(_) if exact(&types.set) => Shape::Set(vm.set_items(value).unwrap_or_default()),
            Payload::FrozenSet(_) if exact(&types.frozenset) => Shape::FrozenSet(vm.set_items(value).unwrap_or_default()),
            Payload::Code(code) => {
                let names = |names: &[PyBytes]| Value::tuple(names.iter().cloned().map(Value::Str).collect());
                Shape::Code(Box::new(CodeShape {
                    argcount: code.argcount,
                    nlocals: code.nlocals,
                    stacksize: code.stacksize,
                    flags: code.flags.0,
                    code: Value::Str(PyBytes::new_unshared(code.code.clone())),
                    consts: Value::tuple(code.consts.clone()),
                    names: names(&code.names),
                    varnames: names(&code.varnames),
                    freevars: names(&code.freevars),
                    cellvars: names(&code.cellvars),
                    filename: Value::Str(code.filename.clone()),
                    name: Value::Str(code.name.clone()),
                    firstlineno: code.firstlineno,
                    lnotab: Value::Str(code.lnotab.clone()),
                }))
            }
            // A unicode object's read buffer is its UCS-2 storage.
            Payload::Unicode(text) => Shape::Buffer(Cow::Owned(text.units().iter().flat_map(|unit| unit.to_le_bytes()).collect())),
            _ if vm.buffer_slots(value).is_some_and(|slots| slots.read) => match vm.buffer(value, BufferInterface::Any)? {
                Some(bytes) => Shape::Buffer(Cow::Owned(bytes.as_bytes().to_vec())),
                None => Shape::Unmarshallable,
            },
            _ => Shape::Unmarshallable,
        };

        Ok(shape)
    }
}
