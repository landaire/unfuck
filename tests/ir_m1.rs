//! Milestone 1 of the raising IR: branch-free functions decompile to Python.
//!
//! These run as an integration test so they compile against unfuck's public API
//! only, independent of the crate's in-tree unit-test modules.

use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use py27_marshal::bstr::BString;
use py27_marshal::{Code, CodeFlags, Obj};

const LOAD_CONST: u8 = 100;
const LOAD_FAST: u8 = 124;
const STORE_FAST: u8 = 125;
const LOAD_ATTR: u8 = 106;
const CALL_FUNCTION: u8 = 131;
const BINARY_ADD: u8 = 23;
const BINARY_MULTIPLY: u8 = 20;
const RETURN_VALUE: u8 = 83;
const JUMP_FORWARD: u8 = 110;

fn bstr(text: &str) -> Arc<BString> {
    Arc::new(BString::from(text))
}

fn long(value: i64) -> Obj {
    Obj::Long(Arc::new(RwLock::new(BigInt::from(value))))
}

fn op(opcode: u8, arg: u16) -> Vec<u8> {
    vec![opcode, (arg & 0xff) as u8, (arg >> 8) as u8]
}

fn op0(opcode: u8) -> Vec<u8> {
    vec![opcode]
}

struct Builder {
    name: String,
    argcount: u32,
    varnames: Vec<Arc<BString>>,
    names: Vec<Arc<BString>>,
    consts: Vec<Obj>,
    code: Vec<u8>,
}

impl Builder {
    fn new(name: &str, argcount: u32, varnames: &[&str], names: &[&str], consts: Vec<Obj>) -> Builder {
        Builder {
            name: name.to_string(),
            argcount,
            varnames: varnames.iter().map(|v| bstr(v)).collect(),
            names: names.iter().map(|n| bstr(n)).collect(),
            consts,
            code: Vec::new(),
        }
    }

    fn emit(mut self, bytes: Vec<u8>) -> Builder {
        self.code.extend(bytes);
        self
    }

    fn finish(self) -> Arc<Code> {
        Arc::new(Code {
            argcount: self.argcount,
            nlocals: self.varnames.len() as u32,
            stacksize: 16,
            flags: CodeFlags::empty(),
            code: Arc::new(self.code),
            consts: Arc::new(self.consts),
            names: self.names,
            varnames: self.varnames,
            freevars: vec![],
            cellvars: vec![],
            filename: bstr("test"),
            name: bstr(&self.name),
            firstlineno: 1,
            lnotab: Arc::new(vec![]),
        })
    }
}

#[test]
fn arithmetic_return() {
    let code = Builder::new("add_one_two", 0, &[], &[], vec![Obj::None, long(1), long(2)])
        .emit(op(LOAD_CONST, 1))
        .emit(op(LOAD_CONST, 2))
        .emit(op0(BINARY_ADD))
        .emit(op0(RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def add_one_two():\n    return 1 + 2\n");
}

#[test]
fn precedence_parenthesises() {
    // (1 + 2) * 3
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, long(1), long(2), long(3)])
        .emit(op(LOAD_CONST, 1))
        .emit(op(LOAD_CONST, 2))
        .emit(op0(BINARY_ADD))
        .emit(op(LOAD_CONST, 3))
        .emit(op0(BINARY_MULTIPLY))
        .emit(op0(RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f():\n    return (1 + 2) * 3\n");
}

#[test]
fn attribute_call_assignment() {
    // def f(self): x = self.a.b(1, 2); return x
    let code = Builder::new("f", 1, &["self", "x"], &["a", "b"], vec![Obj::None, long(1), long(2)])
        .emit(op(LOAD_FAST, 0))
        .emit(op(LOAD_ATTR, 0))
        .emit(op(LOAD_ATTR, 1))
        .emit(op(LOAD_CONST, 1))
        .emit(op(LOAD_CONST, 2))
        .emit(op(CALL_FUNCTION, 2))
        .emit(op(STORE_FAST, 1))
        .emit(op(LOAD_FAST, 1))
        .emit(op0(RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f(self):\n    x = self.a.b(1, 2)\n    return x\n");
}

#[test]
fn control_flow_is_rejected() {
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None])
        .emit(op(JUMP_FORWARD, 0))
        .emit(op(LOAD_CONST, 0))
        .emit(op0(RETURN_VALUE))
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(
        result,
        Err(unfuck::ir::IrError::HasControlFlow(_))
    ));
}
