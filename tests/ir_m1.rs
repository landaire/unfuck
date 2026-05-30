//! Raising IR tests: branch-free lowering (Milestone 1) and conditional
//! structuring (Milestone 2).
//!
//! These run as an integration test so they compile against unfuck's public API
//! only, independent of the crate's in-tree unit-test modules.

use std::sync::{Arc, RwLock};

use num_bigint::BigInt;
use py27_marshal::bstr::BString;
use py27_marshal::{Code, CodeFlags, Obj};
use pydis::opcode::py27::Standard;

fn bstr(text: &str) -> Arc<BString> {
    Arc::new(BString::from(text))
}

fn long(value: i64) -> Obj {
    Obj::Long(Arc::new(RwLock::new(BigInt::from(value))))
}

fn pystr(text: &str) -> Obj {
    Obj::String(Arc::new(RwLock::new(BString::from(text))))
}

fn op(opcode: Standard, arg: u16) -> Vec<u8> {
    vec![opcode as u8, (arg & 0xff) as u8, (arg >> 8) as u8]
}

fn op0(opcode: Standard) -> Vec<u8> {
    vec![opcode as u8]
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
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::LOAD_CONST, 2))
        .emit(op0(Standard::BINARY_ADD))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def add_one_two():\n    return 1 + 2\n");
}

#[test]
fn precedence_parenthesises() {
    // (1 + 2) * 3
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, long(1), long(2), long(3)])
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::LOAD_CONST, 2))
        .emit(op0(Standard::BINARY_ADD))
        .emit(op(Standard::LOAD_CONST, 3))
        .emit(op0(Standard::BINARY_MULTIPLY))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f():\n    return (1 + 2) * 3\n");
}

#[test]
fn attribute_call_assignment() {
    // def f(self): x = self.a.b(1, 2); return x
    let code = Builder::new("f", 1, &["self", "x"], &["a", "b"], vec![Obj::None, long(1), long(2)])
        .emit(op(Standard::LOAD_FAST, 0))
        .emit(op(Standard::LOAD_ATTR, 0))
        .emit(op(Standard::LOAD_ATTR, 1))
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::LOAD_CONST, 2))
        .emit(op(Standard::CALL_FUNCTION, 2))
        .emit(op(Standard::STORE_FAST, 1))
        .emit(op(Standard::LOAD_FAST, 1))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f(self):\n    x = self.a.b(1, 2)\n    return x\n");
}

#[test]
fn simple_if() {
    // def f(x): if x: y = 1; return y
    let code = Builder::new("f", 1, &["x", "y"], &[], vec![Obj::None, long(1)])
        .emit(op(Standard::LOAD_FAST, 0))
        .emit(op(Standard::POP_JUMP_IF_FALSE, 12))
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::STORE_FAST, 1))
        .emit(op(Standard::LOAD_FAST, 1))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f(x):\n    if x:\n        y = 1\n    return y\n");
}

#[test]
fn if_else() {
    // def f(x): if x: y = 1 else: y = 2; return y
    let code = Builder::new("f", 1, &["x", "y"], &[], vec![Obj::None, long(1), long(2)])
        .emit(op(Standard::LOAD_FAST, 0))
        .emit(op(Standard::POP_JUMP_IF_FALSE, 15))
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::STORE_FAST, 1))
        .emit(op(Standard::JUMP_FORWARD, 6))
        .emit(op(Standard::LOAD_CONST, 2))
        .emit(op(Standard::STORE_FAST, 1))
        .emit(op(Standard::LOAD_FAST, 1))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(
        source,
        "def f(x):\n    if x:\n        y = 1\n    else:\n        y = 2\n    return y\n"
    );
}

#[test]
fn keyword_arguments() {
    // def f(): return g(1, x=2)
    let consts = vec![Obj::None, long(1), pystr("x"), long(2)];
    let code = Builder::new("f", 0, &[], &["g"], consts)
        .emit(op(Standard::LOAD_GLOBAL, 0))
        .emit(op(Standard::LOAD_CONST, 1))
        .emit(op(Standard::LOAD_CONST, 2))
        .emit(op(Standard::LOAD_CONST, 3))
        .emit(op(Standard::CALL_FUNCTION, 0x0101))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f():\n    return g(1, x=2)\n");
}

#[test]
fn raise_statement() {
    // def f(): raise Boom
    let code = Builder::new("f", 0, &[], &["Boom"], vec![Obj::None])
        .emit(op(Standard::LOAD_GLOBAL, 0))
        .emit(op(Standard::RAISE_VARARGS, 1))
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f():\n    raise Boom\n");
}

#[test]
fn while_loop() {
    // def f(n): while n: n = n; return n   (n as a bare truth test, body reassigns)
    let code = Builder::new("f", 1, &["n"], &[], vec![Obj::None])
        .emit(op(Standard::SETUP_LOOP, 16)) // 0, exit -> 19
        .emit(op(Standard::LOAD_FAST, 0)) // 3 (header)
        .emit(op(Standard::POP_JUMP_IF_FALSE, 18)) // 6 -> POP_BLOCK
        .emit(op(Standard::LOAD_FAST, 0)) // 9 body
        .emit(op(Standard::STORE_FAST, 0)) // 12
        .emit(op(Standard::JUMP_ABSOLUTE, 3)) // 15 back edge
        .emit(op0(Standard::POP_BLOCK)) // 18
        .emit(op(Standard::LOAD_FAST, 0)) // 19
        .emit(op0(Standard::RETURN_VALUE)) // 22
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("decompile failed");
    assert_eq!(source, "def f(n):\n    while n:\n        n = n\n    return n\n");
}

#[test]
fn for_loops_are_rejected() {
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None])
        .emit(op(Standard::FOR_ITER, 4))
        .emit(op(Standard::LOAD_CONST, 0))
        .emit(op0(Standard::RETURN_VALUE))
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(result, Err(unfuck::ir::IrError::HasControlFlow(_))));
}
