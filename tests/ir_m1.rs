//! Raising IR tests built from hand-written bytecode.
//!
//! Instructions are assembled through a small label-based builder so jump targets
//! are written as names, not hand-computed offsets: `finish` lays the program out
//! once to resolve each label, then emits, encoding absolute or relative operands
//! per opcode.
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

/// Jump opcodes whose operand is relative to the following instruction.
fn is_relative(opcode: Standard) -> bool {
    matches!(
        opcode,
        Standard::JUMP_FORWARD
            | Standard::FOR_ITER
            | Standard::SETUP_LOOP
            | Standard::SETUP_EXCEPT
            | Standard::SETUP_FINALLY
            | Standard::SETUP_WITH
    )
}

enum Item {
    Op(Standard),
    Arg(Standard, u16),
    Jump(Standard, &'static str),
    Label(&'static str),
}

impl Item {
    fn size(&self) -> u32 {
        match self {
            Item::Label(_) => 0,
            Item::Op(_) => 1,
            Item::Arg(..) | Item::Jump(..) => 3,
        }
    }
}

struct Builder {
    name: String,
    argcount: u32,
    varnames: Vec<Arc<BString>>,
    names: Vec<Arc<BString>>,
    consts: Vec<Obj>,
    items: Vec<Item>,
}

impl Builder {
    fn new(name: &str, argcount: u32, varnames: &[&str], names: &[&str], consts: Vec<Obj>) -> Builder {
        Builder {
            name: name.to_string(),
            argcount,
            varnames: varnames.iter().map(|v| bstr(v)).collect(),
            names: names.iter().map(|n| bstr(n)).collect(),
            consts,
            items: Vec::new(),
        }
    }

    fn op(mut self, opcode: Standard) -> Builder {
        self.items.push(Item::Op(opcode));
        self
    }

    fn arg(mut self, opcode: Standard, arg: u16) -> Builder {
        self.items.push(Item::Arg(opcode, arg));
        self
    }

    fn jump(mut self, opcode: Standard, label: &'static str) -> Builder {
        self.items.push(Item::Jump(opcode, label));
        self
    }

    fn label(mut self, name: &'static str) -> Builder {
        self.items.push(Item::Label(name));
        self
    }

    fn finish(self) -> Arc<Code> {
        // Pass 1: offset of every item and the position of each label.
        let mut labels = std::collections::HashMap::new();
        let mut offset = 0u32;
        for item in &self.items {
            if let Item::Label(name) = item {
                labels.insert(*name, offset);
            }
            offset += item.size();
        }

        // Pass 2: emit, resolving label references to absolute or relative operands.
        let mut code = Vec::new();
        for item in &self.items {
            let here = code.len() as u32;
            match item {
                Item::Label(_) => {}
                Item::Op(opcode) => code.push(*opcode as u8),
                Item::Arg(opcode, arg) => emit_arg(&mut code, *opcode, *arg),
                Item::Jump(opcode, label) => {
                    let target = labels[label];
                    let operand = if is_relative(*opcode) {
                        target - (here + 3)
                    } else {
                        target
                    };
                    emit_arg(&mut code, *opcode, operand as u16);
                }
            }
        }

        Arc::new(Code {
            argcount: self.argcount,
            nlocals: self.varnames.len() as u32,
            stacksize: 16,
            flags: CodeFlags::empty(),
            code: Arc::new(code),
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

fn emit_arg(code: &mut Vec<u8>, opcode: Standard, arg: u16) {
    code.push(opcode as u8);
    code.push((arg & 0xff) as u8);
    code.push((arg >> 8) as u8);
}

fn decompile(code: Arc<Code>) -> String {
    unfuck::ir::decompile_function(code).expect("decompile failed")
}

#[test]
fn arithmetic_return() {
    let code = Builder::new("add_one_two", 0, &[], &[], vec![Obj::None, long(1), long(2)])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .op(Standard::BINARY_ADD)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def add_one_two():\n    return 1 + 2\n");
}

#[test]
fn precedence_parenthesises() {
    // (1 + 2) * 3
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, long(1), long(2), long(3)])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .op(Standard::BINARY_ADD)
        .arg(Standard::LOAD_CONST, 3)
        .op(Standard::BINARY_MULTIPLY)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    return (1 + 2) * 3\n");
}

#[test]
fn attribute_call_assignment() {
    // def f(self): x = self.a.b(1, 2); return x
    let code = Builder::new("f", 1, &["self", "x"], &["a", "b"], vec![Obj::None, long(1), long(2)])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_ATTR, 0)
        .arg(Standard::LOAD_ATTR, 1)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::CALL_FUNCTION, 2)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(self):\n    x = self.a.b(1, 2)\n    return x\n");
}

#[test]
fn keyword_arguments() {
    // def f(): return g(1, x=2)
    let consts = vec![Obj::None, long(1), pystr("x"), long(2)];
    let code = Builder::new("f", 0, &[], &["g"], consts)
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::LOAD_CONST, 3)
        .arg(Standard::CALL_FUNCTION, 0x0101)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    return g(1, x=2)\n");
}

#[test]
fn raise_statement() {
    // def f(): raise Boom
    let code = Builder::new("f", 0, &[], &["Boom"], vec![Obj::None])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::RAISE_VARARGS, 1)
        .finish();

    assert_eq!(decompile(code), "def f():\n    raise Boom\n");
}

#[test]
fn simple_if() {
    // def f(x): if x: y = 1; return y
    let code = Builder::new("f", 1, &["x", "y"], &[], vec![Obj::None, long(1)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "after")
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::STORE_FAST, 1)
        .label("after")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(x):\n    if x:\n        y = 1\n    return y\n");
}

#[test]
fn if_else() {
    // def f(x): if x: y = 1 else: y = 2; return y
    let code = Builder::new("f", 1, &["x", "y"], &[], vec![Obj::None, long(1), long(2)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::STORE_FAST, 1)
        .jump(Standard::JUMP_FORWARD, "after")
        .label("else_")
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::STORE_FAST, 1)
        .label("after")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(x):\n    if x:\n        y = 1\n    else:\n        y = 2\n    return y\n"
    );
}

#[test]
fn while_loop() {
    // def f(n): while n: n = n; return n
    let code = Builder::new("f", 1, &["n"], &[], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "exit")
        .label("top")
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "pop")
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::STORE_FAST, 0)
        .jump(Standard::JUMP_ABSOLUTE, "top")
        .label("pop")
        .op(Standard::POP_BLOCK)
        .label("exit")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(n):\n    while n:\n        n = n\n    return n\n");
}

#[test]
fn tuple_assignment() {
    // def f(p): a, b = p; return a
    let code = Builder::new("f", 1, &["p", "a", "b"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(p):\n    a, b = p\n    return a\n");
}

#[test]
fn dict_literal() {
    // def f(): return {'k': 1}
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, long(1), pystr("k")])
        .arg(Standard::BUILD_MAP, 1)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .op(Standard::STORE_MAP)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    return {'k': 1}\n");
}

#[test]
fn short_circuit_and() {
    // def f(a, b): return a and b
    let code = Builder::new("f", 2, &["a", "b"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "end")
        .arg(Standard::LOAD_FAST, 1)
        .label("end")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b):\n    return a and b\n");
}

#[test]
fn short_circuit_chain() {
    // def f(a, b, c): return a and b and c
    let code = Builder::new("f", 3, &["a", "b", "c"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "end")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "end")
        .arg(Standard::LOAD_FAST, 2)
        .label("end")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b, c):\n    return a and b and c\n");
}

#[test]
fn ternary() {
    // def f(c, a, b): x = a if c else b; return x
    let code = Builder::new("f", 3, &["c", "a", "b", "x"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else_")
        .arg(Standard::LOAD_FAST, 2)
        .label("merge")
        .arg(Standard::STORE_FAST, 3)
        .arg(Standard::LOAD_FAST, 3)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(c, a, b):\n    x = a if c else b\n    return x\n");
}

#[test]
fn bare_except() {
    // def f(): try: g() except: h()
    let code = Builder::new("f", 0, &[], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("handler")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        g()\n    except:\n        h()\n    return None\n"
    );
}

#[test]
fn typed_except_as_name() {
    // def f(): try: x = g() except Exception as e: log(e)
    let code = Builder::new("f", 0, &["x", "e"], &["g", "Exception", "log"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .arg(Standard::STORE_FAST, 0)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .arg(Standard::STORE_FAST, 1)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("reraise")
        .op(Standard::END_FINALLY)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        x = g()\n    except Exception as e:\n        log(e)\n    return None\n"
    );
}

#[test]
fn multi_clause_except() {
    // def f(): try: x = g() except A: h1() except B as e: h2(e)
    let code = Builder::new("f", 0, &["x", "e"], &["g", "A", "h1", "B", "h2"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .arg(Standard::STORE_FAST, 0)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "clause2")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("clause2")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 3)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .arg(Standard::STORE_FAST, 1)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 4)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("reraise")
        .op(Standard::END_FINALLY)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        x = g()\n    except A:\n        h1()\n    \
         except B as e:\n        h2(e)\n    return None\n"
    );
}

#[test]
fn except_with_branch_in_handler() {
    // A handler body that itself branches must structure as a nested if.
    // def f(x): try: g() except: (if x: h())
    let code = Builder::new("f", 1, &["x"], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("handler")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "end")
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(x):\n    try:\n        g()\n    except:\n        if x:\n            h()\n    return None\n"
    );
}

#[test]
fn malformed_except_is_rejected() {
    // A SETUP_EXCEPT without the POP_BLOCK; JUMP_FORWARD body exit is not the
    // shape the recoverer accepts, so the function is rejected, not mis-emitted.
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "after")
        .arg(Standard::LOAD_CONST, 0)
        .label("after")
        .op(Standard::RETURN_VALUE)
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(result, Err(unfuck::ir::IrError::HasControlFlow(_))));
}
