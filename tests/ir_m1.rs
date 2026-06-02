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
fn relative_imports() {
    // from . import x; from ..bar import z, w
    // The IMPORT_NAME level operand (LOAD_CONST 1 / 2) supplies the leading dots;
    // the from-list const is popped and ignored.
    let consts = vec![Obj::None, long(1), long(2)];
    let code = Builder::new("f", 0, &[], &["", "x", "bar", "z", "w"], consts)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 0)
        .arg(Standard::IMPORT_NAME, 0)
        .arg(Standard::IMPORT_FROM, 1)
        .arg(Standard::STORE_NAME, 1)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::LOAD_CONST, 0)
        .arg(Standard::IMPORT_NAME, 2)
        .arg(Standard::IMPORT_FROM, 3)
        .arg(Standard::STORE_NAME, 3)
        .arg(Standard::IMPORT_FROM, 4)
        .arg(Standard::STORE_NAME, 4)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    from . import x\n    from ..bar import z, w\n    return None\n"
    );
}

#[test]
fn list_comp_negated_filter() {
    // def f(self): return [x for x in self._actions if not x.option_strings]
    // The compiler emits a negated filter as `<cond>; POP_JUMP_IF_TRUE loop_top`
    // (skip the element when the value is true), which folds to `if not <cond>`.
    let code = Builder::new("f", 1, &["self", "x"], &["_actions", "option_strings"], vec![Obj::None])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_ATTR, 0)
        .op(Standard::GET_ITER)
        .label("top")
        .jump(Standard::FOR_ITER, "exit")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::LOAD_ATTR, 1)
        .jump(Standard::POP_JUMP_IF_TRUE, "top")
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "top")
        .label("exit")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(self):\n    return [x for x in self._actions if not x.option_strings]\n"
    );
}

#[test]
fn int_literal_attribute_is_parenthesized() {
    // def f(): return (6).__index__()
    // A bare `6.__index__` would lex `6.` as a float, so the integer literal needs
    // parentheses as the attribute target.
    let code = Builder::new("f", 0, &[], &["__index__"], vec![Obj::None, long(6)])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_ATTR, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    return (6).__index__()\n");
}

#[test]
fn for_loop_try_except_continue() {
    // def f(xs):
    //     for x in xs:
    //         try: g(x)
    //         except OSError: pass
    // Both the try body and the handler exit by jumping to the FOR_ITER (continue),
    // so the try's merge is the loop header rather than post-try code, and the
    // handler's END_FINALLY (re-raise) sits after that merge. recover_try must drop
    // that END_FINALLY and its dead trailing back-jump; the redundant tail
    // `continue`s are then stripped.
    let code = Builder::new("f", 1, &["xs", "x"], &["g", "OSError"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "end")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "exit")
        .arg(Standard::STORE_FAST, 1)
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "endf")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("endf")
        .op(Standard::END_FINALLY)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("exit")
        .op(Standard::POP_BLOCK)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs):\n    for x in xs:\n        try:\n            g(x)\n        except OSError:\n            pass\n\n    return None\n"
    );
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

    assert_eq!(decompile(code), "def f(x):\n    if x:\n        y = 1\n\n    return y\n");
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
        "def f(x):\n    if x:\n        y = 1\n    else:\n        y = 2\n\n    return y\n"
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

    assert_eq!(decompile(code), "def f(n):\n    while n:\n        n = n\n\n    return n\n");
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
fn aug_assign_name() {
    // def f(x): x += 1; return x
    let code = Builder::new("f", 1, &["x"], &[], vec![Obj::None, long(1)])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::INPLACE_ADD)
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(x):\n    x += 1\n    return x\n");
}

#[test]
fn opaque_predicate_true_drops_dead_branch() {
    // if <const 7>: return a  else: return b  -- the predicate is always true, so
    // the dead `return b` is folded away.
    let code = Builder::new("f", 2, &["a", "b"], &[], vec![Obj::None, long(7)])
        .arg(Standard::LOAD_CONST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "dead")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .label("dead")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b):\n    return a\n");
}

#[test]
fn opaque_predicate_arithmetic_false_drops_branch() {
    // if 3 & 0: return a  else: return b  -- 3 & 0 == 0 is always false.
    let code = Builder::new("f", 2, &["a", "b"], &[], vec![Obj::None, long(3), long(0)])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 2)
        .op(Standard::BINARY_AND)
        .jump(Standard::POP_JUMP_IF_FALSE, "real")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .label("real")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b):\n    return b\n");
}

#[test]
fn opaque_predicate_constant_propagated_across_blocks() {
    // x = 0; <jump to a new block>; if x: return a else: return b
    // x is constant 0, propagated across the block boundary, so the branch folds.
    let code = Builder::new("f", 2, &["a", "b", "x"], &[], vec![Obj::None, long(0)])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::STORE_FAST, 2)
        .jump(Standard::JUMP_FORWARD, "test")
        .label("test")
        .arg(Standard::LOAD_FAST, 2)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .label("else_")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    // The dead branch is folded away; the (now-dead) store survives, as dead-store
    // elimination is a separate pass.
    assert_eq!(decompile(code), "def f(a, b):\n    x = 0\n    return b\n");
}

#[test]
fn opaque_predicate_prunes_unlowerable_junk() {
    // if <const 0>: <junk> else: return a  -- the predicate is always false, so the
    // junk branch (an unsupported ROT_TWO swap that poisons its block) is unreachable
    // and pruned rather than failing the whole function.
    let code = Builder::new("f", 2, &["a", "b"], &[], vec![Obj::None, long(0)])
        .arg(Standard::LOAD_CONST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "real")
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::ROT_TWO)
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .label("real")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b):\n    return a\n");
}

#[test]
fn swap_is_recovered() {
    // A ROT_TWO swap (`a, b = b, a`) is a two-element parallel assignment: the
    // compiler loads both values then rotates so the stores take them in order.
    // Recovered as one tuple assignment (never split into sequential stores, which
    // would mis-order an aliasing swap).
    let code = Builder::new("f", 2, &["a", "b"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::ROT_TWO)
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let source = unfuck::ir::decompile_function(code).expect("swap recovers");
    assert!(source.contains("a, b = (b, a)"), "got: {}", source);
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
fn ternary_shortcircuit_then() {
    // A ternary whose then-arm is a short-circuit value: the and/or operators
    // short-circuit to the ternary merge, so they must fold into the arm at the
    // closing JUMP_FORWARD rather than each block boundary capturing the tail.
    // def f(a, b, c, d): return (a or b) if c else d
    let code = Builder::new("f", 4, &["a", "b", "c", "d"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 2)
        .jump(Standard::POP_JUMP_IF_FALSE, "else")
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "merge")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else")
        .arg(Standard::LOAD_FAST, 3)
        .label("merge")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a, b, c, d):\n    return a or b if c else d\n");
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
        "def f():\n    try:\n        g()\n    except:\n        h()\n\n    return None\n"
    );
}

#[test]
fn try_except_body_falls_through_to_merge() {
    // The body's normal exit is `POP_BLOCK; JUMP merge`, but the deob drops the jump
    // when the merge is the next instruction: the body falls straight through
    // POP_BLOCK into the post-try code (here the `return None` epilogue).
    // def f(): try: g() except: raise
    let code = Builder::new("f", 0, &[], &["g"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("handler")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::RAISE_VARARGS, 0)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        g()\n    except:\n        raise\n\n    return None\n"
    );
}

#[test]
fn loop_typed_except_end_finally_past_merge() {
    // for x in items: try: g(x) except ValueError: pass
    // The body and handler both continue the loop through a shared merge (a
    // JUMP_ABSOLUTE back to FOR_ITER), and the relinearizer places the handler's
    // re-raise END_FINALLY *after* that merge -- where the merge-clamped scan would
    // miss it. recover_try must still exclude it (and its dead trailing jump).
    let code = Builder::new("f", 1, &["items", "x"], &["g", "ValueError"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "exit")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "loopexit")
        .arg(Standard::STORE_FAST, 1)
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "endf")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("merge")
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("endf")
        .op(Standard::END_FINALLY)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("loopexit")
        .op(Standard::POP_BLOCK)
        .label("exit")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(items):\n    for x in items:\n        try:\n            g(x)\n        \
         except ValueError:\n            pass\n\n    return None\n"
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
        "def f():\n    try:\n        x = g()\n    except Exception as e:\n        log(e)\n\n    return None\n"
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
         except B as e:\n        h2(e)\n\n    return None\n"
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
        "def f(x):\n    try:\n        g()\n    except:\n        if x:\n            h()\n\n    return None\n"
    );
}

#[test]
fn finally_body_for_loop_orphan_pop_block() {
    // try/finally whose body ends in a for loop. The deob dropped the loop's
    // SETUP_LOOP but kept its POP_BLOCK, leaving an orphan at depth 0 right before
    // the finally's own POP_BLOCK. recover_finally must skip the orphan.
    // def f(self): acquire(); try: (for x in self: g(x)) finally: release()
    let code = Builder::new("f", 1, &["self", "x"], &["acquire", "g", "release"], vec![Obj::None])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .jump(Standard::SETUP_FINALLY, "finally")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "loopexit")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("loopexit")
        .op(Standard::POP_BLOCK)
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0)
        .label("finally")
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(self):\n    acquire()\n\n    try:\n        for x in self:\n            g(x)\n    \
         finally:\n        release()\n\n    return None\n"
    );
}

#[test]
fn mergeless_finally() {
    // A try/finally whose body always returns: the deob drops the unreachable
    // normal-exit POP_BLOCK; LOAD_CONST None, leaving no body POP_BLOCK. The finally
    // body and merge derive from the SETUP_FINALLY target, not that POP_BLOCK, so the
    // construct still recovers. def f(): try: return g() finally: cleanup()
    let code = Builder::new("f", 0, &[], &["g", "cleanup"], vec![Obj::None])
        .jump(Standard::SETUP_FINALLY, "finally")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::RETURN_VALUE)
        .label("finally")
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        return g()\n    finally:\n        cleanup()\n\n    return None\n"
    );
}

#[test]
fn mergeless_except_in_finally_is_rejected() {
    // A merge-less try/except nested in a try/finally: the inner body returns, so its
    // POP_BLOCK is gone, and the bare handler falls through to the finally's cleanup.
    // Absorbing that cleanup into the handler would double it with the finally clause,
    // so the merge-less recovery is rejected when the object contains a finally/with.
    // try: (try: return g() except: pass) finally: cleanup()
    let code = Builder::new("f", 0, &[], &["g", "cleanup"], vec![Obj::None])
        .jump(Standard::SETUP_FINALLY, "finally")
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::RETURN_VALUE)
        .label("handler")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("merge")
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0)
        .label("finally")
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(result, Err(unfuck::ir::IrError::HasControlFlow(_))));
}

#[test]
fn with_binding_to_attribute() {
    // def f(self, cm): with cm as self.resource: g()
    // The `as` target is an attribute (STORE_ATTR), not a simple name; recover_with
    // lowers the object expression and builds an Attr lvalue.
    let code = Builder::new("f", 2, &["self", "cm"], &["resource", "g"], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::SETUP_WITH, "cleanup")
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::STORE_ATTR, 0)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0)
        .label("cleanup")
        .op(Standard::WITH_CLEANUP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(self, cm):\n    with cm as self.resource:\n        g()\n\n    return None\n"
    );
}

#[test]
fn mergeless_with() {
    // A with-body that always returns: the deob drops the unreachable normal-exit
    // POP_BLOCK; LOAD_CONST None, leaving no body POP_BLOCK. The WITH_CLEANUP runs
    // on every exit and the merge still follows it (it is reachable if __exit__
    // suppresses), so the construct keeps its merge. def f(): with cm() as x: return x
    let code = Builder::new("f", 0, &["x"], &["cm"], vec![Obj::None])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .jump(Standard::SETUP_WITH, "cleanup")
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::RETURN_VALUE)
        .label("cleanup")
        .op(Standard::WITH_CLEANUP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    with cm() as x:\n        return x\n\n    return None\n"
    );
}

#[test]
fn call_with_non_string_keyword_key_is_rejected() {
    // A keyword argument's key is always a string constant in valid CPython 2.7.
    // Corrupted/obfuscated residue can leave a non-string there; emitting it would be
    // invalid source (`g(**{2}=None)`), so the function is rejected rather than emitted.
    // def f(): return g(<2>=None)  (a non-string keyword key)
    let code = Builder::new("f", 0, &[], &["g"], vec![Obj::None, long(2)])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_CONST, 0)
        .arg(Standard::CALL_FUNCTION, 0x0100)
        .op(Standard::RETURN_VALUE)
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(result, Err(unfuck::ir::IrError::Incomplete)));
}

#[test]
fn malformed_except_is_rejected() {
    // A SETUP_EXCEPT whose handler offset is not a real handler dispatch (here a
    // bare RETURN_VALUE, neither the POP_TOP of a bare clause nor the DUP_TOP of a
    // typed one) is not a shape the recoverer accepts, so the function is rejected
    // rather than mis-emitted.
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "after")
        .arg(Standard::LOAD_CONST, 0)
        .label("after")
        .op(Standard::RETURN_VALUE)
        .finish();

    let result = unfuck::ir::decompile_function(code);
    assert!(matches!(result, Err(unfuck::ir::IrError::HasControlFlow(_))));
}

#[test]
fn mergeless_bare_except() {
    // When the try body always raises, the deob drops the dead `POP_BLOCK; JUMP
    // merge` body exit, leaving the function's implicit `return None` epilogue
    // unreachable after the RAISE. The construct then has no merge of its own; the
    // bare handler runs and returns. def f(): try: raise g() except: h(); return
    let code = Builder::new("f", 0, &[], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .arg(Standard::RAISE_VARARGS, 1)
        // Unreachable epilogue the relinearizer leaves after the raising body.
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("handler")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        raise g()\n    except:\n        h()\n        return None\n"
    );
}

#[test]
fn mergeless_typed_except() {
    // The merge-less shape with a typed clause: the unmatched path re-raises through
    // END_FINALLY (excluded), the matched handler binds the value and returns.
    // def f(): try: raise g() except Exception as e: log(e); return
    let code = Builder::new("f", 0, &["e"], &["g", "Exception", "log"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .arg(Standard::RAISE_VARARGS, 1)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .arg(Standard::STORE_FAST, 0)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("reraise")
        .op(Standard::END_FINALLY)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        raise g()\n    except Exception as e:\n        log(e)\n        return None\n"
    );
}
