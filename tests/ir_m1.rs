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
    flags: CodeFlags,
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
            flags: CodeFlags::empty(),
        }
    }

    fn flags(mut self, flags: CodeFlags) -> Builder {
        self.flags = flags;
        self
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
            flags: self.flags,
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
fn list_comp_multiple_for_clauses() {
    // def f(items, border): return [x for a, b in items for x in b if a < border]
    // A multi-`for` comprehension: nested FOR_ITERs, one LIST_APPEND, a filter that
    // jumps back to the inner loop top.
    let code = Builder::new("f", 2, &["items", "border", "a", "b", "x"], &[], vec![Obj::None])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop1")
        .jump(Standard::FOR_ITER, "exit1")
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::STORE_FAST, 3)
        .arg(Standard::LOAD_FAST, 3)
        .op(Standard::GET_ITER)
        .label("loop2")
        .jump(Standard::FOR_ITER, "exit2")
        .arg(Standard::STORE_FAST, 4)
        .arg(Standard::LOAD_FAST, 2)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::COMPARE_OP, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "loop2")
        .arg(Standard::LOAD_FAST, 4)
        .arg(Standard::LIST_APPEND, 3)
        .jump(Standard::JUMP_ABSOLUTE, "loop2")
        .label("exit2")
        .jump(Standard::JUMP_ABSOLUTE, "loop1")
        .label("exit1")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(items, border):\n    return [x for a, b in items for x in b if a < border]\n"
    );
}

#[test]
fn list_comp_nested_element() {
    // def g(rows): return [[f(x) for x in row] for row in rows]
    // A nested list comprehension: the outer comp's element is itself a comp, so
    // there are two BUILD_LIST 0 accumulators and two LIST_APPENDs. recognize_list_comp
    // must accept the outer (one own append, the inner append belonging to the nested
    // comp), and parse_list_comp must fold the inner BUILD_LIST region as the element.
    let code = Builder::new("g", 1, &["rows", "row", "x"], &["f"], vec![Obj::None])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop1")
        .jump(Standard::FOR_ITER, "exit1")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::GET_ITER)
        .label("loop2")
        .jump(Standard::FOR_ITER, "exit2")
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 2)
        .arg(Standard::CALL_FUNCTION, 1)
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "loop2")
        .label("exit2")
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "loop1")
        .label("exit1")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def g(rows):\n    return [[f(x) for x in row] for row in rows]\n"
    );
}

#[test]
fn list_comp_multi_for_with_empty_list_in_iterable() {
    // def f(rewards, picked): return [y for a in picked for y in rewards.get(a, [])]
    // A multi-`for` comprehension whose second iterable is `rewards.get(a, [])`. The
    // `[]` default arg is a BUILD_LIST 0 sitting just before the inner FOR_ITER, but it
    // is a list literal consumed by the call, not a nested accumulator: the inner loop
    // exits by jumping back to the outer loop top, not into a LIST_APPEND. The nested-
    // comp detection must not mistake it for an inner comprehension (which would steal
    // the single real append and reject the whole comprehension).
    let code = Builder::new("f", 2, &["rewards", "picked", "a", "y"], &["get"], vec![Obj::None])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::GET_ITER)
        .label("loop1")
        .jump(Standard::FOR_ITER, "exit1")
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_ATTR, 0)
        .arg(Standard::LOAD_FAST, 2)
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::CALL_FUNCTION, 2)
        .op(Standard::GET_ITER)
        .label("loop2")
        .jump(Standard::FOR_ITER, "exit2")
        .arg(Standard::STORE_FAST, 3)
        .arg(Standard::LOAD_FAST, 3)
        .arg(Standard::LIST_APPEND, 3)
        .jump(Standard::JUMP_ABSOLUTE, "loop2")
        .label("exit2")
        .jump(Standard::JUMP_ABSOLUTE, "loop1")
        .label("exit1")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(rewards, picked):\n    return [y for a in picked for y in rewards.get(a, [])]\n"
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
fn function_docstring_multiline_is_triple_quoted() {
    // A real function (CO_OPTIMIZED) with a multi-line docstring renders as a triple-
    // quoted literal with real newlines. When the def is nested into its class/module,
    // `emit_reindented` leaves the docstring's interior verbatim, so the literal's bytes
    // survive re-indentation (verified byte-exact against the corpus).
    let code = Builder::new("m", 1, &["self"], &[], vec![pystr("line1\nline2"), Obj::None])
        .flags(CodeFlags::OPTIMIZED)
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(code), "def m(self):\n    \"\"\"line1\nline2\"\"\"\n    return None\n");
}

#[test]
fn function_docstring_with_backslash_stays_escaped() {
    // A docstring carrying a literal backslash cannot be triple-quoted byte-exact (the
    // backslash would be a string escape), so it falls back to the single-quoted escaped
    // form.
    let code = Builder::new("m", 1, &["self"], &[], vec![pystr("a\\b\nc"), Obj::None])
        .flags(CodeFlags::OPTIMIZED)
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(code), "def m(self):\n    'a\\\\b\\nc'\n    return None\n");
}

#[test]
fn non_ascii_string_renders_readable_utf8() {
    // def f(): return 'Привет'  (a Python 2 byte string of UTF-8 Cyrillic)
    // The literal is emitted with its characters raw rather than \xNN-escaped; the
    // bytes round-trip exactly in a UTF-8 source file (decompile_module adds the
    // coding header).
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, pystr("Привет")])
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(code), "def f():\n    return 'Привет'\n");
}

#[test]
fn invalid_utf8_string_stays_hex_escaped() {
    // A byte string that is not valid UTF-8 keeps \xNN escapes so every byte is
    // preserved (it cannot be emitted raw without changing or losing bytes).
    let raw = Obj::String(Arc::new(RwLock::new(py27_marshal::bstr::BString::from(
        vec![0xf0u8, 0x28],
    ))));
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, raw])
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(code), "def f():\n    return '\\xf0('\n");
}

#[test]
fn decorated_class() {
    // @deco
    // class Foo(Base):
    //     x = 1
    // A decorated class compiles to deco(<build_class>) stored at the class name.
    // try_decorated_def peels the decorator call down to the BuildClass and emits the
    // `@deco` line plus the class.
    let body = Builder::new("Foo", 0, &[], &["__name__", "__module__", "x"], vec![Obj::None, long(1)])
        .arg(Standard::LOAD_NAME, 0)
        .arg(Standard::STORE_NAME, 1)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::STORE_NAME, 2)
        .op(Standard::LOAD_LOCALS)
        .op(Standard::RETURN_VALUE)
        .finish();
    let body_obj = Obj::Code(Arc::new(RwLock::new((*body).clone())));
    let code = Builder::new("f", 0, &[], &["deco", "Base", "Foo"], vec![Obj::None, pystr("Foo"), body_obj])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::BUILD_TUPLE, 1)
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::MAKE_FUNCTION, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::BUILD_CLASS)
        .arg(Standard::CALL_FUNCTION, 1)
        .arg(Standard::STORE_NAME, 2)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(out.contains("@deco\n"), "missing decorator:\n{}", out);
    assert!(out.contains("class Foo(Base):"), "missing class header:\n{}", out);
    assert!(out.contains("x = 1"), "missing class body:\n{}", out);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
}

#[test]
fn method_misnamed_as_comprehension_uses_store_name() {
    // The obfuscator renamed a real method's code object to `<dictcomp>`, but it has a
    // normal signature (`self`), not the comprehension `.0` argument, and is stored at
    // its real name `m`. It must emit as `def m(self):` (the store name), not be dropped
    // as an unrecoverable `<dictcomp>`.
    let method = Builder::new("<dictcomp>", 1, &["self"], &[], vec![Obj::None])
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();
    let method_obj = Obj::Code(Arc::new(RwLock::new((*method).clone())));
    let outer = Builder::new("f", 0, &[], &["m"], vec![Obj::None, method_obj])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::MAKE_FUNCTION, 0)
        .arg(Standard::STORE_NAME, 0)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(outer);
    assert!(out.contains("def m(self):"), "expected `def m(self):`, got:\n{}", out);
    assert!(!out.contains("__unrecovered__"), "should not be unrecovered:\n{}", out);
    assert!(!out.contains("dictcomp"), "co_name must not leak:\n{}", out);
}

#[test]
fn while_true_infinite_loop() {
    // def f(output):
    //     output.append(1)
    //     while True:
    //         output.append(2)
    // The loop header has no condition test -- only a JUMP_ABSOLUTE back edge to
    // itself -- so structure_loop's non-conditional arm emits `while True:`. The code
    // after the loop (the implicit `return None`) is unreachable and dropped.
    let code = Builder::new("f", 1, &["output"], &["append"], vec![Obj::None, long(1), long(2)])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_ATTR, 0)
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::SETUP_LOOP, "end")
        .label("loop")
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_ATTR, 0)
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(output):\n    output.append(1)\n\n    while True:\n        output.append(2)\n"
    );
}

#[test]
fn while_true_break_recovers() {
    // An optimized `while 1: break` whose loop header block IS the BREAK_LOOP (no
    // POP_BLOCK exit; the back edge is the instruction before the SETUP_LOOP follow).
    // The break lowers to a `Terminator::Break` carrying the SETUP_LOOP follow, so the
    // loop recovers as `while True: break` with the follow code preserved -- not the old
    // `while True: pass` that dropped the break.
    let code = Builder::new("f", 1, &["self"], &[], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "end")
        .label("loop")
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(self):\n    while True:\n        break\n\n    return None\n"
    );
}

#[test]
fn while_true_read_loop_with_test_header() {
    // def f(self):
    //     result = []
    //     while True:
    //         x = self.next()
    //         if x == 0:
    //             break
    //         result.append(x)
    //     return result
    // A relinearized read-loop: the `while 1:` header block carries a per-iteration
    // statement (`x = self.next()`) before its `== 0` test, and one test arm is a
    // BREAK_LOOP. The break's SETUP_LOOP follow defines the loop exit, so it lowers to
    // `Terminator::Break`; `structure_while_true_test` emits `while True:` with the
    // header statement and `if x == 0: break`, instead of a `while x == 0:` that would
    // drop both the per-iteration read and the break.
    let code = Builder::new("f", 1, &["self", "result", "x"], &["next", "append"], vec![
        Obj::None,
        long(0),
    ])
    .arg(Standard::BUILD_LIST, 0)
    .arg(Standard::STORE_FAST, 1)
    .jump(Standard::SETUP_LOOP, "end")
    .label("loop")
    .arg(Standard::LOAD_FAST, 0)
    .arg(Standard::LOAD_ATTR, 0)
    .arg(Standard::CALL_FUNCTION, 0)
    .arg(Standard::STORE_FAST, 2)
    .arg(Standard::LOAD_FAST, 2)
    .arg(Standard::LOAD_CONST, 1)
    .arg(Standard::COMPARE_OP, 2)
    .jump(Standard::POP_JUMP_IF_TRUE, "brk")
    .arg(Standard::LOAD_FAST, 1)
    .arg(Standard::LOAD_ATTR, 1)
    .arg(Standard::LOAD_FAST, 2)
    .arg(Standard::CALL_FUNCTION, 1)
    .op(Standard::POP_TOP)
    .jump(Standard::JUMP_ABSOLUTE, "loop")
    .label("brk")
    .op(Standard::BREAK_LOOP)
    .jump(Standard::JUMP_ABSOLUTE, "loop")
    .label("end")
    .arg(Standard::LOAD_FAST, 1)
    .op(Standard::RETURN_VALUE)
    .finish();

    assert_eq!(
        decompile(code),
        "def f(self):\n    result = []\n\n    while True:\n        x = self.next()\n\n        \
         if x == 0:\n            break\n\n        result.append(x)\n\n    return result\n"
    );
}

#[test]
fn for_loop_nested_tuple_target() {
    // def f(xs):
    //     for a, (b, c) in xs:
    //         g(b)
    // The loop target is a nested unpack (UNPACK_SEQUENCE 2; STORE a; UNPACK_SEQUENCE 2;
    // STORE b; STORE c), parsed recursively into LValue::Tuple[a, Tuple[b, c]].
    let code = Builder::new("f", 1, &["xs", "a", "b", "c"], &["g"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "end")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "exit")
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::STORE_FAST, 3)
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 2)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("exit")
        .op(Standard::POP_BLOCK)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs):\n    for a, (b, c) in xs:\n        g(b)\n\n    return None\n"
    );
}

#[test]
fn for_loop_body_always_returns_has_no_back_edge() {
    // def f(xs):
    //     for x in xs:
    //         return x
    // The loop body returns on the first iteration, so there is no JUMP back to the
    // FOR_ITER -- no back edge, so the dominator scan never registers it as a loop.
    // detect_loops must synthesize the loop straight from the FOR_ITER terminator,
    // otherwise the header reaches region() as a bare ForIter and is rejected with
    // "control-flow graph did not reduce to regions".
    let code = Builder::new("f", 1, &["xs", "x"], &[], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "end")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "exit")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .label("exit")
        .op(Standard::POP_BLOCK)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs):\n    for x in xs:\n        return x\n\n    return None\n"
    );
}

#[test]
fn cross_block_boolean_return() {
    // def f(a, b, c): return (a or b) and not c
    // The boolean is compiled to cross-block short-circuit control flow: a's
    // POP_JUMP_IF_TRUE and b's JUMP_IF_FALSE_OR_POP. recover_returned_bool folds it
    // back (as a faithful, gate-verified ternary translation).
    let code = Builder::new("f", 3, &["a", "b", "c"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_TRUE, "notc")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "ret")
        .label("notc")
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::UNARY_NOT)
        .label("ret")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(a, b, c):\n    return not c if a else b and not c\n"
    );
}

#[test]
fn statements_then_boolean_return() {
    // def f(a): y = a; return y or a
    // A leading straight-line statement (the assignment) precedes a cross-block
    // boolean return. recover_returned_bool peels the statement off and reconstructs
    // the returned boolean from the suffix.
    let code = Builder::new("f", 1, &["a", "y"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "ret")
        .arg(Standard::LOAD_FAST, 0)
        .label("ret")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a):\n    y = a\n    return y or a\n");
}

#[test]
fn list_comp_ternary_element() {
    // def f(xs): return [m if m else 0 for m in xs]
    // The element is a ternary, compiled as a diamond between FOR_ITER and
    // LIST_APPEND; parse_list_comp folds it through the shared ternary machinery.
    let code = Builder::new("f", 1, &["xs", "m"], &[], vec![Obj::None, long(0)])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "done")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_FORWARD, "app")
        .label("else_")
        .arg(Standard::LOAD_CONST, 1)
        .label("app")
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("done")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs):\n    return [m if m else 0 for m in xs]\n"
    );
}

#[test]
fn list_comp_or_filter() {
    // def f(xs, a, b): return [x for x in xs if a or b]
    // The filter is a short-circuit `or`: `a` keeps the element (jumps forward to the
    // element), `b` decides keep/skip. reconstruct_comp_filter folds it to one If.
    let code = Builder::new("f", 3, &["xs", "a", "b", "x"], &[], vec![Obj::None])
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "done")
        .arg(Standard::STORE_FAST, 3)
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::POP_JUMP_IF_TRUE, "keep")
        .arg(Standard::LOAD_FAST, 2)
        .jump(Standard::POP_JUMP_IF_FALSE, "loop")
        .label("keep")
        .arg(Standard::LOAD_FAST, 3)
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("done")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs, a, b):\n    return [x for x in xs if a or b]\n"
    );
}

#[test]
fn straightline_midexpression_boolean() {
    // def f(c, a): x = (a or 0) if c else 0; return x
    // The ternary's then-arm is `a or 0` whose `or` short-circuits to the merge, and
    // the else-arm shares that `0` -- a POP_JUMP split with no JUMP_FORWARD that the
    // block path cannot rejoin. The straight-line fallback folds it (verified) after
    // the normal path fails, then the assignment and return fold normally.
    let code = Builder::new("f", 2, &["c", "a", "x"], &[], vec![Obj::None, long(0)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "elseb")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "merge")
        .label("elseb")
        .arg(Standard::LOAD_CONST, 1)
        .label("merge")
        .arg(Standard::STORE_FAST, 2)
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, a):\n    x = a or 0 if c else 0\n    return x\n"
    );
}

#[test]
fn multi_return_boolean_as_if() {
    // def f(a, b, c): with each short-circuit branch returning directly (two
    // RETURN_VALUEs). The block path recovers this clean shape as an if-statement; the
    // straight-line fallback handles the messier multi-return booleans the block path
    // cannot (verified archive-wide, not reducible to a small synthetic here).
    let code = Builder::new("f", 3, &["a", "b", "c"], &[], vec![Obj::None, long(0)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "lfalse")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "lret")
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::RETURN_VALUE)
        .label("lfalse")
        .arg(Standard::LOAD_CONST, 1)
        .label("lret")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(a, b, c):\n    if a:\n        return b or c\n\n    return 0\n"
    );
}

#[test]
fn shared_else_boolean_in_statement() {
    // def f(c, d, a, b): if c: g((a or b) if d else b)
    // The call argument is a shared-else short-circuit (no JUMP_FORWARD); the block
    // path splits it and fails, so the post-failure rebuild keeps the region in one
    // block and folds it while the surrounding `if` structures normally.
    let code = Builder::new("f", 4, &["c", "d", "a", "b"], &["g"], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "end")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "elseb")
        .arg(Standard::LOAD_FAST, 2)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "callit")
        .label("elseb")
        .arg(Standard::LOAD_FAST, 3)
        .label("callit")
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, d, a, b):\n    if c:\n        g(a or b if d else b)\n\n    return None\n",
    );
}

#[test]
fn if_branch_returns_shared_else_boolean() {
    // def f(c, z, x, y): if c: return (x or y) if z else y; return 0
    // The if's POP_JUMP targets the merge (it is control flow, not a value), so the
    // region scanner must reject it -- otherwise it greedily swallows the if and the
    // genuine shared-else boolean nested in the branch never folds.
    let code = Builder::new("f", 4, &["c", "z", "x", "y"], &[], vec![Obj::None, long(0)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "ret0")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "elsey")
        .arg(Standard::LOAD_FAST, 2)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "branchret")
        .label("elsey")
        .arg(Standard::LOAD_FAST, 3)
        .label("branchret")
        .op(Standard::RETURN_VALUE)
        .label("ret0")
        .arg(Standard::LOAD_CONST, 1)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, z, x, y):\n    if c:\n        return x or y if z else y\n\n    return 0\n",
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
fn elif_chain_collapses() {
    // def f(a, b): if a: y = 1 elif b: y = 2 else: y = 3; return y
    // The compiler nests the elif as `else: if b: ...`; the emitter collapses each
    // single-`if` else body back into `elif` rather than deepening the indent.
    let code = Builder::new("f", 2, &["a", "b", "y"], &[], vec![Obj::None, long(1), long(2), long(3)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "elif")
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::STORE_FAST, 2)
        .jump(Standard::JUMP_FORWARD, "after")
        .label("elif")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_CONST, 2)
        .arg(Standard::STORE_FAST, 2)
        .jump(Standard::JUMP_FORWARD, "after")
        .label("else_")
        .arg(Standard::LOAD_CONST, 3)
        .arg(Standard::STORE_FAST, 2)
        .label("after")
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(a, b):\n    if a:\n        y = 1\n    elif b:\n        y = 2\n    else:\n        \
         y = 3\n\n    return y\n"
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
fn while_with_genuinely_empty_body() {
    // def f(c): while c: pass; return None
    // A genuine empty-body loop (busy-wait): the only body block is the back-edge, with
    // no statements. The lost-body guard must NOT reject this -- it fires only when a
    // non-header loop block carries real statements that the empty recovered body
    // dropped. Regression guard for that check over-firing on legitimate `while c: pass`.
    let code = Builder::new("f", 1, &["c"], &[], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "exit")
        .label("top")
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "pop")
        .jump(Standard::JUMP_ABSOLUTE, "top")
        .label("pop")
        .op(Standard::POP_BLOCK)
        .label("exit")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(c):\n    while c:\n        pass\n\n    return None\n");
}

#[test]
fn for_else_loop() {
    // def f(xs, y):
    //     for x in xs:
    //         if x == y: break
    //     else:
    //         y = 0
    //     return y
    // The else clause sits at the FOR_ITER exit; break skips past it to the follow.
    let code = Builder::new("f", 2, &["xs", "y", "x"], &[], vec![long(0)])
        .jump(Standard::SETUP_LOOP, "follow")
        .arg(Standard::LOAD_FAST, 0) // xs
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "forexit")
        .arg(Standard::STORE_FAST, 2) // x
        .arg(Standard::LOAD_FAST, 2) // x
        .arg(Standard::LOAD_FAST, 1) // y
        .arg(Standard::COMPARE_OP, 2) // ==
        .jump(Standard::POP_JUMP_IF_FALSE, "loop") // mismatch -> continue
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("forexit")
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0) // 0
        .arg(Standard::STORE_FAST, 1) // y = 0  (else)
        .label("follow")
        .arg(Standard::LOAD_FAST, 1) // y
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "for...else failed:\n{}", out);
    assert!(out.contains("for x in xs:"), "missing for header:\n{}", out);
    assert!(out.contains("if x == y:"), "missing if:\n{}", out);
    assert!(out.contains("        break"), "missing break:\n{}", out);
    assert!(out.contains("else:"), "missing else clause:\n{}", out);
    assert!(out.contains("y = 0"), "missing else body:\n{}", out);
}

#[test]
fn inner_break_loop_exit_trampolines_past_sibling() {
    // def f(items):
    //     for k, v in items:
    //         if c(k):
    //             for a in v:
    //                 if g(a):
    //                     break
    //         else:
    //             for b in v:
    //                 if g(b):
    //                     break
    //         use(k)
    //     return None
    // The if-branch inner loop's FOR_ITER exit is `POP_BLOCK; JUMP <conv>`, trampolining
    // to the shared convergence point past the else-branch's inner loop. break_targets'
    // `natural` (the instr before the SETUP_LOOP follow) lands on the else loop's
    // POP_BLOCK, not the if loop's exit, so the break is unrecognised and region() walks
    // out as a bare ForIter. The exit region [exit, follow) is not trivial (it holds the
    // else loop) so trivial_exit does not apply; exit_reaches_follow walks the exit's
    // actual POP_BLOCK/jump chain to the follow and resolves break there.
    // MissionsComponent.onVehicleDeath.
    let code = Builder::new("f", 1, &["items", "k", "v", "a", "b"], &["c", "g", "use"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "outer_follow")
        .arg(Standard::LOAD_FAST, 0) // items
        .op(Standard::GET_ITER)
        .label("outer")
        .jump(Standard::FOR_ITER, "outer_exit")
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 1) // k
        .arg(Standard::STORE_FAST, 2) // v
        .arg(Standard::LOAD_GLOBAL, 0) // c
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_") // if c(k):
        // if-branch inner loop over v, with break
        .jump(Standard::SETUP_LOOP, "if_loop_follow")
        .arg(Standard::LOAD_FAST, 2) // v
        .op(Standard::GET_ITER)
        .label("if_loop")
        .jump(Standard::FOR_ITER, "if_exit")
        .arg(Standard::STORE_FAST, 3) // a
        .arg(Standard::LOAD_GLOBAL, 1) // g
        .arg(Standard::LOAD_FAST, 3)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "if_loop")
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "if_loop")
        .label("if_exit")
        .op(Standard::POP_BLOCK)
        .label("if_loop_follow")
        .jump(Standard::JUMP_FORWARD, "use") // trampoline past the else loop to the merge
        .label("else_")
        // else-branch inner loop over v, with break
        .jump(Standard::SETUP_LOOP, "else_loop_follow")
        .arg(Standard::LOAD_FAST, 2) // v
        .op(Standard::GET_ITER)
        .label("else_loop")
        .jump(Standard::FOR_ITER, "else_exit")
        .arg(Standard::STORE_FAST, 4) // b
        .arg(Standard::LOAD_GLOBAL, 1) // g
        .arg(Standard::LOAD_FAST, 4)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_loop")
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "else_loop")
        .label("else_exit")
        .op(Standard::POP_BLOCK)
        .label("else_loop_follow")
        .label("use")
        .arg(Standard::LOAD_GLOBAL, 2) // use
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "outer") // continue outer
        .label("outer_exit")
        .op(Standard::POP_BLOCK)
        .label("outer_follow")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
    assert_eq!(out.matches("break").count(), 2, "both inner breaks should be recovered:\n{}", out);
    assert!(out.contains("else:"), "if/else should be recovered:\n{}", out);
    assert!(out.contains("use(k)"), "after-if code should follow the loops:\n{}", out);
}

#[test]
fn for_else_with_trampolined_setup_loop_follow() {
    // def f(xs):
    //     for x in xs:
    //         if g(x):
    //             break
    //     else:
    //         h()
    //     return None
    // The relinearizer makes the SETUP_LOOP follow a lone `JUMP_ABSOLUTE <conv>`
    // trampoline rather than the after-loop code, and the else clause (`h()`) sits
    // between the FOR_ITER exit and that trampoline, ending in a jump PAST the follow.
    // clean_else on the raw follow rejects it (the else jumps past), so the for...else
    // is missed and the break walks out as a bare ForIter. Threading the follow through
    // the trampoline to <conv> makes [exit, conv) the real else region; the threaded arm
    // requires it to hold a real statement (here `h()`) so a nested loop's trivial exit
    // cleanup is not mistaken for an else. CamerasKeyHandler.update.
    let code = Builder::new("f", 1, &["xs", "x"], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "setup_follow")
        .arg(Standard::LOAD_FAST, 0) // xs
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "for_exit")
        .arg(Standard::STORE_FAST, 1) // x
        .arg(Standard::LOAD_GLOBAL, 0) // g
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "loop") // if g(x): (false -> continue)
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop") // dead body back-edge
        .label("for_exit")
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_GLOBAL, 1) // h (else body: h())
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_FORWARD, "conv") // else jumps past the follow
        .label("setup_follow")
        .jump(Standard::JUMP_ABSOLUTE, "conv") // SETUP_LOOP follow is a trampoline
        .label("conv")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
    assert!(out.contains("for x in xs:"), "missing for header:\n{}", out);
    assert!(out.contains("        break"), "missing break:\n{}", out);
    assert!(out.contains("    else:"), "missing else clause:\n{}", out);
    assert!(out.contains("h()"), "missing else body h():\n{}", out);
}

#[test]
fn break_target_split_from_for_iter_exit() {
    // def f(xs):
    //     for x in xs:
    //         if g(x):
    //             h(x)
    //             break
    //     return None
    // The relinearizer splits the loop cleanup: the FOR_ITER exit is `POP_BLOCK;
    // JUMP conv` and the SETUP_LOOP follow is a separate `JUMP conv`, both converging
    // past the follow. break_targets' `natural` heuristic (the instr before the
    // SETUP_LOOP follow) then lands on the FOR_ITER exit's trailing JUMP, a different
    // block than the loop's structural follow (the POP_BLOCK), so the break edge is not
    // recognised and walks out of the loop -- duplicating the after-loop code into the
    // body or failing as "did not reduce". When the exit region is only cleanup
    // (POP_BLOCK + jumps, no else), resolve break to the FOR_ITER exit so it aligns with
    // the follow. WishesSystem.__getBestWishes, NavigationCommon, tarfile._proc_sparse.
    let code = Builder::new("f", 1, &["xs", "x"], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "setup_follow")
        .arg(Standard::LOAD_FAST, 0) // xs
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "for_exit")
        .arg(Standard::STORE_FAST, 1) // x
        .arg(Standard::LOAD_GLOBAL, 0) // g
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "loop") // if g(x): (false -> continue)
        .arg(Standard::LOAD_GLOBAL, 1) // h
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop") // dead body back-edge
        .label("for_exit")
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "conv") // FOR_ITER exit trampolines to conv
        .label("setup_follow")
        .jump(Standard::JUMP_FORWARD, "conv") // SETUP_LOOP follow trampolines to conv
        .label("conv")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs):\n    for x in xs:\n        if g(x):\n            h(x)\n            break\n\n    return None\n"
    );
}

#[test]
fn nested_loop_inner_if_breaks() {
    // def f(xs, ys):
    //     for x in xs:
    //         for y in ys:
    //             if g(y):
    //                 h(y)
    //                 break
    //     return None
    // The inner loop body is just `if g(y): h(y); break` -- both arms transfer control
    // (the then breaks, the false branch jumps back to the inner FOR_ITER = continue),
    // so nothing follows the `if` in the inner body. Its post-dominator is the inner
    // loop's follow, which flows straight into the OUTER loop header. region() used to
    // resume at that post-dominator, walk out of the inner body, and hit the outer
    // FOR_ITER as a bare block ("control-flow graph did not reduce"). Stopping the region
    // when both arms terminate recovers it (QuadTree.__createChildren, textwrap.dedent).
    let code = Builder::new("f", 2, &["xs", "ys", "x", "y"], &["g", "h"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "outer_end")
        .arg(Standard::LOAD_FAST, 0) // xs
        .op(Standard::GET_ITER)
        .label("outer_loop")
        .jump(Standard::FOR_ITER, "outer_exit")
        .arg(Standard::STORE_FAST, 2) // x
        .jump(Standard::SETUP_LOOP, "inner_end")
        .arg(Standard::LOAD_FAST, 1) // ys
        .op(Standard::GET_ITER)
        .label("inner_loop")
        .jump(Standard::FOR_ITER, "inner_exit")
        .arg(Standard::STORE_FAST, 3) // y
        .arg(Standard::LOAD_GLOBAL, 0) // g
        .arg(Standard::LOAD_FAST, 3)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "inner_loop") // if g(y): (false -> continue)
        .arg(Standard::LOAD_GLOBAL, 1) // h
        .arg(Standard::LOAD_FAST, 3)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .op(Standard::BREAK_LOOP)
        .jump(Standard::JUMP_ABSOLUTE, "inner_loop") // dead body back-edge
        .label("inner_exit")
        .op(Standard::POP_BLOCK)
        .label("inner_end")
        .jump(Standard::JUMP_ABSOLUTE, "outer_loop") // continue outer
        .label("outer_exit")
        .op(Standard::POP_BLOCK)
        .label("outer_end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(xs, ys):\n    for x in xs:\n        for y in ys:\n            if g(y):\n                h(y)\n                break\n\n    return None\n"
    );
}

#[test]
fn lambda_with_tuple_parameter() {
    // def f(): return lambda (a, b): a + b
    // A Python 2 tuple parameter compiles to a synthetic `.0` arg the body unpacks. A
    // lambda cannot hold the unpack as a statement, so it must render in the parameter
    // list (`lambda (a, b): ...`) with the unpack dropped from the body; previously the
    // leading unpack made body_as_expr reject the lambda as __unrecovered__.
    // PackItemInfo.create's ifilter predicate.
    let lam = Builder::new("<lambda>", 1, &[".0", "a", "b"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0) // .0 (the tuple arg)
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 1) // a
        .arg(Standard::STORE_FAST, 2) // b
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::BINARY_ADD)
        .op(Standard::RETURN_VALUE)
        .finish();
    let lam_obj = Obj::Code(Arc::new(RwLock::new((*lam).clone())));
    let code = Builder::new("f", 0, &[], &[], vec![Obj::None, lam_obj])
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::MAKE_FUNCTION, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    return lambda (a, b): a + b\n");
}

#[test]
fn complex_constant() {
    // def f(): return (2+3j)  /  def g(): return -0j
    // A complex constant rendered as `__unrecovered___const_Complex` because render_obj
    // had no Complex arm. Render it as the Python literal (matching CPython's repr) so it
    // round-trips: a pure imaginary as `<im>j`, otherwise `(<re>±<im>j)`. test_compile.
    use num_complex::Complex;
    let two_three = Builder::new("f", 0, &[], &[], vec![Obj::Complex(Complex::new(2.0, 3.0))])
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(two_three), "def f():\n    return (2+3j)\n");

    let neg_zero = Builder::new("g", 0, &[], &[], vec![Obj::Complex(Complex::new(0.0, -0.0))])
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();
    assert_eq!(decompile(neg_zero), "def g():\n    return -0j\n");
}

#[test]
fn extended_slice_subscript() {
    // def f(x): return x[:1, 2:3]
    // An extended slice: the index is a tuple of slices built with BUILD_SLICE, which
    // pushes an explicit None const for each missing bound. The slice must render `:1`
    // (not `None:1`), and the tuple index must drop its parentheses (`x[:1, 2:3]`, not
    // `x[(:1, 2:3)]` -- a slice inside a parenthesised tuple is a SyntaxError). test_class.
    let code = Builder::new("f", 1, &["x"], &[], vec![Obj::None, long(1), long(2), long(3)])
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_CONST, 0) // None (absent lower)
        .arg(Standard::LOAD_CONST, 1) // 1
        .arg(Standard::BUILD_SLICE, 2)
        .arg(Standard::LOAD_CONST, 2) // 2
        .arg(Standard::LOAD_CONST, 3) // 3
        .arg(Standard::BUILD_SLICE, 2)
        .arg(Standard::BUILD_TUPLE, 2)
        .op(Standard::BINARY_SUBSC)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(x):\n    return x[:1, 2:3]\n");
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
fn strips_opaque_predicate_with_out_of_range_jump() {
    // The obfuscator splices a dead predicate after real code: it unpacks its marker
    // tuple (5 ints ending in 255) into temps, grinds set arithmetic over them, compares,
    // and branches on a target PAST the end of the code -- a jump that can never be taken
    // (CPython would fault), so the whole self-contained predicate is dead injection. It
    // must be stripped, leaving just `x = 5` and the return.
    let tuple = Obj::Tuple(Arc::new(RwLock::new(vec![
        long(189),
        long(23),
        long(39),
        long(61),
        long(255),
    ])));
    let code = Builder::new("f", 0, &[], &["x", "a", "b", "c", "d", "e"], vec![Obj::None, long(5), tuple])
        .arg(Standard::LOAD_CONST, 1) // 5
        .arg(Standard::STORE_NAME, 0) // x = 5
        .arg(Standard::LOAD_CONST, 2) // marker tuple
        .arg(Standard::UNPACK_SEQUENCE, 5)
        .arg(Standard::STORE_NAME, 1) // a
        .arg(Standard::STORE_NAME, 2) // b
        .arg(Standard::STORE_NAME, 3) // c
        .arg(Standard::STORE_NAME, 4) // d
        .arg(Standard::STORE_NAME, 5) // e
        .arg(Standard::LOAD_NAME, 1)
        .arg(Standard::LOAD_NAME, 2)
        .arg(Standard::BUILD_SET, 2)
        .arg(Standard::LOAD_NAME, 3)
        .arg(Standard::LOAD_NAME, 4)
        .arg(Standard::BUILD_SET, 2)
        .arg(Standard::COMPARE_OP, 3) // !=
        .arg(Standard::POP_JUMP_IF_TRUE, 9999) // out-of-range: dead branch
        .arg(Standard::LOAD_CONST, 0) // None
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f():\n    x = 5\n    return None\n");
}

#[test]
fn ternary_arm_with_chained_comparison() {
    // def f(c, p, q, r): return 1 if c else 2 if p <= q < r else 3
    // The outer ternary's else arm holds a nested ternary whose condition is a chained
    // comparison (`p <= q < r`). That comparison short-circuits to its OWN cleanup
    // (ROT_TWO; POP_TOP), not the ternary merge, so pure_ternary_arm must treat the whole
    // chained-comparison machinery as a pure value rather than reject the arm.
    let code = Builder::new("f", 4, &["c", "p", "q", "r"], &[], vec![long(1), long(2), long(3)])
        .arg(Standard::LOAD_FAST, 0) // c
        .jump(Standard::POP_JUMP_IF_FALSE, "else_outer")
        .arg(Standard::LOAD_CONST, 0) // 1
        .jump(Standard::JUMP_FORWARD, "merge_outer")
        .label("else_outer")
        .arg(Standard::LOAD_FAST, 1) // p
        .arg(Standard::LOAD_FAST, 2) // q
        .op(Standard::DUP_TOP)
        .op(Standard::ROT_THREE)
        .arg(Standard::COMPARE_OP, 1) // <=
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "cleanup")
        .arg(Standard::LOAD_FAST, 3) // r
        .arg(Standard::COMPARE_OP, 0) // <
        .jump(Standard::JUMP_FORWARD, "merge_inner")
        .label("cleanup")
        .op(Standard::ROT_TWO)
        .op(Standard::POP_TOP)
        .label("merge_inner")
        .jump(Standard::POP_JUMP_IF_FALSE, "else_inner")
        .arg(Standard::LOAD_CONST, 1) // 2
        .jump(Standard::JUMP_FORWARD, "merge_outer")
        .label("else_inner")
        .arg(Standard::LOAD_CONST, 2) // 3
        .label("merge_outer")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, p, q, r):\n    return 1 if c else 2 if p <= q < r else 3\n"
    );
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
fn lambda_as_or_operand_is_parenthesised() {
    // def f(a): return a or (lambda: 0)
    // A lambda is the lowest-precedence Python expression (its `:` body runs to the
    // end), so as the right operand of `or` it must be parenthesised: without parens
    // `a or lambda: 0` is a SyntaxError. MakeFunction reported prec::ATOM, so the
    // lambda was never wrapped. Report it at TERNARY level so an or/and/binary operand
    // parenthesises while a top-level value does not. (lib2to3 parse.Parser.__init__:
    // `self.convert = convert or (lambda grammar, node: node)`.)
    let lam = Builder::new("<lambda>", 0, &[], &[], vec![long(0)])
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();
    let lam_obj = Obj::Code(Arc::new(RwLock::new((*lam).clone())));
    let code = Builder::new("f", 1, &["a"], &[], vec![Obj::None, lam_obj])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::JUMP_IF_TRUE_OR_POP, "end")
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::MAKE_FUNCTION, 0)
        .label("end")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(decompile(code), "def f(a):\n    return a or (lambda: 0)\n");
}

#[test]
fn shortcircuit_wrapping_ternary() {
    // def f(a, c, b, d): return a and (b if c else d)
    // The `a and` short-circuit (JUMP_IF_FALSE_OR_POP) opens BEFORE the ternary and
    // jumps to the ternary's own merge, so it wraps the whole ternary. The then-arm's
    // JUMP_FORWARD must not absorb it into `then` (which would yield the mis-parenthesised
    // `(a and b) if c else d`, a different program); it stays pending and resolves around
    // the ternary at the merge. Regression guard for FakeStatesController.__updateDunkerque.
    let code = Builder::new("f", 4, &["a", "c", "b", "d"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0) // a
        .jump(Standard::JUMP_IF_FALSE_OR_POP, "merge")
        .arg(Standard::LOAD_FAST, 1) // c (cond)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_FAST, 2) // b (then)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else_")
        .arg(Standard::LOAD_FAST, 3) // d (otherwise)
        .label("merge")
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(a, c, b, d):\n    return a and (b if c else d)\n"
    );
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
fn ternary_arm_with_make_function() {
    // x = (lambda: 1) if c else 0
    // The then-arm pushes a function value via MAKE_FUNCTION. Previously
    // is_statement_or_control flagged MAKE_* as a statement, so pure_ternary_arm
    // rejected the diamond and it structured as an `if` that drops the arm value off
    // the stack (symbolic stack underflow). A MAKE_FUNCTION inside a ternary arm is
    // always an expression (a lambda value, or the function half of an inlined
    // comprehension call), never a `def` -- a def stores the function, and that STORE
    // keeps the arm impure. This is the resetState shape `self.x = ({..} if c else {})`.
    let lam = Builder::new("<lambda>", 0, &[], &[], vec![long(1)])
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();
    let lam_obj = Obj::Code(Arc::new(RwLock::new((*lam).clone())));
    let code = Builder::new("f", 1, &["c", "x"], &[], vec![Obj::None, lam_obj, long(0)])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_CONST, 1)
        .arg(Standard::MAKE_FUNCTION, 0)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else_")
        .arg(Standard::LOAD_CONST, 2)
        .label("merge")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
    assert!(out.contains("if c else"), "should fold as a ternary:\n{}", out);
    assert!(out.contains("lambda"), "then-arm should be the lambda value:\n{}", out);
}

#[test]
fn jump_to_shared_return_with_orphan_dead_block() {
    // def f(c, a):
    //     if c: return a
    //     return None
    // The deob tail-duplicates the else return and orphans a dead `LOAD_CONST None`
    // block between the then arm's JUMP_FORWARD and the shared RETURN_VALUE merge
    // (mb20e87a8.getRestrictions). The then arm leaves `a` on the stack and jumps to a
    // lone RETURN_VALUE block; the per-block stack is cleared between blocks, so without
    // the return-jump lowering the RETURN_VALUE block underflows on an empty stack. The
    // orphan defeats find_reordered_ternaries (the merge is not the instruction right
    // after the then jump). Lowering the jump-to-lone-RETURN as `return a` recovers it.
    let code = Builder::new("f", 2, &["c", "a"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0)
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::LOAD_FAST, 1)
        .jump(Standard::JUMP_FORWARD, "merge")
        .arg(Standard::LOAD_CONST, 0) // orphan dead block: unreachable LOAD_CONST None
        .label("merge")
        .op(Standard::RETURN_VALUE)
        .label("else_")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
    assert!(out.contains("return a"), "then arm should return a:\n{}", out);
    assert!(out.contains("return None"), "else arm should return None:\n{}", out);
}

#[test]
fn ternary_arm_with_inline_list_comp() {
    // x = [a for a in xs] if c else []
    // The then-arm is an inline list comprehension (BUILD_LIST 0; FOR_ITER; STORE_FAST a;
    // LIST_APPEND). Its loop STORE_FAST made is_statement_or_control flag the arm impure,
    // so pure_ternary_arm rejected the diamond and it structured as an `if` that drops the
    // arm value -> underflow. The comprehension folds to one value, so its interior
    // (STORE/FOR_ITER/LIST_APPEND) must not count as arm statements. This is the
    // `str([x for x in xs]) if cond else ''` shape (Entity.toString).
    let code = Builder::new("f", 1, &["c", "xs", "a", "x"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0) // c
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::BUILD_LIST, 0)
        .arg(Standard::LOAD_FAST, 1) // xs
        .op(Standard::GET_ITER)
        .label("for_iter")
        .jump(Standard::FOR_ITER, "fend")
        .arg(Standard::STORE_FAST, 2) // a
        .arg(Standard::LOAD_FAST, 2) // a
        .arg(Standard::LIST_APPEND, 2)
        .jump(Standard::JUMP_ABSOLUTE, "for_iter")
        .label("fend")
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else_")
        .arg(Standard::BUILD_LIST, 0)
        .label("merge")
        .arg(Standard::STORE_FAST, 3) // x
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be fully recovered:\n{}", out);
    assert!(out.contains("if c else"), "should fold as a ternary:\n{}", out);
    assert!(out.contains("for a in xs"), "then arm should be the list comp:\n{}", out);
}

#[test]
fn chained_ternary() {
    // x = a if c1 else b if c2 else d
    // A chained ternary nests in the else arm; both diamonds share the merge. The
    // outer else arm holds the inner ternary's POP_JUMP/JUMP_FORWARD, which
    // is_statement_or_control flagged, so find_ternaries rejected the outer diamond.
    // pure_ternary_arm now accepts nested ternary jumps that converge on the merge, and
    // the unstacker keeps a stack of pending ternaries, resolving them innermost-first.
    let code = Builder::new("f", 5, &["c1", "c2", "a", "b", "d", "x"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0) // c1
        .jump(Standard::POP_JUMP_IF_FALSE, "e1")
        .arg(Standard::LOAD_FAST, 2) // a
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("e1")
        .arg(Standard::LOAD_FAST, 1) // c2
        .jump(Standard::POP_JUMP_IF_FALSE, "e2")
        .arg(Standard::LOAD_FAST, 3) // b
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("e2")
        .arg(Standard::LOAD_FAST, 4) // d
        .label("merge")
        .arg(Standard::STORE_FAST, 5) // x
        .arg(Standard::LOAD_FAST, 5) // x
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c1, c2, a, b, d):\n    x = a if c1 else b if c2 else d\n    return x\n"
    );
}

#[test]
fn ternary_arm_with_dict_display() {
    // x = {'kk': v} if c else {}
    // A dict-display arm builds the dict with BUILD_MAP + STORE_MAP. STORE_MAP starts
    // with STORE_, so is_statement_or_control flagged the arm impure and the diamond
    // mis-structured as an `if` -> underflow. STORE_MAP only ever builds a dict display
    // (no statement form), so pure_ternary_arm allows it. This is the
    // `{...} if cond else {...}` shape (ShipAcesComponent.getUpdateSprintComponentData).
    let code = Builder::new("f", 2, &["c", "v", "x"], &[], vec![Obj::None, pystr("kk")])
        .arg(Standard::LOAD_FAST, 0) // c
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::BUILD_MAP, 1)
        .arg(Standard::LOAD_FAST, 1) // v (value)
        .arg(Standard::LOAD_CONST, 1) // 'kk' (key)
        .op(Standard::STORE_MAP)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("else_")
        .arg(Standard::BUILD_MAP, 0)
        .label("merge")
        .arg(Standard::STORE_FAST, 2) // x
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, v):\n    x = {'kk': v} if c else {}\n    return x\n"
    );
}

#[test]
fn reordered_ternary_with_dict_display_else_arm() {
    // x = {} if c else {'kk': v}
    // A reordered ternary: the relinearizer lays the merge immediately after the then
    // arm's JUMP_FORWARD and puts the else arm *after* the merge, jumping backward to
    // it (so the merge does not dominate the else arm -- an irreducible CFG that
    // region() handles by following edges). find_reordered_ternaries feeds the else
    // value at the merge, but its pure_expression check rejected the else arm's
    // STORE_MAP (dict display), so the diamond was left as control flow and the merge's
    // STORE underflowed on the empty per-block stack. STORE_MAP only builds a dict
    // display, so it is a pure value op. This is the updateProperties shape
    // (ClientSettingsProxy): `unknown_66 = {} if .. else {VERSION: ..}`.
    let code = Builder::new("f", 2, &["c", "v", "x"], &[], vec![Obj::None, pystr("kk")])
        .arg(Standard::LOAD_FAST, 0) // c
        .jump(Standard::POP_JUMP_IF_FALSE, "else_")
        .arg(Standard::BUILD_MAP, 0) // then: {}
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("merge")
        .arg(Standard::STORE_FAST, 2) // x
        .arg(Standard::LOAD_FAST, 2)
        .op(Standard::RETURN_VALUE)
        .label("else_") // laid out after the merge, jumps back
        .arg(Standard::BUILD_MAP, 1)
        .arg(Standard::LOAD_FAST, 1) // v (value)
        .arg(Standard::LOAD_CONST, 1) // 'kk' (key)
        .op(Standard::STORE_MAP)
        .jump(Standard::JUMP_ABSOLUTE, "merge")
        .finish();

    assert_eq!(
        decompile(code),
        "def f(c, v):\n    x = {} if c else {'kk': v}\n    return x\n"
    );
}

#[test]
fn or_chain_if_with_empty_body_is_not_a_ternary() {
    // if c1 or c2: pass
    // return None
    // Each or-test is `POP_JUMP_IF_FALSE <next>; JUMP_FORWARD end` to the same end, with
    // an EMPTY then arm. This must NOT be mis-folded as a ternary (no then value -> would
    // underflow): find_ternaries rejects an empty then arm. Regression guard for the
    // chained-ternary relaxation (Avatar.onActionFailed).
    let code = Builder::new("f", 2, &["c1", "c2"], &[], vec![Obj::None])
        .arg(Standard::LOAD_FAST, 0) // c1
        .jump(Standard::POP_JUMP_IF_FALSE, "next")
        .jump(Standard::JUMP_FORWARD, "end")
        .label("next")
        .arg(Standard::LOAD_FAST, 1) // c2
        .jump(Standard::POP_JUMP_IF_FALSE, "end")
        .jump(Standard::JUMP_FORWARD, "end")
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    let out = decompile(code);
    assert!(!out.contains("__unrecovered__"), "should be recovered, not underflow:\n{}", out);
    assert!(out.contains("return None"), "should return None:\n{}", out);
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
fn loop_if_returns_then_fallthrough_continue() {
    // A loop body with two ifs: the first returns (so its post-dominator is the
    // function exit, making the rest of the body structure with stop == Exit), the
    // second's arms both reach the loop header directly. Control then reaches the
    // header by fall-through with stop != header, which must be recovered as a
    // `continue` of the loop rather than emitting the FOR_ITER header as a plain block.
    // def f(xs):
    //     for x in xs:
    //         if a(x): return x
    //         if b(x): c(x)
    let code = Builder::new("f", 1, &["xs", "x"], &["a", "b", "c"], vec![Obj::None])
        .jump(Standard::SETUP_LOOP, "end")
        .arg(Standard::LOAD_FAST, 0)
        .op(Standard::GET_ITER)
        .label("loop")
        .jump(Standard::FOR_ITER, "exit")
        .arg(Standard::STORE_FAST, 1)
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "if2")
        .arg(Standard::LOAD_FAST, 1)
        .op(Standard::RETURN_VALUE)
        .label("if2")
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .jump(Standard::POP_JUMP_IF_FALSE, "loop")
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::POP_TOP)
        .jump(Standard::JUMP_ABSOLUTE, "loop")
        .label("exit")
        .op(Standard::POP_BLOCK)
        .label("end")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    // The second `if`'s fall-through to the loop header is the redundant back-edge
    // continue, which is dropped (the body falls through to the next iteration anyway).
    assert_eq!(
        decompile(code),
        "def f(xs):\n    for x in xs:\n        if a(x):\n            return x\n\n        if b(x):\n            c(x)\n\n    return None\n"
    );
}

#[test]
fn mergeless_except_raising_handler_in_with_is_accepted() {
    // A merge-less try/except nested in a with: the body returns, so its POP_BLOCK is
    // gone, and the typed handler always raises. A raising handler never falls through,
    // so it cannot reach the with's cleanup -- the merge-less recovery is admitted even
    // though the object holds a SETUP_WITH. with cm(): try: return g() except E: raise h()
    let code = Builder::new("f", 0, &["e"], &["cm", "g", "E", "h"], vec![Obj::None])
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .jump(Standard::SETUP_WITH, "wcleanup")
        .op(Standard::POP_TOP)
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::RETURN_VALUE)
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .arg(Standard::STORE_FAST, 0)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 3)
        .arg(Standard::CALL_FUNCTION, 0)
        .arg(Standard::RAISE_VARARGS, 1)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("reraise")
        .op(Standard::END_FINALLY)
        .op(Standard::POP_BLOCK)
        .arg(Standard::LOAD_CONST, 0)
        .label("wcleanup")
        .op(Standard::WITH_CLEANUP)
        .op(Standard::END_FINALLY)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    with cm():\n        try:\n            return g()\n        except E as e:\n            raise h()\n\n    return None\n"
    );
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
fn try_with_returning_body() {
    // A try whose body is a `with` whose body returns. The with-body's return unwinds
    // through WITH_CLEANUP/END_FINALLY, so the with emits no POP_BLOCK; the try's own
    // POP_BLOCK still follows it. The block-stack scan must pop the unbalanced
    // SETUP_WITH when it reaches the WITH_CLEANUP target, so the following POP_BLOCK is
    // recognised as the try's own merge exit rather than consumed by the with -- which
    // would misclassify the try as merge-less and reject it.
    // def f(): try: with cm() as x: return g(x) except E: return None
    let code = Builder::new("f", 0, &["x"], &["cm", "g", "E"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .jump(Standard::SETUP_WITH, "cleanup")
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::CALL_FUNCTION, 1)
        .op(Standard::RETURN_VALUE)
        .label("cleanup")
        .op(Standard::WITH_CLEANUP)
        .op(Standard::END_FINALLY)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "merge")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .label("reraise")
        .op(Standard::END_FINALLY)
        .label("merge")
        .arg(Standard::LOAD_CONST, 0)
        .op(Standard::RETURN_VALUE)
        .finish();

    assert_eq!(
        decompile(code),
        "def f():\n    try:\n        with cm() as x:\n            return g(x)\n    except E:\n        return None\n\n    return None\n"
    );
}

#[test]
fn typed_except_tuple_target() {
    // A typed except whose `as` target is a tuple, the Python 2 socket idiom
    // `except socket.error, (errno, msg): ...`. The handler binds the exception by
    // UNPACK_SEQUENCE into two names. It must render in the comma form (the `as` form
    // with a tuple is a SyntaxError in 2.7).
    // def f(): try: g() except E, (a, b): h(a, b)
    let code = Builder::new("f", 0, &["a", "b"], &["g", "E", "h"], vec![Obj::None])
        .jump(Standard::SETUP_EXCEPT, "handler")
        .arg(Standard::LOAD_GLOBAL, 0)
        .arg(Standard::CALL_FUNCTION, 0)
        .op(Standard::POP_TOP)
        .op(Standard::POP_BLOCK)
        .jump(Standard::JUMP_FORWARD, "end")
        .label("handler")
        .op(Standard::DUP_TOP)
        .arg(Standard::LOAD_GLOBAL, 1)
        .arg(Standard::COMPARE_OP, 10)
        .jump(Standard::POP_JUMP_IF_FALSE, "reraise")
        .op(Standard::POP_TOP)
        .arg(Standard::UNPACK_SEQUENCE, 2)
        .arg(Standard::STORE_FAST, 0)
        .arg(Standard::STORE_FAST, 1)
        .op(Standard::POP_TOP)
        .arg(Standard::LOAD_GLOBAL, 2)
        .arg(Standard::LOAD_FAST, 0)
        .arg(Standard::LOAD_FAST, 1)
        .arg(Standard::CALL_FUNCTION, 2)
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
        "def f():\n    try:\n        g()\n    except E, (a, b):\n        h(a, b)\n\n    return None\n"
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
