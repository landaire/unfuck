use num_bigint::BigInt;

use super::*;
use crate::interp::compiler::Mode;
use crate::interp::compiler::ast;
use crate::interp::hash::LongWidth;
use crate::interp::value::PyBytes;
use crate::interp::vm::ModuleCode;
use crate::interp::vm::ModuleSource;
use crate::interp::vm::VmConfig;

struct NoModules;

impl ModuleSource for NoModules {
    fn find(&self, _name: &str) -> Option<ModuleCode> {
        None
    }
}

fn vm(long_width: LongWidth) -> Vm {
    let mut config = VmConfig::windows_x64();
    config.long_width = long_width;

    match Vm::new(config, Box::new(NoModules)) {
        Ok(vm) => vm,
        Err(_) => panic!("interpreter bootstrap failed"),
    }
}

fn at(lineno: i32, col_offset: i32) -> ast::Location {
    ast::Location { lineno, col_offset }
}

fn expr(kind: ast::ExprKind) -> ast::Expr {
    ast::Expr { kind, location: at(1, 2) }
}

fn boxed(kind: ast::ExprKind) -> Box<ast::Expr> {
    Box::new(expr(kind))
}

fn stmt(kind: ast::StmtKind) -> ast::Stmt {
    ast::Stmt { kind, location: at(3, -1) }
}

fn name(text: &str) -> ast::Identifier {
    ast::Identifier(text.as_bytes().to_vec())
}

fn load(text: &str) -> ast::Expr {
    expr(ast::ExprKind::Name { id: name(text), ctx: ast::ExprContext::Load })
}

fn int(value: i64) -> ast::Expr {
    expr(ast::ExprKind::Num { n: ast::Number::Int(value) })
}

fn arguments() -> ast::Arguments {
    ast::Arguments { args: vec![expr(ast::ExprKind::Name { id: name("a"), ctx: ast::ExprContext::Param })], vararg: Some(name("rest")), kwarg: None, defaults: vec![int(1)] }
}

fn comprehension() -> ast::Comprehension {
    ast::Comprehension { target: expr(ast::ExprKind::Name { id: name("x"), ctx: ast::ExprContext::Store }), iter: load("xs"), ifs: vec![load("x")] }
}

/// A module using every node class, operator, and context.
fn every_node() -> ast::Mod {
    let expressions = vec![
        expr(ast::ExprKind::BoolOp { op: ast::BoolOp::And, values: vec![load("a"), load("b")] }),
        expr(ast::ExprKind::BoolOp { op: ast::BoolOp::Or, values: vec![load("a"), load("b")] }),
        expr(ast::ExprKind::UnaryOp { op: ast::UnaryOp::Invert, operand: Box::new(load("a")) }),
        expr(ast::ExprKind::UnaryOp { op: ast::UnaryOp::Not, operand: Box::new(load("a")) }),
        expr(ast::ExprKind::UnaryOp { op: ast::UnaryOp::UAdd, operand: Box::new(load("a")) }),
        expr(ast::ExprKind::UnaryOp { op: ast::UnaryOp::USub, operand: Box::new(load("a")) }),
        expr(ast::ExprKind::Lambda { args: Box::new(arguments()), body: Box::new(load("a")) }),
        expr(ast::ExprKind::IfExp { test: Box::new(load("a")), body: Box::new(load("b")), orelse: Box::new(load("c")) }),
        expr(ast::ExprKind::Dict { keys: vec![int(1)], values: vec![int(2)] }),
        expr(ast::ExprKind::Set { elts: vec![int(1)] }),
        expr(ast::ExprKind::ListComp { elt: Box::new(load("x")), generators: vec![comprehension()] }),
        expr(ast::ExprKind::SetComp { elt: Box::new(load("x")), generators: vec![comprehension()] }),
        expr(ast::ExprKind::DictComp { key: Box::new(load("x")), value: Box::new(load("x")), generators: vec![comprehension()] }),
        expr(ast::ExprKind::GeneratorExp { elt: Box::new(load("x")), generators: vec![comprehension()] }),
        expr(ast::ExprKind::Yield { value: None }),
        expr(ast::ExprKind::Yield { value: Some(Box::new(int(1))) }),
        expr(ast::ExprKind::Compare {
            left: Box::new(int(1)),
            ops: vec![ast::CmpOp::Eq, ast::CmpOp::NotEq, ast::CmpOp::Lt, ast::CmpOp::LtE, ast::CmpOp::Gt, ast::CmpOp::GtE, ast::CmpOp::Is, ast::CmpOp::IsNot, ast::CmpOp::In, ast::CmpOp::NotIn],
            comparators: (0..10).map(int).collect(),
        }),
        expr(ast::ExprKind::Call { func: Box::new(load("f")), args: vec![int(1)], keywords: vec![ast::Keyword { arg: name("k"), value: int(2) }], starargs: Some(Box::new(load("s"))), kwargs: Some(Box::new(load("kw"))) }),
        expr(ast::ExprKind::Repr { value: Box::new(load("a")) }),
        expr(ast::ExprKind::Num { n: ast::Number::Long(BigInt::from(7)) }),
        expr(ast::ExprKind::Num { n: ast::Number::Float(1.5) }),
        expr(ast::ExprKind::Str { s: ast::StrLiteral::Bytes { value: b"text".to_vec(), interned: false } }),
        expr(ast::ExprKind::Str { s: ast::StrLiteral::Bytes { value: b"t".to_vec(), interned: true } }),
        expr(ast::ExprKind::Str { s: ast::StrLiteral::Unicode(vec![0x41, 0xd83d, 0xde00]) }),
        expr(ast::ExprKind::Attribute { value: Box::new(load("a")), attr: name("b"), ctx: ast::ExprContext::AugLoad }),
        expr(ast::ExprKind::Subscript { value: Box::new(load("a")), slice: Box::new(ast::Slice::Ellipsis), ctx: ast::ExprContext::AugStore }),
        expr(ast::ExprKind::Subscript {
            value: Box::new(load("a")),
            slice: Box::new(ast::Slice::ExtSlice { dims: vec![ast::Slice::Slice { lower: Some(int(1)), upper: None, step: Some(int(2)) }, ast::Slice::Index { value: int(3) }] }),
            ctx: ast::ExprContext::Del,
        }),
        expr(ast::ExprKind::List { elts: vec![load("a")], ctx: ast::ExprContext::Load }),
        expr(ast::ExprKind::Tuple { elts: vec![], ctx: ast::ExprContext::Store }),
    ];
    let operators = [
        ast::Operator::Add,
        ast::Operator::Sub,
        ast::Operator::Mult,
        ast::Operator::Div,
        ast::Operator::Mod,
        ast::Operator::Pow,
        ast::Operator::LShift,
        ast::Operator::RShift,
        ast::Operator::BitOr,
        ast::Operator::BitXor,
        ast::Operator::BitAnd,
        ast::Operator::FloorDiv,
    ];

    let mut body: Vec<ast::Stmt> = expressions.into_iter().map(|value| stmt(ast::StmtKind::Expr { value })).collect();
    body.extend(operators.iter().map(|op| stmt(ast::StmtKind::AugAssign { target: load("a"), op: *op, value: expr(ast::ExprKind::BinOp { left: boxed(ast::ExprKind::Num { n: ast::Number::Int(1) }), op: *op, right: Box::new(int(2)) }) })));
    body.extend([
        stmt(ast::StmtKind::FunctionDef { name: name("f"), args: arguments(), body: vec![stmt(ast::StmtKind::Return { value: Some(int(1)) })], decorator_list: vec![load("d")] }),
        stmt(ast::StmtKind::ClassDef { name: name("C"), bases: vec![load("object")], body: vec![stmt(ast::StmtKind::Pass)], decorator_list: vec![] }),
        stmt(ast::StmtKind::Return { value: None }),
        stmt(ast::StmtKind::Delete { targets: vec![load("a")] }),
        stmt(ast::StmtKind::Assign { targets: vec![load("a")], value: int(1) }),
        stmt(ast::StmtKind::Print { dest: Some(load("out")), values: vec![int(1)], nl: false }),
        stmt(ast::StmtKind::For { target: load("i"), iter: load("xs"), body: vec![stmt(ast::StmtKind::Break)], orelse: vec![stmt(ast::StmtKind::Continue)] }),
        stmt(ast::StmtKind::While { test: load("a"), body: vec![stmt(ast::StmtKind::Pass)], orelse: vec![] }),
        stmt(ast::StmtKind::If { test: load("a"), body: vec![stmt(ast::StmtKind::Pass)], orelse: vec![stmt(ast::StmtKind::Pass)] }),
        stmt(ast::StmtKind::With { context_expr: load("m"), optional_vars: Some(load("v")), body: vec![stmt(ast::StmtKind::Pass)] }),
        stmt(ast::StmtKind::Raise { type_: Some(load("E")), inst: None, tback: Some(load("t")) }),
        stmt(ast::StmtKind::TryExcept {
            body: vec![stmt(ast::StmtKind::Pass)],
            handlers: vec![ast::ExceptHandler { type_: Some(load("E")), name: Some(load("e")), body: vec![stmt(ast::StmtKind::Pass)], location: at(9, 4) }],
            orelse: vec![],
        }),
        stmt(ast::StmtKind::TryFinally { body: vec![stmt(ast::StmtKind::Pass)], finalbody: vec![stmt(ast::StmtKind::Pass)] }),
        stmt(ast::StmtKind::Assert { test: load("a"), msg: None }),
        stmt(ast::StmtKind::Import { names: vec![ast::Alias { name: name("os"), asname: Some(name("o")) }] }),
        stmt(ast::StmtKind::ImportFrom { module: None, names: vec![ast::Alias { name: name("x"), asname: None }], level: Some(2) }),
        stmt(ast::StmtKind::Exec { body: load("code"), globals: Some(load("g")), locals: None }),
        stmt(ast::StmtKind::Global { names: vec![name("g"), name("h")] }),
    ]);

    ast::Mod::Module { body }
}

#[test]
fn every_node_round_trips() {
    let vm = vm(LongWidth::Bits32);
    let module = every_node();

    let object = ast_to_object(&vm, &module).unwrap_or_else(|_| panic!("ast_to_object failed"));
    let back = object_to_ast(&vm, &object, Mode::Exec).unwrap_or_else(|_| panic!("object_to_ast failed"));

    assert_eq!(back, module);
}

#[test]
fn modes_round_trip() {
    let vm = vm(LongWidth::Bits32);

    for (module, mode) in [
        (ast::Mod::Expression { body: Box::new(int(5)) }, Mode::Eval),
        (ast::Mod::Interactive { body: vec![stmt(ast::StmtKind::Pass)] }, Mode::Single),
    ] {
        let object = ast_to_object(&vm, &module).unwrap_or_else(|_| panic!("ast_to_object failed"));
        assert!(matches!(is_ast_node(&vm, &object), Ok(true)));
        let back = object_to_ast(&vm, &object, mode).unwrap_or_else(|_| panic!("object_to_ast failed"));
        assert_eq!(back, module);
    }

    assert!(matches!(is_ast_node(&vm, &Value::Int(1)), Ok(false)));
}

/// An `Int` beyond a 32-bit C long becomes a `long`, which converts back
/// as a `Long`.
#[test]
fn wide_int_becomes_long_on_win64() {
    let module = ast::Mod::Expression { body: Box::new(int(1 << 40)) };

    let narrow = vm(LongWidth::Bits32);
    let object = ast_to_object(&narrow, &module).unwrap_or_else(|_| panic!("ast_to_object failed"));
    let back = object_to_ast(&narrow, &object, Mode::Eval).unwrap_or_else(|_| panic!("object_to_ast failed"));
    assert_eq!(back, ast::Mod::Expression { body: Box::new(expr(ast::ExprKind::Num { n: ast::Number::Long(BigInt::from(1_i64 << 40)) })) });

    let wide = vm(LongWidth::Bits64);
    let object = ast_to_object(&wide, &module).unwrap_or_else(|_| panic!("ast_to_object failed"));
    let back = object_to_ast(&wide, &object, Mode::Eval).unwrap_or_else(|_| panic!("object_to_ast failed"));
    assert_eq!(back, module);
}

/// `x = y`, a docstring-like `'s'`, and a bare `print`, for tests that
/// alter the node objects before converting them back.
fn small_module() -> ast::Mod {
    ast::Mod::Module {
        body: vec![
            stmt(ast::StmtKind::Assign { targets: vec![expr(ast::ExprKind::Name { id: name("x"), ctx: ast::ExprContext::Store })], value: load("y") }),
            stmt(ast::StmtKind::Expr { value: expr(ast::ExprKind::Str { s: ast::StrLiteral::Bytes { value: b"s".to_vec(), interned: true } }) }),
            stmt(ast::StmtKind::Print { dest: None, values: vec![], nl: true }),
        ],
    }
}

fn attribute(vm: &Vm, target: &Value, path: &[&str]) -> PyResult<Value> {
    let mut value = target.clone();
    for step in path {
        value = match step.parse::<i64>() {
            Ok(index) => vm.getitem(&value, &Value::Int(index))?,
            Err(_) => vm.getattr_str(&value, step)?,
        };
    }

    Ok(value)
}

fn set(vm: &Vm, module: &Value, path: &[&str], name: &str, value: Value) -> PyResult<()> {
    vm.setattr_str(&attribute(vm, module, path)?, name, value)
}

fn delete(vm: &Vm, module: &Value, path: &[&str], name: &str) -> PyResult<()> {
    vm.delattr(&attribute(vm, module, path)?, &PyBytes::from(name))
}

/// A change made to the node objects of `small_module`.
type Alteration = fn(&Vm, &Value) -> PyResult<()>;

/// The outcome of converting `small_module` back after `alter` changes it.
fn convert_altered(long_width: LongWidth, mode: Mode, alter: Alteration) -> String {
    let vm = vm(long_width);
    let object = ast_to_object(&vm, &small_module()).unwrap_or_else(|_| panic!("ast_to_object failed"));
    alter(&vm, &object).unwrap_or_else(|_| panic!("altering the module failed"));

    match object_to_ast(&vm, &object, mode) {
        Ok(module) => format!("{module:?}"),
        Err(Signal::Raise(error)) => vm.describe_exception(&error),
        Err(Signal::Halt(halt)) => format!("halt: {halt}"),
    }
}

/// Messages and their order match `compile()` of the same altered tree in
/// CPython 2.7.18.
#[test]
fn conversion_errors_match_cpython() {
    let cases: [(Alteration, Mode, &str); 13] = [
        (|vm, module| delete(vm, module, &["body", "0"], "lineno"), Mode::Exec, "TypeError: required field \"lineno\" missing from stmt"),
        (|vm, module| set(vm, module, &[], "body", Value::Int(5)), Mode::Exec, "TypeError: Module field \"body\" must be a list, not a int"),
        (|vm, module| set(vm, module, &["body", "0"], "value", Value::None), Mode::Exec, "ValueError: field value is required for Assign"),
        (|vm, module| set(vm, module, &["body", "0", "value"], "ctx", Value::None), Mode::Exec, "TypeError: expected some sort of expr_context, but got None"),
        (|vm, module| set(vm, module, &["body", "0", "value"], "id", Value::Int(5)), Mode::Exec, "TypeError: AST identifier must be of type str"),
        (|vm, module| set(vm, module, &["body", "1", "value"], "s", Value::Int(5)), Mode::Exec, "TypeError: AST string must be of type str or unicode"),
        (|vm, module| set(vm, module, &["body", "0"], "lineno", Value::str("x")), Mode::Exec, "ValueError: invalid integer value: 'x'"),
        (|vm, module| set(vm, module, &["body", "2"], "nl", Value::Int(1)), Mode::Exec, "ValueError: invalid boolean value: 1"),
        (|_, _| Ok(()), Mode::Eval, "TypeError: expected Expression node, got Module"),
        (
            |vm, module| {
                delete(vm, module, &["body", "0"], "targets")?;
                delete(vm, module, &["body", "0"], "value")
            },
            Mode::Exec,
            "TypeError: required field \"targets\" missing from Assign",
        ),
        (|vm, module| set(vm, module, &["body", "0"], "value", Value::Int(5)), Mode::Exec, "TypeError: required field \"lineno\" missing from expr"),
        (|vm, module| set(vm, module, &["body", "0"], "targets", Value::Int(5)), Mode::Exec, "TypeError: Assign field \"targets\" must be a list, not a int"),
        (
            |vm, module| {
                set(vm, module, &["body", "0", "targets", "0"], "ctx", Value::Int(5))?;
                delete(vm, module, &["body", "0"], "value")
            },
            Mode::Exec,
            "TypeError: expected some sort of expr_context, but got 5",
        ),
    ];

    for (alter, mode, expected) in cases {
        assert_eq!(convert_altered(LongWidth::Bits32, mode, alter), expected);
    }
}

/// A C `long` conversion narrowed to `int`: a 32-bit C long rejects what
/// does not fit, a 64-bit one is truncated to an int.
#[test]
fn lineno_follows_c_long_width() {
    fn wide_lineno(vm: &Vm, module: &Value) -> PyResult<()> {
        set(vm, module, &["body", "2"], "lineno", Value::Long(Rc::new(BigInt::from((1_i64 << 33) + 7))))
    }

    assert_eq!(convert_altered(LongWidth::Bits32, Mode::Exec, wide_lineno), "OverflowError: Python int too large to convert to C long");
    assert!(convert_altered(LongWidth::Bits64, Mode::Exec, wide_lineno).contains("location: Location { lineno: 7, col_offset: -1 }"));
}

/// Values CPython accepts but the `ast` types cannot hold halt, unless a
/// Python error comes first.
#[test]
fn unrepresentable_values_halt() {
    let cases: [(Alteration, &str); 6] = [
        (|vm, module| vm.list_append(&attribute(vm, module, &["body"])?, Value::None), "halt: unsupported: None in the body list of _ast.Module"),
        (|vm, module| set(vm, module, &["body", "1", "value"], "s", Value::Bool(true)), "TypeError: AST string must be of type str or unicode"),
        (
            |vm, module| {
                let number = ast_to_object(vm, &ast::Mod::Expression { body: Box::new(int(1)) })?;
                let number = attribute(vm, &number, &["body"])?;
                vm.setattr_str(&number, "n", Value::Bool(true))?;
                set(vm, module, &["body", "1"], "value", number)
            },
            "halt: unsupported: Num node holding a 'bool' object",
        ),
        (
            |vm, module| {
                vm.list_append(&attribute(vm, module, &["body"])?, Value::None)?;
                set(vm, module, &["body", "0"], "value", Value::None)
            },
            "ValueError: field value is required for Assign",
        ),
        (
            |vm, module| {
                let import = ast_to_object(vm, &ast::Mod::Module { body: vec![stmt(ast::StmtKind::Import { names: vec![ast::Alias { name: name("os"), asname: None }] })] })?;
                let import = attribute(vm, &import, &["body", "0"])?;
                set(vm, &import, &["names", "0"], "name", Value::None)?;
                vm.list_append(&attribute(vm, module, &["body"])?, import)
            },
            "halt: unsupported: _ast.alias with name set to None",
        ),
        (
            |vm, module| {
                let import = ast_to_object(vm, &ast::Mod::Module { body: vec![stmt(ast::StmtKind::Import { names: vec![ast::Alias { name: name("os"), asname: None }] })] })?;
                let import = attribute(vm, &import, &["body", "0"])?;
                set(vm, &import, &["names", "0"], "name", Value::None)?;
                let body = attribute(vm, module, &["body"])?;
                vm.list_append(&body, import)?;
                vm.list_append(&body, Value::Int(5))
            },
            "TypeError: required field \"lineno\" missing from stmt",
        ),
    ];

    for (alter, expected) in cases {
        assert_eq!(convert_altered(LongWidth::Bits32, Mode::Exec, alter), expected);
    }
}

/// A left-nested `a+a+...+a` chain far deeper than the native stack could
/// hold with one frame per level. Derived equality recurses, so the check
/// walks the chain.
#[test]
fn deep_chain_round_trips() {
    const DEPTH: usize = 20_000;

    let vm = vm(LongWidth::Bits32);
    let mut chain = load("a");
    for _ in 0..DEPTH {
        chain = expr(ast::ExprKind::BinOp { left: Box::new(chain), op: ast::Operator::Add, right: Box::new(load("a")) });
    }
    let module = ast::Mod::Expression { body: Box::new(chain) };

    let object = ast_to_object(&vm, &module).unwrap_or_else(|_| panic!("ast_to_object failed"));
    let back = object_to_ast(&vm, &object, Mode::Eval).unwrap_or_else(|_| panic!("object_to_ast failed"));

    let ast::Mod::Expression { body } = &back else {
        panic!("not an Expression");
    };
    let mut node: &ast::Expr = body;
    let mut depth = 0;
    while let ast::ExprKind::BinOp { left, op: ast::Operator::Add, right } = &node.kind {
        assert_eq!(**right, load("a"));
        node = left;
        depth += 1;
    }
    assert_eq!(depth, DEPTH);
    assert_eq!(*node, load("a"));
}
