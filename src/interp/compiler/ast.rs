//! The abstract syntax tree of CPython 2.7.12, one type per node class of
//! the `_ast` module. Names and field order follow `_ast` so the module
//! can expose nodes field for field.

use num_bigint::BigInt;

/// An identifier. Python 2 identifiers are ASCII `str` objects.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identifier(pub Vec<u8>);

/// Source position of a statement, expression, or exception handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub lineno: i32,
    /// `-1` for a token that starts on an earlier line than the tokenizer's
    /// current line, such as a string literal spanning lines.
    pub col_offset: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mod {
    Module { body: Vec<Stmt> },
    Interactive { body: Vec<Stmt> },
    Expression { body: Box<Expr> },
    Suite { body: Vec<Stmt> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub location: Location,
}

/// Trees can be far deeper than the native stack allows recursion: long
/// chains such as `a + b + c + ...` nest one level per operand. Dropping
/// detaches subtrees onto a worklist instead of recursing, so fields of a
/// node cannot be moved out of it by value.
impl Drop for Stmt {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.detach_children(&mut pending);
        drop_detached(pending);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StmtKind {
    FunctionDef { name: Identifier, args: Arguments, body: Vec<Stmt>, decorator_list: Vec<Expr> },
    ClassDef { name: Identifier, bases: Vec<Expr>, body: Vec<Stmt>, decorator_list: Vec<Expr> },
    Return { value: Option<Expr> },
    Delete { targets: Vec<Expr> },
    Assign { targets: Vec<Expr>, value: Expr },
    AugAssign { target: Expr, op: Operator, value: Expr },
    Print { dest: Option<Expr>, values: Vec<Expr>, nl: bool },
    For { target: Expr, iter: Expr, body: Vec<Stmt>, orelse: Vec<Stmt> },
    While { test: Expr, body: Vec<Stmt>, orelse: Vec<Stmt> },
    If { test: Expr, body: Vec<Stmt>, orelse: Vec<Stmt> },
    With { context_expr: Expr, optional_vars: Option<Expr>, body: Vec<Stmt> },
    Raise { type_: Option<Expr>, inst: Option<Expr>, tback: Option<Expr> },
    TryExcept { body: Vec<Stmt>, handlers: Vec<ExceptHandler>, orelse: Vec<Stmt> },
    TryFinally { body: Vec<Stmt>, finalbody: Vec<Stmt> },
    Assert { test: Expr, msg: Option<Expr> },
    Import { names: Vec<Alias> },
    ImportFrom { module: Option<Identifier>, names: Vec<Alias>, level: Option<u32> },
    Exec { body: Expr, globals: Option<Expr>, locals: Option<Expr> },
    Global { names: Vec<Identifier> },
    Expr { value: Expr },
    Pass,
    Break,
    Continue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub location: Location,
}

impl Expr {
    /// An expression owning nothing, left behind where a subtree is taken.
    pub fn placeholder() -> Self {
        Self { kind: ExprKind::Tuple { elts: Vec::new(), ctx: ExprContext::Load }, location: Location { lineno: 0, col_offset: 0 } }
    }
}

impl Drop for Expr {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.detach_children(&mut pending);
        drop_detached(pending);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    BoolOp { op: BoolOp, values: Vec<Expr> },
    BinOp { left: Box<Expr>, op: Operator, right: Box<Expr> },
    UnaryOp { op: UnaryOp, operand: Box<Expr> },
    Lambda { args: Box<Arguments>, body: Box<Expr> },
    IfExp { test: Box<Expr>, body: Box<Expr>, orelse: Box<Expr> },
    Dict { keys: Vec<Expr>, values: Vec<Expr> },
    Set { elts: Vec<Expr> },
    ListComp { elt: Box<Expr>, generators: Vec<Comprehension> },
    SetComp { elt: Box<Expr>, generators: Vec<Comprehension> },
    DictComp { key: Box<Expr>, value: Box<Expr>, generators: Vec<Comprehension> },
    GeneratorExp { elt: Box<Expr>, generators: Vec<Comprehension> },
    Yield { value: Option<Box<Expr>> },
    Compare { left: Box<Expr>, ops: Vec<CmpOp>, comparators: Vec<Expr> },
    Call { func: Box<Expr>, args: Vec<Expr>, keywords: Vec<Keyword>, starargs: Option<Box<Expr>>, kwargs: Option<Box<Expr>> },
    Repr { value: Box<Expr> },
    Num { n: Number },
    Str { s: StrLiteral },
    Attribute { value: Box<Expr>, attr: Identifier, ctx: ExprContext },
    Subscript { value: Box<Expr>, slice: Box<Slice>, ctx: ExprContext },
    Name { id: Identifier, ctx: ExprContext },
    List { elts: Vec<Expr>, ctx: ExprContext },
    Tuple { elts: Vec<Expr>, ctx: ExprContext },
}

/// The `object n` of a `Num` node: `int`, `long`, `float`, or `complex`.
#[derive(Clone, Debug, PartialEq)]
pub enum Number {
    Int(i64),
    Long(BigInt),
    Float(f64),
    /// A complex constant; an imaginary literal such as `2j` has a zero
    /// real part.
    Complex { real: f64, imag: f64 },
}

/// The `string s` of a `Str` node: a `str` or, with a `u` prefix or
/// `unicode_literals`, a `unicode` of UTF-16 code units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrLiteral {
    /// `interned`: the string literal object is interned, as every 0- and
    /// 1-byte string created from bytes is.
    Bytes { value: Vec<u8>, interned: bool },
    Unicode(Vec<u16>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExprContext {
    Load,
    Store,
    Del,
    AugLoad,
    AugStore,
    Param,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Slice {
    Ellipsis,
    Slice { lower: Option<Expr>, upper: Option<Expr>, step: Option<Expr> },
    ExtSlice { dims: Vec<Slice> },
    Index { value: Expr },
}

impl Drop for Slice {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        self.detach_children(&mut pending);
        drop_detached(pending);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoolOp {
    And,
    Or,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    Add,
    Sub,
    Mult,
    Div,
    Mod,
    Pow,
    LShift,
    RShift,
    BitOr,
    BitXor,
    BitAnd,
    FloorDiv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Invert,
    Not,
    UAdd,
    USub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    NotEq,
    Lt,
    LtE,
    Gt,
    GtE,
    Is,
    IsNot,
    In,
    NotIn,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Comprehension {
    pub target: Expr,
    pub iter: Expr,
    pub ifs: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExceptHandler {
    pub type_: Option<Expr>,
    pub name: Option<Expr>,
    pub body: Vec<Stmt>,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arguments {
    pub args: Vec<Expr>,
    pub vararg: Option<Identifier>,
    pub kwarg: Option<Identifier>,
    pub defaults: Vec<Expr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Keyword {
    pub arg: Identifier,
    pub value: Expr,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Alias {
    pub name: Identifier,
    pub asname: Option<Identifier>,
}

/// A subtree detached from a node being dropped.
enum Detached {
    Expr(Expr),
    Stmt(Stmt),
    Slice(Slice),
}

/// Drops detached subtrees, detaching each one's children before it is
/// dropped so that no drop recurses.
fn drop_detached(mut pending: Vec<Detached>) {
    while let Some(mut node) = pending.pop() {
        match &mut node {
            Detached::Expr(expr) => expr.detach_children(&mut pending),
            Detached::Stmt(stmt) => stmt.detach_children(&mut pending),
            Detached::Slice(slice) => slice.detach_children(&mut pending),
        }
    }
}

fn detach_expr(expr: &mut Expr, pending: &mut Vec<Detached>) {
    pending.push(Detached::Expr(std::mem::replace(expr, Expr::placeholder())));
}

fn detach_optional(expr: &mut Option<Expr>, pending: &mut Vec<Detached>) {
    if let Some(expr) = expr.take() {
        pending.push(Detached::Expr(expr));
    }
}

fn detach_optional_box(expr: &mut Option<Box<Expr>>, pending: &mut Vec<Detached>) {
    if let Some(expr) = expr.take() {
        pending.push(Detached::Expr(*expr));
    }
}

fn detach_exprs(exprs: &mut Vec<Expr>, pending: &mut Vec<Detached>) {
    pending.extend(exprs.drain(..).map(Detached::Expr));
}

fn detach_stmts(stmts: &mut Vec<Stmt>, pending: &mut Vec<Detached>) {
    pending.extend(stmts.drain(..).map(Detached::Stmt));
}

fn detach_arguments(arguments: &mut Arguments, pending: &mut Vec<Detached>) {
    detach_exprs(&mut arguments.args, pending);
    detach_exprs(&mut arguments.defaults, pending);
}

fn detach_comprehensions(generators: &mut Vec<Comprehension>, pending: &mut Vec<Detached>) {
    for mut generator in generators.drain(..) {
        detach_expr(&mut generator.target, pending);
        detach_expr(&mut generator.iter, pending);
        detach_exprs(&mut generator.ifs, pending);
    }
}

impl Expr {
    fn detach_children(&mut self, pending: &mut Vec<Detached>) {
        match &mut self.kind {
            ExprKind::BoolOp { values, .. } => detach_exprs(values, pending),
            ExprKind::BinOp { left, right, .. } => {
                detach_expr(left, pending);
                detach_expr(right, pending);
            }
            ExprKind::UnaryOp { operand, .. } => detach_expr(operand, pending),
            ExprKind::Lambda { args, body } => {
                detach_arguments(args, pending);
                detach_expr(body, pending);
            }
            ExprKind::IfExp { test, body, orelse } => {
                detach_expr(test, pending);
                detach_expr(body, pending);
                detach_expr(orelse, pending);
            }
            ExprKind::Dict { keys, values } => {
                detach_exprs(keys, pending);
                detach_exprs(values, pending);
            }
            ExprKind::Set { elts } | ExprKind::List { elts, .. } | ExprKind::Tuple { elts, .. } => detach_exprs(elts, pending),
            ExprKind::ListComp { elt, generators } | ExprKind::SetComp { elt, generators } | ExprKind::GeneratorExp { elt, generators } => {
                detach_expr(elt, pending);
                detach_comprehensions(generators, pending);
            }
            ExprKind::DictComp { key, value, generators } => {
                detach_expr(key, pending);
                detach_expr(value, pending);
                detach_comprehensions(generators, pending);
            }
            ExprKind::Yield { value } => detach_optional_box(value, pending),
            ExprKind::Compare { left, comparators, .. } => {
                detach_expr(left, pending);
                detach_exprs(comparators, pending);
            }
            ExprKind::Call { func, args, keywords, starargs, kwargs } => {
                detach_expr(func, pending);
                detach_exprs(args, pending);
                for mut keyword in keywords.drain(..) {
                    detach_expr(&mut keyword.value, pending);
                }
                detach_optional_box(starargs, pending);
                detach_optional_box(kwargs, pending);
            }
            ExprKind::Repr { value } | ExprKind::Attribute { value, .. } => detach_expr(value, pending),
            ExprKind::Subscript { value, slice, .. } => {
                detach_expr(value, pending);
                pending.push(Detached::Slice(std::mem::replace(&mut **slice, Slice::Ellipsis)));
            }
            ExprKind::Num { .. } | ExprKind::Str { .. } | ExprKind::Name { .. } => {}
        }
    }
}

impl Stmt {
    fn detach_children(&mut self, pending: &mut Vec<Detached>) {
        match &mut self.kind {
            StmtKind::FunctionDef { args, body, decorator_list, .. } => {
                detach_arguments(args, pending);
                detach_stmts(body, pending);
                detach_exprs(decorator_list, pending);
            }
            StmtKind::ClassDef { bases, body, decorator_list, .. } => {
                detach_exprs(bases, pending);
                detach_stmts(body, pending);
                detach_exprs(decorator_list, pending);
            }
            StmtKind::Return { value } => detach_optional(value, pending),
            StmtKind::Delete { targets } => detach_exprs(targets, pending),
            StmtKind::Assign { targets, value } => {
                detach_exprs(targets, pending);
                detach_expr(value, pending);
            }
            StmtKind::AugAssign { target, value, .. } => {
                detach_expr(target, pending);
                detach_expr(value, pending);
            }
            StmtKind::Print { dest, values, .. } => {
                detach_optional(dest, pending);
                detach_exprs(values, pending);
            }
            StmtKind::For { target, iter, body, orelse } => {
                detach_expr(target, pending);
                detach_expr(iter, pending);
                detach_stmts(body, pending);
                detach_stmts(orelse, pending);
            }
            StmtKind::While { test, body, orelse } | StmtKind::If { test, body, orelse } => {
                detach_expr(test, pending);
                detach_stmts(body, pending);
                detach_stmts(orelse, pending);
            }
            StmtKind::With { context_expr, optional_vars, body } => {
                detach_expr(context_expr, pending);
                detach_optional(optional_vars, pending);
                detach_stmts(body, pending);
            }
            StmtKind::Raise { type_, inst, tback } => {
                detach_optional(type_, pending);
                detach_optional(inst, pending);
                detach_optional(tback, pending);
            }
            StmtKind::TryExcept { body, handlers, orelse } => {
                detach_stmts(body, pending);
                for mut handler in handlers.drain(..) {
                    detach_optional(&mut handler.type_, pending);
                    detach_optional(&mut handler.name, pending);
                    detach_stmts(&mut handler.body, pending);
                }
                detach_stmts(orelse, pending);
            }
            StmtKind::TryFinally { body, finalbody } => {
                detach_stmts(body, pending);
                detach_stmts(finalbody, pending);
            }
            StmtKind::Assert { test, msg } => {
                detach_expr(test, pending);
                detach_optional(msg, pending);
            }
            StmtKind::Exec { body, globals, locals } => {
                detach_expr(body, pending);
                detach_optional(globals, pending);
                detach_optional(locals, pending);
            }
            StmtKind::Expr { value } => detach_expr(value, pending),
            StmtKind::Import { .. } | StmtKind::ImportFrom { .. } | StmtKind::Global { .. } | StmtKind::Pass | StmtKind::Break | StmtKind::Continue => {}
        }
    }
}

impl Slice {
    fn detach_children(&mut self, pending: &mut Vec<Detached>) {
        match self {
            Self::Ellipsis => {}
            Self::Slice { lower, upper, step } => {
                detach_optional(lower, pending);
                detach_optional(upper, pending);
                detach_optional(step, pending);
            }
            Self::ExtSlice { dims } => pending.extend(dims.drain(..).map(Detached::Slice)),
            Self::Index { value } => detach_expr(value, pending),
        }
    }
}
