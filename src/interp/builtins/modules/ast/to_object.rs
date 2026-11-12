//! Conversion of the compiler's `ast` types to node objects. A task stack
//! stands in for recursion without growing the native stack: each node
//! object is allocated, then each field is converted and set in `_fields`
//! order, then the location, and the finished object goes to its parent.

use std::rc::Rc;

use crate::interp::builtins::modules::ast::AstTypes;
use crate::interp::builtins::modules::ast::NodeClass;
use crate::interp::builtins::modules::ast::ast_types;
use crate::interp::builtins::modules::ast::internal_error;
use crate::interp::builtins::modules::ast::new_node;
use crate::interp::compiler::ast;
use crate::interp::complex::Complex;
use crate::interp::error::PyResult;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// One step of the conversion. A node step leaves the node object on the
/// value stack once its fields are set.
enum Task<'a> {
    Mod(&'a ast::Mod),
    Stmt(&'a ast::Stmt),
    Expr(&'a ast::Expr),
    Slice(&'a ast::Slice),
    Comprehension(&'a ast::Comprehension),
    ExceptHandler(&'a ast::ExceptHandler),
    Arguments(&'a ast::Arguments),
    Keyword(&'a ast::Keyword),
    Alias(&'a ast::Alias),
    /// A value that needs no conversion.
    Push(Value),
    /// Collects the top `count` values into a list.
    List(usize),
    /// Pops a value into an attribute of a node.
    Set(Value, &'static str),
}

struct Writer<'a, 'v> {
    vm: &'v Vm,
    types: &'v AstTypes,
    tasks: Vec<Task<'a>>,
    values: Vec<Value>,
}

impl<'a> Writer<'a, '_> {
    fn run(&mut self) -> PyResult<()> {
        while let Some(task) = self.tasks.pop() {
            match task {
                Task::Mod(module) => {
                    let (class, fields) = match module {
                        ast::Mod::Module { body } => (NodeClass::Module, vec![sequence(body, Task::Stmt)]),
                        ast::Mod::Interactive { body } => (NodeClass::Interactive, vec![sequence(body, Task::Stmt)]),
                        ast::Mod::Expression { body } => (NodeClass::Expression, vec![vec![Task::Expr(body)]]),
                        ast::Mod::Suite { body } => (NodeClass::Suite, vec![sequence(body, Task::Stmt)]),
                    };
                    self.begin(class, fields, None);
                }
                Task::Stmt(stmt) => {
                    let fields = self.stmt_fields(&stmt.kind)?;
                    self.begin(stmt_class(&stmt.kind), fields, Some(stmt.location));
                }
                Task::Expr(expr) => {
                    let fields = self.expr_fields(&expr.kind)?;
                    self.begin(expr_class(&expr.kind), fields, Some(expr.location));
                }
                Task::Slice(slice) => {
                    let fields = match slice {
                        ast::Slice::Ellipsis => Vec::new(),
                        ast::Slice::Slice { lower, upper, step } => vec![optional_expr(lower.as_ref()), optional_expr(upper.as_ref()), optional_expr(step.as_ref())],
                        ast::Slice::ExtSlice { dims } => vec![sequence(dims, Task::Slice)],
                        ast::Slice::Index { value } => vec![vec![Task::Expr(value)]],
                    };
                    self.begin(slice_class(slice), fields, None);
                }
                Task::Comprehension(comprehension) => {
                    let fields = vec![vec![Task::Expr(&comprehension.target)], vec![Task::Expr(&comprehension.iter)], sequence(&comprehension.ifs, Task::Expr)];
                    self.begin(NodeClass::Comprehension, fields, None);
                }
                Task::ExceptHandler(handler) => {
                    let fields = vec![optional_expr(handler.type_.as_ref()), optional_expr(handler.name.as_ref()), sequence(&handler.body, Task::Stmt)];
                    self.begin(NodeClass::ExceptHandler, fields, Some(handler.location));
                }
                Task::Arguments(arguments) => {
                    let fields = vec![sequence(&arguments.args, Task::Expr), push(optional_identifier(arguments.vararg.as_ref())), push(optional_identifier(arguments.kwarg.as_ref())), sequence(&arguments.defaults, Task::Expr)];
                    self.begin(NodeClass::Arguments, fields, None);
                }
                Task::Keyword(keyword) => {
                    let fields = vec![push(identifier(&keyword.arg)), vec![Task::Expr(&keyword.value)]];
                    self.begin(NodeClass::Keyword, fields, None);
                }
                Task::Alias(alias) => {
                    let fields = vec![push(identifier(&alias.name)), push(optional_identifier(alias.asname.as_ref()))];
                    self.begin(NodeClass::Alias, fields, None);
                }
                Task::Push(value) => self.values.push(value),
                Task::List(count) => {
                    let Some(start) = self.values.len().checked_sub(count) else {
                        return Err(internal_error(self.vm, "list of more values than were converted"));
                    };
                    let items = self.values.split_off(start);
                    self.values.push(self.vm.new_list(items));
                }
                Task::Set(node, name) => {
                    let Some(value) = self.values.pop() else {
                        return Err(internal_error(self.vm, "field set before its value was converted"));
                    };
                    self.vm.setattr_str(&node, name, value)?;
                }
            }
        }

        Ok(())
    }

    /// Allocation of the node's class, then each field's tasks followed by
    /// setting the attribute, then the location.
    fn begin(&mut self, class: NodeClass, fields: Vec<Vec<Task<'a>>>, location: Option<ast::Location>) {
        let node = new_node(self.vm, self.types.class(class));

        let mut plan = Vec::new();
        for (field, tasks) in class.spec().fields.iter().zip(fields) {
            plan.extend(tasks);
            plan.push(Task::Set(node.clone(), field.name));
        }
        if let Some(location) = location {
            plan.push(Task::Push(Value::Int(i64::from(location.lineno))));
            plan.push(Task::Set(node.clone(), "lineno"));
            plan.push(Task::Push(Value::Int(i64::from(location.col_offset))));
            plan.push(Task::Set(node.clone(), "col_offset"));
        }
        plan.push(Task::Push(node));

        self.tasks.extend(plan.into_iter().rev());
    }

    fn singleton(&self, class: NodeClass) -> PyResult<Vec<Task<'a>>> {
        Ok(push(self.types.singleton(self.vm, class)?))
    }

    fn stmt_fields(&self, kind: &'a ast::StmtKind) -> PyResult<Vec<Vec<Task<'a>>>> {
        let fields = match kind {
            ast::StmtKind::FunctionDef { name, args, body, decorator_list } => vec![push(identifier(name)), vec![Task::Arguments(args)], sequence(body, Task::Stmt), sequence(decorator_list, Task::Expr)],
            ast::StmtKind::ClassDef { name, bases, body, decorator_list } => vec![push(identifier(name)), sequence(bases, Task::Expr), sequence(body, Task::Stmt), sequence(decorator_list, Task::Expr)],
            ast::StmtKind::Return { value } => vec![optional_expr(value.as_ref())],
            ast::StmtKind::Delete { targets } => vec![sequence(targets, Task::Expr)],
            ast::StmtKind::Assign { targets, value } => vec![sequence(targets, Task::Expr), vec![Task::Expr(value)]],
            ast::StmtKind::AugAssign { target, op, value } => vec![vec![Task::Expr(target)], self.singleton(operator_class(*op))?, vec![Task::Expr(value)]],
            ast::StmtKind::Print { dest, values, nl } => vec![optional_expr(dest.as_ref()), sequence(values, Task::Expr), push(Value::Bool(*nl))],
            ast::StmtKind::For { target, iter, body, orelse } => vec![vec![Task::Expr(target)], vec![Task::Expr(iter)], sequence(body, Task::Stmt), sequence(orelse, Task::Stmt)],
            ast::StmtKind::While { test, body, orelse } => vec![vec![Task::Expr(test)], sequence(body, Task::Stmt), sequence(orelse, Task::Stmt)],
            ast::StmtKind::If { test, body, orelse } => vec![vec![Task::Expr(test)], sequence(body, Task::Stmt), sequence(orelse, Task::Stmt)],
            ast::StmtKind::With { context_expr, optional_vars, body } => vec![vec![Task::Expr(context_expr)], optional_expr(optional_vars.as_ref()), sequence(body, Task::Stmt)],
            ast::StmtKind::Raise { type_, inst, tback } => vec![optional_expr(type_.as_ref()), optional_expr(inst.as_ref()), optional_expr(tback.as_ref())],
            ast::StmtKind::TryExcept { body, handlers, orelse } => vec![sequence(body, Task::Stmt), sequence(handlers, Task::ExceptHandler), sequence(orelse, Task::Stmt)],
            ast::StmtKind::TryFinally { body, finalbody } => vec![sequence(body, Task::Stmt), sequence(finalbody, Task::Stmt)],
            ast::StmtKind::Assert { test, msg } => vec![vec![Task::Expr(test)], optional_expr(msg.as_ref())],
            ast::StmtKind::Import { names } => vec![sequence(names, Task::Alias)],
            // `level` is a C int, so a statement without one reads as 0.
            ast::StmtKind::ImportFrom { module, names, level } => vec![push(optional_identifier(module.as_ref())), sequence(names, Task::Alias), push(Value::Int(i64::from(level.unwrap_or(0))))],
            ast::StmtKind::Exec { body, globals, locals } => vec![vec![Task::Expr(body)], optional_expr(globals.as_ref()), optional_expr(locals.as_ref())],
            ast::StmtKind::Global { names } => vec![push(self.vm.new_list(names.iter().map(identifier).collect()))],
            ast::StmtKind::Expr { value } => vec![vec![Task::Expr(value)]],
            ast::StmtKind::Pass | ast::StmtKind::Break | ast::StmtKind::Continue => Vec::new(),
        };

        Ok(fields)
    }

    fn expr_fields(&self, kind: &'a ast::ExprKind) -> PyResult<Vec<Vec<Task<'a>>>> {
        let fields = match kind {
            ast::ExprKind::BoolOp { op, values } => vec![self.singleton(boolop_class(*op))?, sequence(values, Task::Expr)],
            ast::ExprKind::BinOp { left, op, right } => vec![vec![Task::Expr(left)], self.singleton(operator_class(*op))?, vec![Task::Expr(right)]],
            ast::ExprKind::UnaryOp { op, operand } => vec![self.singleton(unaryop_class(*op))?, vec![Task::Expr(operand)]],
            ast::ExprKind::Lambda { args, body } => vec![vec![Task::Arguments(args)], vec![Task::Expr(body)]],
            ast::ExprKind::IfExp { test, body, orelse } => vec![vec![Task::Expr(test)], vec![Task::Expr(body)], vec![Task::Expr(orelse)]],
            ast::ExprKind::Dict { keys, values } => vec![sequence(keys, Task::Expr), sequence(values, Task::Expr)],
            ast::ExprKind::Set { elts } => vec![sequence(elts, Task::Expr)],
            ast::ExprKind::ListComp { elt, generators } => vec![vec![Task::Expr(elt)], sequence(generators, Task::Comprehension)],
            ast::ExprKind::SetComp { elt, generators } => vec![vec![Task::Expr(elt)], sequence(generators, Task::Comprehension)],
            ast::ExprKind::DictComp { key, value, generators } => vec![vec![Task::Expr(key)], vec![Task::Expr(value)], sequence(generators, Task::Comprehension)],
            ast::ExprKind::GeneratorExp { elt, generators } => vec![vec![Task::Expr(elt)], sequence(generators, Task::Comprehension)],
            ast::ExprKind::Yield { value } => vec![optional_expr(value.as_deref())],
            ast::ExprKind::Compare { left, ops, comparators } => {
                let ops = ops.iter().map(|op| self.types.singleton(self.vm, cmpop_class(*op))).collect::<PyResult<Vec<Value>>>()?;
                vec![vec![Task::Expr(left)], push(self.vm.new_list(ops)), sequence(comparators, Task::Expr)]
            }
            ast::ExprKind::Call { func, args, keywords, starargs, kwargs } => vec![vec![Task::Expr(func)], sequence(args, Task::Expr), sequence(keywords, Task::Keyword), optional_expr(starargs.as_deref()), optional_expr(kwargs.as_deref())],
            ast::ExprKind::Repr { value } => vec![vec![Task::Expr(value)]],
            ast::ExprKind::Num { n } => vec![push(self.number(n)?)],
            ast::ExprKind::Str { s } => vec![push(string(s))],
            ast::ExprKind::Attribute { value, attr, ctx } => vec![vec![Task::Expr(value)], push(identifier(attr)), self.singleton(context_class(*ctx))?],
            ast::ExprKind::Subscript { value, slice, ctx } => vec![vec![Task::Expr(value)], vec![Task::Slice(slice)], self.singleton(context_class(*ctx))?],
            ast::ExprKind::Name { id, ctx } => vec![push(identifier(id)), self.singleton(context_class(*ctx))?],
            ast::ExprKind::List { elts, ctx } => vec![sequence(elts, Task::Expr), self.singleton(context_class(*ctx))?],
            ast::ExprKind::Tuple { elts, ctx } => vec![sequence(elts, Task::Expr), self.singleton(context_class(*ctx))?],
        };

        Ok(fields)
    }

    /// The constant of a `Num`. The parser reads integers as 64-bit C longs;
    /// where a C long is narrower, CPython would have made a `long`.
    fn number(&self, number: &ast::Number) -> PyResult<Value> {
        match number {
            ast::Number::Int(value) => Ok(self.vm.new_int_from_i64(*value)),
            ast::Number::Long(value) => Ok(Value::Long(Rc::new(value.clone()))),
            ast::Number::Float(value) => Ok(Value::Float(*value)),
            ast::Number::Complex { real, imag } => Ok(self.vm.new_complex(Complex::new(*real, *imag))),
        }
    }
}

/// Converts a module to a node object.
pub fn ast_to_object(vm: &Vm, module: &ast::Mod) -> PyResult<Value> {
    let types = ast_types(vm)?;
    let mut writer = Writer { vm, types: &types, tasks: vec![Task::Mod(module)], values: Vec::new() };

    writer.run()?;

    match (writer.values.pop(), writer.values.is_empty()) {
        (Some(root), true) => Ok(root),
        _ => Err(internal_error(vm, "module conversion left no single result")),
    }
}

fn push<'a>(value: Value) -> Vec<Task<'a>> {
    vec![Task::Push(value)]
}

fn optional_expr(expr: Option<&ast::Expr>) -> Vec<Task<'_>> {
    match expr {
        Some(expr) => vec![Task::Expr(expr)],
        None => push(Value::None),
    }
}

/// A list node: each element, then the list of them.
fn sequence<'a, T>(items: &'a [T], task: fn(&'a T) -> Task<'a>) -> Vec<Task<'a>> {
    let mut tasks: Vec<Task<'a>> = items.iter().map(task).collect();
    tasks.push(Task::List(items.len()));

    tasks
}

fn identifier(name: &ast::Identifier) -> Value {
    Value::Str(PyBytes::new(name.0.as_slice()))
}

fn optional_identifier(name: Option<&ast::Identifier>) -> Value {
    match name {
        Some(name) => identifier(name),
        None => Value::None,
    }
}

fn string(literal: &ast::StrLiteral) -> Value {
    match literal {
        ast::StrLiteral::Bytes { value, .. } => Value::Str(PyBytes::new(value.as_slice())),
        ast::StrLiteral::Unicode(units) => Value::Unicode(PyText::new_unshared(units.as_slice())),
    }
}

fn stmt_class(kind: &ast::StmtKind) -> NodeClass {
    match kind {
        ast::StmtKind::FunctionDef { .. } => NodeClass::FunctionDef,
        ast::StmtKind::ClassDef { .. } => NodeClass::ClassDef,
        ast::StmtKind::Return { .. } => NodeClass::Return,
        ast::StmtKind::Delete { .. } => NodeClass::Delete,
        ast::StmtKind::Assign { .. } => NodeClass::Assign,
        ast::StmtKind::AugAssign { .. } => NodeClass::AugAssign,
        ast::StmtKind::Print { .. } => NodeClass::Print,
        ast::StmtKind::For { .. } => NodeClass::For,
        ast::StmtKind::While { .. } => NodeClass::While,
        ast::StmtKind::If { .. } => NodeClass::If,
        ast::StmtKind::With { .. } => NodeClass::With,
        ast::StmtKind::Raise { .. } => NodeClass::Raise,
        ast::StmtKind::TryExcept { .. } => NodeClass::TryExcept,
        ast::StmtKind::TryFinally { .. } => NodeClass::TryFinally,
        ast::StmtKind::Assert { .. } => NodeClass::Assert,
        ast::StmtKind::Import { .. } => NodeClass::Import,
        ast::StmtKind::ImportFrom { .. } => NodeClass::ImportFrom,
        ast::StmtKind::Exec { .. } => NodeClass::Exec,
        ast::StmtKind::Global { .. } => NodeClass::Global,
        ast::StmtKind::Expr { .. } => NodeClass::Expr,
        ast::StmtKind::Pass => NodeClass::Pass,
        ast::StmtKind::Break => NodeClass::Break,
        ast::StmtKind::Continue => NodeClass::Continue,
    }
}

fn expr_class(kind: &ast::ExprKind) -> NodeClass {
    match kind {
        ast::ExprKind::BoolOp { .. } => NodeClass::BoolOp,
        ast::ExprKind::BinOp { .. } => NodeClass::BinOp,
        ast::ExprKind::UnaryOp { .. } => NodeClass::UnaryOp,
        ast::ExprKind::Lambda { .. } => NodeClass::Lambda,
        ast::ExprKind::IfExp { .. } => NodeClass::IfExp,
        ast::ExprKind::Dict { .. } => NodeClass::Dict,
        ast::ExprKind::Set { .. } => NodeClass::Set,
        ast::ExprKind::ListComp { .. } => NodeClass::ListComp,
        ast::ExprKind::SetComp { .. } => NodeClass::SetComp,
        ast::ExprKind::DictComp { .. } => NodeClass::DictComp,
        ast::ExprKind::GeneratorExp { .. } => NodeClass::GeneratorExp,
        ast::ExprKind::Yield { .. } => NodeClass::Yield,
        ast::ExprKind::Compare { .. } => NodeClass::Compare,
        ast::ExprKind::Call { .. } => NodeClass::Call,
        ast::ExprKind::Repr { .. } => NodeClass::Repr,
        ast::ExprKind::Num { .. } => NodeClass::Num,
        ast::ExprKind::Str { .. } => NodeClass::Str,
        ast::ExprKind::Attribute { .. } => NodeClass::Attribute,
        ast::ExprKind::Subscript { .. } => NodeClass::Subscript,
        ast::ExprKind::Name { .. } => NodeClass::Name,
        ast::ExprKind::List { .. } => NodeClass::List,
        ast::ExprKind::Tuple { .. } => NodeClass::Tuple,
    }
}

fn slice_class(slice: &ast::Slice) -> NodeClass {
    match slice {
        ast::Slice::Ellipsis => NodeClass::Ellipsis,
        ast::Slice::Slice { .. } => NodeClass::Slice,
        ast::Slice::ExtSlice { .. } => NodeClass::ExtSlice,
        ast::Slice::Index { .. } => NodeClass::Index,
    }
}

fn context_class(context: ast::ExprContext) -> NodeClass {
    match context {
        ast::ExprContext::Load => NodeClass::Load,
        ast::ExprContext::Store => NodeClass::Store,
        ast::ExprContext::Del => NodeClass::Del,
        ast::ExprContext::AugLoad => NodeClass::AugLoad,
        ast::ExprContext::AugStore => NodeClass::AugStore,
        ast::ExprContext::Param => NodeClass::Param,
    }
}

fn boolop_class(op: ast::BoolOp) -> NodeClass {
    match op {
        ast::BoolOp::And => NodeClass::And,
        ast::BoolOp::Or => NodeClass::Or,
    }
}

fn operator_class(op: ast::Operator) -> NodeClass {
    match op {
        ast::Operator::Add => NodeClass::Add,
        ast::Operator::Sub => NodeClass::Sub,
        ast::Operator::Mult => NodeClass::Mult,
        ast::Operator::Div => NodeClass::Div,
        ast::Operator::Mod => NodeClass::Mod,
        ast::Operator::Pow => NodeClass::Pow,
        ast::Operator::LShift => NodeClass::LShift,
        ast::Operator::RShift => NodeClass::RShift,
        ast::Operator::BitOr => NodeClass::BitOr,
        ast::Operator::BitXor => NodeClass::BitXor,
        ast::Operator::BitAnd => NodeClass::BitAnd,
        ast::Operator::FloorDiv => NodeClass::FloorDiv,
    }
}

fn unaryop_class(op: ast::UnaryOp) -> NodeClass {
    match op {
        ast::UnaryOp::Invert => NodeClass::Invert,
        ast::UnaryOp::Not => NodeClass::Not,
        ast::UnaryOp::UAdd => NodeClass::UAdd,
        ast::UnaryOp::USub => NodeClass::USub,
    }
}

fn cmpop_class(op: ast::CmpOp) -> NodeClass {
    match op {
        ast::CmpOp::Eq => NodeClass::Eq,
        ast::CmpOp::NotEq => NodeClass::NotEq,
        ast::CmpOp::Lt => NodeClass::Lt,
        ast::CmpOp::LtE => NodeClass::LtE,
        ast::CmpOp::Gt => NodeClass::Gt,
        ast::CmpOp::GtE => NodeClass::GtE,
        ast::CmpOp::Is => NodeClass::Is,
        ast::CmpOp::IsNot => NodeClass::IsNot,
        ast::CmpOp::In => NodeClass::In,
        ast::CmpOp::NotIn => NodeClass::NotIn,
    }
}
