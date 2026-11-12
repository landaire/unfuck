//! Statements: assignment, control flow, exception handling, and imports.

use num_bigint::BigInt;

use crate::interp::code::op;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::assemble::Jump;
use crate::interp::compiler::ast;
use crate::interp::compiler::ast::ExprContext;
use crate::interp::compiler::ast::ExprKind;
use crate::interp::compiler::ast::StmtKind;
use crate::interp::compiler::context::CompileError;
use crate::interp::compiler::context::CompileWarning;
use crate::interp::compiler::context::WarningCategory;
use crate::interp::compiler::context::WarningLocation;
use crate::interp::compiler::future::c_str;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::symtable::BlockType;

use super::Compiler;
use super::Control;
use super::NameList;
use super::system_error;

impl Compiler<'_> {
    pub(super) fn statements(&mut self, statements: &[ast::Stmt]) -> Result<(), CompileError> {
        for statement in statements {
            self.statement(statement)?;
        }

        Ok(())
    }

    /// A module or class body: a leading string literal is stored as
    /// `__doc__`.
    pub(super) fn body_with_docstring(&mut self, statements: &[ast::Stmt]) -> Result<(), CompileError> {
        if let Some((first, rest)) = statements.split_first()
            && let Some((value, _)) = docstring(first)
        {
            self.expression(value)?;
            self.access_name(b"__doc__", ExprContext::Store)?;
            return self.statements(rest);
        }

        self.statements(statements)
    }

    fn statement(&mut self, statement: &ast::Stmt) -> Result<(), CompileError> {
        self.set_line(statement.location.lineno);

        match &statement.kind {
            StmtKind::FunctionDef { name, args, body, decorator_list } => self.function_definition(statement, name, args, body, decorator_list),
            StmtKind::ClassDef { name, bases, body, decorator_list } => self.class_definition(statement, name, bases, body, decorator_list),
            StmtKind::Return { value } => self.return_statement(value.as_ref()),
            StmtKind::Delete { targets } => self.expressions(targets),
            StmtKind::Assign { targets, value } => self.assignment(targets, value),
            StmtKind::AugAssign { target, op: operator, value } => self.augmented_assignment(target, *operator, value),
            StmtKind::Print { dest, values, nl } => self.print(dest.as_ref(), values, *nl),
            StmtKind::For { target, iter, body, orelse } => self.for_loop(target, iter, body, orelse),
            StmtKind::While { test, body, orelse } => self.while_loop(test, body, orelse),
            StmtKind::If { test, body, orelse } => self.if_statement(test, body, orelse),
            StmtKind::Raise { type_, inst, tback } => self.raise(type_.as_ref(), inst.as_ref(), tback.as_ref()),
            StmtKind::TryExcept { body, handlers, orelse } => self.try_except(body, handlers, orelse),
            StmtKind::TryFinally { body, finalbody } => self.try_finally(body, finalbody),
            StmtKind::Assert { test, msg } => self.assert(test, msg.as_ref()),
            StmtKind::Import { names } => self.import(names),
            StmtKind::ImportFrom { module, names, level } => self.import_from(statement, module.as_ref(), names, level.unwrap_or(0)),
            StmtKind::Exec { body, globals, locals } => self.exec(body, globals.as_ref(), locals.as_ref()),
            StmtKind::Global { .. } | StmtKind::Pass => Ok(()),
            StmtKind::Expr { value } => self.expression_statement(value),
            StmtKind::Break => self.break_statement(),
            StmtKind::Continue => self.continue_statement(),
            StmtKind::With { context_expr, optional_vars, body } => self.with(context_expr, optional_vars.as_ref(), body),
        }
    }

    fn return_statement(&mut self, value: Option<&ast::Expr>) -> Result<(), CompileError> {
        if self.scope_kind() != BlockType::Function {
            return Err(self.syntax_error("'return' outside function"));
        }

        match value {
            Some(value) => self.expression(value)?,
            None => self.load_constant(Object::None),
        }
        self.emit(op::RETURN_VALUE);

        Ok(())
    }

    /// `a = b = value` evaluates `value` once and stores a copy in every
    /// target but the last.
    fn assignment(&mut self, targets: &[ast::Expr], value: &ast::Expr) -> Result<(), CompileError> {
        self.expression(value)?;

        let Some((last, others)) = targets.split_last() else {
            return Ok(());
        };
        for target in others {
            self.emit(op::DUP_TOP);
            self.expression(target)?;
        }

        self.expression(last)
    }

    fn augmented_assignment(&mut self, target: &ast::Expr, operator: ast::Operator, value: &ast::Expr) -> Result<(), CompileError> {
        let line = target.location.lineno;
        let inplace = self.inplace_opcode(operator);

        match &target.kind {
            ExprKind::Attribute { value: object, attr, .. } => {
                self.advance_line(line);
                self.attribute(object, attr, ExprContext::AugLoad)?;
                self.expression(value)?;
                self.emit(inplace);
                self.advance_line(line);
                self.attribute(object, attr, ExprContext::AugStore)
            }
            ExprKind::Subscript { value: object, slice, .. } => {
                self.advance_line(line);
                self.subscript(object, slice, ExprContext::AugLoad)?;
                self.expression(value)?;
                self.emit(inplace);
                self.advance_line(line);
                self.subscript(object, slice, ExprContext::AugStore)
            }
            ExprKind::Name { id, .. } => {
                self.access_name(&id.0, ExprContext::Load)?;
                self.expression(value)?;
                self.emit(inplace);
                self.access_name(&id.0, ExprContext::Store)
            }
            _ => Err(system_error("invalid node type for augmented assignment")),
        }
    }

    fn print(&mut self, dest: Option<&ast::Expr>, values: &[ast::Expr], newline: bool) -> Result<(), CompileError> {
        let Some(dest) = dest else {
            for value in values {
                self.expression(value)?;
                self.emit(op::PRINT_ITEM);
            }
            if newline {
                self.emit(op::PRINT_NEWLINE);
            }
            return Ok(());
        };

        // The stream stays on the stack below each value until the end.
        self.expression(dest)?;
        for value in values {
            self.emit(op::DUP_TOP);
            self.expression(value)?;
            self.emit(op::ROT_TWO);
            self.emit(op::PRINT_ITEM_TO);
        }
        self.emit(if newline { op::PRINT_NEWLINE_TO } else { op::POP_TOP });

        Ok(())
    }

    /// `raise` takes up to three operands; each is only present when the
    /// one before it is.
    fn raise(&mut self, kind: Option<&ast::Expr>, instance: Option<&ast::Expr>, traceback: Option<&ast::Expr>) -> Result<(), CompileError> {
        let mut count = 0;
        for operand in [kind, instance, traceback].into_iter().map_while(|operand| operand) {
            self.expression(operand)?;
            count += 1;
        }
        self.emit_arg(op::RAISE_VARARGS, count);

        Ok(())
    }

    /// `exec code in globals, locals`; missing namespaces are `None`, and a
    /// missing `locals` is the same object as `globals`.
    fn exec(&mut self, code: &ast::Expr, globals: Option<&ast::Expr>, locals: Option<&ast::Expr>) -> Result<(), CompileError> {
        self.expression(code)?;

        match (globals, locals) {
            (None, _) => {
                self.load_constant(Object::None);
                self.emit(op::DUP_TOP);
            }
            (Some(globals), None) => {
                self.expression(globals)?;
                self.emit(op::DUP_TOP);
            }
            (Some(globals), Some(locals)) => {
                self.expression(globals)?;
                self.expression(locals)?;
            }
        }
        self.emit(op::EXEC_STMT);

        Ok(())
    }

    /// Outside interactive top-level code, a bare string or number is
    /// dropped without evaluation.
    fn expression_statement(&mut self, value: &ast::Expr) -> Result<(), CompileError> {
        if self.interactive && self.enclosing.is_empty() {
            self.expression(value)?;
            self.emit(op::PRINT_EXPR);
            return Ok(());
        }
        if matches!(value.kind, ExprKind::Str { .. } | ExprKind::Num { .. }) {
            return Ok(());
        }

        self.expression(value)?;
        self.emit(op::POP_TOP);

        Ok(())
    }

    /// A test whose truth is known at compile time only compiles the branch
    /// taken. An `elif` chain nests one `If` per clause however long it is,
    /// so an `else` suite that is a lone `If` continues the loop.
    fn if_statement<'a>(&mut self, mut test: &'a ast::Expr, mut body: &'a [ast::Stmt], mut orelse: &'a [ast::Stmt]) -> Result<(), CompileError> {
        let mut outer_ends = Vec::new();
        let mut end = self.allocate_block();

        loop {
            let remaining = match constant_truth(test) {
                Some(true) => {
                    self.statements(body)?;
                    &[][..]
                }
                Some(false) => orelse,
                None => {
                    let otherwise = if orelse.is_empty() { end } else { self.allocate_block() };
                    self.expression(test)?;
                    self.emit_jump(op::POP_JUMP_IF_FALSE, Jump::Absolute(otherwise));
                    self.statements(body)?;
                    self.emit_jump(op::JUMP_FORWARD, Jump::Relative(end));
                    if !orelse.is_empty() {
                        self.continue_in(otherwise);
                    }
                    orelse
                }
            };

            let [statement] = remaining else {
                self.statements(remaining)?;
                break;
            };
            let StmtKind::If { test: inner_test, body: inner_body, orelse: inner_orelse } = &statement.kind else {
                self.statement(statement)?;
                break;
            };

            self.set_line(statement.location.lineno);
            outer_ends.push(end);
            end = self.allocate_block();
            test = inner_test;
            body = inner_body;
            orelse = inner_orelse;
        }

        self.continue_in(end);
        for end in outer_ends.into_iter().rev() {
            self.continue_in(end);
        }

        Ok(())
    }

    fn for_loop(&mut self, target: &ast::Expr, iterable: &ast::Expr, body: &[ast::Stmt], orelse: &[ast::Stmt]) -> Result<(), CompileError> {
        let start = self.allocate_block();
        let exhausted = self.allocate_block();
        let end = self.allocate_block();

        self.emit_jump(op::SETUP_LOOP, Jump::Relative(end));
        self.enter_control(Control::Loop { start })?;
        self.expression(iterable)?;
        self.emit(op::GET_ITER);

        self.continue_in(start);
        self.emit_jump(op::FOR_ITER, Jump::Relative(exhausted));
        self.expression(target)?;
        self.statements(body)?;
        self.emit_jump(op::JUMP_ABSOLUTE, Jump::Absolute(start));

        self.continue_in(exhausted);
        self.emit(op::POP_BLOCK);
        self.leave_control();
        self.statements(orelse)?;
        self.continue_in(end);

        Ok(())
    }

    /// A loop whose test is a true constant has no test; one whose test is
    /// a false constant is only its `else` suite.
    fn while_loop(&mut self, test: &ast::Expr, body: &[ast::Stmt], orelse: &[ast::Stmt]) -> Result<(), CompileError> {
        let truth = constant_truth(test);
        if truth == Some(false) {
            return self.statements(orelse);
        }

        let start = self.allocate_block();
        let end = self.allocate_block();
        let exit = match truth {
            Some(_) => None,
            None => Some(self.allocate_block()),
        };

        self.emit_jump(op::SETUP_LOOP, Jump::Relative(end));
        self.continue_in(start);
        self.enter_control(Control::Loop { start })?;
        if let Some(exit) = exit {
            self.expression(test)?;
            self.emit_jump(op::POP_JUMP_IF_FALSE, Jump::Absolute(exit));
        }
        self.statements(body)?;
        self.emit_jump(op::JUMP_ABSOLUTE, Jump::Absolute(start));

        if let Some(exit) = exit {
            self.continue_in(exit);
        }
        self.emit(op::POP_BLOCK);
        self.leave_control();
        self.statements(orelse)?;
        self.continue_in(end);

        Ok(())
    }

    fn break_statement(&mut self) -> Result<(), CompileError> {
        if !self.unit.control.iter().any(|control| matches!(control, Control::Loop { .. })) {
            return Err(self.syntax_error("'break' outside loop"));
        }
        self.emit(op::BREAK_LOOP);

        Ok(())
    }

    /// Directly inside a loop, `continue` is a jump to the loop's start.
    /// Inside a `try` within the loop it needs `CONTINUE_LOOP`, which
    /// unwinds the handler blocks first. It may not cross a `finally` suite.
    fn continue_statement(&mut self) -> Result<(), CompileError> {
        const NOT_IN_LOOP: &str = "'continue' not properly in loop";
        const IN_FINALLY: &str = "'continue' not supported inside 'finally' clause";

        for (depth, control) in self.unit.control.iter().rev().enumerate() {
            match *control {
                Control::Loop { start } => {
                    let opcode = if depth == 0 { op::JUMP_ABSOLUTE } else { op::CONTINUE_LOOP };
                    self.emit_jump(opcode, Jump::Absolute(start));
                    return Ok(());
                }
                Control::FinallyBody => return Err(self.syntax_error(IN_FINALLY)),
                Control::TryExcept | Control::TryFinally => {}
            }
        }

        Err(self.syntax_error(NOT_IN_LOOP))
    }

    /// The `finally` suite runs with `None` pushed after a normal exit and
    /// with the exception after an abnormal one.
    fn try_finally(&mut self, body: &[ast::Stmt], finalbody: &[ast::Stmt]) -> Result<(), CompileError> {
        let protected = self.allocate_block();
        let cleanup = self.allocate_block();

        self.emit_jump(op::SETUP_FINALLY, Jump::Relative(cleanup));
        self.continue_in(protected);
        self.enter_control(Control::TryFinally)?;
        self.statements(body)?;
        self.emit(op::POP_BLOCK);
        self.leave_control();
        self.load_constant(Object::None);

        self.continue_in(cleanup);
        self.enter_control(Control::FinallyBody)?;
        self.statements(finalbody)?;
        self.emit(op::END_FINALLY);
        self.leave_control();

        Ok(())
    }

    /// Each handler compares the exception type with its own, falling
    /// through to the next handler on mismatch; after the last one the
    /// exception is re-raised.
    fn try_except(&mut self, body: &[ast::Stmt], handlers: &[ast::ExceptHandler], orelse: &[ast::Stmt]) -> Result<(), CompileError> {
        const EXCEPTION_MATCH: i32 = 10;

        let protected = self.allocate_block();
        let mut next_handler = self.allocate_block();
        let no_exception = self.allocate_block();
        let end = self.allocate_block();

        self.emit_jump(op::SETUP_EXCEPT, Jump::Relative(next_handler));
        self.continue_in(protected);
        self.enter_control(Control::TryExcept)?;
        self.statements(body)?;
        self.emit(op::POP_BLOCK);
        self.leave_control();
        self.emit_jump(op::JUMP_FORWARD, Jump::Relative(no_exception));

        for (index, handler) in handlers.iter().enumerate() {
            self.continue_in(next_handler);
            if handler.type_.is_none() && index + 1 < handlers.len() {
                return Err(self.syntax_error("default 'except:' must be last"));
            }
            self.set_line(handler.location.lineno);
            next_handler = self.allocate_block();

            if let Some(kind) = &handler.type_ {
                self.emit(op::DUP_TOP);
                self.expression(kind)?;
                self.emit_arg(op::COMPARE_OP, EXCEPTION_MATCH);
                self.emit_jump(op::POP_JUMP_IF_FALSE, Jump::Absolute(next_handler));
            }
            // The stack holds the traceback, the value, and the type; the
            // value is bound to the target, if any.
            self.emit(op::POP_TOP);
            match &handler.name {
                Some(target) => self.expression(target)?,
                None => self.emit(op::POP_TOP),
            }
            self.emit(op::POP_TOP);
            self.statements(&handler.body)?;
            self.emit_jump(op::JUMP_FORWARD, Jump::Relative(end));
        }

        self.continue_in(next_handler);
        self.emit(op::END_FINALLY);
        self.continue_in(no_exception);
        self.statements(orelse)?;
        self.continue_in(end);

        Ok(())
    }

    /// Relative imports are tried first (level -1) unless absolute imports
    /// are in effect.
    fn implicit_import_level(&self) -> i64 {
        if self.has_future(CompilerFlags::FUTURE_ABSOLUTE_IMPORT) { 0 } else { -1 }
    }

    fn import(&mut self, aliases: &[ast::Alias]) -> Result<(), CompileError> {
        for alias in aliases {
            self.load_constant(Object::Int(self.implicit_import_level()));
            self.load_constant(Object::None);
            self.emit_mangled(op::IMPORT_NAME, &alias.name.0);

            // The dotted name is split as a NUL-terminated string.
            let dotted = c_str(&alias.name.0);
            match &alias.asname {
                Some(asname) => {
                    // `import a.b.c as d` binds the innermost module.
                    for part in dotted.split(|&byte| byte == b'.').skip(1) {
                        self.emit_name(op::LOAD_ATTR, NameList::Names, part);
                    }
                    self.access_name(&asname.0, ExprContext::Store)?;
                }
                None => {
                    // `import a.b.c` binds the outermost package.
                    let top = match dotted.iter().position(|&byte| byte == b'.') {
                        Some(dot) => &dotted[..dot],
                        None => alias.name.0.as_slice(),
                    };
                    self.access_name(top, ExprContext::Store)?;
                }
            }
        }

        Ok(())
    }

    fn import_from(&mut self, statement: &ast::Stmt, module: Option<&ast::Identifier>, aliases: &[ast::Alias], level: u32) -> Result<(), CompileError> {
        let level = if level == 0 { self.implicit_import_level() } else { i64::from(level) };
        self.load_constant(Object::Int(level));

        // Without a leading `__future__` import, any later one is late,
        // except on the negative lines only trees built through `_ast` have.
        let line = statement.location.lineno;
        let late = match self.future_import_line {
            Some(last) => line > last,
            None => line >= 0,
        };
        if late && module.is_some_and(|module| c_str(&module.0) == b"__future__") {
            return Err(self.syntax_error("from __future__ imports must occur at the beginning of the file"));
        }

        let imported: Vec<Object> = aliases.iter().map(|alias| Self::identifier(&alias.name)).collect();
        self.load_constant(Object::Tuple(imported.into()));
        let module_name = module.map_or(&b""[..], |module| module.0.as_slice());
        self.emit_mangled(op::IMPORT_NAME, module_name);

        if aliases.first().is_some_and(|alias| alias.name.0.first() == Some(&b'*')) {
            self.emit(op::IMPORT_STAR);
            return Ok(());
        }
        for alias in aliases {
            self.emit_mangled(op::IMPORT_FROM, &alias.name.0);
            let bound = alias.asname.as_ref().unwrap_or(&alias.name);
            self.access_name(&bound.0, ExprContext::Store)?;
        }
        self.emit(op::POP_TOP);

        Ok(())
    }

    fn assert(&mut self, test: &ast::Expr, message: Option<&ast::Expr>) -> Result<(), CompileError> {
        if let ExprKind::Tuple { elts, .. } = &test.kind
            && !elts.is_empty()
        {
            let warning = CompileWarning {
                category: WarningCategory::SyntaxWarning,
                message: "assertion is always true, perhaps remove parentheses?".to_owned(),
                location: Some(WarningLocation { filename: self.filename.to_vec(), lineno: self.unit.line }),
            };
            if self.context.warn(&warning).is_err() {
                return Err(CompileError::WarningRaised);
            }
        }

        self.expression(test)?;
        let passed = self.allocate_block();
        self.emit_jump(op::POP_JUMP_IF_TRUE, Jump::Absolute(passed));
        self.emit_name(op::LOAD_GLOBAL, NameList::Names, b"AssertionError");
        if let Some(message) = message {
            self.expression(message)?;
            self.emit_arg(op::CALL_FUNCTION, 1);
        }
        self.emit_arg(op::RAISE_VARARGS, 1);
        self.continue_in(passed);

        Ok(())
    }

    /// `SETUP_WITH` calls `__enter__` and protects the body like
    /// `try`/`finally`; the cleanup calls `__exit__`.
    fn with(&mut self, manager: &ast::Expr, target: Option<&ast::Expr>, body: &[ast::Stmt]) -> Result<(), CompileError> {
        let protected = self.allocate_block();
        let cleanup = self.allocate_block();

        self.expression(manager)?;
        self.emit_jump(op::SETUP_WITH, Jump::Relative(cleanup));

        self.continue_in(protected);
        self.enter_control(Control::TryFinally)?;
        match target {
            Some(target) => self.expression(target)?,
            None => self.emit(op::POP_TOP),
        }
        self.statements(body)?;
        self.emit(op::POP_BLOCK);
        self.leave_control();
        self.load_constant(Object::None);

        self.continue_in(cleanup);
        self.enter_control(Control::FinallyBody)?;
        self.emit(op::WITH_CLEANUP);
        self.emit(op::END_FINALLY);
        self.leave_control();

        Ok(())
    }
}

/// The expression and literal of a statement that is a string literal
/// alone, which makes it the docstring when it comes first.
pub(super) fn docstring(statement: &ast::Stmt) -> Option<(&ast::Expr, &ast::StrLiteral)> {
    let StmtKind::Expr { value } = &statement.kind else {
        return None;
    };
    let ExprKind::Str { s } = &value.kind else {
        return None;
    };

    Some((value, s))
}

/// The truth of a test that is a number, a string literal, or the name
/// `__debug__` (true, since optimization is off); `None` for others.
fn constant_truth(test: &ast::Expr) -> Option<bool> {
    match &test.kind {
        ExprKind::Num { n } => Some(match n {
            ast::Number::Int(value) => *value != 0,
            ast::Number::Long(value) => *value != BigInt::from(0),
            ast::Number::Float(value) => *value != 0.0,
            ast::Number::Complex { real, imag } => *real != 0.0 || *imag != 0.0,
        }),
        ExprKind::Str { s } => Some(match s {
            ast::StrLiteral::Bytes { value, .. } => !value.is_empty(),
            ast::StrLiteral::Unicode(units) => !units.is_empty(),
        }),
        // The name is compared as a NUL-terminated string.
        ExprKind::Name { id, .. } if c_str(&id.0) == b"__debug__" => Some(true),
        _ => None,
    }
}
