//! Constructs that compile to their own code object: functions, lambdas,
//! classes, and comprehensions other than list comprehensions, plus the
//! closures that bind them to the enclosing scope.

use std::rc::Rc;

use crate::interp::code::op;
use crate::interp::compiler::assemble::BlockIndex;
use crate::interp::compiler::assemble::Jump;
use crate::interp::compiler::ast;
use crate::interp::compiler::ast::ExprContext;
use crate::interp::compiler::ast::ExprKind;
use crate::interp::compiler::context::CompileError;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::symtable::NodeKey;
use crate::interp::compiler::symtable::Scope;
use crate::interp::compiler::unit::CodeUnit;

use super::CodeBuilder;
use super::Compiler;
use super::statements::docstring;
use super::system_error;

/// What a comprehension builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ComprehensionKind {
    /// A list comprehension, which runs inline in the enclosing code.
    List,
    Generator,
    Set,
    Dict,
}

impl Compiler<'_> {
    /// Compiles `body` as a new code object nested in the current one.
    fn nested_code(&mut self, name: Vec<u8>, name_interned: bool, key: NodeKey, line: i32, body: impl FnOnce(&mut Self) -> Result<CodeUnit, CompileError>) -> Result<CodeUnit, CompileError> {
        let Some(symbols) = self.symtable.lookup(key) else {
            return Err(system_error("unknown symbol table entry"));
        };

        // Line 0, which only trees built through `_ast` carry, counts as no
        // definition line.
        let definition_line = Some(line).filter(|&line| line != 0);
        let mut unit = CodeBuilder::new(self.symtable, symbols, name, name_interned, definition_line);
        unit.class_name = self.unit.class_name.clone();
        let enclosing = std::mem::replace(&mut self.unit, unit);
        self.enclosing.push(enclosing);

        let result = body(self);

        if let Some(enclosing) = self.enclosing.pop() {
            self.unit = enclosing;
        }

        result
    }

    /// A `def` statement: decorators and defaults are evaluated first, and
    /// the decorated function is bound to its name.
    pub(super) fn function_definition(&mut self, statement: &ast::Stmt, name: &ast::Identifier, args: &ast::Arguments, body: &[ast::Stmt], decorators: &[ast::Expr]) -> Result<(), CompileError> {
        self.expressions(decorators)?;
        self.expressions(&args.defaults)?;

        let code = self.nested_code(name.0.clone(), true, NodeKey::of_stmt(statement), statement.location.lineno, |this| {
            // The first constant is the docstring, or `None` without one.
            let documented = body.first().and_then(docstring);
            let doc = documented.map_or(Object::None, |(_, literal)| Self::string(literal));
            this.unit.constants.index_of(doc);

            this.unpack_parameters(args)?;
            this.unit.argcount = args.args.len() as u32;
            let statements = if documented.is_some() { body.get(1..).unwrap_or_default() } else { body };
            this.statements(statements)?;

            this.finish_unit(true)
        })?;

        self.make_function(code, args.defaults.len() as i32)?;
        for _ in decorators {
            self.emit_arg(op::CALL_FUNCTION, 1);
        }

        self.access_name(&name.0, ExprContext::Store)
    }

    /// Parameters written as tuples, as in `def f((a, b)):`, arrive in the
    /// hidden locals `.0`, `.1`, ... named after their position, and are
    /// unpacked on entry.
    fn unpack_parameters(&mut self, args: &ast::Arguments) -> Result<(), CompileError> {
        for (position, parameter) in args.args.iter().enumerate() {
            if let ExprKind::Tuple { .. } = parameter.kind {
                self.access_name(format!(".{position}").as_bytes(), ExprContext::Load)?;
                self.expression(parameter)?;
            }
        }

        Ok(())
    }

    pub(super) fn lambda(&mut self, expr: &ast::Expr, args: &ast::Arguments, body: &ast::Expr) -> Result<(), CompileError> {
        self.expressions(&args.defaults)?;

        let code = self.nested_code(b"<lambda>".to_vec(), true, NodeKey::of_expr(expr), expr.location.lineno, |this| {
            this.unpack_parameters(args)?;
            // A `None` first constant: a lambda has no docstring.
            this.unit.constants.index_of(Object::None);

            this.unit.argcount = args.args.len() as u32;
            this.expression(body)?;
            // A lambda containing `yield` is a generator that discards the
            // body's value.
            let generator = this.symtable.block(this.unit.symbols).generator;
            this.emit(if generator { op::POP_TOP } else { op::RETURN_VALUE });

            this.finish_unit(true)
        })?;

        self.make_function(code, args.defaults.len() as i32)
    }

    /// A class statement calls the body as a function returning its
    /// namespace, then builds the class from its name, bases, and that
    /// namespace.
    pub(super) fn class_definition(&mut self, statement: &ast::Stmt, name: &ast::Identifier, bases: &[ast::Expr], body: &[ast::Stmt], decorators: &[ast::Expr]) -> Result<(), CompileError> {
        self.expressions(decorators)?;

        self.load_constant(Self::identifier(name));
        self.expressions(bases)?;
        self.emit_arg(op::BUILD_TUPLE, bases.len() as i32);

        let code = self.nested_code(name.0.clone(), true, NodeKey::of_stmt(statement), statement.location.lineno, |this| {
            this.unit.class_name = Some(name.0.clone());
            this.access_name(b"__name__", ExprContext::Load)?;
            this.access_name(b"__module__", ExprContext::Store)?;
            this.body_with_docstring(body)?;
            this.emit(op::LOAD_LOCALS);
            this.emit(op::RETURN_VALUE);

            this.finish_unit(true)
        })?;

        self.make_function(code, 0)?;
        self.emit_arg(op::CALL_FUNCTION, 0);
        self.emit(op::BUILD_CLASS);
        for _ in decorators {
            self.emit_arg(op::CALL_FUNCTION, 1);
        }

        self.access_name(&name.0, ExprContext::Store)
    }

    /// Creates a function from `code` and `defaults` values on the stack.
    /// Code with free variables becomes a closure over the matching cells
    /// of the current scope.
    fn make_function(&mut self, code: CodeUnit, defaults: i32) -> Result<(), CompileError> {
        if code.freevars.is_empty() {
            self.load_constant(Object::Code(Rc::new(code)));
            self.emit_arg(op::MAKE_FUNCTION, defaults);
            return Ok(());
        }

        for name in &code.freevars {
            // In a class, a name can be both a class variable and a cell
            // for its methods; the closure takes the cell.
            let scope = self.symtable.block(self.unit.symbols).scope(name);
            let pool = if scope == Some(Scope::Cell) { &self.unit.cells } else { &self.unit.frees };
            let Some(index) = pool.position(name) else {
                let name = String::from_utf8_lossy(name);
                return Err(system_error(&format!("no cell or free variable '{name}' to close over")));
            };
            self.emit_arg(op::LOAD_CLOSURE, index);
        }
        self.emit_arg(op::BUILD_TUPLE, code.freevars.len() as i32);
        self.load_constant(Object::Code(Rc::new(code)));
        self.emit_arg(op::MAKE_CLOSURE, defaults);

        Ok(())
    }

    /// A list comprehension builds its list in the current code object.
    pub(super) fn list_comprehension(&mut self, generators: &[ast::Comprehension], element: &ast::Expr) -> Result<(), CompileError> {
        self.emit_arg(op::BUILD_LIST, 0);

        self.comprehension_loops(ComprehensionKind::List, generators, element, None)
    }

    /// Generator expressions and set and dict comprehensions run in a
    /// function of their own, called with the iterator of the outermost
    /// iterable, which is evaluated in the enclosing scope.
    pub(super) fn comprehension(
        &mut self,
        expr: &ast::Expr,
        kind: ComprehensionKind,
        name: &[u8],
        generators: &[ast::Comprehension],
        element: &ast::Expr,
        value: Option<&ast::Expr>,
    ) -> Result<(), CompileError> {
        let Some(outermost) = generators.first() else {
            return Err(system_error("comprehension with no generators"));
        };

        let code = self.nested_code(name.to_vec(), false, NodeKey::of_expr(expr), expr.location.lineno, |this| {
            match kind {
                ComprehensionKind::Set => this.emit_arg(op::BUILD_SET, 0),
                ComprehensionKind::Dict => this.emit_arg(op::BUILD_MAP, 0),
                ComprehensionKind::Generator | ComprehensionKind::List => {}
            }
            this.comprehension_loops(kind, generators, element, value)?;
            if kind != ComprehensionKind::Generator {
                this.emit(op::RETURN_VALUE);
            }

            this.finish_unit(true)
        })?;

        self.make_function(code, 0)?;
        self.expression(&outermost.iter)?;
        self.emit(op::GET_ITER);
        self.emit_arg(op::CALL_FUNCTION, 1);

        Ok(())
    }

    /// One nested loop per `for` clause, innermost last, with each clause's
    /// `if` tests skipping to its next item. The innermost loop adds the
    /// element to the result, which sits below one iterator per clause.
    fn comprehension_loops(&mut self, kind: ComprehensionKind, generators: &[ast::Comprehension], element: &ast::Expr, value: Option<&ast::Expr>) -> Result<(), CompileError> {
        /// The blocks of one clause's loop.
        struct Clause {
            start: BlockIndex,
            next_item: BlockIndex,
            exhausted: BlockIndex,
        }

        if generators.is_empty() {
            return Err(system_error("comprehension with no generators"));
        }

        let mut clauses = Vec::with_capacity(generators.len());
        for (depth, generator) in generators.iter().enumerate() {
            let clause = Clause { start: self.allocate_block(), next_item: self.allocate_block(), exhausted: self.allocate_block() };

            if depth == 0 && kind != ComprehensionKind::List {
                // The outermost iterator is the function's argument `.0`.
                self.unit.argcount = 1;
                self.emit_arg(op::LOAD_FAST, 0);
            } else {
                self.expression(&generator.iter)?;
                self.emit(op::GET_ITER);
            }
            self.continue_in(clause.start);
            self.emit_jump(op::FOR_ITER, Jump::Relative(clause.exhausted));
            self.continue_in_new_block();
            self.expression(&generator.target)?;

            for test in &generator.ifs {
                self.expression(test)?;
                self.emit_jump(op::POP_JUMP_IF_FALSE, Jump::Absolute(clause.next_item));
                self.continue_in_new_block();
            }
            clauses.push(clause);
        }

        let result_depth = generators.len() as i32 + 1;
        match kind {
            ComprehensionKind::List => {
                self.expression(element)?;
                self.emit_arg(op::LIST_APPEND, result_depth);
            }
            ComprehensionKind::Generator => {
                self.expression(element)?;
                self.emit(op::YIELD_VALUE);
                self.emit(op::POP_TOP);
            }
            ComprehensionKind::Set => {
                self.expression(element)?;
                self.emit_arg(op::SET_ADD, result_depth);
            }
            ComprehensionKind::Dict => {
                // As in `d[k] = v`, the value is evaluated before the key.
                let Some(value) = value else {
                    return Err(system_error("dict comprehension without a value"));
                };
                self.expression(value)?;
                self.expression(element)?;
                self.emit_arg(op::MAP_ADD, result_depth);
            }
        }

        for clause in clauses.iter().rev() {
            self.continue_in(clause.next_item);
            self.emit_jump(op::JUMP_ABSOLUTE, Jump::Absolute(clause.start));
            self.continue_in(clause.exhausted);
        }

        Ok(())
    }
}
