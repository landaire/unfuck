//! Renders the statement IR back into Python 2.7 source.
//!
//! Expression rendering is precedence aware: each expression reports a binding
//! precedence and parenthesises a child only when the child binds more loosely
//! than its position requires.

use std::sync::Arc;

use num_traits::ToPrimitive;
use py27_marshal::{Code, CodeFlags, Obj};

use super::expr::*;

/// Marker emitted where a construct could not be fully recovered. Its presence in
/// the output makes [`super::decompile_function`] reject the function rather than
/// return source that is invalid or incomplete.
pub(crate) const UNRECOVERED: &str = "__unrecovered__";

/// The def or class at the bottom of a decorator chain (see `try_decorated_def`).
enum Decorated {
    Func(ConstId, Vec<ValueId>),
    Class(ValueId, ValueId, ConstId),
}

/// Binding precedence levels, lowest to highest.
mod prec {
    pub const TERNARY: u8 = 0;
    pub const OR: u8 = 1;
    pub const AND: u8 = 2;
    // Boolean `not` binds looser than comparison and arithmetic but tighter than
    // `and`/`or` (Python: or < and < not < comparison), unlike the arithmetic
    // unaries `-`/`+`/`~` which bind at UNARY.
    pub const NOT: u8 = 3;
    pub const COMPARE: u8 = 4;
    pub const BIT_OR: u8 = 5;
    pub const BIT_XOR: u8 = 6;
    pub const BIT_AND: u8 = 7;
    pub const SHIFT: u8 = 8;
    pub const ADD: u8 = 9;
    pub const MUL: u8 = 10;
    pub const UNARY: u8 = 11;
    pub const POWER: u8 = 12;
    pub const ATOM: u8 = 14;
}

/// Renders statements and expressions for one function body.
pub struct Emitter<'a> {
    code: &'a Code,
    arena: &'a ExprArena,
    out: String,
    indent: usize,
}

impl<'a> Emitter<'a> {
    pub fn new(code: &'a Code, arena: &'a ExprArena) -> Emitter<'a> {
        Emitter {
            code,
            arena,
            out: String::new(),
            indent: 1,
        }
    }

    /// Like [`Self::new`] but renders at module scope: statements start at column 0
    /// rather than indented under an enclosing `def`. Used for a module's root code
    /// object, whose statements are the module's own top-level code.
    pub fn new_module(code: &'a Code, arena: &'a ExprArena) -> Emitter<'a> {
        Emitter {
            code,
            arena,
            out: String::new(),
            indent: 0,
        }
    }

    /// Renders a single expression at statement precedence. Used to recover a
    /// lambda body in the enclosing scope.
    pub(crate) fn expr_text(&self, id: ValueId) -> String {
        self.expr(id, 0)
    }

    /// Renders a function body that reduces to a single expression -- a `return e`,
    /// or an `if`/`else` whose arms each reduce the same way -- as one expression,
    /// rendered at `parent` precedence. The compiler lowers a lambda's ternary to
    /// `if c: return a else: return b`, so this lets such a lambda still emit as
    /// `a if c else b`. Returns `None` for any body that is not a return/ternary tree.
    pub(crate) fn body_as_expr(&self, body: &[Stmt], parent: u8) -> Option<String> {
        match body {
            [Stmt::Return(Some(value))] => Some(self.expr(*value, parent)),
            [Stmt::If { cond, then, els }] if !then.is_empty() && !els.is_empty() => {
                let then_text = self.body_as_expr(then, prec::OR)?;
                let else_text = self.body_as_expr(els, prec::TERNARY)?;
                let text =
                    format!("{} if {} else {}", then_text, self.expr(*cond, prec::OR), else_text);
                Some(if prec::TERNARY < parent { format!("({})", text) } else { text })
            }
            _ => None,
        }
    }

    /// Renders a body and returns the accumulated source, prefixed with the
    /// function's docstring when it has one.
    pub fn render_body(mut self, stmts: &[Stmt]) -> String {
        let mut had_doc = false;
        if let Some(doc) = self.docstring() {
            self.line(&doc);
            had_doc = true;
        }
        // A module body stores its docstring as a leading `__doc__ = <str>` rather
        // than via the function docstring convention; render that as a bare docstring
        // literal so it stays a docstring. A non-docstring statement before a
        // `from __future__ import ...` is a syntax error, so this also keeps a
        // module's future imports legal.
        let stmts = match (had_doc, self.module_docstring(stmts)) {
            (false, Some((doc, rest))) => {
                self.line(&doc);
                had_doc = true;
                rest
            }
            _ => stmts,
        };
        if stmts.is_empty() && !had_doc {
            self.line("pass");
        }
        self.emit_stmts(stmts);
        self.out
    }

    /// If `stmts` begins with a module-scope docstring assignment (`__doc__ = <string
    /// literal>`), returns the rendered docstring and the remaining statements. Only
    /// fires at module scope (indent 0): a module stores its docstring with a
    /// `STORE_NAME __doc__` rather than the `co_consts[0]` convention functions use.
    fn module_docstring<'b>(&self, stmts: &'b [Stmt]) -> Option<(String, &'b [Stmt])> {
        if self.indent != 0 {
            return None;
        }
        let (first, rest) = stmts.split_first()?;
        let Stmt::Assign(LValue::Name(name), value) = first else {
            return None;
        };
        if self.code.names.get(name.0 as usize)?.to_string() != "__doc__" {
            return None;
        }
        let Expr::Const(c) = self.arena.get(*value) else {
            return None;
        };
        let Some(Obj::String(s)) = self.code.consts.get(c.0 as usize) else {
            return None;
        };
        // A module docstring is emitted at the top level and never re-indented, so a
        // multi-line triple-quoted form is safe and stays readable.
        Some((docstring_literal(s.read().unwrap().as_slice(), true), rest))
    }

    /// The function's docstring literal, if any. A docstring is `co_consts[0]` when
    /// it is a string, but only for real functions (CO_OPTIMIZED): class and module
    /// bodies store `__doc__` explicitly, and comprehensions reuse slot 0 for an
    /// ordinary constant, so neither follows the convention.
    fn docstring(&self) -> Option<String> {
        if !self.code.flags.contains(CodeFlags::OPTIMIZED)
            || self.code.name.to_string().starts_with('<')
        {
            return None;
        }
        match self.code.consts.first() {
            // Emit the readable triple-quoted form. When the def is nested into its
            // class or module the source is re-indented line by line, but
            // `emit_reindented` leaves a triple-quoted docstring's interior verbatim, so
            // the literal's bytes survive. `docstring_literal` still falls back to the
            // escaped one-line form when triple-quoting would not be byte-exact (a
            // backslash, an embedded `"""`, a trailing quote).
            Some(Obj::String(s)) => Some(docstring_literal(s.read().unwrap().as_slice(), true)),
            _ => None,
        }
    }

    /// Emits a block of already-rendered source (a nested `def`/`class`) at the current
    /// indent, line by line. Lines inside a triple-quoted docstring are emitted verbatim
    /// rather than re-indented: adding indentation there would inject whitespace into the
    /// string's bytes and change its value. The only multi-line `"""` the emitter ever
    /// produces is a docstring (other string literals render escaped on one line, and
    /// `docstring_literal` rejects content containing `"""`), so toggling on each line's
    /// `"""` count tracks the docstring interior exactly.
    fn emit_reindented(&mut self, source: &str) {
        let mut in_docstring = false;
        for text in source.trim_end_matches('\n').split('\n') {
            let triples = text.matches("\"\"\"").count();
            if in_docstring {
                // Verbatim while inside; the docstring body never contains `"""`
                // (`docstring_literal` rejects that), so an odd count here is the close.
                self.out.push_str(text);
                self.out.push('\n');
                if triples % 2 == 1 {
                    in_docstring = false;
                }
            } else {
                self.line(text);
                // A docstring opener is the start of its line (after indent); a `"""`
                // inside a code string literal is mid-line, so it cannot open one.
                if triples % 2 == 1 && text.trim_start().starts_with("\"\"\"") {
                    in_docstring = true;
                }
            }
        }
    }

    fn line(&mut self, text: &str) {
        // A blank line carries no indentation, so emit it as a truly empty line
        // rather than one padded with trailing whitespace.
        if !text.is_empty() {
            for _ in 0..self.indent {
                self.out.push_str("    ");
            }
            self.out.push_str(text);
        }
        self.out.push('\n');
    }

    /// The nested code object referenced by a code constant, if it is one.
    fn nested_code(&self, code: ConstId) -> Option<Arc<Code>> {
        match self.code.consts.get(code.0 as usize) {
            Some(Obj::Code(nested)) => Some(Arc::new(nested.read().unwrap().clone())),
            _ => None,
        }
    }

    /// Renders a `MakeFunction` used as an expression. A function object that
    /// appears inline (never bound to a name by a `STORE`) can only be a lambda in
    /// Python 2.7, so any code object whose body is a single `return expr` becomes
    /// `lambda args: expr`. The obfuscator may have replaced the `<lambda>` co_name
    /// with a numeric one, so the name is not relied on. A body that is not a single
    /// return cannot be inlined and is marked unrecovered.
    fn lambda_expr(&self, code: ConstId, defaults: &[ValueId]) -> String {
        let Some(nested) = self.nested_code(code) else {
            return UNRECOVERED.to_string();
        };
        // Defaults are evaluated in this (enclosing) scope.
        let rendered: Vec<String> = defaults.iter().map(|d| self.expr(*d, 0)).collect();
        match super::DecodedFunction::decode(nested).and_then(|f| f.structure()) {
            Ok(structured) => {
                structured.lambda_source(&rendered).unwrap_or_else(|| UNRECOVERED.to_string())
            }
            Err(_) => UNRECOVERED.to_string(),
        }
    }

    /// Recognises `name = deco(...(make_function|build_class))` where the def/class's
    /// own name matches the store target: the bytecode shape of a decorated `def` or
    /// `class`. Emits the `@deco` lines and the def/class, and returns `true`. Returns
    /// `false` for any other assignment, which the caller renders normally.
    fn try_decorated_def(&mut self, target: &LValue, value: ValueId) -> bool {
        let mut decorators = Vec::new();
        let mut cur = value;
        let bottom = loop {
            match self.arena.get(cur) {
                // Each decorator wraps the def/class in a single-positional call. A
                // decorator factory (`@register(x)`) puts its own arguments on an inner
                // call, which becomes the `@...` expression; the wrapping call that
                // applies it to the def/class is the single-positional one peeled here.
                Expr::Call { func, args, kwargs, star, kwstar }
                    if args.len() == 1
                        && kwargs.is_empty()
                        && star.is_none()
                        && kwstar.is_none() =>
                {
                    decorators.push(*func);
                    cur = args[0];
                }
                Expr::MakeFunction { code, defaults } => {
                    break Decorated::Func(*code, defaults.clone());
                }
                Expr::BuildClass { name, bases, code } => {
                    break Decorated::Class(*name, *bases, *code);
                }
                _ => return false,
            }
        };
        if decorators.is_empty() {
            return false;
        }
        match bottom {
            Decorated::Func(code, defaults) => {
                let Some(nested) = self.nested_code(code) else {
                    return false;
                };
                let name = nested.name.to_string();
                // `name = deco(MAKE_FUNCTION(code))` is always a decorated def: a
                // MAKE_FUNCTION creates the function inline, so the store target IS the
                // def's name (`@deco def name`). The obfuscator rewrites the code object's
                // co_name to `<dictcomp>`/`<genexpr>`/`unknown_N`/other junk, so it cannot
                // be matched against the target -- trust a simple-name target and let
                // `function_def` rename the header to it. Excluded: a `<lambda>` (rendered
                // as an assignment, not a def, so `@deco` could not attach), a genuine
                // comprehension body (`.0` arg, no standalone def form), and a non-name
                // target (`x.attr = deco(...)`, `x[0] = ...`), which has no `@deco def`.
                let target_is_name = matches!(
                    target,
                    LValue::Local(_) | LValue::Deref(_) | LValue::Name(_) | LValue::Global(_)
                );
                let is_decorated_def =
                    target_is_name && name != "<lambda>" && !super::is_comprehension_body(&nested);
                if !is_decorated_def {
                    return false;
                }
                self.emit_decorators(&decorators);
                self.function_def(target, code, &defaults);
                true
            }
            Decorated::Class(name, bases, code) => {
                // A decorated class binds to its own name; require the store target to
                // match the class name so an ordinary `x = deco(SomeClass)` is not
                // mis-rendered as a class definition.
                let Expr::Const(name_const) = self.arena.get(name) else {
                    return false;
                };
                let Some(class_name) = self.const_string(*name_const) else {
                    return false;
                };
                if self.lvalue(target) != sanitize_identifier(&class_name) {
                    return false;
                }
                self.emit_decorators(&decorators);
                self.class_def(name, bases, code);
                true
            }
        }
    }

    /// Emits the `@decorator` lines for a decorated def/class. Decorators are listed
    /// outermost-first, which is top-to-bottom source order.
    fn emit_decorators(&mut self, decorators: &[ValueId]) {
        let lines: Vec<String> =
            decorators.iter().map(|d| format!("@{}", self.expr(*d, 0))).collect();
        for line in lines {
            self.line(&line);
        }
    }

    /// Emits a nested `def` by recursively decompiling its code constant and
    /// indenting the result under the current block.
    /// Emits a syntactically-valid stub for a `def` that could not be recovered: a
    /// one-line `def <name>(): __unrecovered__  # <reason>`. A bare `__unrecovered__` would
    /// be invalid right after a decorator line (which must be followed by a `def`/`class`),
    /// so this keeps the whole-module form recompilable while still carrying the marker, the
    /// real name, and the failure reason (so a preserved class body documents why each
    /// method was lost). A non-name target (`x.attr = ...`) has no `def` form, so it stays a
    /// bare marker line (it is never decorated).
    fn unrecovered_def_stub(&mut self, target: &LValue, reason: &str) {
        match target {
            LValue::Name(_) | LValue::Global(_) | LValue::Local(_) | LValue::Deref(_) => {
                let name = self.lvalue(target);
                self.line(&format!("def {}(): {}  # {}", name, UNRECOVERED, reason));
            }
            _ => self.line(&format!("{}  # {}", UNRECOVERED, reason)),
        }
    }

    fn function_def(&mut self, target: &LValue, code: ConstId, defaults: &[ValueId]) {
        let nested = match self.nested_code(code) {
            Some(nested) => nested,
            None => {
                self.unrecovered_def_stub(target, "code object unavailable");
                return;
            }
        };
        // A lambda bound to a name (`f = lambda ...:`) reaches here as a stored
        // function; render it as an assignment rather than a `def`.
        if nested.name.to_string() == "<lambda>" {
            let lambda = self.lambda_expr(code, defaults);
            let line = format!("{} = {}", self.lvalue(target), lambda);
            self.line(&line);
            return;
        }
        // The obfuscator renames a method's own code object to a `<comprehension>`
        // form (`<dictcomp>`, `<genexpr>`, ...) to mislead decompilers, but it is a
        // real function: a genuine comprehension/generator body takes the implicit
        // `.0` argument, which these do not, and the method is still stored at its
        // real name. Emit a `def` under the store target rather than the obfuscated
        // co_name. A genuine comprehension body (with `.0`) has no standalone `def`
        // form, so it stays unrecovered.
        let obfuscated_name = nested.name.to_string().starts_with('<');
        let renamed_method = obfuscated_name && !super::is_comprehension_body(&nested);
        if obfuscated_name && !renamed_method {
            self.unrecovered_def_stub(target, "unrecoverable comprehension body");
            return;
        }
        // A function whose (de-mangled) co_name differs from its store target was renamed
        // by the obfuscator -- emit the `def` under the store target, the real name. This
        // covers a method renamed to `<dictcomp>` and one renamed to a `unknown_N`
        // placeholder (a decorated def/closure whose name survives only at the store).
        // Only when the target is a plain name: `Cls.m = func` / `d[k] = func` are
        // assignments, not defs, and must keep the co_name to stay valid (no `def Cls.m`).
        let target_name = self.lvalue(target);
        let target_is_name = matches!(
            target,
            LValue::Local(_) | LValue::Deref(_) | LValue::Name(_) | LValue::Global(_)
        );
        let needs_rename = renamed_method
            || (target_is_name
                && strip_orig_suffix(&sanitize_identifier(&nested.name.to_string())) != target_name);
        // Default values are evaluated in this (enclosing) scope, so render them
        // here and inject them into the nested signature.
        let defaults: Vec<String> = defaults.iter().map(|d| self.expr(*d, 0)).collect();
        match super::decompile_function_with_defaults(nested, &defaults) {
            Ok(source) => {
                let source = if needs_rename {
                    rename_def_header(&source, &target_name).unwrap_or(source)
                } else {
                    source
                };
                self.emit_reindented(&source);
            }
            Err(err) => self.unrecovered_def_stub(target, &err.to_string()),
        }
    }

    /// Emits a `class name(bases):` by decompiling its body code object, dropping
    /// the `__module__ = __name__` boilerplate and the trailing `return locals()`,
    /// and indenting the result under the current block.
    fn class_def(&mut self, name: ValueId, bases: ValueId, code: ConstId) {
        let Some(header) = self.class_header(name, bases) else {
            self.line(UNRECOVERED);
            return;
        };
        let body_code = match self.nested_code(code) {
            Some(nested) => nested,
            None => {
                // Keep the `class name(bases):` header so a decorated class whose body is
                // unrecoverable still forms a valid one-line stub (a bare marker would
                // dangle after the `@decorator`), preserving the class wrapper.
                self.line(&format!("{} {}  # code object unavailable", header, UNRECOVERED));
                return;
            }
        };
        match class_body_source(body_code) {
            Ok(body) => {
                self.line(&header);
                // The body is rendered at one indent level; `emit_reindented` adds the
                // current indent on top (nesting it under the class) while leaving any
                // docstring interior verbatim.
                self.emit_reindented(&body);
            }
            // One-line stub keeps the wrapper and stays valid after a decorator.
            Err(err) => self.line(&format!("{} {}  # {}", header, UNRECOVERED, err)),
        }
    }

    /// Builds the `class name(bases):` header, or `None` if the name is not a
    /// constant string.
    fn class_header(&self, name: ValueId, bases: ValueId) -> Option<String> {
        let Expr::Const(name_const) = self.arena.get(name) else {
            return None;
        };
        let name = sanitize_identifier(&self.const_string(*name_const)?);
        // Non-empty base lists are built with BUILD_TUPLE; an empty one is the
        // empty-tuple constant the compiler loads for `class C:` / `class C():`.
        let bases = match self.arena.get(bases) {
            Expr::Tuple(items) => items
                .iter()
                .map(|item| self.expr(*item, 0))
                .collect::<Vec<_>>()
                .join(", "),
            Expr::Const(c) => match self.code.consts.get(c.0 as usize) {
                Some(Obj::Tuple(items)) => {
                    items.read().unwrap().iter().map(render_obj).collect::<Vec<_>>().join(", ")
                }
                _ => return None,
            },
            _ => return None,
        };
        Some(if bases.is_empty() {
            format!("class {}:", name)
        } else {
            format!("class {}({}):", name, bases)
        })
    }

    /// Whether `v` is the `None` constant. Used to render the bare `exec code` form
    /// (the compiler fills the omitted globals/locals slots with `None`).
    fn is_none_const(&self, v: ValueId) -> bool {
        match self.arena.get(v) {
            Expr::Const(c) => matches!(self.code.consts.get(c.0 as usize), Some(Obj::None)),
            _ => false,
        }
    }

    /// Whether `id` is an integer (`Obj::Long`) literal. Such a value needs
    /// parentheses as an attribute target, since `6.attr` lexes `6.` as a float.
    fn is_int_literal(&self, id: ValueId) -> bool {
        match self.arena.get(id) {
            Expr::Const(c) => matches!(self.code.consts.get(c.0 as usize), Some(Obj::Long(_))),
            _ => false,
        }
    }

    /// The value of a string constant, if it is one.
    fn const_string(&self, c: ConstId) -> Option<String> {
        match self.code.consts.get(c.0 as usize) {
            Some(Obj::String(s)) => {
                Some(String::from_utf8_lossy(s.read().unwrap().as_slice()).into_owned())
            }
            _ => None,
        }
    }

    /// Renders a suite at one deeper indent level, emitting `pass` if empty.
    fn block(&mut self, stmts: &[Stmt]) {
        self.indent += 1;
        if stmts.is_empty() {
            self.line("pass");
        }
        self.emit_stmts(stmts);
        self.indent -= 1;
    }

    /// A statement that spans an indented block of its own. These get a blank line
    /// separating them from neighbouring statements at the same level so the output
    /// reads with the visual spacing of hand-written Python.
    fn is_compound(stmt: &Stmt) -> bool {
        matches!(
            stmt,
            Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::WhileElse { .. }
                | Stmt::Loop { .. }
                | Stmt::For { .. }
                | Stmt::ForElse { .. }
                | Stmt::Try { .. }
                | Stmt::With { .. }
                | Stmt::TryFinally { .. }
                | Stmt::FunctionDef { .. }
                | Stmt::ClassDef { .. }
        )
    }

    /// Emits a sequence of statements, inserting a blank line between two of them
    /// whenever either is a compound block (an `if`/`for`/`def`/etc.). This keeps a
    /// run of simple statements tight while giving functions and control-flow blocks
    /// breathing room above and below.
    fn emit_stmts(&mut self, stmts: &[Stmt]) {
        let mut prev: Option<&Stmt> = None;
        for stmt in stmts {
            if let Some(prev) = prev {
                if Self::is_compound(prev) || Self::is_compound(stmt) {
                    self.line("");
                }
            }
            self.stmt(stmt);
            prev = Some(stmt);
        }
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign(target, value) => {
                // A decorated `def` compiles to `name = deco(<make_function>)`; emit
                // it as `@deco` + `def` rather than an assignment when it matches.
                if !self.try_decorated_def(target, *value) {
                    let line = format!("{} = {}", self.lvalue(target), self.expr(*value, 0));
                    self.line(&line);
                }
            }
            Stmt::AugAssign(target, op, value) => {
                let line =
                    format!("{} {}= {}", self.lvalue(target), op.symbol(), self.expr(*value, 0));
                self.line(&line);
            }
            Stmt::Delete(target) => {
                let line = format!("del {}", self.lvalue(target));
                self.line(&line);
            }
            Stmt::Expr(value) => {
                let line = self.expr(*value, 0);
                self.line(&line);
            }
            Stmt::Return(value) => match value {
                // A generator may only `return` without a value; the trailing
                // `LOAD_CONST None; RETURN_VALUE` every function ends with is the
                // implicit fall-off-the-end, so render it bare.
                Some(value) if !self.code.flags.contains(CodeFlags::GENERATOR) => {
                    let line = format!("return {}", self.expr(*value, 0));
                    self.line(&line);
                }
                _ => self.line("return"),
            },
            Stmt::Print { values, newline, stream } => {
                let mut line = String::from("print");
                if let Some(stream) = stream {
                    line.push_str(&format!(" >>{}", self.expr(*stream, prec::ATOM)));
                    if !values.is_empty() {
                        line.push(',');
                    }
                }
                line.push(' ');
                let rendered: Vec<String> = values.iter().map(|v| self.expr(*v, 0)).collect();
                line.push_str(&rendered.join(", "));
                if !newline {
                    line.push(',');
                }
                self.line(line.trim_end());
            }
            Stmt::Exec { code, globals, locals } => {
                let code_s = self.expr(*code, 0);
                let line = if self.is_none_const(*globals) {
                    format!("exec {}", code_s)
                } else if let Some(locals) = locals {
                    format!("exec {} in {}, {}", code_s, self.expr(*globals, 0), self.expr(*locals, 0))
                } else {
                    format!("exec {} in {}", code_s, self.expr(*globals, 0))
                };
                self.line(&line);
            }
            Stmt::FunctionDef { target, code, defaults } => {
                self.function_def(target, *code, defaults)
            }
            Stmt::ClassDef { name, bases, code, .. } => self.class_def(*name, *bases, *code),
            Stmt::Raise(args) => {
                let rendered: Vec<String> = args.iter().map(|a| self.expr(*a, 0)).collect();
                if rendered.is_empty() {
                    self.line("raise");
                } else {
                    self.line(&format!("raise {}", rendered.join(", ")));
                }
            }
            Stmt::Assert { test, msg } => {
                // `assert` binds its test at the precedence of a bare expression; a
                // message, when present, is a second comma-separated expression.
                match msg {
                    Some(m) => self.line(&format!("assert {}, {}", self.expr(*test, 0), self.expr(*m, 0))),
                    None => self.line(&format!("assert {}", self.expr(*test, 0))),
                }
            }
            Stmt::While { cond, negated, body } => {
                let rendered = if *negated {
                    format!("while not {}:", self.expr(*cond, prec::UNARY))
                } else {
                    format!("while {}:", self.expr(*cond, 0))
                };
                self.line(&rendered);
                self.block(body);
            }
            Stmt::WhileElse { cond, negated, body, els } => {
                let rendered = if *negated {
                    format!("while not {}:", self.expr(*cond, prec::UNARY))
                } else {
                    format!("while {}:", self.expr(*cond, 0))
                };
                self.line(&rendered);
                self.block(body);
                if !els.is_empty() {
                    self.line("else:");
                    self.block(els);
                }
            }
            Stmt::Loop { body } => {
                self.line("while True:");
                self.block(body);
            }
            Stmt::For { target, iter, body } => {
                let rendered = format!("for {} in {}:", self.lvalue(target), self.expr(*iter, 0));
                self.line(&rendered);
                self.block(body);
            }
            Stmt::ForElse { target, iter, body, els } => {
                let rendered = format!("for {} in {}:", self.lvalue(target), self.expr(*iter, 0));
                self.line(&rendered);
                self.block(body);
                // An empty else clause (its region held only dead code, pruned by cleanup)
                // is a no-op; emit a plain `for` rather than a redundant `else: pass`.
                if !els.is_empty() {
                    self.line("else:");
                    self.block(els);
                }
            }
            Stmt::Try { body, handlers } => {
                self.line("try:");
                self.block(body);
                for handler in handlers {
                    let header = match (&handler.exc_type, &handler.name) {
                        (None, _) => "except:".to_string(),
                        (Some(exc), None) => format!("except {}:", self.expr(*exc, 0)),
                        // A tuple target is only valid in the comma form
                        // `except E, (a, b):`; `except E as (a, b):` is a SyntaxError
                        // in Python 2.7. A simple name keeps the `as` form so existing
                        // output stays byte-identical.
                        (Some(exc), Some(name @ LValue::Tuple(_))) => {
                            format!("except {}, ({}):", self.expr(*exc, 0), self.lvalue(name))
                        }
                        (Some(exc), Some(name)) => {
                            format!("except {} as {}:", self.expr(*exc, 0), self.lvalue(name))
                        }
                    };
                    self.line(&header);
                    self.block(&handler.body);
                }
            }
            Stmt::With { context, target, body } => {
                let header = match target {
                    Some(target) => {
                        format!("with {} as {}:", self.expr(*context, 0), self.lvalue(target))
                    }
                    None => format!("with {}:", self.expr(*context, 0)),
                };
                self.line(&header);
                self.block(body);
            }
            Stmt::TryFinally { body, finalbody } => {
                self.line("try:");
                self.block(body);
                self.line("finally:");
                self.block(finalbody);
            }
            Stmt::Import { module, target, level } => {
                self.line(&self.import_line(*module, target, *level))
            }
            Stmt::FromImport { module, names, star, level } => {
                self.line(&self.from_import_line(*module, names, *star, *level))
            }
            // These appear only inside a comprehension code object, where the
            // comprehension folder consumes them; reaching emission means a shape
            // the folder did not recognise, so mark it unrecovered.
            Stmt::SetAdd(_) | Stmt::DictAdd { .. } => {self.line(UNRECOVERED) }
            Stmt::Break => self.line("break"),
            Stmt::Continue => self.line("continue"),
            Stmt::If { cond, then, els } => {
                if then.is_empty() && !els.is_empty() {
                    let line = format!("if not {}:", self.expr(*cond, prec::UNARY));
                    self.line(&line);
                    self.block(els);
                } else {
                    let line = format!("if {}:", self.expr(*cond, 0));
                    self.line(&line);
                    self.block(then);
                    self.emit_else_chain(then, els);
                }
            }
        }
    }

    /// Emits the `else` part of an `if` whose `then` branch was just printed. An empty
    /// `else` prints nothing; a `then` that always transfers control flattens the else
    /// body to this level (the `if guard: return ...` idiom); an else that is a single
    /// `if` collapses to `elif` rather than nesting; otherwise a plain `else:`.
    fn emit_else_chain(&mut self, then: &[Stmt], els: &[Stmt]) {
        if els.is_empty() {
            return;
        }
        if then.last().is_some_and(is_terminal_stmt) {
            // The `then` branch always leaves the block (return/raise/break/continue),
            // so the `else` only adds nesting; emit its body at this level instead.
            self.line("");
            self.emit_stmts(els);
            return;
        }
        // `else: if c: ...` is an `elif` -- collapse it, and recurse so a chain of them
        // renders flat. Only when the inner `if` is the whole else body and takes the
        // ordinary `if c:` form (an empty-then `if not c:` keeps the plain `else:`).
        if let [Stmt::If { cond, then: inner_then, els: inner_els }] = els {
            if !inner_then.is_empty() {
                let line = format!("elif {}:", self.expr(*cond, 0));
                self.line(&line);
                self.block(inner_then);
                self.emit_else_chain(inner_then, inner_els);
                return;
            }
        }
        self.line("else:");
        self.block(els);
    }

    pub(crate) fn lvalue(&self, target: &LValue) -> String {
        match target {
            LValue::Local(var) => self.varname(*var),
            LValue::Deref(deref) => self.derefname(*deref),
            LValue::Name(name) | LValue::Global(name) => self.name(*name),
            LValue::Attr(obj, name) => {
                format!("{}.{}", self.expr(*obj, prec::ATOM), self.name(*name))
            }
            LValue::Subscript(container, key) => {
                format!("{}[{}]", self.expr(*container, prec::ATOM), self.subscript_key(*key))
            }
            LValue::Tuple(items) => {
                let rendered: Vec<String> = items
                    .iter()
                    .map(|i| match i {
                        // A nested tuple target needs parentheses: `(a, b), c = ...`
                        // unpacks two items, not the three of `a, b, c = ...`.
                        LValue::Tuple(_) => format!("({})", self.lvalue(i)),
                        _ => self.lvalue(i),
                    })
                    .collect();
                rendered.join(", ")
            }
        }
    }

    /// Renders an expression, wrapping in parentheses when its precedence is
    /// below `parent` (the precedence required by the surrounding context).
    fn expr(&self, id: ValueId, parent: u8) -> String {
        let (text, prec) = self.expr_prec(id);
        if prec < parent {
            format!("({})", text)
        } else {
            text
        }
    }

    /// Renders a subscript index. A tuple index is emitted WITHOUT its parentheses
    /// (`x[a, b]`, not `x[(a, b)]`): the two are equivalent, and the paren-free form is
    /// required for an extended slice, whose slice elements (`x[:42, ..., :24]`) are a
    /// SyntaxError inside a parenthesised tuple.
    fn subscript_key(&self, key: ValueId) -> String {
        if let Expr::Tuple(items) = self.arena.get(key) {
            let rendered: Vec<String> = items.iter().map(|i| self.expr(*i, 0)).collect();
            return if rendered.len() == 1 {
                format!("{},", rendered[0])
            } else {
                rendered.join(", ")
            };
        }
        self.expr(key, 0)
    }

    fn expr_prec(&self, id: ValueId) -> (String, u8) {
        match self.arena.get(id) {
            Expr::Const(c) => (self.render_const(*c), prec::ATOM),
            Expr::Local(var) => (self.varname(*var), prec::ATOM),
            Expr::Deref(deref) => (self.derefname(*deref), prec::ATOM),
            Expr::Global(name) | Expr::Name(name) => (self.name(*name), prec::ATOM),
            Expr::Attr(obj, name) => {
                // A bare integer literal as the attribute target lexes as a float
                // (`6.__index__` scans `6.` then `__index__`), so parenthesise it:
                // `(6).__index__()`.
                let obj_text = if self.is_int_literal(*obj) {
                    format!("({})", self.expr(*obj, prec::ATOM))
                } else {
                    self.expr(*obj, prec::ATOM)
                };
                (format!("{}.{}", obj_text, self.name(*name)), prec::ATOM)
            }
            Expr::Subscript(container, key) => (
                format!("{}[{}]", self.expr(*container, prec::ATOM), self.subscript_key(*key)),
                prec::ATOM,
            ),
            // A slice renders as `lower:upper`, each bound omitted when absent. Only
            // valid inside a subscript, which supplies the brackets. An extended slice
            // (`x[:42, ...]`) is compiled with BUILD_SLICE, which pushes an explicit
            // `None` constant for each missing bound rather than leaving it absent, so a
            // bound that is the `None` const is also omitted (`None:42` is a SyntaxError).
            Expr::Slice { lower, upper, step } => {
                let bound = |b: &Option<ValueId>| match b {
                    Some(id) if !self.is_none_const(*id) => self.expr(*id, 0),
                    _ => String::new(),
                };
                let text = match step {
                    Some(step) if !self.is_none_const(*step) => {
                        format!("{}:{}:{}", bound(lower), bound(upper), self.expr(*step, 0))
                    }
                    // A `None` step from BUILD_SLICE is the absent step (`x[a:b]`).
                    _ => format!("{}:{}", bound(lower), bound(upper)),
                };
                (text, prec::ATOM)
            }
            // An in-place op normally becomes an augmented assignment; if one is
            // ever used as a value it renders like the plain binary operation.
            Expr::BinOp(op, lhs, rhs) | Expr::Inplace(op, lhs, rhs) => {
                let p = binop_prec(*op);
                // Left-associative for everything except power; render the right
                // operand one level tighter so same-precedence chains parenthesise.
                let (lp, rp) = if *op == BinOp::Power {
                    (p + 1, p)
                } else {
                    (p, p + 1)
                };
                (
                    format!("{} {} {}", self.expr(*lhs, lp), op.symbol(), self.expr(*rhs, rp)),
                    p,
                )
            }
            Expr::Unary(op, operand) => {
                // `not` binds far looser than the arithmetic unaries, so report and
                // render it at NOT: `x % not y` then parenthesises to `x % (not y)`
                // (a Python 2.7 SyntaxError otherwise), while `not a == b` and
                // `not not x` stay paren-free.
                let level = if *op == UnaryOp::Not { prec::NOT } else { prec::UNARY };
                (format!("{}{}", op.symbol(), self.expr(*operand, level)), level)
            }
            Expr::Compare(op, lhs, rhs) => (
                format!(
                    "{} {} {}",
                    self.expr(*lhs, prec::COMPARE + 1),
                    op.symbol(),
                    self.expr(*rhs, prec::COMPARE + 1)
                ),
                prec::COMPARE,
            ),
            Expr::Ternary { cond, then, otherwise } => (
                format!(
                    "{} if {} else {}",
                    self.expr(*then, prec::OR),
                    self.expr(*cond, prec::OR),
                    self.expr(*otherwise, prec::TERNARY)
                ),
                prec::TERNARY,
            ),
            Expr::BoolOp(kind, operands) => {
                let level = match kind {
                    BoolKind::And => prec::AND,
                    BoolKind::Or => prec::OR,
                };
                // Group consecutive comparisons that share their boundary operand
                // into the chained form `a < b < c` they were compiled from; render
                // everything else as an ordinary operand.
                let mut parts = Vec::new();
                let mut i = 0;
                while i < operands.len() {
                    if let Some((chained, consumed)) = self.chained_comparison(*kind, &operands[i..])
                    {
                        parts.push(chained);
                        i += consumed;
                    } else {
                        parts.push(self.expr(operands[i], level + 1));
                        i += 1;
                    }
                }
                // A single part means the whole operator folded into one chained
                // comparison, which binds at comparison precedence, not boolean.
                if parts.len() == 1 {
                    (parts.pop().unwrap(), prec::COMPARE)
                } else {
                    (parts.join(&format!(" {} ", kind.symbol())), level)
                }
            }
            Expr::Call { func, args, kwargs, star, kwstar } => {
                if let Some(comp) = self.comprehension_call(*func, args, kwargs, *star, *kwstar) {
                    return (comp, prec::ATOM);
                }
                let mut rendered: Vec<String> = args.iter().map(|a| self.expr(*a, 0)).collect();
                for (key, value) in kwargs {
                    rendered.push(format!("{}={}", self.kwarg_name(*key), self.expr(*value, 0)));
                }
                if let Some(star) = star {
                    rendered.push(format!("*{}", self.expr(*star, prec::UNARY)));
                }
                if let Some(kwstar) = kwstar {
                    rendered.push(format!("**{}", self.expr(*kwstar, prec::UNARY)));
                }
                (
                    format!("{}({})", self.expr(*func, prec::ATOM), rendered.join(", ")),
                    prec::ATOM,
                )
            }
            Expr::Tuple(items) => {
                let rendered: Vec<String> = items.iter().map(|i| self.expr(*i, 0)).collect();
                let body = if items.len() == 1 {
                    format!("{},", rendered[0])
                } else {
                    rendered.join(", ")
                };
                (format!("({})", body), prec::ATOM)
            }
            Expr::List(items) => {
                let rendered: Vec<String> = items.iter().map(|i| self.expr(*i, 0)).collect();
                (format!("[{}]", rendered.join(", ")), prec::ATOM)
            }
            Expr::Set(items) => {
                let rendered: Vec<String> = items.iter().map(|i| self.expr(*i, 0)).collect();
                (format!("set([{}])", rendered.join(", ")), prec::ATOM)
            }
            Expr::Dict(pairs) => {
                let rendered: Vec<String> = pairs
                    .iter()
                    .map(|(k, v)| format!("{}: {}", self.expr(*k, 0), self.expr(*v, 0)))
                    .collect();
                (format!("{{{}}}", rendered.join(", ")), prec::ATOM)
            }
            // An unconsumed unpack slot indicates a tuple-assignment shape the
            // unstacker did not fully match; mark it so the function is rejected.
            Expr::UnpackSlot | Expr::ClosureCell(_) => {(UNRECOVERED.to_string(), prec::ATOM) }
            // A `<lambda>` renders inline; a named function used as a value (an
            // undetected decorator) cannot, and is marked unrecovered. A lambda is the
            // lowest-precedence expression in Python (its `:` body extends to the end), so
            // report it at TERNARY level: as an operand of `or`/`and`/a binary op or a call
            // (`convert or lambda ...`, `(lambda: x)()`) it then parenthesises, while a
            // top-level value (`f = lambda ...`, `g(lambda ...)`, rendered at parent 0) does
            // not.
            Expr::MakeFunction { code, defaults } => (self.lambda_expr(*code, defaults), prec::TERNARY),
            Expr::Yield(value) => (format!("yield {}", self.expr(*value, prec::TERNARY)), prec::TERNARY),
            // Import values are consumed by the store or POP_TOP that completes the
            // statement; one reaching here is an import shape the unstacker did not
            // fully match (e.g. `import a.b as c`), so reject the function.
            Expr::Import { .. } | Expr::ImportFrom(_) => {(UNRECOVERED.to_string(), prec::ATOM) }
            // `LOAD_LOCALS` is the class namespace a class body returns. Inline
            // class recovery drops the trailing `return locals()`, so this is only
            // reached when a class body is decompiled on its own; render the builtin.
            Expr::Locals => ("locals()".to_string(), prec::ATOM),
            // The class object is consumed by its store; one reaching here is a class
            // shape that was not fully matched.
            Expr::BuildClass { .. } => {(UNRECOVERED.to_string(), prec::ATOM) }
            Expr::ListComp { element, clauses } => {
                let mut text = format!("[{}", self.expr(*element, 0));
                for clause in clauses {
                    match clause {
                        ListClause::For { target, iter } => text.push_str(&format!(
                            " for {} in {}",
                            self.lvalue(target),
                            self.expr(*iter, 0)
                        )),
                        ListClause::If(cond) => {
                            text.push_str(&format!(" if {}", self.expr(*cond, prec::OR)))
                        }
                    }
                }
                text.push(']');
                (text, prec::ATOM)
            }
        }
    }

    /// Renders a call of the form `(<comp code>)(<iter>)` as an inline
    /// comprehension. CPython 2.7 compiles a generator/set/dict comprehension to a
    /// nested code object invoked with the outer iterable; this re-inlines it.
    /// Returns `None` when the call is not a recognised comprehension, so the
    /// caller renders an ordinary call.
    fn comprehension_call(
        &self,
        func: ValueId,
        args: &[ValueId],
        kwargs: &[(ValueId, ValueId)],
        star: Option<ValueId>,
        kwstar: Option<ValueId>,
    ) -> Option<String> {
        if args.len() != 1 || !kwargs.is_empty() || star.is_some() || kwstar.is_some() {
            return None;
        }
        let Expr::MakeFunction { code: const_id, defaults } = self.arena.get(func) else {
            return None;
        };
        if !defaults.is_empty() {
            return None;
        };
        let comp_code = match self.code.consts.get(const_id.0 as usize) {
            Some(Obj::Code(code)) => Arc::new(code.read().unwrap().clone()),
            _ => return None,
        };
        // comprehension_parts validates the `.0` comprehension signature, so an
        // ordinary nested-function call returns None and renders normally. The
        // obfuscator's numeric rename of the comprehension co_name is irrelevant.
        let parts = comprehension_parts(comp_code).ok()?;
        let iter = self.expr(args[0], 0);
        let body = format!("{}{}{}", parts.head, iter, parts.tail);
        Some(match parts.kind {
            CompKind::Gen => format!("({})", body),
            CompKind::List => format!("[{}]", body),
            CompKind::Set | CompKind::Dict => format!("{{{}}}", body),
        })
    }

    /// If `operands` begins with two or more comparisons where each shares its
    /// right operand with the next one's left operand (the same value id, produced
    /// by a chained comparison's `DUP_TOP`), renders that run as `a op1 b op2 c` and
    /// returns it with the number of operands consumed. Returns `None` otherwise, so
    /// an ordinary `and`/`or` of comparisons is unaffected.
    fn chained_comparison(&self, kind: BoolKind, operands: &[ValueId]) -> Option<(String, usize)> {
        if kind != BoolKind::And {
            return None;
        }
        let compare = |id: ValueId| match self.arena.get(id) {
            Expr::Compare(op, lhs, rhs) => Some((*op, *lhs, *rhs)),
            _ => None,
        };
        let mut chain = vec![compare(operands[0])?];
        for &operand in &operands[1..] {
            let next = compare(operand)?;
            // The next comparison must continue the chain from the previous bound.
            if chain.last().unwrap().2 != next.1 {
                break;
            }
            chain.push(next);
        }
        if chain.len() < 2 {
            return None;
        }
        let mut text = self.expr(chain[0].1, prec::COMPARE + 1);
        for (op, _lhs, rhs) in &chain {
            text.push_str(&format!(" {} {}", op.symbol(), self.expr(*rhs, prec::COMPARE + 1)));
        }
        Some((text, chain.len()))
    }

    fn varname(&self, var: VarId) -> String {
        match self.code.varnames.get(var.0 as usize) {
            Some(name) => sanitize_identifier(&name.to_string()),
            None => format!("var{}", var.0),
        }
    }

    /// The raw `co_names` entry, without identifier sanitization. Module paths and
    /// imported attribute names are real Python identifiers (often dotted), so they
    /// must keep their dots rather than be mangled like deobfuscated locals.
    fn raw_name(&self, name: NameId) -> Option<String> {
        self.code.names.get(name.0 as usize).map(|n| n.to_string())
    }

    /// The leading-dot prefix of a relative import. The `IMPORT_NAME` level operand
    /// is a positive int for an explicit relative import (the dot count) and `-1`/`0`
    /// for an absolute one; a missing or non-int level yields no dots, preserving the
    /// prior absolute-only behaviour. A level outside the plausible package-nesting
    /// range is treated as no dots too: it cannot be a real relative import, and the
    /// bound keeps a corrupt operand from driving an unbounded `repeat` allocation.
    fn import_dots(&self, level: Option<ConstId>) -> String {
        let count = match level.and_then(|c| self.code.consts.get(c.0 as usize)) {
            Some(Obj::Long(v)) => v.read().unwrap().to_i64().unwrap_or(0),
            _ => 0,
        };
        if (1..=32).contains(&count) {
            ".".repeat(count as usize)
        } else {
            String::new()
        }
    }

    /// Renders an `import module [as target]` statement. No `as` clause is emitted
    /// when the bound name matches the module's top-level component.
    fn import_line(&self, module: NameId, target: &LValue, level: Option<ConstId>) -> String {
        let Some(module) = self.raw_name(module) else {
            return UNRECOVERED.to_string();
        };
        let module = format!("{}{}", self.import_dots(level), module);
        let head = module.split('.').next().unwrap_or(&module);
        match self.import_binding(target) {
            Some(bind) if bind == head => format!("import {}", module),
            Some(bind) => format!("import {} as {}", module, sanitize_identifier(&bind)),
            None => UNRECOVERED.to_string(),
        }
    }

    /// Renders a `from module import ...` statement (or `from module import *`).
    fn from_import_line(
        &self,
        module: NameId,
        names: &[(NameId, LValue)],
        star: bool,
        level: Option<ConstId>,
    ) -> String {
        let Some(module) = self.raw_name(module) else {
            return UNRECOVERED.to_string();
        };
        let dots = self.import_dots(level);
        // An empty module name with no leading dots is an unrecoverable relative
        // import (the level operand was lost), and `from  import x` is a syntax
        // error -- reject rather than emit invalid source. `from . import x` has the
        // empty name but a positive level, so the dots supply a valid module path.
        if module.is_empty() && dots.is_empty() {
            return UNRECOVERED.to_string();
        }
        let module = format!("{}{}", dots, module);
        if star {
            return format!("from {} import *", module);
        }
        let parts: Vec<String> = names
            .iter()
            .map(|(src, target)| match (self.raw_name(*src), self.import_binding(target)) {
                (Some(src), Some(bind)) if src == bind => src,
                (Some(src), Some(bind)) => format!("{} as {}", src, sanitize_identifier(&bind)),
                _ => UNRECOVERED.to_string(),
            })
            .collect();
        format!("from {} import {}", module, parts.join(", "))
    }

    /// The raw bound name of a simple import target (`STORE_NAME`/`STORE_FAST`/
    /// `STORE_DEREF`). A deref target is a closure cell -- a conditional import bound to
    /// a name a nested function captures, e.g. `try: from hashlib import md5 as _hash_new`
    /// where `_hash_new` is read by an inner constructor.
    fn import_binding(&self, target: &LValue) -> Option<String> {
        match target {
            LValue::Name(name) | LValue::Global(name) => {
                self.code.names.get(name.0 as usize).map(|n| n.to_string())
            }
            LValue::Local(var) => self.code.varnames.get(var.0 as usize).map(|n| n.to_string()),
            LValue::Deref(deref) => self.raw_derefname(*deref),
            _ => None,
        }
    }

    /// The raw (unsanitized) name behind a `LOAD_DEREF`/`STORE_DEREF` index, resolved
    /// against `co_cellvars` then `co_freevars` -- the unsanitized companion to
    /// [`derefname`], used where the caller compares or sanitizes the name itself.
    fn raw_derefname(&self, deref: DerefId) -> Option<String> {
        let index = deref.0 as usize;
        let cells = self.code.cellvars.len();
        if index < cells {
            self.code.cellvars.get(index)
        } else {
            self.code.freevars.get(index - cells)
        }
        .map(|n| n.to_string())
    }

    fn name(&self, name: NameId) -> String {
        match self.code.names.get(name.0 as usize) {
            Some(name) => sanitize_identifier(&name.to_string()),
            None => format!("name{}", name.0),
        }
    }

    /// Resolves a `LOAD_DEREF`/`STORE_DEREF` index against `co_cellvars` followed
    /// by `co_freevars`.
    fn derefname(&self, deref: DerefId) -> String {
        let index = deref.0 as usize;
        let cells = self.code.cellvars.len();
        let resolved = if index < cells {
            self.code.cellvars.get(index)
        } else {
            self.code.freevars.get(index - cells)
        };
        match resolved {
            Some(name) => sanitize_identifier(&name.to_string()),
            None => format!("deref{}", deref.0),
        }
    }

    /// Renders a keyword-argument name. `CALL_FUNCTION` keys are always constant
    /// strings; fall back to an inline form if that ever does not hold.
    fn kwarg_name(&self, key: ValueId) -> String {
        if let Expr::Const(c) = self.arena.get(key) {
            if let Some(Obj::String(s)) = self.code.consts.get(c.0 as usize) {
                return String::from_utf8_lossy(s.read().unwrap().as_slice()).into_owned();
            }
        }
        // A keyword argument's key is always a string constant in valid CPython 2.7.
        // Corrupted/obfuscated residue can leave a non-string here; emitting it would
        // produce invalid source like `f(**{2}=x)`, so surface it as unrecoverable
        // (the caller rejects a body containing this marker).
        UNRECOVERED.to_string()
    }

    fn render_const(&self, c: ConstId) -> String {
        match self.code.consts.get(c.0 as usize) {
            Some(obj) => render_obj(obj),
            None => format!("const{}", c.0),
        }
    }
}

/// Which comprehension a recovered nested code object represents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompKind {
    Gen,
    List,
    Set,
    Dict,
}

/// One clause of a comprehension: a `for` over an iterable or an `if` filter.
enum CompClause {
    For { target: LValue, iter: ValueId },
    If(ValueId),
    /// A negated filter `if not cond`, from `if cond: <skip> else: <element>`.
    IfNot(ValueId),
    /// A disjunctive filter `if a or b or ...`, from the short-circuit `if a:
    /// <element> else: if b: <element> ...` the compiler emits for an `or` filter.
    IfAny(Vec<ValueId>),
}

/// A recovered comprehension over the nested code object's own arena.
struct RecognizedComp {
    kind: CompKind,
    element: ValueId,
    /// The key expression for a dict comprehension; `None` otherwise.
    key: Option<ValueId>,
    clauses: Vec<CompClause>,
}

/// Rendered comprehension text split around the outermost iterable, which lives
/// in the caller's scope: the full source is `head + <outer iter> + tail`.
struct CompParts {
    kind: CompKind,
    head: String,
    tail: String,
}

/// Decompiles a class body code object into its rendered suite, dropping the
/// `__module__ = __name__` boilerplate and the trailing `return locals()`.
fn class_body_source(body_code: Arc<Code>) -> Result<String, super::IrError> {
    let structured = super::DecodedFunction::decode(body_code)?.structure()?;
    let mut stmts: Vec<Stmt> = structured.body.clone();
    if matches!(stmts.last(), Some(Stmt::Return(_))) {
        stmts.pop();
    }
    // A class body cannot legally contain a `return` (its methods are separate code
    // objects, not inlined here), so the only one is the implicit `return locals()`
    // namespace return, dropped above. A `return` surviving anywhere in the tree
    // means the relinearizer split that return into a branch and the body was not
    // soundly recovered; reject rather than emit invalid `return locals()`.
    if contains_return(&stmts) {
        return Err(super::IrError::Incomplete);
    }
    stmts.retain(|stmt| !is_class_boilerplate(&structured.code, stmt));
    Ok(Emitter::new(&structured.code, &structured.arena).render_body(&stmts))
}

/// Whether any statement in the tree is a `return`. Used to reject a class body
/// whose implicit namespace return the relinearizer hoisted into a branch (see
/// [`class_body_source`]). Nested `def`/`class` bodies are separate code objects,
/// not inlined statements, so their returns are not visited here.
fn contains_return(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        Stmt::Return(_) => true,
        Stmt::If { then, els, .. } => contains_return(then) || contains_return(els),
        Stmt::While { body, .. }
        | Stmt::Loop { body }
        | Stmt::For { body, .. }
        | Stmt::With { body, .. } => contains_return(body),
        Stmt::ForElse { body, els, .. } | Stmt::WhileElse { body, els, .. } => {
            contains_return(body) || contains_return(els)
        }
        Stmt::Try { body, handlers } => {
            contains_return(body) || handlers.iter().any(|h| contains_return(&h.body))
        }
        Stmt::TryFinally { body, finalbody } => {
            contains_return(body) || contains_return(finalbody)
        }
        _ => false,
    })
}

/// Whether a statement unconditionally leaves its enclosing block, so a following
/// `else` is redundant and can be flattened away. An `if`/`else` qualifies when both
/// arms are present and each always leaves, so a chain of fully-returning branches
/// collapses level by level.
fn is_terminal_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break | Stmt::Continue => true,
        Stmt::If { then, els, .. } => {
            !then.is_empty()
                && !els.is_empty()
                && then.last().is_some_and(is_terminal_stmt)
                && els.last().is_some_and(is_terminal_stmt)
        }
        _ => false,
    }
}

/// Whether a class-body statement is compiler-inserted boilerplate (`__module__`
/// or `__qualname__` binding) rather than source the class actually declared.
fn is_class_boilerplate(code: &Code, stmt: &Stmt) -> bool {
    let (LValue::Name(name) | LValue::Global(name)) = (match stmt {
        Stmt::Assign(target, _) => target,
        _ => return false,
    }) else {
        return false;
    };
    matches!(
        code.names.get(name.0 as usize).map(|n| n.to_string()).as_deref(),
        Some("__module__") | Some("__qualname__")
    )
}

/// Decompiles a comprehension code object and renders it, leaving the outermost
/// iterable (the `.0` argument) as a hole for the caller to fill from its scope.
fn comprehension_parts(comp_code: Arc<Code>) -> Result<CompParts, super::IrError> {
    // A comprehension code object takes its iterable as the implicit `.0` argument;
    // require that signature so an ordinary nested call is not mistaken for one. The
    // obfuscator rewrites the `<genexpr>`/`<setcomp>`/`<dictcomp>` co_name to a
    // numeric one, so the kind is taken from structure, not the name: a generator
    // expression lowers normally (its `yield` needs no accumulator), while a set or
    // dict comprehension needs accumulator-aware lowering.
    if comp_code.varnames.first().map(|v| v.to_string()).as_deref() != Some(".0") {
        return Err(super::IrError::Incomplete);
    }
    let is_generator = comp_code.flags.contains(CodeFlags::GENERATOR);
    let decoded = super::DecodedFunction::decode(comp_code)?;
    let structured = if is_generator {
        decoded.structure()?
    } else {
        decoded.structure_comp()?
    };
    let recog =
        recognize_comprehension(&structured.arena, &structured.body).ok_or(super::IrError::Incomplete)?;
    // The first clause iterates the implicit `.0` argument; that iterable is
    // supplied by the caller, so it is omitted from the rendered text.
    let CompClause::For { target, iter } = &recog.clauses[0] else {
        return Err(super::IrError::Incomplete);
    };
    if !matches!(structured.arena.get(*iter), Expr::Local(VarId(0))) {
        return Err(super::IrError::Incomplete);
    }
    let emitter = Emitter::new(&structured.code, &structured.arena);
    let element = match recog.key {
        Some(key) => format!("{}: {}", emitter.expr(key, 0), emitter.expr(recog.element, 0)),
        None => emitter.expr(recog.element, 0),
    };
    let head = format!("{} for {} in ", element, emitter.lvalue(target));
    let mut tail = String::new();
    for clause in &recog.clauses[1..] {
        match clause {
            CompClause::For { target, iter } => tail.push_str(&format!(
                " for {} in {}",
                emitter.lvalue(target),
                emitter.expr(*iter, 0)
            )),
            // A comprehension `if` takes an `or_test`, so a ternary or lambda
            // condition must parenthesise; render at `or` precedence.
            CompClause::If(cond) => tail.push_str(&format!(" if {}", emitter.expr(*cond, prec::OR))),
            // `not` binds looser than comparison but tighter than `or`/`and`, so
            // parenthesise anything at `and` precedence or below.
            CompClause::IfNot(cond) => {
                tail.push_str(&format!(" if not {}", emitter.expr(*cond, prec::COMPARE)))
            }
            CompClause::IfAny(conds) => {
                let joined = conds
                    .iter()
                    .map(|c| emitter.expr(*c, prec::OR))
                    .collect::<Vec<_>>()
                    .join(" or ");
                tail.push_str(&format!(" if {}", joined));
            }
        }
    }
    Ok(CompParts { kind: recog.kind, head, tail })
}

/// Matches the structured body of a comprehension code object: a (possibly
/// nested) `for` whose innermost body produces one element. Returns `None` for
/// any shape that is not a plain comprehension.
fn recognize_comprehension(arena: &ExprArena, body: &[Stmt]) -> Option<RecognizedComp> {
    // The body ends in the comprehension's implicit `return None`.
    let body = match body.last() {
        Some(Stmt::Return(_)) => &body[..body.len() - 1],
        _ => body,
    };
    let [outer @ Stmt::For { .. }] = body else {
        return None;
    };
    let mut clauses = Vec::new();
    let (kind, element, key) = walk_comp_for(arena, outer, &mut clauses)?;
    Some(RecognizedComp { kind, element, key, clauses })
}

/// Descends one `for` clause, recording it, then continues into its body.
fn walk_comp_for(
    arena: &ExprArena,
    stmt: &Stmt,
    clauses: &mut Vec<CompClause>,
) -> Option<(CompKind, ValueId, Option<ValueId>)> {
    let Stmt::For { target, iter, body } = stmt else {
        return None;
    };
    clauses.push(CompClause::For { target: target.clone(), iter: *iter });
    walk_comp_body(arena, body, clauses)
}

/// Descends a comprehension clause body: an `if` filter, a nested `for`, or the
/// terminal element-producing statement. The back edge's trailing `continue` is
/// dropped.
fn walk_comp_body(
    arena: &ExprArena,
    body: &[Stmt],
    clauses: &mut Vec<CompClause>,
) -> Option<(CompKind, ValueId, Option<ValueId>)> {
    let body = match body.last() {
        Some(Stmt::Continue) => &body[..body.len() - 1],
        _ => body,
    };
    match body {
        [Stmt::Expr(value)] => match arena.get(*value) {
            Expr::Yield(element) => Some((CompKind::Gen, *element, None)),
            _ => None,
        },
        [Stmt::SetAdd(element)] => Some((CompKind::Set, *element, None)),
        [Stmt::DictAdd { key, value }] => Some((CompKind::Dict, *value, Some(*key))),
        [Stmt::If { cond, then, els }] if els.is_empty() => {
            clauses.push(CompClause::If(*cond));
            walk_comp_body(arena, then, clauses)
        }
        // `if cond: <skip> else: <element>` is a negated filter `if not cond`.
        [Stmt::If { cond, then, els }] if then.is_empty() => {
            clauses.push(CompClause::IfNot(*cond));
            walk_comp_body(arena, els, clauses)
        }
        // `if a: BODY else: if b: BODY else: ...` (each arm the same element) is the
        // short-circuit form of a disjunctive filter `if a or b or ...`.
        [Stmt::If { cond, then, els }] => {
            let element = comp_terminal(arena, then)?;
            let mut conds = vec![*cond];
            let mut rest: &[Stmt] = els;
            loop {
                match rest {
                    [Stmt::If { cond, then, els }] if comp_terminal(arena, then) == Some(element) => {
                        conds.push(*cond);
                        rest = els;
                    }
                    [] => break,
                    _ => return None,
                }
            }
            clauses.push(CompClause::IfAny(conds));
            walk_comp_body(arena, then, clauses)
        }
        [for_stmt @ Stmt::For { .. }] => walk_comp_for(arena, for_stmt, clauses),
        _ => None,
    }
}

/// The element signature of a comprehension's terminal body (its accumulator add or
/// generator yield), used to confirm the arms of a disjunctive filter all produce the
/// same element. Returns `None` for any non-terminal body.
fn comp_terminal(arena: &ExprArena, body: &[Stmt]) -> Option<(CompKind, ValueId, Option<ValueId>)> {
    match body {
        [Stmt::Expr(value)] => match arena.get(*value) {
            Expr::Yield(element) => Some((CompKind::Gen, *element, None)),
            _ => None,
        },
        [Stmt::SetAdd(element)] => Some((CompKind::Set, *element, None)),
        [Stmt::DictAdd { key, value }] => Some((CompKind::Dict, *value, Some(*key))),
        _ => None,
    }
}

/// Python 2.7 reserved words that cannot be used as identifiers.
const KEYWORDS: &[&str] = &[
    "and", "as", "assert", "break", "class", "continue", "def", "del", "elif", "else", "except",
    "exec", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "not", "or",
    "pass", "print", "raise", "return", "try", "while", "with", "yield",
];

/// Maps a name to a valid Python identifier. The deobfuscator's variable renaming
/// can leave reserved words or names with illegal characters; replace illegal
/// characters with `_` and suffix reserved words so the output parses.
pub(crate) fn sanitize_identifier(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (index, ch) in name.chars().enumerate() {
        let legal = if index == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        out.push(if legal { ch } else { '_' });
    }
    if out.is_empty() {
        out.push('_');
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if KEYWORDS.contains(&out.as_str()) {
        out.push('_');
    }
    out
}

/// Splits the deobfuscator's `<name>_orig_<id>` co_name into the recovered name and
/// the original (pre-rename) name. The renamer rewrites a code object's `co_name` to
/// `<recovered>_orig_<original>` (carrying the original through marshalling, which
/// has no spare field for it) while leaving the binding at the clean `<recovered>`.
/// Returns `(recovered, Some(original))` when the suffix is present, else
/// `(name, None)` -- so a non-obfuscated input (no suffix) is returned unchanged.
pub(crate) fn split_orig_suffix(name: &str) -> (&str, Option<&str>) {
    if let Some(index) = name.rfind("_orig_") {
        let original = &name[index + "_orig_".len()..];
        if index > 0 && !original.is_empty() && original.bytes().all(|b| b.is_ascii_digit()) {
            return (&name[..index], Some(original));
        }
    }
    (name, None)
}

/// The recovered name only (see [`split_orig_suffix`]).
fn strip_orig_suffix(name: &str) -> &str {
    split_orig_suffix(name).0
}

/// Renders a constant object as a Python literal.
fn render_obj(obj: &Obj) -> String {
    match obj {
        Obj::None => "None".to_string(),
        Obj::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Obj::Long(value) => value.read().unwrap().to_string(),
        Obj::Float(f) => render_float(*f),
        Obj::String(s) => python_bytes_literal(s.read().unwrap().as_slice()),
        Obj::Tuple(items) => {
            let items = items.read().unwrap();
            let rendered: Vec<String> = items.iter().map(render_obj).collect();
            if rendered.len() == 1 {
                format!("({},)", rendered[0])
            } else {
                format!("({})", rendered.join(", "))
            }
        }
        Obj::Complex(c) => render_complex(c.re, c.im),
        // Python 2 `str` is bytes; a marshalled Bytes object renders as a str literal.
        Obj::Bytes(b) => python_bytes_literal(b.read().unwrap().as_slice()),
        Obj::Ellipsis => "Ellipsis".to_string(),
        Obj::StopIteration => "StopIteration".to_string(),
        other => format!("{}_const_{:?}", UNRECOVERED, other.typ()),
    }
}

/// Renders a complex constant the way CPython 2 `repr` does: a pure-imaginary value
/// (real is +0.0) prints as `<imag>j`, otherwise `(<real>+/-<imag>j)`. Each part uses
/// the bare float form (no trailing `.0` -- `2`, `-0`, `1.5`), matching the compiler's
/// own repr so the literal round-trips to the same constant (`-0j`, `(2+3j)`, `(1.5-2.5j)`).
fn render_complex(re: f64, im: f64) -> String {
    if re == 0.0 && re.is_sign_positive() {
        format!("{}j", complex_part(im))
    } else {
        let sign = if im.is_sign_negative() { "-" } else { "+" };
        format!("({}{}{}j)", complex_part(re), sign, complex_part(im.abs()))
    }
}

/// One component of a complex literal: the bare float form. Rust's `f64` `Display`
/// already drops the decimal for whole values (`2.0` -> `2`) and keeps the sign of
/// negative zero (`-0.0` -> `-0`), matching CPython's complex-repr formatting.
fn complex_part(f: f64) -> String {
    format!("{}", f)
}

fn render_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 {
        format!("{:.1}", f)
    } else if let Some(int) = f.to_i64() {
        format!("{}.0", int)
    } else {
        format!("{}", f)
    }
}

/// Renders a docstring. A triple-quoted literal is used only for plain ASCII text with
/// no embedded triple quote or trailing quote/backslash, so multi-line ASCII docstrings
/// stay readable. A docstring with non-ASCII bytes uses the single-quoted form instead
/// (via `python_bytes_literal`): a triple-quoted literal's real newlines would be
/// re-indented when the method is nested inside its class, corrupting the string, while
/// the single-quoted `\n`/`\t`-escaped form is one physical line and survives nesting.
/// `python_bytes_literal` still renders the non-ASCII characters raw (readable), valid
/// because `decompile_module` adds a `# -*- coding: utf-8 -*-` header.
fn docstring_literal(bytes: &[u8], multiline_ok: bool) -> String {
    let printable = bytes
        .iter()
        .all(|&b| matches!(b, b'\n' | b'\t' | 0x20..=0x7e));
    let text = String::from_utf8_lossy(bytes);
    // A backslash inside a triple-quoted literal is a string escape, so a docstring
    // carrying a literal backslash (a doctest's `\xe4`, a regex, a Windows path) would
    // recompile to different bytes. A multi-line literal is corrupted by re-indentation
    // when the def is nested (see the caller). Both fall to the single-quoted form,
    // which escapes backslashes and newlines and is byte-exact regardless of nesting.
    if printable
        && !text.contains("\"\"\"")
        && !text.contains('\\')
        && !text.ends_with('"')
        && (multiline_ok || !text.contains('\n'))
    {
        format!("\"\"\"{}\"\"\"", text)
    } else {
        python_bytes_literal(bytes)
    }
}

/// Rewrites the `def <id>(` header of a decompiled function so it names `name`,
/// used when the code object's own co_name was obfuscated to a `<comprehension>`
/// form but it is a real method stored at `name`. Only the header identifier is
/// replaced (the parameter list and body are untouched); a recursive call inside
/// the body reaches the method through `self`/the binding, not the co_name, so it is
/// unaffected. Returns `None` if no `def ` header line is found (the source is then
/// left as-is).
fn rename_def_header(source: &str, name: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    let mut done = false;
    for line in source.split('\n') {
        if !done {
            if let Some(rest) = line.strip_prefix("def ") {
                if let Some(paren) = rest.find('(') {
                    out.push(format!("def {}{}", name, &rest[paren..]));
                    done = true;
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    done.then(|| out.join("\n"))
}

/// Renders a byte string as a single-quoted Python 2 string literal. When the bytes
/// are valid UTF-8 with non-ASCII content, those characters are emitted raw (readable,
/// e.g. Cyrillic) -- they round-trip byte-exact in a UTF-8 source file, which
/// `decompile_module` guarantees with a `# -*- coding: utf-8 -*-` header. Control and
/// quote characters are still escaped. Invalid UTF-8 (real binary) falls back to
/// byte-wise `\xNN` escapes so every byte is preserved.
fn python_bytes_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('\'');
    match std::str::from_utf8(bytes) {
        Ok(text) if bytes.iter().any(|&b| b >= 0x80) => {
            for ch in text.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '\'' => out.push_str("\\'"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 || c == '\u{7f}' => {
                        out.push_str(&format!("\\x{:02x}", c as u32))
                    }
                    c => out.push(c),
                }
            }
        }
        _ => {
            for &byte in bytes {
                match byte {
                    b'\\' => out.push_str("\\\\"),
                    b'\'' => out.push_str("\\'"),
                    b'\n' => out.push_str("\\n"),
                    b'\r' => out.push_str("\\r"),
                    b'\t' => out.push_str("\\t"),
                    0x20..=0x7e => out.push(byte as char),
                    _ => out.push_str(&format!("\\x{:02x}", byte)),
                }
            }
        }
    }
    out.push('\'');
    out
}

fn binop_prec(op: BinOp) -> u8 {
    match op {
        BinOp::Or => prec::BIT_OR,
        BinOp::Xor => prec::BIT_XOR,
        BinOp::And => prec::BIT_AND,
        BinOp::LeftShift | BinOp::RightShift => prec::SHIFT,
        BinOp::Add | BinOp::Subtract => prec::ADD,
        BinOp::Multiply
        | BinOp::Divide
        | BinOp::FloorDivide
        | BinOp::TrueDivide
        | BinOp::Modulo => prec::MUL,
        BinOp::Power => prec::POWER,
    }
}
