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

/// Binding precedence levels, lowest to highest.
mod prec {
    pub const TERNARY: u8 = 0;
    pub const OR: u8 = 1;
    pub const AND: u8 = 2;
    pub const COMPARE: u8 = 3;
    pub const BIT_OR: u8 = 4;
    pub const BIT_XOR: u8 = 5;
    pub const BIT_AND: u8 = 6;
    pub const SHIFT: u8 = 7;
    pub const ADD: u8 = 8;
    pub const MUL: u8 = 9;
    pub const UNARY: u8 = 10;
    pub const POWER: u8 = 11;
    pub const ATOM: u8 = 13;
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

    /// Renders a single expression at statement precedence. Used to recover a
    /// lambda body in the enclosing scope.
    pub(crate) fn expr_text(&self, id: ValueId) -> String {
        self.expr(id, 0)
    }

    /// Renders a body and returns the accumulated source, prefixed with the
    /// function's docstring when it has one.
    pub fn render_body(mut self, stmts: &[Stmt]) -> String {
        let docstring = self.docstring();
        if let Some(doc) = &docstring {
            self.line(doc);
        }
        if stmts.is_empty() && docstring.is_none() {
            self.line("pass");
        }
        for stmt in stmts {
            self.stmt(stmt);
        }
        self.out
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
            Some(Obj::String(s)) => Some(docstring_literal(s.read().unwrap().as_slice())),
            _ => None,
        }
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
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

    /// Recognises `name = deco(... (make_function))` where the function's own name
    /// matches the store target: the bytecode shape of a decorated `def`. Emits the
    /// `@deco` lines and the def, and returns `true`. Returns `false` for any other
    /// assignment, which the caller renders normally.
    fn try_decorated_def(&mut self, target: &LValue, value: ValueId) -> bool {
        let mut decorators = Vec::new();
        let mut cur = value;
        let (code, defaults) = loop {
            match self.arena.get(cur) {
                // Each decorator wraps the function in a single-positional call.
                Expr::Call { func, args, kwargs, star, kwstar }
                    if args.len() == 1
                        && kwargs.is_empty()
                        && star.is_none()
                        && kwstar.is_none() =>
                {
                    decorators.push(*func);
                    cur = args[0];
                }
                Expr::MakeFunction { code, defaults } => break (*code, defaults.clone()),
                _ => return false,
            }
        };
        if decorators.is_empty() {
            return false;
        }
        let Some(nested) = self.nested_code(code) else {
            return false;
        };
        let name = nested.name.to_string();
        // A `<lambda>`/`<genexpr>` has no `def` form, and the target must name the
        // function for `@deco def name` to be the original source. The deobfuscator
        // renames the nested code object to `<name>_orig_<id>` while leaving the
        // store at the clean name, so compare against the de-mangled form.
        if name.starts_with('<') || self.lvalue(target) != strip_orig_suffix(&sanitize_identifier(&name)) {
            return false;
        }
        // Decorators are listed outermost-first, which is top-to-bottom order.
        let lines: Vec<String> =
            decorators.iter().map(|d| format!("@{}", self.expr(*d, 0))).collect();
        for line in lines {
            self.line(&line);
        }
        self.function_def(target, code, &defaults);
        true
    }

    /// Emits a nested `def` by recursively decompiling its code constant and
    /// indenting the result under the current block.
    fn function_def(&mut self, target: &LValue, code: ConstId, defaults: &[ValueId]) {
        let nested = match self.nested_code(code) {
            Some(nested) => nested,
            None => {
                self.line(UNRECOVERED);
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
        // A `def` names itself; any other non-identifier name (`<genexpr>`) is a form
        // this path does not render, so mark it unrecovered.
        if nested.name.to_string().starts_with('<') {
            self.line(UNRECOVERED);
            return;
        }
        // Default values are evaluated in this (enclosing) scope, so render them
        // here and inject them into the nested signature.
        let defaults: Vec<String> = defaults.iter().map(|d| self.expr(*d, 0)).collect();
        match super::decompile_function_with_defaults(nested, &defaults) {
            Ok(source) => {
                for text in source.trim_end_matches('\n').split('\n') {
                    self.line(text);
                }
            }
            Err(_) => self.line(UNRECOVERED),
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
                self.line(UNRECOVERED);
                return;
            }
        };
        match class_body_source(body_code) {
            Ok(body) => {
                self.line(&header);
                // The body is rendered at one indent level; `line` adds the current
                // indent on top, nesting it under the class.
                for text in body.trim_end_matches('\n').split('\n') {
                    self.line(text);
                }
            }
            Err(_) => self.line(UNRECOVERED),
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
        for stmt in stmts {
            self.stmt(stmt);
        }
        self.indent -= 1;
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
            Stmt::Print { values, newline } => {
                let mut line = String::from("print ");
                let rendered: Vec<String> = values.iter().map(|v| self.expr(*v, 0)).collect();
                line.push_str(&rendered.join(", "));
                if !newline {
                    line.push(',');
                }
                self.line(line.trim_end());
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
            Stmt::While { cond, negated, body } => {
                let rendered = if *negated {
                    format!("while not {}:", self.expr(*cond, prec::UNARY))
                } else {
                    format!("while {}:", self.expr(*cond, 0))
                };
                self.line(&rendered);
                self.block(body);
            }
            Stmt::For { target, iter, body } => {
                let rendered = format!("for {} in {}:", self.lvalue(target), self.expr(*iter, 0));
                self.line(&rendered);
                self.block(body);
            }
            Stmt::Try { body, handlers } => {
                self.line("try:");
                self.block(body);
                for handler in handlers {
                    let header = match (&handler.exc_type, &handler.name) {
                        (None, _) => "except:".to_string(),
                        (Some(exc), None) => format!("except {}:", self.expr(*exc, 0)),
                        (Some(exc), Some(name)) => {
                            format!("except {} as {}:", self.expr(*exc, 0), self.lvalue(name))
                        }
                    };
                    self.line(&header);
                    self.block(&handler.body);
                }
            }
            Stmt::Import { module, target } => self.line(&self.import_line(*module, target)),
            Stmt::FromImport { module, names, star } => {
                self.line(&self.from_import_line(*module, names, *star))
            }
            // These appear only inside a comprehension code object, where the
            // comprehension folder consumes them; reaching emission means a shape
            // the folder did not recognise, so mark it unrecovered.
            Stmt::SetAdd(_) | Stmt::DictAdd { .. } => self.line(UNRECOVERED),
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
                    if !els.is_empty() {
                        self.line("else:");
                        self.block(els);
                    }
                }
            }
        }
    }

    fn lvalue(&self, target: &LValue) -> String {
        match target {
            LValue::Local(var) => self.varname(*var),
            LValue::Deref(deref) => self.derefname(*deref),
            LValue::Name(name) | LValue::Global(name) => self.name(*name),
            LValue::Attr(obj, name) => {
                format!("{}.{}", self.expr(*obj, prec::ATOM), self.name(*name))
            }
            LValue::Subscript(container, key) => {
                format!("{}[{}]", self.expr(*container, prec::ATOM), self.expr(*key, 0))
            }
            LValue::Tuple(items) => {
                let rendered: Vec<String> = items.iter().map(|i| self.lvalue(i)).collect();
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

    fn expr_prec(&self, id: ValueId) -> (String, u8) {
        match self.arena.get(id) {
            Expr::Const(c) => (self.render_const(*c), prec::ATOM),
            Expr::Local(var) => (self.varname(*var), prec::ATOM),
            Expr::Deref(deref) => (self.derefname(*deref), prec::ATOM),
            Expr::Global(name) | Expr::Name(name) => (self.name(*name), prec::ATOM),
            Expr::Attr(obj, name) => (
                format!("{}.{}", self.expr(*obj, prec::ATOM), self.name(*name)),
                prec::ATOM,
            ),
            Expr::Subscript(container, key) => (
                format!("{}[{}]", self.expr(*container, prec::ATOM), self.expr(*key, 0)),
                prec::ATOM,
            ),
            // A slice renders as `lower:upper`, each bound omitted when absent. Only
            // valid inside a subscript, which supplies the brackets.
            Expr::Slice { lower, upper } => {
                let bound = |b: &Option<ValueId>| b.map_or(String::new(), |id| self.expr(id, 0));
                (format!("{}:{}", bound(lower), bound(upper)), prec::ATOM)
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
            Expr::Unary(op, operand) => (
                format!("{}{}", op.symbol(), self.expr(*operand, prec::UNARY)),
                prec::UNARY,
            ),
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
            Expr::UnpackSlot | Expr::ClosureCell(_) => (UNRECOVERED.to_string(), prec::ATOM),
            // A `<lambda>` renders inline; a named function used as a value (an
            // undetected decorator) cannot, and is marked unrecovered.
            Expr::MakeFunction { code, defaults } => (self.lambda_expr(*code, defaults), prec::ATOM),
            Expr::Yield(value) => (format!("yield {}", self.expr(*value, prec::TERNARY)), prec::TERNARY),
            // Import values are consumed by the store or POP_TOP that completes the
            // statement; one reaching here is an import shape the unstacker did not
            // fully match (e.g. `import a.b as c`), so reject the function.
            Expr::Import(_) | Expr::ImportFrom(_) => (UNRECOVERED.to_string(), prec::ATOM),
            // `LOAD_LOCALS` is the class namespace a class body returns. Inline
            // class recovery drops the trailing `return locals()`, so this is only
            // reached when a class body is decompiled on its own; render the builtin.
            Expr::Locals => ("locals()".to_string(), prec::ATOM),
            // The class object is consumed by its store; one reaching here is a class
            // shape that was not fully matched.
            Expr::BuildClass { .. } => (UNRECOVERED.to_string(), prec::ATOM),
            Expr::ListComp { element, target, iter, conds } => {
                let mut text = format!(
                    "[{} for {} in {}",
                    self.expr(*element, 0),
                    self.lvalue(target),
                    self.expr(*iter, 0)
                );
                for cond in conds {
                    text.push_str(&format!(" if {}", self.expr(*cond, prec::OR)));
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

    /// Renders an `import module [as target]` statement. No `as` clause is emitted
    /// when the bound name matches the module's top-level component.
    fn import_line(&self, module: NameId, target: &LValue) -> String {
        let Some(module) = self.raw_name(module) else {
            return UNRECOVERED.to_string();
        };
        let head = module.split('.').next().unwrap_or(&module);
        match self.import_binding(target) {
            Some(bind) if bind == head => format!("import {}", module),
            Some(bind) => format!("import {} as {}", module, sanitize_identifier(&bind)),
            None => UNRECOVERED.to_string(),
        }
    }

    /// Renders a `from module import ...` statement (or `from module import *`).
    fn from_import_line(&self, module: NameId, names: &[(NameId, LValue)], star: bool) -> String {
        let Some(module) = self.raw_name(module) else {
            return UNRECOVERED.to_string();
        };
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

    /// The raw bound name of a simple import target (`STORE_NAME`/`STORE_FAST`).
    fn import_binding(&self, target: &LValue) -> Option<String> {
        match target {
            LValue::Name(name) | LValue::Global(name) => {
                self.code.names.get(name.0 as usize).map(|n| n.to_string())
            }
            LValue::Local(var) => self.code.varnames.get(var.0 as usize).map(|n| n.to_string()),
            _ => None,
        }
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
        format!("**{{{}}}", self.expr(key, 0))
    }

    fn render_const(&self, c: ConstId) -> String {
        match self.code.consts.get(c.0 as usize) {
            Some(obj) => render_obj(obj),
            None => format!("const{}", c.0),
        }
    }
}

/// Which comprehension a recovered nested code object represents.
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
    stmts.retain(|stmt| !is_class_boilerplate(&structured.code, stmt));
    Ok(Emitter::new(&structured.code, &structured.arena).render_body(&stmts))
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
        [for_stmt @ Stmt::For { .. }] => walk_comp_for(arena, for_stmt, clauses),
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

/// Strips the deobfuscator's `_orig_<id>` suffix from a nested code object name.
/// The renamer rewrites a code object's `co_name` to `<name>_orig_<co_name>` while
/// leaving the binding at the clean `<name>`; this recovers that clean name so a
/// decorated `def` can be matched to its store target.
fn strip_orig_suffix(name: &str) -> &str {
    if let Some(index) = name.rfind("_orig_") {
        if index > 0 && name[index + "_orig_".len()..].chars().all(|c| c.is_ascii_digit()) {
            return &name[..index];
        }
    }
    name
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
        other => format!("{}_const_{:?}", UNRECOVERED, other.typ()),
    }
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

/// Renders a docstring. A triple-quoted literal is used when the bytes are plain
/// ASCII text with no embedded triple quote or trailing quote/backslash, so
/// multi-line docstrings stay readable; otherwise the fully escaped single-quoted
/// form keeps non-ASCII bytes valid in a Python 2 source file.
fn docstring_literal(bytes: &[u8]) -> String {
    let printable = bytes
        .iter()
        .all(|&b| matches!(b, b'\n' | b'\t' | 0x20..=0x7e));
    let text = String::from_utf8_lossy(bytes);
    if printable && !text.contains("\"\"\"") && !text.ends_with('"') && !text.ends_with('\\') {
        format!("\"\"\"{}\"\"\"", text)
    } else {
        python_bytes_literal(bytes)
    }
}

/// Renders a byte string as a single-quoted Python 2 string literal.
fn python_bytes_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('\'');
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
