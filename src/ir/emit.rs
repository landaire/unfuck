//! Renders the statement IR back into Python 2.7 source.
//!
//! Expression rendering is precedence aware: each expression reports a binding
//! precedence and parenthesises a child only when the child binds more loosely
//! than its position requires.

use num_traits::ToPrimitive;
use py27_marshal::{Code, Obj};

use super::expr::*;

/// Binding precedence levels, lowest to highest.
mod prec {
    pub const COMPARE: u8 = 2;
    pub const BIT_OR: u8 = 3;
    pub const BIT_XOR: u8 = 4;
    pub const BIT_AND: u8 = 5;
    pub const SHIFT: u8 = 6;
    pub const ADD: u8 = 7;
    pub const MUL: u8 = 8;
    pub const UNARY: u8 = 9;
    pub const POWER: u8 = 10;
    pub const ATOM: u8 = 12;
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

    /// Renders a body and returns the accumulated source.
    pub fn render_body(mut self, stmts: &[Stmt]) -> String {
        if stmts.is_empty() {
            self.line("pass");
        }
        for stmt in stmts {
            self.stmt(stmt);
        }
        self.out
    }

    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign(target, value) => {
                let line = format!("{} = {}", self.lvalue(target), self.expr(*value, 0));
                self.line(&line);
            }
            Stmt::Expr(value) => {
                let line = self.expr(*value, 0);
                self.line(&line);
            }
            Stmt::Return(value) => match value {
                Some(value) => {
                    let line = format!("return {}", self.expr(*value, 0));
                    self.line(&line);
                }
                None => self.line("return"),
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
        }
    }

    fn lvalue(&self, target: &LValue) -> String {
        match target {
            LValue::Local(var) => self.varname(*var),
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
            Expr::Global(name) | Expr::Name(name) => (self.name(*name), prec::ATOM),
            Expr::Attr(obj, name) => (
                format!("{}.{}", self.expr(*obj, prec::ATOM), self.name(*name)),
                prec::ATOM,
            ),
            Expr::Subscript(container, key) => (
                format!("{}[{}]", self.expr(*container, prec::ATOM), self.expr(*key, 0)),
                prec::ATOM,
            ),
            Expr::BinOp(op, lhs, rhs) => {
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
            Expr::Call { func, args } => {
                let rendered: Vec<String> = args.iter().map(|a| self.expr(*a, 0)).collect();
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
        }
    }

    fn varname(&self, var: VarId) -> String {
        match self.code.varnames.get(var.0 as usize) {
            Some(name) => name.to_string(),
            None => format!("var{}", var.0),
        }
    }

    fn name(&self, name: NameId) -> String {
        match self.code.names.get(name.0 as usize) {
            Some(name) => name.to_string(),
            None => format!("name{}", name.0),
        }
    }

    fn render_const(&self, c: ConstId) -> String {
        match self.code.consts.get(c.0 as usize) {
            Some(obj) => render_obj(obj),
            None => format!("const{}", c.0),
        }
    }
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
        other => format!("<const {:?}>", other.typ()),
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
