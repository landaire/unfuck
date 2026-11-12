//! Expressions, including assignment targets, attribute and subscript
//! access, and slices.

use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::code::op;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::assemble::Jump;
use crate::interp::compiler::ast;
use crate::interp::compiler::ast::ExprContext;
use crate::interp::compiler::ast::ExprKind;
use crate::interp::compiler::context::CompileError;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::object::StrObject;
use crate::interp::compiler::symtable::BlockType;
use crate::interp::complex::Complex;
use crate::interp::numbers;

use super::Compiler;
use super::functions::ComprehensionKind;
use super::system_error;

impl Compiler<'_> {
    pub(super) fn expressions(&mut self, expressions: &[ast::Expr]) -> Result<(), CompileError> {
        for expression in expressions {
            self.expression(expression)?;
        }

        Ok(())
    }

    pub(super) fn expression(&mut self, expr: &ast::Expr) -> Result<(), CompileError> {
        stacker::maybe_grow(64 * 1024, 2 * 1024 * 1024, || self.expression_on_stack(expr))
    }

    fn expression_on_stack(&mut self, expr: &ast::Expr) -> Result<(), CompileError> {
        self.advance_line(expr.location.lineno);

        match &expr.kind {
            ExprKind::BoolOp { op: operator, values } => self.short_circuit(*operator, values)?,
            ExprKind::BinOp { left, op: operator, right } => {
                self.expression(left)?;
                self.expression(right)?;
                self.emit(self.binary_opcode(*operator));
            }
            ExprKind::UnaryOp { op: operator, operand } => {
                self.expression(operand)?;
                self.emit(unary_opcode(*operator));
            }
            ExprKind::Lambda { args, body } => self.lambda(expr, args, body)?,
            ExprKind::IfExp { test, body, orelse } => self.conditional_expression(test, body, orelse)?,
            ExprKind::Dict { keys, values } => self.dict_display(keys, values)?,
            ExprKind::Set { elts } => {
                self.expressions(elts)?;
                self.emit_arg(op::BUILD_SET, elts.len() as i32);
            }
            ExprKind::ListComp { elt, generators } => self.list_comprehension(generators, elt)?,
            ExprKind::SetComp { elt, generators } => self.comprehension(expr, ComprehensionKind::Set, b"<setcomp>", generators, elt, None)?,
            ExprKind::DictComp { key, value, generators } => self.comprehension(expr, ComprehensionKind::Dict, b"<dictcomp>", generators, key, Some(value))?,
            ExprKind::GeneratorExp { elt, generators } => self.comprehension(expr, ComprehensionKind::Generator, b"<genexpr>", generators, elt, None)?,
            ExprKind::Yield { value } => {
                if self.scope_kind() != BlockType::Function {
                    return Err(self.syntax_error("'yield' outside function"));
                }
                match value {
                    Some(value) => self.expression(value)?,
                    None => self.load_constant(Object::None),
                }
                self.emit(op::YIELD_VALUE);
            }
            ExprKind::Compare { left, ops, comparators } => self.comparison(left, ops, comparators)?,
            ExprKind::Call { func, args, keywords, starargs, kwargs } => self.call(func, args, keywords, starargs.as_deref(), kwargs.as_deref())?,
            ExprKind::Repr { value } => {
                self.expression(value)?;
                self.emit(op::UNARY_CONVERT);
            }
            ExprKind::Num { n } => {
                let number = self.number(n);
                self.load_constant(number);
            }
            ExprKind::Str { s } => self.load_constant(Self::string(s)),
            ExprKind::Attribute { value, attr, ctx } => self.attribute(value, attr, *ctx)?,
            ExprKind::Subscript { value, slice, ctx } => self.subscript(value, slice, *ctx)?,
            ExprKind::Name { id, ctx } => self.access_name(&id.0, *ctx)?,
            ExprKind::List { elts, ctx } => self.sequence(elts, *ctx, op::BUILD_LIST)?,
            ExprKind::Tuple { elts, ctx } => self.sequence(elts, *ctx, op::BUILD_TUPLE)?,
        }

        Ok(())
    }

    fn number(&self, number: &ast::Number) -> Object {
        match number {
            ast::Number::Int(value) if numbers::fits_int(self.context.long_width(), *value) => Object::Int(*value),
            ast::Number::Int(value) => Object::Long(Rc::new(BigInt::from(*value))),
            ast::Number::Long(value) => Object::Long(Rc::new(value.clone())),
            ast::Number::Float(value) => Object::Float(*value),
            ast::Number::Complex { real, imag } => Object::Complex(Complex { real: *real, imag: *imag }),
        }
    }

    pub(super) fn string(literal: &ast::StrLiteral) -> Object {
        match literal {
            ast::StrLiteral::Bytes { value, interned } => Object::str(value.clone(), *interned),
            ast::StrLiteral::Unicode(units) => Object::Unicode(units.as_slice().into()),
        }
    }

    /// An identifier used as a constant; identifiers are always interned.
    pub(super) fn identifier(name: &ast::Identifier) -> Object {
        Object::Str(StrObject::new(name.0.clone(), true))
    }

    /// `and` and `or` leave the deciding operand on the stack and skip the
    /// rest.
    fn short_circuit(&mut self, operator: ast::BoolOp, values: &[ast::Expr]) -> Result<(), CompileError> {
        let decided = match operator {
            ast::BoolOp::And => op::JUMP_IF_FALSE_OR_POP,
            ast::BoolOp::Or => op::JUMP_IF_TRUE_OR_POP,
        };
        let Some((last, leading)) = values.split_last() else {
            return Err(system_error("BoolOp with no values"));
        };

        let end = self.allocate_block();
        for value in leading {
            self.expression(value)?;
            self.emit_jump(decided, Jump::Absolute(end));
        }
        self.expression(last)?;
        self.continue_in(end);

        Ok(())
    }

    fn conditional_expression(&mut self, test: &ast::Expr, body: &ast::Expr, orelse: &ast::Expr) -> Result<(), CompileError> {
        let end = self.allocate_block();
        let otherwise = self.allocate_block();

        self.expression(test)?;
        self.emit_jump(op::POP_JUMP_IF_FALSE, Jump::Absolute(otherwise));
        self.expression(body)?;
        self.emit_jump(op::JUMP_FORWARD, Jump::Relative(end));
        self.continue_in(otherwise);
        self.expression(orelse)?;
        self.continue_in(end);

        Ok(())
    }

    /// The size hint of `BUILD_MAP` saturates at 16 bits. Each value is
    /// evaluated before its key.
    fn dict_display(&mut self, keys: &[ast::Expr], values: &[ast::Expr]) -> Result<(), CompileError> {
        self.emit_arg(op::BUILD_MAP, values.len().min(0xFFFF) as i32);

        for (index, value) in values.iter().enumerate() {
            self.expression(value)?;
            let Some(key) = keys.get(index) else {
                return Err(system_error("Dict doesn't have the same number of keys as values"));
            };
            self.expression(key)?;
            self.emit(op::STORE_MAP);
        }

        Ok(())
    }

    /// `a < b < c` evaluates each middle operand once: it stays below the
    /// result of each comparison, and a false result skips the rest and
    /// drops it.
    fn comparison(&mut self, left: &ast::Expr, operators: &[ast::CmpOp], operands: &[ast::Expr]) -> Result<(), CompileError> {
        self.expression(left)?;

        let (Some((&last_operator, leading)), Some(last)) = (operators.split_last(), operands.get(operators.len().wrapping_sub(1))) else {
            return Err(system_error("Compare with no operators"));
        };
        if leading.is_empty() {
            self.expression(last)?;
            self.emit_arg(op::COMPARE_OP, comparison_arg(last_operator));
            return Ok(());
        }

        let failed = self.allocate_block();
        for (&operator, operand) in leading.iter().zip(operands) {
            self.expression(operand)?;
            self.emit(op::DUP_TOP);
            self.emit(op::ROT_THREE);
            self.emit_arg(op::COMPARE_OP, comparison_arg(operator));
            self.emit_jump(op::JUMP_IF_FALSE_OR_POP, Jump::Absolute(failed));
            self.continue_in_new_block();
        }
        self.expression(last)?;
        self.emit_arg(op::COMPARE_OP, comparison_arg(last_operator));

        let end = self.allocate_block();
        self.emit_jump(op::JUMP_FORWARD, Jump::Relative(end));
        self.continue_in(failed);
        self.emit(op::ROT_TWO);
        self.emit(op::POP_TOP);
        self.continue_in(end);

        Ok(())
    }

    /// The call argument holds the positional count in its low byte and
    /// the keyword count in the next; `*args` and `**kwargs` select the
    /// opcode.
    fn call(&mut self, function: &ast::Expr, args: &[ast::Expr], keywords: &[ast::Keyword], starargs: Option<&ast::Expr>, kwargs: Option<&ast::Expr>) -> Result<(), CompileError> {
        self.expression(function)?;
        self.expressions(args)?;
        for keyword in keywords {
            self.load_constant(Self::identifier(&keyword.arg));
            self.expression(&keyword.value)?;
        }
        if let Some(starargs) = starargs {
            self.expression(starargs)?;
        }
        if let Some(kwargs) = kwargs {
            self.expression(kwargs)?;
        }

        let opcode = match (starargs.is_some(), kwargs.is_some()) {
            (false, false) => op::CALL_FUNCTION,
            (true, false) => op::CALL_FUNCTION_VAR,
            (false, true) => op::CALL_FUNCTION_KW,
            (true, true) => op::CALL_FUNCTION_VAR_KW,
        };
        self.emit_arg(opcode, args.len() as i32 | (keywords.len() as i32) << 8);

        Ok(())
    }

    /// Attribute access. An augmented assignment loads with `AugLoad`,
    /// keeping the object for the store, and stores with `AugStore`, which
    /// finds the object below the new value.
    pub(super) fn attribute(&mut self, object: &ast::Expr, attribute: &ast::Identifier, ctx: ExprContext) -> Result<(), CompileError> {
        if ctx != ExprContext::AugStore {
            self.expression(object)?;
        }

        match ctx {
            ExprContext::AugLoad => {
                self.emit(op::DUP_TOP);
                self.emit_mangled(op::LOAD_ATTR, &attribute.0);
            }
            ExprContext::Load => self.emit_mangled(op::LOAD_ATTR, &attribute.0),
            ExprContext::AugStore => {
                self.emit(op::ROT_TWO);
                self.emit_mangled(op::STORE_ATTR, &attribute.0);
            }
            ExprContext::Store => self.emit_mangled(op::STORE_ATTR, &attribute.0),
            ExprContext::Del => self.emit_mangled(op::DELETE_ATTR, &attribute.0),
            ExprContext::Param => return Err(system_error("param invalid in attribute expression")),
        }

        Ok(())
    }

    /// Subscript access, with the same `AugLoad`/`AugStore` split as
    /// `attribute`: the store reuses the object and index left on the stack.
    pub(super) fn subscript(&mut self, object: &ast::Expr, slice: &ast::Slice, ctx: ExprContext) -> Result<(), CompileError> {
        match ctx {
            ExprContext::AugStore => {}
            ExprContext::AugLoad | ExprContext::Load | ExprContext::Store | ExprContext::Del => self.expression(object)?,
            ExprContext::Param => return Err(system_error("param invalid in subscript expression")),
        }

        let reloads = ctx == ExprContext::AugStore;
        match slice {
            ast::Slice::Index { value } if !reloads => self.expression(value)?,
            ast::Slice::Ellipsis if !reloads => self.load_constant(Object::Ellipsis),
            ast::Slice::Slice { lower, upper, step: None } => return self.two_part_slice(lower.as_ref(), upper.as_ref(), ctx),
            ast::Slice::Slice { lower, upper, step: Some(step) } if !reloads => self.slice_object(lower.as_ref(), upper.as_ref(), Some(step))?,
            ast::Slice::ExtSlice { dims } if !reloads => {
                for dimension in dims {
                    self.slice_dimension(dimension)?;
                }
                self.emit_arg(op::BUILD_TUPLE, dims.len() as i32);
            }
            ast::Slice::Index { .. } | ast::Slice::Ellipsis | ast::Slice::Slice { .. } | ast::Slice::ExtSlice { .. } => {}
        }

        let opcode = match ctx {
            ExprContext::AugLoad | ExprContext::Load => op::BINARY_SUBSCR,
            ExprContext::AugStore | ExprContext::Store => op::STORE_SUBSCR,
            ExprContext::Del => op::DELETE_SUBSCR,
            ExprContext::Param => return Err(system_error("invalid subscript kind in subscript")),
        };
        match ctx {
            ExprContext::AugLoad => self.emit_arg(op::DUP_TOPX, 2),
            ExprContext::AugStore => self.emit(op::ROT_THREE),
            ExprContext::Load | ExprContext::Store | ExprContext::Del | ExprContext::Param => {}
        }
        self.emit(opcode);

        Ok(())
    }

    /// `x[a:b]` without a step uses the `SLICE+n` family, where bit 0 of
    /// `n` means a lower bound and bit 1 an upper bound.
    fn two_part_slice(&mut self, lower: Option<&ast::Expr>, upper: Option<&ast::Expr>, ctx: ExprContext) -> Result<(), CompileError> {
        let mut variant = 0;
        let mut bounds = 0;
        for (bound, bit) in [(lower, 1), (upper, 2)] {
            let Some(bound) = bound else {
                continue;
            };
            variant += bit;
            bounds += 1;
            if ctx != ExprContext::AugStore {
                self.expression(bound)?;
            }
        }

        match (ctx, bounds) {
            (ExprContext::AugLoad, 0) => self.emit(op::DUP_TOP),
            (ExprContext::AugLoad, 1) => self.emit_arg(op::DUP_TOPX, 2),
            (ExprContext::AugLoad, _) => self.emit_arg(op::DUP_TOPX, 3),
            (ExprContext::AugStore, 0) => self.emit(op::ROT_TWO),
            (ExprContext::AugStore, 1) => self.emit(op::ROT_THREE),
            (ExprContext::AugStore, _) => self.emit(op::ROT_FOUR),
            _ => {}
        }

        let family = match ctx {
            ExprContext::AugLoad | ExprContext::Load => op::SLICE,
            ExprContext::AugStore | ExprContext::Store => op::STORE_SLICE,
            ExprContext::Del => op::DELETE_SLICE,
            ExprContext::Param => return Err(system_error("param invalid in simple slice")),
        };
        self.emit(family + variant);

        Ok(())
    }

    /// A `slice` object built from its bounds; missing bounds are `None`.
    fn slice_object(&mut self, lower: Option<&ast::Expr>, upper: Option<&ast::Expr>, step: Option<&ast::Expr>) -> Result<(), CompileError> {
        for bound in [lower, upper] {
            match bound {
                Some(bound) => self.expression(bound)?,
                None => self.load_constant(Object::None),
            }
        }

        let mut parts = 2;
        if let Some(step) = step {
            self.expression(step)?;
            parts += 1;
        }
        self.emit_arg(op::BUILD_SLICE, parts);

        Ok(())
    }

    /// One dimension of an extended slice such as `x[a:b, ...]`.
    fn slice_dimension(&mut self, slice: &ast::Slice) -> Result<(), CompileError> {
        match slice {
            ast::Slice::Ellipsis => self.load_constant(Object::Ellipsis),
            ast::Slice::Slice { lower, upper, step } => self.slice_object(lower.as_ref(), upper.as_ref(), step.as_ref())?,
            ast::Slice::Index { value } => self.expression(value)?,
            ast::Slice::ExtSlice { .. } => return Err(system_error("extended slice invalid in nested slice")),
        }

        Ok(())
    }

    /// A list or tuple display, or an unpacking target.
    fn sequence(&mut self, elements: &[ast::Expr], ctx: ExprContext, build: u8) -> Result<(), CompileError> {
        if ctx == ExprContext::Store {
            self.emit_arg(op::UNPACK_SEQUENCE, elements.len() as i32);
        }
        self.expressions(elements)?;
        if ctx == ExprContext::Load {
            self.emit_arg(build, elements.len() as i32);
        }

        Ok(())
    }

    fn binary_opcode(&self, operator: ast::Operator) -> u8 {
        match operator {
            ast::Operator::Add => op::BINARY_ADD,
            ast::Operator::Sub => op::BINARY_SUBTRACT,
            ast::Operator::Mult => op::BINARY_MULTIPLY,
            ast::Operator::Div if self.has_future(CompilerFlags::FUTURE_DIVISION) => op::BINARY_TRUE_DIVIDE,
            ast::Operator::Div => op::BINARY_DIVIDE,
            ast::Operator::Mod => op::BINARY_MODULO,
            ast::Operator::Pow => op::BINARY_POWER,
            ast::Operator::LShift => op::BINARY_LSHIFT,
            ast::Operator::RShift => op::BINARY_RSHIFT,
            ast::Operator::BitOr => op::BINARY_OR,
            ast::Operator::BitXor => op::BINARY_XOR,
            ast::Operator::BitAnd => op::BINARY_AND,
            ast::Operator::FloorDiv => op::BINARY_FLOOR_DIVIDE,
        }
    }

    pub(super) fn inplace_opcode(&self, operator: ast::Operator) -> u8 {
        match operator {
            ast::Operator::Add => op::INPLACE_ADD,
            ast::Operator::Sub => op::INPLACE_SUBTRACT,
            ast::Operator::Mult => op::INPLACE_MULTIPLY,
            ast::Operator::Div if self.has_future(CompilerFlags::FUTURE_DIVISION) => op::INPLACE_TRUE_DIVIDE,
            ast::Operator::Div => op::INPLACE_DIVIDE,
            ast::Operator::Mod => op::INPLACE_MODULO,
            ast::Operator::Pow => op::INPLACE_POWER,
            ast::Operator::LShift => op::INPLACE_LSHIFT,
            ast::Operator::RShift => op::INPLACE_RSHIFT,
            ast::Operator::BitOr => op::INPLACE_OR,
            ast::Operator::BitXor => op::INPLACE_XOR,
            ast::Operator::BitAnd => op::INPLACE_AND,
            ast::Operator::FloorDiv => op::INPLACE_FLOOR_DIVIDE,
        }
    }
}

fn unary_opcode(operator: ast::UnaryOp) -> u8 {
    match operator {
        ast::UnaryOp::Invert => op::UNARY_INVERT,
        ast::UnaryOp::Not => op::UNARY_NOT,
        ast::UnaryOp::UAdd => op::UNARY_POSITIVE,
        ast::UnaryOp::USub => op::UNARY_NEGATIVE,
    }
}

/// The `COMPARE_OP` argument, the operator's index in
/// `opcode.cmp_op`.
fn comparison_arg(operator: ast::CmpOp) -> i32 {
    match operator {
        ast::CmpOp::Lt => 0,
        ast::CmpOp::LtE => 1,
        ast::CmpOp::Eq => 2,
        ast::CmpOp::NotEq => 3,
        ast::CmpOp::Gt => 4,
        ast::CmpOp::GtE => 5,
        ast::CmpOp::In => 6,
        ast::CmpOp::NotIn => 7,
        ast::CmpOp::Is => 8,
        ast::CmpOp::IsNot => 9,
    }
}
