//! Symbolic stack execution: turns a straight-line run of bytecode into a list
//! of statements over an [`ExprArena`].
//!
//! Each value-producing instruction pushes a [`ValueId`] onto a symbolic stack;
//! each effecting instruction pops its operands and emits a [`Stmt`]. Opcodes
//! outside the supported set return [`IrError::Unsupported`] so coverage gaps
//! surface instead of producing wrong output.

use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use super::expr::*;
use super::IrError;

/// A tuple-assignment target under construction by `UNPACK_SEQUENCE` and the
/// stores that follow it.
struct PendingUnpack {
    rhs: ValueId,
    arity: usize,
    targets: Vec<LValue>,
}

/// A short-circuit operator awaiting its right operand. `JUMP_IF_*_OR_POP` records
/// the left operand and the offset where the two sides merge; the merged value is
/// built once execution reaches that offset.
struct ShortCircuit {
    kind: BoolKind,
    lhs: ValueId,
    merge: Offset,
}

/// Symbolic stack machine for one basic block.
pub struct Unstacker {
    arena: ExprArena,
    stack: Vec<ValueId>,
    stmts: Vec<Stmt>,
    unpack: Option<PendingUnpack>,
    shortcircuit: Vec<ShortCircuit>,
}

impl Unstacker {
    pub fn new() -> Unstacker {
        Unstacker {
            arena: ExprArena::new(),
            stack: Vec::new(),
            stmts: Vec::new(),
            unpack: None,
            shortcircuit: Vec::new(),
        }
    }

    /// Resolves any pending short-circuit whose merge point is `offset`: the right
    /// operand is on the stack, so combine it with the recorded left operand.
    pub fn resolve_shortcircuits(&mut self, offset: Offset) -> Result<(), IrError> {
        while self.shortcircuit.last().map(|s| s.merge) == Some(offset) {
            let sc = self.shortcircuit.pop().unwrap();
            let rhs = self.pop()?;
            let combined = self.combine_bool(sc.kind, sc.lhs, rhs);
            self.stack.push(combined);
        }
        Ok(())
    }

    /// Whether all short-circuit operators in this block have been resolved.
    pub fn shortcircuits_resolved(&self) -> bool {
        self.shortcircuit.is_empty()
    }

    /// Combines two short-circuit operands, flattening a right side of the same
    /// kind so `a and b and c` is one chain rather than nested pairs.
    fn combine_bool(&mut self, kind: BoolKind, lhs: ValueId, rhs: ValueId) -> ValueId {
        let mut operands = vec![lhs];
        match self.arena.get(rhs) {
            Expr::BoolOp(rhs_kind, items) if *rhs_kind == kind => {
                operands.extend(items.iter().copied());
            }
            _ => operands.push(rhs),
        }
        self.arena.alloc(Expr::BoolOp(kind, operands))
    }

    fn push(&mut self, expr: Expr) {
        let id = self.arena.alloc(expr);
        self.stack.push(id);
    }

    fn pop(&mut self) -> Result<ValueId, IrError> {
        self.stack.pop().ok_or(IrError::StackUnderflow)
    }

    /// Records an assignment to `target`. While an `UNPACK_SEQUENCE` is in progress
    /// the stores it feeds collect into a single tuple assignment instead of
    /// emitting one statement each.
    fn complete_store(&mut self, target: LValue, value: ValueId) {
        if self.unpack.is_some() && matches!(self.arena.get(value), Expr::UnpackSlot) {
            let pending = self.unpack.as_mut().unwrap();
            pending.targets.push(target);
            if pending.targets.len() == pending.arity {
                let pending = self.unpack.take().unwrap();
                self.emit(Stmt::Assign(LValue::Tuple(pending.targets), pending.rhs));
            }
        } else {
            self.emit(Stmt::Assign(target, value));
        }
    }

    fn pop_n(&mut self, n: usize) -> Result<Vec<ValueId>, IrError> {
        if self.stack.len() < n {
            return Err(IrError::StackUnderflow);
        }
        Ok(self.stack.split_off(self.stack.len() - n))
    }

    fn emit(&mut self, stmt: Stmt) {
        self.stmts.push(stmt);
    }

    /// Builds a call expression. The operand byte encodes positional and keyword
    /// counts; `has_star`/`has_kwstar` add `*args`/`**kwargs`. Popped top to
    /// bottom: `**kwargs`, `*args`, keyword `(key, value)` pairs, positionals,
    /// then the callee.
    fn call(&mut self, raw: u16, has_star: bool, has_kwstar: bool) -> Result<(), IrError> {
        let positional = (raw & 0xff) as usize;
        let keyword = (raw >> 8) as usize;
        let kwstar = if has_kwstar { Some(self.pop()?) } else { None };
        let star = if has_star { Some(self.pop()?) } else { None };
        let mut kwargs = Vec::with_capacity(keyword);
        for _ in 0..keyword {
            let value = self.pop()?;
            let key = self.pop()?;
            kwargs.push((key, value));
        }
        kwargs.reverse();
        let args = self.pop_n(positional)?;
        let func = self.pop()?;
        self.push(Expr::Call {
            func,
            args,
            kwargs,
            star,
            kwstar,
        });
        Ok(())
    }

    /// Clears the symbolic stack before lowering a new basic block. The arena and
    /// accumulated statements are retained across blocks of the same function.
    pub fn start_block(&mut self) {
        self.stack.clear();
        self.unpack = None;
        self.shortcircuit.clear();
    }

    /// Pops a value left on the stack, e.g. a branch condition or return value.
    pub fn pop_value(&mut self) -> Result<ValueId, IrError> {
        self.pop()
    }

    /// Removes and returns the statements lowered so far.
    pub fn take_stmts(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    /// Returns the values currently left on the symbolic stack.
    pub fn stack_snapshot(&self) -> Vec<ValueId> {
        self.stack.clone()
    }

    /// Consumes the machine, yielding just the expression arena.
    pub fn into_arena(self) -> ExprArena {
        self.arena
    }

    /// Consumes the machine, yielding the arena and the statement list.
    pub fn finish(self) -> (ExprArena, Vec<Stmt>) {
        (self.arena, self.stmts)
    }

    /// Folds one instruction into the symbolic state.
    pub fn step(&mut self, instr: &Instruction<Standard>) -> Result<(), IrError> {
        let arg = instr.arg;
        let mnemonic = instr.opcode.mnemonic();

        if let Some(op) = binary_op(mnemonic) {
            let rhs = self.pop()?;
            let lhs = self.pop()?;
            self.push(Expr::BinOp(op, lhs, rhs));
            return Ok(());
        }
        if let Some(op) = unary_op(mnemonic) {
            let operand = self.pop()?;
            self.push(Expr::Unary(op, operand));
            return Ok(());
        }

        match mnemonic {
            // SETUP_LOOP / POP_BLOCK manage the runtime block stack; they have no
            // effect on the recovered statement stream. GET_ITER is a no-op for
            // source purposes: the operand it would wrap is the value the `for`
            // loop iterates, so it is left on the stack as-is.
            Mnemonic::NOP | Mnemonic::SETUP_LOOP | Mnemonic::POP_BLOCK | Mnemonic::GET_ITER => {}
            Mnemonic::LOAD_CONST => self.push(Expr::Const(ConstId(arg_u16(arg)?))),
            Mnemonic::LOAD_FAST => self.push(Expr::Local(VarId(arg_u16(arg)?))),
            Mnemonic::LOAD_DEREF => self.push(Expr::Deref(DerefId(arg_u16(arg)?))),
            Mnemonic::LOAD_GLOBAL => self.push(Expr::Global(NameId(arg_u16(arg)?))),
            Mnemonic::LOAD_NAME => self.push(Expr::Name(NameId(arg_u16(arg)?))),
            Mnemonic::LOAD_ATTR => {
                let obj = self.pop()?;
                self.push(Expr::Attr(obj, NameId(arg_u16(arg)?)));
            }
            Mnemonic::BINARY_SUBSC => {
                let key = self.pop()?;
                let container = self.pop()?;
                self.push(Expr::Subscript(container, key));
            }
            Mnemonic::COMPARE_OP => {
                let op = CmpOp::from_arg(arg_u16(arg)?).ok_or(IrError::BadOperand)?;
                let rhs = self.pop()?;
                let lhs = self.pop()?;
                self.push(Expr::Compare(op, lhs, rhs));
            }
            Mnemonic::CALL_FUNCTION => self.call(arg_u16(arg)?, false, false)?,
            Mnemonic::CALL_FUNCTION_VAR => self.call(arg_u16(arg)?, true, false)?,
            Mnemonic::CALL_FUNCTION_KW => self.call(arg_u16(arg)?, false, true)?,
            Mnemonic::CALL_FUNCTION_VAR_KW => self.call(arg_u16(arg)?, true, true)?,
            Mnemonic::BUILD_TUPLE => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::Tuple(items));
            }
            Mnemonic::BUILD_LIST => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::List(items));
            }
            Mnemonic::BUILD_SET => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::Set(items));
            }
            // BUILD_MAP makes an empty dict; the STORE_MAPs that follow grow it in
            // place while it stays on the stack.
            Mnemonic::BUILD_MAP => self.push(Expr::Dict(Vec::new())),
            Mnemonic::STORE_MAP => {
                let key = self.pop()?;
                let value = self.pop()?;
                let dict = *self.stack.last().ok_or(IrError::StackUnderflow)?;
                match self.arena.get(dict) {
                    Expr::Dict(pairs) => {
                        let mut pairs = pairs.clone();
                        pairs.push((key, value));
                        self.arena.set(dict, Expr::Dict(pairs));
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                }
            }
            Mnemonic::DUP_TOP => {
                let top = *self.stack.last().ok_or(IrError::StackUnderflow)?;
                self.stack.push(top);
            }
            Mnemonic::STORE_FAST => {
                let value = self.pop()?;
                self.complete_store(LValue::Local(VarId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_DEREF => {
                let value = self.pop()?;
                self.complete_store(LValue::Deref(DerefId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_NAME => {
                let value = self.pop()?;
                self.complete_store(LValue::Name(NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_GLOBAL => {
                let value = self.pop()?;
                self.complete_store(LValue::Global(NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_ATTR => {
                let obj = self.pop()?;
                let value = self.pop()?;
                self.complete_store(LValue::Attr(obj, NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_SUBSCR => {
                let key = self.pop()?;
                let container = self.pop()?;
                let value = self.pop()?;
                self.complete_store(LValue::Subscript(container, key), value);
            }
            Mnemonic::JUMP_IF_FALSE_OR_POP | Mnemonic::JUMP_IF_TRUE_OR_POP => {
                let kind = if mnemonic == Mnemonic::JUMP_IF_FALSE_OR_POP {
                    BoolKind::And
                } else {
                    BoolKind::Or
                };
                let lhs = self.pop()?;
                self.shortcircuit.push(ShortCircuit {
                    kind,
                    lhs,
                    merge: Offset(arg_u16(arg)? as u32),
                });
            }
            Mnemonic::UNPACK_SEQUENCE => {
                let arity = arg_u16(arg)? as usize;
                let rhs = self.pop()?;
                // Nested unpack targets, e.g. `(a, b), c = ...`, are not handled yet.
                if matches!(self.arena.get(rhs), Expr::UnpackSlot) {
                    return Err(IrError::Unsupported(mnemonic));
                }
                self.unpack = Some(PendingUnpack {
                    rhs,
                    arity,
                    targets: Vec::new(),
                });
                for _ in 0..arity {
                    self.push(Expr::UnpackSlot);
                }
            }
            Mnemonic::POP_TOP => {
                let value = self.pop()?;
                self.emit(Stmt::Expr(value));
            }
            Mnemonic::RETURN_VALUE => {
                let value = self.pop()?;
                self.emit(Stmt::Return(Some(value)));
            }
            other => return Err(IrError::Unsupported(other)),
        }
        Ok(())
    }
}

fn arg_u16(arg: Option<u16>) -> Result<u16, IrError> {
    arg.ok_or(IrError::MissingOperand)
}

fn binary_op(mnemonic: Mnemonic) -> Option<BinOp> {
    Some(match mnemonic {
        Mnemonic::BINARY_ADD | Mnemonic::INPLACE_ADD => BinOp::Add,
        Mnemonic::BINARY_SUBTRACT | Mnemonic::INPLACE_SUBTRACT => BinOp::Subtract,
        Mnemonic::BINARY_MULTIPLY | Mnemonic::INPLACE_MULTIPLY => BinOp::Multiply,
        Mnemonic::BINARY_DIVIDE | Mnemonic::INPLACE_DIVIDE => BinOp::Divide,
        Mnemonic::BINARY_FLOOR_DIVIDE | Mnemonic::INPLACE_FLOOR_DIVIDE => BinOp::FloorDivide,
        Mnemonic::BINARY_TRUE_DIVIDE | Mnemonic::INPLACE_TRUE_DIVIDE => BinOp::TrueDivide,
        Mnemonic::BINARY_MODULO | Mnemonic::INPLACE_MODULO => BinOp::Modulo,
        Mnemonic::BINARY_POWER | Mnemonic::INPLACE_POWER => BinOp::Power,
        Mnemonic::BINARY_LSHIFT | Mnemonic::INPLACE_LSHIFT => BinOp::LeftShift,
        Mnemonic::BINARY_RSHIFT | Mnemonic::INPLACE_RSHIFT => BinOp::RightShift,
        Mnemonic::BINARY_AND | Mnemonic::INPLACE_AND => BinOp::And,
        Mnemonic::BINARY_OR | Mnemonic::INPLACE_OR => BinOp::Or,
        Mnemonic::BINARY_XOR | Mnemonic::INPLACE_XOR => BinOp::Xor,
        _ => return None,
    })
}

fn unary_op(mnemonic: Mnemonic) -> Option<UnaryOp> {
    Some(match mnemonic {
        Mnemonic::UNARY_NEGATIVE => UnaryOp::Negate,
        Mnemonic::UNARY_POSITIVE => UnaryOp::Positive,
        Mnemonic::UNARY_INVERT => UnaryOp::Invert,
        Mnemonic::UNARY_NOT => UnaryOp::Not,
        _ => return None,
    })
}
