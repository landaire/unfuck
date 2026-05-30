//! Symbolic stack execution: turns a straight-line run of bytecode into a list
//! of statements over an [`ExprArena`].
//!
//! Each value-producing instruction pushes a [`ValueId`] onto a symbolic stack;
//! each effecting instruction pops its operands and emits a [`Stmt`]. This is
//! the Milestone 1 scope: a single basic block with no control flow. Opcodes
//! outside that scope return [`IrError::Unsupported`] so coverage gaps surface
//! instead of producing wrong output.

use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use super::expr::*;
use super::IrError;

/// Symbolic stack machine for one basic block.
pub struct Unstacker {
    arena: ExprArena,
    stack: Vec<ValueId>,
    stmts: Vec<Stmt>,
}

impl Unstacker {
    pub fn new() -> Unstacker {
        Unstacker {
            arena: ExprArena::new(),
            stack: Vec::new(),
            stmts: Vec::new(),
        }
    }

    fn push(&mut self, expr: Expr) {
        let id = self.arena.alloc(expr);
        self.stack.push(id);
    }

    fn pop(&mut self) -> Result<ValueId, IrError> {
        self.stack.pop().ok_or(IrError::StackUnderflow)
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
            Mnemonic::NOP => {}
            Mnemonic::LOAD_CONST => self.push(Expr::Const(ConstId(arg_u16(arg)?))),
            Mnemonic::LOAD_FAST => self.push(Expr::Local(VarId(arg_u16(arg)?))),
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
            Mnemonic::CALL_FUNCTION => {
                let raw = arg_u16(arg)?;
                let positional = (raw & 0xff) as usize;
                let keyword = (raw >> 8) as usize;
                if keyword != 0 {
                    return Err(IrError::Unsupported(mnemonic));
                }
                let args = self.pop_n(positional)?;
                let func = self.pop()?;
                self.push(Expr::Call { func, args });
            }
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
            Mnemonic::DUP_TOP => {
                let top = *self.stack.last().ok_or(IrError::StackUnderflow)?;
                self.stack.push(top);
            }
            Mnemonic::STORE_FAST => {
                let value = self.pop()?;
                self.emit(Stmt::Assign(LValue::Local(VarId(arg_u16(arg)?)), value));
            }
            Mnemonic::STORE_NAME => {
                let value = self.pop()?;
                self.emit(Stmt::Assign(LValue::Name(NameId(arg_u16(arg)?)), value));
            }
            Mnemonic::STORE_GLOBAL => {
                let value = self.pop()?;
                self.emit(Stmt::Assign(LValue::Global(NameId(arg_u16(arg)?)), value));
            }
            Mnemonic::STORE_ATTR => {
                let obj = self.pop()?;
                let value = self.pop()?;
                self.emit(Stmt::Assign(LValue::Attr(obj, NameId(arg_u16(arg)?)), value));
            }
            Mnemonic::STORE_SUBSCR => {
                let key = self.pop()?;
                let container = self.pop()?;
                let value = self.pop()?;
                self.emit(Stmt::Assign(LValue::Subscript(container, key), value));
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
