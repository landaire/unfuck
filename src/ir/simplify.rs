//! Constant-folding deobfuscation on the control-flow graph.
//!
//! World of Warships' stage-4 obfuscation guards junk with opaque predicates:
//! conditions that compute a constant and so always take one branch. This pass
//! evaluates such conditions and rewrites the [`Terminator::CondBranch`] into an
//! unconditional [`Terminator::Jump`] to the taken side. The structurer only emits
//! blocks reachable from the entry, so the junk the predicate guarded is simply
//! never decompiled. Nothing is deleted, so no live instruction can be removed by
//! mistake (unlike taint-based bytecode removal).

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use py27_marshal::{Code, Obj};

use super::cfg::{Cfg, Terminator};
use super::expr::*;

/// A constant value the folder can reason about. Anything it cannot represent
/// exactly is left unevaluated so a branch is only folded when its value is known.
#[derive(Clone)]
enum ConstVal {
    None,
    Bool(bool),
    Int(BigInt),
    Float(f64),
    Str(Vec<u8>),
}

impl ConstVal {
    /// Python truthiness, used to pick a folded branch.
    fn truthy(&self) -> bool {
        match self {
            ConstVal::None => false,
            ConstVal::Bool(b) => *b,
            ConstVal::Int(i) => !i.is_zero(),
            ConstVal::Float(f) => *f != 0.0,
            ConstVal::Str(s) => !s.is_empty(),
        }
    }

    /// The numeric value of an int, bool, or float, for arithmetic and ordering.
    fn as_f64(&self) -> Option<f64> {
        match self {
            ConstVal::Bool(b) => Some(*b as i64 as f64),
            ConstVal::Int(i) => i.to_f64(),
            ConstVal::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// The integer value of an int or bool, for bitwise operations.
    fn as_int(&self) -> Option<BigInt> {
        match self {
            ConstVal::Bool(b) => Some(BigInt::from(*b as i64)),
            ConstVal::Int(i) => Some(i.clone()),
            _ => None,
        }
    }
}

/// Folds every opaque-predicate `CondBranch` in `cfg` to an unconditional jump.
pub fn simplify(cfg: &mut Cfg, code: &Code) {
    for idx in 0..cfg.blocks.len() {
        let Terminator::CondBranch {
            cond,
            if_true,
            if_false,
        } = cfg.blocks[idx].terminator
        else {
            continue;
        };
        if let Some(value) = eval_const(code, &cfg.arena, cond) {
            let target = if value.truthy() { if_true } else { if_false };
            cfg.blocks[idx].terminator = Terminator::Jump(target);
        }
    }
}

/// Evaluates an expression to a constant, or `None` if it is not statically known.
/// Conservative by construction: any operand or operation it cannot fold exactly
/// yields `None`, so a value is never guessed.
fn eval_const(code: &Code, arena: &ExprArena, id: ValueId) -> Option<ConstVal> {
    match arena.get(id) {
        Expr::Const(c) => obj_to_const(code.consts.get(c.0 as usize)?),
        Expr::Unary(op, operand) => {
            let value = eval_const(code, arena, *operand)?;
            match op {
                UnaryOp::Not => Some(ConstVal::Bool(!value.truthy())),
                UnaryOp::Positive => Some(value),
                UnaryOp::Negate => match value {
                    ConstVal::Int(i) => Some(ConstVal::Int(-i)),
                    ConstVal::Float(f) => Some(ConstVal::Float(-f)),
                    ConstVal::Bool(b) => Some(ConstVal::Int(-BigInt::from(b as i64))),
                    _ => None,
                },
                UnaryOp::Invert => value.as_int().map(|i| ConstVal::Int(!i)),
            }
        }
        Expr::BinOp(op, lhs, rhs) => {
            let lhs = eval_const(code, arena, *lhs)?;
            let rhs = eval_const(code, arena, *rhs)?;
            eval_binop(*op, &lhs, &rhs)
        }
        Expr::Compare(op, lhs, rhs) => {
            let lhs = eval_const(code, arena, *lhs)?;
            let rhs = eval_const(code, arena, *rhs)?;
            eval_compare(*op, &lhs, &rhs).map(ConstVal::Bool)
        }
        // `a and b` is the first falsy operand or the last; `a or b` the first
        // truthy or the last. Every operand must be foldable.
        Expr::BoolOp(kind, operands) => {
            let mut last = None;
            for operand in operands {
                let value = eval_const(code, arena, *operand)?;
                let short_circuits = match kind {
                    BoolKind::And => !value.truthy(),
                    BoolKind::Or => value.truthy(),
                };
                if short_circuits {
                    return Some(value);
                }
                last = Some(value);
            }
            last
        }
        _ => None,
    }
}

/// Folds an integer or float binary operation; bitwise operations require ints.
/// Division or modulo by zero is left unevaluated rather than folded.
fn eval_binop(op: BinOp, lhs: &ConstVal, rhs: &ConstVal) -> Option<ConstVal> {
    match op {
        BinOp::And | BinOp::Or | BinOp::Xor | BinOp::LeftShift | BinOp::RightShift => {
            let (a, b) = (lhs.as_int()?, rhs.as_int()?);
            Some(ConstVal::Int(match op {
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::LeftShift => a << b.to_usize()?,
                BinOp::RightShift => a >> b.to_usize()?,
                _ => unreachable!(),
            }))
        }
        BinOp::Add | BinOp::Subtract | BinOp::Multiply => {
            // Keep integers exact; fall back to float when either side is a float.
            if let (Some(a), Some(b)) = (lhs.as_int(), rhs.as_int()) {
                Some(ConstVal::Int(match op {
                    BinOp::Add => a + b,
                    BinOp::Subtract => a - b,
                    BinOp::Multiply => a * b,
                    _ => unreachable!(),
                }))
            } else {
                let (a, b) = (lhs.as_f64()?, rhs.as_f64()?);
                Some(ConstVal::Float(match op {
                    BinOp::Add => a + b,
                    BinOp::Subtract => a - b,
                    BinOp::Multiply => a * b,
                    _ => unreachable!(),
                }))
            }
        }
        BinOp::Modulo | BinOp::FloorDivide => {
            let (a, b) = (lhs.as_int()?, rhs.as_int()?);
            if b.is_zero() {
                return None;
            }
            // Python's `%` and `//` floor toward negative infinity.
            Some(ConstVal::Int(match op {
                BinOp::Modulo => python_mod(&a, &b),
                BinOp::FloorDivide => python_floordiv(&a, &b),
                _ => unreachable!(),
            }))
        }
        // Float division and exponentiation can lose precision or overflow; leave
        // these unevaluated so only exact results fold.
        BinOp::Divide | BinOp::TrueDivide | BinOp::Power => None,
    }
}

/// Floor division matching Python semantics (rounds toward negative infinity).
fn python_floordiv(a: &BigInt, b: &BigInt) -> BigInt {
    let q = a / b;
    let r = a % b;
    if !r.is_zero() && ((r < BigInt::from(0)) != (b < &BigInt::from(0))) {
        q - 1
    } else {
        q
    }
}

/// Modulo matching Python semantics (result has the sign of the divisor).
fn python_mod(a: &BigInt, b: &BigInt) -> BigInt {
    let r = a % b;
    if !r.is_zero() && ((r < BigInt::from(0)) != (b < &BigInt::from(0))) {
        r + b
    } else {
        r
    }
}

/// Evaluates a comparison to a boolean, for the orderings and equalities the
/// folder can decide exactly.
fn eval_compare(op: CmpOp, lhs: &ConstVal, rhs: &ConstVal) -> Option<bool> {
    use std::cmp::Ordering;
    let ordering = match (lhs, rhs) {
        (ConstVal::Str(a), ConstVal::Str(b)) => a.partial_cmp(b),
        (ConstVal::None, ConstVal::None) => Some(Ordering::Equal),
        _ => {
            let (a, b) = (lhs.as_f64()?, rhs.as_f64()?);
            a.partial_cmp(&b)
        }
    };
    // `is`/`is not` between two constants of the same kind behave like ==/!= here;
    // `in`/`not in`/exception-match need a container or type, so are not folded.
    Some(match op {
        CmpOp::Eq | CmpOp::Is => ordering == Some(Ordering::Equal),
        CmpOp::Ne | CmpOp::IsNot => ordering != Some(Ordering::Equal),
        CmpOp::Lt => ordering == Some(Ordering::Less),
        CmpOp::Le => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        CmpOp::Gt => ordering == Some(Ordering::Greater),
        CmpOp::Ge => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
        CmpOp::In | CmpOp::NotIn | CmpOp::ExceptionMatch => return None,
    })
}

/// Converts a marshalled constant into a foldable value, or `None` for types the
/// folder does not reason about.
fn obj_to_const(obj: &Obj) -> Option<ConstVal> {
    match obj {
        Obj::None => Some(ConstVal::None),
        Obj::Bool(b) => Some(ConstVal::Bool(*b)),
        Obj::Long(value) => Some(ConstVal::Int(value.read().unwrap().clone())),
        Obj::Float(f) => Some(ConstVal::Float(*f)),
        Obj::String(s) => Some(ConstVal::Str(s.read().unwrap().to_vec())),
        _ => None,
    }
}
