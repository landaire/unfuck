use log::warn;
use num_bigint::{BigInt, ToBigInt};
use num_integer::Integer;
use num_traits::ToPrimitive;
use py27_marshal::Obj;
use py27_marshal::bstr::BString;
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::sync::{Arc, RwLock};

use super::{VmStack, stack_pop};
use crate::error::Error;

/// Represents a binary arithmetic operation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    TrueDivide,
    Power,
    Modulo,
    Xor,
    And,
    Or,
}

impl BinaryOp {
    fn apply_long_long(self, left: &BigInt, right: &BigInt) -> Obj {
        Obj::Long(Arc::new(RwLock::new(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left.div_floor(right),
            BinaryOp::FloorDivide => left.div_floor(right),
            BinaryOp::Modulo => left.mod_floor(right),
            BinaryOp::Xor => left ^ right,
            BinaryOp::And => left & right,
            BinaryOp::Or => left | right,
            // Power and TrueDivide are handled specially before calling this
            BinaryOp::Power | BinaryOp::TrueDivide => {
                unreachable!("handled in apply_binary_op directly")
            }
        })))
    }

    fn apply_long_float(self, left: &BigInt, right: f64) -> Obj {
        let left = left.to_f64().unwrap();
        Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            other => panic!("operator {:?} not handled for Long x Float", other),
        })
    }

    fn apply_float_long(self, left: f64, right: &BigInt) -> Obj {
        let right = right.to_f64().unwrap();
        Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            other => panic!("operator {:?} not handled for Float x Long", other),
        })
    }

    fn apply_float_float(self, left: f64, right: f64) -> Obj {
        Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            other => panic!("operator {:?} not handled for Float x Float", other),
        })
    }
}

/// Executes a binary arithmetic operation by popping two values from the stack,
/// applying the operation, and pushing the result.
pub(crate) fn apply_binary_op<O, T>(
    op: BinaryOp,
    _instr: &Instruction<O>,
    stack: &mut VmStack<T>,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    T: Clone + Copy,
{
    let (tos, tos_accesses) = stack_pop(stack)?;
    let (tos1, tos1_accesses) = stack_pop(stack)?;

    tos_accesses.push(access_tracking);
    let tos_accesses = tos_accesses.deep_clone();
    tos_accesses.extend(&tos1_accesses);

    match (&tos1, &tos) {
        (Some(Obj::Long(left)), Some(Obj::Long(right))) => {
            // Special case: Power with negative exponent returns Float
            if let BinaryOp::Power = op {
                let right_guard = right.read().unwrap();
                if let num_bigint::Sign::Minus = right_guard.sign() {
                    let positive_exponent = (-&*right_guard).to_u32().unwrap();
                    let value = left.read().unwrap().pow(positive_exponent);
                    stack.push((
                        Some(Obj::Float(1.0 / value.to_f64().unwrap())),
                        tos_accesses,
                    ));
                    return Ok(());
                } else {
                    let value =
                        left.read()
                            .unwrap()
                            .pow(right_guard.to_u32().unwrap_or_else(|| {
                                panic!("could not convert {:?} to u32", right_guard)
                            }));
                    stack.push((Some(Obj::Long(Arc::new(RwLock::new(value)))), tos_accesses));
                    return Ok(());
                }
            }

            // Special case: TrueDivide converts to floats
            if let BinaryOp::TrueDivide = op {
                let value = left.read().unwrap().to_f64().unwrap()
                    / right.read().unwrap().to_f64().unwrap();
                stack.push((Some(Obj::Float(value)), tos_accesses));
                return Ok(());
            }

            let result = op.apply_long_long(&left.read().unwrap(), &right.read().unwrap());
            stack.push((Some(result), tos_accesses));
        }
        (Some(Obj::Long(left)), Some(Obj::Float(right))) => {
            let result = op.apply_long_float(&left.read().unwrap(), *right);
            stack.push((Some(result), tos_accesses));
        }
        (Some(Obj::Float(left)), Some(Obj::Long(right))) => {
            let result = op.apply_float_long(*left, &right.read().unwrap());
            stack.push((Some(result), tos_accesses));
        }
        (Some(Obj::Float(left)), Some(Obj::Float(right))) => {
            let result = op.apply_float_float(*left, *right);
            stack.push((Some(result), tos_accesses));
        }
        (Some(Obj::Set(left)), Some(Obj::Set(right))) => match op {
            BinaryOp::And => {
                let left_set = left.read().unwrap();
                let right_set = right.read().unwrap();
                let intersection = left_set.intersection(&right_set);
                stack.push((
                    Some(Obj::Set(Arc::new(std::sync::RwLock::new(
                        intersection
                            .cloned()
                            .collect::<std::collections::HashSet<_>>(),
                    )))),
                    tos_accesses,
                ));
            }
            BinaryOp::Or => {
                let left_set = left.read().unwrap();
                let right_set = right.read().unwrap();
                let union = left_set.union(&right_set);
                stack.push((
                    Some(Obj::Set(Arc::new(std::sync::RwLock::new(
                        union.cloned().collect::<std::collections::HashSet<_>>(),
                    )))),
                    tos_accesses,
                ));
            }
            other => panic!("unsupported operator {:?} for Set", other),
        },
        (Some(Obj::String(left)), _) => {
            // String formatting special case
            if let BinaryOp::Modulo = op {
                stack.push((
                    Some(Obj::String(Arc::new(RwLock::new(
                        left.read().unwrap().clone(),
                    )))),
                    tos_accesses,
                ));
                return Ok(());
            }
            match &tos {
                Some(Obj::Long(right)) => match op {
                    BinaryOp::Multiply => {
                        let value = left
                            .read()
                            .unwrap()
                            .repeat(right.read().unwrap().to_usize().unwrap());
                        stack.push((
                            Some(Obj::String(Arc::new(RwLock::new(BString::from(value))))),
                            tos_accesses,
                        ));
                    }
                    BinaryOp::Add => {
                        let mut new_val = left.read().unwrap().clone();
                        new_val.extend_from_slice(right.read().unwrap().to_string().as_bytes());
                        stack.push((
                            Some(Obj::String(Arc::new(RwLock::new(new_val)))),
                            tos_accesses,
                        ));
                    }
                    other => panic!("unsupported operator {:?} for LHS String RHS Long", other),
                },
                Some(Obj::String(right)) => match op {
                    BinaryOp::Add => {
                        let mut new_val = left.read().unwrap().clone();
                        new_val.extend_from_slice(right.read().unwrap().as_slice());
                        stack.push((
                            Some(Obj::String(Arc::new(RwLock::new(new_val)))),
                            tos_accesses,
                        ));
                    }
                    other => panic!("unsupported operator {:?} for LHS String RHS String", other),
                },
                Some(right) => panic!(
                    "unsupported RHS. left: String, right: {:?}. operator: {:?}",
                    right.typ(),
                    op
                ),
                None => stack.push((None, tos_accesses)),
            }
        }
        (Some(Obj::Tuple(left)), Some(Obj::Tuple(right))) => match op {
            BinaryOp::Add => {
                let mut new_val = left.read().unwrap().clone();
                new_val.extend(right.read().unwrap().iter().cloned());
                stack.push((
                    Some(Obj::Tuple(Arc::new(RwLock::new(new_val)))),
                    tos_accesses,
                ));
            }
            other => panic!("unsupported operator {:?} for Tuple", other),
        },
        (Some(left), Some(right)) => {
            warn!(
                "unsupported LHS {:?} for operator {:?}. right was {:?}",
                left.typ(),
                op,
                right.typ()
            );
            stack.push((None, tos_accesses));
        }
        (Some(_left), None) => {
            stack.push((None, tos_accesses));
        }
        (None, _) => {
            stack.push((None, tos_accesses));
        }
    }

    Ok(())
}

/// Represents a unary operation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum UnaryOp {
    Not,
    Negative,
}

/// Executes a unary operation by popping one value from the stack,
/// applying the operation, and pushing the result.
pub(crate) fn apply_unary_op<O, T>(
    op: UnaryOp,
    stack: &mut VmStack<T>,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    T: Clone + Copy,
{
    let (tos, tos_accesses) = stack_pop(stack)?;
    tos_accesses.push(access_tracking);

    match tos {
        Some(Obj::Bool(result)) => match op {
            UnaryOp::Not => stack.push((Some(Obj::Bool(!result)), tos_accesses)),
            UnaryOp::Negative => panic!("unexpected unary operator Negative for bool"),
        },
        Some(Obj::Long(result)) => match op {
            UnaryOp::Not => {
                let truthy_value = *result.read().unwrap() != 0_i32.to_bigint().unwrap();
                stack.push((Some(Obj::Bool(!truthy_value)), tos_accesses));
            }
            UnaryOp::Negative => {
                stack.push((
                    Some(Obj::Long(Arc::new(RwLock::new(-&*result.read().unwrap())))),
                    tos_accesses,
                ));
            }
        },
        Some(Obj::None) => match op {
            UnaryOp::Not => stack.push((Some(Obj::Bool(true)), tos_accesses)),
            UnaryOp::Negative => panic!("unexpected unary operator Negative for None"),
        },
        Some(_other) => {
            stack.push((None, tos_accesses));
        }
        None => {
            stack.push((None, tos_accesses));
        }
    }

    Ok(())
}

/// Executes a shift operation (BINARY_LSHIFT or BINARY_RSHIFT).
pub(crate) fn execute_shift<O, T>(
    instr: &Instruction<O>,
    stack: &mut VmStack<T>,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    T: Clone + Copy,
{
    let is_left = matches!(
        instr.opcode.mnemonic(),
        Mnemonic::BINARY_LSHIFT | Mnemonic::INPLACE_LSHIFT
    );

    let (tos, tos_accesses) = stack_pop(stack)?;
    let tos_value = tos.and_then(|tos| match tos {
        Obj::Long(l) => Some(Arc::clone(&l)),
        _ => None,
    });
    let (tos1, tos1_accesses) = stack_pop(stack)?;
    let tos1_value = tos1.and_then(|tos| match tos {
        Obj::Long(l) => Some(Arc::clone(&l)),
        _ => None,
    });

    let tos_accesses = if is_left {
        tos_accesses.deep_clone()
    } else {
        tos_accesses
    };
    tos_accesses.extend(&tos1_accesses);
    tos_accesses.push(access_tracking);

    if tos_value.is_some() && tos1_value.is_some() {
        let shift_amount = tos_value.unwrap().read().unwrap().to_usize().unwrap();
        let value = if is_left {
            &*tos1_value.unwrap().read().unwrap() << shift_amount
        } else {
            &*tos1_value.unwrap().read().unwrap() >> shift_amount
        };
        stack.push((Some(Obj::Long(Arc::new(RwLock::new(value)))), tos_accesses));
    } else {
        stack.push((None, tos_accesses));
    }

    Ok(())
}
