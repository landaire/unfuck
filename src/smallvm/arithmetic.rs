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
    fn apply_long_long(self, left: &BigInt, right: &BigInt) -> Option<Obj> {
        // Integer division or modulo by zero panics in num-bigint; opaque junk
        // can produce a zero divisor, so yield unknown instead.
        if matches!(
            self,
            BinaryOp::Divide | BinaryOp::FloorDivide | BinaryOp::Modulo
        ) && matches!(right.sign(), num_bigint::Sign::NoSign)
        {
            return None;
        }
        Some(Obj::Long(Arc::new(RwLock::new(match self {
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
        }))))
    }

    fn apply_long_float(self, left: &BigInt, right: f64) -> Option<Obj> {
        let left = left.to_f64().unwrap();
        Some(Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            _ => return None,
        }))
    }

    fn apply_float_long(self, left: f64, right: &BigInt) -> Option<Obj> {
        let right = right.to_f64().unwrap();
        Some(Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            _ => return None,
        }))
    }

    fn apply_float_float(self, left: f64, right: f64) -> Option<Obj> {
        Some(Obj::Float(match self {
            BinaryOp::Add => left + right,
            BinaryOp::Subtract => left - right,
            BinaryOp::Multiply => left * right,
            BinaryOp::Divide => left / right,
            _ => return None,
        }))
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
    T: Clone + Copy + Ord,
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
                // Opaque junk computes `base ** huge`, whose result has
                // exp * bits(base) bits and would allocate gigabytes before we
                // could use it. Bound the result and treat an oversized (or
                // out-of-u32-range) exponent as unknown -- real code never
                // raises to a billion-bit power, so these are only dead
                // predicates.
                const MAX_RESULT_BITS: u64 = 1 << 23; // ~1 MB
                let right_guard = right.read().unwrap();
                let exponent = right_guard.magnitude().to_u32();
                let base_bits = left.read().unwrap().bits().max(1);
                let oversized = match exponent {
                    Some(exp) => (exp as u64).saturating_mul(base_bits) > MAX_RESULT_BITS,
                    None => true,
                };
                if oversized {
                    stack.push((None, tos_accesses));
                    return Ok(());
                }
                let exp = exponent.unwrap();
                if let num_bigint::Sign::Minus = right_guard.sign() {
                    let value = left.read().unwrap().pow(exp);
                    stack.push((
                        Some(Obj::Float(1.0 / value.to_f64().unwrap())),
                        tos_accesses,
                    ));
                    return Ok(());
                } else {
                    let value = left.read().unwrap().pow(exp);
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

            // Multiply grows without bound -- a chain of `x * x` doubles the bit
            // count each step -- so junk opaque computation can balloon to
            // gigabytes. Cap the result (add/sub/bitwise stay within the operand
            // sizes, so only multiply needs guarding here).
            if let BinaryOp::Multiply = op {
                const MAX_RESULT_BITS: u64 = 1 << 23; // ~1 MB
                let bits = left
                    .read()
                    .unwrap()
                    .bits()
                    .saturating_add(right.read().unwrap().bits());
                if bits > MAX_RESULT_BITS {
                    stack.push((None, tos_accesses));
                    return Ok(());
                }
            }

            let result = op.apply_long_long(&left.read().unwrap(), &right.read().unwrap());
            stack.push((result, tos_accesses));
        }
        (Some(Obj::Long(left)), Some(Obj::Float(right))) => {
            let result = op.apply_long_float(&left.read().unwrap(), *right);
            stack.push((result, tos_accesses));
        }
        (Some(Obj::Float(left)), Some(Obj::Long(right))) => {
            let result = op.apply_float_long(*left, &right.read().unwrap());
            stack.push((result, tos_accesses));
        }
        (Some(Obj::Float(left)), Some(Obj::Float(right))) => {
            let result = op.apply_float_float(*left, *right);
            stack.push((result, tos_accesses));
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
            _ => stack.push((None, tos_accesses.clone())),
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
                        // The obfuscator feeds huge multipliers; partial execution only
                        // tracks the value, so materializing `str * huge` would allocate
                        // gigabytes and abort the process. Cap the result size and treat
                        // an oversized (or out-of-range) repetition as an unknown value.
                        const MAX_REPEAT_BYTES: usize = 1 << 20;
                        let count = right.read().unwrap().to_usize();
                        let len = left.read().unwrap().len();
                        match count.filter(|c| c.checked_mul(len).is_some_and(|n| n <= MAX_REPEAT_BYTES))
                        {
                            Some(count) => {
                                let value = left.read().unwrap().repeat(count);
                                stack.push((
                                    Some(Obj::String(Arc::new(RwLock::new(BString::from(value))))),
                                    tos_accesses,
                                ));
                            }
                            None => stack.push((None, tos_accesses)),
                        }
                    }
                    BinaryOp::Add => {
                        let mut new_val = left.read().unwrap().clone();
                        new_val.extend_from_slice(right.read().unwrap().to_string().as_bytes());
                        stack.push((
                            Some(Obj::String(Arc::new(RwLock::new(new_val)))),
                            tos_accesses,
                        ));
                    }
                    _ => stack.push((None, tos_accesses.clone())),
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
                    _ => stack.push((None, tos_accesses.clone())),
                },
                _ => stack.push((None, tos_accesses.clone())),
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
            _ => stack.push((None, tos_accesses.clone())),
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
    T: Clone + Copy + Ord,
{
    let (tos, tos_accesses) = stack_pop(stack)?;
    tos_accesses.push(access_tracking);

    match tos {
        Some(Obj::Bool(result)) => match op {
            UnaryOp::Not => stack.push((Some(Obj::Bool(!result)), tos_accesses)),
            UnaryOp::Negative => stack.push((
                Some(Obj::Long(Arc::new(RwLock::new(if result {
                    -BigInt::from(1)
                } else {
                    BigInt::from(0)
                })))),
                tos_accesses,
            )),
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
            // -None is a runtime TypeError in Python; treat as unknown rather
            // than panic during partial execution.
            UnaryOp::Negative => stack.push((None, tos_accesses)),
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
    T: Clone + Copy + Ord,
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
        // The obfuscator feeds huge shift amounts as junk opaque computation;
        // `x << huge` materializes a multi-gigabyte integer and aborts the
        // process. Bound a left shift's result and treat an oversized (or
        // out-of-range) shift as an unknown value -- real code never shifts by
        // millions of bits, so these only ever appear in dead predicates. A
        // right shift only shrinks the value, so it is always safe.
        const MAX_SHIFT_BITS: u64 = 1 << 23; // ~1 MB result
        let shift_amount = tos_value.unwrap().read().unwrap().to_usize();
        let value = match shift_amount {
            Some(shift_amount) => {
                let operand = tos1_value.unwrap();
                let operand = operand.read().unwrap();
                if is_left {
                    // A left shift grows the value by `shift_amount` bits; bound
                    // the total so an already-large operand cannot balloon.
                    if operand.bits().saturating_add(shift_amount as u64) <= MAX_SHIFT_BITS {
                        Some(&*operand << shift_amount)
                    } else {
                        None
                    }
                } else {
                    // A right shift only shrinks the value, so it is always safe.
                    Some(&*operand >> shift_amount)
                }
            }
            None => None,
        };
        match value {
            Some(value) => {
                stack.push((Some(Obj::Long(Arc::new(RwLock::new(value)))), tos_accesses))
            }
            None => stack.push((None, tos_accesses)),
        }
    } else {
        stack.push((None, tos_accesses));
    }

    Ok(())
}
