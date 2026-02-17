use num_bigint::ToBigInt;
use num_traits::ToPrimitive;
use py27_marshal::*;
use pydis::opcode::py27;
use pydis::prelude::*;

use std::sync::Arc;
use super::{PYTHON27_COMPARE_OPS, VmStack, stack_pop};
use crate::error::Error;

/// Executes a COMPARE_OP instruction.
pub(crate) fn execute_compare_op<O, T>(
    instr: &Instruction<O>,
    stack: &mut VmStack<T>,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    T: Clone + Copy,
{
    let (right, right_modifying_instrs) = stack_pop(stack)?;
    let (left, left_modifying_instrs) = stack_pop(stack)?;

    left_modifying_instrs.push(access_tracking);
    let left_modifying_instrs = left_modifying_instrs.deep_clone();
    left_modifying_instrs.extend(&right_modifying_instrs);

    if right.is_none() || left.is_none() {
        stack.push((None, left_modifying_instrs));
        return Ok(());
    }

    let left = left.unwrap();
    let right = right.unwrap();

    let op = PYTHON27_COMPARE_OPS[instr.arg.unwrap() as usize];
    match op {
        "<" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() < *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() < r)),
                    left_modifying_instrs,
                )),
                other => panic!("unsupported right-hand operand: {:?}", other.typ()),
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l < r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l < r)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Float <: {:?}",
                    other.typ()
                ),
            },
            Obj::String(left) => match right {
                Obj::String(right) => {
                    let left_guard = left.read().unwrap();
                    let right_guard = right.read().unwrap();
                    for idx in 0..std::cmp::min(left_guard.len(), right_guard.len()) {
                        if left_guard[idx] != right_guard[idx] {
                            stack.push((
                                Some(Obj::Bool(left_guard[idx] < right_guard[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left_guard.len() < right_guard.len())),
                        left_modifying_instrs,
                    ))
                }
                _other => {
                    stack.push((Some(Obj::Bool(false)), left_modifying_instrs));
                }
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        "<=" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() <= *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() <= r)),
                    left_modifying_instrs,
                )),
                other => panic!(
                    "unsupported right-hand operand for Long <=: {:?}",
                    other.typ()
                ),
            },
            Obj::Bool(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool((l as u32).to_bigint().unwrap() <= *r.read().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool((l as u64) as f64 <= r)),
                    left_modifying_instrs,
                )),
                Obj::Bool(r) => {
                    stack.push((Some(Obj::Bool(l as u32 <= r as u32)), left_modifying_instrs))
                }
                other => panic!(
                    "unsupported right-hand operand for Bool <=: {:?}",
                    other.typ()
                ),
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l <= r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l <= r)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Float <=: {:?}",
                    other.typ()
                ),
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        "==" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() == *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() == r)),
                    left_modifying_instrs,
                )),
                other => panic!(
                    "unsupported right-hand operand for Long ==: {:?}",
                    other.typ()
                ),
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l == r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l == r)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Float ==: {:?}",
                    other.typ()
                ),
            },
            Obj::Set(left_set) => match right {
                Obj::Set(right_set) => {
                    let left_set_lock = left_set.read().unwrap();
                    let right_set_lock = right_set.read().unwrap();
                    stack.push((
                        Some(Obj::Bool(*left_set_lock == *right_set_lock)),
                        left_modifying_instrs,
                    ))
                }
                other => panic!(
                    "unsupported right-hand operand for Set == : {:?}",
                    other.typ()
                ),
            },
            Obj::String(left_str) => match right {
                Obj::String(right_str) => {
                    let result = *left_str.read().unwrap() == *right_str.read().unwrap();
                    stack.push((Some(Obj::Bool(result)), left_modifying_instrs));
                }
                _ => {
                    stack.push((Some(Obj::Bool(false)), left_modifying_instrs));
                }
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        "!=" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() != *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() != r)),
                    left_modifying_instrs,
                )),
                other => panic!(
                    "unsupported right-hand operand for Long !=: {:?}",
                    other.typ()
                ),
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l != r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l != r)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Float !=: {:?}",
                    other.typ()
                ),
            },
            Obj::Set(left_set) => match right {
                Obj::Set(right_set) => {
                    let left_set_lock = left_set.read().unwrap();
                    let right_set_lock = right_set.read().unwrap();
                    stack.push((
                        Some(Obj::Bool(*left_set_lock != *right_set_lock)),
                        left_modifying_instrs,
                    ))
                }
                other => panic!("unsupported right-hand operand for !=: {:?}", other.typ()),
            },
            Obj::String(left_str) => match right {
                Obj::String(right_str) => {
                    let result = *left_str.read().unwrap() != *right_str.read().unwrap();
                    stack.push((Some(Obj::Bool(result)), left_modifying_instrs));
                }
                _ => {
                    stack.push((Some(Obj::Bool(true)), left_modifying_instrs));
                }
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        ">" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() > *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() > r)),
                    left_modifying_instrs,
                )),
                other => panic!(
                    "unsupported right-hand operand for Long >: {:?}",
                    other.typ()
                ),
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l > r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l > r)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Float >: {:?}",
                    other.typ()
                ),
            },
            Obj::String(left) => match right {
                Obj::String(right) => {
                    let left_guard = left.read().unwrap();
                    let right_guard = right.read().unwrap();
                    for idx in 0..std::cmp::min(left_guard.len(), right_guard.len()) {
                        if left_guard[idx] != right_guard[idx] {
                            stack.push((
                                Some(Obj::Bool(left_guard[idx] > right_guard[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left_guard.len() > right_guard.len())),
                        left_modifying_instrs,
                    ))
                }
                _other => {
                    stack.push((Some(Obj::Bool(true)), left_modifying_instrs));
                }
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        ">=" => match left {
            Obj::Long(l) => match right {
                Obj::Long(r) => stack.push((Some(Obj::Bool(*l.read().unwrap() >= *r.read().unwrap())), left_modifying_instrs)),
                Obj::Float(r) => stack.push((
                    Some(Obj::Bool(l.read().unwrap().to_f64().unwrap() >= r)),
                    left_modifying_instrs,
                )),
                other => {
                    panic!("unsupported right-hand operand for Long: {:?}", other.typ())
                }
            },
            Obj::Float(l) => match right {
                Obj::Long(r) => stack.push((
                    Some(Obj::Bool(l >= r.read().unwrap().to_f64().unwrap())),
                    left_modifying_instrs,
                )),
                Obj::Float(r) => stack.push((Some(Obj::Bool(l >= r)), left_modifying_instrs)),
                other => {
                    panic!("unsupported right-hand operand for Long: {:?}", other.typ())
                }
            },
            Obj::Tuple(left_tuple) => match right {
                Obj::Tuple(right_tuple) => {
                    let left_guard = left_tuple.read().unwrap();
                    let right_guard = right_tuple.read().unwrap();
                    // Lexicographic comparison for tuples
                    let mut result = true; // default: left >= right if all equal
                    for (l, r) in left_guard.iter().zip(right_guard.iter()) {
                        match (l, r) {
                            (Obj::Long(ll), Obj::Long(rl)) => {
                                let ll = ll.read().unwrap();
                                let rl = rl.read().unwrap();
                                if *ll > *rl {
                                    result = true;
                                    break;
                                } else if *ll < *rl {
                                    result = false;
                                    break;
                                }
                            }
                            (Obj::Float(ll), Obj::Float(rl)) => {
                                if ll > rl {
                                    result = true;
                                    break;
                                } else if ll < rl {
                                    result = false;
                                    break;
                                }
                            }
                            (Obj::String(ll), Obj::String(rl)) => {
                                let ll = ll.read().unwrap();
                                let rl = rl.read().unwrap();
                                if *ll > *rl {
                                    result = true;
                                    break;
                                } else if *ll < *rl {
                                    result = false;
                                    break;
                                }
                            }
                            _ => {
                                // For unsupported element types, treat as unresolvable
                                stack.push((None, left_modifying_instrs));
                                return Ok(());
                            }
                        }
                    }
                    // If all compared elements are equal, check lengths
                    if left_guard.len() != right_guard.len() {
                        let min_len = std::cmp::min(left_guard.len(), right_guard.len());
                        let all_equal = left_guard.iter().zip(right_guard.iter()).take(min_len).all(|(l, r)| {
                            match (l, r) {
                                (Obj::Long(ll), Obj::Long(rl)) => *ll.read().unwrap() == *rl.read().unwrap(),
                                (Obj::Float(ll), Obj::Float(rl)) => ll == rl,
                                (Obj::String(ll), Obj::String(rl)) => *ll.read().unwrap() == *rl.read().unwrap(),
                                _ => false,
                            }
                        });
                        if all_equal {
                            result = left_guard.len() >= right_guard.len();
                        }
                    }
                    stack.push((Some(Obj::Bool(result)), left_modifying_instrs));
                }
                other => panic!(
                    "unsupported right-hand operand for Tuple >=: {:?}",
                    other.typ()
                ),
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        "is not" => match left {
            Obj::Long(_) => match right {
                Obj::None => stack.push((Some(Obj::Bool(true)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for Long {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            Obj::String(_) => match right {
                Obj::None => stack.push((Some(Obj::Bool(true)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for string {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            Obj::None => match right {
                Obj::None => stack.push((Some(Obj::Bool(false)), left_modifying_instrs)),
                other => panic!(
                    "unsupported right-hand operand for None, operator {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}. RHS is {:?}",
                other.typ(),
                op,
                right.typ(),
            ),
        },
        "is" => match left {
            Obj::String(_) => match right {
                other => panic!(
                    "unsupported right-hand operand for string {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            Obj::None => match right {
                Obj::None => {
                    stack.push((Some(Obj::Bool(true)), left_modifying_instrs));
                }
                other => panic!(
                    "unsupported right-hand operand for None {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },
        "in" => match left {
            Obj::String(left) => match right {
                Obj::Dict(set) => {
                    let dict = set.read().unwrap();
                    let hashed_string = ObjHashable::String(Arc::new(left.read().unwrap().clone()));
                    stack.push((
                        Some(Obj::Bool(dict.contains_key(&hashed_string))),
                        left_modifying_instrs,
                    ));
                }
                Obj::Set(set) => {
                    let set = set.read().unwrap();
                    let hashed_string = ObjHashable::String(Arc::new(left.read().unwrap().clone()));
                    stack.push((
                        Some(Obj::Bool(set.contains(&hashed_string))),
                        left_modifying_instrs,
                    ));
                }
                Obj::List(set) => {
                    let list = set.read().unwrap();
                    let left_guard = left.read().unwrap();
                    let list_contains = list.iter().find(|obj| {
                        if let Obj::String(list_item) = obj {
                            *list_item.read().unwrap() == *left_guard
                        } else {
                            false
                        }
                    });
                    stack.push((
                        Some(Obj::Bool(list_contains.is_some())),
                        left_modifying_instrs,
                    ));
                }
                Obj::Tuple(tuple) => {
                    let tuple = tuple.read().unwrap();
                    let left_guard = left.read().unwrap();
                    let tuple_contains = tuple.iter().any(|obj| {
                        if let Obj::String(item) = obj {
                            *item.read().unwrap() == *left_guard
                        } else {
                            false
                        }
                    });
                    stack.push((
                        Some(Obj::Bool(tuple_contains)),
                        left_modifying_instrs,
                    ));
                }
                other => panic!(
                    "unsupported right-hand operand for string operator {:?}: {:?}",
                    op,
                    other.typ()
                ),
            },
            other => panic!(
                "unsupported left-hand operand: {:?} for op {}",
                other.typ(),
                op
            ),
        },

        other => panic!(
            "unsupported comparison operator: {:?} (left: {:?}, right: {:?})",
            other, left, right
        ),
    }

    Ok(())
}
