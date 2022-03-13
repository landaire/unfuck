use log::{debug, trace};
use num_bigint::{ToBigInt};
use num_traits::{Pow, ToPrimitive};
use py27_marshal::bstr::BString;
use py27_marshal::*;
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

pub enum WalkerState {
    /// Continue parsing normally
    Continue,
    /// Continue parsing and parse the next instruction even if it's already
    /// been parsed before
    ContinueIgnoreAnalyzedInstructions,
    /// Stop parsing
    Break,
    /// Immediately start parsing at the given offset and continue parsing
    JumpTo(u64),
    /// Assume the result of the previous comparison evaluated to the given bool
    /// and continue parsing
    AssumeComparison(bool),
}

impl WalkerState {
    /// Returns whether we need to force queue the next instruction
    fn force_queue_next(&self) -> bool {
        matches!(
            self,
            Self::ContinueIgnoreAnalyzedInstructions | Self::JumpTo(_) | Self::AssumeComparison(_)
        )
    }
}

/// Represents a VM variable. The value is either `Some` (something we can)
/// statically resolve or `None` (something that cannot be resolved statically)
pub type VmVar = Option<Obj>;
/// A VM variable and the data it tracks. Typically this will be a VmVarWithTracking<()>,
/// or VmVarWithTracking<usize> where the usize represents an instruction index. But,
/// this can be anything you'd like it to be within the context of how you'll be executing
/// the instruction, and what data you'd like to track across instructions that share data.
pub type VmVarWithTracking<T> = (VmVar, InstructionTracker<T>);
/// The VM's stack state.
pub type VmStack<T> = Vec<VmVarWithTracking<T>>;
/// The VM's variable table
pub type VmVars<T> = HashMap<u16, VmVarWithTracking<T>>;
/// The VM's name table
pub type VmNames<T> = HashMap<Arc<BString>, VmVarWithTracking<T>>;
/// Names that get loaded while executing the VM. These are identifiers such as
/// module names and names *from* modules.
pub type LoadedNames = Arc<Mutex<Vec<Arc<BString>>>>;

/// Implements high-level routines that are useful when performing taint tracking
/// operations
#[derive(Debug)]
pub struct InstructionTracker<T>(pub Arc<Mutex<Vec<T>>>);

/// We implement a custom Clone routine since, in some scenarios, we want to share
/// the taint tracking across multiple objects in different locations. e.g. we may
/// want to share taint tracking state between our saved objects in our tables (vm vars, names, etc.)
/// and variables on the stack.
impl<T> Clone for InstructionTracker<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        InstructionTracker(Arc::clone(&self.0))
    }
}

impl<T> InstructionTracker<T>
where
    T: Clone,
{
    /// Creates a new instruction tracker with no tracked data.
    pub fn new() -> InstructionTracker<T> {
        InstructionTracker(Arc::new(Mutex::new(vec![])))
    }

    /// Performs a deep clone of this instruction tracking state
    pub fn deep_clone(&self) -> InstructionTracker<T> {
        InstructionTracker(Arc::new(Mutex::new(self.0.lock().unwrap().clone())))
    }

    /// Pushes new data into the instruction tracking vector
    pub fn push(&self, data: T) {
        self.0.lock().unwrap().push(data)
    }

    /// Extends the state of this instruction tracker by copying all items from `other`'s
    /// tracked state into this.
    pub fn extend(&self, other: &InstructionTracker<T>) {
        self.0
            .lock()
            .unwrap()
            .extend_from_slice(other.0.lock().unwrap().as_slice());
    }
}

/// SAFETY: The data in an `InstructionTracker` is wrapped in an Arc<Mutex<T>>
unsafe impl<T: Sync + Send> Send for InstructionTracker<T> {}
/// SAFETY: The data in an `InstructionTracker` is wrapped in an Arc<Mutex<T>>
unsafe impl<T: Sync + Send> Sync for InstructionTracker<T> {}

use py27_marshal::ObjHashable;

use crate::error::Error;

pub(crate) const PYTHON27_COMPARE_OPS: [&str; 12] = [
    "<",
    "<=",
    "==",
    "!=",
    ">",
    ">=",
    "in",
    "not in",
    "is",
    "is not",
    "exception match",
    "BAD",
];

/// Executes an instruction, altering the input state and returning an error
/// when the instruction cannot be correctly emulated. For example, some complex
/// instructions are not currently supported at this time.
pub fn execute_instruction<O: Opcode<Mnemonic = py27::Mnemonic>, F, T>(
    instr: &Instruction<O>,
    code: Arc<Code>,
    stack: &mut VmStack<T>,
    vars: &mut VmVars<T>,
    names: &mut VmNames<T>,
    globals: &mut VmNames<T>,
    names_loaded: LoadedNames,
    mut function_callback: F,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    F: FnMut(VmVar, Vec<VmVar>, std::collections::HashMap<Option<ObjHashable>, VmVar>) -> VmVar,
    T: Clone + Copy,
{
    macro_rules! apply_operator {
        ($operator_str:expr) => {
            let (tos, tos_accesses) = stack.pop().expect("no top of stack?");
            let (tos1, tos1_accesses) = stack.pop().expect("no operand");

            tos_accesses.push(access_tracking);

            let tos_accesses = tos_accesses.deep_clone();
            tos_accesses.extend(&tos1_accesses);

            let operator_str = $operator_str;
            match &tos1 {
                Some(Obj::Long(left)) => {
                    match &tos {
                        Some(Obj::Long(right)) => {
                            let value = match operator_str {
                                "^" => {
                                    left.as_ref() ^ right.as_ref()
                                }
                                "|" => {
                                    left.as_ref() | right.as_ref()
                                }
                                "&" => {
                                    left.as_ref() & right.as_ref()
                                }
                                "%" => {
                                    left.as_ref() % right.as_ref()
                                }
                                "-" => {
                                    left.as_ref() - right.as_ref()
                                }
                                "+" => {
                                    left.as_ref() + right.as_ref()
                                }
                                "*" => {
                                    left.as_ref() * right.as_ref()
                                }
                                "/" => {
                                    left.as_ref() / right.as_ref()
                                }
                                "//" => {
                                    left.as_ref() / right.as_ref()
                                }
                                "**" => {
                                    // Check if our exponent is negative
                                    if let num_bigint::Sign::Minus = right.sign() {
                                        let positive_exponent = (-right.as_ref()).to_u32().unwrap();
                                        let value = left.as_ref().pow(positive_exponent);

                                        stack.push((
                                            Some(Obj::Float(1.0 / value.to_f64().unwrap())),
                                            tos_accesses,
                                        ));
                                        return Ok(());
                                    } else {
                                        left.as_ref().pow(right.as_ref().to_u32().unwrap_or_else(|| panic!("could not convert {:?} to u32", right)))
                                    }
                                }
                                "///" => {
                                    // triple division is true divide -- convert to floats
                                    let value = left.as_ref().to_f64().unwrap() / right.as_ref().to_f64().unwrap();
                                    stack.push((
                                        Some(Obj::Float(value)),
                                        tos_accesses,
                                    ));
                                    return Ok(());
                                }
                                other => {
                                    panic!("operator {:?} not handled for Long operands", other);
                                }
                            };
                            stack.push((
                                Some(Obj::Long(Arc::new(
                                    value
                                ))),
                                tos_accesses,
                            ));
                        }
                        Some(Obj::Float(right)) => {
                            match operator_str {
                                "*" => {
                                    // For longs we can just use the operator outright
                                    let value = left.as_ref().to_f64().unwrap() * right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "/" => {
                                    // For longs we can just use the operator outright
                                    let value = left.as_ref().to_f64().unwrap() / right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "+" => {
                                    // For longs we can just use the operator outright
                                    let value = left.as_ref().to_f64().unwrap() / right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "-" => {
                                    // For longs we can just use the operator outright
                                    let value = left.as_ref().to_f64().unwrap() / right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                _other => panic!("unsupported RHS. left: {:?}, right: {:?}. operator: {}", tos1.unwrap().typ(), "Float", operator_str),
                            }
                        }
                        Some(right)=> panic!("unsupported RHS. left: {:?}, right: {:?}. operator: {}", tos1.unwrap().typ(), right.typ(), operator_str),
                        None => stack.push((None, tos_accesses)),
                    }
                }
                Some(Obj::Float(left)) => {
                    match &tos {
                        Some(Obj::Float(right)) => {
                            match operator_str {
                                "*" => {
                                    // For longs we can just use the operator outright
                                    let value = left * right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "-" => {
                                    // For longs we can just use the operator outright
                                    let value = left - right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "+" => {
                                    // For longs we can just use the operator outright
                                    let value = left + right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                "/" => {
                                    // For longs we can just use the operator outright
                                    let value = left + right;
                                    stack.push((
                                        Some(Obj::Float(
                                            value
                                        )),
                                        tos_accesses,
                                    ));
                                }
                                _ => panic!("operator {:?} not handled for float", operator_str),
                            }
                        }
                        Some(Obj::String(right)) => {
                            panic!("{:?}", right);
                            //return Err(crate::error::ExecutionError::ComplexExpression(instr.clone(), Some(tos1.unwrap().typ())).into());
                        }
                        Some(right)=> panic!("unsupported RHS. left: {:?}, right: {:?}. operator: {}", tos1.unwrap().typ(), right.typ(), operator_str),
                        None => stack.push((None, tos_accesses)),
                    }
                }
                Some(Obj::Set(left)) => {
                    match &tos {
                        Some(Obj::Set(right)) => {
                            match operator_str {
                                "&" => {
                                    let left_set = left.read().unwrap();
                                    let right_set = right.read().unwrap();
                                    let intersection = left_set.intersection(&right_set);

                                    stack.push((
                                        Some(Obj::Set(Arc::new(
                                            std::sync::RwLock::new(
                                            intersection.cloned().collect::<std::collections::HashSet<_>>()
                                        )
                                        ))),
                                        tos_accesses,
                                    ));
                                }
                                "|" => {
                                    let left_set = left.read().unwrap();
                                    let right_set = right.read().unwrap();
                                    let union = left_set.union(&right_set);

                                    stack.push((
                                        Some(Obj::Set(Arc::new(
                                            std::sync::RwLock::new(
                                            union.cloned().collect::<std::collections::HashSet<_>>()
                                        )
                                        ))),
                                        tos_accesses,
                                    ));
                                }
                                other => panic!("unsupported operator `{}` for {:?}", other, "set")
                            }
                        }
                        Some(right)=> panic!("unsupported RHS. left: {:?}, right: {:?}. operator: {}", tos1.unwrap().typ(), right.typ(), operator_str),
                        None => stack.push((None, tos_accesses)),
                    }
                }
                Some(Obj::String(left)) => {
                    // special case -- this is string formatting
                    if operator_str == "%" {
                        stack.push((
                            Some(Obj::String(Arc::new(
                                left.as_ref().clone()
                            ))),
                            tos_accesses,
                        ));
                        return Ok(());
                    }
                    match &tos{
                        Some(Obj::Long(right)) => {
                            match operator_str {
                                "*" => {
                                    let value = left.repeat(right.to_usize().unwrap());
                                    stack.push((
                                        Some(Obj::String(Arc::new(
                                            BString::from(value)
                                        ))),
                                        tos_accesses,
                                    ));
                                }
                                "+" => {
                                    let mut value = left.clone();
                                    unsafe { Arc::get_mut_unchecked(&mut value) }.extend_from_slice(right.to_string().as_bytes());
                                    stack.push((
                                        Some(Obj::String(value)),
                                        tos_accesses,
                                    ));
                                }
                                _other => panic!("unsupported operator {:?} for LHS {:?} RHS {:?}", operator_str, tos1.unwrap().typ(), tos.unwrap().typ())
                            }
                        }
                        Some(Obj::String(right)) => {
                            match operator_str {
                                "+" => {
                                    let mut value = left.clone();
                                    unsafe { Arc::get_mut_unchecked(&mut value) }.extend_from_slice(right.as_slice());
                                    stack.push((
                                        Some(Obj::String(value)),
                                        tos_accesses,
                                    ));
                                }
                                _other => {
                                    //return Err(crate::error::ExecutionError::ComplexExpression(instr.clone(), Some(tos1.unwrap().typ())).into());
                                    panic!("unsupported operator {:?} for LHS {:?} RHS {:?}", operator_str, tos1.unwrap().typ(), tos.unwrap().typ())
                                }
                            }
                        }
                        Some(right)=> panic!("unsupported RHS. left: {:?}, right: {:?}. operator: {}", tos1.unwrap().typ(), right.typ(), operator_str),
                        None => stack.push((None, tos_accesses)),
                    }
                }
                Some(left)=> match &tos {
                    Some(right) => {
                        panic!("unsupported LHS {:?} for operator {:?}. right was {:?}", left.typ(), operator_str, right.typ())
                    }
                    None => {
                        panic!("unsupported LHS {:?} for operator {:?}. right was None", left.typ(), operator_str)
                    }
                }
                None => {
                    stack.push((None, tos_accesses));
                }
            }
        };
    }

    use num_traits::Signed;
    macro_rules! apply_unary_operator {
        ($operator:tt) => {
            let (tos, tos_accesses) = stack.pop().expect("no top of stack?");

            tos_accesses.push(access_tracking);

            let operator_str = stringify!($operator);
            match tos {
                Some(Obj::Bool(result)) => {
                    let val = match operator_str {
                        "!" => !result,
                        other => panic!("unexpected unary operator {:?} for bool", other),
                    };
                    stack.push((Some(Obj::Bool(val)), tos_accesses));
                }
                Some(Obj::Long(result)) => {
                    let val = match operator_str {
                        "!" => {
                            let truthy_value = *result != 0.to_bigint().unwrap();
                            stack.push((Some(Obj::Bool(!truthy_value)), tos_accesses));
                            return Ok(());
                        }
                        "-" => -&*result,
                        "+" => result.abs(),
                        "~" => !&*result,
                        other => panic!("unexpected unary operator {:?} for bool", other),
                    };
                    stack.push((Some(Obj::Long(Arc::new(val))), tos_accesses));
                }
                Some(Obj::None) => {
                    let val = match operator_str {
                        "!" => true,
                        other => panic!("unexpected unary operator {:?} for None", other),
                    };
                    stack.push((Some(Obj::Bool(val)), tos_accesses));
                }
                Some(other) => {
                    panic!("unexpected TOS type for condition: {:?}", other.typ());
                }
                None => {
                    stack.push((None, tos_accesses));
                }
            }
        };
    }

    match instr.opcode.mnemonic() {
        Mnemonic::ROT_TWO => {
            let (tos, tos_accesses) = stack.pop().unwrap();
            let (tos1, tos1_accesses) = stack.pop().unwrap();
            tos_accesses.push(access_tracking);
            tos1_accesses.push(access_tracking);

            stack.push((tos1, tos1_accesses));
            stack.push((tos, tos_accesses));
        }
        Mnemonic::ROT_THREE => {
            let (tos, tos_accesses) = stack.pop().unwrap();
            let (tos1, tos1_accesses) = stack.pop().unwrap();
            let (tos2, tos2_accesses) = stack.pop().unwrap();
            tos_accesses.push(access_tracking);
            tos1_accesses.push(access_tracking);
            tos2_accesses.push(access_tracking);

            stack.push((tos2, tos2_accesses));
            stack.push((tos1, tos1_accesses));
            stack.push((tos, tos_accesses));
        }
        Mnemonic::DUP_TOP => {
            let (var, accesses) = stack.last().unwrap();
            accesses.push(access_tracking);
            let new_var = (var.clone(), accesses.deep_clone());
            stack.push(new_var);
        }
        Mnemonic::COMPARE_OP => {
            let (right, right_modifying_instrs) = stack.pop().unwrap();
            let (left, left_modifying_instrs) = stack.pop().unwrap();

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
                        Obj::Long(r) => stack.push((Some(Obj::Bool(l < r)), left_modifying_instrs)),
                        other => panic!("unsupported right-hand operand: {:?}", other.typ()),
                    },
                    Obj::String(left) => match right {
                        Obj::String(right) => {
                            for idx in 0..std::cmp::min(left.len(), right.len()) {
                                if left[idx] != right[idx] {
                                    stack.push((
                                        Some(Obj::Bool(left[idx] < right[idx])),
                                        left_modifying_instrs,
                                    ));
                                    return Ok(());
                                }
                            }
                            stack.push((
                                Some(Obj::Bool(left.len() < right.len())),
                                left_modifying_instrs,
                            ))
                        }
                        _other => {
                            stack.push((Some(Obj::Bool(false)), left_modifying_instrs));
                            //     panic!(
                            //     "unsupported right-hand operand for string >: {:?}",
                            //     other.typ()
                            // )
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
                        Obj::Long(r) => {
                            stack.push((Some(Obj::Bool(l <= r)), left_modifying_instrs))
                        }
                        Obj::Float(r) => stack.push((
                            Some(Obj::Bool(l.to_f64().unwrap() <= r)),
                            left_modifying_instrs,
                        )),
                        other => panic!(
                            "unsupported right-hand operand for Long <=: {:?}",
                            other.typ()
                        ),
                    },
                    Obj::Bool(l) => match right {
                        Obj::Long(r) => stack.push((
                            Some(Obj::Bool((l as u32).to_bigint().unwrap() <= *r)),
                            left_modifying_instrs,
                        )),
                        Obj::Float(r) => stack.push((
                            Some(Obj::Bool((l as u64) as f64 <= r)),
                            left_modifying_instrs,
                        )),
                        Obj::Bool(r) => stack
                            .push((Some(Obj::Bool(l as u32 <= r as u32)), left_modifying_instrs)),
                        other => panic!(
                            "unsupported right-hand operand for Long <=: {:?}",
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
                        Obj::Long(r) => {
                            stack.push((Some(Obj::Bool(l == r)), left_modifying_instrs))
                        }
                        other => panic!(
                            "unsupported right-hand operand for Long ==: {:?}",
                            other.typ()
                        ),
                    },
                    Obj::Set(left_set) => match right {
                        Obj::Set(right_set) => {
                            let left_set_lock = left_set.read().unwrap();
                            let right_set_lock = right_set.read().unwrap();
                            stack.push((
                                Some(Obj::Bool(&*left_set_lock == &*right_set_lock)),
                                left_modifying_instrs,
                            ))
                        }
                        other => panic!(
                            "unsupported right-hand operand for Set == : {:?}",
                            other.typ()
                        ),
                    },
                    other => panic!(
                        "unsupported left-hand operand: {:?} for op {}",
                        other.typ(),
                        op
                    ),
                },
                "!=" => match left {
                    Obj::Long(l) => match right {
                        Obj::Long(r) => {
                            stack.push((Some(Obj::Bool(l != r)), left_modifying_instrs))
                        }
                        other => panic!(
                            "unsupported right-hand operand for Long !=: {:?}",
                            other.typ()
                        ),
                    },
                    Obj::Set(left_set) => match right {
                        Obj::Set(right_set) => {
                            let left_set_lock = left_set.read().unwrap();
                            let right_set_lock = right_set.read().unwrap();
                            stack.push((
                                Some(Obj::Bool(&*left_set_lock != &*right_set_lock)),
                                left_modifying_instrs,
                            ))
                        }
                        other => panic!("unsupported right-hand operand for !=: {:?}", other.typ()),
                    },
                    other => panic!(
                        "unsupported left-hand operand: {:?} for op {}",
                        other.typ(),
                        op
                    ),
                },
                ">" => match left {
                    Obj::Long(l) => match right {
                        Obj::Long(r) => stack.push((Some(Obj::Bool(l > r)), left_modifying_instrs)),
                        Obj::Float(r) => stack.push((
                            Some(Obj::Bool(l.to_f64().unwrap() > r)),
                            left_modifying_instrs,
                        )),
                        other => panic!(
                            "unsupported right-hand operand for Long >: {:?}",
                            other.typ()
                        ),
                    },
                    Obj::String(left) => match right {
                        Obj::String(right) => {
                            for idx in 0..std::cmp::min(left.len(), right.len()) {
                                if left[idx] != right[idx] {
                                    stack.push((
                                        Some(Obj::Bool(left[idx] > right[idx])),
                                        left_modifying_instrs,
                                    ));
                                    return Ok(());
                                }
                            }
                            stack.push((
                                Some(Obj::Bool(left.len() > right.len())),
                                left_modifying_instrs,
                            ))
                        }
                        _other => {
                            stack.push((Some(Obj::Bool(true)), left_modifying_instrs));
                            //     panic!(
                            //     "unsupported right-hand operand for string >: {:?}",
                            //     other.typ()
                            // )
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
                        Obj::Long(r) => {
                            stack.push((Some(Obj::Bool(l >= r)), left_modifying_instrs))
                        }
                        Obj::Float(r) => stack.push((
                            Some(Obj::Bool(l.to_f64().unwrap() >= r)),
                            left_modifying_instrs,
                        )),
                        other => {
                            panic!("unsupported right-hand operand for Long: {:?}", other.typ())
                        }
                    },
                    other => panic!(
                        "unsupported left-hand operand: {:?} for op {}",
                        other.typ(),
                        op
                    ),
                },
                "is not" => match left {
                    Obj::String(_left) => match right {
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
                    Obj::String(_left) => match right {
                        // all => {
                        //     return Err(crate::error::ExecutionError::ComplexExpression(
                        //         instr.clone(),
                        //         Some(all.typ()),
                        //     )
                        //     .into())
                        // }
                        // Obj::None => stack.push((Some(Obj::Bool(true)), left_modifying_instrs)),
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
                other => panic!("unsupported comparison operator: {:?}", other),
            }
        }
        Mnemonic::IMPORT_NAME => {
            let (_fromlist, fromlist_modifying_instrs) = stack.pop().unwrap();
            let (_level, level_modifying_instrs) = stack.pop().unwrap();

            level_modifying_instrs.extend(&fromlist_modifying_instrs);
            level_modifying_instrs.push(access_tracking);

            let _name = &code.names[instr.arg.unwrap() as usize];
            // println!("importing: {}", name);

            stack.push((None, level_modifying_instrs));
        }
        Mnemonic::IMPORT_FROM => {
            let (_module, accessing_instrs) = stack.last().unwrap();
            accessing_instrs.push(access_tracking);
            let accessing_instrs = accessing_instrs.clone();

            stack.push((None, accessing_instrs));
        }
        Mnemonic::LOAD_ATTR => {
            // we don't support attributes
            let (_obj, obj_modifying_instrs) = stack.pop().unwrap();
            let _name = &code.names[instr.arg.unwrap() as usize];

            obj_modifying_instrs.push(access_tracking);

            stack.push((None, obj_modifying_instrs));
        }
        Mnemonic::STORE_ATTR => {
            // we don't support attributes
            let (_obj, _obj_modifying_instrs) = stack.pop().unwrap();
            let (_obj, _obj_modifying_instrs) = stack.pop().unwrap();
        }
        Mnemonic::FOR_ITER => {
            // Top of stack needs to be something we can iterate over
            // get the next item from our iterator
            let top_of_stack_index = stack.len() - 1;
            let (tos, _modifying_instrs) = &mut stack[top_of_stack_index];
            let new_tos = match tos {
                Some(Obj::String(s)) => {
                    if let Some(byte) = unsafe { Arc::get_mut_unchecked(s) }.pop() {
                        Some(Obj::Long(Arc::new(byte.to_bigint().unwrap())))
                    } else {
                        // iterator is empty -- return
                        return Ok(());
                    }
                }
                Some(other) => panic!("stack object `{:?}` is not iterable", other),
                None => None,
            };

            // let modifying_instrs = Rc::new(RefCell::new(modifying_instrs.borrow().clone()));
            // modifying_instrs.borrow_mut().push(access_tracking);

            stack.push((new_tos, InstructionTracker::new()))
        }
        Mnemonic::STORE_FAST => {
            let (tos, accessing_instrs) = stack.pop().unwrap();
            accessing_instrs.push(access_tracking);
            // Store TOS in a var slot
            vars.insert(instr.arg.unwrap(), (tos, accessing_instrs));
        }
        Mnemonic::STORE_NAME => {
            let (tos, accessing_instrs) = stack.pop().unwrap();
            let name = &code.names[instr.arg.unwrap() as usize];
            accessing_instrs.push(access_tracking);
            // Store TOS in a var slot
            names.insert(Arc::clone(name), (tos, accessing_instrs));
        }
        Mnemonic::LOAD_NAME => {
            let name = &code.names[instr.arg.unwrap() as usize];
            names_loaded.lock().unwrap().push(Arc::clone(name));
            if let Some((val, accesses)) = names.get(name) {
                accesses.push(access_tracking);
                stack.push((val.clone(), accesses.clone()));
            } else {
                let tracking = InstructionTracker::new();
                tracking.push(access_tracking);
                stack.push((None, tracking));
            }
        }
        Mnemonic::LOAD_FAST => {
            if let Some((var, accesses)) = vars.get(&instr.arg.unwrap()) {
                accesses.push(access_tracking);
                stack.push((var.clone(), accesses.clone()));
            } else {
                let tracking = InstructionTracker::new();
                tracking.push(access_tracking);
                stack.push((None, tracking));
            }
        }
        Mnemonic::LOAD_CONST => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);

            stack.push((
                Some(code.consts[instr.arg.unwrap() as usize].clone()),
                tracking,
            ));
        }
        Mnemonic::BINARY_FLOOR_DIVIDE => {
            apply_operator!("//");
        }
        Mnemonic::BINARY_TRUE_DIVIDE => {
            apply_operator!("///");
        }
        Mnemonic::BINARY_POWER => {
            apply_operator!("**");
        }
        Mnemonic::BINARY_MODULO => {
            apply_operator!("%");
        }
        Mnemonic::INPLACE_ADD | Mnemonic::BINARY_ADD => {
            apply_operator!("+");
        }
        Mnemonic::INPLACE_MULTIPLY | Mnemonic::BINARY_MULTIPLY => {
            apply_operator!("*");
        }
        Mnemonic::INPLACE_SUBTRACT | Mnemonic::BINARY_SUBTRACT => {
            apply_operator!("-");
        }
        Mnemonic::STORE_SUBSCR => {
            let (key, key_accessing_instrs) = stack.pop().unwrap();
            let (collection, collection_accessing_instrs) = stack.pop().unwrap();
            let (value, value_accessing_instrs) = stack.pop().unwrap();

            collection_accessing_instrs.extend(&key_accessing_instrs);

            collection_accessing_instrs.extend(&value_accessing_instrs);

            collection_accessing_instrs.push(access_tracking);

            // If key, value, or the collection are `None`, we destroy the entire collection
            // TODO: allow more granular failure of taint tracking at a per-index level

            match (collection, key, value) {
                (Some(collection), Some(key), Some(value)) => match collection {
                    Obj::Dict(list_lock) => {
                        let mut dict = list_lock.write().unwrap();
                        let key = ObjHashable::try_from(&key).expect("key is not hashable");
                        dict.insert(key, value);
                    }
                    Obj::List(list_lock) => {
                        let mut list = list_lock.write().unwrap();
                        let index = key.extract_long().expect("key is not a long");
                        let index = index
                            .to_usize()
                            .expect("index cannot be converted to usize");
                        if index > list.len() {
                            panic!("index {} is greater than list length {}", index, list.len());
                        }

                        list[index] = value;
                    }
                    other => {
                        panic!("need to implement STORE_SUBSCR for {:?}", other.typ());
                    }
                },
                _ => {
                    // we do nothing
                }
            }
        }
        Mnemonic::BINARY_SUBSC => {
            let (tos, accessing_instrs) = stack.pop().unwrap();
            let (tos1, tos1_accessing_instrs) = stack.pop().unwrap();
            accessing_instrs.extend(&tos1_accessing_instrs);
            accessing_instrs.push(access_tracking);

            if tos.is_none() {
                stack.push((None, accessing_instrs));
                return Ok(());
            }

            match tos1 {
                Some(Obj::List(list_lock)) => {
                    let list = list_lock.read().unwrap();
                    if let Obj::Long(long) = tos.unwrap() {
                        if long.to_usize().unwrap() >= list.len() {
                            stack.push((None, accessing_instrs));
                        } else {
                            stack.push((
                                Some(list[long.to_usize().unwrap()].clone()),
                                accessing_instrs,
                            ));
                        }
                    } else {
                        panic!("TOS must be a long");
                    }
                }
                Some(other) => {
                    return Err(crate::error::ExecutionError::ComplexExpression(
                        instr.clone(),
                        Some(other.typ()),
                    )
                    .into());
                }
                None => {
                    stack.push((None, accessing_instrs));
                }
            }
        }
        Mnemonic::BINARY_DIVIDE => {
            apply_operator!("/");
        }
        Mnemonic::BINARY_XOR => {
            apply_operator!("^");
        }
        Mnemonic::BINARY_AND => {
            apply_operator!("&");
        }
        Mnemonic::BINARY_OR | Mnemonic::INPLACE_OR => {
            apply_operator!("|");
        }
        Mnemonic::UNARY_NOT => {
            apply_unary_operator!(!);
        }
        Mnemonic::UNARY_NEGATIVE => {
            apply_unary_operator!(-);
        }
        Mnemonic::BINARY_RSHIFT => {
            let (tos, tos_accesses) = stack.pop().unwrap();
            let tos_value = tos.map(|tos| match tos {
                Obj::Long(l) => Arc::clone(&l),
                other => panic!("did not expect type: {:?}", other.typ()),
            });
            let (tos1, tos1_accesses) = stack.pop().unwrap();
            let tos1_value = tos1.map(|tos| match tos {
                Obj::Long(l) => Arc::clone(&l),
                other => panic!("did not expect type: {:?}", other.typ()),
            });

            tos_accesses.extend(&tos1_accesses);

            tos_accesses.push(access_tracking);
            if tos_value.is_some() && tos1_value.is_some() {
                stack.push((
                    Some(Obj::Long(Arc::new(
                        &*tos1_value.unwrap() >> tos_value.unwrap().to_usize().unwrap(),
                    ))),
                    tos_accesses,
                ));
            } else {
                stack.push((None, tos_accesses));
            }
        }
        Mnemonic::BINARY_LSHIFT => {
            let (tos, tos_accesses) = stack.pop().unwrap();
            let tos_value = tos.map(|tos| match tos {
                Obj::Long(l) => Arc::clone(&l),
                other => panic!("did not expect type: {:?}", other.typ()),
            });
            let (tos1, tos1_accesses) = stack.pop().unwrap();
            let tos1_value = tos1.map(|tos| match tos {
                Obj::Long(l) => Arc::clone(&l),
                other => panic!("did not expect type: {:?}", other.typ()),
            });

            let tos_accesses = tos_accesses.deep_clone();

            tos_accesses.extend(&tos1_accesses);
            tos_accesses.push(access_tracking);

            if tos_value.is_some() && tos1_value.is_some() {
                stack.push((
                    Some(Obj::Long(Arc::new(
                        &*tos1_value.unwrap() << tos_value.unwrap().to_usize().unwrap(),
                    ))),
                    tos_accesses,
                ));
            } else {
                stack.push((None, tos_accesses));
            }
        }
        Mnemonic::LIST_APPEND => {
            let (tos, tos_modifiers) = stack.pop().unwrap();
            let tos_value = tos.map(|tos| {
                match tos {
                    Obj::Long(l) => Arc::clone(&l),
                    other => panic!("did not expect type: {:?}", other.typ()),
                }
                .to_u8()
                .unwrap()
            });

            let stack_len = stack.len();
            let (output, output_modifiers) = &mut stack[stack_len - instr.arg.unwrap() as usize];

            output_modifiers.extend(&tos_modifiers);
            output_modifiers.push(access_tracking);

            match output {
                Some(Obj::String(s)) => {
                    unsafe { Arc::get_mut_unchecked(s) }.push(tos_value.unwrap());
                }
                Some(other) => {
                    return Err(crate::error::ExecutionError::ComplexExpression(
                        instr.clone(),
                        Some(other.typ()),
                    )
                    .into());
                }
                None => {
                    // do nothing here
                }
            }
        }
        Mnemonic::UNPACK_SEQUENCE => {
            let (tos, tos_modifiers) = stack.pop().unwrap();

            tos_modifiers.push(access_tracking);

            match tos {
                Some(Obj::Tuple(t)) => {
                    for item in t.iter().rev().take(instr.arg.unwrap() as usize) {
                        stack.push((Some(item.clone()), tos_modifiers.deep_clone()));
                    }
                }
                Some(other) => {
                    panic!("need to add UNPACK_SEQUENCE support for {:?}", other.typ());
                }
                None => {
                    for _i in 0..instr.arg.unwrap() {
                        stack.push((None, tos_modifiers.deep_clone()));
                    }
                }
            }
        }
        Mnemonic::BUILD_SET => {
            let mut set = std::collections::HashSet::new();
            let mut push_none = false;

            let set_accessors = InstructionTracker::new();
            for _i in 0..instr.arg.unwrap() {
                let (tos, tos_modifiers) = stack.pop().unwrap();
                set_accessors.extend(&tos_modifiers);
                // we don't build the set if we can't resolve the args
                if tos.is_none() || push_none {
                    push_none = true;
                    continue;
                }

                tos_modifiers.push(access_tracking);

                set.insert(py27_marshal::ObjHashable::try_from(&tos.unwrap()).unwrap());
            }

            set_accessors.push(access_tracking);

            if push_none {
                stack.push((None, set_accessors));
            } else {
                stack.push((
                    Some(Obj::Set(Arc::new(std::sync::RwLock::new(set)))),
                    set_accessors,
                ));
            }
        }
        Mnemonic::BUILD_TUPLE => {
            let mut tuple = Vec::new();
            let mut push_none = false;

            let tuple_accessors = InstructionTracker::new();
            for _i in 0..instr.arg.unwrap() {
                let (tos, tos_modifiers) = stack.pop().unwrap();
                tuple_accessors.extend(&tos_modifiers);
                // we don't build the set if we can't resolve the args
                if tos.is_none() || push_none {
                    push_none = true;
                    continue;
                }

                tos_modifiers.push(access_tracking);
                tuple.push(tos.unwrap());
            }

            tuple_accessors.push(access_tracking);
            if push_none {
                stack.push((None, tuple_accessors));
            } else {
                stack.push((Some(Obj::Tuple(Arc::new(tuple))), tuple_accessors));
            }
        }
        Mnemonic::BUILD_MAP => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);

            let map = Some(Obj::Dict(Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(instr.arg.unwrap() as usize),
            ))));

            stack.push((map, tracking));
        }
        Mnemonic::LOAD_GLOBAL => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);

            let name = &code.names[instr.arg.unwrap() as usize];
            names_loaded.lock().unwrap().push(Arc::clone(name));

            stack.push((None, tracking));
        }
        Mnemonic::STORE_GLOBAL => {
            let (tos, accessing_instrs) = stack.pop().unwrap();
            let name = &code.names[instr.arg.unwrap() as usize];
            accessing_instrs.push(access_tracking);
            // Store TOS in a var slot
            globals.insert(Arc::clone(name), (tos, accessing_instrs));
        }
        Mnemonic::LOAD_DEREF => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);

            stack.push((None, tracking));
        }
        Mnemonic::BUILD_LIST => {
            let mut list = Vec::new();
            // TODO: this is always true right now to avoid
            // testing empty sets that are added to as truthy values
            let mut push_none = true;

            let tuple_accessors = InstructionTracker::new();
            for _i in 0..instr.arg.unwrap() {
                let (tos, tos_modifiers) = stack.pop().unwrap();
                tuple_accessors.extend(&tos_modifiers);
                // we don't build the set if we can't resolve the args
                if tos.is_none() {
                    push_none = true;
                    break;
                }

                tos_modifiers.push(access_tracking);

                list.push(tos.unwrap());
            }
            tuple_accessors.push(access_tracking);
            if push_none {
                stack.push((None, tuple_accessors));
            } else {
                stack.push((
                    Some(Obj::List(Arc::new(std::sync::RwLock::new(list)))),
                    tuple_accessors,
                ));
            }
        }
        Mnemonic::BUILD_CLASS => {
            let (_tos, tos_accesses) = stack.pop().unwrap();
            let (_tos1, tos1_accesses) = stack.pop().unwrap();
            let (_tos2, tos2_accesses) = stack.pop().unwrap();
            tos_accesses.extend(&tos1_accesses);
            tos_accesses.extend(&tos2_accesses);
            tos_accesses.push(access_tracking);

            stack.push((None, tos_accesses));
        }
        Mnemonic::MAKE_FUNCTION => {
            let (_tos, tos_modifiers) = stack.pop().unwrap();
            let tos_modifiers = tos_modifiers.deep_clone();
            tos_modifiers.push(access_tracking);

            stack.push((None, tos_modifiers));
        }
        Mnemonic::POP_TOP => {
            let (_tos, tos_modifiers) = stack.pop().unwrap();
            tos_modifiers.push(access_tracking);
        }
        Mnemonic::GET_ITER => {
            // nop
        }
        Mnemonic::CALL_FUNCTION => {
            let accessed_instrs = InstructionTracker::new();

            let kwarg_count = (instr.arg.unwrap() >> 8) & 0xFF;
            let mut kwargs = std::collections::HashMap::with_capacity(kwarg_count as usize);
            for _ in 0..kwarg_count {
                let (value, value_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&value_accesses);

                let (key, key_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&key_accesses);
                let key = key.map(|key| ObjHashable::try_from(&key).unwrap());
                kwargs.insert(key, value);
            }

            let positional_args_count = instr.arg.unwrap() & 0xFF;
            let mut args = Vec::with_capacity(positional_args_count as usize);
            for _ in 0..positional_args_count {
                let (arg, arg_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&arg_accesses);
                args.push(arg);
            }

            // Function code reference
            // NOTE: we skip the function accesses here since we don't really
            // want to be tracking across functions
            let function = stack.pop().unwrap();
            let result = function_callback(function.0, args, kwargs);

            accessed_instrs.push(access_tracking);

            stack.push((result, accessed_instrs));

            // No name resolution for now -- let's assume this is ord().
            // This function is a nop since it returns its input
            // panic!(
            //     "we're calling a function with {} args: {:#?}",
            //     instr.arg.unwrap(),
            //     stack[stack.len() - (1 + instr.arg.unwrap()) as usize]
            // );
        }
        Mnemonic::CALL_FUNCTION_VAR => {
            let (_additional_positional_args, arg_accesses) = stack.pop().unwrap();
            let accessed_instrs = arg_accesses.deep_clone();

            let kwarg_count = (instr.arg.unwrap() >> 8) & 0xFF;
            let mut kwargs = std::collections::HashMap::with_capacity(kwarg_count as usize);
            for _ in 0..kwarg_count {
                let (value, value_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&value_accesses);

                let (key, key_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&key_accesses);
                let key = key.map(|key| ObjHashable::try_from(&key).unwrap());
                kwargs.insert(key, value);
            }

            let positional_args_count = instr.arg.unwrap() & 0xFF;
            let mut args = Vec::with_capacity(positional_args_count as usize);
            for _ in 0..positional_args_count {
                let (arg, arg_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&arg_accesses);
                args.push(arg);
            }

            // Function code reference
            // NOTE: we skip the function accesses here since we don't really
            // want to be tracking across functions
            let function = stack.pop().unwrap();
            let result = function_callback(function.0, args, kwargs);

            accessed_instrs.push(access_tracking);

            stack.push((result, accessed_instrs));
        }
        Mnemonic::CALL_FUNCTION_KW => {
            let (_additional_kw_args, arg_accesses) = stack.pop().unwrap();
            let accessed_instrs = arg_accesses.deep_clone();

            let kwarg_count = (instr.arg.unwrap() >> 8) & 0xFF;
            let mut kwargs = std::collections::HashMap::with_capacity(kwarg_count as usize);
            for _ in 0..kwarg_count {
                let (value, value_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&value_accesses);

                let (key, key_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&key_accesses);
                let key = key.map(|key| ObjHashable::try_from(&key).unwrap());
                kwargs.insert(key, value);
            }

            let positional_args_count = instr.arg.unwrap() & 0xFF;
            let mut args = Vec::with_capacity(positional_args_count as usize);
            for _ in 0..positional_args_count {
                let (arg, arg_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&arg_accesses);
                args.push(arg);
            }

            // Function code reference
            // NOTE: we skip the function accesses here since we don't really
            // want to be tracking across functions
            let function = stack.pop().unwrap();
            let result = function_callback(function.0, args, kwargs);

            accessed_instrs.push(access_tracking);

            stack.push((result, accessed_instrs));
        }
        Mnemonic::CALL_FUNCTION_VAR_KW => {
            let (_additional_kw_args, arg_accesses) = stack.pop().unwrap();
            let accessed_instrs = arg_accesses.deep_clone();
            let (_additional_positional_args, arg_accesses) = stack.pop().unwrap();
            accessed_instrs.extend(&arg_accesses);

            let kwarg_count = (instr.arg.unwrap() >> 8) & 0xFF;
            let mut kwargs = std::collections::HashMap::with_capacity(kwarg_count as usize);
            for _ in 0..kwarg_count {
                let (value, value_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&value_accesses);

                let (key, key_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&key_accesses);
                let key = key.map(|key| ObjHashable::try_from(&key).unwrap());
                kwargs.insert(key, value);
            }

            let positional_args_count = instr.arg.unwrap() & 0xFF;
            let mut args = Vec::with_capacity(positional_args_count as usize);
            for _ in 0..positional_args_count {
                let (arg, arg_accesses) = stack.pop().unwrap();
                accessed_instrs.extend(&arg_accesses);
                args.push(arg);
            }

            // Function code reference
            // NOTE: we skip the function accesses here since we don't really
            // want to be tracking across functions
            let function = stack.pop().unwrap();
            let result = function_callback(function.0, args, kwargs);

            accessed_instrs.push(access_tracking);

            stack.push((result, accessed_instrs));
        }
        Mnemonic::POP_BLOCK | Mnemonic::JUMP_ABSOLUTE => {
            // nops
        }
        Mnemonic::PRINT_ITEM => {
            stack.pop();
        }
        Mnemonic::PRINT_ITEM_TO => {
            stack.pop();
            stack.pop();
        }
        Mnemonic::PRINT_NEWLINE => {
            // nop
        }
        Mnemonic::PRINT_NEWLINE_TO => {
            stack.pop();
        }
        Mnemonic::STORE_MAP => {
            let (key, key_accesses) = stack.pop().unwrap();
            let (value, value_accesses) = stack.pop().unwrap();
            let (dict, dict_accesses) = stack.pop().unwrap();

            let new_accesses = dict_accesses;
            new_accesses.extend(&value_accesses);
            new_accesses.extend(&key_accesses);
            new_accesses.push(access_tracking);

            if dict.is_none() || key.is_none() || value.is_none() {
                // We cannot track the state of at least one of these variables. Corrupt
                // the entire state.
                // TODO: this is a bit aggressive. In the future when we develop a new map type
                // we should be able to track individual keys
                stack.push((None, new_accesses));

                return Ok(());
            }

            let dict_lock = dict.unwrap().extract_dict().unwrap();
            let mut dict = dict_lock.write().unwrap();
            let hashable_key: ObjHashable = key
                .as_ref()
                .unwrap()
                .try_into()
                .expect("key is not hashable");
            dict.insert(hashable_key, value.unwrap());

            drop(dict);

            stack.push((Some(Obj::Dict(dict_lock)), new_accesses));
        }
        Mnemonic::MAP_ADD => {
            return Err(
                crate::error::ExecutionError::UnsupportedOpcode(Mnemonic::MAP_ADD.into()).into(),
            );

            // let (value, value_accesses) = stack.pop().unwrap();
            // let (dict, dict_accesses) = stack.pop().unwrap();

            // let mut new_accesses = dict_accesses;
            // new_accesses.extend(&value_accesses);
            // new_accesses.push(access_tracking);

            // if dict.is_none() || key.is_none() || value.is_none() {
            //     // We cannot track the state of at least one of these variables. Corrupt
            //     // the entire state.
            //     // TODO: this is a bit aggressive. In the future when we develop a new map type
            //     // we should be able to track individual keys
            //     stack.push((None, new_accesses));

            //     return Ok(());
            // }

            // let arc_dict = dict.unwrap().extract_dict().unwrap();
            // let mut dict = arc_dict.write().unwrap();
            // let hashable_key: ObjHashable = key.as_ref().unwrap().try_into().expect("key is not hashable");
            // dict.insert(hashable_key, value.unwrap());

            // drop(dict);

            // stack.push((Some(Obj::Dict(arc_dict)), new_accesses));
        }
        Mnemonic::YIELD_VALUE => {
            // todo: add to generator
            let (_tos, _accesses) = stack.pop().unwrap();
        }
        other => {
            return Err(crate::error::ExecutionError::UnsupportedOpcode(other.into()).into());
        }
    }

    Ok(())
}

/// Represents an instruction that was parsed from its raw bytecode.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParsedInstr<O: Opcode<Mnemonic = py27::Mnemonic>> {
    Good(Arc<Instruction<O>>),
    Bad,
}

impl<O: Opcode<Mnemonic = py27::Mnemonic>> ParsedInstr<O> {
    #[track_caller]
    pub fn unwrap(&self) -> Arc<Instruction<O>> {
        if let ParsedInstr::Good(ins) = self {
            Arc::clone(ins)
        } else {
            panic!("unwrap called on bad instruction")
        }
    }
}

/// Walks the bytecode in a manner that only follows what "looks like" valid
/// codepaths. This will only decode instructions that are either proven statically
/// to be taken (with `JUMP_ABSOLUTE`, `JUMP_IF_TRUE` with a const value that evaluates
/// to true, etc.)
pub fn const_jmp_instruction_walker<F, O: Opcode<Mnemonic = py27::Mnemonic>>(
    bytecode: &[u8],
    consts: Arc<Vec<Obj>>,
    mut callback: F,
) -> Result<BTreeMap<u64, ParsedInstr<O>>, Error<O>>
where
    F: FnMut(&Instruction<O>, u64) -> WalkerState,
{
    let debug = !true;
    let mut rdr = Cursor::new(bytecode);
    let mut instruction_sequence = Vec::new();
    let mut analyzed_instructions = BTreeMap::<u64, ParsedInstr<O>>::new();
    // Offset of instructions that need to be read
    let mut instruction_queue = VecDeque::<u64>::new();

    instruction_queue.push_front(0);

    macro_rules! queue {
        ($offset:expr) => {
            queue!($offset, false)
        };
        ($offset:expr, $force_queue:expr) => {
            if $offset as usize > bytecode.len() {
                panic!(
                    "bad offset queued: 0x{:X} (bufsize is 0x{:X}). Analyzed instructions: {:#?}",
                    $offset,
                    bytecode.len(),
                    analyzed_instructions
                );
            }

            if $force_queue {
                if debug {
                    trace!("adding instruction at {} to front queue", $offset);
                }
                instruction_queue.push_front($offset);
            } else if (!analyzed_instructions.contains_key(&$offset)
                && !instruction_queue.contains(&$offset))
            {
                if debug {
                    trace!("adding instruction at {} to queue", $offset);
                }
                instruction_queue.push_back($offset);
            }
        };
    };

    if debug {
        trace!("{:#?}", consts);
    }

    'decode_loop: while let Some(offset) = instruction_queue.pop_front() {
        if debug {
            trace!("offset: {}", offset);
        }

        if offset as usize == bytecode.len() {
            continue;
        }

        rdr.set_position(offset);
        // Ignore invalid instructions
        let instr = match decode_py27(&mut rdr) {
            Ok(instr) => Arc::new(instr),
            Err(e @ pydis::error::DecodeError::UnknownOpcode(_)) => {
                trace!("");
                debug!(
                    "Error decoding queued instruction at position: {}: {}",
                    offset, e
                );

                trace!(
                    "previous: {:?}",
                    instruction_sequence[instruction_sequence.len() - 1]
                );

                //remove_bad_instructions_behind_offset(offset, &mut analyzed_instructions);
                // rdr.set_position(offset);
                // let instr_size = rdr.position() - offset;
                // let mut data = vec![0u8; instr_size as usize];
                // rdr.read_exact(data.as_mut_slice())?;

                // let data_rc = Rc::new(data);
                analyzed_instructions.insert(offset, ParsedInstr::Bad);
                instruction_sequence.push(ParsedInstr::Bad);

                //queue!(rdr.position());
                continue;
            }
            Err(e) => {
                if cfg!(debug_assertions) {
                    panic!("{:?}", e);
                }
                return Err(e.into());
            }
        };
        trace!("{}", bytecode[offset as usize]);
        trace!("{:?}", instr);

        let next_instr_offset = rdr.position();

        let state = callback(&instr, offset);
        // We should stop decoding now
        if matches!(state, WalkerState::Break) {
            break;
        }

        if let WalkerState::JumpTo(offset) = &state {
            queue!(*offset, true);
            continue;
        }

        //println!("Instruction: {:X?}", instr);
        instruction_sequence.push(ParsedInstr::Good(Arc::clone(&instr)));
        analyzed_instructions.insert(offset, ParsedInstr::Good(Arc::clone(&instr)));

        let mut ignore_jump_target = false;

        if instr.opcode.is_jump() {
            if matches!(
                instr.opcode.mnemonic(),
                Mnemonic::JUMP_ABSOLUTE | Mnemonic::JUMP_FORWARD
            ) {
                // We've reached an unconditional jump. We need to decode the target
                let target = if instr.opcode.is_relative_jump() {
                    next_instr_offset + instr.arg.unwrap() as u64
                } else {
                    instr.arg.unwrap() as u64
                };

                if target as usize >= bytecode.len() {
                    // This is a bad instruction. Replace it with bad instr
                    analyzed_instructions.insert(offset, ParsedInstr::Bad);
                    instruction_sequence.push(ParsedInstr::Bad);
                    continue;
                }

                rdr.set_position(target);
                match decode_py27::<O, _>(&mut rdr) {
                    Ok(_instr) => {
                        // Queue the target
                        queue!(target, state.force_queue_next());
                        continue;
                    }
                    Err(e @ pydis::error::DecodeError::UnknownOpcode(_)) => {
                        // Definitely do not queue this target
                        ignore_jump_target = true;

                        debug!(
                            "Error while parsing target opcode: {} at position {}",
                            e, offset
                        );
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }

        let ignore_jump_target = false;
        if !ignore_jump_target && instr.opcode.is_absolute_jump() {
            if instr.arg.unwrap() as usize > bytecode.len() {
                debug!("instruction {:?} at {} has a bad target", instr, offset);
            //remove_bad_instructions_behind_offset(offset, &mut analyzed_instructions);
            } else {
                queue!(instr.arg.unwrap() as u64, state.force_queue_next());
            }
        }

        if !ignore_jump_target && instr.opcode.is_relative_jump() {
            let target = next_instr_offset + instr.arg.unwrap() as u64;
            if target as usize > bytecode.len() {
                debug!("instruction {:?} at {} has a bad target", instr, offset);
            //remove_bad_instructions_behind_offset(offset, &mut analyzed_instructions);
            } else {
                queue!(target as u64);
            }
        }

        if instr.opcode.mnemonic() != Mnemonic::RETURN_VALUE
            && instr.opcode.mnemonic() != Mnemonic::RAISE_VARARGS
        {
            queue!(next_instr_offset, state.force_queue_next());
        }
    }

    if true || debug {
        trace!("analyzed\n{:#?}", analyzed_instructions);
    }

    Ok(analyzed_instructions)
}

fn remove_bad_instructions_behind_offset<O: Opcode<Mnemonic = py27::Mnemonic>>(
    offset: u64,
    analyzed_instructions: &mut BTreeMap<u64, Arc<Instruction<O>>>,
) {
    // We need to remove all instructions parsed between the last
    // conditional jump and this instruction
    if let Some(last_jump_offset) = analyzed_instructions
        .iter()
        .rev()
        .find_map(|(addr, instr)| {
            if *addr < offset && instr.opcode.is_jump() {
                Some(*addr)
            } else {
                None
            }
        })
    {
        let bad_offsets: Vec<u64> = analyzed_instructions
            .keys()
            .into_iter()
            .filter(|addr| **addr > last_jump_offset && **addr < offset)
            .copied()
            .collect();

        for offset in bad_offsets {
            trace!("removing {:?}", analyzed_instructions.get(&offset));
            analyzed_instructions.remove(&offset);
        }
    }
}

#[macro_export]
macro_rules! Instr {
    ($opcode:expr) => {
        Instruction {
            opcode: $opcode,
            arg: None,
        }
    };
    ($opcode:expr, $arg:expr) => {
        Instruction {
            opcode: $opcode,
            arg: Some($arg),
        }
    };
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use num_bigint::BigInt;
    use py27_marshal::bstr::BString;

    use std::sync::{Arc, RwLock};

    type TargetOpcode = pydis::opcode::py27::Standard;

    #[macro_export]
    macro_rules! Long {
        ($value:expr) => {
            py27_marshal::Obj::Long(Arc::new(BigInt::from($value)))
        };
    }

    #[macro_export]
    macro_rules! String {
        ($value:expr) => {
            py27_marshal::Obj::String(Arc::new(bstr::BString::from($value)))
        };
    }

    #[test]
    fn binary_xor() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 0b10101010_11111111;
        let right = 0b01010101_11111111;
        let expected = left ^ right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_XOR),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_lshift() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 0b10101010_11111111;
        let right = 3;
        let expected = left << right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_LSHIFT),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }
    #[test]
    fn binary_rshift() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 0b10101010_11111111;
        let right = 3;
        let expected = left >> right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_RSHIFT),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_modulo() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5;
        let right = 3;
        let expected = left % right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_MODULO),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_divide_longs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5;
        let right = 3;
        let expected = left / right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_DIVIDE),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_floor_divide_longs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5;
        let right = 3;
        let expected = left / right;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_FLOOR_DIVIDE),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_positive_pow_longs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5u32;
        let right = 3;
        let expected = left.pow(right);

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_POWER),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_negative_pow_longs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5u32;
        let right = -3i32;
        let expected = 1.0 / left.pow((-right) as u32) as f64;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_POWER),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Float(f)) => {
                assert_eq!(*f, expected);
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn binary_true_divide_longs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let left = 5;
        let right = 3;
        let expected = left as f64 / right as f64;

        let consts = vec![Long!(left), Long!(right)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_TRUE_DIVIDE),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Float(f)) => {
                assert_eq!(*f, expected);
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn unary_not_long() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let num = 5u32;
        let expected = false;

        let consts = vec![Long!(num)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::UNARY_NOT),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Bool(result)) => {
                assert_eq!(*result, expected);
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn unary_negative_long() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let num = 5u32;
        let expected = -5i32;

        let consts = vec![Long!(num)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::UNARY_NEGATIVE),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert_eq!(stack.len(), 1);

        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.as_ref(), expected.to_bigint().unwrap());
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    #[test]
    fn store_subscr_list() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let key = Long!(0);
        let value = Long!(0x41);

        let _expected_list = vec![0x41];

        let actual_list = Obj::List(Arc::new(RwLock::new(vec![Long!(0)])));
        let consts = vec![actual_list.clone(), key, value];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            // Load value on to stack
            Instr!(TargetOpcode::LOAD_CONST, 2),
            // Load list on to stack
            Instr!(TargetOpcode::LOAD_CONST, 0),
            // Load key on to stack
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::STORE_SUBSCR),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert!(stack.is_empty());

        match &actual_list {
            Obj::List(list_lock) => {
                let list = list_lock.read().unwrap();
                assert_eq!(list.len(), 1);

                assert_eq!(*list[0].clone().extract_long().unwrap(), BigInt::from(0x41));
            }
            other => panic!("unexpected type: {:?}", other.typ()),
        }
    }

    #[test]
    fn store_subscr_dict() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let key = String!("key");
        let value = Long!(0x41);

        let mut expected_hashmap = HashMap::new();
        expected_hashmap.insert(ObjHashable::try_from(&key).unwrap(), value.clone());

        let actual_dict = Obj::Dict(Default::default());
        let consts = vec![actual_dict.clone(), key, value];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            // Load value on to stack
            Instr!(TargetOpcode::LOAD_CONST, 2),
            // Load dict on to stack
            Instr!(TargetOpcode::LOAD_CONST, 0),
            // Load key on to stack
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::STORE_SUBSCR),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        assert!(stack.is_empty());

        match &actual_dict {
            Obj::Dict(dict_lock) => {
                let actual_dict = dict_lock.read().unwrap();
                for (key, expected_value) in &expected_hashmap {
                    let actual_value = actual_dict.get(key);

                    assert!(actual_value.is_some());

                    let actual_value = actual_value.unwrap().clone().extract_long();
                    let expected_value = expected_value.clone().extract_long().unwrap();

                    assert_eq!(expected_value, actual_value.unwrap());
                }
            }
            other => panic!("unexpected type: {:?}", other.typ()),
        }
    }

    #[test]
    fn store_map() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let key = String!("key");
        let value = Long!(0x41);

        let mut expected_hashmap = HashMap::new();
        expected_hashmap.insert(ObjHashable::try_from(&key).unwrap(), value.clone());

        let consts = vec![Obj::Dict(Default::default()), key, value];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            // Load dict on to stack
            Instr!(TargetOpcode::LOAD_CONST, 0),
            // Load value on to stack
            Instr!(TargetOpcode::LOAD_CONST, 2),
            // Load key on to stack
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::STORE_MAP),
        ];

        for instr in &instrs {
            execute_instruction(
                instr,
                Arc::clone(&code),
                &mut stack,
                &mut vars,
                &mut names,
                &mut globals,
                Arc::clone(&names_loaded),
                |_f, _args, _kwargs| {
                    panic!("functions should not be invoked");
                },
                (),
            )
            .expect("unexpected error")
        }

        // The dict should still be on the stack
        assert_eq!(stack.len(), 1, "stack size is not 1");

        match &stack[0].0 {
            Some(Obj::Dict(dict)) => {
                let actual_dict = dict.read().unwrap();
                for (key, expected_value) in &expected_hashmap {
                    let actual_value = actual_dict.get(key);

                    assert!(actual_value.is_some());

                    let actual_value = actual_value.unwrap().clone().extract_long();
                    let expected_value = expected_value.clone().extract_long().unwrap();

                    assert_eq!(expected_value, actual_value.unwrap());
                }
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    pub(crate) fn setup_vm_vars() -> (
        VmStack<()>,
        VmVars<()>,
        VmNames<()>,
        VmNames<()>,
        LoadedNames,
    ) {
        (
            VmStack::new(),
            VmVars::new(),
            VmNames::new(),
            VmNames::new(),
            LoadedNames::default(),
        )
    }

    pub(crate) fn default_code_obj() -> Arc<Code> {
        Arc::new(py27_marshal::Code {
            argcount: 0,
            nlocals: 0,
            stacksize: 0,
            flags: CodeFlags::OPTIMIZED,
            code: Arc::new(vec![]),
            consts: Arc::new(vec![]),
            names: vec![],
            varnames: vec![],
            freevars: vec![],
            cellvars: vec![],
            filename: Arc::new(BString::from("filename")),
            name: Arc::new(BString::from("name")),
            firstlineno: 0,
            lnotab: Arc::new(vec![]),
        })
    }
}
