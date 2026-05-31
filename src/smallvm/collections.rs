use log::warn;
use num_traits::ToPrimitive;
use py27_marshal::*;
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, RwLock};

use super::{InstructionTracker, VmStack, stack_pop};
use crate::error::Error;

/// Executes collection-related instructions: BUILD_LIST, BUILD_TUPLE, BUILD_MAP,
/// BUILD_SET, BUILD_SLICE, BUILD_CLASS, LIST_APPEND, MAP_ADD, STORE_SUBSCR,
/// BINARY_SUBSC, STORE_MAP.
pub(crate) fn execute_collection_op<O, T>(
    instr: &Instruction<O>,
    stack: &mut VmStack<T>,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    T: Clone + Copy + Ord,
{
    match instr.opcode.mnemonic() {
        Mnemonic::STORE_SUBSCR => {
            let (key, key_accessing_instrs) = stack_pop(stack)?;
            let (collection, collection_accessing_instrs) = stack_pop(stack)?;
            let (value, value_accessing_instrs) = stack_pop(stack)?;

            collection_accessing_instrs.extend(&key_accessing_instrs);
            collection_accessing_instrs.extend(&value_accessing_instrs);
            collection_accessing_instrs.push(access_tracking);

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
                            .read()
                            .unwrap()
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
            let (tos, accessing_instrs) = stack_pop(stack)?;
            let (tos1, tos1_accessing_instrs) = stack_pop(stack)?;
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
                        let long_val = long.read().unwrap();
                        if long_val.to_usize().unwrap() >= list.len() {
                            stack.push((None, accessing_instrs));
                        } else {
                            stack.push((
                                Some(list[long_val.to_usize().unwrap()].clone()),
                                accessing_instrs,
                            ));
                        }
                    } else {
                        panic!("TOS must be a long");
                    }
                }
                Some(Obj::Dict(dict_lock)) => {
                    let dict = dict_lock.read().unwrap();
                    if let Some(tos) = tos {
                        let hashable_tos = (&tos).try_into().unwrap();
                        stack.push((dict.get(&hashable_tos).cloned(), accessing_instrs));
                    } else {
                        stack.push((None, accessing_instrs));
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
        Mnemonic::LIST_APPEND => {
            let (tos, tos_modifiers) = stack_pop(stack)?;

            let stack_len = stack.len();
            let (output, output_modifiers) = &mut stack[stack_len - instr.arg.unwrap() as usize];

            output_modifiers.extend(&tos_modifiers);
            output_modifiers.push(access_tracking);

            warn!("LIST_APPEND is implemented poorly");

            if let Some(tos) = tos {
                match output {
                    Some(Obj::String(s)) => {
                        let tos_value = match tos {
                            Obj::Long(l) => l.read().unwrap().to_u8(),
                            other => panic!("did not expect type: {:?}", other.typ()),
                        };
                        s.write().unwrap().push(tos_value.unwrap());
                    }
                    Some(Obj::List(list)) => {
                        list.write().unwrap().push(tos);
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
            } else {
                output_modifiers.push(access_tracking);
            }
        }
        Mnemonic::BUILD_SLICE => {
            warn!("BUILD_SLICE is implemented poorly");
            let slice_accessors = InstructionTracker::new();
            slice_accessors.push(access_tracking);

            for _ in 0..instr.arg.unwrap() {
                stack.pop();
            }

            stack.push((None, slice_accessors));
        }
        Mnemonic::BUILD_SET => {
            let mut set = std::collections::HashSet::new();
            let mut push_none = false;

            let set_accessors = InstructionTracker::new();
            for _i in 0..instr.arg.unwrap() {
                let (tos, tos_modifiers) = stack_pop(stack)?;
                set_accessors.extend(&tos_modifiers);
                if tos.is_none() || push_none {
                    push_none = true;
                    continue;
                }
                tos_modifiers.push(access_tracking);
                set.insert(ObjHashable::try_from(&tos.unwrap()).unwrap());
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
                let (tos, tos_modifiers) = stack_pop(stack)?;
                tuple_accessors.extend(&tos_modifiers);
                if tos.is_none() || push_none {
                    push_none = true;
                    continue;
                }
                tos_modifiers.push(access_tracking);
                tuple.push(tos.unwrap());
            }

            // CPython pops into descending indices, so first popped = last element.
            // We popped into ascending order, so reverse to match CPython.
            tuple.reverse();

            tuple_accessors.push(access_tracking);
            if push_none {
                stack.push((None, tuple_accessors));
            } else {
                stack.push((
                    Some(Obj::Tuple(Arc::new(RwLock::new(tuple)))),
                    tuple_accessors,
                ));
            }
        }
        Mnemonic::MAP_ADD => {
            // CPython: TOP()=key, SECOND()=value, then stack_pointer[-oparg] = dict
            let (key, key_tracking) = stack_pop(stack)?;
            let (value, value_tracking) = stack_pop(stack)?;
            if key.is_none() || value.is_none() {
                return Ok(());
            }
            let stack_len = stack.len();
            let oparg = instr.arg.unwrap() as usize;
            if let Some((dict_entry, dict_tracking)) = stack.get_mut(stack_len - oparg) {
                match dict_entry {
                    Some(Obj::Dict(dict)) => {
                        dict.write()
                            .unwrap()
                            .insert(key.as_ref().unwrap().try_into().unwrap(), value.unwrap());
                        dict_tracking.extend(&key_tracking);
                        dict_tracking.extend(&value_tracking);
                        dict_tracking.push(access_tracking);
                    }
                    Some(_) => {
                        panic!(
                            "Error executing MAP_ADD: target is not a dict -- this indicates a bug somewhere"
                        );
                    }
                    None => {
                        // This scenario is fine
                    }
                }
            } else {
                panic!("no dict for MAP_ADD at stack depth {}?", oparg);
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
        Mnemonic::BUILD_LIST => {
            let mut list = Vec::new();
            let mut push_none = instr.arg.unwrap() == 0;

            let tuple_accessors = InstructionTracker::new();
            for _i in 0..instr.arg.unwrap() {
                let (tos, tos_modifiers) = stack_pop(stack)?;
                tuple_accessors.extend(&tos_modifiers);
                if tos.is_none() {
                    push_none = true;
                    break;
                }
                tos_modifiers.push(access_tracking);
                list.push(tos.unwrap());
            }
            // CPython pops into descending indices — reverse to match.
            list.reverse();
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
            let (_tos, tos_accesses) = stack_pop(stack)?;
            let (_tos1, tos1_accesses) = stack_pop(stack)?;
            let (_tos2, tos2_accesses) = stack_pop(stack)?;
            tos_accesses.extend(&tos1_accesses);
            tos_accesses.extend(&tos2_accesses);
            tos_accesses.push(access_tracking);

            stack.push((None, tos_accesses));
        }
        Mnemonic::UNPACK_SEQUENCE => {
            let (tos, tos_modifiers) = stack_pop(stack)?;
            tos_modifiers.push(access_tracking);

            match tos {
                Some(Obj::Tuple(t)) => {
                    for item in t
                        .read()
                        .unwrap()
                        .iter()
                        .rev()
                        .take(instr.arg.unwrap() as usize)
                    {
                        stack.push((Some(item.clone()), tos_modifiers.deep_clone()));
                    }
                }
                Some(Obj::List(l)) => {
                    let list = l.read().unwrap();
                    for item in list.iter().rev().take(instr.arg.unwrap() as usize) {
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
        Mnemonic::STORE_MAP => {
            let (key, key_accesses) = stack_pop(stack)?;
            let (value, value_accesses) = stack_pop(stack)?;
            let (dict, dict_accesses) = stack_pop(stack)?;

            let new_accesses = dict_accesses;
            new_accesses.extend(&value_accesses);
            new_accesses.extend(&key_accesses);
            new_accesses.push(access_tracking);

            if dict.is_none() || key.is_none() || value.is_none() {
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
        other => unreachable!("not a collection op: {:?}", other),
    }

    Ok(())
}
