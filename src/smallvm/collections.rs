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
                    // The index may be unknown, a non-integer (e.g. a slice), or
                    // negative/out-of-range (to_usize yields None). In any of
                    // those cases we cannot statically resolve the element, so
                    // push an unknown value rather than panic.
                    let index = tos.as_ref().and_then(|t| match t {
                        Obj::Long(long) => long.read().unwrap().to_usize(),
                        _ => None,
                    });
                    match index {
                        Some(idx) if idx < list.len() => {
                            stack.push((Some(list[idx].clone()), accessing_instrs));
                        }
                        _ => stack.push((None, accessing_instrs)),
                    }
                }
                Some(Obj::Dict(dict_lock)) => {
                    let dict = dict_lock.read().unwrap();
                    // An unknown or non-hashable key cannot index the dict.
                    match tos.as_ref().and_then(|t| ObjHashable::try_from(t).ok()) {
                        Some(hashable_tos) => {
                            stack.push((dict.get(&hashable_tos).cloned(), accessing_instrs));
                        }
                        None => stack.push((None, accessing_instrs)),
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
                // Skip an unhashable element rather than panic.
                if let Ok(hashable) = ObjHashable::try_from(&tos.unwrap()) {
                    set.insert(hashable);
                }
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
                        // Skip an unhashable key rather than panic.
                        if let Some(hashable_key) =
                            key.as_ref().and_then(|k| ObjHashable::try_from(k).ok())
                        {
                            dict.write().unwrap().insert(hashable_key, value.unwrap());
                        }
                        dict_tracking.extend(&key_tracking);
                        dict_tracking.extend(&value_tracking);
                        dict_tracking.push(access_tracking);
                    }
                    // Target is an unknown/unmodeled value: skip the add.
                    Some(_) => {}
                    None => {
                        // This scenario is fine
                    }
                }
            }
            // If there is no stack entry at that depth there is nothing to add
            // to; skip rather than panic.
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
                Some(_other) => {
                    // Unknown or unsupported sequence shape: push the right
                    // number of unknown elements rather than panic.
                    for _i in 0..instr.arg.unwrap() {
                        stack.push((None, tos_modifiers.deep_clone()));
                    }
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

            let Ok(dict_lock) = dict.unwrap().extract_dict() else {
                // The map slot is not a dict we can model; yield unknown.
                stack.push((None, new_accesses));
                return Ok(());
            };
            match key.as_ref().and_then(|k| ObjHashable::try_from(k).ok()) {
                Some(hashable_key) => {
                    dict_lock.write().unwrap().insert(hashable_key, value.unwrap());
                }
                // Unhashable key: leave the dict unchanged rather than panic.
                None => {}
            }
            stack.push((Some(Obj::Dict(dict_lock)), new_accesses));
        }
        other => unreachable!("not a collection op: {:?}", other),
    }

    Ok(())
}
