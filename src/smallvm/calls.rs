use py27_marshal::ObjHashable;
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::convert::TryFrom;

use super::{InstructionTracker, VmStack, VmVar, stack_pop};
use crate::error::Error;

/// Executes function/closure-related instructions: MAKE_FUNCTION, MAKE_CLOSURE,
/// CALL_FUNCTION, CALL_FUNCTION_VAR, CALL_FUNCTION_KW, CALL_FUNCTION_VAR_KW.
pub(crate) fn execute_call_op<O, F, T>(
    instr: &Instruction<O>,
    stack: &mut VmStack<T>,
    function_callback: &mut F,
    access_tracking: T,
) -> Result<(), Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
    F: FnMut(VmVar, Vec<VmVar>, std::collections::HashMap<Option<ObjHashable>, VmVar>) -> VmVar,
    T: Clone + Copy,
{
    match instr.opcode.mnemonic() {
        Mnemonic::MAKE_FUNCTION => {
            let (_tos, tos_modifiers) = stack_pop(stack)?;
            let tos_modifiers = tos_modifiers.deep_clone();
            tos_modifiers.push(access_tracking);

            for _ in 0..instr.arg.unwrap() {
                // default args
                stack.pop();
            }

            stack.push((None, tos_modifiers));
        }
        Mnemonic::MAKE_CLOSURE => {
            let (_code_obj, obj_modifying_instrs) = stack_pop(stack)?;
            let (_free_vars, free_var_instrs) = stack_pop(stack)?;

            obj_modifying_instrs.push(access_tracking);

            for _ in 0..instr.arg.unwrap() {
                let (_obj, instrs) = stack_pop(stack)?;
                obj_modifying_instrs.extend(&instrs);
            }
            obj_modifying_instrs.extend(&free_var_instrs);

            stack.push((None, obj_modifying_instrs));
        }
        Mnemonic::CALL_FUNCTION
        | Mnemonic::CALL_FUNCTION_VAR
        | Mnemonic::CALL_FUNCTION_KW
        | Mnemonic::CALL_FUNCTION_VAR_KW => {
            let mnemonic = instr.opcode.mnemonic();
            let has_var = matches!(
                mnemonic,
                Mnemonic::CALL_FUNCTION_VAR | Mnemonic::CALL_FUNCTION_VAR_KW
            );
            let has_kw = matches!(
                mnemonic,
                Mnemonic::CALL_FUNCTION_KW | Mnemonic::CALL_FUNCTION_VAR_KW
            );

            // Pop extra *args and/or **kwargs in the correct order:
            // VAR_KW: **kwargs on top, then *args
            // KW: **kwargs on top
            // VAR: *args on top
            let accessed_instrs = if has_kw && has_var {
                // CALL_FUNCTION_VAR_KW
                let (_additional_kw_args, arg_accesses) = stack_pop(stack)?;
                let instrs = arg_accesses.deep_clone();
                let (_additional_positional_args, arg_accesses) = stack_pop(stack)?;
                instrs.extend(&arg_accesses);
                instrs
            } else if has_kw {
                // CALL_FUNCTION_KW
                let (_additional_kw_args, arg_accesses) = stack_pop(stack)?;
                arg_accesses.deep_clone()
            } else if has_var {
                // CALL_FUNCTION_VAR
                let (_additional_positional_args, arg_accesses) = stack_pop(stack)?;
                arg_accesses.deep_clone()
            } else {
                // CALL_FUNCTION
                InstructionTracker::new()
            };

            let kwarg_count = (instr.arg.unwrap() >> 8) & 0xFF;
            let mut kwargs = std::collections::HashMap::with_capacity(kwarg_count as usize);
            for _ in 0..kwarg_count {
                let (value, value_accesses) = stack_pop(stack)?;
                accessed_instrs.extend(&value_accesses);

                let (key, key_accesses) = stack_pop(stack)?;
                accessed_instrs.extend(&key_accesses);
                let key = key.map(|key| ObjHashable::try_from(&key).unwrap());
                kwargs.insert(key, value);
            }

            let positional_args_count = instr.arg.unwrap() & 0xFF;
            let mut args = Vec::with_capacity(positional_args_count as usize);
            for _ in 0..positional_args_count {
                let (arg, arg_accesses) = stack_pop(stack)?;
                accessed_instrs.extend(&arg_accesses);
                args.push(arg);
            }
            // Popping gives args in reverse order; reverse to match CPython's forward order
            args.reverse();

            let function = stack_pop(stack)?;
            let result = function_callback(function.0, args, kwargs);

            accessed_instrs.push(access_tracking);

            stack.push((result, accessed_instrs));
        }
        other => unreachable!("not a call op: {:?}", other),
    }

    Ok(())
}
