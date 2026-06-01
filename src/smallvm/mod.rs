mod arithmetic;
mod calls;
mod collections;
mod compare;

use log::{debug, trace, warn};
use num_bigint::ToBigInt;
use py27_marshal::bstr::BString;
use py27_marshal::*;
use pydis::opcode::py27::{self, Mnemonic};
use pydis::prelude::*;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Cursor;
use std::sync::{Arc, Mutex, RwLock};

/// Helper to pop from the VM stack, returning a StackUnderflow error if empty.
pub(crate) fn stack_pop<O, T>(
    stack: &mut VmStack<T>,
) -> Result<VmVarWithTracking<T>, crate::error::Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
{
    stack
        .pop()
        .ok_or_else(|| crate::error::ExecutionError::StackUnderflow.into())
}

/// Helper to peek at the top of the VM stack, returning a StackUnderflow error if empty.
pub(crate) fn stack_last<O, T>(
    stack: &mut VmStack<T>,
) -> Result<&VmVarWithTracking<T>, crate::error::Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
{
    stack
        .last()
        .ok_or_else(|| crate::error::ExecutionError::StackUnderflow.into())
}

/// Helper to peek at the top of the VM stack mutably, returning a StackUnderflow error if empty.
pub(crate) fn stack_last_mut<O, T>(
    stack: &mut VmStack<T>,
) -> Result<&mut VmVarWithTracking<T>, crate::error::Error<O>>
where
    O: Opcode<Mnemonic = py27::Mnemonic>,
{
    stack
        .last_mut()
        .ok_or_else(|| crate::error::ExecutionError::StackUnderflow.into())
}

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

/// Cloning a tracker copies its tracked set so each value owns its own provenance.
/// An earlier design shared the `Vec` by `Arc` so a push to one value was seen by
/// every value cloned from it; that pollutes a value's producer set with the
/// instructions of unrelated values (a load of a var leaking into every other use
/// of that var, a sibling fork's instructions leaking back into this path). Precise
/// per-value provenance is what lets `remove_const_conditions` delete a folded
/// predicate's operand closure -- cross-block included -- without touching live code.
/// Combining values (binary ops, `extend`) unions the operand sets explicitly.
impl<T> Clone for InstructionTracker<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        self.deep_clone()
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
}

impl<T> InstructionTracker<T>
where
    T: Clone + Ord,
{
    /// Extends the state of this instruction tracker by copying all items from `other`'s
    /// tracked state into this.
    ///
    /// Obfuscated control flow merges the same producer instructions over and
    /// over, so this set is almost entirely duplicates and can balloon to many
    /// gigabytes. Collapsing duplicates is semantically a no-op for removal --
    /// deleting an instruction twice is the same as deleting it once -- so we
    /// dedup whenever the set grows past a high-water mark, keeping memory
    /// bounded by the number of *distinct* instructions instead of the number
    /// of merges.
    pub fn extend(&self, other: &InstructionTracker<T>) {
        const DEDUP_HIGH_WATER: usize = 1 << 16;
        // Extending a tracker with itself would lock the same (non-reentrant)
        // mutex twice and deadlock. It is also a no-op: appending a set's own
        // entries adds nothing the dedup would not remove. Shared trackers
        // (cloned Arc) make this reachable, so guard against it explicitly.
        if Arc::ptr_eq(&self.0, &other.0) {
            return;
        }
        let mut data = self.0.lock().unwrap();
        data.extend_from_slice(other.0.lock().unwrap().as_slice());
        if data.len() > DEDUP_HIGH_WATER {
            data.sort_unstable();
            data.dedup();
        }
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
/// State threaded through the small VM as it interprets a code object: the
/// operand stack, locals, names, globals, the set of loaded names, and the
/// caller's access-tracking token. Bundling it lets callers run an instruction
/// with [`VmFrame::execute`] instead of nine positional arguments.
pub struct VmFrame<'a, T> {
    pub code: Arc<Code>,
    pub stack: &'a mut VmStack<T>,
    pub vars: &'a mut VmVars<T>,
    pub names: &'a mut VmNames<T>,
    pub globals: &'a mut VmNames<T>,
    pub names_loaded: LoadedNames,
    pub access_tracking: T,
}

impl<T: Clone + Copy + Ord> VmFrame<'_, T> {
    /// Interprets one instruction against this frame. `function_callback` resolves
    /// the result of a `CALL_FUNCTION` the VM cannot evaluate on its own.
    pub fn execute<O, F>(
        &mut self,
        instr: &Instruction<O>,
        function_callback: F,
    ) -> Result<(), Error<O>>
    where
        O: Opcode<Mnemonic = py27::Mnemonic>,
        F: FnMut(VmVar, Vec<VmVar>, std::collections::HashMap<Option<ObjHashable>, VmVar>) -> VmVar,
    {
        execute_instruction(
            instr,
            Arc::clone(&self.code),
            self.stack,
            self.vars,
            self.names,
            self.globals,
            Arc::clone(&self.names_loaded),
            function_callback,
            self.access_tracking,
        )
    }
}

pub(crate) fn execute_instruction<O: Opcode<Mnemonic = py27::Mnemonic>, F, T>(
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
    T: Clone + Copy + Ord,
{
    use arithmetic::BinaryOp;

    match instr.opcode.mnemonic() {
        // === Stack manipulation ===
        Mnemonic::ROT_TWO => {
            let (tos, tos_accesses) = stack_pop(stack)?;
            let (tos1, tos1_accesses) = stack_pop(stack)?;
            tos_accesses.push(access_tracking);
            tos1_accesses.push(access_tracking);

            stack.push((tos, tos_accesses));
            stack.push((tos1, tos1_accesses));
        }
        Mnemonic::ROT_THREE => {
            // CPython: SET_TOP(SECOND), SET_SECOND(THIRD), SET_THIRD(TOP)
            // Before: [..., C, B, A] (A=TOP, B=SECOND, C=THIRD)
            // After:  [..., A, C, B] (B=TOP, C=SECOND, A=THIRD)
            let (tos, tos_accesses) = stack_pop(stack)?;
            let (tos1, tos1_accesses) = stack_pop(stack)?;
            let (tos2, tos2_accesses) = stack_pop(stack)?;
            tos_accesses.push(access_tracking);
            tos1_accesses.push(access_tracking);
            tos2_accesses.push(access_tracking);

            stack.push((tos, tos_accesses)); // old TOP -> THIRD
            stack.push((tos2, tos2_accesses)); // old THIRD -> SECOND
            stack.push((tos1, tos1_accesses)); // old SECOND -> TOP
        }
        Mnemonic::DUP_TOP => {
            let (var, accesses) = stack_last(stack)?;
            accesses.push(access_tracking);
            let new_var = (var.clone(), accesses.deep_clone());
            stack.push(new_var);
        }
        Mnemonic::DUP_TOPX => {
            let count = instr.arg.unwrap() as usize;
            if count != 2 && count != 3 {
                panic!("DUP_TOPX should only be called with count == 2 or 3")
            }

            let mut new_items = vec![];
            for i in (0..count).rev() {
                let (var, accesses) = &stack[(stack.len() - 1) - i];
                accesses.push(access_tracking);
                let new_var = (var.clone(), accesses.deep_clone());
                new_items.push(new_var);
            }

            stack.append(&mut new_items);
        }
        Mnemonic::POP_TOP => {
            let (_tos, tos_modifiers) = stack_pop(stack)?;
            tos_modifiers.push(access_tracking);
        }
        Mnemonic::GET_ITER => {
            let (_tos, tos_modifiers) = stack_pop(stack)?;
            tos_modifiers.push(access_tracking);
            stack.push((None, tos_modifiers));
        }

        // === Comparison ===
        Mnemonic::COMPARE_OP => {
            return compare::execute_compare_op(instr, stack, access_tracking);
        }

        // === Binary arithmetic ===
        Mnemonic::INPLACE_ADD | Mnemonic::BINARY_ADD => {
            return arithmetic::apply_binary_op(BinaryOp::Add, instr, stack, access_tracking);
        }
        Mnemonic::INPLACE_SUBTRACT | Mnemonic::BINARY_SUBTRACT => {
            return arithmetic::apply_binary_op(BinaryOp::Subtract, instr, stack, access_tracking);
        }
        Mnemonic::INPLACE_MULTIPLY | Mnemonic::BINARY_MULTIPLY => {
            return arithmetic::apply_binary_op(BinaryOp::Multiply, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_DIVIDE | Mnemonic::INPLACE_DIVIDE => {
            return arithmetic::apply_binary_op(BinaryOp::Divide, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_FLOOR_DIVIDE | Mnemonic::INPLACE_FLOOR_DIVIDE => {
            return arithmetic::apply_binary_op(
                BinaryOp::FloorDivide,
                instr,
                stack,
                access_tracking,
            );
        }
        Mnemonic::BINARY_TRUE_DIVIDE | Mnemonic::INPLACE_TRUE_DIVIDE => {
            return arithmetic::apply_binary_op(
                BinaryOp::TrueDivide,
                instr,
                stack,
                access_tracking,
            );
        }
        Mnemonic::BINARY_POWER | Mnemonic::INPLACE_POWER => {
            return arithmetic::apply_binary_op(BinaryOp::Power, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_MODULO | Mnemonic::INPLACE_MODULO => {
            return arithmetic::apply_binary_op(BinaryOp::Modulo, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_XOR | Mnemonic::INPLACE_XOR => {
            return arithmetic::apply_binary_op(BinaryOp::Xor, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_AND | Mnemonic::INPLACE_AND => {
            return arithmetic::apply_binary_op(BinaryOp::And, instr, stack, access_tracking);
        }
        Mnemonic::BINARY_OR | Mnemonic::INPLACE_OR => {
            return arithmetic::apply_binary_op(BinaryOp::Or, instr, stack, access_tracking);
        }

        // === Shifts ===
        Mnemonic::BINARY_LSHIFT
        | Mnemonic::BINARY_RSHIFT
        | Mnemonic::INPLACE_LSHIFT
        | Mnemonic::INPLACE_RSHIFT => {
            return arithmetic::execute_shift(instr, stack, access_tracking);
        }

        // === Unary operations ===
        Mnemonic::UNARY_NOT => {
            return arithmetic::apply_unary_op(arithmetic::UnaryOp::Not, stack, access_tracking);
        }
        Mnemonic::UNARY_NEGATIVE => {
            return arithmetic::apply_unary_op(
                arithmetic::UnaryOp::Negative,
                stack,
                access_tracking,
            );
        }

        // === Collections ===
        Mnemonic::STORE_SUBSCR
        | Mnemonic::BINARY_SUBSC
        | Mnemonic::LIST_APPEND
        | Mnemonic::BUILD_SLICE
        | Mnemonic::BUILD_SET
        | Mnemonic::BUILD_TUPLE
        | Mnemonic::MAP_ADD
        | Mnemonic::BUILD_MAP
        | Mnemonic::BUILD_LIST
        | Mnemonic::BUILD_CLASS
        | Mnemonic::UNPACK_SEQUENCE
        | Mnemonic::STORE_MAP => {
            return collections::execute_collection_op(instr, stack, access_tracking);
        }

        // === Function calls ===
        Mnemonic::MAKE_FUNCTION
        | Mnemonic::MAKE_CLOSURE
        | Mnemonic::CALL_FUNCTION
        | Mnemonic::CALL_FUNCTION_VAR
        | Mnemonic::CALL_FUNCTION_KW
        | Mnemonic::CALL_FUNCTION_VAR_KW => {
            return calls::execute_call_op(instr, stack, &mut function_callback, access_tracking);
        }

        // === Imports ===
        Mnemonic::IMPORT_NAME => {
            let (_fromlist, fromlist_modifying_instrs) = stack_pop(stack)?;
            let (_level, level_modifying_instrs) = stack_pop(stack)?;

            level_modifying_instrs.extend(&fromlist_modifying_instrs);
            level_modifying_instrs.push(access_tracking);

            let _name = &code.names[instr.arg.unwrap() as usize];
            stack.push((None, level_modifying_instrs));
        }
        Mnemonic::IMPORT_FROM => {
            let (_module, accessing_instrs) = stack_last(stack)?;
            accessing_instrs.push(access_tracking);
            let accessing_instrs = accessing_instrs.clone();
            stack.push((None, accessing_instrs));
        }
        Mnemonic::IMPORT_STAR => {
            let (_tos, _accesses) = stack_pop(stack)?;
        }

        // === Load/Store ===
        Mnemonic::LOAD_CLOSURE => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);
            stack.push((None, tracking));
        }
        Mnemonic::LOAD_ATTR => {
            let (_obj, obj_modifying_instrs) = stack_pop(stack)?;
            let _name = &code.names[instr.arg.unwrap() as usize];
            obj_modifying_instrs.push(access_tracking);
            stack.push((None, obj_modifying_instrs));
        }
        Mnemonic::STORE_ATTR => {
            let (_obj, _obj_modifying_instrs) = stack_pop(stack)?;
            let (_obj, _obj_modifying_instrs) = stack_pop(stack)?;
        }
        Mnemonic::FOR_ITER => {
            let top_of_stack_index = stack.len() - 1;
            let (tos, _modifying_instrs) = &mut stack[top_of_stack_index];
            let new_tos = match tos {
                Some(Obj::String(s)) => {
                    let mut s_guard = s.write().unwrap();
                    if s_guard.is_empty() {
                        return Ok(());
                    }
                    // Iterate front-to-back: remove the first byte
                    let byte = s_guard.remove(0);
                    Some(Obj::Long(Arc::new(RwLock::new(byte.to_bigint().unwrap()))))
                }
                Some(other) => panic!("stack object `{:?}` is not iterable", other),
                None => None,
            };
            stack.push((new_tos, InstructionTracker::new()))
        }
        Mnemonic::DELETE_FAST => {
            vars.remove(&instr.arg.unwrap());
        }
        Mnemonic::STORE_FAST => {
            let (tos, accessing_instrs) = stack_pop(stack)?;
            accessing_instrs.push(access_tracking);
            vars.insert(instr.arg.unwrap(), (tos, accessing_instrs));
        }
        Mnemonic::STORE_NAME => {
            let (tos, accessing_instrs) = stack_pop(stack)?;
            let name = &code.names[instr.arg.unwrap() as usize];
            accessing_instrs.push(access_tracking);
            names.insert(Arc::clone(name), (tos, accessing_instrs));
        }
        Mnemonic::LOAD_NAME => {
            let name = &code.names[instr.arg.unwrap() as usize];
            names_loaded.lock().unwrap().push(Arc::clone(name));
            if let Some((val, accesses)) = names.get(name) {
                // The loaded value's provenance is the stored value's producers plus
                // this load. Copy rather than mutate the table entry: the load is a
                // consumer, not a producer of the stored binding, so recording it on
                // the table entry would leak this use into every later load of the name.
                let loaded = accesses.deep_clone();
                loaded.push(access_tracking);
                stack.push((val.clone(), loaded));
            } else {
                let tracking = InstructionTracker::new();
                tracking.push(access_tracking);
                stack.push((None, tracking));
            }
        }
        Mnemonic::LOAD_FAST => {
            if let Some((var, accesses)) = vars.get(&instr.arg.unwrap()) {
                // Copy the stored value's producers and add this load; do not mutate
                // the table entry (see LOAD_NAME). Keeping the load off the stored
                // var's set is what makes a later folded predicate's operand closure
                // exact instead of accumulating every prior load of the same var.
                let loaded = accesses.deep_clone();
                loaded.push(access_tracking);
                stack.push((var.clone(), loaded));
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
        Mnemonic::LOAD_GLOBAL => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);
            let name = &code.names[instr.arg.unwrap() as usize];
            names_loaded.lock().unwrap().push(Arc::clone(name));
            stack.push((None, tracking));
        }
        Mnemonic::STORE_GLOBAL => {
            let (tos, accessing_instrs) = stack_pop(stack)?;
            let name = &code.names[instr.arg.unwrap() as usize];
            accessing_instrs.push(access_tracking);
            globals.insert(Arc::clone(name), (tos, accessing_instrs));
        }
        Mnemonic::LOAD_DEREF => {
            let tracking = InstructionTracker::new();
            tracking.push(access_tracking);
            stack.push((None, tracking));
        }
        Mnemonic::DELETE_NAME => {
            let name = &code.names[instr.arg.unwrap() as usize];
            names.remove(name);
        }

        // === Control flow / misc ===
        Mnemonic::POP_BLOCK
        | Mnemonic::JUMP_ABSOLUTE
        | Mnemonic::BREAK_LOOP
        | Mnemonic::CONTINUE_LOOP
        | Mnemonic::END_FINALLY => {
            // nops -- these opcodes affect control flow or the block stack,
            // neither of which the partial executor tracks
        }
        Mnemonic::EXEC_STMT => {
            stack.pop();
            stack.pop();
            stack.pop();
        }
        Mnemonic::LOAD_LOCALS => {
            warn!("LOAD_LOCALS is implemented poorly");
            stack.push((None, InstructionTracker::new()));
        }
        Mnemonic::YIELD_VALUE => {
            let (_tos, _accesses) = stack_pop(stack)?;
        }

        // === Print ===
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
    GoodDoNotRemove(Arc<Instruction<O>>),
    Bad,
}

impl<O: Opcode<Mnemonic = py27::Mnemonic>> ParsedInstr<O> {
    #[track_caller]
    pub fn unwrap(&self) -> Arc<Instruction<O>> {
        match self {
            ParsedInstr::Good(ins) | ParsedInstr::GoodDoNotRemove(ins) => Arc::clone(ins),
            ParsedInstr::Bad => {
                panic!("unwrap called on bad instruction")
            }
        }
    }

    /// Returns the decoded instruction, or `None` if this slot holds a
    /// bad/undecodable instruction. Use at sites that must tolerate undecodable
    /// bytecode (offset fixups, branch updates) rather than panic on it.
    pub fn get(&self) -> Option<Arc<Instruction<O>>> {
        match self {
            ParsedInstr::Good(ins) | ParsedInstr::GoodDoNotRemove(ins) => Some(Arc::clone(ins)),
            ParsedInstr::Bad => None,
        }
    }

    /// Returns a mutable reference to the inner Arc, panicking if Bad.
    #[track_caller]
    pub fn unwrap_mut(&mut self) -> &mut Arc<Instruction<O>> {
        match self {
            ParsedInstr::Good(ins) | ParsedInstr::GoodDoNotRemove(ins) => ins,
            ParsedInstr::Bad => {
                panic!("unwrap_mut called on bad instruction")
            }
        }
    }

    /// Returns a boolean indicating if this instruction is a "good"/valid instruction
    pub fn is_good(&self) -> bool {
        match self {
            ParsedInstr::Good(_) | ParsedInstr::GoodDoNotRemove(_) => true,
            ParsedInstr::Bad => false,
        }
    }
}

/// Walks the bytecode in a manner that only follows what "looks like" valid
/// codepaths. This will only decode instructions that are either proven statically
/// to be taken (with `JUMP_ABSOLUTE`, `JUMP_IF_TRUE` with a const value that evaluates
/// to true, etc.)
pub fn const_jmp_instruction_walker<F, O: Opcode<Mnemonic = py27::Mnemonic> + PartialEq>(
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

    macro_rules! add_instruction {
        ($offset:expr, $instr:expr) => {
            instruction_sequence.push($instr.clone());
            let removed_instr = analyzed_instructions.insert($offset, $instr);
            if let Some(ParsedInstr::Good(removed_instr)) = removed_instr {
                if let ParsedInstr::GoodDoNotRemove(new_instr) = $instr {
                    if removed_instr != new_instr {
                        assert!(false, "instruction was replaced: {:?}", removed_instr);
                    }
                }
            }
        };
    }

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
    }

    if debug {
        trace!("{:#?}", consts);
    }

    while let Some(offset) = instruction_queue.pop_front() {
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
                warn!(
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
                add_instruction!(offset, ParsedInstr::Bad);

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
        add_instruction!(offset, ParsedInstr::Good(Arc::clone(&instr)));

        if instr.opcode.is_jump()
            && matches!(
                instr.opcode.mnemonic(),
                Mnemonic::JUMP_ABSOLUTE | Mnemonic::JUMP_FORWARD | Mnemonic::CONTINUE_LOOP
            )
        {
            // We've reached an unconditional jump. We need to decode the target
            let target = if instr.opcode.is_relative_jump() {
                next_instr_offset + instr.arg.unwrap() as u64
            } else {
                instr.arg.unwrap() as u64
            };

            if target as usize >= bytecode.len() {
                // This is a bad instruction
                add_instruction!(offset, ParsedInstr::Bad);
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

    // For each sequential instruction we should see if there's a gap. If so,
    // we should check the instruction coming after the one at the lower offset
    // to see if it's a JUMP_FORWARD.

    let mut jump_forward_instrs = HashMap::new();
    for (offset, instr) in &analyzed_instructions {
        if !instr.is_good() {
            continue;
        }

        let mut next_instr_offset = offset + u64::try_from(instr.unwrap().len()).unwrap();
        if usize::try_from(next_instr_offset).unwrap() >= bytecode.len()
            || analyzed_instructions.contains_key(&next_instr_offset)
        {
            continue;
        }

        // The next instruction was not parsed. We should fetch it and see if
        // we care
        rdr.set_position(next_instr_offset);

        while let Ok(next_instr) = decode_py27::<O, _>(&mut rdr) {
            let offset = next_instr_offset;
            next_instr_offset += next_instr.len() as u64;

            if next_instr.opcode.is_jump() {
                match next_instr.opcode.mnemonic() {
                    // Mnemonic::JUMP_ABSOLUTE => {
                    //     let jump_offset = next_instr.arg.unwrap() as u64;
                    //     if !analyzed_instructions.contains_key(&jump_offset) {
                    //         break;
                    //     }
                    // }
                    Mnemonic::JUMP_FORWARD => {
                        let jump_offset = next_instr.arg.unwrap() as u64 + offset;
                        if !analyzed_instructions.contains_key(&jump_offset) {
                            break;
                        }
                    }
                    _ => {
                        break;
                    }
                }
                let next_instr = Arc::new(next_instr);
                jump_forward_instrs.insert(offset, ParsedInstr::GoodDoNotRemove(next_instr));
            } else {
                break;
            }
        }
    }

    analyzed_instructions.extend(jump_forward_instrs.drain());

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
    use num_traits::ToPrimitive;
    use py27_marshal::bstr::BString;

    use std::sync::{Arc, RwLock};

    type TargetOpcode = pydis::opcode::py27::Standard;

    #[macro_export]
    macro_rules! Long {
        ($value:expr) => {
            py27_marshal::Obj::Long(Arc::new(RwLock::new(BigInt::from($value))))
        };
    }

    #[macro_export]
    macro_rules! String {
        ($value:expr) => {
            py27_marshal::Obj::String(Arc::new(RwLock::new(bstr::BString::from($value))))
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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
                assert_eq!(*l.lock().unwrap(), expected.to_bigint().unwrap());
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

                assert_eq!(
                    *list[0].clone().extract_long().unwrap().lock().unwrap(),
                    BigInt::from(0x41)
                );
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

                    assert_eq!(
                        *expected_value.lock().unwrap(),
                        *actual_value.unwrap().lock().unwrap()
                    );
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

                    assert_eq!(
                        *expected_value.lock().unwrap(),
                        *actual_value.unwrap().lock().unwrap()
                    );
                }
            }
            Some(other) => panic!("unexpected type: {:?}", other.typ()),
            _ => panic!("unexpected None value for TOS"),
        }
    }

    /// Helper to execute a sequence of instructions on a fresh VM.
    fn run_instrs(
        code: &mut Arc<Code>,
        instrs: &[Instruction<TargetOpcode>],
        stack: &mut VmStack<()>,
        vars: &mut VmVars<()>,
        names: &mut VmNames<()>,
        globals: &mut VmNames<()>,
        names_loaded: &LoadedNames,
    ) {
        run_instrs_with_callback(
            code,
            instrs,
            stack,
            vars,
            names,
            globals,
            names_loaded,
            |_f, _args, _kwargs| {
                panic!("functions should not be invoked");
            },
        );
    }

    /// Helper to execute instructions with a custom function callback.
    fn run_instrs_with_callback<F>(
        code: &mut Arc<Code>,
        instrs: &[Instruction<TargetOpcode>],
        stack: &mut VmStack<()>,
        vars: &mut VmVars<()>,
        names: &mut VmNames<()>,
        globals: &mut VmNames<()>,
        names_loaded: &LoadedNames,
        mut function_callback: F,
    ) where
        F: FnMut(VmVar, Vec<VmVar>, std::collections::HashMap<Option<ObjHashable>, VmVar>) -> VmVar,
    {
        for instr in instrs {
            execute_instruction(
                instr,
                Arc::clone(code),
                stack,
                vars,
                names,
                globals,
                Arc::clone(names_loaded),
                &mut function_callback,
                (),
            )
            .expect("unexpected error");
        }
    }

    // =========================================================================
    // ROT_TWO: should swap TOS and TOS1
    // =========================================================================
    #[test]
    fn rot_two_swaps() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(10), Long!(20)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0), // push 10
            Instr!(TargetOpcode::LOAD_CONST, 1), // push 20 (TOS)
            Instr!(TargetOpcode::ROT_TWO),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 2);
        // After ROT_TWO: TOS should be 10 (was TOS1), TOS1 should be 20 (was TOS)
        match (&stack[0].0, &stack[1].0) {
            (Some(Obj::Long(bottom)), Some(Obj::Long(top))) => {
                assert_eq!(
                    *bottom.lock().unwrap(),
                    BigInt::from(20),
                    "TOS1 (bottom) should be old TOS (20)"
                );
                assert_eq!(
                    *top.lock().unwrap(),
                    BigInt::from(10),
                    "TOS (top) should be old TOS1 (10)"
                );
            }
            _ => panic!("unexpected stack contents"),
        }
    }

    // =========================================================================
    // ROT_THREE: CPython rotates so old SECOND becomes TOP, old THIRD becomes
    // SECOND, old TOP becomes THIRD
    // =========================================================================
    #[test]
    fn rot_three_rotates() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(10), Long!(20), Long!(30)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0), // push 10 (THIRD)
            Instr!(TargetOpcode::LOAD_CONST, 1), // push 20 (SECOND)
            Instr!(TargetOpcode::LOAD_CONST, 2), // push 30 (TOP)
            Instr!(TargetOpcode::ROT_THREE),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 3);
        // CPython: SET_TOP(SECOND=20), SET_SECOND(THIRD=10), SET_THIRD(TOP=30)
        // Result: [30, 10, 20] (20=TOP)
        let vals: Vec<i64> = stack
            .iter()
            .map(|(obj, _)| match obj.as_ref().unwrap() {
                Obj::Long(l) => l.lock().unwrap().to_i64().unwrap(),
                _ => panic!("expected Long"),
            })
            .collect();
        assert_eq!(
            vals,
            vec![30, 10, 20],
            "stack should be [30(THIRD), 10(SECOND), 20(TOP)]"
        );
    }

    // =========================================================================
    // Floor division for negative numbers: Python 2.7 floors toward -inf
    // =========================================================================
    #[test]
    fn binary_divide_negative_floors() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        // Python 2.7: -7 / 2 == -4 (floor), not -3 (truncate)
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(-7), Long!(2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_DIVIDE),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(
                    *l.lock().unwrap(),
                    BigInt::from(-4),
                    "-7 / 2 should be -4 (floor)"
                )
            }
            _ => panic!("expected Long"),
        }
    }

    #[test]
    fn binary_floor_divide_negative_floors() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(-7), Long!(2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_FLOOR_DIVIDE),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.lock().unwrap(), BigInt::from(-4), "-7 // 2 should be -4")
            }
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // Modulo for negative numbers: Python 2.7 result has sign of divisor
    // =========================================================================
    #[test]
    fn binary_modulo_negative_dividend() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        // Python 2.7: -7 % 2 == 1 (sign of divisor), not -1 (C remainder)
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(-7), Long!(2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_MODULO),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.lock().unwrap(), BigInt::from(1), "-7 % 2 should be 1")
            }
            _ => panic!("expected Long"),
        }
    }

    #[test]
    fn binary_modulo_negative_divisor() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        // Python 2.7: 7 % -2 == -1 (sign of divisor)
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(7), Long!(-2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::BINARY_MODULO),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => {
                assert_eq!(*l.lock().unwrap(), BigInt::from(-1), "7 % -2 should be -1")
            }
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // BUILD_TUPLE: elements should be in correct order
    // =========================================================================
    #[test]
    fn build_tuple_order() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(1), Long!(2), Long!(3)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0), // push 1
            Instr!(TargetOpcode::LOAD_CONST, 1), // push 2
            Instr!(TargetOpcode::LOAD_CONST, 2), // push 3
            Instr!(TargetOpcode::BUILD_TUPLE, 3),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Tuple(t)) => {
                let t_guard = t.lock().unwrap();
                let vals: Vec<i64> = t_guard
                    .iter()
                    .map(|obj| match obj {
                        Obj::Long(l) => l.lock().unwrap().to_i64().unwrap(),
                        _ => panic!("expected Long"),
                    })
                    .collect();
                assert_eq!(vals, vec![1, 2, 3], "tuple should be (1, 2, 3)");
            }
            _ => panic!("expected Tuple"),
        }
    }

    // =========================================================================
    // BUILD_LIST: elements should be in correct order (for non-empty lists)
    // =========================================================================
    #[test]
    fn build_list_order() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(10), Long!(20), Long!(30)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::LOAD_CONST, 2),
            Instr!(TargetOpcode::BUILD_LIST, 3),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::List(list_lock)) => {
                let list = list_lock.read().unwrap();
                let vals: Vec<i64> = list
                    .iter()
                    .map(|obj| match obj {
                        Obj::Long(l) => l.lock().unwrap().to_i64().unwrap(),
                        _ => panic!("expected Long"),
                    })
                    .collect();
                assert_eq!(vals, vec![10, 20, 30], "list should be [10, 20, 30]");
            }
            _ => panic!("expected List"),
        }
    }

    // =========================================================================
    // MAP_ADD: key/value should be in correct positions
    // =========================================================================
    #[test]
    fn map_add_key_value_order() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        let key = String!("mykey");
        let value = Long!(42);
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![key.clone(), value.clone()]);

        // Simulate a dict comprehension: BUILD_MAP, then load value, load key, MAP_ADD
        // CPython: STACKADJ(-2) then stack_pointer[-oparg]
        // After popping key+value, stack = [dict], so stack_pointer[-1] = dict => oparg=1
        let instrs = [
            Instr!(TargetOpcode::BUILD_MAP, 1),
            Instr!(TargetOpcode::LOAD_CONST, 1), // push value (42)
            Instr!(TargetOpcode::LOAD_CONST, 0), // push key ("mykey")
            Instr!(TargetOpcode::MAP_ADD, 1), // oparg=1: dict is 1 below stack pointer after pops
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        // Stack should have just the dict
        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Dict(dict_lock)) => {
                let dict = dict_lock.read().unwrap();
                let hashable_key = ObjHashable::try_from(&key).unwrap();
                let val = dict.get(&hashable_key).expect("key should exist in dict");
                match val {
                    Obj::Long(l) => assert_eq!(*l.lock().unwrap(), BigInt::from(42)),
                    _ => panic!("expected Long value"),
                }
            }
            _ => panic!("expected Dict"),
        }
    }

    // =========================================================================
    // INPLACE_DIVIDE: should work like BINARY_DIVIDE
    // =========================================================================
    #[test]
    fn inplace_divide() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(-7), Long!(2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::INPLACE_DIVIDE),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(-4)),
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // INPLACE_MODULO: should work like BINARY_MODULO
    // =========================================================================
    #[test]
    fn inplace_modulo() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(-7), Long!(2)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::INPLACE_MODULO),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(1)),
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // INPLACE_XOR: should work like BINARY_XOR
    // =========================================================================
    #[test]
    fn inplace_xor() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(0xFF), Long!(0x0F)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::INPLACE_XOR),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(0xF0)),
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // INPLACE_LSHIFT: should work like BINARY_LSHIFT
    // =========================================================================
    #[test]
    fn inplace_lshift() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![Long!(1), Long!(4)]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::INPLACE_LSHIFT),
        ];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(16)),
            _ => panic!("expected Long"),
        }
    }

    // =========================================================================
    // FOR_ITER on a string: should iterate bytes front-to-back
    // =========================================================================
    #[test]
    fn for_iter_string_front_to_back() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();

        // Simulate: push a string, then call FOR_ITER twice to get first two bytes
        // We push the string directly onto the stack since GET_ITER would replace it with None
        let s = Obj::String(Arc::new(RwLock::new(BString::from("ABC"))));
        stack.push((Some(s), InstructionTracker::new()));

        let instrs = [Instr!(TargetOpcode::FOR_ITER, 0)];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        // Stack should have: [remaining_string, first_byte]
        assert_eq!(stack.len(), 2);
        // TOS should be the first byte (0x41 = 'A'), not the last
        match &stack[1].0 {
            Some(Obj::Long(l)) => assert_eq!(
                *l.lock().unwrap(),
                BigInt::from(0x41u8),
                "first iteration should yield 'A' (0x41)"
            ),
            _ => panic!("expected Long for iteration result"),
        }

        // Pop the yielded value (like STORE_FAST would in real bytecode)
        stack.pop();

        // Iterate again
        let instrs = [Instr!(TargetOpcode::FOR_ITER, 0)];
        run_instrs(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
        );

        assert_eq!(stack.len(), 2);
        match &stack[1].0 {
            Some(Obj::Long(l)) => assert_eq!(
                *l.lock().unwrap(),
                BigInt::from(0x42u8),
                "second iteration should yield 'B' (0x42)"
            ),
            _ => panic!("expected Long for iteration result"),
        }
    }

    // =========================================================================
    // CALL_FUNCTION: args should be in forward order
    // =========================================================================
    #[test]
    fn call_function_args_order() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let mut code = default_code_obj();
        Arc::get_mut(&mut code).unwrap().consts = Arc::new(vec![
            Obj::None,  // 0: the "function"
            Long!(100), // 1: first arg
            Long!(200), // 2: second arg
            Long!(300), // 3: third arg
        ]);

        let instrs = [
            Instr!(TargetOpcode::LOAD_CONST, 0),    // function
            Instr!(TargetOpcode::LOAD_CONST, 1),    // arg 0
            Instr!(TargetOpcode::LOAD_CONST, 2),    // arg 1
            Instr!(TargetOpcode::LOAD_CONST, 3),    // arg 2
            Instr!(TargetOpcode::CALL_FUNCTION, 3), // 3 positional args
        ];

        use std::sync::Mutex;
        let captured_args: Arc<Mutex<Vec<VmVar>>> = Arc::new(RwLock::new(Vec::new()));
        let captured_args_clone = Arc::clone(&captured_args);

        run_instrs_with_callback(
            &mut code,
            &instrs,
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            &names_loaded,
            move |_f, args, _kwargs| {
                *captured_args_clone.lock().unwrap() = args;
                None
            },
        );

        let args = captured_args.lock().unwrap();
        assert_eq!(args.len(), 3);
        // args[0] should be 100 (first positional), args[2] should be 300 (last positional)
        let vals: Vec<i64> = args
            .iter()
            .map(|a| match a.as_ref().unwrap() {
                Obj::Long(l) => l.lock().unwrap().to_i64().unwrap(),
                _ => panic!("expected Long"),
            })
            .collect();
        assert_eq!(
            vals,
            vec![100, 200, 300],
            "args should be in forward order [100, 200, 300]"
        );
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

#[cfg(test)]
mod arithmetic_none_tests {
    use super::tests::*;
    use super::*;
    use crate::Long;
    use num_bigint::BigInt;
    use std::sync::Arc;

    type TargetOpcode = pydis::opcode::py27::Standard;

    /// When the right-hand operand is None (unknown), binary add on Long should
    /// produce None instead of panicking.
    #[test]
    fn binary_add_long_none_rhs() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        // Push a known Long, then a None (unknown value)
        stack.push((Some(Long!(42)), InstructionTracker::new()));
        stack.push((None, InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BINARY_ADD);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        assert!(stack[0].0.is_none(), "result should be None (unknown)");
    }

    /// When the left-hand operand is None, binary or on Long should produce None.
    #[test]
    fn binary_or_none_lhs_long() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((None, InstructionTracker::new()));
        stack.push((Some(Long!(7)), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BINARY_OR);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        assert!(stack[0].0.is_none(), "result should be None (unknown)");
    }

    /// Both operands None should produce None.
    #[test]
    fn binary_xor_both_none() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((None, InstructionTracker::new()));
        stack.push((None, InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BINARY_XOR);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        assert!(stack[0].0.is_none(), "result should be None (unknown)");
    }

    /// Unsupported type combination (e.g. Tuple + Long) should produce None
    /// instead of panicking.
    #[test]
    fn binary_add_unsupported_types_returns_none() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let tuple = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(1)])));
        stack.push((Some(tuple), InstructionTracker::new()));
        stack.push((Some(Long!(2)), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BINARY_ADD);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        assert!(
            stack[0].0.is_none(),
            "result should be None for unsupported type combo"
        );
    }
}

#[cfg(test)]
mod fix_regression_tests {
    use super::tests::*;
    use super::*;
    use crate::{Long, String};
    use num_bigint::BigInt;
    use py27_marshal::bstr::BString;
    use std::sync::{Arc, RwLock};

    type TargetOpcode = pydis::opcode::py27::Standard;

    // -- String == String --

    #[test]
    fn compare_string_eq_equal() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((Some(String!("hello")), InstructionTracker::new()));
        stack.push((Some(String!("hello")), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 2);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(*b, "equal strings should be =="),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_string_eq_not_equal() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((Some(String!("hello")), InstructionTracker::new()));
        stack.push((Some(String!("world")), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 2);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(!*b, "different strings should not be =="),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    // -- String != String --

    #[test]
    fn compare_string_ne_different() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((Some(String!("hello")), InstructionTracker::new()));
        stack.push((Some(String!("world")), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 3);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(*b, "different strings should be !="),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_string_ne_equal() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((Some(String!("same")), InstructionTracker::new()));
        stack.push((Some(String!("same")), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 3);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(!*b, "equal strings should not be !="),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    // -- String in Tuple --

    #[test]
    fn compare_string_in_tuple_found() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let needle = String!("banana");
        let haystack = Obj::Tuple(Arc::new(RwLock::new(vec![
            String!("apple"),
            String!("banana"),
            String!("cherry"),
        ])));

        stack.push((Some(needle), InstructionTracker::new()));
        stack.push((Some(haystack), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 6);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(*b, "'banana' should be in tuple"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_string_in_tuple_not_found() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let needle = String!("mango");
        let haystack = Obj::Tuple(Arc::new(RwLock::new(vec![
            String!("apple"),
            String!("banana"),
        ])));

        stack.push((Some(needle), InstructionTracker::new()));
        stack.push((Some(haystack), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 6);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(!*b, "'mango' should not be in tuple"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    // -- Tuple >= Tuple --

    #[test]
    fn compare_tuple_ge_equal() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let left = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(2), Long!(3)])));
        let right = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(2), Long!(3)])));

        stack.push((Some(left), InstructionTracker::new()));
        stack.push((Some(right), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 5);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(*b, "(2,3) >= (2,3) should be true"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_tuple_ge_greater() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let left = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(3), Long!(1)])));
        let right = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(2), Long!(9)])));

        stack.push((Some(left), InstructionTracker::new()));
        stack.push((Some(right), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 5);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(*b, "(3,1) >= (2,9) should be true"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_tuple_ge_less() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let left = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(1), Long!(5)])));
        let right = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(2), Long!(0)])));

        stack.push((Some(left), InstructionTracker::new()));
        stack.push((Some(right), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 5);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(!*b, "(1,5) >= (2,0) should be false"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn compare_tuple_ge_shorter_prefix() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let left = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(1), Long!(2)])));
        let right = Obj::Tuple(Arc::new(RwLock::new(vec![Long!(1), Long!(2), Long!(3)])));

        stack.push((Some(left), InstructionTracker::new()));
        stack.push((Some(right), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::COMPARE_OP, 5);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        match &stack[0].0 {
            Some(Obj::Bool(b)) => assert!(!*b, "(1,2) >= (1,2,3) should be false"),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    // -- UNPACK_SEQUENCE for List --

    #[test]
    fn unpack_sequence_list() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        let list = Obj::List(Arc::new(RwLock::new(vec![Long!(10), Long!(20), Long!(30)])));
        stack.push((Some(list), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::UNPACK_SEQUENCE, 3);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        // UNPACK_SEQUENCE pushes items in reverse so that subsequent
        // STORE_FAST pops them in forward order.
        assert_eq!(stack.len(), 3);
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(30)),
            other => panic!("unexpected stack[0]: {:?}", other),
        }
        match &stack[1].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(20)),
            other => panic!("unexpected stack[1]: {:?}", other),
        }
        match &stack[2].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(10)),
            other => panic!("unexpected stack[2]: {:?}", other),
        }
    }

    // -- Shift with non-Long TOS --

    #[test]
    fn lshift_none_tos_returns_none() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        stack.push((Some(Long!(42)), InstructionTracker::new()));
        stack.push((None, InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BINARY_LSHIFT);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("should not error");

        assert_eq!(stack.len(), 1);
        assert!(
            stack[0].0.is_none(),
            "shift with None TOS should produce None"
        );
    }

    // -- StackUnderflow --

    #[test]
    fn empty_stack_pop_returns_error() {
        let mut stack: VmStack<()> = VmStack::new();
        let result = stack_pop::<TargetOpcode, ()>(&mut stack);
        assert!(result.is_err(), "popping empty stack should return Err");
    }

    #[test]
    fn break_loop_is_nop() {
        let (mut stack, mut vars, mut names, mut globals, names_loaded) = setup_vm_vars();
        let code = default_code_obj();

        // Push a value so we can verify the stack is unchanged
        stack.push((Some(Long!(99)), InstructionTracker::new()));

        let instr = Instr!(TargetOpcode::BREAK_LOOP);
        execute_instruction(
            &instr,
            Arc::clone(&code),
            &mut stack,
            &mut vars,
            &mut names,
            &mut globals,
            Arc::clone(&names_loaded),
            |_f, _args, _kwargs| panic!("no calls expected"),
            (),
        )
        .expect("BREAK_LOOP should not error");

        assert_eq!(stack.len(), 1, "stack should be unchanged after BREAK_LOOP");
        match &stack[0].0 {
            Some(Obj::Long(l)) => assert_eq!(*l.lock().unwrap(), BigInt::from(99)),
            other => panic!("unexpected stack value: {:?}", other),
        }
    }
}
