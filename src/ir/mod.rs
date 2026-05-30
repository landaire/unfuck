//! A raising IR for recovering Python source from deobfuscated bytecode.
//!
//! The pipeline lowers a [`Code`] object through a sequence of typed stages, each
//! produced by consuming the previous one:
//!
//! ```text
//! DecodedFunction  -> UnstackedFunction  -> (later) Ssa -> Structured -> source
//! ```
//!
//! Milestone 1 covers branch-free functions: decode, symbolic-stack into
//! statements, and emit Python. Control flow returns [`IrError::HasControlFlow`]
//! so the supported surface is explicit and grows pass by pass.

pub mod emit;
pub mod expr;
pub mod unstack;

use std::sync::Arc;

use py27_marshal::{Code, CodeFlags};
use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use expr::{ExprArena, Stmt};
use unstack::Unstacker;

/// Reasons the IR pipeline can reject or fail on a code object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrError {
    /// The bytecode could not be decoded into instructions.
    Decode,
    /// An opcode is not yet handled by the unstack pass.
    Unsupported(Mnemonic),
    /// The function contains control flow, which Milestone 1 does not structure.
    HasControlFlow(Mnemonic),
    /// An instruction that requires an operand had none.
    MissingOperand,
    /// An instruction operand was outside its valid range.
    BadOperand,
    /// The symbolic stack was empty when an operand was needed.
    StackUnderflow,
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrError::Decode => write!(f, "failed to decode bytecode"),
            IrError::Unsupported(m) => write!(f, "unsupported opcode {:?}", m),
            IrError::HasControlFlow(m) => write!(f, "control flow not yet structured ({:?})", m),
            IrError::MissingOperand => write!(f, "instruction operand missing"),
            IrError::BadOperand => write!(f, "instruction operand out of range"),
            IrError::StackUnderflow => write!(f, "symbolic stack underflow"),
        }
    }
}

impl std::error::Error for IrError {}

/// A decoded, not-yet-lowered function: the entry stage of the pipeline.
pub struct DecodedFunction {
    code: Arc<Code>,
    instrs: Vec<Instruction<Standard>>,
}

/// A function whose body has been lowered to a flat statement list.
pub struct UnstackedFunction {
    code: Arc<Code>,
    arena: ExprArena,
    body: Vec<Stmt>,
}

impl DecodedFunction {
    /// Decodes a code object's bytecode into instructions.
    pub fn decode(code: Arc<Code>) -> Result<DecodedFunction, IrError> {
        let bytecode = Arc::clone(&code.code);
        let mut reader = std::io::Cursor::new(bytecode.as_slice());
        let mut instrs = Vec::new();
        while (reader.position() as usize) < bytecode.len() {
            match decode_py27::<Standard, _>(&mut reader) {
                Ok(instr) => instrs.push(instr),
                Err(_) => return Err(IrError::Decode),
            }
        }
        Ok(DecodedFunction { code, instrs })
    }

    /// Lowers a branch-free function body to statements via symbolic execution.
    pub fn unstack(self) -> Result<UnstackedFunction, IrError> {
        let mut unstacker = Unstacker::new();
        for instr in &self.instrs {
            if let Some(control) = control_flow_mnemonic(instr.opcode.mnemonic()) {
                return Err(IrError::HasControlFlow(control));
            }
            unstacker.step(instr)?;
        }
        let (arena, body) = unstacker.finish();
        Ok(UnstackedFunction {
            code: self.code,
            arena,
            body,
        })
    }
}

impl UnstackedFunction {
    /// Renders the function as a Python `def`, including its signature.
    pub fn to_source(&self) -> String {
        let mut source = self.signature();
        source.push('\n');
        let body = emit::Emitter::new(&self.code, &self.arena).render_body(&self.body);
        source.push_str(&body);
        source
    }

    /// Builds the `def name(args):` line from the code object's metadata.
    fn signature(&self) -> String {
        let name = self.code.name.to_string();
        let argcount = self.code.argcount as usize;
        let mut params: Vec<String> = self
            .code
            .varnames
            .iter()
            .take(argcount)
            .map(|p| p.to_string())
            .collect();
        if self.code.flags.contains(CodeFlags::VARARGS) {
            params.push(format!("*{}", self.code.varnames.get(argcount).map_or("args".to_string(), |v| v.to_string())));
        }
        if self.code.flags.contains(CodeFlags::VARKEYWORDS) {
            let idx = argcount + self.code.flags.contains(CodeFlags::VARARGS) as usize;
            params.push(format!("**{}", self.code.varnames.get(idx).map_or("kwargs".to_string(), |v| v.to_string())));
        }
        format!("def {}({}):", name, params.join(", "))
    }
}

/// Decompiles a single code object to Python source. Milestone 1: branch-free
/// bodies only.
pub fn decompile_function(code: Arc<Code>) -> Result<String, IrError> {
    Ok(DecodedFunction::decode(code)?.unstack()?.to_source())
}

/// Returns the mnemonic if the opcode introduces control flow that Milestone 1
/// does not yet structure. `RETURN_VALUE` is allowed as a block terminator.
fn control_flow_mnemonic(mnemonic: Mnemonic) -> Option<Mnemonic> {
    let is_control = matches!(
        mnemonic,
        Mnemonic::SETUP_LOOP
            | Mnemonic::SETUP_EXCEPT
            | Mnemonic::SETUP_FINALLY
            | Mnemonic::SETUP_WITH
            | Mnemonic::FOR_ITER
            | Mnemonic::BREAK_LOOP
            | Mnemonic::CONTINUE_LOOP
            | Mnemonic::END_FINALLY
            | Mnemonic::RAISE_VARARGS
            | Mnemonic::YIELD_VALUE
            | Mnemonic::JUMP_FORWARD
            | Mnemonic::JUMP_ABSOLUTE
            | Mnemonic::POP_JUMP_IF_FALSE
            | Mnemonic::POP_JUMP_IF_TRUE
            | Mnemonic::JUMP_IF_FALSE_OR_POP
            | Mnemonic::JUMP_IF_TRUE_OR_POP
    );
    is_control.then_some(mnemonic)
}
