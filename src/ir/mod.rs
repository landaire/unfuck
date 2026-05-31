//! A raising IR for recovering Python source from deobfuscated bytecode.
//!
//! The pipeline lowers a [`Code`] object through typed stages, each produced by
//! consuming the previous one:
//!
//! ```text
//! DecodedFunction -> StructuredFunction -> source
//! ```
//!
//! [`DecodedFunction`] holds the decoded instruction stream. [`DecodedFunction::structure`]
//! builds a control-flow graph, lowers each block by symbolic execution, and
//! recovers nested `if`/`else` from post-dominators. [`StructuredFunction::to_source`]
//! prints Python. Loops, exceptions, and short-circuit expressions are not yet
//! structured and surface as [`IrError::HasControlFlow`].

pub mod cfg;
pub mod emit;
pub mod expr;
pub mod simplify;
pub mod structure;
pub mod unstack;

use std::sync::Arc;

use py27_marshal::{Code, CodeFlags};
use pydis::opcode::py27::Mnemonic;

use cfg::{Cfg, OffsetInstr};
use expr::{ExprArena, Stmt};

/// Reasons the IR pipeline can reject or fail on a code object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrError {
    /// The bytecode could not be decoded into instructions.
    Decode,
    /// An opcode is not yet handled by the unstack pass.
    Unsupported(Mnemonic),
    /// The function uses control flow that is not yet structured (loops,
    /// exceptions, short-circuit operators, or a back edge).
    HasControlFlow(Mnemonic),
    /// An instruction that requires an operand had none.
    MissingOperand,
    /// An instruction operand was outside its valid range.
    BadOperand,
    /// The symbolic stack was empty when an operand was needed.
    StackUnderflow,
    /// The control-flow graph did not reduce to nested regions.
    Unstructurable,
    /// A construct was only partially recovered, so the emitted source would be
    /// incomplete or invalid.
    Incomplete,
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
            IrError::Unstructurable => write!(f, "control-flow graph did not reduce to regions"),
            IrError::Incomplete => write!(f, "construct only partially recovered"),
        }
    }
}

impl std::error::Error for IrError {}

/// A decoded, not-yet-structured function: the entry stage of the pipeline.
pub struct DecodedFunction {
    code: Arc<Code>,
    instrs: Vec<OffsetInstr>,
}

/// A function whose body has been recovered to a nested statement list.
pub struct StructuredFunction {
    code: Arc<Code>,
    arena: ExprArena,
    body: Vec<Stmt>,
}

impl DecodedFunction {
    /// Decodes a code object's bytecode into offset-tagged instructions.
    pub fn decode(code: Arc<Code>) -> Result<DecodedFunction, IrError> {
        let instrs = cfg::decode(code.code.as_slice())?;
        Ok(DecodedFunction { code, instrs })
    }

    /// Builds the CFG, lowers each block, and recovers control flow.
    pub fn structure(self) -> Result<StructuredFunction, IrError> {
        let cfg = Cfg::build(&self.instrs)?;
        self.structure_with(cfg)
    }

    /// Structures a comprehension code object, lowering its accumulator and
    /// `SET_ADD`/`MAP_ADD` instructions into comprehension element statements.
    pub fn structure_comp(self) -> Result<StructuredFunction, IrError> {
        let cfg = Cfg::build_comp(&self.instrs)?;
        self.structure_with(cfg)
    }

    fn structure_with(self, mut cfg: Cfg) -> Result<StructuredFunction, IrError> {
        // Fold opaque-predicate branches before structuring so the junk they guard
        // becomes unreachable and is never emitted.
        simplify::simplify(&mut cfg, &self.code);
        let body = structure::structure(&cfg)?;
        Ok(StructuredFunction {
            code: self.code,
            arena: cfg.arena,
            body,
        })
    }
}

impl StructuredFunction {
    /// Renders the function as a Python `def`, including its signature.
    pub fn to_source(&self) -> String {
        let mut source = self.signature();
        source.push('\n');
        let body = emit::Emitter::new(&self.code, &self.arena).render_body(&self.body);
        source.push_str(&body);
        source
    }

    /// Builds the `def name(args):` line from the code object's metadata, with
    /// identifiers sanitized so deobfuscator-mangled names still parse.
    fn signature(&self) -> String {
        let ident = |name: &str| emit::sanitize_identifier(name);
        let argcount = self.code.argcount as usize;
        let mut params: Vec<String> = self
            .code
            .varnames
            .iter()
            .take(argcount)
            .map(|p| ident(&p.to_string()))
            .collect();
        if self.code.flags.contains(CodeFlags::VARARGS) {
            let name = self
                .code
                .varnames
                .get(argcount)
                .map_or_else(|| "args".to_string(), |v| ident(&v.to_string()));
            params.push(format!("*{}", name));
        }
        if self.code.flags.contains(CodeFlags::VARKEYWORDS) {
            let idx = argcount + self.code.flags.contains(CodeFlags::VARARGS) as usize;
            let name = self
                .code
                .varnames
                .get(idx)
                .map_or_else(|| "kwargs".to_string(), |v| ident(&v.to_string()));
            params.push(format!("**{}", name));
        }
        format!("def {}({}):", ident(&self.code.name.to_string()), params.join(", "))
    }
}

/// Decompiles a single code object to Python source. Returns
/// [`IrError::Incomplete`] if any construct could not be fully recovered, so the
/// caller never receives invalid or partial source.
pub fn decompile_function(code: Arc<Code>) -> Result<String, IrError> {
    let source = DecodedFunction::decode(code)?.structure()?.to_source();
    if source.contains(emit::UNRECOVERED) {
        return Err(IrError::Incomplete);
    }
    Ok(source)
}
