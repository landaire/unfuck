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

use std::sync::{Arc, RwLock};

use py27_marshal::{Code, CodeFlags, Obj};
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
        let mut instrs = cfg::decode(code.code.as_slice())?;
        // Both cleanups are semantics-preserving but reshape the CFG, which a few
        // structuring patterns are sensitive to. They run under the same flag as the
        // opaque strip so the no-strip fallback in `decompile_function_with_defaults`
        // decompiles the untouched bytecode when a cleanup trips the structurer.
        if STRIP_OPAQUE.with(|flag| flag.get()) {
            // Drop the obfuscator's no-op forward jumps, which only fragment the
            // instruction stream and break straight-line pattern matching.
            cfg::strip_noop_jumps(&mut instrs);
            // Neutralize the obfuscator's opaque-predicate stack injections so the
            // buried operands of imports/class/function defs reach the unstacker.
            cfg::strip_opaque_predicates(&mut instrs, &code);
        }
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
    /// Renders the function as a Python `def`, including its signature. `defaults`
    /// are the rendered default values for the trailing positional parameters,
    /// supplied by the enclosing scope's `MAKE_FUNCTION`.
    pub fn to_source(&self, defaults: &[String]) -> String {
        let mut source = self.signature(defaults);
        source.push('\n');
        let body = emit::Emitter::new(&self.code, &self.arena).render_body(&self.body);
        source.push_str(&body);
        source
    }

    /// Builds the `def name(args):` line from the code object's metadata, with
    /// identifiers sanitized so deobfuscator-mangled names still parse.
    fn signature(&self, defaults: &[String]) -> String {
        let ident = |name: &str| emit::sanitize_identifier(name);
        format!("def {}({}):", ident(&self.code.name.to_string()), self.params(defaults).join(", "))
    }

    /// Builds the parameter list (positional with defaults, then `*args`/`**kwargs`)
    /// from the code object's metadata. Shared by [`Self::signature`] and lambda
    /// rendering. `defaults` are already rendered in the enclosing scope.
    fn params(&self, defaults: &[String]) -> Vec<String> {
        let ident = |name: &str| emit::sanitize_identifier(name);
        let argcount = self.code.argcount as usize;
        let mut params: Vec<String> = self
            .code
            .varnames
            .iter()
            .take(argcount)
            .map(|p| ident(&p.to_string()))
            .collect();
        // The defaults apply to the last `defaults.len()` positional parameters.
        let first_default = argcount.saturating_sub(defaults.len());
        for (offset, default) in defaults.iter().enumerate() {
            if let Some(param) = params.get_mut(first_default + offset) {
                *param = format!("{}={}", param, default);
            }
        }
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
        params
    }

    /// Renders this function as a `lambda args: expr` when its body is a single
    /// `return expr` (the only shape a Python lambda compiles to). `defaults` are
    /// rendered in the enclosing scope. Returns `None` for any other body, so the
    /// caller can fall back to rejecting the construct.
    fn lambda_source(&self, defaults: &[String]) -> Option<String> {
        // A lambda body is a single expression, but the compiler lowers a ternary in
        // it to `if c: return a else: return b`; accept that shape as well.
        let body = emit::Emitter::new(&self.code, &self.arena).body_as_expr(&self.body, 0)?;
        let params = self.params(defaults).join(", ");
        Some(if params.is_empty() {
            format!("lambda: {}", body)
        } else {
            format!("lambda {}: {}", params, body)
        })
    }
}

/// Decompiles a single code object to Python source. Returns
/// [`IrError::Incomplete`] if any construct could not be fully recovered, so the
/// caller never receives invalid or partial source.
pub fn decompile_function(code: Arc<Code>) -> Result<String, IrError> {
    decompile_function_with_defaults(code, &[])
}

/// Collects `code` and every code object nested in its consts (functions, class
/// bodies, comprehensions) into `out`, parents before children.
fn collect_code_objects(code: &Arc<RwLock<Code>>, out: &mut Vec<Arc<Code>>) {
    let guard = code.read().unwrap_or_else(|e| e.into_inner());
    out.push(Arc::new(guard.clone()));
    for konst in guard.consts.iter() {
        if let Obj::Code(inner) = konst {
            collect_code_objects(inner, out);
        }
    }
}

/// Whether `code` is a comprehension or generator-expression body. Such objects
/// take the synthetic single argument `.0` (not a writable identifier, so no real
/// function has one) and are only valid inlined into their parent, where the folder
/// recovers them. Decompiled standalone they always fail, so the module dump skips
/// them rather than emit a noise comment for a construct that is already inlined.
pub fn is_comprehension_body(code: &Code) -> bool {
    code.argcount == 1
        && code.varnames.first().map(|name| name.to_string()).as_deref() == Some(".0")
}

/// Decompiles every code object reachable from `root` (the module body and all
/// nested functions and classes) to Python source, concatenated. Comprehension and
/// generator-expression bodies are skipped because they are recovered inline in
/// their parent. A code object that cannot be fully recovered is emitted as a
/// comment naming the object and the reason, so output is always produced rather
/// than the whole module failing on one unsupported construct. This is the
/// whole-module entry point the deobfuscator uses in place of an external decompiler.
pub fn decompile_module(root: &Arc<RwLock<Code>>) -> String {
    let mut all = Vec::new();
    collect_code_objects(root, &mut all);
    let mut out = String::new();
    for code in &all {
        if is_comprehension_body(code) {
            continue;
        }
        match decompile_function(Arc::clone(code)) {
            Ok(source) => {
                out.push_str(&source);
                out.push_str("\n\n");
            }
            Err(err) => {
                out.push_str(&format!("# {}: {}\n\n", code.name, err));
            }
        }
    }
    out
}

/// Decompiles a code object whose enclosing scope supplied default argument
/// values (rendered in that scope), used for nested `def`s with defaults.
pub fn decompile_function_with_defaults(
    code: Arc<Code>,
    defaults: &[String],
) -> Result<String, IrError> {
    // The opaque-predicate stripper is a heuristic that can, in rare interleaved
    // cases, hand the unstacker a code object it cannot balance. Decompile with the
    // strip first (it fixes operands the obfuscator buried, and corrects functions
    // the strip-free path would render wrongly); only if that fails fall back to
    // decompiling without it, so the strip never regresses a function below what the
    // strip-free pipeline already recovered.
    decompile_attempt(Arc::clone(&code), defaults, true)
        .or_else(|_| decompile_attempt(code, defaults, false))
}

/// Runs the decode/structure/emit pipeline for one code object with opaque-predicate
/// stripping toggled. The flag is saved and restored so nested comprehensions decoded
/// during emission inherit this attempt's choice without disturbing the caller's.
fn decompile_attempt(
    code: Arc<Code>,
    defaults: &[String],
    strip: bool,
) -> Result<String, IrError> {
    let previous = STRIP_OPAQUE.with(|flag| flag.replace(strip));
    let result = (|| {
        let source = DecodedFunction::decode(code)?.structure()?.to_source(defaults);
        if source.contains(emit::UNRECOVERED) {
            return Err(IrError::Incomplete);
        }
        Ok(source)
    })();
    STRIP_OPAQUE.with(|flag| flag.set(previous));
    result
}

thread_local! {
    /// Whether [`DecodedFunction::decode`] should strip opaque-predicate injections
    /// for the code object currently being decoded. Toggled per decompile attempt.
    static STRIP_OPAQUE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}
