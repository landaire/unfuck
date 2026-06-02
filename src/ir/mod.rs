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
        // A function whose whole body is a returned boolean expression compiled to
        // cross-block short-circuit control flow does not reduce to blocks the
        // unstacker can fold (it clears the stack at boundaries). Recover it directly
        // as one expression, verified against the control flow; on any mismatch this
        // returns None and the normal block-structuring path runs (and rejects).
        let mut us = unstack::Unstacker::new();
        if let Some(value) = us.recover_returned_bool(&self.instrs) {
            let mut body = us.take_stmts();
            body.push(Stmt::Return(Some(value)));
            return Ok(StructuredFunction {
                code: self.code,
                arena: us.into_arena(),
                body,
            });
        }
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
        let mut source = String::new();
        if let Some(comment) = self.original_name_comment() {
            source.push_str(&comment);
            source.push('\n');
        }
        source.push_str(&self.signature(defaults));
        source.push('\n');
        let body = emit::Emitter::new(&self.code, &self.arena).render_body(&self.body);
        source.push_str(&body);
        source
    }

    /// Renders this code object as a module: its statements at top level, with no
    /// enclosing `def` wrapper. The root of a module is the module's own bytecode
    /// (imports, `def` statements, a trailing implicit `return None`); emitting it
    /// here recovers a real module instead of a function named after the body's
    /// co_name. The trailing `return None` is dropped (a bare `return` is illegal at
    /// module scope).
    ///
    /// Returns `None` when the body cannot be a module: a generator, or one that
    /// still contains a module-scope `return` (deobfuscation residue, or a code
    /// object that is really a function). The caller then keeps the `def` form.
    pub fn to_module_source(&self) -> Option<String> {
        if self.code.flags.contains(CodeFlags::GENERATOR) {
            return None;
        }
        let mut stmts: Vec<Stmt> = self.body.clone();
        if matches!(stmts.last(), Some(Stmt::Return(_))) {
            stmts.pop();
        }
        if has_module_scope_return(&stmts) {
            return None;
        }
        let body = emit::Emitter::new_module(&self.code, &self.arena).render_body(&stmts);
        Some(match self.original_name_comment() {
            Some(comment) => format!("{}\n{}", comment, body),
            None => body,
        })
    }

    /// Builds the `def name(args):` line from the code object's metadata, with
    /// identifiers sanitized so deobfuscator-mangled names still parse.
    fn signature(&self, defaults: &[String]) -> String {
        format!("def {}({}):", self.display_name(), self.params(defaults).join(", "))
    }

    /// Whether the body holds a statement only legal at module scope, so it cannot be
    /// rendered as a `def` (the module-as-function fallback): a `from __future__
    /// import ...` (must lead the module) or a `from m import *`. `import *` inside a
    /// function is a SyntaxError whenever the function has a nested function that
    /// closes over one of its bindings -- which a module body wrapped in a `def`
    /// routinely does, since its classes and functions reference module-level names
    /// that become the wrapper's locals. The bytecode's own `co_freevars` are empty
    /// (those references are globals until the wrap), so the closure cannot be
    /// detected cheaply; reject any `import *` rather than emit source that may not
    /// compile. The module dump then falls back to a comment plus the recoverable
    /// nested leaves, which is more useful than a non-runnable `def` wrapper anyway.
    fn requires_module_scope(&self) -> bool {
        self.body.iter().any(|stmt| match stmt {
            Stmt::FromImport { module, star, .. } => {
                *star
                    || self.code.names.get(module.0 as usize).map(|n| n.to_string()).as_deref()
                        == Some("__future__")
            }
            _ => false,
        })
    }

    /// The recovered display name: the deobfuscator's `_orig_<id>` suffix removed,
    /// then sanitized to a legal identifier.
    fn display_name(&self) -> String {
        emit::sanitize_identifier(emit::split_orig_suffix(&self.code.name.to_string()).0)
    }

    /// `# original name: <id>` when the deobfuscator recovered a name different from
    /// the original, surfacing the pre-rename name `co_name` carries without keeping
    /// it in the emitted identifier. `None` for unrenamed input (no suffix), so a
    /// non-obfuscated code object gets no comment.
    fn original_name_comment(&self) -> Option<String> {
        let name = self.code.name.to_string();
        let (recovered, original) = emit::split_orig_suffix(&name);
        original
            .filter(|orig| *orig != recovered)
            .map(|orig| format!("# original name: {}", orig))
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
/// Whether `stmts` contain a `return` at module scope -- in the body itself or any
/// nested control-flow block, but not inside a nested `def`/`class` (whose bodies
/// are separate code objects, where `return` is legal). A module emitted at top
/// level cannot contain such a return, so its presence forces the `def`-wrapped form.
fn has_module_scope_return(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        Stmt::Return(_) => true,
        Stmt::If { then, els, .. } => {
            has_module_scope_return(then) || has_module_scope_return(els)
        }
        Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::With { body, .. } => {
            has_module_scope_return(body)
        }
        Stmt::Try { body, handlers } => {
            has_module_scope_return(body)
                || handlers.iter().any(|handler| has_module_scope_return(&handler.body))
        }
        Stmt::TryFinally { body, finalbody } => {
            has_module_scope_return(body) || has_module_scope_return(finalbody)
        }
        _ => false,
    })
}

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

    // The root code object is the module's own body (imports, `def` statements, the
    // implicit `return None`). When it fully decompiles it has inlined every nested
    // function, so emit it at module level -- no `def` wrapper, no extra indent --
    // which recovers a real, runnable module instead of a function named after the
    // body's co_name (and avoids re-emitting every nested function a second time
    // standalone).
    if let Some(root_code) = all.first()
        && let Ok(mut body) = decompile_module_body(Arc::clone(root_code))
    {
        if !body.ends_with('\n') {
            body.push('\n');
        }
        return body;
    }

    // Fallback: some nested object is unrecoverable, so the module body could not be
    // emitted whole. Dump every code object standalone (each failure as a comment) so
    // the recoverable leaves still appear.
    let mut out = String::new();
    for code in &all {
        if is_comprehension_body(code) {
            continue;
        }
        // A class or module body is not a function. Rendering it as a standalone
        // `def` wrapper turns its methods into nested functions and its module-level
        // names into the wrapper's locals, which makes `exec`, `import *`, and
        // `from __future__` inside it illegal (a SyntaxError on recompile). Its
        // methods are genuine functions dumped on their own below, so emit only a
        // marker for the body itself. Real functions carry CO_OPTIMIZED; class and
        // module bodies do not.
        if !code.flags.contains(CodeFlags::OPTIMIZED) {
            out.push_str(&format!("# {}: class or module body, not recovered\n\n", code.name));
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
    decompile_attempt(Arc::clone(&code), defaults, true, false)
        .or_else(|_| decompile_attempt(code, defaults, false, false))
}

/// Decompiles a module's root code object as a module body: its statements emitted
/// at top level rather than wrapped in a `def`. Succeeds only when the whole module
/// recovers (every nested object inlined without an `__unrecovered__` marker), in
/// which case the result is a real, top-level Python module.
fn decompile_module_body(code: Arc<Code>) -> Result<String, IrError> {
    decompile_attempt(Arc::clone(&code), &[], true, true)
        .or_else(|_| decompile_attempt(code, &[], false, true))
}

/// Runs the decode/structure/emit pipeline for one code object with opaque-predicate
/// stripping toggled. The flag is saved and restored so nested comprehensions decoded
/// during emission inherit this attempt's choice without disturbing the caller's.
/// `as_module` renders the body at top level (no `def` wrapper) instead of as a `def`.
fn decompile_attempt(
    code: Arc<Code>,
    defaults: &[String],
    strip: bool,
    as_module: bool,
) -> Result<String, IrError> {
    let previous = STRIP_OPAQUE.with(|flag| flag.replace(strip));
    let result = (|| {
        let structured = DecodedFunction::decode(code)?.structure()?;
        let source = if as_module {
            structured.to_module_source().ok_or(IrError::Incomplete)?
        } else {
            // `from __future__` and `import *` are only valid at module top level, so
            // a body holding one cannot be wrapped in a `def`; reject so the module
            // dump falls back to a comment rather than emitting invalid source.
            if structured.requires_module_scope() {
                return Err(IrError::Incomplete);
            }
            structured.to_source(defaults)
        };
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
