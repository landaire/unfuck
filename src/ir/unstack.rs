//! Symbolic stack execution: turns a straight-line run of bytecode into a list
//! of statements over an [`ExprArena`].
//!
//! Each value-producing instruction pushes a [`ValueId`] onto a symbolic stack;
//! each effecting instruction pops its operands and emits a [`Stmt`]. Opcodes
//! outside the supported set return [`IrError::Unsupported`] so coverage gaps
//! surface instead of producing wrong output.

use std::collections::{HashMap, HashSet};

use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use super::cfg::OffsetInstr;
use super::expr::*;
use super::IrError;

/// A tuple-assignment target under construction by `UNPACK_SEQUENCE` and the
/// stores that follow it.
struct PendingUnpack {
    /// The value being unpacked. `None` for a nested target (e.g. the `(a, b)` of
    /// `(a, b), c = ...`): it has no right-hand side of its own and its completed
    /// tuple fills a slot of the enclosing unpack.
    rhs: Option<ValueId>,
    arity: usize,
    targets: Vec<LValue>,
}

/// A short-circuit operator awaiting its right operand. `JUMP_IF_*_OR_POP` records
/// the left operand and the offset where the two sides merge; the merged value is
/// built once execution reaches that offset.
struct ShortCircuit {
    kind: BoolKind,
    lhs: ValueId,
    merge: Offset,
}

/// A ternary `then if cond else otherwise` under construction. The diamond's
/// `POP_JUMP_IF_FALSE` records `cond`; its `JUMP_FORWARD` records `then` and the
/// merge offset; the `otherwise` operand is on the stack at the merge.
struct PendingTernary {
    cond: ValueId,
    then: Option<ValueId>,
    merge: Offset,
    /// The diamond's else target -- where the `POP_JUMP_IF_*` branches when the test
    /// fails. A following `POP_JUMP` that branches to the SAME target (and whose `then`
    /// is not yet set) is an `and`-chain continuation of this ternary's condition; one
    /// that branches elsewhere begins a nested ternary inside this arm.
    else_target: Offset,
    /// The `shortcircuit` stack depth when this ternary was opened. Short-circuits
    /// below this depth were opened *before* the ternary, so they wrap the whole
    /// ternary (`a and (x if c else y)`); those at or above it belong to the then/else
    /// arm value. Used to fold and resolve in the correct nesting order rather than
    /// draining all short-circuits ahead of the ternary.
    sc_depth: usize,
}

/// A `from module import ...` under construction. `IMPORT_NAME` leaves the module
/// on the stack; each `IMPORT_FROM`/store pair adds a name, and the trailing
/// `POP_TOP` of the module completes it.
struct PendingFrom {
    module: NameId,
    names: Vec<(NameId, LValue)>,
    /// The `IMPORT_NAME` relative-import level operand (see [`Expr::Import`]).
    level: Option<ConstId>,
}

/// Symbolic stack machine for one basic block.
pub struct Unstacker {
    arena: ExprArena,
    stack: Vec<ValueId>,
    stmts: Vec<Stmt>,
    /// Stack of in-progress unpacks (outermost first). A flat assignment has at
    /// most one entry; nested targets like `(a, b), c = ...` push a second.
    unpacks: Vec<PendingUnpack>,
    shortcircuit: Vec<ShortCircuit>,
    /// Stack of in-progress ternaries (outermost first). A flat `a if c else b` has at
    /// most one entry; a chained `a if c1 else b if c2 else d` pushes a new entry for
    /// each nested ternary in an else arm, all sharing the merge and resolved
    /// innermost-first there.
    ternary: Vec<PendingTernary>,
    from_import: Option<PendingFrom>,
    /// Overrides the merge offset of a `JUMP_IF_FALSE_OR_POP` whose short-circuit is
    /// a chained-comparison test: the value lands after the cleanup, not at the
    /// jump's literal target. Keyed by the jump's offset.
    merge_overrides: HashMap<Offset, Offset>,
    /// True when lowering a comprehension code object: its leading `BUILD_SET`/
    /// `BUILD_MAP` is the accumulator (kept off the stack), and `SET_ADD`/`MAP_ADD`
    /// become element statements instead of unsupported opcodes.
    comp: bool,
    /// Whether the comprehension accumulator has been consumed from the stream.
    comp_acc_seen: bool,
    /// Operands of a `print` statement under construction. `PRINT_ITEM` appends one;
    /// `PRINT_NEWLINE` (or the next non-print instruction) flushes them.
    print_values: Vec<ValueId>,
    /// A `print >>stream, ...` statement under construction (PRINT_*_TO). Kept
    /// separate from `print_values` so the DUP_TOP/ROT_TWO between its operands does
    /// not trigger the stdout-print trailing-comma flush.
    print_to: Option<PrintTo>,
}

/// A `print >>stream, ...` under construction (see [`Unstacker::print_to`]).
struct PrintTo {
    stream: ValueId,
    values: Vec<ValueId>,
}

impl Unstacker {
    pub fn new() -> Unstacker {
        Unstacker::with_comp(false)
    }

    /// Builds an unstacker for a comprehension code object (see [`Unstacker::comp`]).
    pub fn new_comp() -> Unstacker {
        Unstacker::with_comp(true)
    }

    fn with_comp(comp: bool) -> Unstacker {
        Unstacker {
            arena: ExprArena::new(),
            stack: Vec::new(),
            stmts: Vec::new(),
            unpacks: Vec::new(),
            shortcircuit: Vec::new(),
            ternary: Vec::new(),
            from_import: None,
            merge_overrides: HashMap::new(),
            comp,
            comp_acc_seen: false,
            print_values: Vec::new(),
            print_to: None,
        }
    }

    /// Emits a pending `print` statement, if any, with a trailing comma. Called when
    /// a non-print instruction or the block terminator interrupts a `print a,` whose
    /// suppressed newline left no `PRINT_NEWLINE`.
    pub fn flush_print(&mut self) {
        if !self.print_values.is_empty() {
            let values = std::mem::take(&mut self.print_values);
            self.emit(Stmt::Print { values, newline: false, stream: None });
        }
    }

    /// Records the chained-comparison merge overrides for this function.
    pub fn set_merge_overrides(&mut self, overrides: HashMap<Offset, Offset>) {
        self.merge_overrides = overrides;
    }

    /// Whether this unstacker is lowering a comprehension code object.
    pub fn is_comp(&self) -> bool {
        self.comp
    }

    /// Whether the symbolic stack is currently empty.
    pub fn stack_is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Whether the top of the stack is an [`Expr::Import`] module object.
    fn tops_import(&self) -> bool {
        self.stack
            .last()
            .is_some_and(|top| matches!(self.arena.get(*top), Expr::Import { .. }))
    }

    /// Whether the top of the stack is an in-place result (an augmented-assignment
    /// rotation).
    fn tos_is_inplace(&self) -> bool {
        self.stack
            .last()
            .is_some_and(|top| matches!(self.arena.get(*top), Expr::Inplace(..)))
    }

    /// Whether the top two stack values are the same id, the signature of a
    /// `DUP_TOP` feeding a chained comparison's `ROT_THREE`.
    fn tos_equals_below(&self) -> bool {
        let len = self.stack.len();
        len >= 2 && self.stack[len - 1] == self.stack[len - 2]
    }

    /// Whether the top of stack is an unpack placeholder, i.e. a multi-element
    /// parallel assignment is already in progress.
    fn tos_is_unpack_slot(&self) -> bool {
        self.stack
            .last()
            .is_some_and(|top| matches!(self.arena.get(*top), Expr::UnpackSlot))
    }

    /// Whether a `print >>stream` is pending and its base stream is on top, i.e. a
    /// suppressed-newline `print >>f, a,` is being terminated by a `POP_TOP`.
    fn print_to_at_top(&self) -> bool {
        matches!(
            (self.print_to.as_ref(), self.stack.last()),
            (Some(pt), Some(top)) if *top == pt.stream
        )
    }

    /// Resolves any pending short-circuit or ternary whose merge point is `offset`:
    /// the remaining operand is on the stack, so combine it with what was recorded.
    pub fn resolve_pending(&mut self, offset: Offset) -> Result<(), IrError> {
        loop {
            // A short-circuit resolves before the innermost pending ternary only when it
            // was opened *inside* that ternary's arm (its stack depth is at or above the
            // ternary's `sc_depth`); the else arm's trailing `or`/`and` falls through to
            // the merge and is the ternary's otherwise. A short-circuit opened before the
            // ternary wraps it (`a and (x if c else y)`), so the ternary must resolve
            // first and become that short-circuit's right operand -- handled once the
            // ternary is popped and no enclosing ternary remains.
            if self.shortcircuit.last().map(|s| s.merge) == Some(offset)
                && self
                    .ternary
                    .last()
                    .is_none_or(|t| self.shortcircuit.len() > t.sc_depth)
            {
                let sc = self.shortcircuit.pop().unwrap();
                let rhs = self.pop()?;
                let combined = self.combine_bool(sc.kind, sc.lhs, rhs);
                self.stack.push(combined);
                continue;
            }
            // Resolve the innermost pending ternary first: a chained ternary nests its
            // else arms, so the last one pushed (deepest in the else chain) takes the
            // true else value off the stack, and each enclosing one then takes the
            // freshly-built nested ternary as its otherwise.
            if self.ternary.last().is_some_and(|t| t.merge == offset && t.then.is_some()) {
                let pending = self.ternary.pop().unwrap();
                let otherwise = self.pop()?;
                let ternary = self.arena.alloc(Expr::Ternary {
                    cond: pending.cond,
                    then: pending.then.unwrap(),
                    otherwise,
                });
                self.stack.push(ternary);
                continue;
            }
            return Ok(());
        }
    }

    /// Whether all short-circuit and ternary operators in this block resolved.
    pub fn pending_resolved(&self) -> bool {
        self.shortcircuit.is_empty() && self.ternary.is_empty()
    }

    /// Records the just-folded comprehension as the pending ternary's then operand,
    /// to be completed at `merge` (the comprehension's FOR_ITER exit). Used when a
    /// list comprehension is the then-arm of a ternary: the comprehension takes the
    /// place of the `JUMP_FORWARD` that records `then` for an ordinary ternary.
    pub fn set_comp_ternary_then(&mut self, merge: Offset) -> Result<(), IrError> {
        let then = self.pop()?;
        match self.ternary.last_mut() {
            Some(pending) if pending.then.is_none() => {
                pending.then = Some(then);
                pending.merge = merge;
                Ok(())
            }
            _ => Err(IrError::Unsupported(Mnemonic::FOR_ITER)),
        }
    }

    /// Folds every pending short-circuit into the value on top of the stack, used at
    /// a `RETURN` whose short-circuits never reached their merge. `return X and Y`
    /// where an arm is itself a chained comparison returns its value directly from
    /// the arm rather than at a single merge, so the merge blocks are dead
    /// (JUMP_IF_*_OR_POP creates no CFG edge) and the operators are left pending. The
    /// top of stack is the short-circuit's final operand, so combining inward yields
    /// the returned expression. The most recently opened operator binds tightest.
    pub fn force_resolve_shortcircuits(&mut self) -> Result<(), IrError> {
        while let Some(sc) = self.shortcircuit.pop() {
            let rhs = self.pop()?;
            let combined = self.combine_bool(sc.kind, sc.lhs, rhs);
            self.stack.push(combined);
        }
        Ok(())
    }

    /// Combines two short-circuit operands, flattening a right side of the same
    /// kind so `a and b and c` is one chain rather than nested pairs.
    fn combine_bool(&mut self, kind: BoolKind, lhs: ValueId, rhs: ValueId) -> ValueId {
        let mut operands = vec![lhs];
        match self.arena.get(rhs) {
            Expr::BoolOp(rhs_kind, items) if *rhs_kind == kind => {
                operands.extend(items.iter().copied());
            }
            _ => operands.push(rhs),
        }
        self.arena.alloc(Expr::BoolOp(kind, operands))
    }

    /// Whether `lhs` is the same place as the assignment target `target`, used to
    /// confirm an augmented assignment stores back to its own operand. The operand
    /// expression and target share ids (built from the same `DUP_TOP`), so a
    /// shallow comparison suffices.
    fn lvalue_matches(&self, target: &LValue, lhs: ValueId) -> bool {
        match (target, self.arena.get(lhs)) {
            (LValue::Local(a), Expr::Local(b)) => a == b,
            (LValue::Deref(a), Expr::Deref(b)) => a == b,
            (LValue::Name(a) | LValue::Global(a), Expr::Name(b) | Expr::Global(b)) => a == b,
            (LValue::Attr(obj, name), Expr::Attr(obj2, name2)) => obj == obj2 && name == name2,
            (LValue::Subscript(c, k), Expr::Subscript(c2, k2)) => c == c2 && k == k2,
            _ => false,
        }
    }

    /// Pops the bounds of a `SLICE_*`/`STORE_SLICE_*`/`DELETE_SLICE_*` opcode. The
    /// opcode number selects which bounds are present: +1 a lower, +2 an upper, +3
    /// both (upper on top of the stack).
    fn pop_slice_bounds(
        &mut self,
        mnemonic: Mnemonic,
    ) -> Result<(Option<ValueId>, Option<ValueId>), IrError> {
        let kind = format!("{:?}", mnemonic);
        let upper = if kind.ends_with("_2") || kind.ends_with("_3") {
            Some(self.pop()?)
        } else {
            None
        };
        let lower = if kind.ends_with("_1") || kind.ends_with("_3") {
            Some(self.pop()?)
        } else {
            None
        };
        Ok((lower, upper))
    }

    /// Pops the code constant that `MAKE_FUNCTION`/`MAKE_CLOSURE` builds from. In
    /// real 2.7 bytecode the code object is always the `LOAD_CONST` immediately on
    /// top, but the obfuscator injects an opaque-predicate value (a comparison built
    /// from junk `unknown_N` temps) between that `LOAD_CONST` and the `MAKE_*`. That
    /// value is never a constant, so any non-`Const` entries on top are opaque junk:
    /// discard them until the real code constant resurfaces. A function's defaults
    /// sit *below* the code object, so this never consumes them.
    fn pop_code_const(&mut self) -> Result<ValueId, IrError> {
        loop {
            let top = self.pop()?;
            if matches!(self.arena.get(top), Expr::Const(_)) {
                return Ok(top);
            }
        }
    }

    /// Pushes a function object built from a code constant with the given defaults,
    /// shared by `MAKE_FUNCTION` and `MAKE_CLOSURE`.
    fn make_function(&mut self, code: ValueId, defaults: Vec<ValueId>) -> Result<(), IrError> {
        match self.arena.get(code) {
            Expr::Const(const_id) => {
                let code = *const_id;
                self.push(Expr::MakeFunction { code, defaults });
                Ok(())
            }
            _ => Err(IrError::Unsupported(Mnemonic::MAKE_FUNCTION)),
        }
    }

    /// Appends a condition to a flat `and` chain, keeping `a and b and c` as one
    /// `BoolOp` rather than nesting.
    fn and_chain(&mut self, existing: ValueId, new: ValueId) -> ValueId {
        let mut operands = match self.arena.get(existing) {
            Expr::BoolOp(BoolKind::And, items) => items.clone(),
            _ => vec![existing],
        };
        operands.push(new);
        self.arena.alloc(Expr::BoolOp(BoolKind::And, operands))
    }

    fn push(&mut self, expr: Expr) {
        let id = self.arena.alloc(expr);
        self.stack.push(id);
    }

    fn pop(&mut self) -> Result<ValueId, IrError> {
        self.stack.pop().ok_or(IrError::StackUnderflow)
    }

    /// Records an assignment to `target`. While an `UNPACK_SEQUENCE` is in progress
    /// the stores it feeds collect into a single tuple assignment instead of
    /// emitting one statement each.
    fn complete_store(&mut self, target: LValue, value: ValueId) {
        if let Expr::MakeFunction { code, defaults } = self.arena.get(value) {
            let (code, defaults) = (*code, defaults.clone());
            self.emit(Stmt::FunctionDef { target, code, defaults });
            return;
        }
        if let Expr::BuildClass { name, bases, code } = self.arena.get(value) {
            let (name, bases, code) = (*name, *bases, *code);
            self.emit(Stmt::ClassDef { target, name, bases, code });
            return;
        }
        // `import module` binds the module object; `import a.b as c` drills into the
        // submodule with `LOAD_ATTR` after `IMPORT_NAME`, leaving an attribute access
        // that bottoms out at the imported module. Either way it is one import bound
        // to the target. `from module import name` binds each name pulled by
        // IMPORT_FROM into the pending from-import.
        let mut base = value;
        while let Expr::Attr(obj, _) = self.arena.get(base) {
            base = *obj;
        }
        if let Expr::Import { module, level } = self.arena.get(base) {
            let (module, level) = (*module, *level);
            self.emit(Stmt::Import { module, target, level });
            return;
        }
        if let Expr::ImportFrom(name) = self.arena.get(value) {
            let name = *name;
            if let Some(pending) = self.from_import.as_mut() {
                pending.names.push((name, target));
            }
            return;
        }
        // An in-place result stored back to its own left operand is an augmented
        // assignment (`target op= rhs`).
        if let Expr::Inplace(op, lhs, rhs) = *self.arena.get(value) {
            if self.lvalue_matches(&target, lhs) {
                self.emit(Stmt::AugAssign(target, op, rhs));
                return;
            }
        }
        if !self.unpacks.is_empty() && matches!(self.arena.get(value), Expr::UnpackSlot) {
            self.unpacks.last_mut().unwrap().targets.push(target);
            self.finish_unpacks();
        } else {
            self.emit(Stmt::Assign(target, value));
        }
    }

    /// Pops every unpack whose targets are all filled. A completed nested unpack
    /// becomes a tuple target of the enclosing unpack; the outermost one (which has
    /// a right-hand side) is emitted as the assignment.
    fn finish_unpacks(&mut self) {
        while let Some(top) = self.unpacks.last() {
            if top.targets.len() != top.arity {
                break;
            }
            let done = self.unpacks.pop().unwrap();
            let tuple = LValue::Tuple(done.targets);
            match (self.unpacks.last_mut(), done.rhs) {
                (Some(parent), _) => parent.targets.push(tuple),
                (None, Some(rhs)) => self.emit(Stmt::Assign(tuple, rhs)),
                // A top-level unpack always has a right-hand side; this is unreachable.
                (None, None) => {}
            }
        }
    }

    fn pop_n(&mut self, n: usize) -> Result<Vec<ValueId>, IrError> {
        if self.stack.len() < n {
            return Err(IrError::StackUnderflow);
        }
        Ok(self.stack.split_off(self.stack.len() - n))
    }

    fn emit(&mut self, stmt: Stmt) {
        self.stmts.push(stmt);
    }

    /// Builds a call expression. The operand byte encodes positional and keyword
    /// counts; `has_star`/`has_kwstar` add `*args`/`**kwargs`. Popped top to
    /// bottom: `**kwargs`, `*args`, keyword `(key, value)` pairs, positionals,
    /// then the callee.
    fn call(&mut self, raw: u16, has_star: bool, has_kwstar: bool) -> Result<(), IrError> {
        let positional = (raw & 0xff) as usize;
        let keyword = (raw >> 8) as usize;
        let kwstar = if has_kwstar { Some(self.pop()?) } else { None };
        let star = if has_star { Some(self.pop()?) } else { None };
        let mut kwargs = Vec::with_capacity(keyword);
        for _ in 0..keyword {
            let value = self.pop()?;
            let key = self.pop()?;
            kwargs.push((key, value));
        }
        kwargs.reverse();
        let args = self.pop_n(positional)?;
        let func = self.pop()?;
        self.push(Expr::Call {
            func,
            args,
            kwargs,
            star,
            kwstar,
        });
        Ok(())
    }

    /// Clears the symbolic stack before lowering a new basic block. The arena and
    /// accumulated statements are retained across blocks of the same function.
    pub fn start_block(&mut self) {
        self.stack.clear();
        self.unpacks.clear();
        self.shortcircuit.clear();
        self.ternary.clear();
        self.from_import = None;
        self.print_values.clear();
        self.print_to = None;
    }

    /// Pops a value left on the stack, e.g. a branch condition or return value.
    pub fn pop_value(&mut self) -> Result<ValueId, IrError> {
        self.pop()
    }

    /// Removes and returns the statements lowered so far.
    pub fn take_stmts(&mut self) -> Vec<Stmt> {
        std::mem::take(&mut self.stmts)
    }

    /// Returns the values currently left on the symbolic stack.
    pub fn stack_snapshot(&self) -> Vec<ValueId> {
        self.stack.clone()
    }

    /// Consumes the machine, yielding just the expression arena.
    pub fn into_arena(self) -> ExprArena {
        self.arena
    }

    /// Consumes the machine, yielding the arena and the statement list.
    pub fn finish(self) -> (ExprArena, Vec<Stmt>) {
        (self.arena, self.stmts)
    }

    /// Folds an inline list comprehension region into a single [`Expr::ListComp`].
    /// `region` runs from the `BUILD_LIST 0` accumulator through the outer loop's
    /// back edge. Each `for` clause is `<iter>; GET_ITER; FOR_ITER exit; <target>`;
    /// filters are `<cond>; POP_JUMP_IF_FALSE/TRUE loop_top` (jumping back to the loop
    /// they filter); the element precedes `LIST_APPEND`. Multiple `for` clauses nest,
    /// each pushing its loop top so a filter can target any enclosing loop. Only this
    /// shape with straight-line sub-expressions is accepted; anything else returns an
    /// error so the function is rejected rather than mis-recovered.
    pub fn parse_list_comp(&mut self, region: &[&OffsetInstr]) -> Result<(), IrError> {
        let mnemonic = |i: usize| region.get(i).map(|item| item.instr.opcode.mnemonic());
        if mnemonic(0) != Some(Mnemonic::BUILD_LIST) {
            return Err(IrError::Unsupported(Mnemonic::BUILD_LIST));
        }
        let mut clauses: Vec<ListClause> = Vec::new();
        let mut loop_tops: Vec<Offset> = Vec::new();
        let mut i = 1;
        // A comprehension used as a ternary then-arm enters with the enclosing
        // ternary's cond already pending; the element may add its own ternary/short-
        // circuit (`[x if c else y for ..]`, `[a or b for ..]`), which must fully
        // resolve before the LIST_APPEND. Snapshot the pending state at entry so the
        // append-time check rejects only an element that left a NEW pending operator.
        let entry_ternary = self.ternary.len();
        let entry_shortcircuits = self.shortcircuit.len();
        let element = loop {
            let item = region.get(i).ok_or(IrError::Decode)?;
            // Resolve an element ternary or short-circuit whose merge is here. Comp-
            // interior offsets never coincide with an enclosing ternary's merge (which
            // lies past the region), so this leaves any entry-pending operator alone.
            self.resolve_pending(item.offset)?;
            match item.instr.opcode.mnemonic() {
                // A `for` clause: the iterable is on the stack (GET_ITER was a no-op),
                // and the target (a single store, or an UNPACK_SEQUENCE whose elements are
                // themselves targets -- so nested tuples `a, (b, c)` recurse) follows
                // FOR_ITER.
                Mnemonic::FOR_ITER => {
                    let loop_top = item.offset;
                    let iter = self.pop()?;
                    i += 1;
                    let target = comp_target_at(region, &mut i)?;
                    clauses.push(ListClause::For { target, iter });
                    loop_tops.push(loop_top);
                    // A boolean filter `if a or b` guarding this loop short-circuits to
                    // either the loop top (skip) or the element (keep). Reconstruct it
                    // as one If clause when it contains such a forward keep jump; a
                    // pure-`and` filter (only loop-top jumps) is left to the per-jump
                    // path below so already-recovered comprehensions stay byte-identical.
                    while let Some((cond, keep_idx)) =
                        self.reconstruct_comp_filter(region, i, loop_top)?
                    {
                        clauses.push(ListClause::If(cond));
                        i = keep_idx;
                    }
                }
                // A filter jumps back to the loop it guards when the element is to be
                // skipped. POP_JUMP_IF_FALSE keeps the element when the value is true
                // (`if cond`); POP_JUMP_IF_TRUE skips when true, so the kept condition
                // is the negation (`if not cond`). A jump to anything but an enclosing
                // loop top is instead a branch inside the element (a ternary's cond),
                // folded through the shared ternary machinery (see LIST_APPEND).
                Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE => {
                    let dest = Offset(item.instr.arg.ok_or(IrError::MissingOperand)? as u32);
                    if loop_tops.contains(&dest) {
                        let cond = self.pop()?;
                        let cond = if item.instr.opcode.mnemonic() == Mnemonic::POP_JUMP_IF_TRUE
                        {
                            self.arena.alloc(Expr::Unary(UnaryOp::Not, cond))
                        } else {
                            cond
                        };
                        clauses.push(ListClause::If(cond));
                    } else {
                        self.step(&item.instr, item.offset)?;
                    }
                    i += 1;
                }
                // Control flow internal to the element expression: a ternary then-arm
                // exit (`JUMP_FORWARD`) or a short-circuit operand (`JUMP_IF_*_OR_POP`),
                // both recorded by `step` and completed by `resolve_pending` at the
                // merge -- the same folding the block path uses outside comprehensions.
                Mnemonic::JUMP_FORWARD
                | Mnemonic::JUMP_IF_FALSE_OR_POP
                | Mnemonic::JUMP_IF_TRUE_OR_POP => {
                    self.step(&item.instr, item.offset)?;
                    i += 1;
                }
                // A nested element comprehension (`[[..] for ..]`): the element is
                // itself a list comp, brought inline as its own `BUILD_LIST 0 .. back
                // edge`. Fold that sub-region recursively into one Expr::ListComp value
                // and skip past it; the enclosing LIST_APPEND below takes it as the
                // element. Only fires for the empty-accumulator build of a recognised
                // inner comp -- a plain list literal `[]` element keeps the old path.
                Mnemonic::BUILD_LIST
                    if item.instr.arg == Some(0)
                        && nested_comp_end(region, i).is_some() =>
                {
                    let end = nested_comp_end(region, i).ok_or(IrError::Decode)?;
                    let sub: Vec<&OffsetInstr> = region[i..end].to_vec();
                    self.parse_list_comp(&sub)?;
                    i = end;
                }
                // LIST_APPEND leaves the element on top of the stack. Any element
                // ternary/short-circuit must have resolved by now (the entry-pending
                // operator of a ternary then-arm comp aside); a leftover one is a shape
                // this folder cannot reconstruct, so reject rather than mis-emit.
                Mnemonic::LIST_APPEND => {
                    if self.ternary.len() != entry_ternary
                        || self.shortcircuit.len() != entry_shortcircuits
                    {
                        return Err(IrError::Unsupported(Mnemonic::LIST_APPEND));
                    }
                    break self.pop()?;
                }
                _ => {
                    reject_comp_control(item)?;
                    self.step(&item.instr, item.offset)?;
                    i += 1;
                }
            }
        };
        self.push(Expr::ListComp { element, clauses });
        Ok(())
    }

    /// Reconstructs a boolean filter `if <expr>` beginning at `region[start]` that
    /// guards the loop whose `FOR_ITER` is at `loop_top`. Such a filter is a chain of
    /// `POP_JUMP` short-circuits whose every exit reaches the loop top (skip, condition
    /// false) or the keep point where the element begins (keep, condition true) -- so
    /// the loop top is the boolean's `False` terminal and the keep point its `True`
    /// terminal, and each short-circuit translates to `and`/`or`/`not` accordingly.
    ///
    /// Returns `Ok(None)` when no such filter starts here: either no jump targets the
    /// loop top (it is the element, not a filter), or the filter has no forward keep
    /// jump (a pure-`and` filter, left to the per-jump path so its `If` clauses stay
    /// byte-identical). A detected filter that does not reconstruct and verify returns
    /// `Err`, rejecting the whole comprehension rather than mis-emitting it. On success
    /// returns the condition value and the region index of the keep point.
    fn reconstruct_comp_filter(
        &mut self,
        region: &[&OffsetInstr],
        start: usize,
        loop_top: Offset,
    ) -> Result<Option<(ValueId, usize)>, IrError> {
        let index: HashMap<Offset, usize> =
            region.iter().enumerate().map(|(k, it)| (it.offset, k)).collect();
        // The filter ends at the next FOR_ITER or LIST_APPEND (the element or an inner
        // loop). Within that, a jump to the loop top marks a filter; the last such jump
        // fixes the keep point at the instruction after it.
        let mut bound = region.len();
        for k in start..region.len() {
            let m = region[k].instr.opcode.mnemonic();
            if matches!(m, Mnemonic::FOR_ITER | Mnemonic::LIST_APPEND) {
                bound = k;
                break;
            }
        }
        // The last jump to the loop top is the filter's final skip; the instruction
        // after it is the keep point where the element begins.
        let mut last_skip = None;
        for k in start..bound {
            let m = region[k].instr.opcode.mnemonic();
            if !matches!(m, Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE) {
                continue;
            }
            let target = Offset(region[k].instr.arg.ok_or(IrError::MissingOperand)? as u32);
            if target == loop_top {
                last_skip = Some(k);
            }
        }
        let Some(last_skip) = last_skip else { return Ok(None) };
        let keep_idx = last_skip + 1;
        if keep_idx > bound {
            return Ok(None);
        }
        let keep_point = region.get(keep_idx).ok_or(IrError::Decode)?.offset;
        let start_off = region[start].offset;

        // A forward keep jump (`or`) must lie inside the FILTER region [start, keep);
        // a forward jump in the element that follows (a ternary element's cond) is not
        // a filter `or`. Without a keep jump this is a pure-`and` filter, left to the
        // per-jump path so its `If` clauses stay byte-identical.
        let mut has_forward_keep = false;
        for k in start..keep_idx {
            let m = region[k].instr.opcode.mnemonic();
            if !matches!(m, Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE) {
                continue;
            }
            let target = Offset(region[k].instr.arg.ok_or(IrError::MissingOperand)? as u32);
            if target != loop_top && target.0 > region[k].offset.0 {
                has_forward_keep = true;
            }
        }
        if !has_forward_keep {
            return Ok(None);
        }

        // Only a pure short-circuit filter -- value ops and `POP_JUMP`s -- is folded
        // here. A `JUMP_FORWARD` or `JUMP_IF_*_OR_POP` inside the region means the
        // condition is a ternary/short-circuit VALUE tested by a single trailing
        // `POP_JUMP` (e.g. `if (a in c if c else a)`); the per-jump path already folds
        // that value, so decline and leave it alone rather than mis-handle the merge.
        for k in start..keep_idx {
            if matches!(
                region[k].instr.opcode.mnemonic(),
                Mnemonic::JUMP_FORWARD
                    | Mnemonic::JUMP_ABSOLUTE
                    | Mnemonic::JUMP_IF_FALSE_OR_POP
                    | Mnemonic::JUMP_IF_TRUE_OR_POP
            ) {
                return Ok(None);
            }
        }

        // Lower each leaf (a value-op run ending in a POP_JUMP) once, keyed by start
        // offset. Leaf starts: the region start, plus the fall-through and any forward
        // (non-loop-top) target of each short-circuit jump that lands inside the filter.
        let mut leaf_starts: Vec<Offset> = vec![start_off];
        for k in start..keep_idx {
            let m = region[k].instr.opcode.mnemonic();
            if !matches!(m, Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE) {
                continue;
            }
            let target = Offset(region[k].instr.arg.ok_or(IrError::MissingOperand)? as u32);
            let after = region.get(k + 1).ok_or(IrError::Decode)?.offset;
            for cand in [target, after] {
                if cand != loop_top && cand != keep_point && index.contains_key(&cand) {
                    let ci = index[&cand];
                    if ci >= start && ci < keep_idx {
                        leaf_starts.push(cand);
                    }
                }
            }
        }
        leaf_starts.sort();
        leaf_starts.dedup();

        let mut leaves: HashMap<Offset, FilterLeaf> = HashMap::new();
        let mut leaf_index: HashMap<ValueId, usize> = HashMap::new();
        let mut leaf_order: Vec<ValueId> = Vec::new();
        for &leaf_start in &leaf_starts {
            let mut j = index[&leaf_start];
            self.start_block();
            loop {
                let m = region.get(j).ok_or(IrError::Decode)?.instr.opcode.mnemonic();
                if matches!(m, Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE) {
                    break;
                }
                // A filter predicate is straight-line value ops; any other control
                // flow is a shape this folder does not model.
                if is_control_flow(m) {
                    return Err(IrError::Unsupported(m));
                }
                self.step(&region[j].instr, region[j].offset)?;
                j += 1;
            }
            let value = self.pop()?;
            if !self.stack_is_empty() {
                return Err(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE));
            }
            leaf_index.entry(value).or_insert_with(|| {
                leaf_order.push(value);
                leaf_order.len() - 1
            });
            let kind = region[j].instr.opcode.mnemonic();
            let target = Offset(region[j].instr.arg.ok_or(IrError::MissingOperand)? as u32);
            let after = region.get(j + 1).ok_or(IrError::Decode)?.offset;
            leaves.insert(leaf_start, FilterLeaf { value, kind, target, after });
        }

        // Translate the short-circuit graph to one boolean expression, then verify it
        // against the original control flow by truth-table equivalence.
        let mut structure: HashSet<ValueId> = HashSet::new();
        let mut memo: HashMap<Offset, FilterVal> = HashMap::new();
        let built = self.filter_eval(
            start_off,
            keep_point,
            loop_top,
            &leaves,
            &mut memo,
            &mut structure,
        )?;
        let FilterVal::Val(value) = built else {
            // A filter that collapses to a constant is not a real condition.
            return Err(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE));
        };

        let k = leaf_order.len();
        if k > 16 {
            return Err(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE));
        }
        for bits in 0..(1u32 << k) {
            let assign: Vec<bool> = (0..k).map(|b| (bits >> b) & 1 == 1).collect();
            let cfg = filter_cfg_sim(start_off, keep_point, loop_top, &leaves, &leaf_index, &assign)
                .ok_or(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE))?;
            let exp = self
                .filter_expr_eval(value, &leaf_index, &structure, &assign)
                .ok_or(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE))?;
            if cfg != exp {
                return Err(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE));
            }
        }
        Ok(Some((value, keep_idx)))
    }

    /// Recursive translation of a comprehension filter rooted at `start` (see
    /// [`Self::reconstruct_comp_filter`]). The keep point is the `True` terminal and
    /// the loop top the `False` terminal.
    fn filter_eval(
        &mut self,
        start: Offset,
        keep_point: Offset,
        loop_top: Offset,
        leaves: &HashMap<Offset, FilterLeaf>,
        memo: &mut HashMap<Offset, FilterVal>,
        structure: &mut HashSet<ValueId>,
    ) -> Result<FilterVal, IrError> {
        if start == keep_point {
            return Ok(FilterVal::True);
        }
        if start == loop_top {
            return Ok(FilterVal::False);
        }
        if let Some(v) = memo.get(&start) {
            return Ok(*v);
        }
        let leaf = leaves.get(&start).ok_or(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE))?;
        let cond = leaf.value;
        let (target, after) = (leaf.target, leaf.after);
        // POP_JUMP_IF_TRUE: cond true takes the target, false falls through; for
        // POP_JUMP_IF_FALSE the two are swapped.
        let (when_true, when_false) = match leaf.kind {
            Mnemonic::POP_JUMP_IF_TRUE => (target, after),
            Mnemonic::POP_JUMP_IF_FALSE => (after, target),
            other => return Err(IrError::Unsupported(other)),
        };
        let then = self.filter_eval(when_true, keep_point, loop_top, leaves, memo, structure)?;
        let otherwise =
            self.filter_eval(when_false, keep_point, loop_top, leaves, memo, structure)?;
        let value = self.build_filter_cond(cond, then, otherwise, structure);
        memo.insert(start, value);
        Ok(value)
    }

    /// Builds `cond ? then : otherwise` for a filter, folding the `True`/`False`
    /// control terminals into `and`/`or`/`not` so the result is idiomatic boolean
    /// source rather than a ternary over constants.
    fn build_filter_cond(
        &mut self,
        cond: ValueId,
        then: FilterVal,
        otherwise: FilterVal,
        structure: &mut HashSet<ValueId>,
    ) -> FilterVal {
        let not = |s: &mut Self, structure: &mut HashSet<ValueId>, v: ValueId| {
            let n = s.arena.alloc(Expr::Unary(UnaryOp::Not, v));
            structure.insert(n);
            n
        };
        match (then, otherwise) {
            (FilterVal::True, FilterVal::True) => FilterVal::True,
            (FilterVal::False, FilterVal::False) => FilterVal::False,
            // cond ? True : False == cond; cond ? False : True == not cond.
            (FilterVal::True, FilterVal::False) => FilterVal::Val(cond),
            (FilterVal::False, FilterVal::True) => FilterVal::Val(not(self, structure, cond)),
            // cond ? True : x == cond or x; cond ? x : False == cond and x.
            (FilterVal::True, FilterVal::Val(x)) => {
                let r = self.combine_bool(BoolKind::Or, cond, x);
                structure.insert(r);
                FilterVal::Val(r)
            }
            (FilterVal::Val(x), FilterVal::False) => {
                let r = self.combine_bool(BoolKind::And, cond, x);
                structure.insert(r);
                FilterVal::Val(r)
            }
            // cond ? False : x == not cond and x; cond ? x : True == not cond or x.
            (FilterVal::False, FilterVal::Val(x)) => {
                let n = not(self, structure, cond);
                let r = self.combine_bool(BoolKind::And, n, x);
                structure.insert(r);
                FilterVal::Val(r)
            }
            (FilterVal::Val(x), FilterVal::True) => {
                let n = not(self, structure, cond);
                let r = self.combine_bool(BoolKind::Or, n, x);
                structure.insert(r);
                FilterVal::Val(r)
            }
            (FilterVal::Val(t), FilterVal::Val(e)) => {
                let id = self.arena.alloc(Expr::Ternary { cond, then: t, otherwise: e });
                structure.insert(id);
                FilterVal::Val(id)
            }
        }
    }

    /// Evaluates the reconstructed filter expression to a truth value under a leaf
    /// assignment, returning `(result, leaves evaluated in order)` for the truth-table
    /// gate. Structure nodes are the `and`/`or`/`not`/ternary built above; anything
    /// else is an opaque leaf condition.
    fn filter_expr_eval(
        &self,
        value: ValueId,
        leaf_index: &HashMap<ValueId, usize>,
        structure: &HashSet<ValueId>,
        assign: &[bool],
    ) -> Option<(bool, Vec<usize>)> {
        if !structure.contains(&value) {
            let idx = *leaf_index.get(&value)?;
            return Some((assign[idx], vec![idx]));
        }
        match self.arena.get(value) {
            Expr::Unary(UnaryOp::Not, inner) => {
                let (b, order) = self.filter_expr_eval(*inner, leaf_index, structure, assign)?;
                Some((!b, order))
            }
            Expr::BoolOp(kind, ops) => {
                let mut order = Vec::new();
                let mut last = matches!(kind, BoolKind::And);
                for &op in ops {
                    let (b, o) = self.filter_expr_eval(op, leaf_index, structure, assign)?;
                    order.extend(o);
                    last = b;
                    let short = match kind {
                        BoolKind::Or => b,
                        BoolKind::And => !b,
                    };
                    if short {
                        return Some((b, order));
                    }
                }
                Some((last, order))
            }
            Expr::Ternary { cond, then, otherwise } => {
                let (bc, mut order) = self.filter_expr_eval(*cond, leaf_index, structure, assign)?;
                let branch = if bc { *then } else { *otherwise };
                let (b, rest) = self.filter_expr_eval(branch, leaf_index, structure, assign)?;
                order.extend(rest);
                Some((b, order))
            }
            _ => None,
        }
    }

    /// Recovers a function whose body is a leading run of straight-line statements
    /// followed by `return <boolean expression>`, where the returned boolean is built
    /// from cross-block short-circuit control flow (e.g. `x = f(); return x and
    /// x.copy() or {}`, or the whole-body `return (a or b) and not c`). The unstacker
    /// clears the stack at block boundaries, so such an expression -- split into blocks
    /// by its short-circuit jumps -- otherwise fails to fold.
    ///
    /// The leading statements (if any) are lowered normally onto `self`; the boolean
    /// return region is reconstructed and verified by [`Self::reconstruct_returned_bool`].
    /// Returns the recovered return value, or `None` when the body is not of this shape.
    pub fn recover_returned_bool(&mut self, instrs: &[OffsetInstr]) -> Option<ValueId> {
        let n = instrs.len();
        if n < 3 || instrs[n - 1].instr.opcode.mnemonic() != Mnemonic::RETURN_VALUE {
            return None;
        }
        // Locate the first short-circuit jump. Everything before the boolean region it
        // begins is a leading run of straight-line statements with no control flow of
        // its own; reject if that prefix contains any jump or block setup, which would
        // make straight-line lowering unsound.
        let first_jump = instrs[..n - 1]
            .iter()
            .position(|it| is_bool_jump(it.instr.opcode.mnemonic()))?;
        if instrs[..first_jump]
            .iter()
            .any(|it| is_control_flow(it.instr.opcode.mnemonic()))
        {
            return None;
        }
        // Find the cut between the leading statements and the boolean region: the last
        // point before `first_jump` where the symbolic stack is empty (a statement
        // boundary). The boolean region's first leaf is the value the first short-
        // circuit jump tests, which begins at that boundary.
        let cut = {
            let mut probe = Unstacker::new();
            let mut cut = 0usize;
            for k in 0..first_jump {
                if probe.stack_is_empty() {
                    cut = k;
                }
                probe.step(&instrs[k].instr, instrs[k].offset).ok()?;
            }
            cut
        };
        // Lower the leading statements onto `self`; the boolean region's leaves are
        // re-lowered from the cut by `reconstruct_returned_bool`.
        for k in 0..cut {
            self.step(&instrs[k].instr, instrs[k].offset).ok()?;
        }
        if !self.stack_is_empty() {
            return None;
        }
        self.reconstruct_returned_bool(&instrs[cut..])
    }

    /// Reconstructs the boolean expression of a `return <boolean expression>` region
    /// (the last instruction is the `RETURN_VALUE`), built from cross-block short-
    /// circuit control flow.
    ///
    /// Each short-circuit jump translates faithfully to a conditional expression:
    /// `POP_JUMP_IF_TRUE T` is `eval(T) if v else eval(continue)` (the value `v` is
    /// consumed; the result comes from whichever side runs), and `JUMP_IF_*_OR_POP`
    /// to the merge keeps `v` as `v or/and eval(continue)`. The translation is sound
    /// by construction, and is additionally checked against the original control flow
    /// by truth-table equivalence (same result operand and same evaluation order for
    /// every assignment of the leaf operands) -- a mismatch returns `None` so the
    /// function falls back to the existing graceful rejection rather than emit a
    /// wrong-but-compilable boolean. Returns the recovered value, or `None` when the
    /// region is not a pure returned boolean of this shape.
    fn reconstruct_returned_bool(&mut self, instrs: &[OffsetInstr]) -> Option<ValueId> {
        let n = instrs.len();
        if n < 3 || instrs[n - 1].instr.opcode.mnemonic() != Mnemonic::RETURN_VALUE {
            return None;
        }
        let merge = instrs[n - 1].offset;
        let index: HashMap<Offset, usize> =
            instrs.iter().enumerate().map(|(i, it)| (it.offset, i)).collect();
        // Every non-final instruction must be a value op or a forward short-circuit
        // jump; anything else (a store, a loop, an unconditional jump) is not a pure
        // returned boolean of this shape.
        let mut has_short = false;
        for (i, it) in instrs[..n - 1].iter().enumerate() {
            let m = it.instr.opcode.mnemonic();
            if is_bool_jump(m) {
                has_short = true;
                let ti = *index.get(&Offset(it.instr.arg? as u32))?;
                if ti <= i {
                    return None;
                }
            } else if super::cfg::is_statement_or_control(m) {
                return None;
            }
        }
        if !has_short {
            return None;
        }

        // Lower every leaf (a maximal run of value ops between jumps) once, keyed by
        // its start offset, recording the jump (or return) that ends it.
        let mut leaf_starts: Vec<Offset> = vec![instrs[0].offset];
        for it in &instrs[..n - 1] {
            if is_bool_jump(it.instr.opcode.mnemonic()) {
                let target = Offset(it.instr.arg? as u32);
                if target != merge {
                    leaf_starts.push(target);
                }
                let after = instrs[index[&it.offset] + 1].offset;
                if after != merge {
                    leaf_starts.push(after);
                }
            }
        }
        leaf_starts.sort();
        leaf_starts.dedup();
        let mut recs: HashMap<Offset, LeafRec> = HashMap::new();
        let mut leaf_index: HashMap<ValueId, usize> = HashMap::new();
        let mut leaf_order: Vec<ValueId> = Vec::new();
        for &start in &leaf_starts {
            let start_idx = *index.get(&start)?;
            self.start_block();
            let mut j = start_idx;
            loop {
                let m = instrs.get(j)?.instr.opcode.mnemonic();
                if is_bool_jump(m) || m == Mnemonic::RETURN_VALUE {
                    break;
                }
                self.step(&instrs[j].instr, instrs[j].offset).ok()?;
                j += 1;
            }
            let value = self.pop_value().ok()?;
            if !self.stack_is_empty() {
                return None; // the leaf left more than one value: not this shape
            }
            leaf_index.entry(value).or_insert_with(|| {
                leaf_order.push(value);
                leaf_order.len() - 1
            });
            let term = if instrs[j].instr.opcode.mnemonic() == Mnemonic::RETURN_VALUE {
                LeafTerm::Return
            } else {
                LeafTerm::Jump {
                    kind: instrs[j].instr.opcode.mnemonic(),
                    target: Offset(instrs[j].instr.arg? as u32),
                    after: instrs[j + 1].offset,
                }
            };
            recs.insert(start, LeafRec { value, term });
        }

        // Build the expression by recursive translation, memoised by leaf start.
        let mut memo: HashMap<Offset, ValueId> = HashMap::new();
        let mut structure: HashSet<ValueId> = HashSet::new();
        let value = self.eval_bool(instrs[0].offset, merge, &recs, &mut memo, &mut structure)?;

        // Verify the translation against the original control flow.
        let k = leaf_order.len();
        if k > 16 {
            return None; // 2^k enumeration would be too large; reject conservatively
        }
        for bits in 0..(1u32 << k) {
            let assign: Vec<bool> = (0..k).map(|b| (bits >> b) & 1 == 1).collect();
            let cfg = cfg_sim(instrs[0].offset, instrs.len(), &leaf_index, &recs, &assign)?;
            let exp = self.expr_sim(value, &leaf_index, &structure, &assign)?;
            if cfg != exp {
                return None;
            }
        }
        Some(value)
    }

    /// Fallback for a straight-line function (statements then a single trailing
    /// `return <expr>`) where an expression embeds a pure short-circuit boolean region
    /// -- a ternary/`and`/`or` mid-expression, e.g. `return fmt % (x[0], a or b if c
    /// else d)` -- that the block structurer splits at its `POP_JUMP` and cannot
    /// rejoin (the values below the region clear at the block boundary). Runs ONLY
    /// after the normal path fails, so it can only convert a failure to a success.
    /// Processes the stream linearly: statements and value ops fold normally, and each
    /// boolean region collapses to one value reconstructed by [`Self::eval_bool`] and
    /// verified by the same truth-table gate as [`Self::recover_returned_bool`].
    /// Returns the return value (leading statements pushed onto `self`), or None.
    pub fn recover_straightline_bools(&mut self, instrs: &[OffsetInstr]) -> Option<ValueId> {
        let n = instrs.len();
        if n < 2 || instrs[n - 1].instr.opcode.mnemonic() != Mnemonic::RETURN_VALUE {
            return None;
        }
        let index: HashMap<Offset, usize> =
            instrs.iter().enumerate().map(|(i, it)| (it.offset, i)).collect();
        // Restrict to straight-line code modulo forward short-circuit jumps. Loops,
        // exception/with setup, backward or unconditional jumps, and JUMP_FORWARD
        // ternaries all mean control flow the block path -- not this fallback -- owns
        // (eval_bool models only the POP_JUMP/OR_POP short-circuit forms, which carry
        // no JUMP_FORWARD). A RETURN_VALUE is allowed anywhere: a short-circuit boolean
        // that returns early from its branches (`return a and (b or c)` compiled with
        // each arm returning directly) has interior RETURNs, which fold_bool_region
        // treats as the region's result terminals.
        for (i, it) in instrs.iter().enumerate() {
            let m = it.instr.opcode.mnemonic();
            if m == Mnemonic::RETURN_VALUE {
                // a result terminal; allowed at any position
            } else if is_bool_jump(m) {
                if *index.get(&Offset(it.instr.arg? as u32))? <= i {
                    return None;
                }
            } else if is_control_flow(m) {
                return None;
            }
        }
        let mut i = 0;
        while i < n {
            let m = instrs[i].instr.opcode.mnemonic();
            if m == Mnemonic::RETURN_VALUE {
                break;
            }
            if is_bool_jump(m) {
                let (_value, next) = self.fold_bool_region(instrs, &index, i)?;
                i = next;
            } else {
                self.step(&instrs[i].instr, instrs[i].offset).ok()?;
                i += 1;
            }
        }
        let value = self.pop_value().ok()?;
        if !self.stack_is_empty() {
            return None;
        }
        Some(value)
    }

    /// Folds the boolean region whose first short-circuit jump is `instrs[jump_idx]`
    /// (its tested value already on top of the stack) into one value, pushing the
    /// result and returning `(value, region-end index)`. The region runs to the merge
    /// where all its short-circuit paths converge; values below it on the stack are
    /// preserved. Verified by the truth-table gate; None on any mismatch or unsupported
    /// shape. See [`Self::recover_straightline_bools`].
    pub(crate) fn fold_bool_region(
        &mut self,
        instrs: &[OffsetInstr],
        index: &HashMap<Offset, usize>,
        jump_idx: usize,
    ) -> Option<(ValueId, usize)> {
        let first_value = self.pop_value().ok()?;
        let base_len = self.stack.len();
        let j1 = &instrs[jump_idx];
        let j1_off = j1.offset;
        // The merge is where the region's short-circuit paths converge: scan forward
        // tracking the furthest short-circuit target; the region ends when the cursor
        // reaches it. Only value ops may sit between the jumps.
        let mut max_target = 0u32;
        let mut k = jump_idx;
        let m_idx = loop {
            let it = instrs.get(k)?;
            if k > jump_idx && it.offset.0 == max_target {
                break k;
            }
            let m = it.instr.opcode.mnemonic();
            if is_bool_jump(m) {
                let t = Offset(it.instr.arg? as u32);
                if t.0 <= it.offset.0 {
                    return None;
                }
                max_target = max_target.max(t.0);
            } else if m == Mnemonic::RETURN_VALUE {
                // An early-return exit from a short-circuit branch; a result terminal
                // inside the region, not a disqualifying control transfer.
            } else if is_control_flow(m) {
                return None;
            }
            k += 1;
        };
        let merge = instrs[m_idx].offset;

        // Lower every leaf (a value-op run between short-circuit jumps) once, keyed by
        // start offset. The first leaf's value is the one already popped; the rest are
        // lowered by stepping from their start, each leaving the stack at `base_len`.
        let mut recs: HashMap<Offset, LeafRec> = HashMap::new();
        let mut leaf_index: HashMap<ValueId, usize> = HashMap::new();
        let mut leaf_order: Vec<ValueId> = Vec::new();
        let mut register = |value: ValueId,
                            leaf_index: &mut HashMap<ValueId, usize>,
                            leaf_order: &mut Vec<ValueId>| {
            leaf_index.entry(value).or_insert_with(|| {
                leaf_order.push(value);
                leaf_order.len() - 1
            });
        };
        let term_of = |k: usize| -> Option<LeafTerm> {
            let it = &instrs[k];
            Some(LeafTerm::Jump {
                kind: it.instr.opcode.mnemonic(),
                target: Offset(it.instr.arg? as u32),
                after: instrs.get(k + 1)?.offset,
            })
        };
        register(first_value, &mut leaf_index, &mut leaf_order);
        recs.insert(j1_off, LeafRec { value: first_value, term: term_of(jump_idx)? });

        let mut queue: Vec<Offset> = Vec::new();
        if let LeafTerm::Jump { target, after, .. } = recs[&j1_off].term {
            queue.push(target);
            queue.push(after);
        }
        while let Some(off) = queue.pop() {
            if off == merge || recs.contains_key(&off) {
                continue;
            }
            let mut j = *index.get(&off)?;
            loop {
                let it = instrs.get(j)?;
                let m = it.instr.opcode.mnemonic();
                // A leaf ends at the merge (its value is the region result) or at a
                // RETURN_VALUE (an early-return branch returns its value directly).
                if it.offset == merge || m == Mnemonic::RETURN_VALUE {
                    let value = self.pop_value().ok()?;
                    if self.stack.len() != base_len {
                        return None;
                    }
                    register(value, &mut leaf_index, &mut leaf_order);
                    recs.insert(off, LeafRec { value, term: LeafTerm::Return });
                    break;
                }
                if is_bool_jump(m) {
                    let value = self.pop_value().ok()?;
                    if self.stack.len() != base_len {
                        return None;
                    }
                    register(value, &mut leaf_index, &mut leaf_order);
                    let term = term_of(j)?;
                    if let LeafTerm::Jump { target, after, .. } = term {
                        queue.push(target);
                        queue.push(after);
                    }
                    recs.insert(off, LeafRec { value, term });
                    break;
                }
                if is_control_flow(m) {
                    return None;
                }
                self.step(&it.instr, it.offset).ok()?;
                j += 1;
            }
        }

        let mut memo: HashMap<Offset, ValueId> = HashMap::new();
        let mut structure: HashSet<ValueId> = HashSet::new();
        let value = self.eval_bool(j1_off, merge, &recs, &mut memo, &mut structure)?;

        let k = leaf_order.len();
        if k > 16 {
            return None;
        }
        for bits in 0..(1u32 << k) {
            let assign: Vec<bool> = (0..k).map(|b| (bits >> b) & 1 == 1).collect();
            let cfg = cfg_sim(j1_off, recs.len(), &leaf_index, &recs, &assign)?;
            let exp = self.expr_sim(value, &leaf_index, &structure, &assign)?;
            if cfg != exp {
                return None;
            }
        }
        self.stack.push(value);
        Some((value, m_idx))
    }

    /// Recursive translation of the boolean region rooted at the leaf starting at
    /// `start` (see [`Self::recover_returned_bool`]).
    fn eval_bool(
        &mut self,
        start: Offset,
        merge: Offset,
        recs: &HashMap<Offset, LeafRec>,
        memo: &mut HashMap<Offset, ValueId>,
        structure: &mut HashSet<ValueId>,
    ) -> Option<ValueId> {
        if let Some(&v) = memo.get(&start) {
            return Some(v);
        }
        let rec = recs.get(&start)?;
        let value = match rec.term {
            LeafTerm::Return => rec.value,
            LeafTerm::Jump { kind, target, after } => {
                let cond = rec.value;
                match kind {
                    Mnemonic::POP_JUMP_IF_TRUE | Mnemonic::POP_JUMP_IF_FALSE => {
                        let t = self.eval_bool(target, merge, recs, memo, structure)?;
                        let e = self.eval_bool(after, merge, recs, memo, structure)?;
                        let (then, otherwise) = if kind == Mnemonic::POP_JUMP_IF_TRUE {
                            (t, e)
                        } else {
                            (e, t)
                        };
                        let id = self.arena.alloc(Expr::Ternary { cond, then, otherwise });
                        structure.insert(id);
                        id
                    }
                    Mnemonic::JUMP_IF_TRUE_OR_POP | Mnemonic::JUMP_IF_FALSE_OR_POP => {
                        if target != merge {
                            return None; // a kept short-circuit to a non-merge target
                        }
                        let rest = self.eval_bool(after, merge, recs, memo, structure)?;
                        let bk = if kind == Mnemonic::JUMP_IF_TRUE_OR_POP {
                            BoolKind::Or
                        } else {
                            BoolKind::And
                        };
                        let id = self.combine_bool(bk, cond, rest);
                        structure.insert(id);
                        id
                    }
                    _ => return None,
                }
            }
        };
        memo.insert(start, value);
        Some(value)
    }

    /// Evaluates the reconstructed expression under a leaf-truthiness assignment,
    /// returning `(result leaf index, leaves evaluated in order)`. Used by the
    /// truth-table verification gate. A `BoolOp`/`Ternary` is a structure node built
    /// by [`Self::eval_bool`]; anything else is an opaque leaf operand.
    fn expr_sim(
        &self,
        value: ValueId,
        leaf_index: &HashMap<ValueId, usize>,
        structure: &HashSet<ValueId>,
        assign: &[bool],
    ) -> Option<(usize, Vec<usize>)> {
        if !structure.contains(&value) {
            let idx = *leaf_index.get(&value)?;
            return Some((idx, vec![idx]));
        }
        match self.arena.get(value) {
            Expr::Ternary { cond, then, otherwise } => {
                let (rc, mut order) = self.expr_sim(*cond, leaf_index, structure, assign)?;
                let next = if assign[rc] { *then } else { *otherwise };
                let (rn, rest) = self.expr_sim(next, leaf_index, structure, assign)?;
                order.extend(rest);
                Some((rn, order))
            }
            Expr::BoolOp(kind, ops) => {
                let mut order = Vec::new();
                let mut last = 0;
                for &op in ops {
                    let (r, o) = self.expr_sim(op, leaf_index, structure, assign)?;
                    order.extend(o);
                    last = r;
                    let short = match kind {
                        BoolKind::Or => assign[r],
                        BoolKind::And => !assign[r],
                    };
                    if short {
                        return Some((r, order));
                    }
                }
                Some((last, order))
            }
            _ => None,
        }
    }

    /// Folds one instruction into the symbolic state. `offset` is the instruction's
    /// byte offset, needed to resolve a relative `JUMP_FORWARD` target.
    pub fn step(&mut self, instr: &Instruction<Standard>, offset: Offset) -> Result<(), IrError> {
        let arg = instr.arg;
        let mnemonic = instr.opcode.mnemonic();

        // A `print a, b` accumulates its operands across PRINT_ITEMs; anything other
        // than another print op (or its terminating PRINT_NEWLINE) ends a trailing-
        // comma `print a,`, so flush the pending statement first.
        if !self.print_values.is_empty()
            && !matches!(mnemonic, Mnemonic::PRINT_ITEM | Mnemonic::PRINT_NEWLINE)
        {
            self.flush_print();
        }

        if let Some(op) = inplace_op(mnemonic) {
            let rhs = self.pop()?;
            let lhs = self.pop()?;
            self.push(Expr::Inplace(op, lhs, rhs));
            return Ok(());
        }
        if let Some(op) = binary_op(mnemonic) {
            let rhs = self.pop()?;
            let lhs = self.pop()?;
            self.push(Expr::BinOp(op, lhs, rhs));
            return Ok(());
        }
        if let Some(op) = unary_op(mnemonic) {
            let operand = self.pop()?;
            self.push(Expr::Unary(op, operand));
            return Ok(());
        }

        match mnemonic {
            // SETUP_LOOP / POP_BLOCK manage the runtime block stack; they have no
            // effect on the recovered statement stream. GET_ITER is a no-op for
            // source purposes: the operand it would wrap is the value the `for`
            // loop iterates, so it is left on the stack as-is.
            Mnemonic::NOP | Mnemonic::SETUP_LOOP | Mnemonic::POP_BLOCK | Mnemonic::GET_ITER => {}
            Mnemonic::LOAD_CONST => self.push(Expr::Const(ConstId(arg_u16(arg)?))),
            Mnemonic::LOAD_FAST => self.push(Expr::Local(VarId(arg_u16(arg)?))),
            Mnemonic::LOAD_DEREF => self.push(Expr::Deref(DerefId(arg_u16(arg)?))),
            Mnemonic::LOAD_GLOBAL => self.push(Expr::Global(NameId(arg_u16(arg)?))),
            Mnemonic::LOAD_NAME => self.push(Expr::Name(NameId(arg_u16(arg)?))),
            Mnemonic::LOAD_ATTR => {
                let obj = self.pop()?;
                self.push(Expr::Attr(obj, NameId(arg_u16(arg)?)));
            }
            Mnemonic::BINARY_SUBSC => {
                let key = self.pop()?;
                let container = self.pop()?;
                self.push(Expr::Subscript(container, key));
            }
            Mnemonic::COMPARE_OP => {
                let op = CmpOp::from_arg(arg_u16(arg)?).ok_or(IrError::BadOperand)?;
                let rhs = self.pop()?;
                let lhs = self.pop()?;
                self.push(Expr::Compare(op, lhs, rhs));
            }
            Mnemonic::CALL_FUNCTION => self.call(arg_u16(arg)?, false, false)?,
            Mnemonic::CALL_FUNCTION_VAR => self.call(arg_u16(arg)?, true, false)?,
            Mnemonic::CALL_FUNCTION_KW => self.call(arg_u16(arg)?, false, true)?,
            Mnemonic::CALL_FUNCTION_VAR_KW => self.call(arg_u16(arg)?, true, true)?,
            Mnemonic::BUILD_TUPLE => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::Tuple(items));
            }
            Mnemonic::BUILD_LIST => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::List(items));
            }
            // In a comprehension the leading empty BUILD is the accumulator: it is
            // returned at the end but never referenced as a value, so it is folded
            // away rather than pushed.
            Mnemonic::BUILD_SET if self.comp && !self.comp_acc_seen => {
                self.comp_acc_seen = true;
            }
            Mnemonic::BUILD_MAP if self.comp && !self.comp_acc_seen => {
                self.comp_acc_seen = true;
            }
            Mnemonic::BUILD_SET => {
                let items = self.pop_n(arg_u16(arg)? as usize)?;
                self.push(Expr::Set(items));
            }
            // BUILD_MAP makes an empty dict; the STORE_MAPs that follow grow it in
            // place while it stays on the stack.
            Mnemonic::BUILD_MAP => self.push(Expr::Dict(Vec::new())),
            // The accumulator pushes of a set/dict comprehension. The element is
            // recorded for the comprehension folder; the accumulator is implicit.
            Mnemonic::SET_ADD if self.comp => {
                let element = self.pop()?;
                self.emit(Stmt::SetAdd(element));
            }
            Mnemonic::MAP_ADD if self.comp => {
                let key = self.pop()?;
                let value = self.pop()?;
                self.emit(Stmt::DictAdd { key, value });
            }
            Mnemonic::STORE_MAP => {
                let key = self.pop()?;
                let value = self.pop()?;
                let dict = *self.stack.last().ok_or(IrError::StackUnderflow)?;
                match self.arena.get(dict) {
                    Expr::Dict(pairs) => {
                        let mut pairs = pairs.clone();
                        pairs.push((key, value));
                        self.arena.set(dict, Expr::Dict(pairs));
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                }
            }
            Mnemonic::DUP_TOP => {
                let top = *self.stack.last().ok_or(IrError::StackUnderflow)?;
                self.stack.push(top);
            }
            Mnemonic::DUP_TOPX => {
                let n = arg_u16(arg)? as usize;
                if self.stack.len() < n {
                    return Err(IrError::StackUnderflow);
                }
                let dup = self.stack[self.stack.len() - n..].to_vec();
                self.stack.extend(dup);
            }
            // ROT_TWO reaches the unstacker as an augmented assignment (the rotated
            // top is the INPLACE result) or as a two-element parallel assignment
            // (`t1, t2 = v1, v2`, which the compiler emits as `LOAD v1; LOAD v2;
            // ROT_TWO; STORE t1; STORE t2` rather than build/unpack a 2-tuple). A
            // chained comparison's `ROT_TWO; POP_TOP` cleanup never reaches here -- it
            // is excluded by find_chained_comparisons.
            Mnemonic::ROT_TWO => {
                let len = self.stack.len();
                if len < 2 {
                    return Err(IrError::Unsupported(mnemonic));
                }
                if self.tos_is_unpack_slot() {
                    // The second rotation of a three-element parallel assignment that
                    // ROT_THREE already set up; the slots are interchangeable.
                } else if self.tos_is_inplace() {
                    self.stack.swap(len - 1, len - 2);
                } else if len >= 3 && self.stack[len - 2] == self.stack[len - 3] {
                    // The `print >>f, x` dance: DUP_TOP left two copies of the stream
                    // below the value (`[stream, stream, value]`). Swap so the
                    // following PRINT_ITEM_TO pops the stream then the value, leaving
                    // the base stream for the next item or the terminating flush.
                    self.stack.swap(len - 1, len - 2);
                } else {
                    // The two values are on the stack; the rotation reverses them so
                    // the following stores take them in source order. Recover the
                    // parallel assignment as a single tuple assignment (never split
                    // into two stores, which would mis-order an aliasing swap).
                    let second = self.pop()?;
                    let first = self.pop()?;
                    let rhs = self.arena.alloc(Expr::Tuple(vec![first, second]));
                    self.unpacks.push(PendingUnpack { rhs: Some(rhs), arity: 2, targets: Vec::new() });
                    self.push(Expr::UnpackSlot);
                    self.push(Expr::UnpackSlot);
                }
            }
            Mnemonic::ROT_THREE => {
                let len = self.stack.len();
                if len < 3 {
                    return Err(IrError::Unsupported(mnemonic));
                }
                if self.tos_is_inplace() || self.tos_equals_below() {
                    // Augmented assignment to a subscript, or a chained comparison's
                    // DUP_TOP'd middle operand.
                    let top = self.stack.remove(len - 1);
                    self.stack.insert(len - 3, top);
                } else {
                    // Three-element parallel assignment `t1, t2, t3 = v1, v2, v3`
                    // (ROT_THREE then ROT_TWO reverse the values so the stores take
                    // them in order). Recover it as one tuple assignment.
                    let third = self.pop()?;
                    let second = self.pop()?;
                    let first = self.pop()?;
                    let rhs = self.arena.alloc(Expr::Tuple(vec![first, second, third]));
                    self.unpacks.push(PendingUnpack { rhs: Some(rhs), arity: 3, targets: Vec::new() });
                    self.push(Expr::UnpackSlot);
                    self.push(Expr::UnpackSlot);
                    self.push(Expr::UnpackSlot);
                }
            }
            Mnemonic::STORE_FAST => {
                let value = self.pop()?;
                self.complete_store(LValue::Local(VarId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_DEREF => {
                let value = self.pop()?;
                self.complete_store(LValue::Deref(DerefId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_NAME => {
                let value = self.pop()?;
                self.complete_store(LValue::Name(NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_GLOBAL => {
                let value = self.pop()?;
                self.complete_store(LValue::Global(NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_ATTR => {
                let obj = self.pop()?;
                let value = self.pop()?;
                self.complete_store(LValue::Attr(obj, NameId(arg_u16(arg)?)), value);
            }
            Mnemonic::STORE_SUBSCR => {
                let key = self.pop()?;
                let container = self.pop()?;
                let value = self.pop()?;
                self.complete_store(LValue::Subscript(container, key), value);
            }
            // The two-bound slice opcodes: read (`x[a:b]`), store, and delete. The
            // bounds are popped top-first (upper before lower), the object below
            // them, and for stores the value below that.
            Mnemonic::SLICE_0 | Mnemonic::SLICE_1 | Mnemonic::SLICE_2 | Mnemonic::SLICE_3 => {
                let (lower, upper) = self.pop_slice_bounds(mnemonic)?;
                let container = self.pop()?;
                let slice = self.arena.alloc(Expr::Slice { lower, upper, step: None });
                self.push(Expr::Subscript(container, slice));
            }
            Mnemonic::STORE_SLICE_0
            | Mnemonic::STORE_SLICE_1
            | Mnemonic::STORE_SLICE_2
            | Mnemonic::STORE_SLICE_3 => {
                let (lower, upper) = self.pop_slice_bounds(mnemonic)?;
                let container = self.pop()?;
                let value = self.pop()?;
                let slice = self.arena.alloc(Expr::Slice { lower, upper, step: None });
                self.complete_store(LValue::Subscript(container, slice), value);
            }
            Mnemonic::DELETE_SLICE_0
            | Mnemonic::DELETE_SLICE_1
            | Mnemonic::DELETE_SLICE_2
            | Mnemonic::DELETE_SLICE_3 => {
                let (lower, upper) = self.pop_slice_bounds(mnemonic)?;
                let container = self.pop()?;
                let slice = self.arena.alloc(Expr::Slice { lower, upper, step: None });
                self.emit(Stmt::Delete(LValue::Subscript(container, slice)));
            }
            Mnemonic::DELETE_SUBSCR => {
                let key = self.pop()?;
                let container = self.pop()?;
                self.emit(Stmt::Delete(LValue::Subscript(container, key)));
            }
            // `obj[lower:upper:step]`: BUILD_SLICE pops 2 or 3 bounds and pushes a
            // slice for the following BINARY_SUBSCR/STORE_SUBSCR. A bound the source
            // omitted is a `None` constant here and round-trips as one.
            Mnemonic::BUILD_SLICE => {
                let (lower, upper, step) = match arg_u16(arg)? {
                    2 => {
                        let upper = self.pop()?;
                        let lower = self.pop()?;
                        (Some(lower), Some(upper), None)
                    }
                    3 => {
                        let step = self.pop()?;
                        let upper = self.pop()?;
                        let lower = self.pop()?;
                        (Some(lower), Some(upper), Some(step))
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.push(Expr::Slice { lower, upper, step });
            }
            Mnemonic::DELETE_FAST => self.emit(Stmt::Delete(LValue::Local(VarId(arg_u16(arg)?)))),
            Mnemonic::DELETE_NAME => self.emit(Stmt::Delete(LValue::Name(NameId(arg_u16(arg)?)))),
            Mnemonic::DELETE_GLOBAL => {
                self.emit(Stmt::Delete(LValue::Global(NameId(arg_u16(arg)?))))
            }
            Mnemonic::DELETE_ATTR => {
                let obj = self.pop()?;
                self.emit(Stmt::Delete(LValue::Attr(obj, NameId(arg_u16(arg)?))));
            }
            Mnemonic::MAKE_FUNCTION => {
                // The operand is the number of default values, pushed (in order)
                // before the code object for the trailing parameters.
                let code = self.pop_code_const()?;
                let defaults = self.pop_n(arg_u16(arg)? as usize)?;
                self.make_function(code, defaults)?;
            }
            // The captured cells of a closure; collected by BUILD_TUPLE into the
            // closure tuple. The capture itself is implicit in the source.
            Mnemonic::LOAD_CLOSURE => self.push(Expr::ClosureCell(DerefId(arg_u16(arg)?))),
            Mnemonic::MAKE_CLOSURE => {
                // Like MAKE_FUNCTION, but with the closure tuple below the code and
                // above the defaults. The tuple is implicit in source, so drop it.
                let code = self.pop_code_const()?;
                let _closure = self.pop()?;
                let defaults = self.pop_n(arg_u16(arg)? as usize)?;
                self.make_function(code, defaults)?;
            }
            // POP_JUMP_IF_FALSE and JUMP_FORWARD reach the unstacker only as the two
            // jumps of a ternary diamond the pre-pass identified; otherwise they are
            // block terminators and never fed here.
            // POP_JUMP_IF_FALSE/TRUE reach the unstacker only as a ternary diamond's
            // test (find_ternaries keeps it in-block). The true form takes the else
            // branch when the condition holds, so the recovered condition is negated.
            // A run of POP_JUMP_IF_FALSE before the then is a compound `and`
            // condition; each one is folded into the pending test.
            Mnemonic::POP_JUMP_IF_FALSE | Mnemonic::POP_JUMP_IF_TRUE => {
                let mut cond = self.pop()?;
                if mnemonic == Mnemonic::POP_JUMP_IF_TRUE {
                    cond = self.arena.alloc(Expr::Unary(UnaryOp::Not, cond));
                }
                // POP_JUMP_IF_* branches absolutely in 2.7: the operand is the else target.
                let else_target = Offset(arg_u16(arg)? as u32);
                // The innermost pending ternary with no `then` yet is still gathering its
                // condition -- BUT only a POP_JUMP that branches to the SAME else target is a
                // compound `and` continuation of it. A POP_JUMP to a DIFFERENT target opens a
                // nested ternary inside the cond/value region (e.g. a subscript key computed
                // by an inner ternary, `d[k1 if c else k2] if outer else e`), whose then is
                // also unset at this point; folding it into the `and` would be wrong. If the
                // top ternary already has its `then` (we are in its else arm), the POP_JUMP
                // likewise begins a nested ternary -- a chained `a if c1 else b if c2 else d`.
                // Nested ternaries push and resolve innermost-first at their own merge.
                if self
                    .ternary
                    .last()
                    .is_some_and(|p| p.then.is_none() && p.else_target == else_target)
                {
                    let prev = self.ternary.last().unwrap().cond;
                    let merged = self.and_chain(prev, cond);
                    self.ternary.last_mut().unwrap().cond = merged;
                } else {
                    self.ternary.push(PendingTernary {
                        cond,
                        then: None,
                        merge: Offset(0),
                        else_target,
                        sc_depth: self.shortcircuit.len(),
                    });
                }
            }
            Mnemonic::JUMP_FORWARD => {
                let merge = Offset(offset.0 + instr.len() as u32 + arg_u16(arg)? as u32);
                // When the ternary then-arm is a short-circuit value (`(a or b) if c
                // else d`), the and/or operators short-circuit to this same merge and
                // are still pending here, with their final operand on the stack. This
                // JUMP_FORWARD is the arm's fall-through exit, so fold them now: the
                // resulting boolean is the arm value. Without this the pending
                // short-circuits would capture only the tail operand as `then`.
                //
                // Only fold short-circuits opened *inside* the then arm (at or above the
                // ternary's `sc_depth`). One opened before the ternary -- e.g. the `a
                // and` of `a and (x if c else y)`, which short-circuits to this same
                // merge -- wraps the whole ternary, so it must stay pending and resolve
                // around the ternary at the merge, not be absorbed into `then`.
                let floor = self.ternary.last().map_or(0, |t| t.sc_depth);
                while self.shortcircuit.len() > floor
                    && self.shortcircuit.last().map(|s| s.merge) == Some(merge)
                {
                    let sc = self.shortcircuit.pop().unwrap();
                    let rhs = self.pop()?;
                    let combined = self.combine_bool(sc.kind, sc.lhs, rhs);
                    self.stack.push(combined);
                }
                let then = self.pop()?;
                match self.ternary.last_mut() {
                    Some(pending) if pending.then.is_none() => {
                        pending.then = Some(then);
                        pending.merge = merge;
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                }
            }
            Mnemonic::JUMP_IF_FALSE_OR_POP | Mnemonic::JUMP_IF_TRUE_OR_POP => {
                let kind = if mnemonic == Mnemonic::JUMP_IF_FALSE_OR_POP {
                    BoolKind::And
                } else {
                    BoolKind::Or
                };
                let lhs = self.pop()?;
                // A chained comparison lands its value after the cleanup, not at the
                // jump target; use the override when one was recorded.
                let merge = self
                    .merge_overrides
                    .get(&offset)
                    .copied()
                    .unwrap_or(Offset(arg_u16(arg)? as u32));
                self.shortcircuit.push(ShortCircuit { kind, lhs, merge });
            }
            Mnemonic::UNPACK_SEQUENCE => {
                let arity = arg_u16(arg)? as usize;
                let rhs = self.pop()?;
                // A nested target, e.g. the `(a, b)` of `(a, b), c = ...`, unpacks a
                // slot of the enclosing unpack: the popped rhs is that slot, the
                // nested unpack has no rhs of its own, and its completed tuple fills
                // the parent slot. A slot with no enclosing unpack would be malformed.
                let nested = matches!(self.arena.get(rhs), Expr::UnpackSlot);
                if nested && self.unpacks.is_empty() {
                    return Err(IrError::Unsupported(mnemonic));
                }
                self.unpacks.push(PendingUnpack {
                    rhs: if nested { None } else { Some(rhs) },
                    arity,
                    targets: Vec::new(),
                });
                for _ in 0..arity {
                    self.push(Expr::UnpackSlot);
                }
            }
            Mnemonic::YIELD_VALUE => {
                let value = self.pop()?;
                self.push(Expr::Yield(value));
            }
            // `exec code in globals, locals`. The compiler dups the namespace into
            // the locals slot for `exec code` and `exec code in g`, so equal operands
            // mean the source supplied no separate locals mapping.
            Mnemonic::EXEC_STMT => {
                let locals = self.pop()?;
                let globals = self.pop()?;
                let code = self.pop()?;
                let locals = if locals == globals { None } else { Some(locals) };
                self.emit(Stmt::Exec { code, globals, locals });
            }
            // `print a, b` is PRINT_ITEM per operand then PRINT_NEWLINE; `print a,`
            // (suppressed newline) omits the PRINT_NEWLINE.
            Mnemonic::PRINT_ITEM => {
                let value = self.pop()?;
                self.print_values.push(value);
            }
            Mnemonic::PRINT_NEWLINE => {
                let values = std::mem::take(&mut self.print_values);
                self.emit(Stmt::Print { values, newline: true, stream: None });
            }
            // `print >>f, a, b`: each operand is `DUP_TOP; LOAD v; ROT_TWO;
            // PRINT_ITEM_TO`, which pops the dup'd stream and the value and leaves the
            // base stream on the stack; the trailing PRINT_NEWLINE_TO (or a POP_TOP for
            // a suppressed newline) pops that base stream and flushes. Tracked
            // separately from the stdout `print_values` so the DUP/ROT between items
            // does not trip the trailing-comma flush.
            Mnemonic::PRINT_ITEM_TO => {
                let stream = self.pop()?;
                let value = self.pop()?;
                self.print_to
                    .get_or_insert_with(|| PrintTo { stream, values: Vec::new() })
                    .values
                    .push(value);
            }
            Mnemonic::PRINT_NEWLINE_TO => {
                let top = self.pop()?;
                let (stream, values) = match self.print_to.take() {
                    Some(pt) => (pt.stream, pt.values),
                    None => (top, Vec::new()),
                };
                self.emit(Stmt::Print { values, newline: true, stream: Some(stream) });
            }
            // The namespace a class body returns; placed so the body's RETURN_VALUE
            // has a value to pop and the class recogniser can drop it.
            Mnemonic::LOAD_LOCALS => self.push(Expr::Locals),
            // BUILD_CLASS pops the namespace (the called class body), the base
            // tuple, and the name constant, and builds the class.
            Mnemonic::BUILD_CLASS => {
                let namespace = self.pop()?;
                let bases = self.pop()?;
                let name = self.pop()?;
                let code = match self.arena.get(namespace) {
                    Expr::Call { func, args, kwargs, star, kwstar }
                        if args.is_empty()
                            && kwargs.is_empty()
                            && star.is_none()
                            && kwstar.is_none() =>
                    {
                        match self.arena.get(*func) {
                            Expr::MakeFunction { code, defaults } if defaults.is_empty() => *code,
                            _ => return Err(IrError::Unsupported(mnemonic)),
                        }
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.push(Expr::BuildClass { name, bases, code });
            }
            Mnemonic::IMPORT_NAME => {
                // Pops the from-list and the relative-import level; the import form is
                // determined by the opcodes that follow, not these operands. The level
                // (`LOAD_CONST` below the from-list) is kept so a relative import can
                // restore its leading dots; the compiler always emits it as a constant
                // int, so a non-constant here just means no level info is available.
                let _fromlist = self.pop()?;
                let level = self.pop()?;
                let level = match self.arena.get(level) {
                    Expr::Const(c) => Some(*c),
                    _ => None,
                };
                self.push(Expr::Import {
                    module: NameId(arg_u16(arg)?),
                    level,
                });
            }
            Mnemonic::IMPORT_FROM => {
                // The obfuscator can push a junk constant on top of the module that
                // IMPORT_NAME produced. A constant never legitimately sits on top at
                // an IMPORT_FROM, so discard any before reading the module; a non-junk
                // value left here is a shape we do not handle and is left to fail.
                while matches!(
                    self.stack.last().map(|top| self.arena.get(*top)),
                    Some(Expr::Const(_))
                ) {
                    self.pop()?;
                }
                let (module, level) = match self.arena.get(*self.stack.last().ok_or(IrError::StackUnderflow)?) {
                    Expr::Import { module, level } => (*module, *level),
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.from_import.get_or_insert_with(|| PendingFrom {
                    module,
                    names: Vec::new(),
                    level,
                });
                self.push(Expr::ImportFrom(NameId(arg_u16(arg)?)));
            }
            Mnemonic::IMPORT_STAR => {
                let top = self.pop()?;
                let (module, level) = match self.arena.get(top) {
                    Expr::Import { module, level } => (*module, *level),
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.emit(Stmt::FromImport { module, names: Vec::new(), star: true, level });
            }
            // The trailing POP_TOP of a `from module import ...` discards the module
            // and completes the statement; otherwise it is an expression statement.
            Mnemonic::POP_TOP if self.from_import.is_some() && self.tops_import() => {
                self.pop()?;
                let pending = self.from_import.take().unwrap();
                self.emit(Stmt::FromImport {
                    module: pending.module,
                    names: pending.names,
                    star: false,
                    level: pending.level,
                });
            }
            // A `print >>f, a,` with a suppressed newline ends in POP_TOP of the base
            // stream instead of PRINT_NEWLINE_TO; flush the pending statement.
            Mnemonic::POP_TOP if self.print_to_at_top() => {
                self.pop()?;
                let pt = self.print_to.take().unwrap();
                self.emit(Stmt::Print {
                    values: pt.values,
                    newline: false,
                    stream: Some(pt.stream),
                });
            }
            Mnemonic::POP_TOP => {
                let value = self.pop()?;
                self.emit(Stmt::Expr(value));
            }
            Mnemonic::RETURN_VALUE => {
                let value = self.pop()?;
                self.emit(Stmt::Return(Some(value)));
            }
            other => return Err(IrError::Unsupported(other)),
        }
        Ok(())
    }
}

fn arg_u16(arg: Option<u16>) -> Result<u16, IrError> {
    arg.ok_or(IrError::MissingOperand)
}

/// Rejects any control-flow opcode inside a list comprehension's sub-expressions,
/// so only the straight-line single-`for` shape is folded.
/// How a boolean-region leaf ends: the function's `return`, or a short-circuit jump
/// to `target` with the fall-through at `after` (see [`Unstacker::recover_returned_bool`]).
enum LeafTerm {
    Return,
    Jump { kind: Mnemonic, target: Offset, after: Offset },
}

/// One lowered leaf of a boolean region: its value and how it ends.
struct LeafRec {
    value: ValueId,
    term: LeafTerm,
}

/// A reconstructed list-comprehension filter sub-result: a `True`/`False` control
/// terminal (the keep point / the loop top), or a real condition value.
#[derive(Clone, Copy)]
enum FilterVal {
    True,
    False,
    Val(ValueId),
}

/// One lowered leaf of a comprehension filter: its condition value and the
/// short-circuit jump that ends it (`POP_JUMP_IF_TRUE`/`FALSE` -- filters discard the
/// tested value, so the value-keeping `JUMP_IF_*_OR_POP` forms never appear here).
struct FilterLeaf {
    value: ValueId,
    kind: Mnemonic,
    target: Offset,
    after: Offset,
}

/// Whether a mnemonic is a short-circuit jump connecting boolean-expression operands.
fn is_bool_jump(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::POP_JUMP_IF_TRUE
            | Mnemonic::POP_JUMP_IF_FALSE
            | Mnemonic::JUMP_IF_TRUE_OR_POP
            | Mnemonic::JUMP_IF_FALSE_OR_POP
    )
}

/// Whether a mnemonic transfers control or manages a block, so it cannot appear in a
/// straight-line statement prefix lowered ahead of a boolean return region.
fn is_control_flow(m: Mnemonic) -> bool {
    if is_bool_jump(m) {
        return true;
    }
    let name = format!("{:?}", m);
    name.starts_with("JUMP")
        || name.starts_with("SETUP_")
        || name.starts_with("FOR_")
        || matches!(
            m,
            Mnemonic::RETURN_VALUE
                | Mnemonic::RAISE_VARARGS
                | Mnemonic::YIELD_VALUE
                | Mnemonic::END_FINALLY
                | Mnemonic::BREAK_LOOP
                | Mnemonic::CONTINUE_LOOP
                | Mnemonic::POP_BLOCK
        )
}

/// Simulates the original boolean region's control flow under a leaf-truthiness
/// assignment, returning `(result leaf index, leaves evaluated in order)`. Compared
/// against [`Unstacker::expr_sim`] to verify the reconstruction.
/// Simulates a comprehension filter's control flow under a leaf assignment, returning
/// `(reaches keep point, leaves evaluated in order)`. Compared against
/// [`Unstacker::filter_expr_eval`] to verify the reconstruction.
fn filter_cfg_sim(
    start: Offset,
    keep_point: Offset,
    loop_top: Offset,
    leaves: &HashMap<Offset, FilterLeaf>,
    leaf_index: &HashMap<ValueId, usize>,
    assign: &[bool],
) -> Option<(bool, Vec<usize>)> {
    let mut cur = start;
    let mut order = Vec::new();
    for _ in 0..=leaves.len() {
        if cur == keep_point {
            return Some((true, order));
        }
        if cur == loop_top {
            return Some((false, order));
        }
        let leaf = leaves.get(&cur)?;
        let li = *leaf_index.get(&leaf.value)?;
        order.push(li);
        let t = assign[li];
        cur = match leaf.kind {
            Mnemonic::POP_JUMP_IF_TRUE => if t { leaf.target } else { leaf.after },
            Mnemonic::POP_JUMP_IF_FALSE => if t { leaf.after } else { leaf.target },
            _ => return None,
        };
    }
    None
}

fn cfg_sim(
    start: Offset,
    steps: usize,
    leaf_index: &HashMap<ValueId, usize>,
    recs: &HashMap<Offset, LeafRec>,
    assign: &[bool],
) -> Option<(usize, Vec<usize>)> {
    let mut cur = start;
    let mut order = Vec::new();
    // The region is finite and every jump moves strictly forward, so this terminates.
    for _ in 0..=steps {
        let rec = recs.get(&cur)?;
        let li = *leaf_index.get(&rec.value)?;
        order.push(li);
        match rec.term {
            LeafTerm::Return => return Some((li, order)),
            LeafTerm::Jump { kind, target, after } => {
                let t = assign[li];
                cur = match kind {
                    Mnemonic::POP_JUMP_IF_TRUE => if t { target } else { after },
                    Mnemonic::POP_JUMP_IF_FALSE => if t { after } else { target },
                    Mnemonic::JUMP_IF_TRUE_OR_POP => {
                        if t {
                            return Some((li, order));
                        }
                        after
                    }
                    Mnemonic::JUMP_IF_FALSE_OR_POP => {
                        if !t {
                            return Some((li, order));
                        }
                        after
                    }
                    _ => return None,
                };
            }
        }
    }
    None
}

/// Locates the end (region index, exclusive) of a nested element comprehension
/// whose `BUILD_LIST 0` accumulator is at `region[build]`. The sub-comp runs from
/// that build through the back edge that closes its outer loop -- a `JUMP_ABSOLUTE`
/// to the first `FOR_ITER` after the build -- and the instruction at that end must be
/// the `LIST_APPEND` that appends the inner list to the enclosing accumulator.
/// Returns `None` when the build is an ordinary `[]` literal (no following FOR_ITER,
/// or the borrowed loop exits by jumping to an enclosing loop top rather than into an
/// append), so the caller leaves it on the normal path.
fn nested_comp_end(region: &[&OffsetInstr], build: usize) -> Option<usize> {
    let mut for_i = build + 1;
    loop {
        let mnemonic = region.get(for_i)?.instr.opcode.mnemonic();
        if mnemonic == Mnemonic::FOR_ITER {
            break;
        }
        // A store or jump before any FOR_ITER means this build is a list literal,
        // not a comprehension accumulator.
        let name = format!("{:?}", mnemonic);
        if name.starts_with("STORE_") || name.starts_with("JUMP") || name.starts_with("POP_JUMP")
        {
            return None;
        }
        for_i += 1;
    }
    let loop_top = region[for_i].offset;
    for k in (for_i + 1)..region.len() {
        if region[k].instr.opcode.mnemonic() == Mnemonic::JUMP_ABSOLUTE
            && region[k].instr.arg.map(|a| Offset(a as u32)) == Some(loop_top)
        {
            // The inner list must be consumed by an append into the enclosing
            // accumulator; otherwise the borrowed loop is a multi-`for` continuation
            // and this build was a `[]` literal in its iterable.
            return match region.get(k + 1).map(|item| item.instr.opcode.mnemonic()) {
                Some(Mnemonic::LIST_APPEND) => Some(k + 1),
                _ => None,
            };
        }
    }
    None
}

fn reject_comp_control(item: &OffsetInstr) -> Result<(), IrError> {
    let mnemonic = item.instr.opcode.mnemonic();
    if matches!(
        mnemonic,
        Mnemonic::JUMP_FORWARD
            | Mnemonic::JUMP_ABSOLUTE
            | Mnemonic::POP_JUMP_IF_TRUE
            | Mnemonic::POP_JUMP_IF_FALSE
            | Mnemonic::JUMP_IF_FALSE_OR_POP
            | Mnemonic::JUMP_IF_TRUE_OR_POP
            | Mnemonic::FOR_ITER
            | Mnemonic::SETUP_LOOP
            | Mnemonic::SETUP_EXCEPT
            | Mnemonic::SETUP_FINALLY
            | Mnemonic::SETUP_WITH
            | Mnemonic::BREAK_LOOP
            | Mnemonic::CONTINUE_LOOP
            | Mnemonic::YIELD_VALUE
            | Mnemonic::RETURN_VALUE
            | Mnemonic::LIST_APPEND
    ) {
        return Err(IrError::Unsupported(mnemonic));
    }
    Ok(())
}

/// Resolves a list comprehension's loop target store to an [`LValue`]. Tuple
/// Returns the assignment target for a single comprehension store opcode. A tuple
/// target (`UNPACK_SEQUENCE` then one store per element) is assembled by the caller.
fn comp_target(instr: &Instruction<Standard>) -> Result<LValue, IrError> {
    let arg = instr.arg.ok_or(IrError::MissingOperand)?;
    Ok(match instr.opcode.mnemonic() {
        Mnemonic::STORE_FAST => LValue::Local(VarId(arg)),
        Mnemonic::STORE_NAME => LValue::Name(NameId(arg)),
        Mnemonic::STORE_GLOBAL => LValue::Global(NameId(arg)),
        Mnemonic::STORE_DEREF => LValue::Deref(DerefId(arg)),
        other => return Err(IrError::Unsupported(other)),
    })
}

/// Parses a comprehension `for` clause's target starting at `region[*i]`, advancing `*i`
/// past every instruction it consumes. A bare store is a simple target; an
/// `UNPACK_SEQUENCE` introduces a tuple target whose `arity` elements are each parsed the
/// same way, so a nested target like `a, (b, c)` recovers as a nested [`LValue::Tuple`].
fn comp_target_at(region: &[&OffsetInstr], i: &mut usize) -> Result<LValue, IrError> {
    let item = region.get(*i).ok_or(IrError::Decode)?;
    if item.instr.opcode.mnemonic() == Mnemonic::UNPACK_SEQUENCE {
        let arity = item.instr.arg.ok_or(IrError::MissingOperand)? as usize;
        *i += 1;
        let mut targets = Vec::with_capacity(arity);
        for _ in 0..arity {
            targets.push(comp_target_at(region, i)?);
        }
        Ok(LValue::Tuple(targets))
    } else {
        let t = comp_target(&item.instr)?;
        *i += 1;
        Ok(t)
    }
}

fn binary_op(mnemonic: Mnemonic) -> Option<BinOp> {
    Some(match mnemonic {
        Mnemonic::BINARY_ADD => BinOp::Add,
        Mnemonic::BINARY_SUBTRACT => BinOp::Subtract,
        Mnemonic::BINARY_MULTIPLY => BinOp::Multiply,
        Mnemonic::BINARY_DIVIDE => BinOp::Divide,
        Mnemonic::BINARY_FLOOR_DIVIDE => BinOp::FloorDivide,
        Mnemonic::BINARY_TRUE_DIVIDE => BinOp::TrueDivide,
        Mnemonic::BINARY_MODULO => BinOp::Modulo,
        Mnemonic::BINARY_POWER => BinOp::Power,
        Mnemonic::BINARY_LSHIFT => BinOp::LeftShift,
        Mnemonic::BINARY_RSHIFT => BinOp::RightShift,
        Mnemonic::BINARY_AND => BinOp::And,
        Mnemonic::BINARY_OR => BinOp::Or,
        Mnemonic::BINARY_XOR => BinOp::Xor,
        _ => return None,
    })
}

/// The operator of an `INPLACE_*` opcode, kept separate from [`binary_op`] so an
/// augmented assignment is distinguishable from a plain binary operation.
fn inplace_op(mnemonic: Mnemonic) -> Option<BinOp> {
    Some(match mnemonic {
        Mnemonic::INPLACE_ADD => BinOp::Add,
        Mnemonic::INPLACE_SUBTRACT => BinOp::Subtract,
        Mnemonic::INPLACE_MULTIPLY => BinOp::Multiply,
        Mnemonic::INPLACE_DIVIDE => BinOp::Divide,
        Mnemonic::INPLACE_FLOOR_DIVIDE => BinOp::FloorDivide,
        Mnemonic::INPLACE_TRUE_DIVIDE => BinOp::TrueDivide,
        Mnemonic::INPLACE_MODULO => BinOp::Modulo,
        Mnemonic::INPLACE_POWER => BinOp::Power,
        Mnemonic::INPLACE_LSHIFT => BinOp::LeftShift,
        Mnemonic::INPLACE_RSHIFT => BinOp::RightShift,
        Mnemonic::INPLACE_AND => BinOp::And,
        Mnemonic::INPLACE_OR => BinOp::Or,
        Mnemonic::INPLACE_XOR => BinOp::Xor,
        _ => return None,
    })
}

fn unary_op(mnemonic: Mnemonic) -> Option<UnaryOp> {
    Some(match mnemonic {
        Mnemonic::UNARY_NEGATIVE => UnaryOp::Negate,
        Mnemonic::UNARY_POSITIVE => UnaryOp::Positive,
        Mnemonic::UNARY_INVERT => UnaryOp::Invert,
        Mnemonic::UNARY_NOT => UnaryOp::Not,
        _ => return None,
    })
}
