//! Symbolic stack execution: turns a straight-line run of bytecode into a list
//! of statements over an [`ExprArena`].
//!
//! Each value-producing instruction pushes a [`ValueId`] onto a symbolic stack;
//! each effecting instruction pops its operands and emits a [`Stmt`]. Opcodes
//! outside the supported set return [`IrError::Unsupported`] so coverage gaps
//! surface instead of producing wrong output.

use pydis::opcode::py27::{Mnemonic, Standard};
use pydis::prelude::*;

use super::cfg::OffsetInstr;
use super::expr::*;
use super::IrError;

/// A tuple-assignment target under construction by `UNPACK_SEQUENCE` and the
/// stores that follow it.
struct PendingUnpack {
    rhs: ValueId,
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
}

/// A `from module import ...` under construction. `IMPORT_NAME` leaves the module
/// on the stack; each `IMPORT_FROM`/store pair adds a name, and the trailing
/// `POP_TOP` of the module completes it.
struct PendingFrom {
    module: NameId,
    names: Vec<(NameId, LValue)>,
}

/// Symbolic stack machine for one basic block.
pub struct Unstacker {
    arena: ExprArena,
    stack: Vec<ValueId>,
    stmts: Vec<Stmt>,
    unpack: Option<PendingUnpack>,
    shortcircuit: Vec<ShortCircuit>,
    ternary: Option<PendingTernary>,
    from_import: Option<PendingFrom>,
    /// True when lowering a comprehension code object: its leading `BUILD_SET`/
    /// `BUILD_MAP` is the accumulator (kept off the stack), and `SET_ADD`/`MAP_ADD`
    /// become element statements instead of unsupported opcodes.
    comp: bool,
    /// Whether the comprehension accumulator has been consumed from the stream.
    comp_acc_seen: bool,
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
            unpack: None,
            shortcircuit: Vec::new(),
            ternary: None,
            from_import: None,
            comp,
            comp_acc_seen: false,
        }
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
            .is_some_and(|top| matches!(self.arena.get(*top), Expr::Import(_)))
    }

    /// Resolves any pending short-circuit or ternary whose merge point is `offset`:
    /// the remaining operand is on the stack, so combine it with what was recorded.
    pub fn resolve_pending(&mut self, offset: Offset) -> Result<(), IrError> {
        loop {
            if self.shortcircuit.last().map(|s| s.merge) == Some(offset) {
                let sc = self.shortcircuit.pop().unwrap();
                let rhs = self.pop()?;
                let combined = self.combine_bool(sc.kind, sc.lhs, rhs);
                self.stack.push(combined);
                continue;
            }
            if self.ternary.as_ref().is_some_and(|t| t.merge == offset && t.then.is_some()) {
                let pending = self.ternary.take().unwrap();
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
        self.shortcircuit.is_empty() && self.ternary.is_none()
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
        if let Expr::MakeFunction(code) = self.arena.get(value) {
            let code = *code;
            self.emit(Stmt::FunctionDef { target, code });
            return;
        }
        // `import module` binds the module object; `from module import name` binds
        // each name pulled by IMPORT_FROM into the pending from-import.
        if let Expr::Import(module) = self.arena.get(value) {
            let module = *module;
            self.emit(Stmt::Import { module, target });
            return;
        }
        if let Expr::ImportFrom(name) = self.arena.get(value) {
            let name = *name;
            if let Some(pending) = self.from_import.as_mut() {
                pending.names.push((name, target));
            }
            return;
        }
        if self.unpack.is_some() && matches!(self.arena.get(value), Expr::UnpackSlot) {
            let pending = self.unpack.as_mut().unwrap();
            pending.targets.push(target);
            if pending.targets.len() == pending.arity {
                let pending = self.unpack.take().unwrap();
                self.emit(Stmt::Assign(LValue::Tuple(pending.targets), pending.rhs));
            }
        } else {
            self.emit(Stmt::Assign(target, value));
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
        self.unpack = None;
        self.shortcircuit.clear();
        self.ternary = None;
        self.from_import = None;
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
    /// `region` runs from the `BUILD_LIST 0` accumulator through the loop's back
    /// edge: `BUILD_LIST 0; <iter>; GET_ITER; FOR_ITER exit; STORE target;
    /// [<cond>; POP_JUMP_IF_FALSE top]*; <element>; LIST_APPEND; JUMP_ABSOLUTE top`.
    /// Only this single-`for` shape with straight-line sub-expressions is accepted;
    /// anything else returns an error so the function is rejected rather than
    /// mis-recovered.
    pub fn parse_list_comp(&mut self, region: &[&OffsetInstr]) -> Result<(), IrError> {
        let mnemonic = |i: usize| region.get(i).map(|item| item.instr.opcode.mnemonic());
        if mnemonic(0) != Some(Mnemonic::BUILD_LIST) {
            return Err(IrError::Unsupported(Mnemonic::BUILD_LIST));
        }
        // The iterable expression, ending in GET_ITER (a no-op for the stack)
        // before FOR_ITER consumes the iterator.
        let mut i = 1;
        while mnemonic(i) != Some(Mnemonic::FOR_ITER) {
            let item = region.get(i).ok_or(IrError::Decode)?;
            reject_comp_control(item)?;
            self.step(&item.instr, item.offset)?;
            i += 1;
        }
        let for_iter = region[i];
        let loop_top = for_iter.offset;
        let iter = self.pop()?;
        i += 1;
        // The loop target is the store immediately after FOR_ITER.
        let target = comp_target(&region.get(i).ok_or(IrError::Decode)?.instr)?;
        i += 1;
        // Filters and the element, up to LIST_APPEND.
        let mut conds = Vec::new();
        while mnemonic(i) != Some(Mnemonic::LIST_APPEND) {
            let item = region.get(i).ok_or(IrError::Decode)?;
            if item.instr.opcode.mnemonic() == Mnemonic::POP_JUMP_IF_FALSE {
                // A filter jumps back to the loop top; a forward jump would be
                // branching inside the element, which this shape does not handle.
                let dest = Offset(item.instr.arg.ok_or(IrError::MissingOperand)? as u32);
                if dest != loop_top {
                    return Err(IrError::Unsupported(Mnemonic::POP_JUMP_IF_FALSE));
                }
                conds.push(self.pop()?);
            } else {
                reject_comp_control(item)?;
                self.step(&item.instr, item.offset)?;
            }
            i += 1;
        }
        // LIST_APPEND leaves the element on top of the stack.
        let element = self.pop()?;
        self.push(Expr::ListComp { element, target, iter, conds });
        Ok(())
    }

    /// Folds one instruction into the symbolic state. `offset` is the instruction's
    /// byte offset, needed to resolve a relative `JUMP_FORWARD` target.
    pub fn step(&mut self, instr: &Instruction<Standard>, offset: Offset) -> Result<(), IrError> {
        let arg = instr.arg;
        let mnemonic = instr.opcode.mnemonic();

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
            Mnemonic::MAKE_FUNCTION => {
                // Default arguments are not recovered into the signature yet, so
                // only the no-default form is supported.
                if arg_u16(arg)? != 0 {
                    return Err(IrError::Unsupported(mnemonic));
                }
                let code = self.pop()?;
                match self.arena.get(code) {
                    Expr::Const(const_id) => {
                        let const_id = *const_id;
                        self.push(Expr::MakeFunction(const_id));
                    }
                    _ => return Err(IrError::Unsupported(mnemonic)),
                }
            }
            // POP_JUMP_IF_FALSE and JUMP_FORWARD reach the unstacker only as the two
            // jumps of a ternary diamond the pre-pass identified; otherwise they are
            // block terminators and never fed here.
            Mnemonic::POP_JUMP_IF_FALSE => {
                if self.ternary.is_some() {
                    return Err(IrError::Unsupported(mnemonic));
                }
                let cond = self.pop()?;
                self.ternary = Some(PendingTernary {
                    cond,
                    then: None,
                    merge: Offset(0),
                });
            }
            Mnemonic::JUMP_FORWARD => {
                let then = self.pop()?;
                let merge = Offset(offset.0 + instr.len() as u32 + arg_u16(arg)? as u32);
                match self.ternary.as_mut() {
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
                self.shortcircuit.push(ShortCircuit {
                    kind,
                    lhs,
                    merge: Offset(arg_u16(arg)? as u32),
                });
            }
            Mnemonic::UNPACK_SEQUENCE => {
                let arity = arg_u16(arg)? as usize;
                let rhs = self.pop()?;
                // Nested unpack targets, e.g. `(a, b), c = ...`, are not handled yet.
                if matches!(self.arena.get(rhs), Expr::UnpackSlot) {
                    return Err(IrError::Unsupported(mnemonic));
                }
                self.unpack = Some(PendingUnpack {
                    rhs,
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
            Mnemonic::IMPORT_NAME => {
                // Pops the from-list and relative-import level; the import form is
                // determined by the opcodes that follow, not these operands.
                let _fromlist = self.pop()?;
                let _level = self.pop()?;
                self.push(Expr::Import(NameId(arg_u16(arg)?)));
            }
            Mnemonic::IMPORT_FROM => {
                let module = match self.arena.get(*self.stack.last().ok_or(IrError::StackUnderflow)?) {
                    Expr::Import(module) => *module,
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.from_import
                    .get_or_insert_with(|| PendingFrom { module, names: Vec::new() });
                self.push(Expr::ImportFrom(NameId(arg_u16(arg)?)));
            }
            Mnemonic::IMPORT_STAR => {
                let top = self.pop()?;
                let module = match self.arena.get(top) {
                    Expr::Import(module) => *module,
                    _ => return Err(IrError::Unsupported(mnemonic)),
                };
                self.emit(Stmt::FromImport { module, names: Vec::new(), star: true });
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
/// targets (an `UNPACK_SEQUENCE`) are not folded and reach the error path.
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

fn binary_op(mnemonic: Mnemonic) -> Option<BinOp> {
    Some(match mnemonic {
        Mnemonic::BINARY_ADD | Mnemonic::INPLACE_ADD => BinOp::Add,
        Mnemonic::BINARY_SUBTRACT | Mnemonic::INPLACE_SUBTRACT => BinOp::Subtract,
        Mnemonic::BINARY_MULTIPLY | Mnemonic::INPLACE_MULTIPLY => BinOp::Multiply,
        Mnemonic::BINARY_DIVIDE | Mnemonic::INPLACE_DIVIDE => BinOp::Divide,
        Mnemonic::BINARY_FLOOR_DIVIDE | Mnemonic::INPLACE_FLOOR_DIVIDE => BinOp::FloorDivide,
        Mnemonic::BINARY_TRUE_DIVIDE | Mnemonic::INPLACE_TRUE_DIVIDE => BinOp::TrueDivide,
        Mnemonic::BINARY_MODULO | Mnemonic::INPLACE_MODULO => BinOp::Modulo,
        Mnemonic::BINARY_POWER | Mnemonic::INPLACE_POWER => BinOp::Power,
        Mnemonic::BINARY_LSHIFT | Mnemonic::INPLACE_LSHIFT => BinOp::LeftShift,
        Mnemonic::BINARY_RSHIFT | Mnemonic::INPLACE_RSHIFT => BinOp::RightShift,
        Mnemonic::BINARY_AND | Mnemonic::INPLACE_AND => BinOp::And,
        Mnemonic::BINARY_OR | Mnemonic::INPLACE_OR => BinOp::Or,
        Mnemonic::BINARY_XOR | Mnemonic::INPLACE_XOR => BinOp::Xor,
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
