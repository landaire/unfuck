use std::cell::OnceCell;
use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::activation::Activation;
use crate::interp::code::CodeFlags;
use crate::interp::code::CodeObject;
use crate::interp::code::op;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::ops::BinaryOp;
use crate::interp::ops::CompareOp;
use crate::interp::traceback::Handled;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::UnwindMarker;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    Loop,
    Except,
    Finally,
    /// `SETUP_WITH`: a finally block whose exception becomes current.
    With,
}

#[derive(Clone, Copy, Debug)]
struct Block {
    kind: BlockKind,
    handler: usize,
    level: usize,
}

/// How a frame stopped running.
pub enum FrameExit {
    Return(Value),
    Yield(Value),
}

/// Pending non-local exit while unwinding the block stack.
enum Why {
    Exception(Signal),
    Return(Value),
    Break,
    Continue(usize),
}

/// The variables of a frame: fast slots, cells, and `f_locals`. A frame
/// shares it with its `Activation`, so natives that read the caller's
/// variables and frame objects see the live values.
pub struct FrameScope {
    code: Rc<CodeObject>,
    fast: RefCell<Vec<Option<Value>>>,
    /// Cell variables followed by free variables.
    cells: Vec<ObjectRef>,
    /// `f_locals`. Module, class, unoptimized function, and `exec` frames
    /// receive it at creation; optimized function frames create it on the
    /// first `fast_to_locals`.
    locals: OnceCell<ObjectRef>,
}

impl FrameScope {
    pub fn new(code: Rc<CodeObject>, locals: Option<ObjectRef>, fast: Vec<Option<Value>>, cells: Vec<ObjectRef>) -> Self {
        let locals = match locals {
            Some(locals) => OnceCell::from(locals),
            None => OnceCell::new(),
        };

        Self { code, fast: RefCell::new(fast), cells, locals }
    }

    pub fn code(&self) -> &Rc<CodeObject> {
        &self.code
    }

    /// `f_locals` as it stands, without merging the fast slots.
    pub fn locals(&self) -> Option<&ObjectRef> {
        self.locals.get()
    }

    /// Stores the fast slots, the cell variables,
    /// and, for optimized code, the free variables into `f_locals`
    /// (creating it on first use) and removes the names whose slot is
    /// unbound. Errors from the mapping are discarded as CPython does.
    pub fn fast_to_locals(&self, vm: &Vm) -> PyResult<ObjectRef> {
        let locals = Rc::clone(self.locals.get_or_init(|| vm.new_dict()));
        let mapping = Value::Object(Rc::clone(&locals));

        let fast = self.fast.borrow().clone();
        store_slots(vm, &mapping, &self.code.varnames, &fast)?;

        let cells: Vec<Option<Value>> = self.cells.iter().map(cell_value).collect();
        let (cellvars, freevars) = cells.split_at(self.code.cellvars.len().min(cells.len()));
        store_slots(vm, &mapping, &self.code.cellvars, cellvars)?;

        if self.code.flags.contains(CodeFlags::OPTIMIZED) {
            store_slots(vm, &mapping, &self.code.freevars, freevars)?;
        }

        Ok(locals)
    }

    /// Copies the names present in `f_locals`
    /// back into the fast slots and cells. Absent names leave their slot as
    /// it is.
    pub fn locals_to_fast(&self, vm: &Vm) -> PyResult<()> {
        let Some(locals) = self.locals.get() else {
            return Ok(());
        };
        let mapping = Value::Object(Rc::clone(locals));

        let count = self.code.varnames.len().min(self.fast.borrow().len());
        for index in (0..count).rev() {
            let Some(value) = mapping_value(vm, &mapping, &self.code.varnames[index])? else {
                continue;
            };
            if let Some(slot) = self.fast.borrow_mut().get_mut(index) {
                *slot = Some(value);
            }
        }

        let cellvars = self.code.cellvars.len().min(self.cells.len());
        let (cellvar_cells, freevar_cells) = self.cells.split_at(cellvars);
        dict_to_cells(vm, &mapping, &self.code.cellvars, cellvar_cells)?;

        if self.code.flags.contains(CodeFlags::OPTIMIZED) {
            dict_to_cells(vm, &mapping, &self.code.freevars, freevar_cells)?;
        }

        Ok(())
    }
}

/// An activation record. Generators keep theirs between resumptions.
pub struct Frame {
    // Fields drop in declaration order; CPython frees a frame's locals
    // and the value stack before the code, builtins, and globals.
    pub scope: Rc<FrameScope>,
    stack: Vec<Value>,
    blocks: Vec<Block>,
    pc: usize,

    pub code: Rc<CodeObject>,
    /// The code object `code` belongs to, for `f_code`.
    pub code_object: ObjectRef,
    pub builtins: ObjectRef,
    pub globals: ObjectRef,
    /// The part of the frame that frame objects and tracebacks share.
    pub activation: Rc<Activation>,
    /// The opcode last fetched and the offset after it, for opcode
    /// prediction.
    last: (u8, usize),
    /// Opcodes that, coming next, run without updating `f_lasti`, as
    /// opcode prediction in the Windows build does.
    predicts: &'static [u8],
    /// The pending exception is re-raised with its traceback,
    /// so this frame is not added to it.
    reraise: bool,
}

impl Frame {
    pub fn new(code: Rc<CodeObject>, code_object: ObjectRef, globals: ObjectRef, builtins: ObjectRef, locals: Option<ObjectRef>, cells: Vec<ObjectRef>) -> Self {
        let fast = vec![None; code.nlocals as usize];

        Self::from_scope(code_object, globals, builtins, FrameScope::new(code, locals, fast, cells))
    }

    pub fn from_scope(code_object: ObjectRef, globals: ObjectRef, builtins: ObjectRef, scope: FrameScope) -> Self {
        let code = Rc::clone(&scope.code);
        let stack = Vec::with_capacity(code.stacksize as usize);

        let scope = Rc::new(scope);
        let activation = Rc::new(Activation::new(Rc::clone(&code_object), Rc::clone(&globals), Rc::clone(&builtins), Rc::clone(&scope)));

        Self { code, code_object, globals, builtins, scope, stack, blocks: Vec::new(), pc: 0, activation, last: (op::NOP, 0), predicts: &[], reraise: false }
    }

    pub fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    pub fn is_started(&self) -> bool {
        self.pc != 0
    }

    fn pop(&mut self) -> PyResult<Value> {
        match self.stack.pop() {
            Some(value) => Ok(value),
            None => Err(self.malformed("value stack underflow")),
        }
    }

    fn top(&self) -> PyResult<&Value> {
        match self.stack.last() {
            Some(value) => Ok(value),
            None => Err(self.malformed("value stack underflow")),
        }
    }

    fn peek(&self, depth: usize) -> PyResult<&Value> {
        let len = self.stack.len();
        if depth == 0 || depth > len {
            return Err(self.malformed("value stack underflow"));
        }

        Ok(&self.stack[len - depth])
    }

    fn pop_n(&mut self, count: usize) -> PyResult<Vec<Value>> {
        if count > self.stack.len() {
            return Err(self.malformed("value stack underflow"));
        }

        let start = self.stack.len() - count;

        Ok(self.stack.split_off(start))
    }

    fn malformed(&self, detail: &str) -> Signal {
        Signal::Halt(Halt::MalformedCode { code: self.describe(), detail: format!("{detail} at offset {}", self.pc) })
    }

    pub fn describe(&self) -> String {
        format!("{} at offset {} line {}", self.code.name.to_string_lossy(), self.pc, self.code.line_at(self.pc))
    }

    /// `describe` qualified with the module that owns the frame's globals.
    pub fn location(&self, vm: &Vm) -> String {
        let module = vm.dict_get_str(&self.globals, "__name__").ok().flatten().and_then(|name| vm.text_of(&name)).unwrap_or_default();

        format!("{module}: {}", self.describe())
    }

    fn name(&self, index: usize) -> PyResult<PyBytes> {
        match self.code.names.get(index) {
            Some(name) => Ok(name.clone()),
            None => Err(self.malformed("name index out of range")),
        }
    }

    fn cell(&self, index: usize) -> PyResult<ObjectRef> {
        match self.scope.cells.get(index) {
            Some(cell) => Ok(Rc::clone(cell)),
            None => Err(self.malformed("cell index out of range")),
        }
    }

    fn cell_name(&self, index: usize) -> String {
        let cellvars = &self.code.cellvars;

        let name = if index < cellvars.len() { cellvars.get(index) } else { self.code.freevars.get(index - cellvars.len()) };

        name.map(PyBytes::to_string_lossy).unwrap_or_default()
    }

    /// Reads the instruction at `pc` and advances past it, folding
    /// `EXTENDED_ARG` prefixes.
    fn fetch(&mut self) -> PyResult<(u8, usize)> {
        let start = self.pc;
        let predicted = self.code.code.get(start).is_some_and(|opcode| self.predicts.contains(opcode));
        self.predicts = &[];
        if !predicted {
            self.activation.set_lasti(start);
        }

        let (opcode, argument) = self.decode()?;
        self.last = (opcode, self.pc);

        Ok((opcode, argument))
    }

    /// Sets the opcode predictions after an instruction that
    /// completed without jumping.
    fn predict(&mut self) {
        let (opcode, end) = self.last;
        if self.pc != end {
            return;
        }

        self.predicts = match opcode {
            op::LIST_APPEND | op::SET_ADD | op::MAP_ADD => &[op::JUMP_ABSOLUTE],
            op::COMPARE_OP => &[op::POP_JUMP_IF_FALSE, op::POP_JUMP_IF_TRUE],
            op::GET_ITER => &[op::FOR_ITER],
            op::FOR_ITER => &[op::STORE_FAST, op::UNPACK_SEQUENCE],
            op::WITH_CLEANUP => &[op::END_FINALLY],
            _ => &[],
        };
    }

    /// Decodes the instruction at `pc` and advances past it, folding
    /// `EXTENDED_ARG` prefixes.
    fn decode(&mut self) -> PyResult<(u8, usize)> {
        let mut extended = 0usize;

        loop {
            let Some(&opcode) = self.code.code.get(self.pc) else {
                return Err(self.malformed("execution ran past the end of the code"));
            };

            if opcode < op::HAVE_ARGUMENT {
                self.pc += 1;
                return Ok((opcode, 0));
            }

            let Some(bytes) = self.code.code.get(self.pc + 1..self.pc + 3) else {
                return Err(self.malformed("truncated instruction argument"));
            };

            let argument = (extended << 16) | usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            self.pc += 3;

            if opcode != op::EXTENDED_ARG {
                return Ok((opcode, argument));
            }

            extended = argument;
        }
    }
}

/// Runs `frame` until it returns or yields.
pub fn run_frame(vm: &Vm, frame: &mut Frame) -> PyResult<FrameExit> {
    enter(vm, frame, None)
}

/// Resumes a suspended frame by raising `signal` at its current
/// instruction, as `generator.throw` does.
pub fn resume_raising(vm: &Vm, frame: &mut Frame, signal: Signal) -> PyResult<FrameExit> {
    enter(vm, frame, Some(signal))
}

fn enter(vm: &Vm, frame: &mut Frame, pending: Option<Signal>) -> PyResult<FrameExit> {
    vm.enter_frame(&frame.activation);
    let result = run_loop(vm, frame, pending);
    vm.leave_frame(&frame.activation);

    if let Err(signal) = &result {
        vm.push_trace(signal, frame.location(vm));
    }

    result
}

fn run_loop(vm: &Vm, frame: &mut Frame, mut pending: Option<Signal>) -> PyResult<FrameExit> {
    loop {
        let outcome = match pending.take() {
            Some(signal) => Err(signal),
            None => step(vm, frame),
        };
        // Objects freed by the instruction are finalized before the next
        // one, where CPython's synchronous deallocation would have run.
        vm.run_finalizers()?;

        if let Err(Signal::Raise(exception)) = &outcome
            && !std::mem::take(&mut frame.reraise)
        {
            vm.traceback_here(&frame.activation, exception);
        }

        let why = match outcome {
            Ok(None) => {
                vm.discard_traceback();
                frame.predict();
                continue;
            }
            Ok(Some(Flow::Yield(value))) => return Ok(FrameExit::Yield(value)),
            Ok(Some(Flow::Why(why))) => why,
            Err(signal @ Signal::Halt(_)) => return Err(signal),
            Err(signal) => Why::Exception(signal),
        };

        if let Some(exit) = unwind(vm, frame, why)? {
            return Ok(FrameExit::Return(exit));
        }
    }
}

enum Flow {
    Yield(Value),
    Why(Why),
}

/// Unwinds the block stack for a non-local exit. Returns the frame's return
/// value when no block intercepts the exit.
fn unwind(vm: &Vm, frame: &mut Frame, mut why: Why) -> PyResult<Option<Value>> {
    while let Some(block) = frame.blocks.last().copied() {
        if block.kind == BlockKind::Loop {
            if let Why::Continue(target) = why {
                frame.pc = target;
                return Ok(None);
            }
        }

        frame.blocks.pop();
        frame.stack.truncate(block.level);

        match (block.kind, why) {
            (BlockKind::Loop, Why::Break) => {
                frame.pc = block.handler;
                return Ok(None);
            }
            (kind @ (BlockKind::Finally | BlockKind::Except | BlockKind::With), Why::Exception(Signal::Raise(exception))) => {
                let traceback = vm.take_traceback(&exception).unwrap_or(Value::None);
                // Except and with blocks
                // normalize the exception and make it current; finally
                // blocks do not.
                let exception = match kind {
                    BlockKind::Except => vm.normalize_received(exception)?,
                    BlockKind::With => {
                        vm.mark_normalized(&exception);
                        exception
                    }
                    _ => exception,
                };
                let class = vm.class_of(&exception);
                if kind != BlockKind::Finally {
                    if kind == BlockKind::Except {
                        vm.clear_trace();
                    }
                    vm.set_handled(Handled { exception: exception.clone(), traceback: traceback.clone() });
                }
                frame.push(traceback);
                frame.push(exception);
                frame.push(Value::Object(class));
                frame.pc = block.handler;
                return Ok(None);
            }
            (BlockKind::Finally | BlockKind::With, pending) => {
                let marker = match pending {
                    Why::Return(value) => UnwindMarker::Return(value),
                    Why::Continue(target) => UnwindMarker::Continue(target),
                    Why::Break => UnwindMarker::Break,
                    Why::Exception(signal) => return Err(signal),
                };
                frame.push(vm.new_unwind_marker(marker));
                frame.pc = block.handler;
                return Ok(None);
            }
            (_, pending) => why = pending,
        }
    }

    match why {
        Why::Return(value) => Ok(Some(value)),
        Why::Exception(signal) => Err(signal),
        Why::Break | Why::Continue(_) => Err(frame.malformed("break or continue outside a loop")),
    }
}

fn jump(frame: &mut Frame, target: usize) -> PyResult<()> {
    if target >= frame.code.code.len() {
        return Err(frame.malformed("jump target out of range"));
    }

    frame.pc = target;

    Ok(())
}

fn binary_for(opcode: u8) -> Option<(BinaryOp, bool)> {
    let pair = match opcode {
        op::BINARY_POWER => (BinaryOp::Power, false),
        op::BINARY_MULTIPLY => (BinaryOp::Multiply, false),
        op::BINARY_DIVIDE => (BinaryOp::Divide, false),
        op::BINARY_MODULO => (BinaryOp::Modulo, false),
        op::BINARY_ADD => (BinaryOp::Add, false),
        op::BINARY_SUBTRACT => (BinaryOp::Subtract, false),
        op::BINARY_FLOOR_DIVIDE => (BinaryOp::FloorDivide, false),
        op::BINARY_TRUE_DIVIDE => (BinaryOp::TrueDivide, false),
        op::BINARY_LSHIFT => (BinaryOp::LeftShift, false),
        op::BINARY_RSHIFT => (BinaryOp::RightShift, false),
        op::BINARY_AND => (BinaryOp::And, false),
        op::BINARY_XOR => (BinaryOp::Xor, false),
        op::BINARY_OR => (BinaryOp::Or, false),
        op::INPLACE_POWER => (BinaryOp::Power, true),
        op::INPLACE_MULTIPLY => (BinaryOp::Multiply, true),
        op::INPLACE_DIVIDE => (BinaryOp::Divide, true),
        op::INPLACE_MODULO => (BinaryOp::Modulo, true),
        op::INPLACE_ADD => (BinaryOp::Add, true),
        op::INPLACE_SUBTRACT => (BinaryOp::Subtract, true),
        op::INPLACE_FLOOR_DIVIDE => (BinaryOp::FloorDivide, true),
        op::INPLACE_TRUE_DIVIDE => (BinaryOp::TrueDivide, true),
        op::INPLACE_LSHIFT => (BinaryOp::LeftShift, true),
        op::INPLACE_RSHIFT => (BinaryOp::RightShift, true),
        op::INPLACE_AND => (BinaryOp::And, true),
        op::INPLACE_XOR => (BinaryOp::Xor, true),
        op::INPLACE_OR => (BinaryOp::Or, true),
        _ => return None,
    };

    Some(pair)
}

/// Executes one instruction.
fn step(vm: &Vm, frame: &mut Frame) -> PyResult<Option<Flow>> {
    vm.count_step()?;

    let (opcode, arg) = frame.fetch()?;

    if let Some((operation, inplace)) = binary_for(opcode) {
        let right = frame.pop()?;
        let left = frame.pop()?;
        let mut divide = operation;
        if operation == BinaryOp::Divide && frame.code.flags.contains(CodeFlags::FUTURE_DIVISION) {
            divide = BinaryOp::TrueDivide;
        }
        let result = if inplace { vm.inplace_op(divide, &left, &right)? } else { vm.binary_op(divide, &left, &right)? };
        frame.push(result);
        return Ok(None);
    }

    match opcode {
        op::NOP => {}
        op::POP_TOP => {
            frame.pop()?;
        }
        op::ROT_TWO => {
            let len = frame.stack.len();
            if len < 2 {
                return Err(frame.malformed("value stack underflow"));
            }
            frame.stack.swap(len - 1, len - 2);
        }
        op::ROT_THREE => {
            let top = frame.pop()?;
            let len = frame.stack.len();
            if len < 2 {
                return Err(frame.malformed("value stack underflow"));
            }
            frame.stack.insert(len - 2, top);
        }
        op::ROT_FOUR => {
            let top = frame.pop()?;
            let len = frame.stack.len();
            if len < 3 {
                return Err(frame.malformed("value stack underflow"));
            }
            frame.stack.insert(len - 3, top);
        }
        op::DUP_TOP => {
            let top = frame.top()?.clone();
            frame.push(top);
        }
        op::DUP_TOPX => {
            let len = frame.stack.len();
            if arg == 0 || arg > 5 || arg > len {
                return Err(frame.malformed("invalid DUP_TOPX count"));
            }
            let copies = frame.stack[len - arg..].to_vec();
            frame.stack.extend(copies);
        }
        op::UNARY_POSITIVE | op::UNARY_NEGATIVE | op::UNARY_INVERT | op::UNARY_CONVERT => {
            let operand = frame.pop()?;
            let result = match opcode {
                op::UNARY_POSITIVE => vm.positive(&operand)?,
                op::UNARY_NEGATIVE => vm.negative(&operand)?,
                op::UNARY_INVERT => vm.invert(&operand)?,
                _ => vm.repr(&operand)?,
            };
            frame.push(result);
        }
        op::UNARY_NOT => {
            let operand = frame.pop()?;
            let truth = vm.truthy(&operand, "not")?;
            frame.push(Value::Bool(!truth));
        }
        op::BINARY_SUBSCR => {
            let index = frame.pop()?;
            let container = frame.pop()?;
            frame.push(vm.getitem(&container, &index)?);
        }
        op::SLICE..=33 => {
            let (start, stop) = pop_slice_bounds(frame, opcode - op::SLICE)?;
            let container = frame.pop()?;
            frame.push(vm.get_slice(&container, &start, &stop)?);
        }
        op::STORE_SLICE..=43 => {
            let (start, stop) = pop_slice_bounds(frame, opcode - op::STORE_SLICE)?;
            let container = frame.pop()?;
            let value = frame.pop()?;
            vm.set_slice(&container, &start, &stop, Some(value))?;
        }
        op::DELETE_SLICE..=53 => {
            let (start, stop) = pop_slice_bounds(frame, opcode - op::DELETE_SLICE)?;
            let container = frame.pop()?;
            vm.set_slice(&container, &start, &stop, None)?;
        }
        op::STORE_SUBSCR => {
            let index = frame.pop()?;
            let container = frame.pop()?;
            let value = frame.pop()?;
            vm.setitem(&container, &index, value)?;
        }
        op::DELETE_SUBSCR => {
            let index = frame.pop()?;
            let container = frame.pop()?;
            vm.delitem(&container, &index)?;
        }
        op::STORE_MAP => {
            let key = frame.pop()?;
            let value = frame.pop()?;
            let Value::Object(dict) = frame.top()?.clone() else {
                return Err(frame.malformed("STORE_MAP target is not a dict"));
            };
            vm.dict_set(&dict, key, value)?;
        }
        op::GET_ITER => {
            let iterable = frame.pop()?;
            frame.push(vm.iter(&iterable)?);
        }
        op::FOR_ITER => {
            let iterator = frame.top()?.clone();
            match vm.next(&iterator)? {
                Some(item) => frame.push(item),
                None => {
                    frame.pop()?;
                    jump(frame, frame.pc + arg)?;
                }
            }
        }
        op::PRINT_EXPR | op::PRINT_ITEM | op::PRINT_NEWLINE => {
            if opcode != op::PRINT_NEWLINE {
                frame.pop()?;
            }
        }
        op::PRINT_ITEM_TO => {
            frame.pop()?;
            frame.pop()?;
        }
        op::PRINT_NEWLINE_TO => {
            frame.pop()?;
        }
        op::BREAK_LOOP => return Ok(Some(Flow::Why(Why::Break))),
        op::CONTINUE_LOOP => return Ok(Some(Flow::Why(Why::Continue(arg)))),
        op::LOAD_LOCALS => {
            let Some(locals) = frame.scope.locals() else {
                return Err(vm.raise(ExceptionKind::SystemError, "no locals"));
            };
            frame.push(Value::Object(Rc::clone(locals)));
        }
        op::RETURN_VALUE => {
            let value = frame.pop()?;
            return Ok(Some(Flow::Why(Why::Return(value))));
        }
        op::YIELD_VALUE => {
            let value = frame.pop()?;
            return Ok(Some(Flow::Yield(value)));
        }
        op::IMPORT_STAR => {
            let module = frame.pop()?;
            let locals = frame.scope.fast_to_locals(vm)?;
            let imported = vm.import_star(&module, &locals);
            frame.scope.locals_to_fast(vm)?;
            imported?;
        }
        op::EXEC_STMT => {
            let [program, globals, locals] = pop_array(frame)?;
            crate::interp::builtins::exec::exec_statement(vm, frame, program, globals, locals)?;
        }
        op::POP_BLOCK => {
            if frame.blocks.pop().is_none() {
                return Err(frame.malformed("POP_BLOCK with empty block stack"));
            }
        }
        op::END_FINALLY => return end_finally(vm, frame),
        op::BUILD_CLASS => {
            let namespace = frame.pop()?;
            let bases = frame.pop()?;
            let name = frame.pop()?;
            let class = vm.build_class(&name, &bases, &namespace, &frame.globals)?;
            frame.push(class);
        }
        op::WITH_CLEANUP => with_cleanup(vm, frame)?,
        op::STORE_NAME => {
            let name = frame.name(arg)?;
            let value = frame.pop()?;
            let Some(locals) = frame.scope.locals().cloned() else {
                let shown = vm.repr(&Value::Str(name))?;
                return Err(vm.raise(ExceptionKind::SystemError, &format!("no locals found when storing {}", vm.text_of(&shown).unwrap_or_default())));
            };
            if is_exact_dict(vm, &locals) {
                vm.dict_set(&locals, Value::Str(name), value)?;
            } else {
                vm.setitem(&Value::Object(locals), &Value::Str(name), value)?;
            }
        }
        op::DELETE_NAME => {
            let name = frame.name(arg)?;
            let Some(locals) = frame.scope.locals().cloned() else {
                return Err(vm.raise(ExceptionKind::SystemError, &format!("no locals when deleting {}", name.to_string_lossy())));
            };
            match vm.delitem(&Value::Object(locals), &Value::Str(name.clone())) {
                Ok(()) => {}
                Err(Signal::Raise(_)) => return Err(vm.raise(ExceptionKind::NameError, &format!("name '{}' is not defined", name.to_string_lossy()))),
                Err(halt) => return Err(halt),
            }
        }
        op::UNPACK_SEQUENCE => {
            let sequence = frame.pop()?;
            let items = vm.unpack(&sequence, arg)?;
            frame.stack.extend(items.into_iter().rev());
        }
        op::LIST_APPEND => {
            let item = frame.pop()?;
            let list = frame.peek(arg)?.clone();
            vm.list_append(&list, item)?;
        }
        op::SET_ADD => {
            let item = frame.pop()?;
            let set = frame.peek(arg)?.clone();
            vm.set_add(&set, item)?;
        }
        op::MAP_ADD => {
            let key = frame.pop()?;
            let value = frame.pop()?;
            let Value::Object(dict) = frame.peek(arg)?.clone() else {
                return Err(frame.malformed("MAP_ADD target is not a dict"));
            };
            vm.dict_set(&dict, key, value)?;
        }
        op::STORE_ATTR => {
            let name = frame.name(arg)?;
            let target = frame.pop()?;
            let value = frame.pop()?;
            vm.setattr(&target, &name, value)?;
        }
        op::DELETE_ATTR => {
            let name = frame.name(arg)?;
            let target = frame.pop()?;
            vm.delattr(&target, &name)?;
        }
        op::STORE_GLOBAL => {
            let name = frame.name(arg)?;
            let value = frame.pop()?;
            vm.dict_set(&frame.globals, Value::Str(name), value)?;
        }
        op::DELETE_GLOBAL => {
            let name = frame.name(arg)?;
            if !vm.dict_delete(&frame.globals, &Value::Str(name.clone()))? {
                return Err(vm.raise(ExceptionKind::NameError, &format!("global name '{}' is not defined", name.to_string_lossy())));
            }
        }
        op::LOAD_CONST => {
            let Some(value) = frame.code.consts.get(arg).cloned() else {
                return Err(frame.malformed("constant index out of range"));
            };
            frame.push(value);
        }
        op::LOAD_NAME => {
            let name = frame.name(arg)?;
            let Some(locals) = frame.scope.locals().cloned() else {
                return Err(vm.raise(ExceptionKind::SystemError, &format!("no locals when loading {}", name.to_string_lossy())));
            };
            let value = match load_local_name(vm, &locals, &name)? {
                Some(value) => value,
                None => load_global(vm, frame, &name, "name")?,
            };
            frame.push(value);
        }
        op::LOAD_GLOBAL => {
            let name = frame.name(arg)?;
            let value = load_global(vm, frame, &name, "global name")?;
            frame.push(value);
        }
        op::BUILD_TUPLE => {
            let items = frame.pop_n(arg)?;
            frame.push(Value::tuple(items));
        }
        op::BUILD_LIST => {
            let items = frame.pop_n(arg)?;
            frame.push(vm.new_list(items));
        }
        op::BUILD_SET => {
            // Items are added from the top of the stack down, so the last
            // of equal items is the one kept.
            let mut items = frame.pop_n(arg)?;
            items.reverse();
            let set = vm.new_set_from(&Value::tuple(items))?;
            frame.push(set);
        }
        op::BUILD_MAP => frame.push(Value::Object(vm.new_dict_presized(arg))),
        op::LOAD_ATTR => {
            let name = frame.name(arg)?;
            let target = frame.pop()?;
            frame.push(vm.getattr(&target, &name)?);
        }
        op::COMPARE_OP => {
            let right = frame.pop()?;
            let left = frame.pop()?;
            let result = match arg {
                10 => Value::Bool(vm.exception_matches(&left, &right)?),
                _ => {
                    let Some(operation) = CompareOp::from_arg(arg) else {
                        return Err(frame.malformed("invalid comparison operator"));
                    };
                    vm.compare(&left, &right, operation)?
                }
            };
            frame.push(result);
        }
        op::IMPORT_NAME => {
            let name = frame.name(arg)?;
            let fromlist = frame.pop()?;
            let level = frame.pop()?;
            let locals = frame.scope.locals().cloned();
            let module = vm.import_name(&name, &frame.globals, locals.as_ref(), &fromlist, &level)?;
            frame.push(module);
        }
        op::IMPORT_FROM => {
            let name = frame.name(arg)?;
            let module = frame.top()?.clone();
            let value = vm.import_from(&module, &name)?;
            frame.push(value);
        }
        op::JUMP_FORWARD => jump(frame, frame.pc + arg)?,
        op::JUMP_ABSOLUTE => jump(frame, arg)?,
        op::POP_JUMP_IF_FALSE | op::POP_JUMP_IF_TRUE => {
            let condition = frame.pop()?;
            let truth = vm.truthy(&condition, &frame.describe())?;
            if truth == (opcode == op::POP_JUMP_IF_TRUE) {
                jump(frame, arg)?;
            }
        }
        op::JUMP_IF_FALSE_OR_POP | op::JUMP_IF_TRUE_OR_POP => {
            let condition = frame.top()?.clone();
            let truth = vm.truthy(&condition, &frame.describe())?;
            if truth == (opcode == op::JUMP_IF_TRUE_OR_POP) {
                jump(frame, arg)?;
            } else {
                frame.pop()?;
            }
        }
        op::SETUP_LOOP | op::SETUP_EXCEPT | op::SETUP_FINALLY => {
            let kind = match opcode {
                op::SETUP_LOOP => BlockKind::Loop,
                op::SETUP_EXCEPT => BlockKind::Except,
                _ => BlockKind::Finally,
            };
            frame.blocks.push(Block { kind, handler: frame.pc + arg, level: frame.stack.len() });
        }
        op::SETUP_WITH => {
            let manager = frame.pop()?;
            let exit = vm.special_method(&manager, "__exit__")?;
            let enter = vm.special_method(&manager, "__enter__")?;
            frame.push(exit);
            let entered = vm.call(&enter, CallArgs::default())?;
            frame.blocks.push(Block { kind: BlockKind::With, handler: frame.pc + arg, level: frame.stack.len() });
            frame.push(entered);
        }
        op::LOAD_FAST => {
            let Some(slot) = frame.scope.fast.borrow().get(arg).cloned() else {
                return Err(frame.malformed("local index out of range"));
            };
            let Some(value) = slot else {
                let name = frame.code.varnames.get(arg).map(PyBytes::to_string_lossy).unwrap_or_default();
                return Err(vm.raise(ExceptionKind::UnboundLocalError, &format!("local variable '{name}' referenced before assignment")));
            };
            frame.push(value);
        }
        op::STORE_FAST => {
            let value = frame.pop()?;
            let stored = match frame.scope.fast.borrow_mut().get_mut(arg) {
                Some(slot) => {
                    *slot = Some(value);
                    true
                }
                None => false,
            };
            if !stored {
                return Err(frame.malformed("local index out of range"));
            }
        }
        op::DELETE_FAST => {
            let removed = match frame.scope.fast.borrow_mut().get_mut(arg) {
                Some(slot) => slot.take(),
                None => return Err(frame.malformed("local index out of range")),
            };
            if removed.is_none() {
                let name = frame.code.varnames.get(arg).map(PyBytes::to_string_lossy).unwrap_or_default();
                return Err(vm.raise(ExceptionKind::UnboundLocalError, &format!("local variable '{name}' referenced before assignment")));
            }
        }
        op::RAISE_VARARGS => {
            let parts = frame.pop_n(arg)?;
            let (signal, reraise) = vm.raise_statement(parts)?;
            frame.reraise = reraise;
            return Err(signal);
        }
        op::CALL_FUNCTION | op::CALL_FUNCTION_VAR | op::CALL_FUNCTION_KW | op::CALL_FUNCTION_VAR_KW => {
            let result = call_from_stack(vm, frame, opcode, arg)?;
            frame.push(result);
        }
        op::MAKE_FUNCTION | op::MAKE_CLOSURE => {
            let code = frame.pop()?;
            let closure = if opcode == op::MAKE_CLOSURE { Some(frame.pop()?) } else { None };
            let defaults = frame.pop_n(arg)?;
            let function = vm.make_function(&code, &frame.globals, defaults, closure)?;
            frame.push(function);
        }
        op::BUILD_SLICE => {
            let step = if arg == 3 { frame.pop()? } else { Value::None };
            let stop = frame.pop()?;
            let start = frame.pop()?;
            frame.push(vm.new_slice(start, stop, step));
        }
        op::LOAD_CLOSURE => {
            let cell = frame.cell(arg)?;
            frame.push(Value::Object(cell));
        }
        op::LOAD_DEREF => {
            let cell = frame.cell(arg)?;
            let Payload::Cell(content) = &cell.payload else {
                return Err(frame.malformed("closure slot is not a cell"));
            };
            let Some(value) = content.borrow().clone() else {
                let name = frame.cell_name(arg);
                return Err(vm.raise(ExceptionKind::NameError, &format!("free variable '{name}' referenced before assignment in enclosing scope")));
            };
            frame.push(value);
        }
        op::STORE_DEREF => {
            let value = frame.pop()?;
            let cell = frame.cell(arg)?;
            let Payload::Cell(content) = &cell.payload else {
                return Err(frame.malformed("closure slot is not a cell"));
            };
            *content.borrow_mut() = Some(value);
        }
        op::STOP_CODE => return Err(frame.malformed("STOP_CODE executed")),
        _ => return Err(frame.malformed(&format!("unknown opcode {opcode}"))),
    }

    Ok(None)
}

fn pop_slice_bounds(frame: &mut Frame, variant: u8) -> PyResult<(Value, Value)> {
    let stop = if variant & 2 != 0 { frame.pop()? } else { Value::None };
    let start = if variant & 1 != 0 { frame.pop()? } else { Value::None };

    Ok((start, stop))
}

/// Pops the top three values in stack order.
fn pop_array(frame: &mut Frame) -> PyResult<[Value; 3]> {
    let third = frame.pop()?;
    let second = frame.pop()?;
    let first = frame.pop()?;

    Ok([first, second, third])
}

/// Whether `object` is a `dict` and not a subclass instance.
fn is_exact_dict(vm: &Vm, object: &ObjectRef) -> bool {
    Rc::ptr_eq(&object.class(), &vm.types().dict)
}

/// The `f_locals` step of `LOAD_NAME`: a direct lookup for an exact dict,
/// otherwise `__getitem__` with `KeyError` meaning absent.
fn load_local_name(vm: &Vm, locals: &ObjectRef, name: &PyBytes) -> PyResult<Option<Value>> {
    let key = Value::Str(name.clone());

    if is_exact_dict(vm, locals) {
        return vm.dict_get(locals, &key);
    }

    match vm.getitem(&Value::Object(Rc::clone(locals)), &key) {
        Ok(value) => Ok(Some(value)),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::KeyError) => Ok(None),
        Err(signal) => Err(signal),
    }
}

fn cell_value(cell: &ObjectRef) -> Option<Value> {
    match &cell.payload {
        Payload::Cell(content) => content.borrow().clone(),
        _ => None,
    }
}

/// Discards a Python exception, keeping halts.
fn clear_raise(result: PyResult<()>) -> PyResult<()> {
    match result {
        Err(Signal::Raise(_)) => Ok(()),
        other => other,
    }
}

/// Stores `values` under `names` in `mapping`: last name first, unbound names
/// deleted.
fn store_slots(vm: &Vm, mapping: &Value, names: &[PyBytes], values: &[Option<Value>]) -> PyResult<()> {
    let count = names.len().min(values.len());

    for index in (0..count).rev() {
        let key = Value::Str(names[index].clone());
        let result = match &values[index] {
            Some(value) => vm.setitem(mapping, &key, value.clone()),
            None => vm.delitem(mapping, &key),
        };
        clear_raise(result)?;
    }

    Ok(())
}

/// Copies the values of `names` in `mapping` into `cells`; absent names leave their cell as it is.
fn dict_to_cells(vm: &Vm, mapping: &Value, names: &[PyBytes], cells: &[ObjectRef]) -> PyResult<()> {
    let count = names.len().min(cells.len());

    for index in (0..count).rev() {
        let Some(value) = mapping_value(vm, mapping, &names[index])? else {
            continue;
        };
        if let Payload::Cell(content) = &cells[index].payload {
            *content.borrow_mut() = Some(value);
        }
    }

    Ok(())
}

/// `mapping[name]` with any exception meaning absent.
fn mapping_value(vm: &Vm, mapping: &Value, name: &PyBytes) -> PyResult<Option<Value>> {
    match vm.getitem(mapping, &Value::Str(name.clone())) {
        Ok(value) => Ok(Some(value)),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

fn load_global(vm: &Vm, frame: &Frame, name: &PyBytes, label: &str) -> PyResult<Value> {
    let key = Value::Str(name.clone());

    if let Some(value) = vm.dict_get(&frame.globals, &key)? {
        return Ok(value);
    }

    if let Some(value) = vm.dict_get(&frame.builtins, &key)? {
        return Ok(value);
    }

    let opaque = vm.has_opaque_names(&frame.globals) || frame.scope.locals().is_some_and(|locals| vm.has_opaque_names(locals));
    if opaque {
        return Ok(Value::unknown(format!("name {} from import *", name.to_string_lossy())));
    }

    Err(vm.raise(ExceptionKind::NameError, &format!("{label} '{}' is not defined", name.to_string_lossy())))
}

fn end_finally(vm: &Vm, frame: &mut Frame) -> PyResult<Option<Flow>> {
    let status = frame.pop()?;

    if status.is_none() {
        return Ok(None);
    }

    if let Some(marker) = vm.unwind_marker(&status) {
        let why = match marker {
            UnwindMarker::Return(value) => Why::Return(value),
            UnwindMarker::Continue(target) => Why::Continue(target),
            UnwindMarker::Break => Why::Break,
        };
        return Ok(Some(Flow::Why(why)));
    }

    if vm.is_exception_class(&status) {
        let exception = frame.pop()?;
        let traceback = frame.pop()?;
        vm.set_traceback(&exception, traceback);
        frame.reraise = true;
        return Err(Signal::Raise(exception));
    }

    Err(frame.malformed("END_FINALLY found an unexpected status"))
}

fn with_cleanup(vm: &Vm, frame: &mut Frame) -> PyResult<()> {
    let status = frame.pop()?;

    if status.is_none() || vm.unwind_marker(&status).is_some() {
        let exit = frame.pop()?;
        frame.push(status);
        vm.call(&exit, CallArgs::new(vec![Value::None, Value::None, Value::None]))?;
        return Ok(());
    }

    let exception = frame.pop()?;
    let traceback = frame.pop()?;
    let exit = frame.pop()?;
    frame.push(traceback.clone());
    frame.push(exception.clone());
    frame.push(status.clone());

    let result = vm.call(&exit, CallArgs::new(vec![status, exception, traceback]))?;
    if vm.truthy(&result, "__exit__ result")? {
        frame.pop_n(3)?;
        frame.push(Value::None);
    }

    Ok(())
}

fn call_from_stack(vm: &Vm, frame: &mut Frame, opcode: u8, arg: usize) -> PyResult<Value> {
    let has_varargs = matches!(opcode, op::CALL_FUNCTION_VAR | op::CALL_FUNCTION_VAR_KW);
    let has_kwargs = matches!(opcode, op::CALL_FUNCTION_KW | op::CALL_FUNCTION_VAR_KW);

    let star_kwargs = if has_kwargs { Some(frame.pop()?) } else { None };
    let star_args = if has_varargs { Some(frame.pop()?) } else { None };

    let keyword_count = (arg >> 8) & 0xff;
    let positional_count = arg & 0xff;

    let keyword_items = frame.pop_n(keyword_count * 2)?;
    let mut positional = frame.pop_n(positional_count)?;
    let function = frame.pop()?;

    // The keyword values move off the stack before the call; the
    // `*args` sequence stays alive until the call returns. cPickle
    // observes both through reference counts.
    let mut keywords = Vec::with_capacity(keyword_count);
    let mut keyword_items = keyword_items.into_iter();
    while let (Some(name), Some(value)) = (keyword_items.next(), keyword_items.next()) {
        let Some(name) = vm.as_str_bytes(&name) else {
            return Err(frame.malformed("keyword name is not a string"));
        };
        keywords.push((name, value));
    }

    if let Some(extra) = &star_args {
        positional.extend(vm.star_args(&function, extra)?);
    }

    // Keywords pass straight to a Python function called without `*` or
    // `**` arguments; every other call collects them into a dict first,
    // and the callee sees that dict's order.
    let direct = star_args_absent(has_varargs, has_kwargs) && vm.is_python_function(&function);
    let args = if star_kwargs.is_none() && (keywords.is_empty() || direct) {
        CallArgs { positional, keywords, keyword_dict: None }
    } else {
        vm.merge_star_kwargs(&function, keywords, star_kwargs.as_ref(), positional)?
    };

    vm.call_from_bytecode(&function, args, !star_args_absent(has_varargs, has_kwargs))
}

fn star_args_absent(has_varargs: bool, has_kwargs: bool) -> bool {
    !has_varargs && !has_kwargs
}
