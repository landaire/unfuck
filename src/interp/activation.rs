//! Activations: the part of a frame that outlives its execution. The
//! executing `Frame`, the VM's frame stack, frame objects, and tracebacks
//! share one `Activation` per call, as CPython shares one frame object.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::code::CodeFlags;
use crate::interp::code::CodeObject;
use crate::interp::error::PyResult;
use crate::interp::frame::FrameScope;
use crate::interp::value::Object;
use crate::interp::value::ObjectId;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub struct Activation {
    // Fields drop in declaration order; CPython frees a frame's locals
    // before the code, builtins, and globals.
    /// The frame's variables, shared with the executing `Frame`; they stay
    /// alive while a frame object or traceback refers to the activation.
    pub scope: Rc<FrameScope>,
    pub code_object: ObjectRef,
    /// `f_builtins`.
    pub builtins: ObjectRef,
    pub globals: ObjectRef,

    /// `f_lasti`: the offset of the instruction executing or last
    /// executed; -1 before the first.
    lasti: Cell<i64>,
    /// `f_back`: the activation that called this one while it runs. A
    /// generator's is cleared whenever it stops running.
    back: RefCell<Option<Rc<Activation>>>,
    /// The frame object, while one exists.
    object: RefCell<Weak<Object>>,
    /// The identity of the first frame object. A frame object holds its
    /// activation, so the activation cannot hold it; one made again after
    /// the first was freed keeps that identity, as CPython has a single
    /// frame object per frame.
    object_id: Cell<Option<ObjectId>>,
}

impl Activation {
    pub fn new(code_object: ObjectRef, globals: ObjectRef, builtins: ObjectRef, scope: Rc<FrameScope>) -> Self {
        Self { scope, code_object, builtins, globals, lasti: Cell::new(-1), back: RefCell::new(None), object: RefCell::new(Weak::new()), object_id: Cell::new(None) }
    }

    pub fn code(&self) -> &Rc<CodeObject> {
        self.scope.code()
    }

    pub fn lasti(&self) -> i64 {
        self.lasti.get()
    }

    pub fn set_lasti(&self, offset: usize) {
        self.lasti.set(i64::try_from(offset).unwrap_or(i64::MAX));
    }

    /// The line of `f_lasti`, or the first line
    /// before the frame started.
    pub fn line_number(&self) -> u32 {
        let code = self.code();
        match usize::try_from(self.lasti.get()) {
            Ok(offset) => code.line_at(offset),
            Err(_) => code.firstlineno,
        }
    }

    pub fn back(&self) -> Option<Rc<Activation>> {
        self.back.borrow().clone()
    }

    pub fn set_back(&self, back: Option<Rc<Activation>>) {
        *self.back.borrow_mut() = back;
    }

    pub fn is_generator(&self) -> bool {
        self.code().flags.contains(CodeFlags::GENERATOR)
    }

    /// `f_locals` after the fast slots are copied into it.
    pub fn locals_value(&self, vm: &Vm) -> PyResult<Value> {
        Ok(Value::Object(self.scope.fast_to_locals(vm)?))
    }
}

impl Vm {
    /// The frame object of `activation`, created on first request and then
    /// shared, so `sys._getframe()`, `f_back`, and `tb_frame` agree on
    /// identity.
    pub fn frame_object_of(&self, activation: &Rc<Activation>) -> Value {
        if let Some(object) = activation.object.borrow().upgrade() {
            return Value::Object(object);
        }

        let class = Rc::clone(&self.types().frame);
        let payload = Payload::Frame(Rc::clone(activation));
        let object = match activation.object_id.get() {
            Some(id) => self.alloc_as(id, &class, payload),
            None => self.alloc(&class, payload, None),
        };
        activation.object_id.set(Some(object.id));
        *activation.object.borrow_mut() = Rc::downgrade(&object);

        Value::Object(object)
    }
}
