//! Object finalization as CPython 2.7 reference counting performs it.
//!
//! Objects are `Rc`s, so the last strong reference going away is the point
//! where CPython's refcount reaches zero. An object whose death is
//! observable (it is weakly referenced, or its class defines `__del__`)
//! cannot be finalized inside `Drop`, where interpreter borrows may be
//! active. Its `Drop` moves the class, dict, and payload into a fresh `Rc`
//! with the same identity and queues it; the VM finalizes queued objects
//! at the next instruction boundary, in the order CPython 2.7 uses for
//! instances: clear weak references and run their callbacks,
//! then call `__del__`. An object that `__del__` stores somewhere survives.
//!
//! Reference cycles are never freed. CPython 2.7 keeps cycles whose
//! objects define `__del__` too (`gc.garbage`), but collects other cycles
//! at points that depend on allocation counts; those objects stay alive
//! here and their weak reference callbacks never run.
//!
//! Freeing nested more than 50 levels deep is deferred to the outermost
//! free on the thread, as CPython's trashcan does, so a structure of any
//! depth is freed on bounded native stack. CPython 2.7 finalizes instances
//! deferred that way only at a later `gc.collect()`; here they are queued
//! like any other.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::rc::Weak;

use crate::interp::attr::MroLookup;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::object::ClassStyle;
use crate::interp::object::GeneratorState;
use crate::interp::object::MroEntry;
use crate::interp::value::Object;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Lifecycle flags of an object.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Lifecycle(u8);

impl Lifecycle {
    /// A weak reference to the object was created.
    pub const WEAKLY_REFERENCED: Self = Self(1);
    /// Finalization is complete; the next drop frees the object.
    pub const RELEASED: Self = Self(2);

    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    pub fn without(self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }
}

/// Objects whose last reference dropped, waiting to be finalized.
#[derive(Default)]
pub struct FinalizerQueue {
    /// Identifies the VM; its objects carry it as their `owner`.
    serial: u32,
    pending: RefCell<VecDeque<ObjectRef>>,
    /// Cleared while the VM is torn down, when finalizers no longer run.
    open: Cell<bool>,
    /// Exceptions that would be printed to stderr as "Exception ... ignored".
    unraisable: RefCell<Vec<String>>,
}

thread_local! {
    /// The queues of the VMs alive on this thread.
    static QUEUES: RefCell<Vec<Weak<FinalizerQueue>>> = const { RefCell::new(Vec::new()) };
    /// The serial number of the next VM on this thread.
    static NEXT_SERIAL: Cell<u32> = const { Cell::new(1) };
    /// Frees in progress on this thread, each nested in the previous one.
    static RELEASE_DEPTH: Cell<usize> = const { Cell::new(0) };
    /// Frees set aside for the outermost free on this thread.
    static DEFERRED: RefCell<Vec<Garbage>> = const { RefCell::new(Vec::new()) };
}

impl FinalizerQueue {
    /// A queue registered as the current one of this thread.
    pub fn register() -> Rc<Self> {
        let serial = NEXT_SERIAL.try_with(|next| {
            let serial = next.get();
            next.set(serial.wrapping_add(1));
            serial
        });
        let queue = Rc::new(Self { serial: serial.unwrap_or(0), open: Cell::new(true), ..Self::default() });
        let weak = Rc::downgrade(&queue);
        let _ = QUEUES.try_with(|queues| queues.borrow_mut().push(weak));

        queue
    }

    /// Stops finalization and forgets pending objects, as the VM goes away.
    pub fn close(self: &Rc<Self>) {
        self.open.set(false);
        let _ = QUEUES.try_with(|queues| {
            if let Ok(mut queues) = queues.try_borrow_mut() {
                queues.retain(|queue| queue.upgrade().is_some_and(|queue| !Rc::ptr_eq(&queue, self)));
            }
        });

        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        drop(pending);
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn take_unraisable(&self) -> Vec<String> {
        std::mem::take(&mut *self.unraisable.borrow_mut())
    }

    fn pop(&self) -> Option<ObjectRef> {
        self.pending.borrow_mut().pop_front()
    }

    /// Sets aside the objects queued so far, so that a finalizer only
    /// finalizes what dies while it runs.
    fn set_aside(&self) -> VecDeque<ObjectRef> {
        std::mem::take(&mut *self.pending.borrow_mut())
    }

    /// Queues the objects set aside after those queued since.
    fn restore(&self, set_aside: VecDeque<ObjectRef>) {
        self.pending.borrow_mut().extend(set_aside);
    }

    fn is_empty(&self) -> bool {
        self.pending.try_borrow().map_or(true, |pending| pending.is_empty())
    }
}

/// The queue of the VM that allocated an object, while it accepts objects.
fn owner_queue(owner: u32) -> Option<Rc<FinalizerQueue>> {
    let queue = QUEUES.try_with(|queues| queues.try_borrow().ok().and_then(|queues| queues.iter().filter_map(Weak::upgrade).find(|queue| queue.serial == owner)));

    queue.ok().flatten().filter(|queue| queue.open.get())
}

impl Drop for Object {
    fn drop(&mut self) {
        let flags = self.lifecycle.get();
        let observable = !flags.contains(Lifecycle::RELEASED) && (flags.contains(Lifecycle::WEAKLY_REFERENCED) || may_define_finalizer(self));
        let queue = if observable { owner_queue(self.owner) } else { None };
        let Some(queue) = queue else {
            self.release();
            return;
        };
        let Ok(mut pending) = queue.pending.try_borrow_mut() else {
            self.release();
            return;
        };

        let revived = Object {
            id: self.id,
            class: RefCell::new(self.class.get_mut().take()),
            dict: RefCell::new(self.dict.get_mut().take()),
            slots: RefCell::new(std::mem::take(self.slots.get_mut())),
            payload: std::mem::replace(&mut self.payload, Payload::Instance),
            lifecycle: Cell::new(flags),
            owner: self.owner,
        };
        pending.push_back(Rc::new(revived));
    }
}

impl Object {
    /// Frees the contents one free level deeper, or defers them to the
    /// outermost free once the nesting is too deep.
    fn release(&mut self) {
        let contents = ObjectContents {
            class: self.class.get_mut().take(),
            dict: self.dict.get_mut().take(),
            slots: std::mem::take(self.slots.get_mut()),
            payload: std::mem::replace(&mut self.payload, Payload::Instance),
        };

        match ReleaseLevel::enter() {
            Some(level) => {
                contents.free();
                drop(level);
            }
            None => defer(Garbage::Object(contents)),
        }
    }
}

/// One level of nested frees on this thread. The outermost level frees
/// the deferred contents before it ends.
pub(crate) struct ReleaseLevel {
    depth: usize,
}

impl ReleaseLevel {
    /// Enters a free nested in those in progress, or `None` when it is
    /// nested too deep and its contents must be deferred.
    pub(crate) fn enter() -> Option<Self> {
        // CPython's trashcan defers deallocations nested this deep.
        const MAX_NESTED_RELEASES: usize = 50;

        // Thread-local storage is gone only while the thread exits; freeing
        // in place is all that remains.
        let depth = RELEASE_DEPTH.try_with(Cell::get).unwrap_or(0);
        if depth >= MAX_NESTED_RELEASES {
            return None;
        }

        let _ = RELEASE_DEPTH.try_with(|current| current.set(depth + 1));

        Some(Self { depth })
    }
}

impl Drop for ReleaseLevel {
    fn drop(&mut self) {
        if self.depth == 0 {
            while let Some(garbage) = DEFERRED.try_with(|deferred| deferred.borrow_mut().pop()).ok().flatten() {
                garbage.free();
            }
        }

        let _ = RELEASE_DEPTH.try_with(|current| current.set(self.depth));
    }
}

/// The references an object held, taken out of it as it is freed.
struct ObjectContents {
    class: Option<ObjectRef>,
    dict: Option<ObjectRef>,
    slots: Box<[Option<Value>]>,
    payload: Payload,
}

impl ObjectContents {
    /// Frees the slot values and then the instance dict, as CPython does
    /// before the base type's deallocator, then a list's or tuple's items,
    /// the class, and the rest of the payload.
    fn free(mut self) {
        release_slots(self.class.as_ref(), &mut self.slots);
        drop(self.dict.take());
        release_items(&mut self.payload);
        drop(self.class.take());
    }
}

/// Contents whose free was deferred to the outermost free.
enum Garbage {
    Object(ObjectContents),
    /// Tuple items, in the order they are freed.
    Items(Vec<Value>),
}

impl Garbage {
    fn free(self) {
        match self {
            Self::Object(contents) => contents.free(),
            Self::Items(items) => drop(items),
        }
    }
}

/// Sets aside tuple items to be freed by the outermost free, in order.
pub(crate) fn defer_items(items: Vec<Value>) {
    defer(Garbage::Items(items));
}

fn defer(garbage: Garbage) {
    // Without thread-local storage the closure is not run and drops the
    // garbage in place.
    let _ = DEFERRED.try_with(move |deferred| deferred.borrow_mut().push(garbage));
}

/// Clears the slot members of each class from `class` up to the
/// builtin base: the members of the most derived class go first.
fn release_slots(class: Option<&ObjectRef>, slots: &mut Box<[Option<Value>]>) {
    if slots.is_empty() {
        return;
    }

    let mut current = class.map(Rc::clone);
    while let Some(class) = current {
        let Some(layout) = class.as_class().and_then(|data| data.heap_layout.as_ref()) else {
            break;
        };
        let added = layout.members.as_ref().map_or(0, |members| members.len());
        for slot in slots.iter_mut().take(layout.slot_count).skip(layout.slot_count.saturating_sub(added)) {
            drop(slot.take());
        }
        current = layout.base.try_borrow().ok().map(|base| Rc::clone(&base));
    }

    drop(std::mem::take(slots));
}

/// Frees the items of a list or tuple from the last, as CPython
/// does; other containers free theirs in storage order.
fn release_items(payload: &mut Payload) {
    let items = match payload {
        Payload::List(items) => std::mem::take(items.get_mut()),
        Payload::Tuple(items) => match items.unique_items_mut() {
            Some(items) => items.iter_mut().map(|item| std::mem::replace(item, Value::None)).collect(),
            None => return,
        },
        _ => return,
    };

    for item in items.into_iter().rev() {
        drop(item);
    }
}

/// Whether the object's class (or a classic instance's dict) defines
/// `__del__`, decided without running Python code. A borrowed class or
/// dict counts as defining it; `finalize` then looks properly.
fn may_define_finalizer(object: &Object) -> bool {
    if let Payload::Generator(generator) = &object.payload {
        return generator.try_borrow().map_or(true, |generator| matches!(generator.state, GeneratorState::Suspended(_)));
    }
    let Ok(class) = object.class.try_borrow() else {
        return true;
    };
    let Some(class) = class.as_ref() else {
        return false;
    };
    let Some(data) = class.as_class() else {
        return false;
    };
    if data.builtin {
        return false;
    }

    if data.style == ClassStyle::Classic {
        let in_instance = match object.dict.try_borrow() {
            Ok(dict) => dict.as_ref().is_some_and(dict_defines_finalizer),
            Err(_) => true,
        };
        return in_instance || classic_defines_finalizer(class);
    }

    let Ok(mro) = data.mro.try_borrow() else {
        return true;
    };
    mro.iter().any(|entry| match entry {
        MroEntry::Class(ancestor) => ancestor.as_class().is_some_and(|ancestor| !ancestor.builtin && dict_defines_finalizer(&ancestor.dict)),
        MroEntry::Unknown(_) => false,
    })
}

fn classic_defines_finalizer(class: &ObjectRef) -> bool {
    let mut pending = vec![Rc::clone(class)];
    while let Some(next) = pending.pop() {
        let Some(data) = next.as_class() else {
            continue;
        };
        if data.builtin {
            continue;
        }
        if dict_defines_finalizer(&data.dict) {
            return true;
        }
        let Ok(bases) = data.bases.try_borrow() else {
            return true;
        };
        pending.extend(bases.iter().filter_map(|base| base.as_object().map(Rc::clone)));
    }

    false
}

/// Whether `dict` has a `__del__` key. Keys are compared by their bytes,
/// which needs neither hashing nor Python `__eq__`.
fn dict_defines_finalizer(dict: &ObjectRef) -> bool {
    let Some(table) = dict.as_dict() else {
        return false;
    };
    let Ok(table) = table.try_borrow() else {
        return true;
    };

    table.keys().any(|key| key.as_bytes() == Some(b"__del__".as_slice()))
}

impl Vm {
    /// Finalizes the objects whose last reference dropped since the last
    /// call. Python code they run may queue more objects, which are
    /// finalized in turn.
    pub fn run_finalizers(&self) -> PyResult<()> {
        let queue = self.finalizer_queue();
        if queue.is_empty() {
            return Ok(());
        }

        // Finalizers run with the exception in flight set aside and
        // restored afterward.
        let in_flight = self.suspend_traceback();
        let result = self.drain_finalizers(queue);
        self.resume_traceback(in_flight);

        result
    }

    fn drain_finalizers(&self, queue: &FinalizerQueue) -> PyResult<()> {

        // Each object is finalized with the objects queued before it set
        // aside, so that what dies while it is finalized (its contents
        // included) is finalized first, as CPython frees it synchronously.
        let mut set_aside: Vec<VecDeque<ObjectRef>> = Vec::new();
        loop {
            if let Some(object) = queue.pop() {
                set_aside.push(queue.set_aside());
                if let Err(signal) = self.finalize(object) {
                    while let Some(earlier) = set_aside.pop() {
                        queue.restore(earlier);
                    }
                    return Err(signal);
                }
                continue;
            }
            let Some(earlier) = set_aside.pop() else {
                break;
            };
            queue.restore(earlier);
        }

        Ok(())
    }

    /// Exceptions raised by finalizers and weak reference callbacks since
    /// the last call, as they would be printed to stderr.
    pub fn take_unraisable(&self) -> Vec<String> {
        self.finalizer_queue().take_unraisable()
    }

    /// Reports `error` raised in `context` without raising it.
    pub(crate) fn write_unraisable(&self, context: &Value, error: &Value) {
        self.take_traceback(error);
        let context = self.repr_text(context).unwrap_or_else(|_| "?".to_owned());
        let text = self.describe_exception(error);
        self.finalizer_queue().unraisable.borrow_mut().push(format!("Exception {text} in {context} ignored"));
    }

    fn finalize(&self, object: ObjectRef) -> PyResult<()> {
        if object.lifecycle.get().contains(Lifecycle::WEAKLY_REFERENCED) {
            object.lifecycle.set(object.lifecycle.get().without(Lifecycle::WEAKLY_REFERENCED));
            crate::interp::builtins::modules::clear_weak_references(self, &object, true)?;
        }

        if matches!(object.payload, Payload::Generator(_)) {
            // A paused generator is closed.
            let generator = Value::Object(Rc::clone(&object));
            match self.call_method(&generator, "close", Vec::new()) {
                Ok(_) => {}
                Err(Signal::Raise(error)) => self.write_unraisable(&generator, &error),
                Err(halt) => return Err(halt),
            }
        }

        match self.finalizer_of(&object) {
            Ok(Some(method)) => match self.call0(&method) {
                Ok(_) => {}
                Err(Signal::Raise(error)) => self.write_unraisable(&method, &error),
                Err(halt) => return Err(halt),
            },
            Ok(None) => {}
            Err(Signal::Raise(error)) => self.write_unraisable(&Value::Object(Rc::clone(&object)), &error),
            Err(halt) => return Err(halt),
        }

        if Rc::strong_count(&object) > 1 {
            return Ok(());
        }

        // Weak references made by `__del__` die without callbacks.
        if object.lifecycle.get().contains(Lifecycle::WEAKLY_REFERENCED) {
            crate::interp::builtins::modules::clear_weak_references(self, &object, false)?;
        }
        object.lifecycle.set(Lifecycle::RELEASED);

        Ok(())
    }

    /// The bound `__del__` of a dying object: looked up on the type for
    /// new-style instances, and in the instance dict then
    /// the class for classic ones.
    fn finalizer_of(&self, object: &ObjectRef) -> PyResult<Option<Value>> {
        let Some(class) = object.class.borrow().clone() else {
            return Ok(None);
        };
        let Some(data) = class.as_class() else {
            return Ok(None);
        };
        if data.builtin {
            return Ok(None);
        }

        let name = PyBytes::from("__del__");
        let target = Value::Object(Rc::clone(object));
        if data.style == ClassStyle::Classic
            && let Some(dict) = object.dict()
            && let Some(found) = self.dict_get(&dict, &Value::Str(name))?
        {
            return Ok(Some(found));
        }

        match self.lookup_mro(&class, "__del__")? {
            MroLookup::Found { value, .. } => Ok(Some(self.descriptor_get(&value, Some(target), &class)?)),
            _ => Ok(None),
        }
    }
}
