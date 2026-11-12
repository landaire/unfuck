//! Traceback objects and the traceback of the
//! exception in flight.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::activation::Activation;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::error::PyResult;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A computed attribute's getter.
type Getter = fn(&Vm, &GetSet, &Value) -> PyResult<Value>;

/// One traceback entry.
pub struct Traceback {
    next: Option<Value>,
    frame: Value,
    activation: Rc<Activation>,
    lasti: i64,
    lineno: u32,
}

impl_native_data!(Traceback, "traceback");

/// The traceback of the exception being raised, kept with that exception
/// so that one swallowed by native code does not lend its traceback to the
/// next.
#[derive(Default)]
pub struct InFlight {
    current: RefCell<Option<(Value, Value)>>,
}

/// An exception a frame handles (`sys.exc_info()`), with its traceback.
#[derive(Clone)]
pub struct Handled {
    pub exception: Value,
    pub traceback: Value,
}

impl Vm {
    /// Records that `exception` passes through
    /// `activation`, on top of its traceback so far.
    pub fn traceback_here(&self, activation: &Rc<Activation>, exception: &Value) {
        let previous = self.take_traceback(exception);
        let lasti = activation.lasti();
        let traceback = Traceback { next: previous, frame: self.frame_object_of(activation), activation: Rc::clone(activation), lasti, lineno: activation.line_number() };
        let class = Rc::clone(&self.types().traceback);
        let traceback = Value::Object(self.alloc(&class, Payload::Native(Box::new(traceback)), None));

        *self.in_flight().current.borrow_mut() = Some((exception.clone(), traceback));
    }

    /// The traceback of `exception` while it is raised, removed from the
    /// thread state.
    pub fn take_traceback(&self, exception: &Value) -> Option<Value> {
        let in_flight = self.in_flight();
        let mut current = in_flight.current.borrow_mut();
        let matches = current.as_ref().is_some_and(|(raised, _)| self.is_same(raised, exception));
        if !matches {
            return None;
        }

        current.take().map(|(_, traceback)| traceback)
    }

    /// Sets the traceback of the exception about to be raised;
    /// `None` traceback values clear it.
    pub fn set_traceback(&self, exception: &Value, traceback: Value) {
        let entry = if traceback.is_none() { None } else { Some((exception.clone(), traceback)) };
        *self.in_flight().current.borrow_mut() = entry;
    }

    /// Drops the traceback of an exception that native code swallowed: an
    /// instruction that completes means no exception is in flight.
    pub fn discard_traceback(&self) {
        let in_flight = self.in_flight();
        let stale = in_flight.current.try_borrow().is_ok_and(|current| current.is_some());
        if stale {
            in_flight.current.borrow_mut().take();
        }
    }

    /// Sets aside the traceback in flight around code that must not see or
    /// disturb it, such as finalizers.
    pub fn suspend_traceback(&self) -> Option<(Value, Value)> {
        self.in_flight().current.borrow_mut().take()
    }

    pub fn resume_traceback(&self, saved: Option<(Value, Value)>) {
        if saved.is_some() {
            *self.in_flight().current.borrow_mut() = saved;
        }
    }

    fn in_flight(&self) -> Rc<InFlight> {
        self.native_state::<InFlight>()
    }

    /// The traceback's entries from the outermost frame inward, as
    /// `(filename, line, function name)`, for diagnostics.
    pub fn traceback_entries(&self, traceback: &Value) -> Vec<(String, u32, String)> {
        let mut entries = Vec::new();
        let mut current = traceback.clone();
        while let Some(entry) = native_data::<Traceback>(&current) {
            let code = entry.activation.code();
            entries.push((code.filename.to_string_lossy(), entry.lineno, code.name.to_string_lossy()));
            let Some(next) = entry.next.clone() else {
                break;
            };
            current = next;
        }

        entries
    }
}

/// Whether `value` is a traceback object.
pub fn is_traceback(value: &Value) -> bool {
    native_data::<Traceback>(value).is_some()
}

/// Installs the fields of `traceback` objects.
pub fn install(vm: &Vm) -> PyResult<()> {
    let class = Rc::clone(&vm.types().traceback);
    vm.register_extension_type(&class);

    let fields: [(&'static str, Getter); 4] = [
        ("tb_next", |vm, getset, instance| Ok(field(vm, getset, instance)?.next.clone().unwrap_or(Value::None))),
        ("tb_frame", |vm, getset, instance| Ok(field(vm, getset, instance)?.frame.clone())),
        ("tb_lasti", |vm, getset, instance| Ok(Value::Int(field(vm, getset, instance)?.lasti))),
        ("tb_lineno", |vm, getset, instance| Ok(Value::Int(i64::from(field(vm, getset, instance)?.lineno)))),
    ];
    for (name, get) in fields {
        add_member(vm, &class, GetSet { name, owner: "traceback", get, set: None })?;
    }

    Ok(())
}

fn field<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Traceback> {
    native_data::<Traceback>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))))
}
