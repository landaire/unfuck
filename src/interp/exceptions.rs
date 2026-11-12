use std::cell::OnceCell;
use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::object::CallArgs;
use crate::interp::traceback::Handled;
use crate::interp::traceback::is_traceback;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::UnwindMarker;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

macro_rules! exception_kinds {
    ($($kind:ident => $parent:expr),* $(,)?) => {
        /// The CPython 2.7 builtin exception classes.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ExceptionKind {
            $($kind,)*
        }

        impl ExceptionKind {
            /// Every kind, parents before children.
            pub const ALL: &'static [ExceptionKind] = &[$(ExceptionKind::$kind,)*];

            pub fn name(self) -> &'static str {
                match self {
                    $(ExceptionKind::$kind => stringify!($kind),)*
                }
            }

            /// Base class; `None` for `BaseException`, whose base is `object`.
            pub fn parent(self) -> Option<ExceptionKind> {
                match self {
                    $(ExceptionKind::$kind => $parent,)*
                }
            }
        }
    };
}

exception_kinds! {
    BaseException => None,
    SystemExit => Some(ExceptionKind::BaseException),
    KeyboardInterrupt => Some(ExceptionKind::BaseException),
    GeneratorExit => Some(ExceptionKind::BaseException),
    Exception => Some(ExceptionKind::BaseException),
    StopIteration => Some(ExceptionKind::Exception),
    StandardError => Some(ExceptionKind::Exception),
    BufferError => Some(ExceptionKind::StandardError),
    ArithmeticError => Some(ExceptionKind::StandardError),
    FloatingPointError => Some(ExceptionKind::ArithmeticError),
    OverflowError => Some(ExceptionKind::ArithmeticError),
    ZeroDivisionError => Some(ExceptionKind::ArithmeticError),
    AssertionError => Some(ExceptionKind::StandardError),
    AttributeError => Some(ExceptionKind::StandardError),
    EnvironmentError => Some(ExceptionKind::StandardError),
    IOError => Some(ExceptionKind::EnvironmentError),
    OSError => Some(ExceptionKind::EnvironmentError),
    WindowsError => Some(ExceptionKind::OSError),
    EOFError => Some(ExceptionKind::StandardError),
    ImportError => Some(ExceptionKind::StandardError),
    LookupError => Some(ExceptionKind::StandardError),
    IndexError => Some(ExceptionKind::LookupError),
    KeyError => Some(ExceptionKind::LookupError),
    MemoryError => Some(ExceptionKind::StandardError),
    NameError => Some(ExceptionKind::StandardError),
    UnboundLocalError => Some(ExceptionKind::NameError),
    ReferenceError => Some(ExceptionKind::StandardError),
    RuntimeError => Some(ExceptionKind::StandardError),
    NotImplementedError => Some(ExceptionKind::RuntimeError),
    SyntaxError => Some(ExceptionKind::StandardError),
    IndentationError => Some(ExceptionKind::SyntaxError),
    TabError => Some(ExceptionKind::IndentationError),
    SystemError => Some(ExceptionKind::StandardError),
    TypeError => Some(ExceptionKind::StandardError),
    ValueError => Some(ExceptionKind::StandardError),
    UnicodeError => Some(ExceptionKind::ValueError),
    UnicodeDecodeError => Some(ExceptionKind::UnicodeError),
    UnicodeEncodeError => Some(ExceptionKind::UnicodeError),
    UnicodeTranslateError => Some(ExceptionKind::UnicodeError),
    Warning => Some(ExceptionKind::Exception),
    UserWarning => Some(ExceptionKind::Warning),
    DeprecationWarning => Some(ExceptionKind::Warning),
    PendingDeprecationWarning => Some(ExceptionKind::Warning),
    SyntaxWarning => Some(ExceptionKind::Warning),
    RuntimeWarning => Some(ExceptionKind::Warning),
    FutureWarning => Some(ExceptionKind::Warning),
    ImportWarning => Some(ExceptionKind::Warning),
    UnicodeWarning => Some(ExceptionKind::Warning),
    BytesWarning => Some(ExceptionKind::Warning),
}

impl Vm {
    /// A builtin exception with a message, ready to propagate.
    pub fn raise(&self, kind: ExceptionKind, message: &str) -> Signal {
        let class = Rc::clone(self.types().exception(kind));

        self.raise_string(&class, Value::str(message))
    }

    /// An exception of `class` raised by native code with a string value.
    /// It stays unnormalized until an
    /// `except` or `with` block receives it. Native code sets the value without a
    /// call, so creating the instance does not count toward the recursion
    /// limit.
    pub fn raise_string(&self, class: &ObjectRef, message: Value) -> Signal {
        match self.without_depth(|| self.instantiate_exception(class, vec![message])) {
            Ok(exception) => {
                if let Some(object) = exception.as_object() {
                    self.mark_unnormalized(object);
                }
                Signal::Raise(exception)
            }
            Err(signal) => signal,
        }
    }

    /// Normalizes `exception` as an `except` block receives it.
    /// Normalizing an exception native code raised calls its
    /// class; past the recursion limit that fails
    /// and a preallocated `RuntimeError` instance takes its place.
    pub(crate) fn normalize_received(&self, exception: Value) -> PyResult<Value> {
        let unnormalized = exception.as_object().is_some_and(|object| self.is_unnormalized(object));
        self.mark_normalized(&exception);
        if !unnormalized || !self.is_recursion_exhausted() {
            return Ok(exception);
        }

        let instance = self.native_state::<RecursionErrorInstance>();
        if let Some(error) = instance.0.get() {
            return Ok(error.clone());
        }
        let class = Rc::clone(self.types().exception(ExceptionKind::RuntimeError));
        let error = self.without_depth(|| self.instantiate_exception(&class, vec![Value::str("maximum recursion depth exceeded")]))?;

        Ok(instance.0.get_or_init(|| error).clone())
    }

    /// The string value of `exception` when native code raised it and it is
    /// still unnormalized.
    pub fn unnormalized_message(&self, exception: &Value) -> Option<PyBytes> {
        let object = exception.as_object()?;
        if !self.is_unnormalized(object) {
            return None;
        }
        let Payload::Exception(data) = &object.payload else {
            return None;
        };
        let args = data.args.borrow();
        let Value::Tuple(items) = &*args else {
            return None;
        };

        match &items[..] {
            [Value::Str(message)] => Some(message.clone()),
            _ => None,
        }
    }

    pub fn type_error(&self, message: &str) -> Signal {
        self.raise(ExceptionKind::TypeError, message)
    }

    /// Whether `value` is an instance of a builtin exception class.
    pub fn is_exception(&self, value: &Value, kind: ExceptionKind) -> bool {
        let class = Rc::clone(self.types().exception(kind));

        self.is_instance_of(value, &class).unwrap_or(false)
    }

    /// Calls an exception class with arguments.
    pub fn instantiate_exception(&self, class: &crate::interp::value::ObjectRef, args: Vec<Value>) -> PyResult<Value> {
        self.call(&Value::Object(Rc::clone(class)), CallArgs::new(args))
    }

    /// Whether `value` is a class usable as an exception type: any class
    /// derived from `BaseException`, or any classic class.
    pub fn is_exception_class(&self, value: &Value) -> bool {
        let Value::Object(object) = value else {
            return false;
        };

        if object.as_class().is_none() {
            return false;
        }
        if self.is_classic_class(object) {
            return true;
        }

        let base = Rc::clone(self.types().exception(ExceptionKind::BaseException));

        self.is_subclass(object, &base).unwrap_or(false)
    }

    /// `COMPARE_OP exception match`.
    pub fn exception_matches(&self, raised: &Value, pattern: &Value) -> PyResult<bool> {
        if let Value::Tuple(items) = pattern {
            for item in items.iter() {
                if self.exception_matches(raised, item)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        }

        if pattern.is_unknown() {
            return Err(Signal::Halt(crate::interp::error::Halt::UnknownCondition { context: "except clause".to_owned(), origin: format!("{pattern:?}") }));
        }

        let (Value::Object(raised_class), Value::Object(pattern_class)) = (raised, pattern) else {
            return Ok(self.is_same(raised, pattern));
        };

        if pattern_class.as_class().is_none() {
            return Ok(Rc::ptr_eq(raised_class, pattern_class));
        }

        self.is_subclass(raised_class, pattern_class)
    }

    /// `RAISE_VARARGS`; a bare `raise` re-raises the exception
    /// being handled. Sets the traceback
    /// of the raised exception and reports whether it is re-raised with a
    /// traceback, which the raising frame does not extend.
    pub fn raise_statement(&self, parts: Vec<Value>) -> PyResult<(Signal, bool)> {
        if parts.is_empty() {
            return Ok(match self.handled_exception() {
                Some(Handled { exception, traceback }) => {
                    self.mark_normalized(&exception);
                    let reraise = !traceback.is_none();
                    self.set_traceback(&exception, traceback);
                    (Signal::Raise(exception), reraise)
                }
                None => (self.type_error("exceptions must be old-style classes or derived from BaseException, not NoneType"), false),
            });
        }

        let mut parts = parts;
        let traceback = parts.get(2).cloned().unwrap_or(Value::None);
        if !traceback.is_none() && !is_traceback(&traceback) {
            return Ok((self.type_error("raise: arg 3 must be a traceback or None"), false));
        }

        let exception = match self.raise_signal(std::mem::take(&mut parts))? {
            Ok(exception) => exception,
            Err(signal) => return Ok((signal, false)),
        };
        let reraise = !traceback.is_none();
        self.set_traceback(&exception, traceback);

        Ok((Signal::Raise(exception), reraise))
    }

    /// The exception a `raise` statement builds from its type and value.
    fn raise_signal(&self, mut parts: Vec<Value>) -> PyResult<Result<Value, Signal>> {
        let mut kind = parts.remove(0);
        let value = if parts.is_empty() { Value::None } else { parts.remove(0) };

        // `raise (A, B), value` raises A: leading tuples are unwrapped.
        while let Value::Tuple(items) = &kind {
            let Some(first) = items.first() else {
                break;
            };
            kind = first.clone();
        }

        if kind.is_unknown() {
            return Err(Signal::Halt(crate::interp::error::Halt::UnknownCondition { context: "raise".to_owned(), origin: format!("{kind:?}") }));
        }

        if self.is_exception_class(&kind) {
            let Value::Object(class) = &kind else {
                return Ok(Err(self.type_error("exceptions must be classes or instances")));
            };
            if !value.is_none() && self.is_instance_of(&value, class).unwrap_or(false) {
                self.mark_normalized(&value);
                return Ok(Ok(value));
            }
            let args = match value {
                Value::None => Vec::new(),
                Value::Tuple(items) => items.to_vec(),
                other => vec![other],
            };
            return Ok(Ok(self.instantiate_exception(class, args)?));
        }

        if !value.is_none() {
            return Ok(Err(self.type_error("instance exception may not have a separate value")));
        }

        let class = self.class_of(&kind);
        if self.is_exception_class(&Value::Object(class)) {
            self.mark_normalized(&kind);
            return Ok(Ok(kind));
        }

        Ok(Err(self.type_error(&format!("exceptions must be old-style classes or derived from BaseException, not {}", self.type_name(&kind)))))
    }

    pub fn new_unwind_marker(&self, marker: UnwindMarker) -> Value {
        let class = Rc::clone(&self.types().unwind);

        Value::Object(self.alloc(&class, Payload::Unwind(marker), None))
    }

    pub fn unwind_marker(&self, value: &Value) -> Option<UnwindMarker> {
        match value.as_object().map(|object| &object.payload) {
            Some(Payload::Unwind(marker)) => Some(marker.clone()),
            _ => None,
        }
    }

    /// Renders an exception for diagnostics: `TypeError: message`.
    pub fn describe_exception(&self, exception: &Value) -> String {
        let class = self.class_of(exception);
        // The top-level error report prints the type name after its last dot.
        let full_name = self.class_name(&class);
        let name = full_name.rsplit('.').next().unwrap_or_default().to_owned();
        let message = match exception.as_object().map(|object| &object.payload) {
            Some(Payload::Exception(data)) => {
                let args = data.args.borrow().clone();
                match self.as_tuple(&args) {
                    Some(items) if items.len() == 1 => self.text_of(&items[0]).unwrap_or_else(|| format!("{:?}", items[0])),
                    Some(items) => format!("{items:?}"),
                    None => String::new(),
                }
            }
            _ => String::new(),
        };

        if message.is_empty() { name } else { format!("{name}: {message}") }
    }
}

/// The preallocated `RuntimeError` instance normalization substitutes
/// past the recursion limit.
#[derive(Default)]
struct RecursionErrorInstance(OnceCell<Value>);
