use crate::interp::value::Value;

#[derive(Debug, thiserror::Error)]
pub enum MarshalError {
    #[error("unmarshalling raised {rendered}")]
    Raised { rendered: String },
    #[error("unmarshalling halted: {0}")]
    Halted(Halt),
    #[error("root object is not a code object")]
    NotCode,
}

/// Why evaluation stopped without a Python-level exception. These cannot be
/// caught by Python code: the interpreter cannot tell what the real client
/// would have done.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Halt {
    #[error("branch on unknown value ({origin}) in {context}")]
    UnknownCondition { context: String, origin: String },
    #[error("iteration over unknown value ({origin})")]
    UnknownIteration { origin: String },
    #[error("unknown value ({origin}) used as a dict or set key")]
    UnknownHash { origin: String },
    #[error("unsupported: {feature}")]
    Unsupported { feature: String },
    #[error("malformed bytecode in {code}: {detail}")]
    MalformedCode { code: String, detail: String },
    #[error("recursion limit exceeded")]
    RecursionLimit,
    #[error("instruction limit exceeded")]
    StepLimit,
}

/// Non-local exit from evaluation.
#[derive(Debug, Clone)]
pub enum Signal {
    /// A Python exception, carried as the exception instance.
    Raise(Value),
    Halt(Halt),
}

impl From<Halt> for Signal {
    fn from(halt: Halt) -> Self {
        Self::Halt(halt)
    }
}

pub type PyResult<T> = Result<T, Signal>;

/// Failure of a host-level operation, with the Python exception rendered.
#[derive(Debug, thiserror::Error)]
pub enum InterpError {
    #[error("Python exception: {rendered}")]
    Exception { rendered: String },
    #[error(transparent)]
    Halt(#[from] Halt),
    #[error(transparent)]
    Marshal(#[from] MarshalError),
    #[error("module {name} not found")]
    ModuleNotFound { name: String },
}
