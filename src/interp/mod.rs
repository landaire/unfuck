//! Concrete Python 2.7 interpreter. It emulates the Windows x64 build of
//! CPython 2.7 closely enough to evaluate module bodies, including the
//! iteration order of dicts and sets. Values produced by native code the
//! interpreter does not emulate are unknown; operations on them yield
//! unknown results and branching on them stops evaluation.
//!
//! The interpreter performs no real host access. File system, network,
//! process, registry, console, shared memory, clock, environment,
//! entropy, and dynamic loading operations are never carried out. The
//! embedder's `VmConfig::host_access` decides, per `HostCapability`,
//! whether such an operation yields unknown results (`Access::Stub`) or
//! raises the error the Windows build reports for refused access
//! (`Access::Deny`). Facts about the emulated installation come from
//! `HostFacts` and are configuration, not access. A denied `os.urandom`
//! raises `NotImplementedError`, so `random` seeds from the clock instead,
//! which fails in turn when `Clock` is denied.
//!
//! Evaluation is reproducible. Identities behind `id()`, default reprs,
//! identity hashes, and the fallback ordering come from a per-VM counter,
//! never from host addresses, and no Rust hash table's iteration order
//! reaches Python code or the embedder.
//!
//! Python recursion recurses on the native stack, so the embedder runs the
//! VM on a thread whose stack covers the recursion limit with a margin.
//! Measured on x86-64, each level of the limit uses about 4.5 KiB of stack
//! in an optimized build and 56 KiB in an unoptimized one, so the default
//! limit of 1000 needs about 4.5 MiB or 56 MiB. Compiling source nested as
//! deeply as the parser allows takes about 2.5 MiB or 13 MiB more. Native
//! recursion that CPython does not check either, such as compiling deeply
//! nested `_ast` trees or the repr of directly nested dicts, is bounded
//! only by that stack.

pub mod activation;
pub mod attr;
pub mod buffer;
pub mod builtins;
pub mod call;
pub mod code;
pub mod compiler;
pub mod complex;
pub mod error;
pub mod exceptions;
pub mod frame;
pub mod hash;
pub mod host;
pub mod import;
pub mod instance_layout;
pub mod lib_source;
pub mod lifecycle;
pub mod marshal;
pub mod numbers;
pub mod object;
pub mod ops;
pub mod pydict;
pub mod pyset;
pub mod sequence;
pub mod sse;
pub mod table;
pub mod traceback;
pub mod type_flags;
pub mod types;
pub mod value;
pub mod vm;

pub use error::Halt;
pub use error::InterpError;
pub use error::PyResult;
pub use error::Signal;
pub use exceptions::ExceptionKind;
pub use host::Access;
pub use host::HostAccess;
pub use host::HostCapability;
pub use value::Value;
pub use vm::BuiltinModule;
pub use vm::HostFacts;
pub use vm::HostTimeZone;
pub use vm::ModuleCode;
pub use vm::ModuleSource;
pub use vm::OpensslDefaultPaths;
pub use vm::OpensslVersion;
pub use vm::Vm;
pub use vm::VmConfig;
