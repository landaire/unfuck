//! The embedder's policy for operations that would reach the host system.
//! The interpreter never performs them. Each one either yields an unknown
//! value or raises the error the Windows build reports when access is
//! refused.

use std::rc::Rc;

use crate::interp::builtins::modules::socket::socket_error;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A class of host resource that client code can reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostCapability {
    /// Files, directories, and file descriptors.
    FileSystem,
    /// Sockets, name resolution, and `select`.
    Network,
    /// Spawning, signalling, and waiting on processes and handles.
    Process,
    /// The Windows registry.
    Registry,
    /// `msvcrt` console functions and reads from standard input.
    Console,
    /// File- or tag-backed `mmap`, `_multiprocessing` shared memory and
    /// handles, and anything that reads or writes another process's memory.
    SharedMemory,
    /// The wall clock, process times, and performance counters.
    Clock,
    /// Environment variables and the user's locale.
    Environment,
    /// OS entropy and process identity.
    Randomness,
    /// Loading native extension modules.
    DynamicLoading,
}

impl HostCapability {
    pub const ALL: [Self; 10] = [
        Self::FileSystem,
        Self::Network,
        Self::Process,
        Self::Registry,
        Self::Console,
        Self::SharedMemory,
        Self::Clock,
        Self::Environment,
        Self::Randomness,
        Self::DynamicLoading,
    ];

    fn index(self) -> usize {
        self as usize
    }

    fn description(self) -> &'static str {
        match self {
            Self::FileSystem => "file system",
            Self::Network => "network",
            Self::Process => "process",
            Self::Registry => "registry",
            Self::Console => "console",
            Self::SharedMemory => "shared memory",
            Self::Clock => "clock",
            Self::Environment => "environment",
            Self::Randomness => "random source",
            Self::DynamicLoading => "dynamic loading",
        }
    }
}

/// How the interpreter answers an operation of one capability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Access {
    /// The operation yields unknown values.
    #[default]
    Stub,
    /// The operation raises the error of a refused access.
    Deny,
}

/// One `Access` per `HostCapability`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAccess {
    access: [Access; HostCapability::ALL.len()],
}

impl HostAccess {
    pub fn stub_all() -> Self {
        Self { access: [Access::Stub; HostCapability::ALL.len()] }
    }

    pub fn deny_all() -> Self {
        Self { access: [Access::Deny; HostCapability::ALL.len()] }
    }

    pub fn with(mut self, capability: HostCapability, access: Access) -> Self {
        self.set(capability, access);
        self
    }

    pub fn set(&mut self, capability: HostCapability, access: Access) {
        self.access[capability.index()] = access;
    }

    pub fn access(&self, capability: HostCapability) -> Access {
        self.access[capability.index()]
    }
}

impl Default for HostAccess {
    fn default() -> Self {
        Self::stub_all()
    }
}

/// The exception form a refused operation raises, where a capability's
/// sites differ in how the Windows build reports the refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The capability's usual error.
    Native,
    /// `IOError(13, 'Permission denied')`, as raised by the CRT file layer
    /// behind `open`, `file`, and `io.FileIO`.
    Crt,
    /// `NotImplementedError`, the error `os.urandom` raises when no entropy
    /// source exists. `random.py` catches it and seeds from the clock, so
    /// `import random` succeeds unless `Clock` is denied as well.
    Unavailable,
}

impl Vm {
    pub fn host_access(&self, capability: HostCapability) -> Access {
        self.config.host_access.access(capability)
    }

    /// The result of a host operation that arguments have already been
    /// validated for: unknown under `Stub`, the refusal under `Deny`.
    pub fn host_operation(&self, capability: HostCapability, origin: impl Into<String>) -> PyResult<Value> {
        self.host_operation_on(capability, origin, Denial::Native, None)
    }

    /// `host_operation` for an operation on a named file, which the
    /// refusal reports.
    pub fn host_operation_on(
        &self,
        capability: HostCapability,
        origin: impl Into<String>,
        denial: Denial,
        filename: Option<&Value>,
    ) -> PyResult<Value> {
        self.host_permit(capability, denial, filename)?;

        Ok(Value::unknown(origin))
    }

    /// Succeeds under `Stub`. For sites whose stubbed effect is not a single
    /// unknown value.
    pub fn host_permit(&self, capability: HostCapability, denial: Denial, filename: Option<&Value>) -> PyResult<()> {
        match self.host_access(capability) {
            Access::Stub => Ok(()),
            Access::Deny => Err(self.host_denial(capability, denial, filename)),
        }
    }

    fn host_denial(&self, capability: HostCapability, denial: Denial, filename: Option<&Value>) -> Signal {
        let result = match (capability, denial) {
            (_, Denial::Crt) => self.errno_exception(ExceptionKind::IOError, 13, "Permission denied", filename),
            (_, Denial::Unavailable) => {
                let message = format!("{} access is denied by the host policy", capability.description());
                return self.raise(ExceptionKind::NotImplementedError, &message);
            }
            (HostCapability::FileSystem | HostCapability::Process | HostCapability::Registry | HostCapability::SharedMemory, Denial::Native) => {
                self.errno_exception(ExceptionKind::WindowsError, 5, "Access is denied", filename)
            }
            (HostCapability::Network, Denial::Native) => socket_error(self).and_then(|class| {
                self.instantiate_exception(&class, vec![Value::Int(10013), Value::str("Access denied")])
            }),
            (HostCapability::DynamicLoading, Denial::Native) => {
                return self.raise(ExceptionKind::ImportError, "DLL load failed: Access is denied.");
            }
            (HostCapability::Console | HostCapability::Clock | HostCapability::Environment | HostCapability::Randomness, Denial::Native) => {
                let message = format!("{} access is denied by the host policy", capability.description());
                return self.raise(ExceptionKind::OSError, &message);
            }
        };

        match result {
            Ok(exception) => Signal::Raise(exception),
            Err(signal) => signal,
        }
    }

    fn errno_exception(&self, kind: ExceptionKind, code: i64, message: &str, filename: Option<&Value>) -> PyResult<Value> {
        let class = Rc::clone(self.types().exception(kind));
        let mut args = vec![Value::Int(code), Value::str(message)];
        if let Some(filename) = filename {
            args.push(filename.clone());
        }

        self.instantiate_exception(&class, args)
    }
}
