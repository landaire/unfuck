//! `VmConfig::host_access` decides whether host operations yield unknown
//! values or raise the refusal the Windows build reports, and the
//! interpreter source contains no real host access.

use std::path::Path;
use std::path::PathBuf;

use unfuck::interp::Access;
use unfuck::interp::HostAccess;
use unfuck::interp::HostCapability;
use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Signal;
use unfuck::interp::Value;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::object::CallArgs;

struct NoModules;

impl ModuleSource for NoModules {
    fn find(&self, _name: &str) -> Option<ModuleCode> {
        None
    }
}

/// One representative operation per capability and the refusal it raises.
struct Probe {
    capability: HostCapability,
    expression: &'static str,
    denial: &'static str,
}

const PROBES: &[Probe] = &[
    Probe {
        capability: HostCapability::FileSystem,
        expression: "open('C:\\\\data.txt')",
        denial: "IOError(13, 'Permission denied')",
    },
    Probe {
        capability: HostCapability::Network,
        expression: "__import__('_socket').gethostname()",
        denial: "error(10013, 'Access denied')",
    },
    Probe {
        capability: HostCapability::Process,
        expression: "__import__('nt').system('dir')",
        denial: "WindowsError(5, 'Access is denied')",
    },
    Probe {
        capability: HostCapability::Registry,
        expression: "__import__('_winreg').OpenKey(-2147483646, 'SOFTWARE')",
        denial: "WindowsError(5, 'Access is denied')",
    },
    Probe {
        capability: HostCapability::Console,
        expression: "__import__('msvcrt').getch()",
        denial: "OSError('console access is denied by the host policy',)",
    },
    Probe {
        capability: HostCapability::SharedMemory,
        expression: "__import__('mmap').mmap(-1, 16, 'tag')",
        denial: "WindowsError(5, 'Access is denied')",
    },
    Probe {
        capability: HostCapability::Clock,
        expression: "__import__('time').time()",
        denial: "OSError('clock access is denied by the host policy',)",
    },
    Probe {
        capability: HostCapability::Environment,
        expression: "__import__('nt').putenv('A', 'B')",
        denial: "OSError('environment access is denied by the host policy',)",
    },
    Probe {
        capability: HostCapability::Randomness,
        expression: "__import__('nt').urandom(4)",
        denial: "NotImplementedError('random source access is denied by the host policy',)",
    },
    Probe {
        capability: HostCapability::DynamicLoading,
        expression: "__import__('imp').load_dynamic('x', 'x.pyd')",
        denial: "ImportError('DLL load failed: Access is denied.',)",
    },
];

fn vm(access: HostAccess) -> Vm {
    let mut config = VmConfig::windows_x64();
    config.host_access = access;

    match Vm::new(config, Box::new(NoModules)) {
        Ok(vm) => vm,
        Err(_) => panic!("interpreter bootstrap failed"),
    }
}

/// `repr` of the expression's value, or of the exception it raised.
fn outcome(vm: &Vm, expression: &str) -> String {
    let Ok(builtins) = vm.import_module("__builtin__") else {
        return "import of __builtin__ failed".to_owned();
    };
    let Ok(eval) = vm.getattr_str(&builtins, "eval") else {
        return "eval is not bound".to_owned();
    };

    let globals = Value::Object(vm.new_dict());
    let value = match vm.call(&eval, CallArgs::new(vec![Value::str(expression), globals])) {
        Ok(value) => value,
        Err(Signal::Raise(exception)) => exception,
        Err(Signal::Halt(halt)) => return format!("halted: {halt}"),
    };

    match vm.repr_text(&value) {
        Ok(text) => text,
        Err(_) => "repr failed".to_owned(),
    }
}

/// A stubbed operation yields unknown values, or halts where its effect
/// on later evaluation cannot be modelled.
fn is_stubbed(text: &str) -> bool {
    text.contains("unknown") || text.starts_with("halted: unsupported")
}

#[test]
fn stub_all_yields_unknown_values() {
    let vm = vm(HostAccess::stub_all());

    for probe in PROBES {
        let text = outcome(&vm, probe.expression);
        assert!(is_stubbed(&text), "{:?}: {} gave {text}", probe.capability, probe.expression);
    }
}

#[test]
fn deny_all_raises_refusals() {
    let vm = vm(HostAccess::deny_all());

    for probe in PROBES {
        assert_eq!(outcome(&vm, probe.expression), probe.denial, "{:?}: {}", probe.capability, probe.expression);
    }
}

#[test]
fn each_capability_is_denied_alone() {
    for denied in HostCapability::ALL {
        let vm = vm(HostAccess::stub_all().with(denied, Access::Deny));

        for probe in PROBES {
            let text = outcome(&vm, probe.expression);
            if probe.capability == denied {
                assert_eq!(text, probe.denial, "{denied:?}: {}", probe.expression);
            } else {
                assert!(is_stubbed(&text), "{denied:?} denied: {} gave {text}", probe.expression);
            }
        }
    }
}

#[test]
fn every_capability_has_a_probe() {
    for capability in HostCapability::ALL {
        assert!(PROBES.iter().any(|probe| probe.capability == capability), "{capability:?}");
    }
}

#[test]
fn argument_validation_precedes_the_policy() {
    let vm = vm(HostAccess::deny_all());

    assert_eq!(outcome(&vm, "__import__('nt').urandom(-1)"), "ValueError('negative argument not allowed',)");
}

#[test]
fn denied_open_names_the_file() {
    let vm = vm(HostAccess::deny_all());
    let Ok(builtins) = vm.import_module("__builtin__") else {
        panic!("import of __builtin__ failed");
    };
    let Ok(open) = vm.getattr_str(&builtins, "open") else {
        panic!("open is not bound");
    };

    let Err(Signal::Raise(exception)) = vm.call1(&open, Value::str("C:\\data.txt")) else {
        panic!("open did not raise");
    };
    let Ok(filename) = vm.getattr_str(&exception, "filename") else {
        panic!("filename is not bound");
    };

    assert_eq!(vm.repr_text(&filename).ok().as_deref(), Some("'C:\\\\data.txt'"));
}

/// Real host access in interpreter code outside tests. `lib_source.rs`
/// is the embedder-side compiler of library sources.
#[test]
fn interpreter_source_has_no_host_access() {
    const FORBIDDEN: &[&str] = &[
        "std::fs",
        "std::net",
        "std::process",
        "std::env",
        "std::time",
        "std::thread",
        "std::os",
        "std::io::stdin",
        "std::io::stdout",
        "std::io::stderr",
        "SystemTime",
        "Instant::",
        "libc::",
        "windows_sys",
        "winapi",
        "getrandom",
        "rand::",
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/interp");
    let mut pending: Vec<PathBuf> = vec![root];
    let mut findings = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("source directory is readable") {
            let path = entry.expect("directory entry is readable").path();
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
            if path.is_dir() {
                if name != "tests" {
                    pending.push(path);
                }
                continue;
            }
            if !name.ends_with(".rs") || name == "tests.rs" || name == "lib_source.rs" {
                continue;
            }

            let text = std::fs::read_to_string(&path).expect("source file is readable");
            let code = text.split("#[cfg(test)]").next().unwrap_or_default();
            for (number, line) in code.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for token in FORBIDDEN {
                    if line.contains(token) {
                        findings.push(format!("{}:{}: {token}", path.display(), number + 1));
                    }
                }
            }
        }
    }

    assert!(findings.is_empty(), "host access in interpreter source:\n{}", findings.join("\n"));
}
