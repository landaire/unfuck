//! Pickles generated object graphs with the interpreter's `cPickle` and
//! compares the bytes with those the Windows build of CPython 2.7.12
//! produced for the same graphs. Regenerate the fixture with
//! `generate_cpickle_graphs.py` under that interpreter.
//!
//! `copy_reg` compiles at test time from `PYTHON27_LIB`; without a `Lib`
//! directory the test is skipped.

#[path = "support/stdlib.rs"]
mod stdlib;

use std::path::Path;
use std::path::PathBuf;

use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Signal;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;

const MODULE: &str = "cpickle_graphs";

/// The generated module, then the standard library.
struct GraphSource {
    directory: PathBuf,
    stdlib: LibSource,
}

impl ModuleSource for GraphSource {
    fn find(&self, name: &str) -> Option<ModuleCode> {
        if name == MODULE {
            let code = std::fs::read(self.directory.join(format!("{name}.marshal"))).ok()?;
            return Some(ModuleCode { code, is_package: false, filename: format!("{name}.py") });
        }

        match self.stdlib.compile(name) {
            Ok(code) => code,
            Err(error) => panic!("{error}"),
        }
    }
}

/// `repr(RESULT)` of the generated module, or what went wrong instead.
fn run(directory: PathBuf, stdlib: LibSource) -> String {
    let source = GraphSource { directory, stdlib };
    let Ok(vm) = Vm::new(VmConfig::windows_x64(), Box::new(source)) else {
        return "interpreter bootstrap failed".to_owned();
    };

    let module = match vm.import_module(MODULE) {
        Ok(module) => module,
        Err(Signal::Raise(error)) => return format!("import raised {}", vm.describe_exception(&error)),
        Err(Signal::Halt(halt)) => return format!("import halted: {halt}"),
    };
    let result = match vm.getattr_str(&module, "RESULT") {
        Ok(result) => result,
        Err(_) => return "RESULT is not bound".to_owned(),
    };

    match vm.repr_text(&result) {
        Ok(text) => text,
        Err(_) => "repr of RESULT failed".to_owned(),
    }
}

#[test]
fn generated_graphs_match_cpython() {
    // Saving recursion reaches the recursion limit on the native stack.
    const STACK_SIZE: usize = 512 * 1024 * 1024;

    let Some(stdlib) = stdlib::source(LongWidth::Bits32) else {
        eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
        return;
    };
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp");
    let expected = std::fs::read_to_string(directory.join(format!("{MODULE}.expected"))).expect("expected output exists");

    let actual = std::thread::Builder::new()
        .name(MODULE.to_owned())
        .stack_size(STACK_SIZE)
        .spawn(move || run(directory, stdlib))
        .expect("test thread spawns")
        .join()
        .expect("test thread completes");

    let expected = expected.trim_end();
    if actual == expected {
        return;
    }

    let offset = actual.bytes().zip(expected.bytes()).position(|(left, right)| left != right).unwrap_or(actual.len().min(expected.len()));
    let window = |text: &str| {
        let start = text.floor_char_boundary(offset.saturating_sub(300));
        let end = text.ceil_char_boundary((offset + 300).min(text.len()));
        text[start..end].to_owned()
    };
    panic!("cPickle output differs from CPython at byte {offset}:\n  expected: ...{}...\n  actual:   ...{}...", window(expected), window(&actual));
}
