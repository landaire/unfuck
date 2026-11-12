//! Runs each `tests/fixtures/interp/cases/<name>.py` with the Windows x64
//! configuration and compares `repr(RESULT)` with what CPython 2.7.12 for
//! Windows x64, the build the client embeds, produced. Regenerate the
//! fixtures with `generate_conformance.py`.
//!
//! Standard library modules compile at test time from `PYTHON27_LIB`, the
//! `Lib` directory of that build; a case that imports one is skipped when no
//! `Lib` directory is available.

#[path = "support/stdlib.rs"]
mod stdlib;

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use unfuck::interp::BuiltinModule;
use unfuck::interp::HostTimeZone;
use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Signal;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::lib_source::LibSource;

/// Case modules, then the listed CPython standard library modules.
struct CaseSource {
    directory: PathBuf,
    stdlib: Option<LibSource>,
    /// Set when the case imports a listed module and no `Lib` is available.
    needs_lib: Arc<AtomicBool>,
}

impl CaseSource {
    /// Whether `name` is a listed module that cannot be loaded.
    fn lacks(&self, name: &str) -> bool {
        let lacking = self.stdlib.is_none() && stdlib::listed_modules().contains(name);
        if lacking {
            self.needs_lib.store(true, Ordering::Relaxed);
        }

        lacking
    }
}

impl ModuleSource for CaseSource {
    fn find(&self, name: &str) -> Option<ModuleCode> {
        if let Ok(code) = std::fs::read(self.directory.join(format!("{name}.marshal"))) {
            return Some(ModuleCode { code, is_package: false, filename: format!("{name}.py") });
        }

        match self.stdlib.as_ref()?.compile(name) {
            Ok(code) => code,
            Err(error) => panic!("{error}"),
        }
    }

    /// A listed module raises ImportError when no `Lib` is available,
    /// rather than loading as an opaque module the case would run on.
    fn builtin(&self, name: &str) -> BuiltinModule {
        if self.lacks(name) { BuiltinModule::Absent } else { BuiltinModule::Unknown }
    }
}

/// Why a case did not produce a comparable result.
enum Outcome {
    Ran(String),
    NeedsLib,
}

/// The CRT globals of a case's `.timezone` file: a TZ string of the form
/// `tzn[+|-]hh[:mm[:ss]][dzn]`, then the Windows names of the standard and
/// daylight zones, one per line.
fn parse_time_zone(text: &str) -> Option<HostTimeZone> {
    let mut lines = text.lines();
    let tz = lines.next()?;
    let standard_name = lines.next()?;
    let daylight_name = lines.next()?;
    let rest = &tz[tz.find(|c: char| !c.is_ascii_alphabetic())?..];
    let offset_end = rest.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(rest.len());
    let (offset, daylight) = rest.split_at(offset_end);

    let (sign, offset) = match offset.strip_prefix('-') {
        Some(offset) => (-1, offset),
        None => (1, offset.strip_prefix('+').unwrap_or(offset)),
    };
    let mut seconds = 0;
    for (part, scale) in offset.split(':').zip([3600, 60, 1]) {
        seconds += part.parse::<i32>().ok()? * scale;
    }

    Some(HostTimeZone {
        timezone: sign * seconds,
        daylight: i32::from(!daylight.is_empty()),
        tzname: [standard_name.as_bytes().to_vec(), daylight_name.as_bytes().to_vec()],
    })
}

fn run_case(directory: &Path, stdlib: Option<LibSource>, name: &str) -> Outcome {
    let needs_lib = Arc::new(AtomicBool::new(false));
    let text = run_case_text(directory, stdlib, Arc::clone(&needs_lib), name);
    if needs_lib.load(Ordering::Relaxed) {
        return Outcome::NeedsLib;
    }

    Outcome::Ran(text)
}

fn run_case_text(directory: &Path, stdlib: Option<LibSource>, needs_lib: Arc<AtomicBool>, name: &str) -> String {
    let mut config = VmConfig::windows_x64();
    if let Ok(text) = std::fs::read_to_string(directory.join(format!("{name}.timezone"))) {
        config.host.time_zone = Some(parse_time_zone(&text).unwrap_or_else(|| panic!("{name}.timezone is malformed")));
    }

    let source = CaseSource { directory: directory.to_path_buf(), stdlib, needs_lib };
    let Ok(vm) = Vm::new(config, Box::new(source)) else {
        return "interpreter bootstrap failed".to_owned();
    };

    let module = match vm.import_module(name) {
        Ok(module) => module,
        Err(Signal::Raise(error)) => return format!("import raised {}", vm.describe_exception(&error)),
        Err(Signal::Halt(halt)) => return format!("import halted: {halt}"),
    };

    if let Some(failure) = vm.import_records().into_iter().find(|record| record.module == name).and_then(|record| record.failure) {
        let message = failure.split(" at ").next().unwrap_or_default().replacen(": ", ": ", 1);
        return format!("raised {message}");
    }

    let result = match vm.getattr_str(&module, "RESULT") {
        Ok(result) => result,
        Err(_) => return "RESULT is not bound".to_owned(),
    };

    match vm.repr_text(&result) {
        Ok(text) => text,
        Err(Signal::Raise(error)) => format!("repr raised {}", vm.describe_exception(&error)),
        Err(Signal::Halt(halt)) => format!("repr halted: {halt}"),
    }
}

#[test]
fn cases_match_cpython() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp");
    let directory = fixtures.join("cases");
    let stdlib = stdlib::source(VmConfig::windows_x64().long_width);
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .expect("cases directory exists")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.path().file_name().and_then(|name| name.to_str()).and_then(|name| name.strip_suffix(".py")).map(str::to_owned))
        .collect();
    names.sort();

    // Python recursion up to the limit recurses on the native stack.
    const CASE_STACK_SIZE: usize = 512 * 1024 * 1024;

    let mut mismatches = Vec::new();
    let mut skipped = Vec::new();
    for name in &names {
        let expected = std::fs::read_to_string(directory.join(format!("{name}.expected"))).expect("expected output exists");
        let case_directory = directory.clone();
        let case_stdlib = stdlib.clone();
        let case_name = name.clone();
        let actual = std::thread::Builder::new()
            .name(name.clone())
            .stack_size(CASE_STACK_SIZE)
            .spawn(move || run_case(&case_directory, case_stdlib, &case_name))
            .expect("case thread spawns")
            .join()
            .unwrap_or_else(|_| Outcome::Ran("case panicked".to_owned()));
        let Outcome::Ran(actual) = actual else {
            skipped.push(name.as_str());
            continue;
        };
        if actual.trim_end() != expected.trim_end() {
            mismatches.push(format!("{name}:\n  expected: {}\n  actual:   {actual}", expected.trim_end()));
        }
    }

    if !skipped.is_empty() {
        eprintln!("skipped {} cases that import the standard library; set PYTHON27_LIB to a CPython 2.7 Lib directory: {}", skipped.len(), skipped.join(", "));
    }
    assert!(mismatches.is_empty(), "{} of {} cases differ from CPython:\n{}", mismatches.len(), names.len(), mismatches.join("\n"));
}
