//! Compares the API surface of the client's builtin modules in the
//! interpreter with CPython 2.7.12 for Windows x64, as recorded by
//! `tests/fixtures/interp/surface/generate_surface.py`. Ignored by
//! default: it reports differences rather than asserting conformance.
//!
//!   cargo test --test interp_surface -- --ignored --nocapture

#[path = "support/stdlib.rs"]
mod stdlib;

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Signal;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::lib_source::LibSource;
use unfuck::interp::object::CallArgs;
use unfuck::interp::value::Value;

/// `surface_dump`, then the CPython standard library modules.
struct SurfaceSource {
    surface: PathBuf,
    stdlib: LibSource,
}

impl ModuleSource for SurfaceSource {
    fn find(&self, name: &str) -> Option<ModuleCode> {
        if name == "surface_dump" {
            let code = std::fs::read(self.surface.join("surface_dump.marshal")).ok()?;
            return Some(ModuleCode { code, is_package: false, filename: "surface_dump.py".to_owned() });
        }

        self.stdlib.find(name)
    }
}

/// Parses `key\tvalue` lines into `facts`.
fn add_facts(facts: &mut BTreeMap<String, String>, text: &str) {
    for (key, value) in text.lines().filter_map(|line| line.split_once('\t')) {
        facts.insert(key.to_owned(), value.to_owned());
    }
}

/// The facts of one module, or why the dump could not start. Each
/// attribute is dumped by its own call, so a halt on one (an unknown
/// host value, say) is recorded as that attribute's value.
fn dump(surface: &Path, stdlib: &LibSource, name: &str) -> Result<BTreeMap<String, String>, String> {
    let source = SurfaceSource { surface: surface.to_path_buf(), stdlib: stdlib.clone() };
    let Ok(vm) = Vm::new(VmConfig::windows_x64(), Box::new(source)) else {
        return Err("interpreter bootstrap failed".to_owned());
    };
    let describe = |signal: Signal| match signal {
        Signal::Raise(error) => format!("raised {}", vm.describe_exception(&error)),
        Signal::Halt(halt) => format!("halted: {halt}"),
    };
    let text = |value: Value| vm.as_str_bytes(&value).map(|bytes| String::from_utf8_lossy(bytes.as_bytes()).into_owned()).ok_or_else(|| "dump returned a non-string".to_owned());

    let module = vm.import_module("surface_dump").map_err(describe)?;
    let names = vm.getattr_str(&module, "names").map_err(describe)?;
    let attribute = vm.getattr_str(&module, "attribute").map_err(describe)?;

    let listing = text(vm.call(&names, CallArgs::new(vec![Value::str(name)])).map_err(describe)?)?;
    let mut facts = BTreeMap::new();
    add_facts(&mut facts, &listing);

    for attribute_name in listing.lines().filter(|line| !line.contains('\t')) {
        match vm.call(&attribute, CallArgs::new(vec![Value::str(name), Value::str(attribute_name)])) {
            Ok(value) => add_facts(&mut facts, &text(value)?),
            Err(signal) => {
                facts.insert(format!("attr:{attribute_name}"), describe(signal));
            }
        }
    }

    Ok(facts)
}

/// Differences of one module.
#[derive(Default)]
struct Report {
    missing: Vec<String>,
    extra: Vec<String>,
    changed: Vec<String>,
    failure: Option<String>,
}

impl Report {
    fn total(&self) -> usize {
        self.missing.len() + self.extra.len() + self.changed.len() + usize::from(self.failure.is_some())
    }
}

fn compare(expected: &BTreeMap<String, String>, actual: &BTreeMap<String, String>) -> Report {
    let mut report = Report::default();

    for (key, value) in expected {
        match actual.get(key) {
            None => report.missing.push(format!("{key} = {value}")),
            Some(found) if found != value => report.changed.push(format!("{key}: expected {value}, got {found}")),
            Some(_) => {}
        }
    }
    for (key, value) in actual {
        if !expected.contains_key(key) {
            report.extra.push(format!("{key} = {value}"));
        }
    }

    report
}

#[test]
#[ignore = "reports API surface differences; run explicitly"]
fn surface_matches_cpython() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp");
    let surface = fixtures.join("surface");
    let Some(stdlib) = stdlib::source(VmConfig::windows_x64().long_width) else {
        eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
        return;
    };

    let text = std::fs::read_to_string(surface.join("surface.json")).expect("surface.json exists");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("surface.json parses");
    let modules = fixture["modules"].as_object().expect("surface.json has modules");

    let mut reports = Vec::new();
    for (name, facts) in modules {
        let expected: BTreeMap<String, String> = facts.as_object().expect("module facts are an object").iter().map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_owned())).collect();
        let report = match dump(&surface, &stdlib, name) {
            Ok(actual) => compare(&expected, &actual),
            Err(failure) => Report { failure: Some(failure), ..Report::default() },
        };
        reports.push((name.clone(), expected.len(), report));
    }

    for (name, _, report) in &reports {
        if report.total() == 0 {
            continue;
        }
        println!("== {name}");
        if let Some(failure) = &report.failure {
            println!("  dump failed: {failure}");
        }
        for line in &report.missing {
            println!("  missing {line}");
        }
        for line in &report.extra {
            println!("  extra   {line}");
        }
        for line in &report.changed {
            println!("  changed {line}");
        }
    }

    reports.sort_by(|left, right| right.2.total().cmp(&left.2.total()).then_with(|| left.0.cmp(&right.0)));
    println!("== summary (module: expected facts, missing, extra, changed)");
    for (name, count, report) in &reports {
        let failure = report.failure.as_deref().map(|failure| format!(" [{failure}]")).unwrap_or_default();
        println!("{name}: {count} facts, {} missing, {} extra, {} changed{failure}", report.missing.len(), report.extra.len(), report.changed.len());
    }

    let differing = reports.iter().filter(|(_, _, report)| report.total() > 0).count();
    assert_eq!(differing, 0, "{differing} of {} modules differ from CPython 2.7.12", reports.len());
}
