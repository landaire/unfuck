//! Runs `tests/fixtures/interp/format_samples/format_samples.py`, which
//! draws random samples of the `%` operator, `format()`, and `str.format`,
//! and compares each outcome with what CPython 2.7.12 for Windows x64
//! produced. Regenerate the outcomes with `generate_format_samples.py`.

use std::collections::BTreeSet;
use std::path::Path;

use unfuck::interp::Signal;
use unfuck::interp::Value;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;

const MODULE: &str = "format_samples";

/// Mismatches shown in a failure report.
const REPORTED: usize = 100000;

/// The outcome line of each sample and a description of its input.
fn run_samples(directory: &Path) -> Result<Vec<(String, String)>, String> {
    let config = VmConfig::windows_x64();
    let source = LibSource::new(directory.to_path_buf(), BTreeSet::from([MODULE.to_owned()]), LongWidth::Bits32);
    let vm = Vm::new(config, Box::new(source)).map_err(|_| "interpreter bootstrap failed".to_owned())?;

    let module = match vm.import_module(MODULE) {
        Ok(module) => module,
        Err(Signal::Raise(error)) => return Err(format!("import raised {}", vm.describe_exception(&error))),
        Err(Signal::Halt(halt)) => return Err(format!("import halted: {halt}")),
    };
    let text = |name: &str| -> Result<Value, String> { vm.getattr_str(&module, name).map_err(|_| format!("{name} is not bound")) };

    let outcomes = text("OUTCOMES")?;
    let Some(outcomes) = outcomes.as_bytes() else {
        return Err("OUTCOMES is not a str".to_owned());
    };
    let outcomes = String::from_utf8_lossy(outcomes).into_owned();

    let samples = text("SAMPLES")?;
    let length = vm.len(&samples).ok().flatten().ok_or_else(|| "SAMPLES has no length".to_owned())?;
    let mut descriptions = Vec::with_capacity(length);
    for index in 0..length {
        let sample = vm.getitem(&samples, &Value::Int(index as i64)).map_err(|_| "SAMPLES item lookup failed".to_owned())?;
        let description = vm.getitem(&sample, &Value::Int(0)).map_err(|_| "sample description lookup failed".to_owned())?;
        descriptions.push(vm.repr_text(&description).unwrap_or_else(|_| "<repr failed>".to_owned()));
    }

    Ok(outcomes.lines().map(str::to_owned).zip(descriptions).collect())
}

#[test]
fn format_samples_match_cpython() {
    // Python calls recurse on the native stack.
    const STACK_SIZE: usize = 256 * 1024 * 1024;

    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp/format_samples");
    let expected = std::fs::read_to_string(directory.join("format_samples.expected")).expect("expected outcomes exist");
    let expected: Vec<&str> = expected.lines().collect();

    let run_directory = directory.clone();
    let actual = std::thread::Builder::new().stack_size(STACK_SIZE).spawn(move || run_samples(&run_directory)).expect("sample thread spawns").join().expect("samples run without panicking");
    let actual = actual.unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(actual.len(), expected.len(), "sample count differs from the recorded outcomes");

    let mismatches: Vec<String> = actual
        .iter()
        .zip(&expected)
        .enumerate()
        .filter(|(_, ((outcome, _), wanted))| outcome != *wanted)
        .map(|(index, ((outcome, description), wanted))| format!("sample {index}: {description}\n  expected: {wanted}\n  actual:   {outcome}"))
        .collect();

    let shown: Vec<&str> = mismatches.iter().take(REPORTED).map(String::as_str).collect();
    assert!(mismatches.is_empty(), "{} of {} samples differ from CPython:\n{}", mismatches.len(), expected.len(), shown.join("\n"));
}
