//! Compares the compiler with CPython 2.7.18: each source is parsed,
//! compiled, and marshalled, and the bytes must equal `marshal.dumps` of
//! CPython's `compile`; an expected exception and the compile warnings must
//! match too.
//!
//! `tests/fixtures/compiler/generate_compiler_fixtures.py` records what
//! CPython does. The committed cases live in
//! `tests/fixtures/compiler/cases/<mode>` with their records in
//! `tests/fixtures/compiler/expected/<mode>`; regenerate them with
//!
//! ```text
//! for mode in exec eval single; do
//!     python2.7 tests/fixtures/compiler/generate_compiler_fixtures.py --mode $mode \
//!         tests/fixtures/compiler/cases/$mode tests/fixtures/compiler/expected/$mode
//! done
//! ```
//!
//! `stdlib_matches_cpython` runs the generator over a whole standard library
//! (`PYTHON27`, `PYTHON27_LIB`). `CORPUS_FILTER=os.py,test/test_grammar.py`
//! restricts any of these tests to the listed relative paths, and
//! `CORPUS_REPORT_LIMIT` sets how many mismatches a failure lists.

#[path = "compiler_corpus/fixture.rs"]
mod fixture;
#[path = "compiler_corpus/marshal_diff.rs"]
mod marshal_diff;

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const MODES: [&str; 3] = ["exec", "eval", "single"];

/// Mismatches shown in a failure message; `CORPUS_REPORT_LIMIT` overrides.
fn report_limit() -> usize {
    const DEFAULT_LIMIT: usize = 30;

    std::env::var("CORPUS_REPORT_LIMIT").ok().and_then(|value| value.parse().ok()).unwrap_or(DEFAULT_LIMIT)
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compiler")
}

fn check_cases(mode: &str) {
    let fixtures = fixtures_dir();
    let summary = fixture::run_corpus(&fixtures.join("cases").join(mode), &fixtures.join("expected").join(mode));

    assert!(summary.checked > 0 || std::env::var_os("CORPUS_FILTER").is_some(), "no {mode} cases found");
    assert!(summary.failures.is_empty(), "{}", summary.report(report_limit()));
}

/// Every recorded marshal output decodes completely, and its root is a code
/// object named after the case.
#[test]
fn cases_marshal_decodes() {
    for mode in MODES {
        let dir = fixtures_dir().join("expected").join(mode);
        let index = fixture::load_index(&dir).unwrap_or_else(|error| panic!("{error}"));

        for rel in &index {
            let record = fixture::load_record(&dir, rel).unwrap_or_else(|error| panic!("{error}"));
            if record.error.is_some() {
                continue;
            }

            let path = fixture::fixture_path(&dir, rel, ".marshal");
            let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let value = marshal_diff::decode(&bytes).unwrap_or_else(|error| panic!("{mode}/{rel}: {error}"));

            let marshal_diff::Value::Code(code) = value else {
                panic!("{mode}/{rel}: root is not a code object");
            };
            let marshal_diff::Value::Str { value: filename, .. } = &code.filename else {
                panic!("{mode}/{rel}: co_filename is not a str");
            };
            assert_eq!(filename.as_slice(), rel.as_bytes(), "{mode}/{rel}: co_filename");
        }
    }
}

#[test]
fn exec_cases_match_cpython() {
    check_cases("exec");
}

#[test]
fn eval_cases_match_cpython() {
    check_cases("eval");
}

#[test]
fn single_cases_match_cpython() {
    check_cases("single");
}

/// Files that differ from the reference for reasons outside the compiler,
/// with the reason.
const KNOWN_DIFFERENCES: [(&str, &str); 5] = [
    ("json/tests/test_scanstring.py", UCS4_REFERENCE),
    ("test/test_codeccallbacks.py", UCS4_REFERENCE),
    ("test/test_codecs.py", UCS4_REFERENCE),
    ("test/test_unicode.py", UCS4_REFERENCE),
    ("test/test_source_encoding.py", "the parser's built-in source codecs have no koi8-r; inside the interpreter `parse_in_vm` decodes it through the codec registry"),
];

/// The reference interpreter stores unicode as UCS4 code points, while the
/// Windows client this compiler targets uses UCS2: there `u'\U0001f49d'`
/// and `u'\ud83d\udc9d'` are the same constant.
const UCS4_REFERENCE: &str = "the reference is a UCS4 build; the target client is UCS2";

/// Needs `PYTHON27` (a CPython 2.7.18 interpreter) and `PYTHON27_LIB` (the
/// root of a standard library with `test/` and `lib2to3/`). The files in
/// `KNOWN_DIFFERENCES` must differ; every other file must match.
#[test]
#[ignore]
fn stdlib_matches_cpython() {
    let python = std::env::var_os("PYTHON27").expect("PYTHON27 must name a CPython 2.7.18 interpreter");
    let library = PathBuf::from(std::env::var_os("PYTHON27_LIB").expect("PYTHON27_LIB must name the standard library root"));
    let output = Path::new(env!("CARGO_TARGET_TMPDIR")).join("compiler-corpus-stdlib");

    if output.exists() {
        std::fs::remove_dir_all(&output).unwrap_or_else(|error| panic!("{}: {error}", output.display()));
    }

    let status = Command::new(&python)
        .arg(fixtures_dir().join("generate_compiler_fixtures.py"))
        .arg(&library)
        .arg(&output)
        .env_remove("LD_LIBRARY_PATH")
        .status()
        .unwrap_or_else(|error| panic!("cannot run {python:?}: {error}"));
    assert!(status.success(), "the fixture generator failed: {status}");

    let mut summary = fixture::run_corpus(&library, &output);
    eprintln!("{}", summary.report(0));
    assert!(summary.checked > 0, "no files selected");

    let filtered = std::env::var_os("CORPUS_FILTER").is_some();
    for (rel, reason) in KNOWN_DIFFERENCES {
        let differs = summary.failures.iter().any(|(failed, _)| failed == rel);
        assert!(differs || filtered, "{rel} is listed as differing ({reason}) but matches");
    }
    summary.failures.retain(|(rel, _)| !KNOWN_DIFFERENCES.iter().any(|(known, _)| known == rel));
    assert!(summary.failures.is_empty(), "{}", summary.report(report_limit()));
}
