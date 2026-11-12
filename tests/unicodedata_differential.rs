//! Differential test of `unicodedata` against CPython 2.7.12 for Windows:
//! random text through every normalization form of both databases, and
//! every property of random code points. Ignored by default since it
//! needs the oracle (`CPYTHON_ORACLE`, default
//! `/var/mnt/build/winpy/winpy2712.sh`) and `PYTHON27_LIB`.
//!
//!   UD_DIFF_CASES=50000 cargo test --test unicodedata_differential -- --ignored --nocapture

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/stdlib.rs"]
mod stdlib;

use std::path::Path;
use std::path::PathBuf;

use serde_json::Value as Json;
use serde_json::json;

use unfuck::interp::Signal;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;
use unfuck::interp::object::CallArgs;
use unfuck::interp::value::PyText;
use unfuck::interp::value::Value;

/// Code units normalization treats specially: composites, combining marks
/// of many classes, Hangul jamo around each range bound, characters
/// Unicode 3.2.0 lacks, compatibility characters, and surrogates.
const UNITS: &[u16] = &[
    0x61, 0x65, 0x6f, 0x41, 0x45, 0x73, 0x6b, 0x20, 0x31, 0xe9, 0xc5, 0xf1, 0xff, 0x17f, 0x1fb, 0x221, 0x234, 0x3d3, 0x1e0d, 0x1e69, 0x1e9b, 0x1ea1,
    0x1eb7, 0x1f43, 0x1fb7, 0x2126, 0x212b, 0xfb01, 0x2460, 0x3300, 0xfdfa, 0x300, 0x301, 0x302, 0x303, 0x304, 0x306, 0x307, 0x308, 0x30a, 0x30c,
    0x313, 0x314, 0x315, 0x31b, 0x323, 0x327, 0x328, 0x331, 0x340, 0x341, 0x342, 0x344, 0x345, 0x350, 0x5ae, 0x5b7, 0x5bc, 0x5c1, 0x5c2, 0x5d0,
    0x5e9, 0x622, 0x627, 0x653, 0x6c0, 0x6d5, 0x915, 0x928, 0x929, 0x931, 0x93c, 0x958, 0xb3e, 0xb47, 0xb56, 0xbbe, 0xbc6, 0xbd7, 0xf71, 0xf72,
    0xf73, 0xf74, 0xf75, 0xf80, 0xf81, 0xfb5, 0x3b1, 0x3b9, 0x391, 0x1f00, 0x1fbe, 0x302a, 0x3099, 0x309a, 0x304b, 0x30ab, 0x30cf, 0x3046, 0x309d,
    0x10ff, 0x1100, 0x1101, 0x1112, 0x1113, 0x1114, 0x1160, 0x1161, 0x1175, 0x1176, 0x1177, 0x11a6, 0x11a7, 0x11a8, 0x11c2, 0x11c3, 0x11c4, 0xac00,
    0xac01, 0xac1c, 0xd7a3, 0x3131, 0xf900, 0xfa2e, 0xfa6c, 0xfb2c, 0xfb49, 0x2adc, 0x2add, 0x338, 0xd800, 0xdc00, 0xd834, 0xdd5e, 0xd87e, 0x1d15,
];

/// A xorshift generator; the cases depend only on the seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn utf16(code: u32) -> Vec<u16> {
    match code.checked_sub(0x10000) {
        Some(offset) => vec![(0xd800 + (offset >> 10)) as u16, (0xdc00 + (offset & 0x3ff)) as u16],
        None => vec![code as u16],
    }
}

fn generate_case(rng: &mut Rng) -> Json {
    if rng.below(3) == 0 {
        let code = match rng.below(10) {
            0..=4 => rng.below(0x10000) as u32,
            5 => 0x300 + rng.below(0x100) as u32,
            6 => 0x10000 + rng.below(0x30000) as u32,
            7 => 0xe0000 + rng.below(0x30000) as u32,
            _ => rng.below(0x110000) as u32,
        };
        return json!({ "kind": "property", "units": utf16(code) });
    }

    let mut units = Vec::new();
    if rng.below(20) == 0 {
        // A starter with a long run of marks.
        units.push(UNITS[rng.below(30)]);
        for _ in 0..15 + rng.below(20) {
            units.push(UNITS[31 + rng.below(25)]);
        }
    } else {
        for _ in 0..rng.below(13) {
            units.push(if rng.below(10) == 0 { rng.below(0x10000) as u16 } else { UNITS[rng.below(UNITS.len())] });
        }
    }

    json!({ "kind": "normalize", "units": units })
}

/// Runs `cases` in one interpreter and returns each disagreement.
fn run_interpreter(driver: &Path, stdlib: LibSource, cases: Vec<(Json, String)>) -> Vec<String> {
    let source = oracle::DriverSource::new(driver, "ud_driver", stdlib);
    let vm = Vm::new(VmConfig::windows_x64(), Box::new(source)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"));
    let describe = |signal: Signal| match signal {
        Signal::Raise(error) => format!("raised {}", vm.describe_exception(&error)),
        Signal::Halt(halt) => format!("halted: {halt}"),
    };
    let module = vm.import_module("ud_driver").map_err(describe).expect("ud_driver imports");
    let run_case = vm.getattr_str(&module, "run_case").map_err(describe).expect("run_case exists");

    let mut mismatches = Vec::new();
    for (case, expected) in cases {
        let units: Vec<u16> = case["units"].as_array().expect("units").iter().map(|unit| unit.as_u64().expect("unit") as u16).collect();
        let kind = case["kind"].as_str().expect("kind");
        let arguments = vec![Value::str(kind), Value::Unicode(PyText::new(units))];
        let actual = match vm.call(&run_case, CallArgs::new(arguments)) {
            Ok(value) => vm.as_str_bytes(&value).map(|bytes| bytes.to_string_lossy()).unwrap_or_else(|| "non-string result".to_owned()),
            Err(signal) => describe(signal),
        };
        if actual != expected {
            mismatches.push(format!("case {case}\n  expected: {expected}\n  actual:   {actual}"));
        }
    }

    mismatches
}

#[test]
#[ignore = "needs the Windows CPython oracle; run explicitly"]
fn unicodedata_agrees_with_cpython() {
    let Some(launcher) = oracle::oracle() else {
        eprintln!("skipped: no oracle");
        return;
    };
    let Some(stdlib) = stdlib::source(LongWidth::Bits32) else {
        eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
        return;
    };

    let count = oracle::env_number("UD_DIFF_CASES", 3000) as usize;
    let mut rng = Rng(oracle::env_number("UD_DIFF_SEED", 0x00c0_ffee).max(1));
    let driver: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp/unicodedata_differential");
    let scratch = oracle::scratch_directory("unicodedata_differential");

    let cases: Vec<Json> = (0..count).map(|_| generate_case(&mut rng)).collect();
    let inputs: Vec<String> = cases.iter().map(Json::to_string).collect();
    let expected = oracle::run(&launcher, &driver.join("oracle.py"), "run", &inputs, &scratch);
    let _ = std::fs::remove_dir_all(&scratch);

    let mut crashed = 0;
    let mut work = Vec::new();
    for (case, expected) in cases.into_iter().zip(expected) {
        match expected.and_then(|expected| expected.as_str().map(str::to_owned)) {
            Some(expected) => work.push((case, expected)),
            None => crashed += 1,
        }
    }
    let ran = work.len();

    let mismatches = oracle::in_threads(work, move |chunk| run_interpreter(&driver, stdlib.clone(), chunk));

    eprintln!("{ran} cases compared, {crashed} oracle crashes skipped");
    for mismatch in mismatches.iter().take(25) {
        eprintln!("{mismatch}");
    }
    assert!(mismatches.is_empty(), "{} disagreements with CPython", mismatches.len());
}
