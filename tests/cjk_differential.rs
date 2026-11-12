//! Differential test of the CJK codecs against CPython 2.7.12 for Windows:
//! random text and bytes go through every codec one-shot, incrementally,
//! and through stream readers and writers, with several error modes,
//! under the CPython oracle and the interpreter. Ignored by default since
//! it needs the oracle (`CPYTHON_ORACLE`, default
//! `/var/mnt/build/winpy/winpy2712.sh`) and `PYTHON27_LIB`.
//!
//!   CJK_DIFF_CASES=24000 cargo test --release --test cjk_differential -- --ignored --nocapture

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
use unfuck::interp::value::Value;

const CODECS: [&str; 24] = [
    "gb2312",
    "gbk",
    "gb18030",
    "hz",
    "big5",
    "cp950",
    "big5hkscs",
    "shift_jis",
    "cp932",
    "euc_jp",
    "shift_jis_2004",
    "shift_jisx0213",
    "euc_jis_2004",
    "euc_jisx0213",
    "euc_kr",
    "cp949",
    "johab",
    "iso2022_jp",
    "iso2022_jp_1",
    "iso2022_jp_2",
    "iso2022_jp_2004",
    "iso2022_jp_3",
    "iso2022_jp_ext",
    "iso2022_kr",
];

const ERROR_MODES: [&str; 9] = ["strict", "ignore", "replace", "xmlcharrefreplace", "backslashreplace", "cjkdiff.mark", "cjkdiff.rewind", "cjkdiff.unencodable", "cjkdiff.jump"];

/// Characters that combine with a preceding one in some codec.
const COMBINING: [u32; 7] = [0x300, 0x301, 0x304, 0x30c, 0x309a, 0x2e5, 0x2e9];

/// Byte runs that change state or start sequences in some codec.
const FRAGMENTS: [&[u8]; 30] = [
    b"\x1b(B",
    b"\x1b(J",
    b"\x1b(I",
    b"\x1b$@",
    b"\x1b$B",
    b"\x1b$A",
    b"\x1b$(C",
    b"\x1b$(D",
    b"\x1b$(O",
    b"\x1b$(P",
    b"\x1b$(Q",
    b"\x1b$)C",
    b"\x1b.A",
    b"\x1b.F",
    b"\x1bN",
    b"\x1b&@\x1b$B",
    b"\x1b",
    b"\x1b$",
    b"\x1b$(",
    b"\x0e",
    b"\x0f",
    b"\n",
    b"~{",
    b"~}",
    b"~~",
    b"~\n",
    b"~",
    b"\x8e",
    b"\x8f",
    b"\xa4\xd4",
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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// The characters a codec encodes alone and their encodings.
struct Pool {
    chars: Vec<Vec<u64>>,
    codes: Vec<Vec<u64>>,
}

impl Pool {
    fn from_json(value: &Json) -> Self {
        let lists = |key: &str| -> Vec<Vec<u64>> {
            value[key].as_array().expect("pool lists").iter().map(|item| item.as_array().expect("pool item").iter().map(|unit| unit.as_u64().expect("pool unit")).collect()).collect()
        };

        Self { chars: lists("chars"), codes: lists("codes") }
    }
}

fn surrogate_pair(code_point: u32) -> [u64; 2] {
    let offset = code_point - 0x10000;
    [u64::from(0xd800 + (offset >> 10)), u64::from(0xdc00 + (offset & 0x3ff))]
}

fn random_text(rng: &mut Rng, pool: &Pool) -> Vec<u64> {
    let mut text = Vec::new();
    for _ in 0..rng.below(12) {
        match rng.below(100) {
            0..=64 if !pool.chars.is_empty() => text.extend(rng.pick(&pool.chars)),
            65..=79 => text.push(*rng.pick(&[0x61, 0x62, 0x7e, 0x5c, 0x0a, 0x0d, 0x20, 0x1b, 0x0e, 0x0f, 0x3f, 0x7f, 0x00]) as u64),
            80..=84 => text.push(rng.below(0xd800) as u64),
            85..=87 => text.push(0xd800 + rng.below(0x800) as u64),
            88..=90 => text.extend(surrogate_pair(0x10000 + rng.below(0x10_0000) as u32)),
            _ => text.push(u64::from(*rng.pick(&COMBINING))),
        }
    }

    text
}

fn random_data(rng: &mut Rng, pool: &Pool) -> Vec<u64> {
    let mut data = Vec::new();
    for _ in 0..rng.below(10) {
        match rng.below(100) {
            0..=54 if !pool.codes.is_empty() => data.extend(rng.pick(&pool.codes)),
            55..=64 if !pool.codes.is_empty() => {
                let code = rng.pick(&pool.codes).clone();
                let cut = rng.below(code.len().max(1));
                data.extend(&code[..cut]);
            }
            65..=74 => data.extend(rng.pick(&FRAGMENTS).iter().map(|byte| u64::from(*byte))),
            75..=84 => data.push(rng.below(256) as u64),
            85..=92 => data.push(0x80 + rng.below(128) as u64),
            _ => data.push(0x21 + rng.below(0x5e) as u64),
        }
    }

    data
}

fn generate_case(rng: &mut Rng, codec: &str, pool: &Pool) -> Json {
    let kind = match rng.below(10) {
        0..=4 => "oneshot",
        5..=7 => "incremental",
        _ => "streams",
    };
    let mut errors: Vec<&str> = (0..1 + rng.below(3)).map(|_| *rng.pick(&ERROR_MODES)).collect();
    errors.dedup();
    let steps: Vec<usize> = (0..rng.below(7)).map(|_| rng.below(12)).collect();

    json!({ "codec": codec, "kind": kind, "text": random_text(rng, pool), "data": random_data(rng, pool), "errors": errors, "steps": steps })
}

/// The Python value of a JSON case: objects become dicts, arrays lists,
/// numbers ints, and strings `str`.
fn to_value(vm: &Vm, json: &Json) -> Value {
    match json {
        Json::Object(map) => {
            let dict = vm.new_dict();
            for (key, item) in map {
                vm.dict_set(&dict, Value::str(key), to_value(vm, item)).expect("dict stores");
            }
            Value::Object(dict)
        }
        Json::Array(items) => vm.new_list(items.iter().map(|item| to_value(vm, item)).collect()),
        Json::Number(number) => vm.new_int_from_i64(number.as_i64().expect("integer")),
        Json::String(text) => Value::str(text),
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Null => Value::None,
    }
}

fn run_interpreter(driver: &Path, stdlib: LibSource, work: Vec<(Json, String)>) -> Vec<String> {
    let source = oracle::DriverSource::new(driver, "cjk_driver", stdlib);
    let vm = Vm::new(VmConfig::windows_x64(), Box::new(source)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"));
    let describe = |signal: Signal| match signal {
        Signal::Raise(error) => format!("raised {}", vm.describe_exception(&error)),
        Signal::Halt(halt) => format!("halted: {halt}"),
    };
    let module = vm.import_module("cjk_driver").map_err(describe).expect("cjk_driver imports");
    let run_case = vm.getattr_str(&module, "run_case").map_err(describe).expect("run_case exists");

    let mut mismatches = Vec::new();
    for (case, expected) in work {
        let actual = match vm.call(&run_case, CallArgs::new(vec![to_value(&vm, &case)])) {
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
fn cjk_codecs_agree_with_cpython() {
    let Some(launcher) = oracle::oracle() else {
        eprintln!("skipped: no oracle");
        return;
    };
    let Some(stdlib) = stdlib::source(LongWidth::Bits32) else {
        eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
        return;
    };

    let count = oracle::env_number("CJK_DIFF_CASES", 2400) as usize;
    let mut rng = Rng(oracle::env_number("CJK_DIFF_SEED", 0xc0de_2712).max(1));
    let selected: Vec<&str> = match std::env::var("CJK_DIFF_CODECS") {
        Ok(names) => CODECS.iter().copied().filter(|codec| names.split(',').any(|name| name == *codec)).collect(),
        Err(_) => CODECS.to_vec(),
    };
    let driver: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp/cjk_differential");
    let script = driver.join("oracle.py");
    let scratch = oracle::scratch_directory("cjk_differential");

    let names: Vec<String> = selected.iter().map(|codec| Json::from(*codec).to_string()).collect();
    let pools: Vec<Pool> = oracle::run(&launcher, &script, "pool", &names, &scratch).into_iter().map(|pool| Pool::from_json(&pool.expect("oracle lists a pool"))).collect();

    let cases: Vec<Json> = (0..count)
        .map(|index| {
            let which = index % selected.len();
            generate_case(&mut rng, selected[which], &pools[which])
        })
        .collect();
    let inputs: Vec<String> = cases.iter().map(Json::to_string).collect();
    let results = oracle::run(&launcher, &script, "run", &inputs, &scratch);

    let mut crashed = 0;
    let mut work = Vec::new();
    for (case, result) in cases.into_iter().zip(results) {
        match result.as_ref().and_then(Json::as_str) {
            Some(expected) => work.push((case, expected.to_owned())),
            None => crashed += 1,
        }
    }
    let ran = work.len();

    let _ = std::fs::remove_dir_all(&scratch);
    let mismatches = oracle::in_threads(work, move |chunk| run_interpreter(&driver, stdlib.clone(), chunk));

    eprintln!("{ran} cases over {} codecs ran, {crashed} oracle crashes skipped", selected.len());
    for mismatch in mismatches.iter().take(25) {
        eprintln!("{mismatch}");
    }
    assert!(mismatches.is_empty(), "{} disagreements with CPython", mismatches.len());
}
