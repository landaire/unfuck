//! Differential test of `_sre` against CPython 2.7.12 for Windows: random
//! patterns and subjects run through the client's `sre_compile` and `_sre`
//! under the CPython oracle and through the interpreter, and random
//! mutations of the resulting code lists go through the structural check
//! of both. Ignored by default since it needs the oracle (`CPYTHON_ORACLE`,
//! default `/var/mnt/build/winpy/winpy2712.sh`) and `PYTHON27_LIB`.
//!
//!   SRE_DIFF_CASES=50000 cargo test --release --test sre_differential -- --ignored --nocapture

#[path = "support/oracle.rs"]
mod oracle;
#[path = "support/stdlib.rs"]
mod stdlib;

use std::path::Path;
use std::path::PathBuf;

use num_bigint::BigInt;
use serde_json::Value as Json;
use serde_json::json;

use unfuck::interp::Signal;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;
use unfuck::interp::object::CallArgs;
use unfuck::interp::value::PyBytes;
use unfuck::interp::value::PyText;
use unfuck::interp::value::Value;

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

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Characters of narrow patterns and subjects.
const NARROW_CHARACTERS: &[u32] = &[0x61, 0x62, 0x63, 0x61, 0x62, 0x41, 0x42, 0x0a, 0x20, 0x5f, 0x31, 0xe9, 0xc9];
/// Characters wide patterns and subjects add.
const WIDE_CHARACTERS: &[u32] = &[0xdf, 0x3a9, 0x3c9, 0x663, 0x2028, 0x3000, 0x212a, 0x130, 0x2603];

/// Builds random regular expressions in `sre_parse` syntax.
struct Generator<'a> {
    rng: &'a mut Rng,
    wide: bool,
    closed_groups: usize,
    open_groups: usize,
    names: Vec<String>,
}

impl Generator<'_> {
    fn character(&mut self) -> u32 {
        if self.wide && self.rng.chance(25) { *self.rng.pick(WIDE_CHARACTERS) } else { *self.rng.pick(NARROW_CHARACTERS) }
    }

    /// A literal character written so the parser reads it as itself.
    fn literal(&mut self) -> String {
        match self.character() {
            0x0a => "\\n".to_owned(),
            0x20 => "\\ ".to_owned(),
            character if character < 0x80 => char::from_u32(character).map(String::from).unwrap_or_default(),
            character if character < 0x100 => format!("\\x{character:02x}"),
            character => char::from_u32(character).map(String::from).unwrap_or_default(),
        }
    }

    fn class(&mut self) -> String {
        let mut text = String::from("[");
        if self.rng.chance(30) {
            text.push('^');
        }
        for _ in 0..1 + self.rng.below(3) {
            match self.rng.below(6) {
                0 => text.push_str(self.rng.pick(&["\\d", "\\w", "\\s", "\\W", "\\D", "\\S"])),
                1 => text.push_str(self.rng.pick(&["a-c", "A-Z", "0-9", "b-b"])),
                _ => {
                    let literal = self.literal();
                    text.push_str(&literal);
                }
            }
        }
        text.push(']');

        text
    }

    /// An item of fixed width one, as a lookbehind needs.
    fn fixed(&mut self) -> String {
        match self.rng.below(4) {
            0 => self.class(),
            1 => self.rng.pick(&["\\d", "\\w", "\\s", "."]).to_string(),
            _ => self.literal(),
        }
    }

    fn atom(&mut self, depth: usize) -> (String, bool) {
        let choice = if depth == 0 { self.rng.below(8) } else { self.rng.below(17) };
        match choice {
            0..=3 => (self.literal(), true),
            4 => (".".to_owned(), true),
            5 => (self.class(), true),
            6 => (self.rng.pick(&["\\d", "\\D", "\\w", "\\W", "\\s", "\\S"]).to_string(), true),
            7 => (self.rng.pick(&["^", "$", "\\A", "\\Z", "\\b", "\\B"]).to_string(), false),
            8..=10 => {
                let kind = self.rng.below(4);
                self.open_groups += usize::from(kind != 1);
                let inner = self.alternation(depth - 1);
                let text = match kind {
                    1 => format!("(?:{inner})"),
                    2 => {
                        let name = format!("g{}", self.names.len());
                        self.names.push(name.clone());
                        format!("(?P<{name}>{inner})")
                    }
                    _ => format!("({inner})"),
                };
                if kind != 1 {
                    self.open_groups -= 1;
                    self.closed_groups += 1;
                }
                (text, true)
            }
            11 if self.closed_groups > 0 => {
                if !self.names.is_empty() && self.rng.chance(30) {
                    let name = self.rng.pick(&self.names).clone();
                    return (format!("(?P={name})"), true);
                }
                (format!("\\{}", 1 + self.rng.below(self.closed_groups)), true)
            }
            12 => {
                let inner = self.alternation(depth - 1);
                (format!("({}{inner})", self.rng.pick(&["?=", "?!"])), false)
            }
            13 => {
                let inner: String = (0..1 + self.rng.below(2)).map(|_| self.fixed()).collect();
                let inner = if self.rng.chance(25) {
                    self.closed_groups += 1;
                    format!("({inner})")
                } else {
                    inner
                };
                (format!("({}{inner})", self.rng.pick(&["?<=", "?<!"])), false)
            }
            14 if self.closed_groups > 0 => {
                let group = 1 + self.rng.below(self.closed_groups);
                let yes = self.sequence(depth - 1);
                let text = if self.rng.chance(60) {
                    let no = self.sequence(depth - 1);
                    format!("(?({group}){yes}|{no})")
                } else {
                    format!("(?({group}){yes})")
                };
                (text, false)
            }
            15 => ("()".to_owned(), true),
            _ => (self.literal(), true),
        }
    }

    fn quantifier(&mut self) -> String {
        let base = match self.rng.below(10) {
            0..=2 => "*".to_owned(),
            3..=4 => "+".to_owned(),
            5..=6 => "?".to_owned(),
            7 => format!("{{{}}}", self.rng.below(3)),
            8 => format!("{{{},{}}}", self.rng.below(2), 1 + self.rng.below(3)),
            _ => format!("{{{},}}", self.rng.below(3)),
        };
        if self.rng.chance(35) { base + "?" } else { base }
    }

    fn sequence(&mut self, depth: usize) -> String {
        let mut text = String::new();
        for _ in 0..1 + self.rng.below(4) {
            let (atom, repeatable) = self.atom(depth);
            text.push_str(&atom);
            if repeatable && self.rng.chance(35) {
                let quantifier = self.quantifier();
                text.push_str(&quantifier);
            }
        }

        text
    }

    fn alternation(&mut self, depth: usize) -> String {
        let branches = match self.rng.below(10) {
            0..=6 => 1,
            7..=8 => 2,
            _ => 3,
        };

        (0..branches).map(|_| self.sequence(depth)).collect::<Vec<_>>().join("|")
    }
}

/// One generated case, as the oracle reads it.
fn generate_case(rng: &mut Rng) -> Json {
    let wide_pattern = rng.chance(30);
    let wide_subject = if rng.chance(85) { wide_pattern } else { !wide_pattern };
    let mut generator = Generator { rng, wide: wide_pattern, closed_groups: 0, open_groups: 0, names: Vec::new() };
    let pattern: Vec<u32> = generator.alternation(3).chars().map(u32::from).collect();

    let mut flags = 0;
    for (flag, percent) in [(2, 30), (8, 15), (16, 15), (32, 30), (4, 5)] {
        if rng.chance(percent) {
            flags |= flag;
        }
    }

    let length = rng.below(11);
    let subject: Vec<u32> = (0..length)
        .map(|_| if wide_subject && rng.chance(25) { *rng.pick(WIDE_CHARACTERS) } else { *rng.pick(NARROW_CHARACTERS) })
        .collect();
    let pos: i64 = if rng.chance(75) { 0 } else { rng.below(length + 3) as i64 - 1 };
    let endpos: i64 = if rng.chance(75) { 2_147_483_647 } else { rng.below(length + 3) as i64 - 1 };

    json!({ "pattern": pattern, "wide_pattern": wide_pattern, "flags": flags, "subject": subject, "wide_subject": wide_subject, "pos": pos, "endpos": endpos })
}

/// A copy of `code` with one random change.
fn mutate(rng: &mut Rng, code: &[u64]) -> Vec<u64> {
    let mut code = code.to_vec();
    let index = rng.below(code.len().max(1));
    match rng.below(6) {
        0 if !code.is_empty() => {
            code.remove(index);
        }
        1 => code.insert(index.min(code.len()), rng.below(34) as u64),
        2 if !code.is_empty() => code[index] = rng.below(34) as u64,
        3 if !code.is_empty() => code[index] = code[index].wrapping_add(1) & 0xffff_ffff,
        4 if !code.is_empty() => code[index] = code[index].saturating_sub(1),
        _ if !code.is_empty() => code[index] = *rng.pick(&[0, 1, 0xffff_ffff, 0x8000_0000, 200, 201, 202]),
        _ => code.push(1),
    }

    code
}

/// What the interpreter checks against the oracle.
enum Work {
    Run { case: Json, compiled: Json },
    Validate { code: Vec<u64>, groups: i64, verdict: String },
}

fn text_value(units: &Json, wide: bool) -> Value {
    let units = units.as_array().expect("units are an array").iter().map(|unit| unit.as_u64().expect("unit is a number"));
    if wide {
        Value::Unicode(PyText::new(units.map(|unit| unit as u16).collect::<Vec<u16>>()))
    } else {
        Value::Str(PyBytes::new(units.map(|unit| unit as u8).collect::<Vec<u8>>()))
    }
}

fn int_value(vm: &Vm, number: i64) -> Value {
    vm.new_int(BigInt::from(number))
}

fn code_value(vm: &Vm, code: impl Iterator<Item = u64>) -> Value {
    vm.new_list(code.map(|word| vm.new_int(BigInt::from(word))).collect())
}

/// Runs `work` in one interpreter and returns a description of each
/// disagreement.
fn run_interpreter(driver: &Path, stdlib: LibSource, work: Vec<Work>) -> Vec<String> {
    let source = oracle::DriverSource::new(driver, "sre_driver", stdlib);
    let vm = Vm::new(VmConfig::windows_x64(), Box::new(source)).unwrap_or_else(|_| panic!("interpreter bootstrap failed"));
    let describe = |signal: Signal| match signal {
        Signal::Raise(error) => format!("raised {}", vm.describe_exception(&error)),
        Signal::Halt(halt) => format!("halted: {halt}"),
    };
    let module = vm.import_module("sre_driver").map_err(describe).expect("sre_driver imports");
    let run_case = vm.getattr_str(&module, "run_case").map_err(describe).expect("run_case exists");
    let check_code = vm.getattr_str(&module, "check_code").map_err(describe).expect("check_code exists");

    let mut mismatches = Vec::new();
    for item in &work {
        let (call, expected, label) = match item {
            Work::Run { case, compiled } => {
                // Group names have the type of the pattern they come from.
                let wide = case["wide_pattern"].as_bool().unwrap_or(false);
                let name_value = |name: &str| if wide { Value::Unicode(PyText::from_str(name)) } else { Value::str(name) };
                let groupindex = vm.new_dict();
                for (name, index) in compiled["groupindex"].as_object().expect("groupindex is an object") {
                    vm.dict_set(&groupindex, name_value(name), int_value(&vm, index.as_i64().expect("group index"))).expect("dict stores");
                }
                let indexgroup = compiled["indexgroup"].as_array().expect("indexgroup is an array").iter().map(|name| name.as_str().map_or(Value::None, name_value)).collect();
                let arguments = vec![
                    text_value(&case["pattern"], case["wide_pattern"].as_bool().unwrap_or(false)),
                    int_value(&vm, compiled["flags"].as_i64().expect("flags")),
                    code_value(&vm, compiled["code"].as_array().expect("code").iter().map(|word| word.as_u64().expect("code word"))),
                    int_value(&vm, compiled["groups"].as_i64().expect("groups")),
                    Value::Object(groupindex),
                    vm.new_list(indexgroup),
                    text_value(&case["subject"], case["wide_subject"].as_bool().unwrap_or(false)),
                    int_value(&vm, case["pos"].as_i64().expect("pos")),
                    int_value(&vm, case["endpos"].as_i64().expect("endpos")),
                ];
                let expected = compiled["expected"].as_str().expect("expected text").to_owned();
                (vm.call(&run_case, CallArgs::new(arguments)), expected, format!("case {case}"))
            }
            Work::Validate { code, groups, verdict } => {
                let arguments = vec![code_value(&vm, code.iter().copied()), int_value(&vm, *groups)];
                (vm.call(&check_code, CallArgs::new(arguments)), verdict.clone(), format!("code {code:?} groups {groups}"))
            }
        };
        let actual = match call {
            Ok(value) => vm.as_str_bytes(&value).map(|bytes| bytes.to_string_lossy()).unwrap_or_else(|| "non-string result".to_owned()),
            Err(signal) => describe(signal),
        };
        if actual != expected {
            mismatches.push(format!("{label}\n  expected: {expected}\n  actual:   {actual}"));
        }
    }

    mismatches
}

#[test]
#[ignore = "needs the Windows CPython oracle; run explicitly"]
fn sre_agrees_with_cpython() {
    let Some(launcher) = oracle::oracle() else {
        eprintln!("skipped: no oracle");
        return;
    };
    let Some(stdlib) = stdlib::source(LongWidth::Bits32) else {
        eprintln!("skipped: set PYTHON27_LIB to a CPython 2.7 Lib directory");
        return;
    };

    let count = oracle::env_number("SRE_DIFF_CASES", 2000) as usize;
    let mut rng = Rng(oracle::env_number("SRE_DIFF_SEED", 0x5eed_2712).max(1));
    let driver: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp/sre_differential");
    let script = driver.join("oracle.py");
    let scratch = oracle::scratch_directory("sre_differential");

    let cases: Vec<Json> = (0..count).map(|_| generate_case(&mut rng)).collect();
    let inputs: Vec<String> = cases.iter().map(Json::to_string).collect();
    let compiled = oracle::run(&launcher, &script, "run", &inputs, &scratch);

    let mut crashed = 0;
    let mut rejected = 0;
    let mut work = Vec::new();
    let mut codes = Vec::new();
    for (case, compiled) in cases.into_iter().zip(compiled) {
        let Some(compiled) = compiled else {
            crashed += 1;
            continue;
        };
        if compiled.get("error").is_some() {
            rejected += 1;
            continue;
        }
        let code: Vec<u64> = compiled["code"].as_array().expect("code").iter().map(|word| word.as_u64().expect("code word")).collect();
        let groups = compiled["groups"].as_i64().expect("groups");
        codes.push((code, groups));
        work.push(Work::Run { case, compiled });
    }
    let ran = work.len();

    let mut mutations: Vec<(Vec<u64>, i64)> = Vec::with_capacity(codes.len() * 2);
    for (code, groups) in &codes {
        let once = mutate(&mut rng, code);
        let twice = mutate(&mut rng, &once);
        mutations.push((once, *groups));
        mutations.push((twice, *groups));
    }
    let inputs: Vec<String> = mutations.iter().map(|(code, groups)| json!({ "code": code, "groups": groups }).to_string()).collect();
    let verdicts = oracle::run(&launcher, &script, "validate", &inputs, &scratch);
    let mut validated = 0;
    for ((code, groups), verdict) in mutations.into_iter().zip(verdicts) {
        let Some(verdict) = verdict.and_then(|verdict| verdict.as_str().map(str::to_owned)) else {
            crashed += 1;
            continue;
        };
        validated += 1;
        work.push(Work::Validate { code, groups, verdict });
    }

    let _ = std::fs::remove_dir_all(&scratch);
    let mismatches = oracle::in_threads(work, move |chunk| run_interpreter(&driver, stdlib.clone(), chunk));

    eprintln!("{ran} pattern/subject pairs ran, {rejected} patterns rejected by sre_parse, {validated} mutated code lists checked, {crashed} oracle crashes skipped");
    for mismatch in mismatches.iter().take(25) {
        eprintln!("{mismatch}");
    }
    assert!(mismatches.is_empty(), "{} disagreements with CPython", mismatches.len());
}
