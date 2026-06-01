//! Sweep the IR decompiler over every `*_stage4_deob.pyc` under a directory and
//! report aggregate coverage, error types, and panic locations. Single-threaded so
//! panic locations are unambiguous. Used to drive the "decompile cleanly, no panics"
//! goals across the whole archive without re-running deobfuscation.
//!
//! Usage: sweep_stats <dir> [suffix]
//!   suffix defaults to `_stage4_deob.pyc`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use py27_marshal::{Code, Obj};

static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

fn collect(code: &Arc<std::sync::RwLock<Code>>, out: &mut Vec<Arc<Code>>) {
    let guard = code.read().unwrap_or_else(|e| e.into_inner());
    out.push(Arc::new(guard.clone()));
    for konst in guard.consts.iter() {
        if let Obj::Code(inner) = konst {
            collect(inner, out);
        }
    }
}

fn walk(dir: &std::path::Path, suffix: &str, out: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, suffix, out);
        } else if path.to_string_lossy().ends_with(suffix) {
            out.push(path);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: sweep_stats <dir> [suffix]"));
    let suffix = args.get(2).map(|s| s.as_str()).unwrap_or("_stage4_deob.pyc");

    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        *LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()) = Some(loc);
    }));

    let mut files = Vec::new();
    walk(&dir, suffix, &mut files);
    files.sort();

    let mut total = 0usize;
    let mut ok = 0usize;
    // Per bucket: (count, smallest example's bytecode length, that example). Keeping
    // the smallest example surfaces a minimal repro for diagnosis rather than just
    // whichever object happened to fail first.
    let mut by_error: BTreeMap<String, (usize, usize, String)> = BTreeMap::new();
    let mut by_panic: BTreeMap<String, (usize, usize, String)> = BTreeMap::new();
    let mut panic_files: usize = 0;
    let mut read_failures: usize = 0;

    for file in &files {
        let data = match std::fs::read(file) {
            Ok(d) => d,
            Err(_) => {
                read_failures += 1;
                continue;
            }
        };
        if data.len() < 8 {
            read_failures += 1;
            continue;
        }
        let fname = file.file_name().unwrap().to_string_lossy().to_string();
        let load = std::panic::catch_unwind(|| py27_marshal::read::marshal_loads(&data[8..]));
        let root = match load {
            Ok(Ok(Obj::Code(code))) => code,
            Ok(Ok(_)) | Ok(Err(_)) => {
                read_failures += 1;
                continue;
            }
            Err(_) => {
                panic_files += 1;
                let loc = LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default();
                let entry = by_panic.entry(format!("marshal {}", loc)).or_default();
                entry.0 += 1;
                if entry.2.is_empty() {
                    entry.2 = fname;
                }
                continue;
            }
        };

        let mut all = Vec::new();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&root, &mut all))).is_err()
        {
            panic_files += 1;
            continue;
        }

        for code in all {
            // Comprehension/genexpr bodies are only valid inlined in their parent
            // (where the folder recovers them); decompiling them standalone always
            // fails, so they are not counted as real coverage gaps.
            if unfuck::ir::is_comprehension_body(&code) {
                continue;
            }
            total += 1;
            let name = code.name.to_string();
            let code_len = code.code.len();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                unfuck::ir::decompile_function(code.clone())
            }));
            let record = |entry: &mut (usize, usize, String)| {
                entry.0 += 1;
                if entry.2.is_empty() || code_len < entry.1 {
                    entry.1 = code_len;
                    entry.2 = format!("{} in {} ({}B)", name, fname, code_len);
                }
            };
            match res {
                Ok(Ok(_)) => ok += 1,
                Ok(Err(err)) => record(by_error.entry(format!("{}", err)).or_default()),
                Err(_) => {
                    let loc = LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default();
                    record(by_panic.entry(loc).or_default());
                }
            }
        }
    }

    println!(
        "files={} code_objects={} ok={} ({:.1}%) read_failures={} panic_files={}",
        files.len(),
        total,
        ok,
        100.0 * ok as f64 / total.max(1) as f64,
        read_failures,
        panic_files,
    );
    println!("--- IR errors (graceful) ---");
    let mut errs: Vec<_> = by_error.into_iter().collect();
    errs.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (err, (count, _len, example)) in errs {
        println!("  {:>6}  {:50}  smallest: {}", count, err, example);
    }
    println!("--- PANICS (must be eliminated) ---");
    let mut panics: Vec<_> = by_panic.into_iter().collect();
    panics.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (loc, (count, _len, example)) in panics {
        println!("  {:>6}  {:50}  smallest: {}", count, loc, example);
    }
}
