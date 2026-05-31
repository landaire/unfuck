//! Sweep the deobfuscator over every raw `*_stage4.pyc` under a directory and
//! report panic locations. Single-threaded so panic locations are unambiguous.
//! Used to drive the "no panics" goal in the deobfuscation path (the symbolic
//! executor and CFG rewrites), separate from the IR decompiler sweep.
//!
//! Usage: sweep_deob <dir> [suffix]   (suffix defaults to `_stage4.pyc`).

use std::collections::BTreeMap;
use std::sync::Mutex;

use pydis::opcode::py27::Standard;

static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

fn walk(dir: &std::path::Path, suffix: &str, out: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, suffix, out);
        } else {
            let name = path.to_string_lossy();
            // Match the raw stage4, not the already-deobfuscated `_stage4_deob.pyc`.
            if name.ends_with(suffix) && !name.ends_with("_stage4_deob.pyc") {
                out.push(path);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: sweep_deob <dir> [suffix]"));
    let suffix = args.get(2).map(|s| s.as_str()).unwrap_or("_stage4.pyc");

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

    let mut ok = 0usize;
    let mut errs = 0usize;
    let mut panicked = 0usize;
    let mut by_panic: BTreeMap<String, (usize, String)> = BTreeMap::new();

    for file in &files {
        let data = match std::fs::read(file) {
            Ok(d) if d.len() > 8 => d,
            _ => continue,
        };
        let fname = file.file_name().unwrap().to_string_lossy().to_string();
        let res = std::panic::catch_unwind(|| {
            unfuck::Deobfuscator::<Standard>::new(&data[8..]).deobfuscate()
        });
        match res {
            Ok(Ok(_)) => ok += 1,
            Ok(Err(_)) => errs += 1,
            Err(_) => {
                panicked += 1;
                let loc = LAST_PANIC
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .unwrap_or_default();
                let entry = by_panic.entry(loc).or_default();
                entry.0 += 1;
                if entry.1.is_empty() {
                    entry.1 = fname;
                }
            }
        }
    }

    println!(
        "files={} ok={} err={} panicked={}",
        files.len(),
        ok,
        errs,
        panicked
    );
    println!("--- deob PANICS (must be eliminated) ---");
    let mut panics: Vec<_> = by_panic.into_iter().collect();
    panics.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (loc, (count, example)) in panics {
        println!("  {:>6}  {:40}  e.g. {}", count, loc, example);
    }
}
