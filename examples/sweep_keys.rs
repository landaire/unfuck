//! Per-object keyed regression sweep. For every `_stage4_deob.pyc` under a directory,
//! decompile each code object via the function path and emit a stable key line
//!
//!   <relpath>#<idx> <name> :: OK|UNREC|ERR|PANIC
//!
//! where idx is the object's index in a deterministic DFS over consts. Diff the sorted
//! output of a baseline build against a changed build to find regressions (a key whose
//! status worsened) and wins (a key that newly recovers). Single-threaded and
//! panic-isolated so one bad object cannot abort or mislabel the rest.
//!
//! Usage: sweep_keys <dir>

use std::io::Write;
use std::sync::Arc;

use py27_marshal::{Code, Obj};

fn collect(code: &Arc<std::sync::RwLock<Code>>, out: &mut Vec<Arc<Code>>) {
    let guard = code.read().unwrap_or_else(|e| e.into_inner());
    out.push(Arc::new(guard.clone()));
    for konst in guard.consts.iter() {
        if let Obj::Code(inner) = konst {
            collect(inner, out);
        }
    }
}

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.to_string_lossy().ends_with("_stage4_deob.pyc") {
            out.push(path);
        }
    }
}

fn classify(code: Arc<Code>) -> &'static str {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unfuck::ir::decompile_function(code)
    }));
    match result {
        Err(_) => "PANIC",
        Ok(Err(_)) => "ERR",
        Ok(Ok(source)) => {
            if source.contains("__unrecovered__") {
                "UNREC"
            } else {
                "OK"
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = std::path::PathBuf::from(args.get(1).expect("usage: sweep_keys <dir>"));

    // Swallow panic output so a per-object panic does not flood stderr; classify catches it.
    std::panic::set_hook(Box::new(|_| {}));

    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for path in &files {
        let rel = path.strip_prefix(&root).unwrap_or(path);
        let rel = rel.to_string_lossy();
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() < 8 {
            continue;
        }
        let obj = match py27_marshal::read::marshal_loads(&bytes[8..]) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let root_code = match obj {
            Obj::Code(code) => code,
            _ => continue,
        };
        let mut objs = Vec::new();
        collect(&root_code, &mut objs);
        for (idx, code) in objs.into_iter().enumerate() {
            let name = code.name.to_string();
            let status = classify(code);
            let _ = writeln!(out, "{}#{} {} :: {}", rel, idx, name, status);
        }
    }
}
