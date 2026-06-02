//! List (file, object) pairs that fail to decompile with an error matching a
//! substring, smallest first. Used to find concrete instances of a residual bucket.
//!
//! Usage: list_fails <dir> <error-substring> [max]

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&args[1]);
    let needle = &args[2];
    let max: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);

    let mut files = Vec::new();
    walk(&dir, &mut files);
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    for path in &files {
        let Ok(data) = std::fs::read(path) else { continue };
        let Ok(obj) = py27_marshal::read::marshal_loads(&data[8..]) else { continue };
        let Obj::Code(root) = obj else { continue };
        let mut all = Vec::new();
        collect(&root, &mut all);
        for code in all {
            let size = code.code.len();
            if let Err(err) = unfuck::ir::decompile_function(code.clone()) {
                if format!("{}", err).contains(needle.as_str()) {
                    let rel = path.strip_prefix(&dir).unwrap_or(path);
                    hits.push((size, rel.to_string_lossy().into_owned(), code.name.to_string()));
                }
            }
        }
    }
    hits.sort();
    for (size, file, name) in hits.into_iter().take(max) {
        println!("{}B  {}  ::  {}", size, file, name);
    }
}
