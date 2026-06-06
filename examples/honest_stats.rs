//! Honest, artifact-faithful coverage: count objects recovered the way the real
//! whole-module pipeline (`decompile_module`) actually emits them, not by decompiling
//! every object standalone as a `def`.
//!
//! `sweep_stats` decompiles every code object with `decompile_function`, which wraps
//! it in a `def`. That mismeasures the two object kinds the real pipeline never wraps:
//!   * a MODULE ROOT containing `from __future__ import` or `import *` (only legal at
//!     module scope) -- the real pipeline emits it via `decompile_module_body`;
//!   * any class/module body (no CO_OPTIMIZED) -- wrapping it in a `def` turns its
//!     methods into nested functions and its names into locals.
//! When the root decompiles as a module it has inlined every nested object without an
//! `__unrecovered__` marker (otherwise `decompile_module_body` fails), so the whole
//! file's objects are genuinely recovered. This tool mirrors that: a file whose root
//! recovers as a module counts all its objects as ok; otherwise it falls back to the
//! same per-object path the real pipeline's fallback uses.
//!
//! Usage: honest_stats <dir> [suffix]

use std::collections::BTreeMap;
use std::sync::Arc;

use py27_marshal::{Code, CodeFlags, Obj};

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
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: honest_stats <dir> [suffix]"));
    let suffix = args.get(2).map(|s| s.as_str()).unwrap_or("_stage4_deob.pyc");

    let mut files = Vec::new();
    walk(&dir, suffix, &mut files);
    files.sort();

    let mut total = 0usize;
    let mut ok = 0usize;
    let mut modules_whole = 0usize; // files recovered as a whole module
    let mut modules_fallback = 0usize;
    let mut by_error: BTreeMap<String, (usize, usize, String)> = BTreeMap::new();
    // Why each fallback module's root failed to recover as a whole module, and how many
    // objects that file forfeits (a single root failure can lose every class body).
    let mut fallback_cause: BTreeMap<String, (usize, usize, String)> = BTreeMap::new();

    for file in &files {
        let Ok(data) = std::fs::read(file) else { continue };
        if data.len() < 8 {
            continue;
        }
        let fname = file.file_name().unwrap().to_string_lossy().to_string();
        let Ok(Obj::Code(root)) = py27_marshal::read::marshal_loads(&data[8..]) else {
            continue;
        };
        let mut all = Vec::new();
        collect(&root, &mut all);
        // Non-comprehension objects only; comprehension bodies are recovered inline.
        let objs: Vec<Arc<Code>> =
            all.into_iter().filter(|c| !unfuck::ir::is_comprehension_body(c)).collect();
        let n = objs.len();
        total += n;

        // Whole-module path: if the root recovers as a module body, every nested object
        // is inlined marker-free -> all recovered.
        if unfuck::ir::decompile_module_body_ok(Arc::clone(&objs[0])) {
            ok += n;
            modules_whole += 1;
            continue;
        }
        modules_fallback += 1;
        // Record why this module fell back, weighted by objects forfeited (the bodies
        // that become markers): the lever is roots whose single failure loses many.
        if let Err(reason) = unfuck::ir::decompile_module_body_err(Arc::clone(&objs[0])) {
            let lost = objs.iter().filter(|c| !c.flags.contains(CodeFlags::OPTIMIZED)).count();
            let e = fallback_cause.entry(reason).or_default();
            e.0 += 1;
            e.1 += lost;
            if e.2.is_empty() {
                e.2 = format!("{} ({} bodies)", fname, lost);
            }
        }
        // Fallback: same per-object treatment the real pipeline uses.
        for code in &objs {
            // Class/module bodies are emitted as a marker in the fallback, never wrapped.
            if !code.flags.contains(CodeFlags::OPTIMIZED) {
                let e = by_error.entry("class or module body (fallback)".to_string()).or_default();
                e.0 += 1;
                if e.2.is_empty() {
                    e.2 = format!("{} in {}", code.name, fname);
                }
                continue;
            }
            match unfuck::ir::decompile_function(Arc::clone(code)) {
                Ok(_) => ok += 1,
                Err(err) => {
                    let len = code.code.len();
                    let e = by_error.entry(format!("{}", err)).or_default();
                    e.0 += 1;
                    if e.2.is_empty() || len < e.1 {
                        e.1 = len;
                        e.2 = format!("{} in {} ({}B)", code.name, fname, len);
                    }
                }
            }
        }
    }

    println!(
        "files={} code_objects={} ok={} ({:.2}%)  modules_whole={} modules_fallback={}",
        files.len(),
        total,
        ok,
        100.0 * ok as f64 / total.max(1) as f64,
        modules_whole,
        modules_fallback,
    );
    println!("--- fallback CAUSES (root failure -> whole module lost), by bodies forfeited ---");
    let mut causes: Vec<_> = fallback_cause.into_iter().collect();
    causes.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    for (reason, (files_n, bodies, example)) in causes {
        println!("  {:>5} files {:>5} bodies  {:45}  e.g. {}", files_n, bodies, reason, example);
    }
    println!("--- residual per-object failures (fallback files only) ---");
    let mut errs: Vec<_> = by_error.into_iter().collect();
    errs.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (err, (count, _len, example)) in errs {
        println!("  {:>6}  {:50}  smallest: {}", count, err, example);
    }
}
