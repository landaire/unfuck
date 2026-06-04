//! Aggregate, across a directory tree, which `__unrecovered__` contexts dominate
//! the "construct only partially recovered" bucket. For every code object whose
//! rendered source contains the marker, classify each marker occurrence by a coarse
//! signature (standalone statement vs inline expression, plus the trimmed marker
//! line) and tally. Usage: probe_agg <dir>

use std::collections::HashMap;
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
    let mut files = Vec::new();
    walk(&dir, &mut files);

    let mut tally: HashMap<String, usize> = HashMap::new();
    let mut objects = 0usize;
    let mut example: HashMap<String, String> = HashMap::new();

    for path in &files {
        let Ok(data) = std::fs::read(path) else { continue };
        if data.len() < 8 {
            continue;
        }
        let Ok(obj) = py27_marshal::read::marshal_loads(&data[8..]) else { continue };
        let Obj::Code(root) = obj else { continue };
        let mut all = Vec::new();
        collect(&root, &mut all);
        for code in &all {
            let structured = match unfuck::ir::DecodedFunction::decode(code.clone())
                .and_then(|f| f.structure())
            {
                Ok(s) => s,
                Err(_) => continue,
            };
            let source = structured.to_source(&[]);
            if !source.contains("__unrecovered__") {
                continue;
            }
            objects += 1;
            let lines: Vec<&str> = source.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.contains("__unrecovered__") {
                    continue;
                }
                let trimmed = line.trim();
                // Signature: standalone statement marker, or the surrounding expr shape.
                let sig = if trimmed == "__unrecovered__" {
                    // classify by the preceding non-empty line's leading keyword
                    let prev = lines[..i]
                        .iter()
                        .rev()
                        .find(|l| !l.trim().is_empty())
                        .map(|l| l.trim())
                        .unwrap_or("");
                    let kw = prev.split_whitespace().next().unwrap_or("<start>");
                    format!("STMT after `{}`", kw)
                } else {
                    // inline: capture the marker's immediate textual neighborhood
                    let pos = line.find("__unrecovered__").unwrap();
                    let before = &line[..pos];
                    let lead = before.trim_start();
                    let head = lead.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
                    format!("EXPR `{}…`", head)
                };
                *tally.entry(sig.clone()).or_default() += 1;
                example.entry(sig).or_insert_with(|| {
                    format!("{} :: {}", code.name, trimmed)
                });
            }
        }
    }

    let mut v: Vec<(String, usize)> = tally.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    println!("objects with markers: {}", objects);
    for (sig, n) in v.iter().take(40) {
        println!("{:6}  {:40}  e.g. {}", n, sig, example.get(sig).map(|s| s.as_str()).unwrap_or(""));
    }

    // If a focus signature is given, dump full ±4-line context for up to 6 examples.
    let Some(focus) = args.get(2) else { return };
    println!("\n==== context for `{}` ====", focus);
    let mut shown = 0;
    'outer: for path in &files {
        let Ok(data) = std::fs::read(path) else { continue };
        if data.len() < 8 { continue; }
        let Ok(obj) = py27_marshal::read::marshal_loads(&data[8..]) else { continue };
        let Obj::Code(root) = obj else { continue };
        let mut all = Vec::new();
        collect(&root, &mut all);
        for code in &all {
            let Ok(structured) = unfuck::ir::DecodedFunction::decode(code.clone())
                .and_then(|f| f.structure()) else { continue };
            let source = structured.to_source(&[]);
            if !source.contains("__unrecovered__") { continue; }
            let lines: Vec<&str> = source.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.contains("__unrecovered__") || line.trim() != "__unrecovered__" { continue; }
                let prev = lines[..i].iter().rev().find(|l| !l.trim().is_empty()).map(|l| l.trim()).unwrap_or("");
                let kw = prev.split_whitespace().next().unwrap_or("<start>");
                if format!("STMT after `{}`", kw) != *focus { continue; }
                println!("-- {} :: {} --", path.file_name().unwrap().to_string_lossy(), code.name);
                let lo = i.saturating_sub(4);
                let hi = (i + 2).min(lines.len());
                for l in &lines[lo..hi] { println!("  |{}", l); }
                shown += 1;
                if shown >= 6 { break 'outer; }
            }
        }
    }
}
