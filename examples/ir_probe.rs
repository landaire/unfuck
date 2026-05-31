//! Diagnostic: show every code object whose IR output is incomplete, with the
//! `__unrecovered__` lines in context so the missing construct is identifiable.
//!
//! Usage: ir_probe <pyc>

use std::sync::Arc;

use py27_marshal::{Code, Obj};

fn collect(code: &Arc<std::sync::RwLock<Code>>, out: &mut Vec<Arc<Code>>) {
    let guard = code.read().unwrap();
    out.push(Arc::new(guard.clone()));
    for konst in guard.consts.iter() {
        if let Obj::Code(inner) = konst {
            collect(inner, out);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).expect("read pyc");
    let obj = py27_marshal::read::marshal_loads(&data[8..]).expect("marshal");
    let root = match obj {
        Obj::Code(code) => code,
        _ => panic!("not a code object"),
    };
    let mut all = Vec::new();
    collect(&root, &mut all);

    for code in &all {
        let name = code.name.to_string();
        // Reach past decompile_function's Incomplete rejection to inspect the
        // partial source directly.
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
        println!("==== {} ====", name);
        let lines: Vec<&str> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("__unrecovered__") {
                let lo = i.saturating_sub(2);
                let hi = (i + 3).min(lines.len());
                for l in &lines[lo..hi] {
                    println!("  {}", l);
                }
                println!("  ---");
            }
        }
    }
}
