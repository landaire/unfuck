//! Decompile a single named code object from a .pyc with the raising IR.
//!
//! Usage: decompile_one <pyc> <co_name substring>

use std::sync::Arc;

use py27_marshal::{Code, Obj};

fn find(code: &Arc<std::sync::RwLock<Code>>, target: &str) -> Option<Arc<Code>> {
    let guard = code.read().unwrap();
    if guard.name.to_string().contains(target) {
        return Some(Arc::new(guard.clone()));
    }
    for konst in guard.consts.iter() {
        if let Obj::Code(inner) = konst {
            if let Some(found) = find(inner, target) {
                return Some(found);
            }
        }
    }
    None
}

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
    let (path, target) = (&args[1], &args[2]);

    let data = std::fs::read(path).expect("read pyc");
    let obj = py27_marshal::read::marshal_loads(&data[8..]).expect("marshal");
    let root = match obj {
        Obj::Code(code) => code,
        _ => panic!("not a code object"),
    };

    if target == "--validate" {
        let dir = std::path::Path::new(&args[3]);
        std::fs::create_dir_all(dir).expect("create dir");
        let mut all = Vec::new();
        collect(&root, &mut all);
        let mut written = 0usize;
        for (index, code) in all.into_iter().enumerate() {
            if let Ok(source) = unfuck::ir::decompile_function(code) {
                let path = dir.join(format!("f{}.py", index));
                std::fs::write(&path, source).expect("write");
                written += 1;
            }
        }
        println!("wrote {} decompiled sources to {}", written, dir.display());
        return;
    }

    if target == "--stats" {
        let mut all = Vec::new();
        collect(&root, &mut all);
        let total = all.len();
        let mut ok = 0usize;
        let mut by_error: std::collections::BTreeMap<String, usize> = Default::default();
        for code in all {
            match unfuck::ir::decompile_function(code) {
                Ok(_) => ok += 1,
                Err(err) => *by_error.entry(format!("{}", err)).or_default() += 1,
            }
        }
        println!("decompiled {}/{} code objects", ok, total);
        for (err, count) in by_error {
            println!("  {:>4}  {}", count, err);
        }
        return;
    }

    let code = find(&root, target).unwrap_or_else(|| panic!("no code object matching {}", target));
    match unfuck::ir::decompile_function(code) {
        Ok(source) => println!("{}", source),
        Err(err) => println!("# decompile error: {}", err),
    }
}
