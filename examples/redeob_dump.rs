//! Re-deobfuscate every `*_stage4.pyc` and decompile the result, writing the source to
//! a sibling `*_stage4_deob.pyc.<suffix>`. Used to validate a deobfuscator change in
//! isolation: run once at the baseline build, once with the change, and diff the two
//! suffixes. Combines the deob + IR decompile so the comparison reflects exactly the
//! end-to-end output the archive consumer sees.
//!
//! Usage: redeob_dump <dir> <suffix>

use std::sync::{Arc, RwLock};

use py27_marshal::{Code, Obj};
use pydis::opcode::py27::Standard;

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            let name = path.to_string_lossy();
            if name.ends_with("_stage4.pyc") && !name.ends_with("_stage4_deob.pyc") {
                out.push(path);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: redeob_dump <dir> <suffix>"));
    let suffix = args.get(2).expect("usage: redeob_dump <dir> <suffix>");
    std::panic::set_hook(Box::new(|_| {}));

    let mut files = Vec::new();
    walk(&dir, &mut files);
    files.sort();

    let mut written = 0usize;
    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if data.len() <= 8 {
            continue;
        }
        let result = std::panic::catch_unwind(|| {
            let deob = unfuck::Deobfuscator::<Standard>::new(&data[8..]);
            deob.deobfuscate()
        });
        let body = match result {
            Ok(Ok(r)) => r.data,
            _ => continue,
        };
        let root: Arc<RwLock<Code>> = match py27_marshal::read::marshal_loads(&body) {
            Ok(Obj::Code(code)) => code,
            _ => continue,
        };
        let src = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unfuck::ir::decompile_module(&root)
        }))
        .unwrap_or_else(|_| String::from("# PANIC during decompile\n"));
        // <name>_stage4.pyc -> <name>_stage4_deob.pyc.<suffix>
        let stem = path.to_string_lossy();
        let out_path = stem.replace("_stage4.pyc", "_stage4_deob.pyc") + "." + suffix;
        if std::fs::write(&out_path, &src).is_ok() {
            written += 1;
        }
    }
    println!("wrote {} re-deob dumps (suffix .{})", written, suffix);
}
