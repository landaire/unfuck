//! Dump every `*_stage4_deob.pyc` under a directory to a sibling `.pyc.newdump`
//! file via `decompile_module`, so a build's whole-archive output can be byte-diffed
//! against a baseline `*_stage4_deob.py` produced by an earlier build. Same `.pyc`
//! inputs, so any diff isolates a decompiler change (not the deobfuscation pipeline).
//!
//! Usage: dump_dir <dir> [suffix]
//!   suffix defaults to `_stage4_deob.pyc`.

use py27_marshal::Obj;

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
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: dump_dir <dir> [suffix]"));
    let suffix = args.get(2).map(|s| s.as_str()).unwrap_or("_stage4_deob.pyc");

    let mut files = Vec::new();
    walk(&dir, suffix, &mut files);
    files.sort();

    let mut written = 0usize;
    for path in &files {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let obj = match py27_marshal::read::marshal_loads(&data[8..]) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let root = match obj {
            Obj::Code(code) => code,
            _ => continue,
        };
        let combined = unfuck::ir::decompile_module(&root);
        let out_path = path.with_extension("pyc.newdump");
        std::fs::write(&out_path, &combined).expect("write dump");
        written += 1;
    }
    println!("wrote {} dumps", written);
}
