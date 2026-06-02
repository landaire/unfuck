//! Re-deobfuscate every `*_stage4.pyc` and overwrite its `*_stage4_deob.pyc`. Used to
//! regenerate the archive's deobfuscated ground truth after a deobfuscator change.
//!
//! Usage: deob_archive <dir>

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
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: deob_archive <dir>"));
    std::panic::set_hook(Box::new(|_| {}));

    let mut files = Vec::new();
    walk(&dir, &mut files);
    files.sort();

    let mut written = 0usize;
    let mut failed = 0usize;
    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if data.len() <= 8 {
            continue;
        }
        let header = data[..8].to_vec();
        let result = std::panic::catch_unwind(|| {
            let deob = unfuck::Deobfuscator::<Standard>::new(&data[8..]);
            deob.deobfuscate()
        });
        let body = match result {
            Ok(Ok(r)) => r.data,
            _ => {
                failed += 1;
                continue;
            }
        };
        let mut out = header;
        out.extend_from_slice(&body);
        let out_path = path.to_string_lossy().replace("_stage4.pyc", "_stage4_deob.pyc");
        if std::fs::write(&out_path, &out).is_ok() {
            written += 1;
        }
    }
    println!("wrote {} deob pyc, {} failed", written, failed);
}
