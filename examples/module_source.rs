//! Decompile a single `.pyc` via the real whole-module path (`decompile_module`, the
//! same path the archive consumer uses) and print the recovered source to stdout. Unlike
//! the per-object function path, this folds dict/set comprehensions inline, so it is the
//! correct way to audit a module's true recovery. Usage: module_source <pyc>

use py27_marshal::Obj;

fn main() {
    let path = std::env::args().nth(1).expect("usage: module_source <pyc>");
    let bytes = std::fs::read(&path).expect("read pyc");
    let obj = py27_marshal::read::marshal_loads(&bytes[8..]).expect("marshal");
    let root = match obj {
        Obj::Code(code) => code,
        _ => panic!("root is not a code object"),
    };
    print!("{}", unfuck::ir::decompile_module(&root));
}
