//! Run the deobfuscator in minimal mode and write a loadable .pyc.
//!
//! Minimal mode repairs basic blocks and serializes terminating bytecode but
//! leaves opaque predicates and dead code in place. It is a diagnostic tool for
//! inspecting the pre-pruning CFG: running `decompile_one --stats` on the output
//! shows the raising IR cannot fold the flattening itself (its symbolic execution
//! assumes stack-neutral, execution-ordered blocks), which is why the default
//! pipeline un-flattens at the bytecode level first.
//!
//! Usage: minimal_deob <input.pyc> <output.pyc>

use pydis::opcode::py27::Standard;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: minimal_deob <input.pyc> <output.pyc>");
        std::process::exit(2);
    }
    let (input, output) = (&args[1], &args[2]);

    let data = std::fs::read(input).expect("read input pyc");
    // The first 8 bytes are the magic + mtime header; the deobfuscator works on
    // the marshalled body and we reuse the original header on the way out.
    let header = data[..8].to_vec();

    let deob = unfuck::Deobfuscator::<Standard>::new(&data[8..]).minimal();
    let result = deob.deobfuscate().expect("minimal deobfuscation failed");

    let mut out = header;
    out.extend_from_slice(&result.data);
    std::fs::write(output, &out).expect("write output pyc");
    println!(
        "wrote minimal-deob pyc to {} ({} bytes body)",
        output,
        result.data.len()
    );
}
