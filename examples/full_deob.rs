//! Run the full deobfuscation pipeline (for debugging the deob passes).
//! Usage: full_deob <input.pyc> <output.pyc>
use pydis::opcode::py27::Standard;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).expect("read input pyc");
    let header = data[..8].to_vec();
    let deob = unfuck::Deobfuscator::<Standard>::new(&data[8..]);
    let result = deob.deobfuscate().expect("deobfuscation failed");
    let mut out = header;
    out.extend_from_slice(&result.data);
    std::fs::write(&args[2], &out).expect("write output pyc");
    println!("wrote {} ({} bytes body)", &args[2], result.data.len());
}
