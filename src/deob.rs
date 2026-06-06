use log::trace;

use py27_marshal::bstr::BString;
use py27_marshal::{Code, CodeFlags, Obj};
use pydis::opcode::py27::{self};
use pydis::prelude::*;
use std::collections::{HashMap, HashSet};

use std::sync::{Arc, RwLock};

use crate::code_graph::*;
use crate::error::Error;
use crate::{DeobfuscatedBytecode, Deobfuscator};

/// Linearly decodes `bytecode` and checks that every jump lands on an instruction
/// boundary (or the end). A bad cross-block dead-operand removal can shift a live
/// jump so it points into the middle of an instruction or past the end; that
/// bytecode no longer decodes, so the caller falls back to the conservative
/// own-block-only removal. Returns true when the bytecode is structurally sound.
fn bytecode_structurally_valid<O: Opcode<Mnemonic = py27::Mnemonic>>(bytecode: &[u8]) -> bool {
    let mut boundaries = HashSet::new();
    let mut targets = Vec::new();
    let mut cursor = std::io::Cursor::new(bytecode);
    let len = bytecode.len() as u64;
    while cursor.position() < len {
        boundaries.insert(cursor.position());
        let instr = match decode_py27::<O, _>(&mut cursor) {
            Ok(instr) => instr,
            Err(_) => return false,
        };
        let next = cursor.position();
        if let Some(arg) = instr.arg {
            if instr.opcode.is_absolute_jump() {
                targets.push(arg as u64);
            } else if instr.opcode.is_relative_jump() {
                targets.push(next + arg as u64);
            }
        }
    }
    boundaries.insert(len);
    targets.iter().all(|target| boundaries.contains(target))
}

impl<'a, TargetOpcode: Opcode<Mnemonic = py27::Mnemonic> + PartialEq>
    Deobfuscator<'a, TargetOpcode>
{
    /// Deobfuscate the given code object. This will remove opaque predicates where possible,
    /// simplify control flow to only go forward where possible, and rename local variables. This returns
    /// the new bytecode and any function names resolved while deobfuscating the code object.
    ///
    /// The returned HashMap is keyed by the code object's `$filename_$name` with a value of
    /// what the suspected function name is.
    ///
    /// Runs the deobfuscation with cross-block dead-operand removal enabled and, if
    /// that yields structurally invalid bytecode (a jump landing mid-instruction --
    /// possible when a removed closure shifted a live jump's layout), retries once
    /// with the conservative own-block-only removal, which is always sound.
    pub(crate) fn deobfuscate_code(
        &self,
        code: Arc<Code>,
        file_identifier: usize,
    ) -> Result<DeobfuscatedBytecode, Error<TargetOpcode>> {
        let result = self.deobfuscate_code_inner(Arc::clone(&code), file_identifier, true)?;
        if self.minimal || bytecode_structurally_valid::<TargetOpcode>(&result.new_bytecode) {
            return Ok(result);
        }
        self.deobfuscate_code_inner(code, file_identifier, false)
    }

    fn deobfuscate_code_inner(
        &self,
        code: Arc<Code>,
        file_identifier: usize,
        enable_cross_block: bool,
    ) -> Result<DeobfuscatedBytecode, Error<TargetOpcode>> {
        let debug = !true;

        let _bytecode = code.code.as_slice();
        let _consts = Arc::clone(&code.consts);
        let mut new_bytecode: Vec<u8> = vec![];
        let mut mapped_function_names = HashMap::new();
        let mut plain_imported_modules = HashSet::new();

        let mut code_graph = CodeGraph::<TargetOpcode>::from_code(
            Arc::clone(&code),
            file_identifier,
            self.enable_dotviz_graphs,
            self.on_graph_generated.as_ref(),
            self.on_store_to_named_var.as_ref(),
        )?;

        code_graph.generate_dot_graph("before");

        code_graph.fix_bbs_with_bad_instr(code_graph.root, &code);

        code_graph.generate_dot_graph("target");

        if self.minimal {
            // Leave opaque predicates and dead code in place for the IR to fold;
            // just produce serializable, terminating bytecode.
            code_graph.update_bb_offsets();
            code_graph.ensure_terminal_returns(&code);
            code_graph.update_bb_offsets();
            code_graph.update_branches();
        } else {
            // The full deob transform sequence, factored onto the graph so the graph-to-IR
            // path (`CodeGraph::deobfuscate_from_code`) shares it.
            code_graph.run_full_deob_passes(
                &code,
                &mut mapped_function_names,
                &mut plain_imported_modules,
                enable_cross_block,
            );
        }

        // code_graph.insert_jump_0();
        // code_graph.update_bb_offsets();

        code_graph.generate_dot_graph("offsets");

        code_graph.write_bytecode(code_graph.root, &mut new_bytecode);

        if debug {
            let mut cursor = std::io::Cursor::new(&new_bytecode);
            trace!("{}", cursor.position());
            while let Ok(instr) = decode_py27::<TargetOpcode, _>(&mut cursor) {
                trace!("{:?}", instr);
                trace!("");
                trace!("{}", cursor.position());
            }
        }

        let key = format!("{}_{}_{}", code.filename, code.name, code.code.len(),);

        if code.flags.contains(CodeFlags::GENERATOR) {
            mapped_function_names.insert(key.clone(), "<genexpr>".to_string());
        } else {
            match code_graph.graph[code_graph.root].instrs[0]
                .unwrap()
                .opcode
                .mnemonic()
            {
                py27::Mnemonic::BUILD_MAP => {
                    mapped_function_names.insert(key, "<dictcomp>".to_string());
                }
                py27::Mnemonic::BUILD_SET => {
                    mapped_function_names.insert(key, "<setcomp>".to_string());
                }
                _ => {}
            }
        }

        Ok(DeobfuscatedBytecode {
            file_number: file_identifier,
            new_bytecode,
            mapped_function_names,
            graphviz_graphs: code_graph.dotviz_graphs,
        })
    }

    /// Rebuild the code-object tree with deobfuscated bytecode and cleaned-up
    /// variable names, then marshal it back to bytes -- entirely in Rust, with
    /// no Python/GIL involvement.
    ///
    /// `original_root` is the input code tree (used for structure and the
    /// original names); `deob_codes` holds the deobfuscated bytecode for each
    /// code object in DFS pre-order, matching the order `deobfuscate_nested_code_objects`
    /// produced them, which is also the order this walk consumes them.
    pub(crate) fn rename_vars(
        &self,
        original_root: &Code,
        deob_codes: &[Vec<u8>],
        mapped_function_names: &HashMap<String, String>,
    ) -> Vec<u8> {
        let mut next_code = 0usize;
        let mut unknowns = 0usize;
        let new_root = cleanup_code_obj(
            original_root,
            deob_codes,
            &mut next_code,
            mapped_function_names,
            &mut unknowns,
        );
        debug_assert_eq!(
            next_code,
            deob_codes.len(),
            "every deobfuscated code object must map to exactly one tree node"
        );
        py27_marshal::write::marshal_dumps(&Obj::Code(Arc::new(RwLock::new(new_root))))
    }
}

/// Recursively rebuild a code object: swap in its deobfuscated bytecode (taken
/// from `deob_codes` in DFS pre-order), recurse into nested code consts, and
/// rename its names/varnames. This mirrors the original Python `cleanup_code_obj`.
fn cleanup_code_obj(
    code: &Code,
    deob_codes: &[Vec<u8>],
    next_code: &mut usize,
    mapped_function_names: &HashMap<String, String>,
    unknowns: &mut usize,
) -> Code {
    let new_code = deob_codes[*next_code].clone();
    *next_code += 1;

    // Resolve the display name: a recovered comprehension/lambda name from the
    // deobfuscator's map, otherwise the cleaned-up original name.
    let key = format!("{}_{}_{}", code.filename, code.name, code.code.len());
    let base_name: Vec<u8> = if let Some(mapped) = mapped_function_names.get(&key) {
        mapped.clone().into_bytes()
    } else {
        fix_one_varname(&code.name[..], unknowns)
    };
    let filename = base_name.clone();

    let mut new_consts = Vec::with_capacity(code.consts.len());
    for konst in code.consts.iter() {
        if let Obj::Code(inner) = konst {
            let inner = inner.read().unwrap_or_else(|e| e.into_inner());
            let cleaned = cleanup_code_obj(
                &inner,
                deob_codes,
                next_code,
                mapped_function_names,
                unknowns,
            );
            new_consts.push(Obj::Code(Arc::new(RwLock::new(cleaned))));
        } else {
            new_consts.push(konst.clone());
        }
    }

    // Real functions get an `_orig_<original>` suffix so identically-named ones
    // stay distinct; synthetic names like `<module>`/`<listcomp>` are kept as-is.
    let name = if base_name.contains(&b'<') {
        base_name
    } else {
        let mut n = base_name;
        n.extend_from_slice(b"_orig_");
        n.extend_from_slice(&code.name[..]);
        n
    };

    Code {
        argcount: code.argcount,
        nlocals: code.nlocals,
        stacksize: code.stacksize,
        flags: code.flags,
        code: Arc::new(new_code),
        consts: Arc::new(new_consts),
        names: fix_varnames(&code.names, unknowns),
        varnames: fix_varnames(&code.varnames, unknowns),
        // freevars/cellvars are passed through unchanged, as in the original.
        freevars: code.freevars.clone(),
        cellvars: code.cellvars.clone(),
        filename: Arc::new(BString::from(filename)),
        name: Arc::new(BString::from(name)),
        firstlineno: code.firstlineno,
        lnotab: Arc::clone(&code.lnotab),
    }
}

fn fix_varnames(varnames: &[Arc<BString>], unknowns: &mut usize) -> Vec<Arc<BString>> {
    varnames
        .iter()
        .map(|var| Arc::new(BString::from(fix_one_varname(&var[..], unknowns))))
        .collect()
}

/// Replace a name that is unusable as a meaningful Python identifier (contains a
/// forbidden character, is a reserved word, or is only underscores) with a fresh
/// `unknown_N` placeholder; otherwise return it trimmed. Operates on raw bytes to
/// match the original Python byte-string behavior.
fn fix_one_varname(var: &[u8], unknowns: &mut usize) -> Vec<u8> {
    // Characters that cannot appear in a Python identifier. `<`, `>`, and `.` are
    // deliberately NOT here: the synthetic names `<dictcomp>`/`<genexpr>`/`<lambda>`
    // and the comprehension argument `.0` must survive unchanged, as the decompiler
    // keys comprehension and lambda recovery on them.
    const UNALLOWED: &[u8] = b"=!@#$%^&*()\"'/, ";
    const BANNED_WORDS: &[&[u8]] = &[
        b"assert", b"in", b"continue", b"break", b"for", b"def", b"as", b"elif", b"else", b"from",
        b"global", b"if", b"import", b"is", b"lambda", b"not", b"or", b"pass", b"print", b"return",
        b"while", b"with",
    ];

    let var = trim_ascii_whitespace(var);
    // An all-underscore name (`_`, `__`, ...) is a valid identifier but carries no
    // meaning -- the obfuscator uses it as a junk name (e.g. a real accumulator renamed
    // to `_`). Normalize it to `unknown_N` like the other junk names.
    let all_underscore = !var.is_empty() && var.iter().all(|&b| b == b'_');
    // A digit-leading name (`4`, `105080795735848`) is not a valid identifier; the
    // emitter would otherwise mangle its leading digit into `_`. (The synthetic
    // `<...>`/`.0` names are not digit-leading, so they are unaffected.)
    let digit_leading = var.first().is_some_and(u8::is_ascii_digit);
    let banned = var.iter().any(|b| UNALLOWED.contains(b))
        || BANNED_WORDS.iter().any(|word| *word == var)
        || all_underscore
        || digit_leading;

    if banned {
        let replacement = format!("unknown_{}", *unknowns).into_bytes();
        *unknowns += 1;
        replacement
    } else {
        var.to_vec()
    }
}

fn trim_ascii_whitespace(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_graph::tests::*;
    use crate::smallvm::PYTHON27_COMPARE_OPS;
    use crate::smallvm::tests::*;
    use crate::{Instr, Long};
    use num_bigint::BigInt;
    use py27_marshal::Obj;
    use pydis::opcode::Instruction;
    use std::sync::Mutex;

    type TargetOpcode = pydis::opcode::py27::Standard;

    #[test]
    fn fix_one_varname_renames_junk_names() {
        let mut n = 0;
        // All-underscore names are junk and get fresh placeholders.
        assert_eq!(fix_one_varname(b"_", &mut n), b"unknown_0".to_vec());
        assert_eq!(fix_one_varname(b"___", &mut n), b"unknown_1".to_vec());
        // A digit-only / digit-leading name is not a valid identifier (the emitter would
        // otherwise mangle it into `_`); rename it too.
        assert_eq!(fix_one_varname(b"4", &mut n), b"unknown_2".to_vec());
        assert_eq!(fix_one_varname(b"3x", &mut n), b"unknown_3".to_vec());
        // A forbidden-character name stays caught.
        assert_eq!(fix_one_varname(b"a b", &mut n), b"unknown_4".to_vec());
        // A real name is kept, even with a leading underscore or trailing digits.
        assert_eq!(fix_one_varname(b"_foo", &mut n), b"_foo".to_vec());
        assert_eq!(fix_one_varname(b"result2", &mut n), b"result2".to_vec());
        assert_eq!(fix_one_varname(b"__init__", &mut n), b"__init__".to_vec());
        // The synthetic comprehension/lambda names must survive unchanged -- the
        // decompiler keys recovery on them.
        assert_eq!(fix_one_varname(b"<dictcomp>", &mut n), b"<dictcomp>".to_vec());
        assert_eq!(fix_one_varname(b"<genexpr>", &mut n), b"<genexpr>".to_vec());
        assert_eq!(fix_one_varname(b".0", &mut n), b".0".to_vec());
    }

    #[test]
    fn simple_deobfuscation() {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();

        let mut code = default_code_obj();

        let consts = vec![Obj::None, Long!(1), Long!(2)];

        Arc::get_mut(&mut code).unwrap().consts = Arc::new(consts);

        let instrs = [
            // 0
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 3),
            // 3
            Instr!(TargetOpcode::JUMP_ABSOLUTE, 6),
            // 6
            Instr!(TargetOpcode::LOAD_CONST, 1),
            // 9
            Instr!(TargetOpcode::LOAD_CONST, 2),
            // 12. 1 < 2, should evaluate to true
            Instr!(
                TargetOpcode::COMPARE_OP,
                PYTHON27_COMPARE_OPS
                    .iter()
                    .position(|op| *op == "<")
                    .unwrap() as u16
            ),
            // 15
            Instr!(TargetOpcode::POP_JUMP_IF_TRUE, 22), // jump to target 1
            // 18
            Instr!(TargetOpcode::LOAD_CONST, 0),
            // 21
            Instr!(TargetOpcode::RETURN_VALUE),
            // 22
            Instr!(TargetOpcode::LOAD_CONST, 1), // target 1
            // 25
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        let expected = [
            Instr!(TargetOpcode::LOAD_CONST, 1),
            Instr!(TargetOpcode::RETURN_VALUE),
        ];

        change_code_instrs(&mut code, &instrs[..]);

        let res = Deobfuscator::<TargetOpcode>::new(&code.code.as_slice())
            .deobfuscate_code(Arc::clone(&code), 0)
            .expect("failed to deobfuscate bytecode");

        // We now need to change this back into a graph for ease of testing
        let mut expected_bytecode = vec![];
        for instr in &expected {
            serialize_instr(instr, &mut expected_bytecode);
        }

        assert_eq!(res.new_bytecode, expected_bytecode);
    }
}
