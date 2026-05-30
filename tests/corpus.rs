//! Snapshot tests over real Python 2.7 fixtures.
//!
//! Each function in `tests/fixtures/cases.pyc` (compiled from `cases.py`) is
//! decompiled and snapshotted, so changes to the emitter show up as reviewable
//! diffs (`cargo insta review`). Because the fixtures are compiled directly,
//! their variable names are the originals, not the deobfuscator's `unknown_N`.

use std::sync::Arc;

use py27_marshal::{Code, Obj};

fn find(code: &Arc<std::sync::RwLock<Code>>, target: &str) -> Option<Arc<Code>> {
    let guard = code.read().unwrap();
    if guard.name.to_string() == target {
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

fn decompile(fixture: &[u8], name: &str) -> String {
    let obj = py27_marshal::read::marshal_loads(&fixture[8..]).expect("marshal");
    let root = match obj {
        Obj::Code(code) => code,
        _ => panic!("fixture root is not a code object"),
    };
    let code = find(&root, name).unwrap_or_else(|| panic!("no function named {}", name));
    unfuck::ir::decompile_function(code).unwrap_or_else(|err| format!("# decompile error: {}", err))
}

#[test]
fn cases() {
    let fixture = include_bytes!("fixtures/cases.pyc");
    for name in [
        "arithmetic",
        "attr_call",
        "call_kw",
        "guard",
        "if_else",
        "do_raise",
        "sum_list",
        "count_down",
        "unpack",
        "make_dict",
        "both",
        "either",
        "guard_chain",
        "outer",
        "pairs",
        "choose",
        "choose_not",
        "aug_name",
        "aug_attr",
        "aug_subscript",
        "try_bare",
        "try_typed",
        "gen_squares",
        "gen_filtered",
        "gen_consumed",
        "dict_comp",
        "dict_comp_filtered",
        "set_comp",
        "list_comp",
        "list_comp_filtered",
        "list_comp_stored",
        "empty_list_arg",
        "do_imports",
        "make_class",
        "make_empty",
    ] {
        insta::assert_snapshot!(name, decompile(fixture, name));
    }
}
