#!/usr/bin/env python3
"""Fix all unfuck source files for Mutex migration of py27-marshal Obj."""

import re


def fix_file(path, replacements, description):
    with open(path, "r") as f:
        content = f.read()

    applied = 0
    for old, new in replacements:
        count = content.count(old)
        if count > 0:
            content = content.replace(old, new)
            applied += count
        else:
            print(f"  WARNING: not found in {description}: {old[:60]!r}...")

    with open(path, "w") as f:
        f.write(content)

    print(f"{description}: {applied} replacements applied")
    return applied


def fix_arithmetic():
    path = "G:/dev/unfuck/src/smallvm/arithmetic.rs"
    with open(path, "r") as f:
        content = f.read()

    # Add Mutex import
    content = content.replace("use std::sync::Arc;", "use std::sync::{Arc, Mutex};")

    # apply_long_long: Arc::new(match ...) -> Arc::new(Mutex::new(match ...))
    content = content.replace(
        "Obj::Long(Arc::new(match self {", "Obj::Long(Arc::new(Mutex::new(match self {"
    )
    content = content.replace(
        """            BinaryOp::Power | BinaryOp::TrueDivide => {
                unreachable!("handled in apply_binary_op directly")
            }
        }))""",
        """            BinaryOp::Power | BinaryOp::TrueDivide => {
                unreachable!("handled in apply_binary_op directly")
            }
        })))""",
    )

    # apply_long_float/apply_float_long: left.to_f64() where left is &BigInt - no change needed (these take &BigInt directly)
    # These helper functions take &BigInt and f64 directly, no Mutex

    # In apply_binary_op, pattern matches on Obj::Long(left) etc - left is now ArcMutex<BigInt>
    # Need to lock for access

    # Power special case - right.sign(), right.as_ref(), left.as_ref()
    content = content.replace(
        "if let num_bigint::Sign::Minus = right.sign() {",
        "if let num_bigint::Sign::Minus = right.lock().unwrap().sign() {",
    )
    content = content.replace(
        "let positive_exponent = (-right.as_ref()).to_u32().unwrap();",
        "let positive_exponent = (-&*right.lock().unwrap()).to_u32().unwrap();",
    )
    content = content.replace(
        "let value = left.as_ref().pow(positive_exponent);",
        "let value = left.lock().unwrap().pow(positive_exponent);",
    )
    content = content.replace(
        "Some(Obj::Float(1.0 / value.to_f64().unwrap())),",
        "Some(Obj::Float(1.0 / value.to_f64().unwrap())),",
    )
    # Positive power
    content = content.replace(
        """                } else {
                    let value = left.as_ref().pow(
                        right
                            .as_ref()
                            .to_u32()
                            .unwrap_or_else(|| panic!("could not convert {:?} to u32", right)),
                    );
                    stack.push((Some(Obj::Long(Arc::new(value))), tos_accesses));""",
        """                } else {
                    let right_guard = right.lock().unwrap();
                    let value = left.lock().unwrap().pow(
                        right_guard
                            .to_u32()
                            .unwrap_or_else(|| panic!("could not convert {:?} to u32", right_guard)),
                    );
                    stack.push((Some(Obj::Long(Arc::new(Mutex::new(value)))), tos_accesses));""",
    )

    # TrueDivide special case
    content = content.replace(
        "let value = left.as_ref().to_f64().unwrap() / right.as_ref().to_f64().unwrap();",
        "let value = left.lock().unwrap().to_f64().unwrap() / right.lock().unwrap().to_f64().unwrap();",
    )

    # apply_long_long call - passes left and right which are ArcMutex<BigInt>, but function takes &BigInt
    content = content.replace(
        "let result = op.apply_long_long(left, right);",
        "let result = op.apply_long_long(&left.lock().unwrap(), &right.lock().unwrap());",
    )

    # apply_long_float / apply_float_long calls
    content = content.replace(
        "let result = op.apply_long_float(left, *right);",
        "let result = op.apply_long_float(&left.lock().unwrap(), *right);",
    )
    content = content.replace(
        "let result = op.apply_float_long(*left, right);",
        "let result = op.apply_float_long(*left, &right.lock().unwrap());",
    )

    # String formatting: left.as_ref().clone() -> lock
    content = content.replace(
        "Some(Obj::String(Arc::new(left.as_ref().clone()))),",
        "Some(Obj::String(Arc::new(Mutex::new(left.lock().unwrap().clone())))),",
    )

    # String * Long: left.repeat(right.to_usize().unwrap())
    content = content.replace(
        "let value = left.repeat(right.to_usize().unwrap());",
        "let value = left.lock().unwrap().repeat(right.lock().unwrap().to_usize().unwrap());",
    )
    content = content.replace(
        "Some(Obj::String(Arc::new(BString::from(value)))),",
        "Some(Obj::String(Arc::new(Mutex::new(BString::from(value))))),",
    )

    # String + Long: Arc::get_mut for mutation
    content = content.replace(
        """                    BinaryOp::Add => {
                        let mut value = left.clone();
                        Arc::get_mut(&mut value)
                            .unwrap()
                            .extend_from_slice(right.to_string().as_bytes());
                        stack.push((Some(Obj::String(value)), tos_accesses));
                    }""",
        """                    BinaryOp::Add => {
                        let mut new_val = left.lock().unwrap().clone();
                        new_val.extend_from_slice(right.lock().unwrap().to_string().as_bytes());
                        stack.push((Some(Obj::String(Arc::new(Mutex::new(new_val)))), tos_accesses));
                    }""",
    )

    # String + String: Arc::get_mut for mutation
    content = content.replace(
        """                    BinaryOp::Add => {
                        let mut value = left.clone();
                        Arc::get_mut(&mut value)
                            .unwrap()
                            .extend_from_slice(right.as_slice());
                        stack.push((Some(Obj::String(value)), tos_accesses));
                    }""",
        """                    BinaryOp::Add => {
                        let mut new_val = left.lock().unwrap().clone();
                        new_val.extend_from_slice(right.lock().unwrap().as_slice());
                        stack.push((Some(Obj::String(Arc::new(Mutex::new(new_val)))), tos_accesses));
                    }""",
    )

    # Tuple + Tuple: Arc::get_mut for mutation
    content = content.replace(
        """        (Some(Obj::Tuple(left)), Some(Obj::Tuple(right))) => match op {
            BinaryOp::Add => {
                let mut value = left.clone();
                Arc::get_mut(&mut value)
                    .unwrap()
                    .extend(right.iter().cloned());
                stack.push((Some(Obj::Tuple(value)), tos_accesses));
            }""",
        """        (Some(Obj::Tuple(left)), Some(Obj::Tuple(right))) => match op {
            BinaryOp::Add => {
                let mut new_val = left.lock().unwrap().clone();
                new_val.extend(right.lock().unwrap().iter().cloned());
                stack.push((Some(Obj::Tuple(Arc::new(Mutex::new(new_val)))), tos_accesses));
            }""",
    )

    # UnaryOp::Not for Long: *result != 0
    content = content.replace(
        "let truthy_value = *result != 0_i32.to_bigint().unwrap();",
        "let truthy_value = *result.lock().unwrap() != 0_i32.to_bigint().unwrap();",
    )

    # UnaryOp::Negative for Long
    content = content.replace(
        "stack.push((Some(Obj::Long(Arc::new(-&*result))), tos_accesses));",
        "stack.push((Some(Obj::Long(Arc::new(Mutex::new(-&*result.lock().unwrap())))), tos_accesses));",
    )

    # execute_shift: Arc::clone(&l) - l is now ArcMutex
    # Actually Arc::clone still works on ArcMutex since it's Arc<Mutex<T>>
    # But we need to lock for .to_usize() and deref
    content = content.replace(
        "let shift_amount = tos_value.unwrap().to_usize().unwrap();",
        "let shift_amount = tos_value.unwrap().lock().unwrap().to_usize().unwrap();",
    )
    content = content.replace(
        "&*tos1_value.unwrap() << shift_amount",
        "&*tos1_value.unwrap().lock().unwrap() << shift_amount",
    )
    content = content.replace(
        "&*tos1_value.unwrap() >> shift_amount",
        "&*tos1_value.unwrap().lock().unwrap() >> shift_amount",
    )
    content = content.replace(
        "stack.push((Some(Obj::Long(Arc::new(value))), tos_accesses));",
        "stack.push((Some(Obj::Long(Arc::new(Mutex::new(value)))), tos_accesses));",
    )

    with open(path, "w") as f:
        f.write(content)
    print("arithmetic.rs: fixed")


def fix_compare():
    path = "G:/dev/unfuck/src/smallvm/compare.rs"
    with open(path, "r") as f:
        content = f.read()

    # For Long comparisons: l and r are ArcMutex<BigInt>, need locking
    # Pattern: l < r, l <= r, l == r, l != r, l > r, l >= r
    # These appear in patterns like: Obj::Long(l) => match right { Obj::Long(r) => stack.push((Some(Obj::Bool(l < r))

    # Replace all Long-Long comparisons
    for op in ["<", "<=", "==", "!=", ">", ">="]:
        content = content.replace(
            f"stack.push((Some(Obj::Bool(l {op} r)), left_modifying_instrs)),",
            f"stack.push((Some(Obj::Bool(*l.lock().unwrap() {op} *r.lock().unwrap())), left_modifying_instrs)),",
        )

    # Long-Float comparisons: l.to_f64()
    content = content.replace(
        "l.to_f64().unwrap() < r)", "l.lock().unwrap().to_f64().unwrap() < r)"
    )
    content = content.replace(
        "l.to_f64().unwrap() <= r)", "l.lock().unwrap().to_f64().unwrap() <= r)"
    )
    content = content.replace(
        "l.to_f64().unwrap() == r)", "l.lock().unwrap().to_f64().unwrap() == r)"
    )
    content = content.replace(
        "l.to_f64().unwrap() != r)", "l.lock().unwrap().to_f64().unwrap() != r)"
    )
    content = content.replace(
        "l.to_f64().unwrap() > r)", "l.lock().unwrap().to_f64().unwrap() > r)"
    )
    content = content.replace(
        "l.to_f64().unwrap() >= r)", "l.lock().unwrap().to_f64().unwrap() >= r)"
    )

    # Float-Long comparisons: r.to_f64()
    content = content.replace(
        "l < r.to_f64().unwrap())", "l < r.lock().unwrap().to_f64().unwrap())"
    )
    content = content.replace(
        "l <= r.to_f64().unwrap())", "l <= r.lock().unwrap().to_f64().unwrap())"
    )
    content = content.replace(
        "l == r.to_f64().unwrap())", "l == r.lock().unwrap().to_f64().unwrap())"
    )
    content = content.replace(
        "l != r.to_f64().unwrap())", "l != r.lock().unwrap().to_f64().unwrap())"
    )
    content = content.replace(
        "l > r.to_f64().unwrap())", "l > r.lock().unwrap().to_f64().unwrap())"
    )
    content = content.replace(
        "l >= r.to_f64().unwrap())", "l >= r.lock().unwrap().to_f64().unwrap())"
    )

    # Bool <= Long: (l as u32).to_bigint().unwrap() <= *r
    content = content.replace(
        "(l as u32).to_bigint().unwrap() <= *r)",
        "(l as u32).to_bigint().unwrap() <= *r.lock().unwrap())",
    )

    # String comparisons - left and right are ArcMutex<BString>
    # left.len(), right.len(), left[idx], right[idx]
    content = content.replace(
        """            Obj::String(left) => match right {
                Obj::String(right) => {
                    for idx in 0..std::cmp::min(left.len(), right.len()) {
                        if left[idx] != right[idx] {
                            stack.push((
                                Some(Obj::Bool(left[idx] < right[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left.len() < right.len())),
                        left_modifying_instrs,
                    ))
                }""",
        """            Obj::String(left) => match right {
                Obj::String(right) => {
                    let left_guard = left.lock().unwrap();
                    let right_guard = right.lock().unwrap();
                    for idx in 0..std::cmp::min(left_guard.len(), right_guard.len()) {
                        if left_guard[idx] != right_guard[idx] {
                            stack.push((
                                Some(Obj::Bool(left_guard[idx] < right_guard[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left_guard.len() < right_guard.len())),
                        left_modifying_instrs,
                    ))
                }""",
    )

    # String > comparison
    content = content.replace(
        """            Obj::String(left) => match right {
                Obj::String(right) => {
                    for idx in 0..std::cmp::min(left.len(), right.len()) {
                        if left[idx] != right[idx] {
                            stack.push((
                                Some(Obj::Bool(left[idx] > right[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left.len() > right.len())),
                        left_modifying_instrs,
                    ))
                }""",
        """            Obj::String(left) => match right {
                Obj::String(right) => {
                    let left_guard = left.lock().unwrap();
                    let right_guard = right.lock().unwrap();
                    for idx in 0..std::cmp::min(left_guard.len(), right_guard.len()) {
                        if left_guard[idx] != right_guard[idx] {
                            stack.push((
                                Some(Obj::Bool(left_guard[idx] > right_guard[idx])),
                                left_modifying_instrs,
                            ));
                            return Ok(());
                        }
                    }
                    stack.push((
                        Some(Obj::Bool(left_guard.len() > right_guard.len())),
                        left_modifying_instrs,
                    ))
                }""",
    )

    # "in" operator: ObjHashable::String(left) - left is ArcMutex<BString>, but ObjHashable::String takes Arc<BString>
    # Need to clone the inner value
    content = content.replace(
        """        "in" => match left {
            Obj::String(left) => match right {
                Obj::Dict(set) => {
                    let dict = set.read().unwrap();
                    let hashed_string = ObjHashable::String(left);""",
        """        "in" => match left {
            Obj::String(left) => match right {
                Obj::Dict(set) => {
                    let dict = set.read().unwrap();
                    let hashed_string = ObjHashable::String(Arc::new(left.lock().unwrap().clone()));""",
    )
    content = content.replace(
        """                Obj::Set(set) => {
                    let set = set.read().unwrap();
                    let hashed_string = ObjHashable::String(left);""",
        """                Obj::Set(set) => {
                    let set = set.read().unwrap();
                    let hashed_string = ObjHashable::String(Arc::new(left.lock().unwrap().clone()));""",
    )
    # "in" List - comparing strings
    content = content.replace(
        """                Obj::List(set) => {
                    let list = set.read().unwrap();
                    let list_contains = list.iter().find(|obj| {
                        if let Obj::String(list_item) = obj {
                            *list_item == left
                        } else {
                            false
                        }
                    });""",
        """                Obj::List(set) => {
                    let list = set.read().unwrap();
                    let left_guard = left.lock().unwrap();
                    let list_contains = list.iter().find(|obj| {
                        if let Obj::String(list_item) = obj {
                            *list_item.lock().unwrap() == *left_guard
                        } else {
                            false
                        }
                    });""",
    )

    # Add Arc import (already has use std::sync::Arc via py27_marshal::*)
    # Actually compare.rs uses `use py27_marshal::*;` which brings in Arc through reexports? No.
    # Let's add the import
    if "use std::sync::Arc;" not in content:
        content = content.replace(
            "use super::{PYTHON27_COMPARE_OPS, VmStack};",
            "use std::sync::Arc;\nuse super::{PYTHON27_COMPARE_OPS, VmStack};",
        )

    with open(path, "w") as f:
        f.write(content)
    print("compare.rs: fixed")


def fix_collections():
    path = "G:/dev/unfuck/src/smallvm/collections.rs"
    with open(path, "r") as f:
        content = f.read()

    # Add Mutex import
    content = content.replace("use std::sync::Arc;", "use std::sync::{Arc, Mutex};")

    # STORE_SUBSCR List: index = key.extract_long() - returns ArcMutex<BigInt>
    content = content.replace(
        """                    Obj::List(list_lock) => {
                        let mut list = list_lock.write().unwrap();
                        let index = key.extract_long().expect("key is not a long");
                        let index = index
                            .to_usize()
                            .expect("index cannot be converted to usize");""",
        """                    Obj::List(list_lock) => {
                        let mut list = list_lock.write().unwrap();
                        let index = key.extract_long().expect("key is not a long");
                        let index = index
                            .lock()
                            .unwrap()
                            .to_usize()
                            .expect("index cannot be converted to usize");""",
    )

    # BINARY_SUBSC Long: long.to_usize() - long is ArcMutex<BigInt>
    content = content.replace(
        """                    if let Obj::Long(long) = tos.unwrap() {
                        if long.to_usize().unwrap() >= list.len() {
                            stack.push((None, accessing_instrs));
                        } else {
                            stack.push((
                                Some(list[long.to_usize().unwrap()].clone()),
                                accessing_instrs,
                            ));
                        }""",
        """                    if let Obj::Long(long) = tos.unwrap() {
                        let long_val = long.lock().unwrap();
                        if long_val.to_usize().unwrap() >= list.len() {
                            stack.push((None, accessing_instrs));
                        } else {
                            stack.push((
                                Some(list[long_val.to_usize().unwrap()].clone()),
                                accessing_instrs,
                            ));
                        }""",
    )

    # LIST_APPEND: Arc::get_mut(s).unwrap().push() and .to_u8()
    content = content.replace(
        """                    Some(Obj::String(s)) => {
                        let tos_value = match tos {
                            Obj::Long(l) => Arc::clone(&l),
                            other => panic!("did not expect type: {:?}", other.typ()),
                        }
                        .to_u8();
                        Arc::get_mut(s).unwrap().push(tos_value.unwrap());
                    }
                    Some(Obj::List(list)) => {
                        Arc::get_mut(list).unwrap().write().unwrap().push(tos);
                    }""",
        """                    Some(Obj::String(s)) => {
                        let tos_value = match tos {
                            Obj::Long(l) => l.lock().unwrap().to_u8(),
                            other => panic!("did not expect type: {:?}", other.typ()),
                        };
                        s.lock().unwrap().push(tos_value.unwrap());
                    }
                    Some(Obj::List(list)) => {
                        list.lock().unwrap().write().unwrap().push(tos);
                    }""",
    )

    # BUILD_TUPLE: Arc::new(tuple) -> Arc::new(Mutex::new(tuple))
    content = content.replace(
        "stack.push((Some(Obj::Tuple(Arc::new(tuple))), tuple_accessors));",
        "stack.push((Some(Obj::Tuple(Arc::new(Mutex::new(tuple)))), tuple_accessors));",
    )

    # UNPACK_SEQUENCE: t.iter() where t is ArcMutex<Vec<Obj>>
    content = content.replace(
        """                Some(Obj::Tuple(t)) => {
                    for item in t.iter().rev().take(instr.arg.unwrap() as usize) {""",
        """                Some(Obj::Tuple(t)) => {
                    for item in t.lock().unwrap().iter().rev().take(instr.arg.unwrap() as usize) {""",
    )

    with open(path, "w") as f:
        f.write(content)
    print("collections.rs: fixed")


def fix_mod():
    path = "G:/dev/unfuck/src/smallvm/mod.rs"
    with open(path, "r") as f:
        content = f.read()

    # FOR_ITER: Arc::get_mut(s).unwrap() -> s.lock().unwrap()
    content = content.replace(
        """                Some(Obj::String(s)) => {
                    let s = Arc::get_mut(s).unwrap();
                    if s.is_empty() {
                        return Ok(());
                    }
                    // Iterate front-to-back: remove the first byte
                    let byte = s.remove(0);
                    Some(Obj::Long(Arc::new(byte.to_bigint().unwrap())))""",
        """                Some(Obj::String(s)) => {
                    let mut s_guard = s.lock().unwrap();
                    if s_guard.is_empty() {
                        return Ok(());
                    }
                    // Iterate front-to-back: remove the first byte
                    let byte = s_guard.remove(0);
                    Some(Obj::Long(Arc::new(Mutex::new(byte.to_bigint().unwrap()))))""",
    )

    # Test macros: Long! and String!
    content = content.replace(
        """    macro_rules! Long {
        ($value:expr) => {
            py27_marshal::Obj::Long(Arc::new(BigInt::from($value)))
        };
    }""",
        """    macro_rules! Long {
        ($value:expr) => {
            py27_marshal::Obj::Long(Arc::new(Mutex::new(BigInt::from($value))))
        };
    }""",
    )

    content = content.replace(
        """    macro_rules! String {
        ($value:expr) => {
            py27_marshal::Obj::String(Arc::new(bstr::BString::from($value)))
        };
    }""",
        """    macro_rules! String {
        ($value:expr) => {
            py27_marshal::Obj::String(Arc::new(Mutex::new(bstr::BString::from($value))))
        };
    }""",
    )

    # Test code: Arc::get_mut(&mut code).unwrap().consts = ...
    content = content.replace(
        "Arc::get_mut(&mut code).unwrap().consts", "code.lock().unwrap().consts"
    )

    # Test assertions: *l.as_ref() -> *l.lock().unwrap()
    content = content.replace(
        "*l.as_ref(), expected.to_bigint().unwrap()",
        "*l.lock().unwrap(), expected.to_bigint().unwrap()",
    )

    # Test assertion for extract_long: *list[0].clone().extract_long().unwrap()
    content = content.replace(
        "assert_eq!(*list[0].clone().extract_long().unwrap(), BigInt::from(0x41));",
        "assert_eq!(*list[0].clone().extract_long().unwrap().lock().unwrap(), BigInt::from(0x41));",
    )

    # default_code_obj returns Arc<Code> — now needs to be Arc<Mutex<Code>>
    # Actually, looking at the code, execute_instruction takes Arc<Code>, not Arc<Mutex<Code>>
    # The Code variant in Obj is ArcMutex<Code>, but when we pass it around we often extract it
    # Let me check... the `code` parameter in execute_instruction is Arc<Code>, not ArcMutex
    # So test code that creates Arc<Code> for passing to execute_instruction is fine
    # But the `code` field in Obj::Code is ArcMutex<Code>

    with open(path, "w") as f:
        f.write(content)
    print("mod.rs: fixed")


def fix_lib():
    path = "G:/dev/unfuck/src/lib.rs"
    with open(path, "r") as f:
        content = f.read()

    # deobfuscate: Obj::Code(code) match - code is ArcMutex<Code>
    content = content.replace(
        """        if let py27_marshal::Obj::Code(code) = py27_marshal::read::marshal_loads(self.input)? {
            // This vector will contain the input code object and all nested objects
            let mut results = vec![];
            let mut mapped_names = HashMap::new();
            let mut graphs = HashMap::new();
            let out_results = Arc::new(Mutex::new(vec![]));
            rayon::scope(|scope| {
                self.deobfuscate_nested_code_objects(
                    Arc::clone(&code),""",
        """        if let py27_marshal::Obj::Code(code_mutex) = py27_marshal::read::marshal_loads(self.input)? {
            let code = Arc::new(code_mutex.lock().unwrap().clone());
            // This vector will contain the input code object and all nested objects
            let mut results = vec![];
            let mut mapped_names = HashMap::new();
            let mut graphs = HashMap::new();
            let out_results = Arc::new(Mutex::new(vec![]));
            rayon::scope(|scope| {
                self.deobfuscate_nested_code_objects(
                    Arc::clone(&code),""",
    )

    # deobfuscate_nested_code_objects: Obj::Code(const_code) match
    content = content.replace(
        """        for c in code.consts.iter() {
            if let Obj::Code(const_code) = c {
                let thread_results = Arc::clone(&out_results);
                let thread_code = Arc::clone(const_code);

                self.deobfuscate_nested_code_objects(thread_code, scope, thread_results);
            }
        }""",
        """        for c in code.consts.iter() {
            if let Obj::Code(const_code) = c {
                let thread_results = Arc::clone(&out_results);
                let thread_code = Arc::new(const_code.lock().unwrap().clone());

                self.deobfuscate_nested_code_objects(thread_code, scope, thread_results);
            }
        }""",
    )

    # dump_strings: Obj::Code(code) match
    content = content.replace(
        """    if let py27_marshal::Obj::Code(code) = py27_marshal::read::marshal_loads(data)? {
        Ok(dump_codeobject_strings(pyc_filename, code))""",
        """    if let py27_marshal::Obj::Code(code_mutex) = py27_marshal::read::marshal_loads(data)? {
        let code = Arc::new(code_mutex.lock().unwrap().clone());
        Ok(dump_codeobject_strings(pyc_filename, code))""",
    )

    # dump_codeobject_strings: Obj::String(s) - s is ArcMutex<BString>
    content = content.replace(
        """        if let py27_marshal::Obj::String(s) = c {
            new_strings.lock().unwrap().push(CodeObjString::new(
                code.as_ref(),
                pyc_filename,
                crate::strings::StringType::Const,
                s.to_string().as_ref(),
            ))
        }""",
        """        if let py27_marshal::Obj::String(s) = c {
            new_strings.lock().unwrap().push(CodeObjString::new(
                code.as_ref(),
                pyc_filename,
                crate::strings::StringType::Const,
                s.lock().unwrap().to_string().as_ref(),
            ))
        }""",
    )

    # dump_codeobject_strings: Obj::Code(const_code) - const_code is ArcMutex<Code>
    content = content.replace(
        """    code.consts.par_iter().for_each(|c| {
        if let Obj::Code(const_code) = c {
            // Call deobfuscate_bytecode first since the bytecode comes before consts and other data
            let mut strings = dump_codeobject_strings(pyc_filename, Arc::clone(const_code));""",
        """    code.consts.par_iter().for_each(|c| {
        if let Obj::Code(const_code) = c {
            // Call deobfuscate_bytecode first since the bytecode comes before consts and other data
            let mut strings = dump_codeobject_strings(pyc_filename, Arc::new(const_code.lock().unwrap().clone()));""",
    )

    with open(path, "w") as f:
        f.write(content)
    print("lib.rs: fixed")


def fix_code_graph():
    path = "G:/dev/unfuck/src/code_graph.rs"
    with open(path, "r") as f:
        content = f.read()

    # change_code_instrs: Arc::get_mut(code).unwrap().code = ...
    content = content.replace(
        "Arc::get_mut(code).unwrap().code = Arc::new(bytecode);",
        "code.lock().unwrap().code = Arc::new(bytecode);",
    )

    with open(path, "w") as f:
        f.write(content)
    print("code_graph.rs: fixed")


def fix_partial_execution():
    path = "G:/dev/unfuck/src/partial_execution.rs"
    with open(path, "r") as f:
        content = f.read()

    # extract_truthy_value macro: Obj::Long(result) => *result != 0
    content = content.replace(
        "Some(Obj::Long(result)) => *result != 0.to_bigint().unwrap(),",
        "Some(Obj::Long(result)) => *result.lock().unwrap() != 0.to_bigint().unwrap(),",
    )

    # Obj::Tuple(result) => !result.is_empty()
    content = content.replace(
        "Some(Obj::Tuple(result)) => !result.is_empty(),",
        "Some(Obj::Tuple(result)) => !result.lock().unwrap().is_empty(),",
    )

    # Obj::String(result) => !result.is_empty()
    content = content.replace(
        "Some(Obj::String(result)) => !result.is_empty(),",
        "Some(Obj::String(result)) => !result.lock().unwrap().is_empty(),",
    )

    # Obj::Code(function_code) - accessing fields
    content = content.replace(
        """                            if let Obj::Code(function_code) = &code.consts[const_idx] {
                                let key = format!(
                                    "{}_{}_{}",
                                    function_code.filename,
                                    function_code.name,
                                    function_code.code.len(),
                                );""",
        """                            if let Obj::Code(function_code) = &code.consts[const_idx] {
                                let function_code_guard = function_code.lock().unwrap();
                                let key = format!(
                                    "{}_{}_{}",
                                    function_code_guard.filename,
                                    function_code_guard.name,
                                    function_code_guard.code.len(),
                                );""",
    )

    with open(path, "w") as f:
        f.write(content)
    print("partial_execution.rs: fixed")


if __name__ == "__main__":
    fix_arithmetic()
    fix_compare()
    fix_collections()
    fix_mod()
    fix_lib()
    fix_code_graph()
    fix_partial_execution()
    print("\nAll files fixed!")
