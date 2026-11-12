//! Compares the folds against CPython 2.7.18 (Linux x64): `matches_cpython`
//! runs `tests/fixtures/compiler/fold_cases.py` with the interpreter named
//! by `PYTHON27` and checks every case it records.

use std::rc::Rc;

use num_bigint::BigInt;
use serde_json::Value;
use serde_json::json;

use super::*;
use crate::interp::compiler::context::TestContext;
use crate::interp::compiler::context::WarningCategory;
use crate::interp::compiler::fold::text::FloatCode;
use crate::interp::compiler::fold::text::FloatFormat;
use crate::interp::hash::LongWidth;

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

fn hex_float(text: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(text, 16).unwrap())
}

fn decode(value: &Value) -> Object {
    let parts = value.as_array().unwrap();
    let field = |index: usize| parts[index].as_str().unwrap();

    match field(0) {
        "none" => Object::None,
        "ellipsis" => Object::Ellipsis,
        "int" => Object::Int(field(1).parse().unwrap()),
        "long" => Object::Long(Rc::new(field(1).parse::<BigInt>().unwrap())),
        "float" => Object::Float(hex_float(field(1))),
        "complex" => Object::Complex(Complex { real: hex_float(field(1)), imag: hex_float(field(2)) }),
        "str" => Object::str(hex_bytes(field(1)), parts[2].as_bool().unwrap()),
        "unicode" => Object::Unicode(parts[1].as_array().unwrap().iter().map(|unit| unit.as_u64().unwrap() as u16).collect()),
        "tuple" => Object::Tuple(parts[1].as_array().unwrap().iter().map(decode).collect()),
        other => panic!("unknown object kind {other}"),
    }
}

fn encode(object: &Object) -> Value {
    let bits = |value: f64| format!("{:016x}", value.to_bits());

    match object {
        Object::None => json!(["none"]),
        Object::Ellipsis => json!(["ellipsis"]),
        Object::Int(value) => json!(["int", value.to_string()]),
        Object::Long(value) => json!(["long", value.to_string()]),
        Object::Float(value) => json!(["float", bits(*value)]),
        Object::Complex(value) => json!(["complex", bits(value.real), bits(value.imag)]),
        Object::Str(object) => {
            let hex: String = object.value.iter().map(|byte| format!("{byte:02x}")).collect();
            json!(["str", hex, object.interned.get()])
        }
        Object::Unicode(units) => json!(["unicode", units.to_vec()]),
        Object::Tuple(items) => json!(["tuple", items.iter().map(encode).collect::<Vec<_>>()]),
        Object::Code(_) => json!(["code"]),
    }
}

fn binary_op(name: &str) -> BinaryFold {
    match name {
        "power" => BinaryFold::Power,
        "multiply" => BinaryFold::Multiply,
        "true_divide" => BinaryFold::TrueDivide,
        "floor_divide" => BinaryFold::FloorDivide,
        "modulo" => BinaryFold::Modulo,
        "add" => BinaryFold::Add,
        "subtract" => BinaryFold::Subtract,
        "subscript" => BinaryFold::Subscript,
        "lshift" => BinaryFold::LShift,
        "rshift" => BinaryFold::RShift,
        "and" => BinaryFold::And,
        "xor" => BinaryFold::Xor,
        "or" => BinaryFold::Or,
        other => panic!("unknown binary op {other}"),
    }
}

fn unary_op(name: &str) -> UnaryFold {
    match name {
        "negative" => UnaryFold::Negative,
        "convert" => UnaryFold::Convert,
        "invert" => UnaryFold::Invert,
        other => panic!("unknown unary op {other}"),
    }
}

/// The operands a `str` result is the same object as.
fn identical_operands(result: &Object, left: &Object, right: &Object) -> Vec<&'static str> {
    let Object::Str(result) = result else {
        return Vec::new();
    };

    [("l", left), ("r", right)].into_iter().filter(|(_, operand)| matches!(operand, Object::Str(operand) if Rc::ptr_eq(result, operand))).map(|(side, _)| side).collect()
}

/// Whether a case holds a surrogate pair, which the wide reference build
/// keeps as two characters and a narrow build reads as one.
fn has_surrogate_pair(value: &Value) -> bool {
    match value {
        Value::Array(parts) if parts.first().and_then(Value::as_str) == Some("unicode") => {
            let units: Vec<u64> = parts[1].as_array().unwrap().iter().map(|unit| unit.as_u64().unwrap()).collect();
            units.windows(2).any(|pair| (0xd800..0xdc00).contains(&pair[0]) && (0xdc00..0xe000).contains(&pair[1]))
        }
        Value::Array(parts) => parts.iter().any(has_surrogate_pair),
        Value::Object(fields) => fields.values().any(has_surrogate_pair),
        _ => false,
    }
}

/// The peephole discards sequence results longer than 20.
fn expected_fold(result: &Value) -> Value {
    if result.is_null() {
        return Value::Null;
    }

    if size(&decode(result)).is_some_and(|size| size > MAX_FOLDED_SIZE) {
        return Value::Null;
    }

    result.clone()
}

fn check_binary(case: &Value, failures: &mut Vec<String>) {
    if has_surrogate_pair(case) {
        return;
    }

    let op = binary_op(case["op"].as_str().unwrap());
    let left = decode(&case["l"]);
    let right = decode(&case["r"]);
    let unicode_subscript = op == BinaryFold::Subscript && matches!(left, Object::Unicode(_));
    let expected = if unicode_subscript { Value::Null } else { expected_fold(&case["res"]) };

    let mut context = TestContext::new();
    let result = binary(op, &left, &right, &mut context);
    let actual = result.as_ref().map_or(Value::Null, encode);
    if actual != expected {
        failures.push(format!("{case}\n    got {actual}"));
        return;
    }

    let Some(result) = result else {
        return;
    };

    // An interned string is the canonical object for its value, so only
    // the identity of uninterned results is observable.
    let interned = matches!(&result, Object::Str(object) if object.interned.get());
    let same = identical_operands(&result, &left, &right);
    let expected_same: Vec<&str> = case["same"].as_array().unwrap().iter().map(|side| side.as_str().unwrap()).collect();
    let identity_matches = same.iter().all(|side| expected_same.contains(side)) && same.is_empty() == expected_same.is_empty();
    if matches!(result, Object::Str(_)) && !interned && !identity_matches {
        failures.push(format!("{case}\n    identical to {same:?}"));
    }

    let warnings = context.warnings.iter().filter(|warning| warning.category == WarningCategory::DeprecationWarning).count();
    if Some(warnings as u64) != case["w"].as_u64() {
        failures.push(format!("{case}\n    {warnings} warnings"));
    }
}

fn check_unary(case: &Value, failures: &mut Vec<String>) {
    if has_surrogate_pair(case) {
        return;
    }

    let op = unary_op(case["op"].as_str().unwrap());
    let operand = decode(&case["x"]);
    let expected = case["res"].clone();

    // The peephole folds a negation only for true operands.
    if op == UnaryFold::Negative && !is_true(&operand) {
        return;
    }

    let mut context = TestContext::new();
    let actual = unary(op, &operand, &mut context).as_ref().map_or(Value::Null, encode);
    if actual != expected {
        failures.push(format!("{case}\n    got {actual}"));
    }
}

fn check_float(case: &Value, failures: &mut Vec<String>) {
    let value = hex_float(case["v"].as_str().unwrap());
    let code = case["code"].as_str().unwrap();
    let precision = case["prec"].as_u64().unwrap() as usize;
    let alternate = case["alt"].as_bool().unwrap();

    let format = match code {
        "r" => FloatFormat { point_zero: true, ..FloatFormat::new(FloatCode::Repr, 0) },
        "s" => FloatFormat { point_zero: true, ..FloatFormat::new(FloatCode::General, precision) },
        _ => {
            let lower = code.to_ascii_lowercase();
            let float_code = match lower.as_str() {
                "e" => FloatCode::Exponent,
                "f" => FloatCode::Fixed,
                _ => FloatCode::General,
            };
            FloatFormat { upper: code != lower, alternate, ..FloatFormat::new(float_code, precision) }
        }
    };

    let actual = String::from_utf8(text::format_float(value, format)).unwrap();
    if actual != case["res"].as_str().unwrap() {
        failures.push(format!("{case}\n    got {actual}"));
    }
}

#[test]
#[ignore]
fn matches_cpython() {
    let python = std::env::var_os("PYTHON27").expect("PYTHON27 must name a CPython 2.7.18 interpreter");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/compiler/fold_cases.py");
    let output = std::process::Command::new(&python).arg(script).env_remove("LD_LIBRARY_PATH").output().expect("the interpreter runs");
    assert!(output.status.success(), "fold_cases.py failed: {}", String::from_utf8_lossy(&output.stderr));
    let cases = String::from_utf8(output.stdout).expect("the cases are UTF-8 JSON lines");

    let mut failures = Vec::new();
    let mut count = 0;

    for line in cases.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        count += 1;
        match case["k"].as_str().unwrap() {
            "bin" => check_binary(&case, &mut failures),
            "un" => check_unary(&case, &mut failures),
            "float" => check_float(&case, &mut failures),
            other => panic!("unknown case kind {other}"),
        }
    }

    assert!(count > 1000);
    assert!(failures.is_empty(), "{} of {count} cases differ:\n{}", failures.len(), failures.iter().take(60).cloned().collect::<Vec<_>>().join("\n"));
}

/// Win64 CPython has a 32-bit C `long`: `int` results outside it become
/// `long`, and a `long` operand never turns back into an `int`.
#[test]
fn int_overflow_with_32_bit_long() {
    let int = Object::Int;
    let long = |value: i64| Object::Long(Rc::new(BigInt::from(value)));
    let maximum = i64::from(i32::MAX);
    let minimum = i64::from(i32::MIN);
    let cases = [
        (BinaryFold::Add, int(maximum), int(1), long(maximum + 1)),
        (BinaryFold::Subtract, int(minimum), int(1), long(minimum - 1)),
        (BinaryFold::Multiply, int(65536), int(32768), long(1 << 31)),
        (BinaryFold::Multiply, int(-65536), int(32768), int(minimum)),
        (BinaryFold::FloorDivide, int(minimum), int(-1), long(1 << 31)),
        // The smallest `int` divided by -1 overflows, so even the zero
        // remainder is a `long`.
        (BinaryFold::Modulo, int(minimum), int(-1), long(0)),
        (BinaryFold::Power, int(2), int(31), long(1 << 31)),
        (BinaryFold::Power, int(-2), int(31), int(minimum)),
        (BinaryFold::Power, int(2), int(30), int(1 << 30)),
        (BinaryFold::LShift, int(1), int(31), long(1 << 31)),
        (BinaryFold::LShift, int(-1), int(31), int(minimum)),
        (BinaryFold::LShift, int(1), int(32), long(1 << 32)),
        (BinaryFold::RShift, int(-5), int(40), int(-1)),
        (BinaryFold::TrueDivide, int(maximum), int(2), Object::Float(maximum as f64 / 2.0)),
        (BinaryFold::Add, long(1), int(1), long(2)),
    ];

    for (op, left, right, expected) in cases {
        let mut context = TestContext::new();
        context.long_width = LongWidth::Bits32;
        let actual = binary(op, &left, &right, &mut context);
        assert_eq!(actual.as_ref().map(encode), Some(encode(&expected)), "{op:?} {left:?} {right:?}");
    }

    let mut context = TestContext::new();
    context.long_width = LongWidth::Bits32;
    assert_eq!(unary(UnaryFold::Negative, &int(minimum), &mut context).as_ref().map(encode), Some(encode(&long(1 << 31))));
    assert_eq!(unary(UnaryFold::Invert, &int(maximum), &mut context).as_ref().map(encode), Some(encode(&int(minimum))));

    // `'%x' % -2**31` writes the sign and the magnitude.
    let format = Object::str(b"%x|%c".to_vec(), false);
    let args = Object::Tuple(Rc::from(vec![int(minimum), long(65)]));
    let result = binary(BinaryFold::Modulo, &format, &args, &mut context);
    assert_eq!(result.as_ref().map(encode), Some(encode(&Object::str(b"-80000000|A".to_vec(), false))));
}

/// Results CPython would spend minutes or gigabytes on.
#[test]
fn huge_results_are_not_folded() {
    let mut context = TestContext::new();
    let int = Object::Int;
    let huge = Object::Long(Rc::new(BigInt::from(1) << 100u32));

    assert!(binary(BinaryFold::Power, &int(2), &int(1 << 25), &mut context).is_none());
    assert!(binary(BinaryFold::LShift, &int(1), &int(1 << 25), &mut context).is_none());
    assert!(binary(BinaryFold::LShift, &int(1), &huge, &mut context).is_none());
    assert!(binary(BinaryFold::Power, &int(1), &huge, &mut context).is_some());
    assert!(binary(BinaryFold::Power, &int(-1), &huge, &mut context).is_some());
    assert!(binary(BinaryFold::Multiply, &Object::str(b"ab".to_vec(), false), &int(i64::MAX), &mut context).is_none());
    assert!(binary(BinaryFold::Modulo, &Object::str(b"%999999999999s".to_vec(), false), &int(1), &mut context).is_none());
    assert!(binary(BinaryFold::Modulo, &Object::str(b"%.999999999f".to_vec(), false), &Object::Float(1.0), &mut context).is_none());
}

#[test]
fn code_objects_are_not_converted() {
    let code = Object::Code(Rc::new(crate::interp::compiler::unit::CodeUnit {
        argcount: 0,
        nlocals: 0,
        stacksize: 0,
        flags: 0,
        code: Vec::new(),
        consts: Vec::new(),
        names: Vec::new(),
        varnames: Vec::new(),
        freevars: Vec::new(),
        cellvars: Vec::new(),
        filename: Vec::new(),
        name: Vec::new(),
        name_interned: true,
        firstlineno: 1,
        lnotab: Vec::new(),
    }));
    let mut context = TestContext::new();

    assert!(unary(UnaryFold::Convert, &code, &mut context).is_none());
    assert!(unary(UnaryFold::Convert, &Object::Tuple(Rc::from(vec![code.clone()])), &mut context).is_none());
    assert!(binary(BinaryFold::Modulo, &Object::str(b"%s".to_vec(), false), &Object::Tuple(Rc::from(vec![code])), &mut context).is_none());
}

/// A narrow build keeps non-BMP characters as surrogate pairs: two units
/// for `len`, one `\U` escape for `repr`.
#[test]
fn unicode_is_utf16() {
    let pair: Rc<[u16]> = Rc::from(vec![0xd83d, 0xde00]);
    let mut context = TestContext::new();

    assert_eq!(size(&Object::Unicode(Rc::clone(&pair))), Some(2));
    let repr = unary(UnaryFold::Convert, &Object::Unicode(Rc::clone(&pair)), &mut context);
    assert_eq!(repr.as_ref().map(encode), Some(encode(&Object::str(b"u'\\U0001f600'".to_vec(), false))));

    let format = Object::Unicode(Rc::from(vec![u16::from(b'%'), u16::from(b'c')]));
    assert!(binary(BinaryFold::Modulo, &format, &Object::Int(0x1_0000), &mut context).is_none());
    let repeated = binary(BinaryFold::Multiply, &Object::Unicode(pair), &Object::Int(11), &mut context);
    assert!(repeated.is_none());
}
