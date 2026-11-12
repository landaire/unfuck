//! Checks the CPython 2.7 hash and table emulation against real interpreter
//! output. `win64_constants_orders.json` comes from the Win64 game client.
//! The `cpython27_*` fixtures come from `generate_cpython_fixtures.py` run
//! under CPython 2.7.12 for Windows x64 (`win64`) and CPython 2.7.18 for
//! Linux x64 and i686.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;

use num_bigint::BigInt;
use serde_json::Value;

use unfuck::interp::hash::LongWidth;
use unfuck::interp::hash::PyHash;
use unfuck::interp::hash::hash_bytes;
use unfuck::interp::hash::hash_float;
use unfuck::interp::hash::hash_int;
use unfuck::interp::hash::hash_long;
use unfuck::interp::hash::hash_pointer;
use unfuck::interp::hash::hash_tuple;
use unfuck::interp::hash::hash_unicode;
use unfuck::interp::table::Hashed;
use unfuck::interp::table::PyDictTable;
use unfuck::interp::table::PySetTable;

type Dict = PyDictTable<PyValue, i64>;
type Set = PySetTable<PyValue>;

/// The subset of Python 2 values the fixtures use. Derived equality is
/// type-sensitive and compares which object a table stored; `py_eq` is
/// Python's `==`.
#[derive(Debug, Clone, PartialEq)]
enum PyValue {
    Int(i64),
    Long(BigInt),
    Float(f64),
    Bytes(Vec<u8>),
    Unicode(Vec<u16>),
    Tuple(Vec<PyValue>),
}

fn fixture(name: &str) -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        "interp",
        name,
    ]
    .iter()
    .collect();
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn decode(value: &Value) -> PyValue {
    let object = value.as_object().expect("encoded value is an object");
    let (kind, payload) = object.iter().next().expect("encoded value has one field");

    match kind.as_str() {
        "i" => PyValue::Int(payload.as_i64().expect("int payload")),
        "l" => PyValue::Long(
            payload
                .as_str()
                .expect("long payload")
                .parse()
                .expect("decimal long"),
        ),
        "f" => PyValue::Float(f64::from_bits(payload.as_u64().expect("float bits"))),
        "b" => PyValue::Bytes(
            numbers(payload)
                .map(|n| u8::try_from(n).expect("byte"))
                .collect(),
        ),
        "u" => PyValue::Unicode(
            numbers(payload)
                .map(|n| u16::try_from(n).expect("BMP code unit"))
                .collect(),
        ),
        "t" => PyValue::Tuple(
            payload
                .as_array()
                .expect("tuple payload")
                .iter()
                .map(decode)
                .collect(),
        ),
        other => panic!("unknown value kind {other}"),
    }
}

fn numbers(value: &Value) -> impl Iterator<Item = u64> + '_ {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|n| n.as_u64().expect("unsigned number"))
}

fn py_hash(width: LongWidth, value: &PyValue) -> PyHash {
    match value {
        PyValue::Int(n) => hash_int(width, *n),
        PyValue::Long(n) => hash_long(width, n),
        PyValue::Float(f) => hash_float(width, *f),
        PyValue::Bytes(bytes) => hash_bytes(width, bytes),
        PyValue::Unicode(units) => hash_unicode(width, units),
        PyValue::Tuple(items) => hash_tuple(
            width,
            items.iter().map(|item| py_hash(width, item)),
            items.len(),
        ),
    }
}

fn int_equals_float(int: i64, float: f64) -> bool {
    float.fract() == 0.0
        && float >= -(2f64.powi(63))
        && float < 2f64.powi(63)
        && float as i64 == int
}

fn py_eq(left: &PyValue, right: &PyValue) -> bool {
    match (left, right) {
        (PyValue::Int(a), PyValue::Int(b)) => a == b,
        (PyValue::Float(a), PyValue::Float(b)) => a == b,
        (PyValue::Int(a), PyValue::Float(b)) | (PyValue::Float(b), PyValue::Int(a)) => {
            int_equals_float(*a, *b)
        }
        (PyValue::Long(a), PyValue::Long(b)) => a == b,
        (PyValue::Long(a), PyValue::Int(b)) | (PyValue::Int(b), PyValue::Long(a)) => {
            *a == BigInt::from(*b)
        }
        (PyValue::Bytes(a), PyValue::Bytes(b)) => a == b,
        (PyValue::Unicode(a), PyValue::Unicode(b)) => a == b,
        (PyValue::Tuple(a), PyValue::Tuple(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        _ => false,
    }
}

fn eq2(stored: &PyValue, probe: &PyValue) -> Result<bool, Infallible> {
    Ok(py_eq(stored, probe))
}

fn eq_with(probe: &PyValue) -> impl FnMut(&PyValue) -> Result<bool, Infallible> + '_ {
    move |stored| Ok(py_eq(stored, probe))
}

fn check_hashes(name: &str, width: LongWidth, expected_bits: u64) {
    let data = fixture(name);
    assert_eq!(data["long_bits"].as_u64(), Some(expected_bits));

    let samples = data["samples"].as_array().expect("samples");
    assert!(samples.len() > 300);
    for sample in samples {
        let value = decode(&sample["value"]);
        let expected = sample["hash"].as_i64().expect("hash");

        assert_eq!(
            py_hash(width, &value).value(),
            expected,
            "hash of {value:?}"
        );
    }
}

#[test]
fn hashes_match_cpython_x64() {
    check_hashes("cpython27_x64_hashes.json", LongWidth::Bits64, 64);
}

/// i686 CPython has a 32-bit `long` like Win64 (and 15-bit long digits), so
/// it is an oracle for 32-bit hash values; the Win64 2.7.12 build prints
/// the same samples. Its 32-bit `size_t` changes probing, so it is not used
/// for table order.
#[test]
fn hashes_match_cpython_i686() {
    check_hashes("cpython27_i686_hashes.json", LongWidth::Bits32, 32);
}

#[test]
fn pointer_hash_rotates_before_truncating() {
    assert_eq!(
        hash_pointer(LongWidth::Bits64, 0x0000_7FFF_1234_5678).value(),
        0x8000_07FF_F123_4567u64 as i64
    );
    assert_eq!(
        hash_pointer(LongWidth::Bits32, 0x0000_7FFF_1234_5678).value(),
        0xF123_4567u32 as i32 as i64
    );
    assert_eq!(hash_pointer(LongWidth::Bits32, 0xF).value(), 0);
}

/// Each `*_INDICES` dict was built by `dict((name, i) for i, name in
/// enumerate(LIST))` in the Win64 client, so its JSON key order is CPython's
/// iteration order.
#[test]
fn dict_order_matches_win64_client() {
    let data = fixture("win64_constants_orders.json");
    let lists = data.as_object().expect("object");
    assert_eq!(lists.len(), 5);

    for (name, case) in lists {
        let strings = |field: &str| -> Vec<String> {
            case[field]
                .as_array()
                .expect("list")
                .iter()
                .map(|s| s.as_str().expect("string").to_string())
                .collect()
        };
        let list = strings("list");
        let order = strings("order");

        let mut dict = PyDictTable::new();
        for (index, key) in list.iter().enumerate() {
            let hash = hash_bytes(LongWidth::Bits32, key.as_bytes());
            let replaced = dict
                .set_item(hash, key.clone(), index, |stored: &String| {
                    Ok::<_, Infallible>(stored == key)
                })
                .unwrap();
            assert!(replaced.is_none());
        }

        assert_eq!(
            dict.keys().collect::<Vec<_>>(),
            order.iter().collect::<Vec<_>>(),
            "{name}"
        );
        assert!(dict.iter().all(|(key, index)| list[*index] == *key));
    }
}

#[test]
fn equality_errors_propagate() {
    let mut dict = PyDictTable::new();
    let mut set = PySetTable::new();
    let key = |n: i64| (hash_int(LongWidth::Bits64, n), n);

    // -1 and -2 share hash -2, so the second insert must compare keys.
    let (hash, value) = key(-1);
    dict.set_item(hash, value, (), |_: &i64| Err("unexpected compare"))
        .unwrap();
    set.add(hash, value, |_: &i64| Err("unexpected compare"))
        .unwrap();

    let (hash, value) = key(-2);
    assert_eq!(
        dict.set_item(hash, value, (), |_: &i64| Err("boom")),
        Err("boom")
    );
    assert_eq!(set.add(hash, value, |_: &i64| Err("boom")), Err("boom"));
    assert_eq!(dict.len(), 1);
    assert_eq!(set.len(), 1);
}

fn int_dict(keys: &[i64]) -> PyDictTable<i64, ()> {
    let mut dict = PyDictTable::new();
    for &key in keys {
        dict.set_item(hash_int(LongWidth::Bits64, key), key, (), |stored: &i64| {
            Ok::<_, Infallible>(*stored == key)
        })
        .unwrap();
    }

    dict
}

/// 11 takes slot 3 and 3 probes 3, 3, 0. Deleting 3 leaves hash 3 in the
/// slot 0 dummy, which `popitem` reads as its search finger. CPython 2.7
/// prints `[3, 1, 11]` and then pops 11.
#[test]
fn popitem_reads_finger_from_slot_zero_dummy() {
    let mut dict = int_dict(&[11, 3, 1]);
    assert_eq!(dict.keys().copied().collect::<Vec<_>>(), [3, 1, 11]);

    dict.del_item(hash_int(LongWidth::Bits64, 3), |stored: &i64| {
        Ok::<_, Infallible>(*stored == 3)
    })
    .unwrap();
    assert_eq!(dict.popitem(), Some((11, ())));
    assert_eq!(dict.keys().copied().collect::<Vec<_>>(), [1]);
}

/// `dictresize` to the minimum size returns early for a small table without
/// dummies. Rebuilding would swap 11 (slot 0, hash 3) and 3 (slot 3).
#[test]
fn small_resize_without_dummies_keeps_order() {
    let mut dict = int_dict(&[3, 11]);
    assert_eq!(dict.keys().copied().collect::<Vec<_>>(), [11, 3]);

    dict.presize(0);
    assert_eq!(dict.keys().copied().collect::<Vec<_>>(), [11, 3]);
}

/// On a size tie `set_intersection` iterates the argument, so the result
/// holds its keys: `set([1]).intersection(set([1.0]))` is `set([1.0])`.
#[test]
fn intersection_tie_keeps_argument_keys() {
    let single = |value: PyValue| {
        Set::from_iterable(
            [Ok(Hashed {
                hash: py_hash(LongWidth::Bits64, &value),
                key: value,
            })],
            eq2,
        )
        .unwrap()
    };
    let int_set = single(PyValue::Int(1));
    let float_set = single(PyValue::Float(1.0));

    let result = int_set.intersection_set(&float_set, eq2).unwrap();
    assert_eq!(result.iter().collect::<Vec<_>>(), [&PyValue::Float(1.0)]);

    let result = float_set.intersection_set(&int_set, eq2).unwrap();
    assert_eq!(result.iter().collect::<Vec<_>>(), [&PyValue::Int(1)]);
}

struct Replay {
    width: LongWidth,
    pool: Vec<PyValue>,
    dicts: HashMap<String, Dict>,
    sets: HashMap<String, Set>,
}

enum Operand {
    Set(Set),
    Dict(Dict),
    List(Vec<Hashed<PyValue>>),
}

impl Replay {
    fn key(&self, index: &Value) -> PyValue {
        let index = usize::try_from(index.as_u64().expect("key index")).expect("index fits");
        self.pool[index].clone()
    }

    fn hashed(&self, index: &Value) -> Hashed<PyValue> {
        let key = self.key(index);
        Hashed {
            hash: py_hash(self.width, &key),
            key,
        }
    }

    fn dict(&mut self, name: &Value) -> &mut Dict {
        self.dicts
            .get_mut(name.as_str().expect("dict name"))
            .expect("known dict")
    }

    fn set(&mut self, name: &Value) -> &mut Set {
        self.sets
            .get_mut(name.as_str().expect("set name"))
            .expect("known set")
    }

    fn operand(&self, kind: &Value, reference: &Value) -> Operand {
        match kind.as_str().expect("operand kind") {
            "set" => Operand::Set(self.sets[reference.as_str().expect("set name")].clone()),
            "dict" => Operand::Dict(self.dicts[reference.as_str().expect("dict name")].clone()),
            "list" => Operand::List(
                reference
                    .as_array()
                    .expect("list")
                    .iter()
                    .map(|index| self.hashed(index))
                    .collect(),
            ),
            other => panic!("unknown operand kind {other}"),
        }
    }

    fn apply(&mut self, op: &[Value]) {
        let code = op[0].as_str().expect("op code");
        match code {
            "dset" => {
                let item = self.hashed(&op[2]);
                let value = op[3].as_i64().expect("value");
                let probe = item.key.clone();
                self.dict(&op[1])
                    .set_item(item.hash, item.key, value, eq_with(&probe))
                    .unwrap();
            }
            "ddel" => {
                let item = self.hashed(&op[2]);
                let removed = self
                    .dict(&op[1])
                    .del_item(item.hash, eq_with(&item.key))
                    .unwrap();
                assert!(removed.is_some());
            }
            "dpop" => {
                let item = self.hashed(&op[2]);
                let found = op[3].as_bool().expect("found");
                let dict = self.dict(&op[1]);
                let removed = if dict.is_empty() {
                    None
                } else {
                    dict.pop(item.hash, eq_with(&item.key)).unwrap()
                };
                assert_eq!(removed.is_some(), found);
            }
            "dpopitem" => {
                let expected = self.key(&op[2]);
                let (key, _) = self.dict(&op[1]).popitem().expect("nonempty dict");
                assert_eq!(key, expected);
            }
            "dclear" => self.dict(&op[1]).clear(),
            "dupdate" => {
                let other = self.dicts[op[2].as_str().expect("dict name")].clone();
                self.dict(&op[1]).merge_from_dict(&other, eq2).unwrap();
            }
            "dcopy" => {
                let copy = self.dicts[op[2].as_str().expect("dict name")]
                    .copy(eq2)
                    .unwrap();
                *self.dict(&op[1]) = copy;
            }
            "dliteral" => {
                let entries = op[2].as_array().expect("entries");
                let mut dict = Dict::new_presized(entries.len());
                for entry in entries {
                    let item = self.hashed(&entry[0]);
                    let probe = item.key.clone();
                    dict.set_item(
                        item.hash,
                        item.key,
                        entry[1].as_i64().expect("value"),
                        eq_with(&probe),
                    )
                    .unwrap();
                }
                *self.dict(&op[1]) = dict;
            }
            "dcheck" => {
                let keys: Vec<PyValue> = op[2]
                    .as_array()
                    .expect("keys")
                    .iter()
                    .map(|index| self.key(index))
                    .collect();
                let values: Vec<i64> = op[3]
                    .as_array()
                    .expect("values")
                    .iter()
                    .map(|v| v.as_i64().expect("value"))
                    .collect();
                let dict = self.dict(&op[1]);
                assert_eq!(dict.keys().cloned().collect::<Vec<_>>(), keys);
                assert_eq!(dict.values().copied().collect::<Vec<_>>(), values);
                assert_eq!(dict.len(), keys.len());
            }
            "sadd" => {
                let item = self.hashed(&op[2]);
                let probe = item.key.clone();
                self.set(&op[1])
                    .add(item.hash, item.key, eq_with(&probe))
                    .unwrap();
            }
            "sdiscard" => {
                let item = self.hashed(&op[2]);
                self.set(&op[1])
                    .discard(item.hash, eq_with(&item.key))
                    .unwrap();
            }
            "spop" => {
                let expected = self.key(&op[2]);
                let key = self.set(&op[1]).pop().expect("nonempty set");
                assert_eq!(key, expected);
            }
            "sclear" => self.set(&op[1]).clear(),
            "snew" => {
                let set = match self.operand(&op[2], &op[3]) {
                    Operand::Set(other) => Set::from_set(&other, eq2),
                    Operand::Dict(other) => Set::from_dict(&other, eq2),
                    Operand::List(items) => Set::from_iterable(items.into_iter().map(Ok), eq2),
                };
                *self.set(&op[1]) = set.unwrap();
            }
            "salg" => {
                let method = op[2].as_str().expect("method");
                let operand = self.operand(&op[3], &op[4]);
                let set = self.set(&op[1]);
                set_algebra(set, method, operand);
            }
            "sbool" => {
                let method = op[2].as_str().expect("method");
                let expected = op[5].as_bool().expect("result");
                let operand = self.operand(&op[3], &op[4]);
                let set = self.set(&op[1]);
                assert_eq!(set_predicate(set, method, operand), expected, "{method}");
            }
            "scheck" => {
                let keys: Vec<PyValue> = op[2]
                    .as_array()
                    .expect("keys")
                    .iter()
                    .map(|index| self.key(index))
                    .collect();
                let set = self.set(&op[1]);
                assert_eq!(set.iter().cloned().collect::<Vec<_>>(), keys);
                assert_eq!(set.len(), keys.len());
            }
            other => panic!("unknown op {other}"),
        }
    }
}

fn dict_keys(dict: &Dict) -> impl Iterator<Item = Result<Hashed<PyValue>, Infallible>> + '_ {
    dict.entries().map(|entry| {
        Ok(Hashed {
            hash: entry.hash,
            key: entry.key.clone(),
        })
    })
}

fn set_algebra(set: &mut Set, method: &str, operand: Operand) {
    let result = match (method, &operand) {
        ("union", Operand::Set(other)) => set.union_set(other, eq2),
        ("union", Operand::Dict(other)) => set.union_dict(other, eq2),
        ("union", Operand::List(items)) => set.union_iter(items.iter().cloned().map(Ok), eq2),
        ("intersection" | "intersection_update", Operand::Set(other)) => {
            set.intersection_set(other, eq2)
        }
        ("intersection" | "intersection_update", Operand::Dict(other)) => {
            set.intersection_iter(dict_keys(other), eq2)
        }
        ("intersection" | "intersection_update", Operand::List(items)) => {
            set.intersection_iter(items.iter().cloned().map(Ok), eq2)
        }
        ("difference", Operand::Set(other)) => set.difference_set(other, eq2),
        ("difference", Operand::Dict(other)) => set.difference_dict(other, eq2),
        ("difference", Operand::List(items)) => {
            set.difference_iter(items.iter().cloned().map(Ok), eq2)
        }
        ("symmetric_difference", Operand::Set(other)) => set.symmetric_difference_set(other, eq2),
        ("symmetric_difference", Operand::Dict(other)) => set.symmetric_difference_dict(other, eq2),
        ("symmetric_difference", Operand::List(items)) => {
            set.symmetric_difference_iter(items.iter().cloned().map(Ok), eq2)
        }
        _ => {
            set_update(set, method, operand);
            return;
        }
    };

    *set = result.unwrap();
}

fn set_update(set: &mut Set, method: &str, operand: Operand) {
    let result = match (method, &operand) {
        ("update", Operand::Set(other)) => set.update_from_set(other, eq2),
        ("update", Operand::Dict(other)) => set.update_from_dict(other, eq2),
        ("update", Operand::List(items)) => {
            set.update_from_iter(items.iter().cloned().map(Ok), eq2)
        }
        ("difference_update", Operand::Set(other)) => set.difference_update_set(other, eq2),
        ("difference_update", Operand::Dict(other)) => {
            set.difference_update_iter(dict_keys(other), eq2)
        }
        ("difference_update", Operand::List(items)) => {
            set.difference_update_iter(items.iter().cloned().map(Ok), eq2)
        }
        ("symmetric_difference_update", Operand::Set(other)) => {
            set.symmetric_difference_update_set(other, eq2)
        }
        ("symmetric_difference_update", Operand::Dict(other)) => {
            set.symmetric_difference_update_dict(other, eq2)
        }
        ("symmetric_difference_update", Operand::List(items)) => {
            set.symmetric_difference_update_iter(items.iter().cloned().map(Ok), eq2)
        }
        _ => panic!("unknown set method {method}"),
    };

    result.unwrap();
}

fn set_predicate(set: &Set, method: &str, operand: Operand) -> bool {
    // issubset and issuperset convert a non-set operand with make_new_set.
    let as_set = |operand: &Operand| match operand {
        Operand::Set(other) => other.clone(),
        Operand::Dict(other) => Set::from_dict(other, eq2).unwrap(),
        Operand::List(items) => Set::from_iterable(items.iter().cloned().map(Ok), eq2).unwrap(),
    };

    let result = match (method, &operand) {
        ("issubset", _) => set.is_subset(&as_set(&operand), eq2),
        ("issuperset", _) => set.is_superset(&as_set(&operand), eq2),
        ("isdisjoint", Operand::Set(other)) => set.is_disjoint_set(other, eq2),
        ("isdisjoint", Operand::Dict(other)) => set.is_disjoint_iter(dict_keys(other), eq2),
        ("isdisjoint", Operand::List(items)) => {
            set.is_disjoint_iter(items.iter().cloned().map(Ok), eq2)
        }
        _ => panic!("unknown set predicate {method}"),
    };

    result.unwrap()
}

/// The C `long` width a table fixture was recorded with.
fn fixture_width(data: &Value) -> LongWidth {
    match data["long_bits"].as_u64() {
        Some(32) => LongWidth::Bits32,
        Some(64) => LongWidth::Bits64,
        other => panic!("unexpected long_bits {other:?}"),
    }
}

fn key_pool(data: &Value) -> Vec<PyValue> {
    data["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(decode)
        .collect()
}

fn check_table_operations(name: &str, width: LongWidth) {
    let data = fixture(name);
    assert_eq!(fixture_width(&data), width);

    let pool = key_pool(&data);
    let scenarios = data["scenarios"].as_array().expect("scenarios");
    assert_eq!(scenarios.len(), 20);

    for (scenario_index, scenario) in scenarios.iter().enumerate() {
        let mut replay = Replay {
            width,
            pool: pool.clone(),
            dicts: ["a", "b"]
                .into_iter()
                .map(|name| (name.to_string(), Dict::new()))
                .collect(),
            sets: ["s", "t"]
                .into_iter()
                .map(|name| (name.to_string(), Set::new()))
                .collect(),
        };

        for (op_index, op) in scenario.as_array().expect("ops").iter().enumerate() {
            let op = op.as_array().expect("op");
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replay.apply(op)));
            if outcome.is_err() {
                panic!("{name} scenario {scenario_index} op {op_index}: {op:?}");
            }
        }
    }
}

#[test]
fn table_operations_match_cpython_x64() {
    check_table_operations("cpython27_x64_tables.json", LongWidth::Bits64);
}

#[test]
fn table_operations_match_cpython_win64() {
    check_table_operations("cpython27_win64_tables.json", LongWidth::Bits32);
}

fn bulk_keys(count: i64) -> Vec<i64> {
    (0..count)
        .map(|i| (i * 2_654_435_761).rem_euclid(1 << 40) - (1 << 39))
        .collect()
}

/// The order digest `generate_cpython_fixtures.py` records.
fn order_digest(keys: impl Iterator<Item = i128>) -> i64 {
    const MODULUS: i128 = (1 << 61) - 1;

    let mut digest: i128 = 0;
    for (position, key) in keys.enumerate() {
        digest = (digest * 1_000_003 + key + position as i128).rem_euclid(MODULUS);
    }

    i64::try_from(digest).expect("digest fits")
}

fn int_key(key: &PyValue) -> i128 {
    let PyValue::Int(key) = key else {
        panic!("bulk keys are ints");
    };

    i128::from(*key)
}

/// Exercises the `used > 50000` doubling rule.
fn check_large_tables(name: &str, width: LongWidth) {
    let data = fixture(name);
    assert_eq!(fixture_width(&data), width);

    let expected = &data["bulk"];
    let keys = bulk_keys(expected["count"].as_i64().expect("count"));

    let mut dict = Dict::new();
    let mut set = Set::new();
    let hashed = |n: i64| Hashed {
        hash: hash_int(width, n),
        key: PyValue::Int(n),
    };

    for &n in &keys {
        let item = hashed(n);
        dict.set_item(item.hash, item.key.clone(), 0, eq_with(&item.key))
            .unwrap();
        set.add(item.hash, item.key.clone(), eq_with(&item.key))
            .unwrap();
    }
    for &n in keys.iter().step_by(7) {
        let item = hashed(n);
        assert!(
            dict.del_item(item.hash, eq_with(&item.key))
                .unwrap()
                .is_some()
        );
        assert!(
            set.discard(item.hash, eq_with(&item.key))
                .unwrap()
                .is_some()
        );
    }
    for &n in &keys[..3000] {
        let item = hashed(-n - 1);
        dict.set_item(item.hash, item.key.clone(), 0, eq_with(&item.key))
            .unwrap();
        set.add(item.hash, item.key.clone(), eq_with(&item.key))
            .unwrap();
    }

    assert_eq!(
        dict.len() as u64,
        expected["dict_len"].as_u64().expect("dict_len")
    );
    assert_eq!(
        set.len() as u64,
        expected["set_len"].as_u64().expect("set_len")
    );
    assert_eq!(
        order_digest(dict.keys().map(int_key)),
        expected["dict_digest"].as_i64().expect("dict_digest")
    );
    assert_eq!(
        order_digest(set.iter().map(int_key)),
        expected["set_digest"].as_i64().expect("set_digest")
    );
}

#[test]
fn large_tables_match_cpython_x64() {
    check_large_tables("cpython27_x64_tables.json", LongWidth::Bits64);
}

#[test]
fn large_tables_match_cpython_win64() {
    check_large_tables("cpython27_win64_tables.json", LongWidth::Bits32);
}

/// The table of one fuzz scenario. Keys are indices into the key pool.
enum FuzzTable {
    Dict(PyDictTable<usize, usize>),
    Set(PySetTable<usize>),
}

impl FuzzTable {
    fn keys(&self) -> Vec<usize> {
        match self {
            FuzzTable::Dict(dict) => dict.keys().copied().collect(),
            FuzzTable::Set(set) => set.iter().copied().collect(),
        }
    }
}

/// Replays a `fuzz` scenario: random inserts, deletes, pops, and clears on
/// one dict or set, with the iteration order digest checked after every
/// operation and the full order checked at the end.
fn replay_fuzz(pool: &[PyValue], hashes: &[PyHash], scenario: &Value) {
    let mut table = match scenario["kind"].as_str() {
        Some("dict") => FuzzTable::Dict(PyDictTable::new()),
        Some("set") => FuzzTable::Set(PySetTable::new()),
        other => panic!("unknown scenario kind {other:?}"),
    };
    let index =
        |value: &Value| usize::try_from(value.as_u64().expect("key index")).expect("index fits");
    let eq = |probe: usize| {
        move |stored: &usize| Ok::<_, Infallible>(py_eq(&pool[*stored], &pool[probe]))
    };

    for (step, op) in scenario["ops"].as_array().expect("ops").iter().enumerate() {
        let op = op.as_array().expect("op");
        match (op[0].as_str().expect("op code"), &mut table) {
            ("i", FuzzTable::Dict(dict)) => {
                let key = index(&op[1]);
                dict.set_item(hashes[key], key, step, eq(key)).unwrap();
            }
            ("i", FuzzTable::Set(set)) => {
                let key = index(&op[1]);
                set.add(hashes[key], key, eq(key)).unwrap();
            }
            ("d", FuzzTable::Dict(dict)) => {
                let key = index(&op[1]);
                let removed = dict.del_item(hashes[key], eq(key)).unwrap();
                assert_eq!(
                    removed.is_some(),
                    op[2].as_bool().expect("found"),
                    "step {step}"
                );
            }
            ("d", FuzzTable::Set(set)) => {
                let key = index(&op[1]);
                let removed = set.discard(hashes[key], eq(key)).unwrap();
                assert_eq!(
                    removed.is_some(),
                    op[2].as_bool().expect("found"),
                    "step {step}"
                );
            }
            ("p", FuzzTable::Dict(dict)) => {
                let popped = dict.popitem().map(|(key, _)| key);
                assert_eq!(popped, Some(index(&op[1])), "step {step}");
            }
            ("p", FuzzTable::Set(set)) => {
                assert_eq!(set.pop(), Some(index(&op[1])), "step {step}");
            }
            ("c", FuzzTable::Dict(dict)) => dict.clear(),
            ("c", FuzzTable::Set(set)) => set.clear(),
            ("k", _) => {
                let expected: Vec<usize> =
                    op[1].as_array().expect("keys").iter().map(index).collect();
                assert_eq!(table.keys(), expected, "final order");
                continue;
            }
            (other, _) => panic!("unknown fuzz op {other}"),
        }

        let digest = op.last().and_then(Value::as_i64).expect("order digest");
        let keys = table.keys();
        assert_eq!(
            order_digest(keys.iter().map(|key| *key as i128)),
            digest,
            "step {step} order {keys:?}"
        );
    }
}

fn check_fuzz(name: &str, width: LongWidth) {
    let data = fixture(name);
    assert_eq!(fixture_width(&data), width);

    let pool = key_pool(&data);
    let hashes: Vec<PyHash> = pool.iter().map(|key| py_hash(width, key)).collect();
    let scenarios = data["scenarios"].as_array().expect("scenarios");
    assert_eq!(scenarios.len(), 16);

    for (scenario_index, scenario) in scenarios.iter().enumerate() {
        let outcome = std::panic::catch_unwind(|| replay_fuzz(&pool, &hashes, scenario));
        if outcome.is_err() {
            panic!("{name} scenario {scenario_index}");
        }
    }
}

#[test]
fn fuzz_orders_match_cpython_x64() {
    check_fuzz("cpython27_x64_fuzz.json", LongWidth::Bits64);
}

#[test]
fn fuzz_orders_match_cpython_win64() {
    check_fuzz("cpython27_win64_fuzz.json", LongWidth::Bits32);
}
