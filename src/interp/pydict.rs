use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::PyHash;
use crate::interp::table::PyDictTable;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub type PyDict = PyDictTable<Value, Value>;

impl Vm {
    pub fn new_dict(&self) -> ObjectRef {
        let class = Rc::clone(&self.types().dict);

        self.alloc(&class, Payload::Dict(RefCell::new(PyDict::new())), None)
    }

    /// A dict sized for `minused` entries, as `BUILD_MAP` creates it.
    pub fn new_dict_presized(&self, minused: usize) -> ObjectRef {
        let class = Rc::clone(&self.types().dict);

        self.alloc(&class, Payload::Dict(RefCell::new(PyDict::new_presized(minused))), None)
    }

    pub(crate) fn dict_cell<'a>(&self, dict: &'a ObjectRef) -> PyResult<&'a RefCell<PyDict>> {
        match &dict.payload {
            Payload::Dict(table) => Ok(table),
            _ => Err(self.type_error(&format!("expected a dict, got {}", self.type_name(&Value::Object(Rc::clone(dict)))))),
        }
    }

    /// Key equality as dict lookups apply it: identity, then `==`.
    pub fn keys_equal(&self, stored: &Value, probe: &Value) -> PyResult<bool> {
        if self.is_same(stored, probe) {
            return Ok(true);
        }

        self.equals(stored, probe)
    }

    fn dict_conflict(&self) -> Signal {
        self.raise(ExceptionKind::RuntimeError, "dictionary changed size during lookup")
    }

    /// Value stored under `key`, without `__missing__`.
    pub fn dict_get(&self, dict: &ObjectRef, key: &Value) -> PyResult<Option<Value>> {
        let hash = self.hash(key)?;

        self.dict_get_hashed(dict, key, hash)
    }

    pub fn dict_get_hashed(&self, dict: &ObjectRef, key: &Value, hash: PyHash) -> PyResult<Option<Value>> {
        let cell = self.dict_cell(dict)?;
        let table = cell.try_borrow().map_err(|_| self.dict_conflict())?;
        let found = table.lookup(hash, |stored| self.keys_equal(stored, key))?;

        Ok(found.map(|entry| entry.value.clone()))
    }

    pub fn dict_get_str(&self, dict: &ObjectRef, key: &str) -> PyResult<Option<Value>> {
        self.dict_get(dict, &Value::str(key))
    }

    /// Stores `value` under `key`.
    pub fn dict_set(&self, dict: &ObjectRef, key: Value, value: Value) -> PyResult<()> {
        let hash = self.hash(&key)?;

        self.dict_set_hashed(dict, key, hash, value)
    }

    /// Stores `value` under `key`; the key is interned.
    pub fn dict_set_str(&self, dict: &ObjectRef, key: &str, value: Value) -> PyResult<()> {
        let key = self.intern(&PyBytes::from(key));

        self.dict_set(dict, Value::Str(key), value)
    }

    pub fn dict_set_hashed(&self, dict: &ObjectRef, key: Value, hash: PyHash, value: Value) -> PyResult<()> {
        let cell = self.dict_cell(dict)?;
        let probe = key.clone();
        let mut table = cell.try_borrow_mut().map_err(|_| self.dict_conflict())?;
        table.set_item(hash, key, value, |stored| self.keys_equal(stored, &probe))?;

        Ok(())
    }

    /// Deletes `key`. Returns whether the key was present.
    pub fn dict_delete(&self, dict: &ObjectRef, key: &Value) -> PyResult<bool> {
        let hash = self.hash(key)?;
        let cell = self.dict_cell(dict)?;
        let removed = {
            let mut table = cell.try_borrow_mut().map_err(|_| self.dict_conflict())?;
            table.del_item(hash, |stored| self.keys_equal(stored, key))?
        };

        Ok(removed.is_some())
    }

    pub fn dict_pop(&self, dict: &ObjectRef, key: &Value) -> PyResult<Option<Value>> {
        let hash = self.hash(key)?;
        let cell = self.dict_cell(dict)?;
        let removed = {
            let mut table = cell.try_borrow_mut().map_err(|_| self.dict_conflict())?;
            table.pop(hash, |stored| self.keys_equal(stored, key))?
        };

        Ok(removed.map(|(_, value)| value))
    }

    pub fn dict_len(&self, dict: &ObjectRef) -> PyResult<usize> {
        Ok(self.dict_cell(dict)?.borrow().len())
    }

    pub fn dict_items(&self, dict: &ObjectRef) -> PyResult<Vec<(Value, Value)>> {
        let table = self.dict_cell(dict)?.borrow();

        Ok(table.iter().map(|(key, value)| (key.clone(), value.clone())).collect())
    }

    pub fn dict_keys(&self, dict: &ObjectRef) -> PyResult<Vec<Value>> {
        let table = self.dict_cell(dict)?.borrow();

        Ok(table.keys().cloned().collect())
    }

    pub fn dict_values(&self, dict: &ObjectRef) -> PyResult<Vec<Value>> {
        let table = self.dict_cell(dict)?.borrow();

        Ok(table.values().cloned().collect())
    }

    /// Entry at or after a slot position, for dict iterators.
    pub fn dict_next_entry(&self, dict: &ObjectRef, position: usize) -> PyResult<Option<(usize, Value, Value)>> {
        let table = self.dict_cell(dict)?.borrow();

        Ok(table.next_active(position).map(|entry| (entry.slot, entry.key.clone(), entry.value.clone())))
    }

    /// A shallow copy of `dict`. The copy is an exact dict.
    pub fn dict_copy(&self, dict: &ObjectRef) -> PyResult<ObjectRef> {
        let copy = {
            let table = self.dict_cell(dict)?.borrow();
            table.copy(|stored, probe| self.keys_equal(stored, probe))?
        };
        let class = Rc::clone(&self.types().dict);

        Ok(self.alloc(&class, Payload::Dict(RefCell::new(copy)), None))
    }

    /// Merges `source` into `target`, replacing existing keys when `override_existing` is set. Dicts, including dict
    /// subclasses, merge table to table; other mappings go through `keys()`
    /// and `__getitem__`.
    pub fn dict_merge(&self, target: &ObjectRef, source: &Value, override_existing: bool) -> PyResult<()> {
        if let Value::Unknown(unknown) = source {
            return Err(Signal::Halt(Halt::UnknownIteration { origin: unknown.origin.clone() }));
        }

        if let Value::Object(source_object) = source {
            if let Payload::Dict(source_table) = &source_object.payload {
                if Rc::ptr_eq(source_object, target) {
                    return Ok(());
                }

                let snapshot = source_table.borrow().clone();
                if override_existing {
                    let cell = self.dict_cell(target)?;
                    let mut table = cell.try_borrow_mut().map_err(|_| self.dict_conflict())?;
                    table.merge_from_dict(&snapshot, |stored, probe| self.keys_equal(stored, probe))?;
                    return Ok(());
                }

                for entry in snapshot.entries() {
                    if self.dict_get_hashed(target, entry.key, entry.hash)?.is_none() {
                        self.dict_set_hashed(target, entry.key.clone(), entry.hash, entry.value.clone())?;
                    }
                }
                return Ok(());
            }
        }

        let keys_method = self.getattr_str(source, "keys")?;
        let keys = self.call0(&keys_method)?;
        for key in self.collect(&keys)? {
            if !override_existing && self.dict_get(target, &key)?.is_some() {
                continue;
            }
            let value = self.getitem(source, &key)?;
            self.dict_set(target, key, value)?;
        }

        Ok(())
    }

    /// `dict(pairs)` and `update(pairs)`.
    pub fn dict_merge_pairs(&self, target: &ObjectRef, pairs: &Value) -> PyResult<()> {
        let iterator = self.iter(pairs)?;
        let mut index = 0usize;

        while let Some(pair) = self.next(&iterator)? {
            let items = match self.collect(&pair) {
                Ok(items) => items,
                Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::TypeError) => {
                    return Err(self.type_error(&format!("cannot convert dictionary update sequence element #{index} to a sequence")));
                }
                Err(error) => return Err(error),
            };
            let [key, value] = <[Value; 2]>::try_from(items).map_err(|items| {
                self.raise(ExceptionKind::ValueError, &format!("dictionary update sequence element #{index} has length {}; 2 is required", items.len()))
            })?;
            self.dict_set(target, key, value)?;
            index += 1;
        }

        Ok(())
    }

    /// Stores into a namespace mapping (`STORE_NAME`).
    pub fn mapping_store(&self, mapping: &ObjectRef, key: Value, value: Value) -> PyResult<()> {
        if matches!(mapping.payload, Payload::Dict(_)) && self.user_override(&Value::Object(Rc::clone(mapping)), "__setitem__")?.is_none() {
            return self.dict_set(mapping, key, value);
        }

        self.setitem(&Value::Object(Rc::clone(mapping)), &key, value)
    }

    /// Loads from a namespace mapping (`LOAD_NAME`); `None` when missing.
    pub fn mapping_load(&self, mapping: &ObjectRef, key: &Value) -> PyResult<Option<Value>> {
        if matches!(mapping.payload, Payload::Dict(_)) && self.user_override(&Value::Object(Rc::clone(mapping)), "__getitem__")?.is_none() {
            return self.dict_get(mapping, key);
        }

        match self.getitem(&Value::Object(Rc::clone(mapping)), key) {
            Ok(value) => Ok(Some(value)),
            Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::KeyError) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
