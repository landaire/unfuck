use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::table::Hashed;
use crate::interp::table::PySetTable;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub type PySet = PySetTable<Value>;

/// Where the elements of a set operand come from; CPython takes a
/// different path for each.
pub enum SetSource {
    Set(PySet),
    Dict(crate::interp::pydict::PyDict),
    Items(Vec<Value>),
}

impl Vm {
    pub fn new_set(&self, table: PySet) -> Value {
        let class = Rc::clone(&self.types().set);

        Value::Object(self.alloc(&class, Payload::Set(RefCell::new(table)), None))
    }

    pub fn new_frozenset(&self, table: PySet) -> Value {
        let class = Rc::clone(&self.types().frozenset);

        Value::Object(self.alloc(&class, Payload::FrozenSet(table), None))
    }

    /// `set(iterable)`.
    pub fn new_set_from(&self, iterable: &Value) -> PyResult<Value> {
        let table = self.set_table_from(iterable)?;

        Ok(self.new_set(table))
    }

    pub fn new_frozenset_from(&self, iterable: &Value) -> PyResult<Value> {
        let table = self.set_table_from(iterable)?;

        Ok(self.new_frozenset(table))
    }

    /// The table of a set or frozenset (including subclass instances).
    pub fn set_snapshot(&self, value: &Value) -> Option<PySet> {
        let Value::Object(object) = value else {
            return None;
        };

        match &object.payload {
            Payload::Set(table) => Some(table.borrow().clone()),
            Payload::FrozenSet(table) => Some(table.clone()),
            _ => None,
        }
    }

    /// Classifies a set operand as `set.update` does: any set or
    /// frozenset, an exact dict, or another iterable.
    pub fn set_source(&self, value: &Value) -> PyResult<SetSource> {
        if let Some(table) = self.set_snapshot(value) {
            return Ok(SetSource::Set(table));
        }

        if let Value::Object(object) = value {
            if let Payload::Dict(table) = &object.payload {
                if Rc::ptr_eq(&object.class(), &self.types().dict) {
                    return Ok(SetSource::Dict(table.borrow().clone()));
                }
            }
        }

        Ok(SetSource::Items(self.collect(value)?))
    }

    pub fn hashed_items(&self, items: Vec<Value>) -> impl Iterator<Item = PyResult<Hashed<Value>>> + '_ {
        items.into_iter().map(|key| Ok(Hashed { hash: self.hash(&key)?, key }))
    }

    pub fn set_table_from(&self, iterable: &Value) -> PyResult<PySet> {
        let eq = |stored: &Value, probe: &Value| self.keys_equal(stored, probe);

        match self.set_source(iterable)? {
            SetSource::Set(other) => PySet::from_set(&other, eq),
            SetSource::Dict(other) => PySet::from_dict(&other, eq),
            SetSource::Items(items) => PySet::from_iterable(self.hashed_items(items), eq),
        }
    }

    pub(crate) fn mutable_set<'a>(&self, set: &'a ObjectRef) -> PyResult<&'a RefCell<PySet>> {
        match &set.payload {
            Payload::Set(table) => Ok(table),
            _ => Err(self.type_error("expected a set")),
        }
    }

    /// Adds `item` to `set`. The table is taken out of the set while equality runs,
    /// so user `__eq__` code sees an empty set instead of a borrowed one.
    pub fn set_add(&self, set: &Value, item: Value) -> PyResult<()> {
        let Value::Object(object) = set else {
            return Err(self.type_error("expected a set"));
        };

        let hash = self.hash(&item)?;
        let cell = self.mutable_set(object)?;
        let changed = || self.raise(ExceptionKind::RuntimeError, "set changed size during lookup");
        let mut table = std::mem::take(&mut *cell.try_borrow_mut().map_err(|_| changed())?);
        let probe = item.clone();
        let result = table.add(hash, item, |stored| self.keys_equal(stored, &probe));
        *cell.try_borrow_mut().map_err(|_| changed())? = table;
        result?;

        Ok(())
    }

    pub fn set_contains(&self, table: &PySet, item: &Value) -> PyResult<bool> {
        let hash = match self.hash(item) {
            Ok(hash) => hash,
            Err(crate::interp::error::Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::TypeError) => {
                let Some(frozen) = self.set_snapshot(item) else {
                    return Err(crate::interp::error::Signal::Raise(error));
                };
                self.frozenset_hash(&frozen)
            }
            Err(error) => return Err(error),
        };

        table.contains(hash, |stored| self.keys_equal(stored, item))
    }

    pub fn set_next_entry(&self, set: &ObjectRef, position: usize) -> Option<(usize, Value)> {
        match &set.payload {
            Payload::Set(table) => table.borrow().next_active(position).map(|entry| (entry.slot, entry.key.clone())),
            Payload::FrozenSet(table) => table.next_active(position).map(|entry| (entry.slot, entry.key.clone())),
            _ => None,
        }
    }

    pub fn set_len(&self, set: &ObjectRef) -> usize {
        match &set.payload {
            Payload::Set(table) => table.borrow().len(),
            Payload::FrozenSet(table) => table.len(),
            _ => 0,
        }
    }

    pub fn set_items(&self, value: &Value) -> Option<Vec<Value>> {
        self.set_snapshot(value).map(|table| table.iter().cloned().collect())
    }
}
