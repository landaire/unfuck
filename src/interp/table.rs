//! Open-addressing tables that place keys in the same buckets as the dicts
//! and sets of CPython 2.7. Iteration walks the buckets in index order, so
//! matching the bucket of every key reproduces the reference iteration
//! order.
//!
//! Key equality comes from the caller and may fail. A table calls it only
//! for a live entry whose stored hash equals the probe hash, and expects it
//! to evaluate `stored == probe`, identity shortcut included. Closures that
//! take one key receive the stored key. Closures that take two receive the
//! stored key, then the probe key.

use crate::interp::hash::PyHash;

/// Bucket count of a new or cleared table.
const MIN_CAPACITY: usize = 8;

/// A borrowed active dict slot.
#[derive(Debug)]
pub struct DictEntryRef<'a, K, V> {
    pub slot: usize,
    pub hash: PyHash,
    pub key: &'a K,
    pub value: &'a V,
}

/// A borrowed active set slot.
#[derive(Debug)]
pub struct SetEntryRef<'a, K> {
    pub slot: usize,
    pub hash: PyHash,
    pub key: &'a K,
}

/// A key paired with its already computed hash.
#[derive(Debug, Clone)]
pub struct Hashed<K> {
    pub hash: PyHash,
    pub key: K,
}

/// The storage of a dict.
#[derive(Debug, Clone)]
pub struct PyDictTable<K, V> {
    store: Store<K, V>,
}

impl<K, V> PyDictTable<K, V> {
    pub fn new() -> Self {
        Self {
            store: Store::new(),
        }
    }

    /// A table sized up front for `minused` entries, as a dict display
    /// allocates it.
    pub fn new_presized(minused: usize) -> Self {
        let mut table = Self::new();
        table.presize(minused);

        table
    }

    pub fn len(&self) -> usize {
        self.store.live
    }

    pub fn is_empty(&self) -> bool {
        self.store.live == 0
    }

    /// Number of live entries.
    pub fn used(&self) -> usize {
        self.store.live
    }

    /// Number of buckets holding a live entry or a tombstone.
    pub fn fill(&self) -> usize {
        self.store.claimed
    }

    /// Bucket count minus one.
    pub fn mask(&self) -> usize {
        self.store.mask()
    }

    /// The live entry whose key equals the probe.
    pub fn lookup<E>(
        &self,
        hash: PyHash,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<DictEntryRef<'_, K, V>>, E> {
        let found = match self.store.find(hash, &mut eq)? {
            Search::Found(index) => self.entry(index),
            Search::Free(_) => None,
        };

        Ok(found)
    }

    /// Stores `value` under `key`, then grows the table if a new key left
    /// it crowded. An existing key keeps its stored key object and takes
    /// the new value; the old value is returned.
    pub fn set_item<E>(
        &mut self,
        hash: PyHash,
        key: K,
        value: V,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<V>, E> {
        let search = self.store.find(hash, &mut eq)?;
        let replaced = self.store.store_at(search, hash, key, value);

        if replaced.is_none() {
            self.store.grow_if_crowded();
        }

        Ok(replaced)
    }

    /// Stores `value` under `key` without a growth check. Callers presize
    /// the table for every key they insert this way.
    pub fn insert_no_resize<E>(
        &mut self,
        hash: PyHash,
        key: K,
        value: V,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<V>, E> {
        // Searches end at a vacant bucket, so one must always remain.
        if self.store.claimed + 1 >= self.store.capacity() {
            self.store.rebuild(growth_target(self.store.live + 1));
        }

        let search = self.store.find(hash, &mut eq)?;

        Ok(self.store.store_at(search, hash, key, value))
    }

    /// Rebuilds the table with room for `minused` entries.
    pub fn presize(&mut self, minused: usize) {
        self.store.rebuild(minused);
    }

    /// Removes the entry whose key equals the probe. Returns `None` when
    /// the key is absent (KeyError).
    pub fn del_item<E>(
        &mut self,
        hash: PyHash,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<(K, V)>, E> {
        let removed = match self.store.find(hash, &mut eq)? {
            Search::Found(index) => self.store.take(index),
            Search::Free(_) => None,
        };

        Ok(removed.map(|entry| (entry.key, entry.value)))
    }

    /// `dict.pop` with a key. An empty dict answers before the key is
    /// hashed, so callers check `is_empty()` before computing `hash`.
    pub fn pop<E>(
        &mut self,
        hash: PyHash,
        eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<(K, V)>, E> {
        self.del_item(hash, eq)
    }

    /// `dict.popitem`. Returns `None` when empty (KeyError).
    pub fn popitem(&mut self) -> Option<(K, V)> {
        self.store
            .take_next_for_pop()
            .map(|entry| (entry.key, entry.value))
    }

    pub fn clear(&mut self) {
        self.store = Store::new();
    }

    /// `dict.update` with a dict: every entry of `other` overrides this
    /// table. Callers skip `a.update(a)`, which leaves `a` unchanged.
    pub fn merge_from_dict<E>(
        &mut self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
        V: Clone,
    {
        // An empty source leaves even an overfull table alone.
        if other.is_empty() {
            return Ok(());
        }

        self.store.reserve(other.len());
        for entry in other.store.live_entries() {
            let search = self
                .store
                .find(entry.hash, &mut |stored| eq(stored, &entry.key))?;
            self.store
                .store_at(search, entry.hash, entry.key.clone(), entry.value.clone());
        }

        Ok(())
    }

    /// `dict.copy`: a new table updated from this one.
    pub fn copy<E>(&self, eq: impl FnMut(&K, &K) -> Result<bool, E>) -> Result<Self, E>
    where
        K: Clone,
        V: Clone,
    {
        let mut copy = Self::new();
        copy.merge_from_dict(self, eq)?;

        Ok(copy)
    }

    /// The first live slot at or after `position`. Iterators resume from
    /// `slot + 1`.
    pub fn next_active(&self, position: usize) -> Option<DictEntryRef<'_, K, V>> {
        let index = self.store.next_live(position)?;

        self.entry(index)
    }

    /// Live entries in slot order.
    pub fn entries(&self) -> impl Iterator<Item = DictEntryRef<'_, K, V>> {
        self.store
            .indexed_entries()
            .map(|(slot, entry)| DictEntryRef {
                slot,
                hash: entry.hash,
                key: &entry.key,
                value: &entry.value,
            })
    }

    /// Items in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries().map(|entry| (entry.key, entry.value))
    }

    /// Keys in slot order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries().map(|entry| entry.key)
    }

    /// Values in slot order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries().map(|entry| entry.value)
    }

    fn entry(&self, index: usize) -> Option<DictEntryRef<'_, K, V>> {
        let entry = self.store.live_at(index)?;

        Some(DictEntryRef {
            slot: index,
            hash: entry.hash,
            key: &entry.key,
            value: &entry.value,
        })
    }
}

impl<K, V> Default for PyDictTable<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// The storage of a set or frozenset.
///
/// Where CPython shortcuts an operation whose operand is the set itself
/// (`update`, `union`, `intersection`, `difference_update`,
/// `symmetric_difference_update`, `isdisjoint`), the caller applies the
/// shortcut; a table cannot see that its operand aliases it.
#[derive(Debug, Clone)]
pub struct PySetTable<K> {
    store: Store<K, ()>,
}

impl<K> PySetTable<K> {
    pub fn new() -> Self {
        Self {
            store: Store::new(),
        }
    }

    /// A new set holding the keys of another set. This is also `copy`.
    pub fn from_set<E>(other: &Self, eq: impl FnMut(&K, &K) -> Result<bool, E>) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut table = Self::new();
        table.update_from_set(other, eq)?;

        Ok(table)
    }

    /// A new set holding the keys of an exact dict.
    pub fn from_dict<V, E>(
        other: &PyDictTable<K, V>,
        eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut table = Self::new();
        table.update_from_dict(other, eq)?;

        Ok(table)
    }

    /// A new set holding the items of any other iterable. An `Err` item
    /// stops construction.
    pub fn from_iterable<E>(
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E> {
        let mut table = Self::new();
        table.update_from_iter(items, eq)?;

        Ok(table)
    }

    pub fn len(&self) -> usize {
        self.store.live
    }

    pub fn is_empty(&self) -> bool {
        self.store.live == 0
    }

    /// Number of live entries.
    pub fn used(&self) -> usize {
        self.store.live
    }

    /// Number of buckets holding a live entry or a tombstone.
    pub fn fill(&self) -> usize {
        self.store.claimed
    }

    /// Bucket count minus one.
    pub fn mask(&self) -> usize {
        self.store.mask()
    }

    pub fn contains<E>(
        &self,
        hash: PyHash,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let search = self.store.find(hash, &mut eq)?;

        Ok(matches!(search, Search::Found(_)))
    }

    /// The stored key equal to the probe.
    pub fn lookup<E>(
        &self,
        hash: PyHash,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<SetEntryRef<'_, K>>, E> {
        let found = match self.store.find(hash, &mut eq)? {
            Search::Found(index) => self.entry(index),
            Search::Free(_) => None,
        };

        Ok(found)
    }

    /// Adds `key`, then grows the table if it is crowded. Returns true when
    /// the key was not already present; an existing stored key is kept.
    pub fn add<E>(
        &mut self,
        hash: PyHash,
        key: K,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let search = self.store.find(hash, &mut eq)?;

        Ok(self.add_at(search, hash, key))
    }

    /// Removes the key equal to the probe. Returns the removed key, or
    /// `None` when absent.
    pub fn discard<E>(
        &mut self,
        hash: PyHash,
        mut eq: impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Option<K>, E> {
        let removed = match self.store.find(hash, &mut eq)? {
            Search::Found(index) => self.store.take(index),
            Search::Free(_) => None,
        };

        Ok(removed.map(|entry| entry.key))
    }

    /// `set.pop`. Returns `None` when empty (KeyError).
    pub fn pop(&mut self) -> Option<K> {
        self.store.take_next_for_pop().map(|entry| entry.key)
    }

    pub fn clear(&mut self) {
        self.store = Store::new();
    }

    /// Rebuilds the table with room for `minused` entries.
    pub fn resize(&mut self, minused: usize) {
        self.store.rebuild(minused);
    }

    /// `update` with a set or frozenset: one presize, then every key of
    /// `other` in slot order without further growth checks.
    pub fn update_from_set<E>(
        &mut self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        if other.is_empty() {
            return Ok(());
        }

        self.store.reserve(other.len());
        for entry in other.store.live_entries() {
            let search = self
                .store
                .find(entry.hash, &mut |stored| eq(stored, &entry.key))?;
            self.store
                .store_at(search, entry.hash, entry.key.clone(), ());
        }

        Ok(())
    }

    /// `update` with an exact dict: one presize, then each key in dict
    /// order with the usual growth check.
    pub fn update_from_dict<V, E>(
        &mut self,
        other: &PyDictTable<K, V>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        self.store.reserve(other.len());
        for entry in other.entries() {
            self.add_entry(entry.hash, entry.key.clone(), &mut eq)?;
        }

        Ok(())
    }

    /// `update` with any other iterable: each item is added in turn.
    pub fn update_from_iter<E>(
        &mut self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E> {
        for item in items {
            let item = item?;
            self.add_entry(item.hash, item.key, &mut eq)?;
        }

        Ok(())
    }

    /// `union` with a set: a copy of this set updated from `other`.
    pub fn union_set<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_set(self, &mut eq)?;
        result.update_from_set(other, &mut eq)?;

        Ok(result)
    }

    /// `union` with an exact dict.
    pub fn union_dict<V, E>(
        &self,
        other: &PyDictTable<K, V>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_set(self, &mut eq)?;
        result.update_from_dict(other, &mut eq)?;

        Ok(result)
    }

    /// `union` with any other iterable.
    pub fn union_iter<E>(
        &self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_set(self, &mut eq)?;
        result.update_from_iter(items, &mut eq)?;

        Ok(result)
    }

    /// `intersection` with a set. The smaller operand is walked (`other`
    /// when the sizes tie) and probed against the larger one, so the
    /// result holds the walked operand's keys.
    pub fn intersection_set<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let (walked, probed) = smaller_first(self, other);

        let mut result = Self::new();
        for entry in walked.store.live_entries() {
            if probed.contains_key(entry.hash, &entry.key, &mut eq)? {
                result.add_entry(entry.hash, entry.key.clone(), &mut eq)?;
            }
        }

        Ok(result)
    }

    /// `intersection` with any other iterable, dicts included.
    pub fn intersection_iter<E>(
        &self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E> {
        let mut result = Self::new();
        for item in items {
            let item = item?;
            if self.contains_key(item.hash, &item.key, &mut eq)? {
                result.add_entry(item.hash, item.key, &mut eq)?;
            }
        }

        Ok(result)
    }

    /// `difference` with a set: the keys of this set absent from `other`.
    pub fn difference_set<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::new();
        for entry in self.store.live_entries() {
            if !other.contains_key(entry.hash, &entry.key, &mut eq)? {
                result.add_entry(entry.hash, entry.key.clone(), &mut eq)?;
            }
        }

        Ok(result)
    }

    /// `difference` with an exact dict: the keys of this set the dict does
    /// not contain.
    pub fn difference_dict<V, E>(
        &self,
        other: &PyDictTable<K, V>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::new();
        for entry in self.store.live_entries() {
            let found = other.lookup(entry.hash, |stored| eq(stored, &entry.key))?;
            if found.is_none() {
                result.add_entry(entry.hash, entry.key.clone(), &mut eq)?;
            }
        }

        Ok(result)
    }

    /// `difference` with any other iterable: a copy of this set, then
    /// `difference_update`.
    pub fn difference_iter<E>(
        &self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_set(self, &mut eq)?;
        result.difference_update_iter(items, &mut eq)?;

        Ok(result)
    }

    /// `difference_update` with a set.
    pub fn difference_update_set<E>(
        &mut self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E> {
        for entry in other.store.live_entries() {
            self.remove_key(entry.hash, &entry.key, &mut eq)?;
        }
        self.shed_tombstones();

        Ok(())
    }

    /// `difference_update` with any other iterable, dicts included. An
    /// `Err` item stops the update before tombstones are shed.
    pub fn difference_update_iter<E>(
        &mut self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E> {
        for item in items {
            let item = item?;
            self.remove_key(item.hash, &item.key, &mut eq)?;
        }
        self.shed_tombstones();

        Ok(())
    }

    /// `symmetric_difference_update` with a set: each key of `other` is
    /// removed when present and added otherwise.
    pub fn symmetric_difference_update_set<E>(
        &mut self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        for entry in other.store.live_entries() {
            self.toggle(entry.hash, &entry.key, &mut eq)?;
        }

        Ok(())
    }

    /// `symmetric_difference_update` with an exact dict, in dict order.
    pub fn symmetric_difference_update_dict<V, E>(
        &mut self,
        other: &PyDictTable<K, V>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        for entry in other.entries() {
            self.toggle(entry.hash, entry.key, &mut eq)?;
        }

        Ok(())
    }

    /// `symmetric_difference_update` with any other iterable: the items
    /// are first collected into a set, which is then applied.
    pub fn symmetric_difference_update_iter<E>(
        &mut self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        let other = Self::from_iterable(items, &mut eq)?;

        self.symmetric_difference_update_set(&other, eq)
    }

    /// `symmetric_difference` with a set: a copy of `other` updated with
    /// this set.
    pub fn symmetric_difference_set<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_set(other, &mut eq)?;
        result.symmetric_difference_update_set(self, &mut eq)?;

        Ok(result)
    }

    /// `symmetric_difference` with an exact dict.
    pub fn symmetric_difference_dict<V, E>(
        &self,
        other: &PyDictTable<K, V>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_dict(other, &mut eq)?;
        result.symmetric_difference_update_set(self, &mut eq)?;

        Ok(result)
    }

    /// `symmetric_difference` with any other iterable.
    pub fn symmetric_difference_iter<E>(
        &self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<Self, E>
    where
        K: Clone,
    {
        let mut result = Self::from_iterable(items, &mut eq)?;
        result.symmetric_difference_update_set(self, &mut eq)?;

        Ok(result)
    }

    /// `issubset` with a set. Callers convert any other operand with
    /// `from_dict`/`from_iterable` first.
    pub fn is_subset<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        if self.len() > other.len() {
            return Ok(false);
        }

        for entry in self.store.live_entries() {
            if !other.contains_key(entry.hash, &entry.key, &mut eq)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// `issuperset` with a set, answered as `other.issubset(self)`.
    pub fn is_superset<E>(
        &self,
        other: &Self,
        eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        other.is_subset(self, eq)
    }

    /// `isdisjoint` with an exact set or frozenset. The smaller operand is
    /// walked (`other` when the sizes tie) and probed against the larger.
    pub fn is_disjoint_set<E>(
        &self,
        other: &Self,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let (walked, probed) = smaller_first(self, other);

        for entry in walked.store.live_entries() {
            if probed.contains_key(entry.hash, &entry.key, &mut eq)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// `isdisjoint` with any other iterable, set subclasses included.
    pub fn is_disjoint_iter<E>(
        &self,
        items: impl IntoIterator<Item = Result<Hashed<K>, E>>,
        mut eq: impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        for item in items {
            let item = item?;
            if self.contains_key(item.hash, &item.key, &mut eq)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// The first live slot at or after `position`. Iterators resume from
    /// `slot + 1`.
    pub fn next_active(&self, position: usize) -> Option<SetEntryRef<'_, K>> {
        let index = self.store.next_live(position)?;

        self.entry(index)
    }

    /// Live entries in slot order.
    pub fn entries(&self) -> impl Iterator<Item = SetEntryRef<'_, K>> {
        self.store
            .indexed_entries()
            .map(|(slot, entry)| SetEntryRef {
                slot,
                hash: entry.hash,
                key: &entry.key,
            })
    }

    /// Keys in slot order.
    pub fn iter(&self) -> impl Iterator<Item = &K> {
        self.entries().map(|entry| entry.key)
    }

    fn entry(&self, index: usize) -> Option<SetEntryRef<'_, K>> {
        let entry = self.store.live_at(index)?;

        Some(SetEntryRef {
            slot: index,
            hash: entry.hash,
            key: &entry.key,
        })
    }

    fn contains_key<E>(
        &self,
        hash: PyHash,
        key: &K,
        eq: &mut impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let search = self.store.find(hash, &mut |stored| eq(stored, key))?;

        Ok(matches!(search, Search::Found(_)))
    }

    /// Adds `key` with the growth check, comparing with a two-key closure.
    fn add_entry<E>(
        &mut self,
        hash: PyHash,
        key: K,
        eq: &mut impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let search = self.store.find(hash, &mut |stored| eq(stored, &key))?;

        Ok(self.add_at(search, hash, key))
    }

    /// Completes an add at the position a search returned. Returns true
    /// when the key is new.
    fn add_at(&mut self, search: Search, hash: PyHash, key: K) -> bool {
        let existed = self.store.store_at(search, hash, key, ()).is_some();
        if existed {
            return false;
        }

        self.store.grow_if_crowded();

        true
    }

    /// Removes the key equal to `key`. Returns true when one was removed.
    fn remove_key<E>(
        &mut self,
        hash: PyHash,
        key: &K,
        eq: &mut impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let removed = match self.store.find(hash, &mut |stored| eq(stored, key))? {
            Search::Found(index) => self.store.take(index).is_some(),
            Search::Free(_) => false,
        };

        Ok(removed)
    }

    /// Removes `key` when present, otherwise adds it.
    fn toggle<E>(
        &mut self,
        hash: PyHash,
        key: &K,
        eq: &mut impl FnMut(&K, &K) -> Result<bool, E>,
    ) -> Result<(), E>
    where
        K: Clone,
    {
        if !self.remove_key(hash, key, eq)? {
            self.add_entry(hash, key.clone(), eq)?;
        }

        Ok(())
    }

    /// Rebuilds the table after a bulk removal once tombstones reach a
    /// fifth of the mask.
    fn shed_tombstones(&mut self) {
        let tombstones = self.store.claimed - self.store.live;
        if tombstones * 5 >= self.store.mask() {
            self.store.rebuild(growth_target(self.store.live));
        }
    }
}

impl<K> Default for PySetTable<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// A live key, its hash, and its value (`()` in sets).
#[derive(Debug, Clone)]
struct Entry<K, V> {
    hash: PyHash,
    key: K,
    value: V,
}

#[derive(Debug, Clone)]
enum Bucket<K, V> {
    /// Never held an entry since the last rebuild. Searches stop here.
    Vacant,
    /// Held an entry that was removed. Searches continue past it, and an
    /// insertion may reuse it.
    Tombstone,
    Live(Entry<K, V>),
}

impl<K, V> Bucket<K, V> {
    fn live(&self) -> Option<&Entry<K, V>> {
        match self {
            Bucket::Live(entry) => Some(entry),
            Bucket::Vacant | Bucket::Tombstone => None,
        }
    }
}

/// Where `take_next_for_pop` starts scanning when bucket 0 is not live.
#[derive(Debug, Clone, Copy)]
enum PopStart {
    /// Nothing recorded since the last rebuild.
    Unset,
    /// The hash of the key last removed from bucket 0 by key.
    RemovedHash(PyHash),
    /// The bucket the previous pop emptied.
    After(usize),
}

/// Outcome of a key search.
#[derive(Debug, Clone, Copy)]
enum Search {
    /// The bucket of the live entry whose key matched.
    Found(usize),
    /// No key matched. An insertion goes to this bucket: the first
    /// tombstone on the probe path, else the vacant bucket that ended it.
    Free(usize),
}

/// The bucket sequence a hash visits. The first bucket is the low bits of
/// the hash. Each later bucket is `5 * previous + 1 + perturb`, where
/// `perturb` starts as the whole hash and loses its low five bits after
/// each step, so the high hash bits steer the first few probes.
#[derive(Debug, Clone, Copy)]
struct ProbePath {
    index: usize,
    perturb: u64,
    mask: usize,
}

impl ProbePath {
    fn new(hash: PyHash, mask: usize) -> Self {
        let perturb = hash.as_size_t();

        Self {
            index: (perturb as usize) & mask,
            perturb,
            mask,
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn advance(&mut self) {
        let next = self
            .index
            .wrapping_mul(5)
            .wrapping_add(1)
            .wrapping_add(self.perturb as usize);
        self.index = next & self.mask;
        self.perturb >>= 5;
    }
}

/// The bucket array shared by dicts and sets.
///
/// At least one bucket is always vacant, which ends every search.
#[derive(Debug, Clone)]
struct Store<K, V> {
    /// A power-of-two number of buckets.
    buckets: Vec<Bucket<K, V>>,

    /// Live buckets.
    live: usize,
    /// Live buckets plus tombstones.
    claimed: usize,

    pop_start: PopStart,
}

impl<K, V> Store<K, V> {
    fn new() -> Self {
        Self::with_capacity(MIN_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            buckets: (0..capacity).map(|_| Bucket::Vacant).collect(),
            live: 0,
            claimed: 0,
            pop_start: PopStart::Unset,
        }
    }

    fn capacity(&self) -> usize {
        self.buckets.len()
    }

    fn mask(&self) -> usize {
        self.buckets.len() - 1
    }

    fn live_at(&self, index: usize) -> Option<&Entry<K, V>> {
        self.buckets.get(index)?.live()
    }

    fn live_entries(&self) -> impl Iterator<Item = &Entry<K, V>> {
        self.buckets.iter().filter_map(Bucket::live)
    }

    fn indexed_entries(&self) -> impl Iterator<Item = (usize, &Entry<K, V>)> {
        self.buckets
            .iter()
            .enumerate()
            .filter_map(|(index, bucket)| Some((index, bucket.live()?)))
    }

    fn next_live(&self, position: usize) -> Option<usize> {
        let rest = self.buckets.get(position..)?;
        let offset = rest.iter().position(|bucket| bucket.live().is_some())?;

        Some(position + offset)
    }

    /// Follows the probe path of `hash` until a live key matches or a
    /// vacant bucket ends the path.
    fn find<E>(
        &self,
        hash: PyHash,
        matches: &mut impl FnMut(&K) -> Result<bool, E>,
    ) -> Result<Search, E> {
        let mut path = ProbePath::new(hash, self.mask());
        let mut first_tombstone = None;

        loop {
            let index = path.index();
            match &self.buckets[index] {
                Bucket::Vacant => return Ok(Search::Free(first_tombstone.unwrap_or(index))),
                Bucket::Tombstone => {
                    first_tombstone.get_or_insert(index);
                }
                Bucket::Live(entry) => {
                    if entry.hash == hash && matches(&entry.key)? {
                        return Ok(Search::Found(index));
                    }
                }
            }
            path.advance();
        }
    }

    /// Completes an insertion at the position `find` returned. A found
    /// entry keeps its key and takes `value`, and the old value is
    /// returned; otherwise a new entry is created and `None` is returned.
    fn store_at(&mut self, search: Search, hash: PyHash, key: K, value: V) -> Option<V> {
        match search {
            Search::Found(index) => {
                let Bucket::Live(entry) = &mut self.buckets[index] else {
                    return None;
                };

                Some(std::mem::replace(&mut entry.value, value))
            }
            Search::Free(index) => {
                let bucket = &mut self.buckets[index];
                if matches!(bucket, Bucket::Vacant) {
                    self.claimed += 1;
                }
                *bucket = Bucket::Live(Entry { hash, key, value });
                self.live += 1;

                None
            }
        }
    }

    /// Turns a live bucket into a tombstone and returns its entry.
    fn take(&mut self, index: usize) -> Option<Entry<K, V>> {
        let bucket = self.buckets.get_mut(index)?;
        let entry = match std::mem::replace(bucket, Bucket::Tombstone) {
            Bucket::Live(entry) => entry,
            unchanged @ (Bucket::Vacant | Bucket::Tombstone) => {
                *bucket = unchanged;
                return None;
            }
        };
        self.live -= 1;

        if index == 0 {
            self.pop_start = PopStart::RemovedHash(entry.hash);
        }

        Some(entry)
    }

    /// Removes the entry `popitem` and `set.pop` return: bucket 0 when it
    /// is live, else the first live bucket found by scanning upward from
    /// the recorded start and wrapping to bucket 1.
    fn take_next_for_pop(&mut self) -> Option<Entry<K, V>> {
        if self.live == 0 {
            return None;
        }

        let mask = self.mask();
        let index = if self.buckets[0].live().is_some() {
            0
        } else {
            let start = match self.pop_start {
                PopStart::Unset => 1,
                PopStart::RemovedHash(hash) => usize::try_from(hash.value())
                    .ok()
                    .filter(|start| (1..=mask).contains(start))
                    .unwrap_or(1),
                PopStart::After(previous) if previous < mask => previous + 1,
                PopStart::After(_) => 1,
            };
            let mut index = start;
            while self.buckets[index].live().is_none() {
                index = if index == mask { 1 } else { index + 1 };
            }
            index
        };

        let entry = self.take(index)?;
        self.pop_start = PopStart::After(index);

        Some(entry)
    }

    /// Grows the table after a new key when live entries and tombstones
    /// fill two thirds of the buckets.
    fn grow_if_crowded(&mut self) {
        if self.claimed * 3 >= self.capacity() * 2 {
            self.rebuild(growth_target(self.live));
        }
    }

    /// Makes room before `incoming` keys are inserted without growth
    /// checks.
    fn reserve(&mut self, incoming: usize) {
        if (self.claimed + incoming) * 3 >= self.capacity() * 2 {
            self.rebuild((self.live + incoming).saturating_mul(2));
        }
    }

    /// Moves the live entries, in bucket order, into a table of the
    /// smallest power-of-two capacity above `min_live`, dropping
    /// tombstones. A minimum-size table without tombstones is left as is.
    fn rebuild(&mut self, min_live: usize) {
        let capacity = capacity_above(min_live);
        if capacity == MIN_CAPACITY && self.capacity() == MIN_CAPACITY && self.claimed == self.live
        {
            return;
        }

        let old = std::mem::replace(self, Self::with_capacity(capacity));
        let mask = self.mask();
        for bucket in old.buckets {
            let Bucket::Live(entry) = bucket else {
                continue;
            };

            let mut path = ProbePath::new(entry.hash, mask);
            while !matches!(self.buckets[path.index()], Bucket::Vacant) {
                path.advance();
            }
            self.buckets[path.index()] = Bucket::Live(entry);
            self.live += 1;
        }
        self.claimed = self.live;
    }
}

/// The capacity a crowded table grows to: room for four times its live
/// entries, or twice for very large tables.
fn growth_target(live: usize) -> usize {
    if live > 50_000 {
        live.saturating_mul(2)
    } else {
        live.saturating_mul(4)
    }
}

/// The smallest power of two above `min_live`, at least `MIN_CAPACITY`.
fn capacity_above(min_live: usize) -> usize {
    let wanted = min_live.saturating_add(1);
    let capacity = wanted
        .checked_next_power_of_two()
        .unwrap_or(1 << (usize::BITS - 1));

    capacity.max(MIN_CAPACITY)
}

/// The operand to walk and the operand to probe: the smaller set first,
/// with `other` walked when the sizes tie.
fn smaller_first<'a, K>(
    this: &'a PySetTable<K>,
    other: &'a PySetTable<K>,
) -> (&'a PySetTable<K>, &'a PySetTable<K>) {
    if other.len() > this.len() {
        (this, other)
    } else {
        (other, this)
    }
}
