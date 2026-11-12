//! Instance structs of new-style classes as `type.__new__` lays them out: the
//! `__slots__` members, the `__dict__` and weak reference list words, the
//! solid base behind layout conflicts, and the layout checks of `__class__`
//! and `__bases__` assignment. Sizes and offsets count pointer-sized words
//! past a class's builtin solid base.

use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::attr::SlotDescriptor;
use crate::interp::attr::SlotKind;
use crate::interp::compiler::symtable::mangle;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::ClassStyle;
use crate::interp::object::HeapLayout;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::object::SlotIndex;
use crate::interp::object::StorageOffset;
use crate::interp::type_flags::TypeFlags;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The instance storage `type.__new__` gives a new class.
pub struct SlotStorage {
    pub add_dict: bool,
    pub add_weak: bool,
    /// The `__slots__` member names; `None` without `__slots__`.
    pub members: Option<Vec<PyBytes>>,
}

/// The fields of a type object that the layout comparisons check.
struct Shape {
    /// The builtin solid base the words count from.
    root: ObjectRef,
    /// `__basicsize__`.
    size: usize,
    /// `__itemsize__ != 0`.
    items: bool,
    dict: Option<StorageOffset>,
    weak: Option<StorageOffset>,
    gc: bool,
    heap: bool,
}

/// How instances of a class are freed.
enum Deallocator {
    /// The generic deallocator of heap classes, with or without GC tracking.
    Subtype { gc: bool },
    /// The deallocator of a builtin solid base.
    Builtin(ObjectRef),
}

impl Deallocator {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Subtype { gc }, Self::Subtype { gc: other_gc }) => gc == other_gc,
            (Self::Builtin(root), Self::Builtin(other_root)) => Rc::ptr_eq(root, other_root),
            _ => false,
        }
    }
}

impl Vm {
    /// `__base__`: the solid base `type.__new__` chose, else the first base of a
    /// builtin type; `None` for `object`.
    pub fn class_base(&self, class: &ObjectRef) -> Option<ObjectRef> {
        let data = class.as_class()?;
        if let Some(layout) = &data.heap_layout {
            return Some(Rc::clone(&layout.base.borrow()));
        }

        data.bases.borrow().iter().find_map(|base| base.as_object().filter(|base| base.as_class().is_some()).map(Rc::clone))
    }

    /// Whether instances of `class` carry a dict (`__dictoffset__ != 0`).
    pub fn class_has_dict(&self, class: &ObjectRef) -> PyResult<bool> {
        if let Some(layout) = class.as_class().and_then(|data| data.heap_layout.as_ref()) {
            return Ok(layout.dict.is_some());
        }

        self.builtin_has_storage(class, SlotKind::Dict, &[Layout::Exception, Layout::Function, Layout::Module, Layout::Type])
    }

    /// Whether instances of `class` take weak references
    /// (`__weakrefoffset__ != 0`).
    pub fn class_has_weakref(&self, class: &ObjectRef) -> PyResult<bool> {
        if let Some(layout) = class.as_class().and_then(|data| data.heap_layout.as_ref()) {
            return Ok(layout.weak.is_some());
        }

        self.builtin_has_storage(class, SlotKind::WeakRef, &[Layout::Set, Layout::FrozenSet, Layout::Function, Layout::Type])
    }

    fn builtin_has_storage(&self, class: &ObjectRef, kind: SlotKind, builtin_layouts: &[Layout]) -> PyResult<bool> {
        let Some(data) = class.as_class() else {
            return Ok(false);
        };
        if data.style == ClassStyle::Classic {
            return Ok(true);
        }
        if builtin_layouts.contains(&data.layout) || (kind == SlotKind::Dict && data.instance_dict) {
            return Ok(true);
        }

        let name = if kind == SlotKind::Dict { "__dict__" } else { "__weakref__" };
        for entry in data.mro() {
            let MroEntry::Class(candidate) = entry else {
                continue;
            };
            let Some(candidate_data) = candidate.as_class() else {
                continue;
            };
            let Some(Value::Object(descriptor)) = self.dict_get_str(&candidate_data.dict, name)? else {
                continue;
            };
            if let Payload::Native(native) = &descriptor.payload {
                if native.as_any().downcast_ref::<SlotDescriptor>().is_some_and(|slot| slot.kind == kind) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// The builtin class whose struct instances of `class` extend: the
    /// topmost builtin ancestor along `__base__` with the same storage.
    fn builtin_root(&self, class: &ObjectRef) -> ObjectRef {
        let mut current = Rc::clone(class);
        while let Some(layout) = current.as_class().and_then(|data| data.heap_layout.as_ref()) {
            let base = Rc::clone(&layout.base.borrow());
            current = base;
        }

        loop {
            let Some(layout) = current.as_class().map(|data| data.layout) else {
                return current;
            };
            let Some(base) = self.class_base(&current) else {
                return current;
            };
            if base.as_class().is_none_or(|data| data.layout != layout) {
                return current;
            }
            current = base;
        }
    }

    fn shape(&self, class: &ObjectRef) -> PyResult<Shape> {
        let root = self.builtin_root(class);
        let items = root.as_class().is_some_and(|data| matches!(data.layout, Layout::Tuple | Layout::Str | Layout::Long | Layout::Type));
        let gc = class.as_class().and_then(|data| data.flags.as_ref()).is_some_and(|flags| flags.get().contains(TypeFlags::HAVE_GC));

        if let Some(layout) = class.as_class().and_then(|data| data.heap_layout.as_ref()) {
            return Ok(Shape { root, size: layout.size, items, dict: layout.dict, weak: layout.weak, gc, heap: true });
        }

        let dict = if self.class_has_dict(class)? { Some(StorageOffset::Builtin) } else { None };
        let weak = if self.class_has_weakref(class)? { Some(StorageOffset::Builtin) } else { None };

        Ok(Shape { root, size: 0, items, dict, weak, gc, heap: false })
    }

    /// Whether `class` adds fields to the struct of `base`
    /// beyond a trailing `__dict__` and weak reference list.
    fn adds_fields(class: &Shape, base: &Shape) -> bool {
        if class.items || base.items {
            return class.size != base.size || class.items != base.items;
        }

        let mut size = class.size;
        if let Some(StorageOffset::Word(offset)) = class.weak
            && base.weak.is_none()
            && offset + 1 == size
            && class.heap
        {
            size -= 1;
        }
        if let Some(StorageOffset::Word(offset)) = class.dict
            && base.dict.is_none()
            && offset + 1 == size
            && class.heap
        {
            size -= 1;
        }

        size != base.size
    }

    /// The nearest class along `__base__` that adds fields.
    pub fn solid_base(&self, class: &ObjectRef) -> PyResult<ObjectRef> {
        let mut chain = Vec::new();
        let mut current = Rc::clone(class);
        while let Some(layout) = current.as_class().and_then(|data| data.heap_layout.as_ref()) {
            let base = Rc::clone(&layout.base.borrow());
            chain.push(current);
            current = base;
        }

        let mut solid = self.builtin_root(&current);
        let mut solid_shape = self.shape(&solid)?;
        for candidate in chain.into_iter().rev() {
            let shape = self.shape(&candidate)?;
            if Self::adds_fields(&shape, &solid_shape) {
                solid = candidate;
                solid_shape = shape;
            }
        }

        Ok(solid)
    }

    /// `best_base`: the base on the path to the most derived solid base.
    /// Classic and unknown bases do not take part; `None` when no other
    /// base remains.
    pub fn best_base(&self, bases: &[Value]) -> PyResult<Option<ObjectRef>> {
        let mut base: Option<ObjectRef> = None;
        let mut winner: Option<ObjectRef> = None;

        for candidate_base in bases {
            let candidate_base = match candidate_base {
                Value::Unknown(_) => continue,
                Value::Object(object) if object.as_class().is_some() => object,
                _ => return Err(self.type_error("bases must be types")),
            };
            if self.is_classic_class(candidate_base) {
                continue;
            }
            if !self.is_base_type(candidate_base) {
                return Err(self.type_error(&format!("type '{}' is not an acceptable base type", self.class_name(candidate_base))));
            }

            let candidate = self.solid_base(candidate_base)?;
            let Some(current) = &winner else {
                winner = Some(candidate);
                base = Some(Rc::clone(candidate_base));
                continue;
            };
            if self.is_subclass(current, &candidate)? {
                continue;
            }
            if self.is_subclass(&candidate, current)? {
                winner = Some(candidate);
                base = Some(Rc::clone(candidate_base));
                continue;
            }
            return Err(self.type_error("multiple bases have instance lay-out conflict"));
        }

        Ok(base)
    }

    /// The `__slots__` part of `type.__new__` for a class named `class_name`
    /// whose solid base is `base`: validates, mangles, and sorts the names,
    /// and decides `__dict__` and `__weakref__` storage, which secondary
    /// bases may supply.
    pub fn slot_storage(&self, class_name: &[u8], slots: Option<&Value>, base: &ObjectRef, bases: &[Value]) -> PyResult<SlotStorage> {
        let base_shape = self.shape(base)?;
        let may_add_dict = base_shape.dict.is_none();
        let may_add_weak = base_shape.weak.is_none() && !base_shape.items;

        let Some(slots) = slots else {
            return Ok(SlotStorage { add_dict: may_add_dict, add_weak: may_add_weak, members: None });
        };

        let names = match slots {
            Value::Str(_) | Value::Unicode(_) => vec![slots.clone()],
            Value::Object(object) if matches!(object.payload, Payload::Str(_) | Payload::Unicode(_)) => vec![slots.clone()],
            _ => self.collect(slots)?,
        };
        if !names.is_empty() && base_shape.items {
            return Err(self.type_error(&format!("nonempty __slots__ not supported for subtype of '{}'", self.class_name(base))));
        }

        // Unicode names convert to `str` first, then each is checked as an identifier.
        let mut converted = Vec::with_capacity(names.len());
        for name in &names {
            let name = match self.as_text(name) {
                Some(text) => self.encode_default(&text)?,
                None => name.clone(),
            };
            converted.push(name);
        }
        let mut identifiers = Vec::with_capacity(converted.len());
        for name in &converted {
            let Some(bytes) = self.as_str_bytes(name) else {
                return Err(self.type_error(&format!("__slots__ items must be strings, not '{}'", self.type_name(name))));
            };
            if !is_identifier(bytes.as_bytes()) {
                return Err(self.type_error("__slots__ must be identifiers"));
            }
            identifiers.push(bytes);
        }

        let mut add_dict = false;
        let mut add_weak = false;
        for name in &identifiers {
            match name.as_bytes() {
                b"__dict__" => {
                    if !may_add_dict || add_dict {
                        return Err(self.type_error("__dict__ slot disallowed: we already got one"));
                    }
                    add_dict = true;
                }
                b"__weakref__" => {
                    if !may_add_weak || add_weak {
                        return Err(self.type_error("__weakref__ slot disallowed: either we already got one, or __itemsize__ != 0"));
                    }
                    add_weak = true;
                }
                _ => {}
            }
        }

        let mut members: Vec<PyBytes> = identifiers
            .iter()
            .filter(|name| !(add_dict && name.as_bytes() == b"__dict__") && !(add_weak && name.as_bytes() == b"__weakref__"))
            .map(|name| match mangle(Some(class_name), name.as_bytes()) {
                Cow::Borrowed(_) => name.clone(),
                Cow::Owned(mangled) => PyBytes::new(mangled),
            })
            .collect();
        members.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        // Secondary bases may provide weakrefs or dict.
        if bases.len() > 1 && ((may_add_dict && !add_dict) || (may_add_weak && !add_weak)) {
            for secondary in bases {
                let Value::Object(secondary) = secondary else {
                    continue;
                };
                if Rc::ptr_eq(secondary, base) {
                    continue;
                }
                if self.is_classic_class(secondary) {
                    add_dict |= may_add_dict;
                    add_weak |= may_add_weak;
                    break;
                }
                if may_add_dict && !add_dict && self.class_has_dict(secondary)? {
                    add_dict = true;
                }
                if may_add_weak && !add_weak && self.class_has_weakref(secondary)? {
                    add_weak = true;
                }
                if (may_add_dict && !add_dict) || (may_add_weak && !add_weak) {
                    continue;
                }
                break;
            }
        }

        Ok(SlotStorage { add_dict, add_weak, members: Some(members) })
    }

    /// Places the members, then the `__dict__`, then the weak reference
    /// list after the struct of `base`.
    pub fn heap_layout(&self, base: &ObjectRef, storage: &SlotStorage) -> PyResult<HeapLayout> {
        let base_shape = self.shape(base)?;
        let base_slots = base.as_class().and_then(|data| data.heap_layout.as_ref()).map_or(0, |layout| layout.slot_count);
        let member_count = storage.members.as_ref().map_or(0, Vec::len);

        let mut size = base_shape.size + member_count;
        let dict = if storage.add_dict {
            let offset = if base_shape.items { StorageOffset::Trailing } else { StorageOffset::Word(size) };
            size += 1;
            Some(offset)
        } else {
            base_shape.dict
        };
        let weak = if storage.add_weak {
            let offset = StorageOffset::Word(size);
            size += 1;
            Some(offset)
        } else {
            base_shape.weak
        };

        Ok(HeapLayout {
            base: RefCell::new(Rc::clone(base)),
            size,
            dict,
            weak,
            slot_count: base_slots + member_count,
            members: storage.members.as_ref().map(|members| members.clone().into_boxed_slice()),
        })
    }

    /// Slot index of member `position` of the `__slots__` of a class whose
    /// instances have `layout`.
    pub fn member_index(layout: &HeapLayout, position: usize) -> SlotIndex {
        let added = layout.members.as_ref().map_or(0, |members| members.len());

        SlotIndex(layout.slot_count - added + position)
    }

    fn deallocator(&self, class: &ObjectRef) -> Deallocator {
        let Some(data) = class.as_class() else {
            return Deallocator::Builtin(Rc::clone(class));
        };
        if data.heap_layout.is_none() {
            return Deallocator::Builtin(self.builtin_root(class));
        }

        let gc = data.flags.as_ref().is_some_and(|flags| flags.get().contains(TypeFlags::HAVE_GC));

        Deallocator::Subtype { gc }
    }

    /// `__base__` of `class` when both have the same instance struct.
    fn equivalent_to_base(&self, class: &ObjectRef) -> PyResult<Option<ObjectRef>> {
        let Some(base) = self.class_base(class) else {
            return Ok(None);
        };

        let shape = self.shape(class)?;
        let base_shape = self.shape(&base)?;
        let equivalent = Rc::ptr_eq(&shape.root, &base_shape.root) && shape.size == base_shape.size && shape.items == base_shape.items && shape.dict == base_shape.dict && shape.weak == base_shape.weak && shape.gc == base_shape.gc;

        Ok(if equivalent { Some(base) } else { None })
    }

    /// Whether two classes with the same `__base__` add the same `__slots__` storage.
    fn adds_same_slots(&self, first: &ObjectRef, second: &ObjectRef) -> PyResult<bool> {
        let (Some(first_layout), Some(second_layout)) = (first.as_class().and_then(|data| data.heap_layout.as_ref()), second.as_class().and_then(|data| data.heap_layout.as_ref())) else {
            return Ok(false);
        };
        let Some(base) = self.class_base(first) else {
            return Ok(false);
        };

        let mut size = self.shape(&base)?.size;
        if first_layout.dict == Some(StorageOffset::Word(size)) && second_layout.dict == Some(StorageOffset::Word(size)) {
            size += 1;
        }
        if first_layout.weak == Some(StorageOffset::Word(size)) && second_layout.weak == Some(StorageOffset::Word(size)) {
            size += 1;
        }

        if let (Some(first_members), Some(second_members)) = (&first_layout.members, &second_layout.members) {
            let same = first_members.len() == second_members.len() && first_members.iter().zip(second_members.iter()).all(|(left, right)| left.as_bytes() == right.as_bytes());
            if !same {
                return Ok(false);
            }
            size += first_members.len();
        }

        Ok(size == first_layout.size && size == second_layout.size)
    }

    /// Checks that instances of `oldto` can become instances of `newto`.
    /// `__class__` assignment passes the new class first, `__bases__`
    /// assignment the old base first; the order shows in the error message.
    pub fn check_layout_compatible(&self, oldto: &ObjectRef, newto: &ObjectRef, attribute: &str) -> PyResult<()> {
        if !self.deallocator(newto).same(&self.deallocator(oldto)) {
            return Err(self.type_error(&format!("{attribute} assignment: '{}' deallocator differs from '{}'", self.class_name(newto), self.class_name(oldto))));
        }

        let mut newbase = Rc::clone(newto);
        while let Some(base) = self.equivalent_to_base(&newbase)? {
            newbase = base;
        }
        let mut oldbase = Rc::clone(oldto);
        while let Some(base) = self.equivalent_to_base(&oldbase)? {
            oldbase = base;
        }

        if Rc::ptr_eq(&newbase, &oldbase) {
            return Ok(());
        }
        let same_base = match (self.class_base(&newbase), self.class_base(&oldbase)) {
            (Some(new_parent), Some(old_parent)) => Rc::ptr_eq(&new_parent, &old_parent),
            (None, None) => true,
            _ => false,
        };
        if same_base && self.adds_same_slots(&newbase, &oldbase)? {
            return Ok(());
        }

        Err(self.type_error(&format!("{attribute} assignment: '{}' object layout differs from '{}'", self.class_name(newto), self.class_name(oldto))))
    }

    /// Assignment to `__class__`.
    pub fn assign_class(&self, object: &ObjectRef, value: Option<Value>) -> PyResult<()> {
        let Some(value) = value else {
            return Err(self.type_error("can't delete __class__ attribute"));
        };
        let Value::Object(newto) = &value else {
            return Err(self.type_error(&format!("__class__ must be set to new-style class, not '{}' object", self.type_name(&value))));
        };
        if !newto.as_class().is_some_and(|data| data.style == ClassStyle::NewStyle) {
            return Err(self.type_error(&format!("__class__ must be set to new-style class, not '{}' object", self.type_name(&value))));
        }

        let oldto = object.class();
        let is_heap = |class: &ObjectRef| class.as_class().is_some_and(|data| data.heap_layout.is_some());
        if !is_heap(newto) || !is_heap(&oldto) {
            return Err(self.type_error("__class__ assignment: only for heap types"));
        }
        self.check_layout_compatible(newto, &oldto, "__class__")?;

        object.set_class(newto);

        Ok(())
    }

    /// Reads the `__slots__` member `name` at `index`.
    pub fn member_get(&self, object: &ObjectRef, index: SlotIndex, name: &PyBytes) -> PyResult<Value> {
        object.slot(index).ok_or_else(|| self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()))
    }

    /// Writes the `__slots__` member `name` at `index`; `None`
    /// deletes.
    pub fn member_set(&self, object: &ObjectRef, index: SlotIndex, name: &PyBytes, value: Option<Value>) -> PyResult<()> {
        let count = object.class().as_class().and_then(|data| data.heap_layout.as_ref()).map_or(0, |layout| layout.slot_count);
        let deleting = value.is_none();
        let previous = object.replace_slot(index, value, count);
        if deleting && previous.is_none() {
            return Err(self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()));
        }

        Ok(())
    }
}

/// ASCII letters, digits, and underscores, not starting
/// with a digit. An empty name fails.
fn is_identifier(name: &[u8]) -> bool {
    let Some((first, rest)) = name.split_first() else {
        return false;
    };

    (first.is_ascii_alphabetic() || *first == b'_') && rest.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
