use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::modules::first_weak_reference;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::ClassData;
use crate::interp::object::ClassStyle;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::object::SlotIndex;
use crate::interp::type_flags;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Unknown;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Result of searching a class's MRO for a name.
pub enum MroLookup {
    Found { value: Value, owner: ObjectRef },
    /// The search reached a base produced by unemulated native code.
    Unknown(Rc<Unknown>),
    Missing,
}

/// Result of an attribute lookup.
enum Lookup {
    Found(Value),
    /// Carries the `AttributeError` a `__getattribute__` or `__getattr__`
    /// hook raised, which `getattr` raises again.
    Missing(Option<Value>),
}

impl From<Option<Value>> for Lookup {
    fn from(value: Option<Value>) -> Self {
        match value {
            Some(value) => Self::Found(value),
            None => Self::Missing(None),
        }
    }
}

/// Marker payload for descriptors the interpreter implements itself:
/// `__slots__` members, the `__dict__`/`__weakref__`/`__class__` getsets,
/// and the fields of builtin objects.
pub struct SlotDescriptor {
    /// Name of the type that defines the descriptor.
    pub owner: PyBytes,
    pub name: PyBytes,
    pub kind: SlotKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// A `__slots__` member stored in the object's slot array.
    Member(SlotIndex),
    Dict,
    WeakRef,
    Class,
    /// A field of a builtin object, read through `intrinsic_attribute`;
    /// CPython exposes these as getset or member descriptors.
    IntrinsicGetSet,
    IntrinsicMember,
}

impl SlotKind {
    pub fn is_member(self) -> bool {
        matches!(self, Self::Member(_) | Self::IntrinsicMember)
    }
}

impl crate::interp::value::NativeData for SlotDescriptor {
    fn type_name(&self) -> &'static str {
        if self.kind.is_member() { "member_descriptor" } else { "getset_descriptor" }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Vm {
    /// `type(value)`. Unknown values have no type; callers handle them first.
    pub fn type_of(&self, value: &Value) -> ObjectRef {
        let types = self.types();
        let class = match value {
            Value::None => &types.none_type,
            Value::NotImplemented => &types.not_implemented_type,
            Value::Ellipsis => &types.ellipsis_type,
            Value::Bool(_) => &types.bool,
            Value::Int(_) => &types.int,
            Value::Long(_) => &types.long,
            Value::Float(_) => &types.float,
            Value::Str(_) => &types.str,
            Value::Unicode(_) => &types.unicode,
            Value::Tuple(_) => &types.tuple,
            Value::Unknown(_) => &types.object,
            Value::Object(object) => {
                let class = object.class();
                if self.is_classic_class(&class) {
                    return Rc::clone(&types.instance);
                }
                return class;
            }
        };

        Rc::clone(class)
    }

    /// `obj.__class__`: like `type_of` but reports the class of classic
    /// instances.
    pub fn class_of(&self, value: &Value) -> ObjectRef {
        match value {
            Value::Object(object) => object.class(),
            _ => self.type_of(value),
        }
    }

    pub fn type_name(&self, value: &Value) -> String {
        if let Value::Unknown(_) = value {
            return "unknown".to_owned();
        }

        self.class_name(&self.type_of(value))
    }

    /// The type name `repr` and errors show: types of native modules include their module.
    pub fn class_name(&self, class: &ObjectRef) -> String {
        let Some(data) = class.as_class() else {
            return "?".to_owned();
        };

        let name = data.name().to_string_lossy();
        if !self.is_extension_type(class) {
            return match self.static_module(class).filter(|_| data.builtin) {
                Some(module) => format!("{module}.{name}"),
                None => name,
            };
        }

        // A type whose dict lacks `__module__` records its name prefix.
        let module = match self.static_module(class) {
            Some(module) => Some(module.to_owned()),
            None => self.dict_get_str(&data.dict, "__module__").ok().flatten().and_then(|module| self.text_of(&module)),
        };
        match module {
            Some(module) if module != "__builtin__" => format!("{module}.{name}"),
            _ => name,
        }
    }

    /// The type name of `class` in error messages, including the `exceptions.` prefix of the
    /// builtin exception types.
    pub fn qualified_class_name(&self, class: &ObjectRef) -> String {
        let name = self.class_name(class);
        let is_builtin_exception = class.as_class().is_some_and(|data| data.builtin && data.layout == Layout::Exception);
        if is_builtin_exception && !name.contains('.') {
            return format!("exceptions.{name}");
        }

        name
    }

    pub fn is_classic_class(&self, class: &ObjectRef) -> bool {
        class.as_class().is_some_and(|data| data.style == ClassStyle::Classic)
    }

    pub fn is_class(&self, value: &Value) -> bool {
        value.as_object().is_some_and(|object| object.as_class().is_some())
    }

    /// Whether operators use the interpreter's native implementation for
    /// instances of `class` instead of its special methods. Extension types
    /// of native modules dispatch through their methods.
    pub fn is_builtin_type(&self, class: &ObjectRef) -> bool {
        class.as_class().is_some_and(|data| data.builtin) && !self.is_extension_type(class)
    }

    /// Searches the MRO of `class` for `name`. Classic
    /// classes are searched depth first, left to right.
    pub fn lookup_mro(&self, class: &ObjectRef, name: &str) -> PyResult<MroLookup> {
        self.lookup_mro_key(class, &Value::str(name))
    }

    /// `lookup_mro` for an attribute name, probing the class dicts with
    /// the `str` subclass instance it was given as.
    pub fn lookup_name(&self, class: &ObjectRef, name: &PyBytes) -> PyResult<MroLookup> {
        self.lookup_mro_key(class, &name.key())
    }

    fn lookup_mro_key(&self, class: &ObjectRef, key: &Value) -> PyResult<MroLookup> {
        let Some(data) = class.as_class() else {
            return Ok(MroLookup::Missing);
        };

        let order = match data.style {
            ClassStyle::NewStyle => data.mro(),
            ClassStyle::Classic => self.classic_order(class),
        };

        for entry in order {
            match entry {
                MroEntry::Class(candidate) => {
                    let Some(candidate_data) = candidate.as_class() else {
                        continue;
                    };
                    if let Some(value) = self.dict_get(&candidate_data.dict, key)? {
                        return Ok(MroLookup::Found { value, owner: candidate });
                    }
                }
                MroEntry::Unknown(unknown) => return Ok(MroLookup::Unknown(unknown)),
            }
        }

        Ok(MroLookup::Missing)
    }

    /// Depth-first, left-to-right base order of a classic class.
    pub fn classic_order(&self, class: &ObjectRef) -> Vec<MroEntry> {
        let mut order = Vec::new();
        let mut pending = vec![Value::Object(Rc::clone(class))];

        while let Some(next) = pending.pop() {
            match next {
                Value::Object(candidate) => {
                    let Some(data) = candidate.as_class() else {
                        continue;
                    };
                    if data.style == ClassStyle::NewStyle {
                        order.extend(data.mro());
                        continue;
                    }
                    let bases = data.bases();
                    order.push(MroEntry::Class(Rc::clone(&candidate)));
                    pending.extend(bases.into_iter().rev());
                }
                Value::Unknown(unknown) => order.push(MroEntry::Unknown(unknown)),
                _ => {}
            }
        }

        order
    }

    /// The first class in the MRO of `type(value)` defining `name`, when it
    /// is not a builtin type. Operators use builtin behavior directly unless
    /// user code overrides it.
    pub fn user_override(&self, value: &Value, name: &str) -> PyResult<Option<Value>> {
        let Value::Object(object) = value else {
            return Ok(None);
        };

        let class = object.class();
        if self.is_classic_class(&class) {
            return self.classic_special(value, name);
        }

        let found = self.lookup_mro(&class, name)?;
        type_flags::note_slot_lookup(&class, &found);
        match found {
            MroLookup::Found { value: function, owner } => {
                if self.is_builtin_type(&owner) {
                    return Ok(None);
                }
                Ok(Some(self.descriptor_get(&function, Some(value.clone()), &class)?))
            }
            MroLookup::Unknown(unknown) => Ok(Some(Value::Unknown(unknown))),
            MroLookup::Missing => Ok(None),
        }
    }

    /// Special method lookup on a classic instance, which consults the
    /// instance dict as well.
    fn classic_special(&self, value: &Value, name: &str) -> PyResult<Option<Value>> {
        match self.getattr_opt(value, &PyBytes::from(name))? {
            Some(found) => Ok(Some(found)),
            None => Ok(None),
        }
    }

    /// Looks up a special method on the type and binds it, including
    /// builtin implementations.
    pub fn lookup_special(&self, value: &Value, name: &str) -> PyResult<Option<Value>> {
        match value {
            Value::Unknown(unknown) => Ok(Some(Value::Unknown(Rc::clone(unknown)))),
            Value::Object(object) if self.is_classic_class(&object.class()) => self.classic_special(value, name),
            _ => {
                let class = self.type_of(value);
                type_flags::note_special_lookup(&class);
                match self.lookup_mro(&class, name)? {
                    MroLookup::Found { value: function, .. } => Ok(Some(self.descriptor_get(&function, Some(value.clone()), &class)?)),
                    MroLookup::Unknown(unknown) => Ok(Some(Value::Unknown(unknown))),
                    MroLookup::Missing => Ok(None),
                }
            }
        }
    }

    /// Whether the type of `value` fills the slot of the special method
    /// `name`, as an iterator check tests for `next`. A slot test looks
    /// nothing up, so it leaves the method cache alone.
    pub fn has_special(&self, value: &Value, name: &str) -> PyResult<bool> {
        match value {
            Value::Unknown(_) => Ok(true),
            Value::Object(object) if self.is_classic_class(&object.class()) => Ok(self.classic_special(value, name)?.is_some()),
            _ => Ok(!matches!(self.lookup_mro(&self.type_of(value), name)?, MroLookup::Missing)),
        }
    }

    /// `lookup_special` for `with`: raises AttributeError when missing.
    pub fn special_method(&self, value: &Value, name: &str) -> PyResult<Value> {
        match self.lookup_special(value, name)? {
            Some(method) => Ok(method),
            None => Err(self.raise(ExceptionKind::AttributeError, name)),
        }
    }

    /// Applies the descriptor protocol to a value found on a class:
    /// `descr.__get__(instance, owner)`.
    pub fn descriptor_get(&self, descriptor: &Value, instance: Option<Value>, owner: &ObjectRef) -> PyResult<Value> {
        let Value::Object(object) = descriptor else {
            return Ok(descriptor.clone());
        };

        match &object.payload {
            Payload::Function(_) => {
                let class = Some(Value::Object(Rc::clone(owner)));
                match instance {
                    Some(receiver) => Ok(self.bind_function(descriptor, Some(receiver), class)),
                    None => Ok(self.bind_function(descriptor, None, class)),
                }
            }
            Payload::NativeFunction(native) => crate::interp::builtins::descriptors::native_descriptor_get(self, object, native, instance, Some(Value::Object(Rc::clone(owner)))),
            Payload::Method(method) => self.method_descr_get(descriptor, method, instance, Some(Value::Object(Rc::clone(owner)))),
            Payload::StaticMethod(function) => Ok(function.clone()),
            Payload::ClassMethod(function) => {
                let class = match &instance {
                    Some(receiver) => self.class_of(receiver),
                    None => Rc::clone(owner),
                };
                let metaclass = Some(Value::Object(class.class()));
                Ok(self.bind_function(function, Some(Value::Object(class)), metaclass))
            }
            Payload::Property(property) => match instance {
                None => Ok(descriptor.clone()),
                Some(receiver) => {
                    let getter = property.fields().getter;
                    if getter.is_none() {
                        return Err(self.raise(ExceptionKind::AttributeError, "unreadable attribute"));
                    }
                    self.call1(&getter, receiver)
                }
            },
            Payload::Native(native) => {
                if let Some(slot) = native.as_any().downcast_ref::<SlotDescriptor>() {
                    return match instance {
                        None => Ok(descriptor.clone()),
                        Some(receiver) => self.slot_get(descriptor, slot, &receiver),
                    };
                }
                self.user_descriptor_get(descriptor, instance, owner)
            }
            Payload::Instance => self.user_descriptor_get(descriptor, instance, owner),
            _ => Ok(descriptor.clone()),
        }
    }

    fn user_descriptor_get(&self, descriptor: &Value, instance: Option<Value>, owner: &ObjectRef) -> PyResult<Value> {
        let Value::Object(object) = descriptor else {
            return Ok(descriptor.clone());
        };

        let class = object.class();
        if self.is_classic_class(&class) {
            return Ok(descriptor.clone());
        }

        match self.lookup_mro(&class, "__get__")? {
            MroLookup::Found { value: getter, .. } => {
                let getter = self.descriptor_get(&getter, Some(descriptor.clone()), &class)?;
                self.call(&getter, CallArgs::new(vec![instance.unwrap_or(Value::None), Value::Object(Rc::clone(owner))]))
            }
            MroLookup::Unknown(unknown) => Ok(Value::Unknown(unknown)),
            MroLookup::Missing => Ok(descriptor.clone()),
        }
    }

    fn is_data_descriptor(&self, descriptor: &Value) -> PyResult<bool> {
        let Value::Object(object) = descriptor else {
            return Ok(false);
        };

        match &object.payload {
            Payload::Property(_) => Ok(true),
            Payload::Native(native) => {
                if native.as_any().downcast_ref::<SlotDescriptor>().is_some() {
                    return Ok(true);
                }
                self.has_set_or_delete(object)
            }
            Payload::Instance => self.has_set_or_delete(object),
            _ => Ok(false),
        }
    }

    fn has_set_or_delete(&self, object: &ObjectRef) -> PyResult<bool> {
        let class = object.class();
        if self.is_classic_class(&class) {
            return Ok(false);
        }

        for name in ["__set__", "__delete__"] {
            if !matches!(self.lookup_mro(&class, name)?, MroLookup::Missing) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn slot_get(&self, descriptor: &Value, slot: &SlotDescriptor, receiver: &Value) -> PyResult<Value> {
        if slot.kind == SlotKind::Class {
            return Ok(Value::Object(self.class_of(receiver)));
        }

        if let SlotKind::Member(_) = slot.kind
            && let Some(owner) = self.descriptor_owner(descriptor)
            && !receiver.is_unknown()
            && !self.is_subclass(&self.type_of(receiver), &owner)?
        {
            return Err(self.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", slot.name.to_string_lossy(), slot.owner.to_string_lossy(), self.type_name(receiver))));
        }

        let Value::Object(object) = receiver else {
            return Err(self.raise(ExceptionKind::AttributeError, &slot.name.to_string_lossy()));
        };

        match slot.kind {
            SlotKind::Member(index) => self.member_get(object, index, &slot.name),
            SlotKind::Dict => Ok(Value::Object(self.instance_dict(object)?)),
            SlotKind::WeakRef => Ok(first_weak_reference(self, object).map_or(Value::None, Value::Object)),
            SlotKind::Class => Ok(Value::Object(object.class())),
            SlotKind::IntrinsicGetSet | SlotKind::IntrinsicMember => match self.intrinsic_attribute(object, &slot.name.to_string_lossy())? {
                Some(value) => Ok(value),
                // Native code hands out payload-less stand-ins of builtin
                // types, such as the frame of a traceback.
                None if matches!(object.payload, Payload::Instance) && self.class_name(&object.class()) == slot.owner.to_string_lossy() => Ok(Value::unknown(format!("{}.{}", slot.owner.to_string_lossy(), slot.name.to_string_lossy()))),
                None => Err(self.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", slot.name.to_string_lossy(), slot.owner.to_string_lossy(), self.type_name(receiver)))),
            },
        }
    }

    /// The `__dict__` of an object that has one, created on first use.
    pub fn instance_dict(&self, object: &ObjectRef) -> PyResult<ObjectRef> {
        if let Some(dict) = object.dict() {
            return Ok(dict);
        }

        let dict = self.new_dict();
        *object.dict.borrow_mut() = Some(Rc::clone(&dict));

        Ok(dict)
    }

    pub fn getattr_str(&self, target: &Value, name: &str) -> PyResult<Value> {
        self.getattr(target, &PyBytes::from(name))
    }

    /// `getattr(target, name)`.
    pub fn getattr(&self, target: &Value, name: &PyBytes) -> PyResult<Value> {
        match self.lookup_attribute(target, name)? {
            Lookup::Found(value) => Ok(value),
            // An `AttributeError` from `__getattribute__` or `__getattr__`
            // propagates as raised.
            Lookup::Missing(Some(error)) => Err(Signal::Raise(error)),
            Lookup::Missing(None) => {
                let text = name.to_string_lossy();
                let message = match target {
                    Value::Object(object) if object.as_module().is_some() => format!("'module' object has no attribute '{text}'"),
                    Value::Object(object) if object.as_class().is_some_and(|data| data.style == ClassStyle::Classic) => format!("class {} has no attribute '{text}'", self.class_name(object)),
                    Value::Object(object) if object.as_class().is_some() => format!("type object '{}' has no attribute '{text}'", self.class_name(object)),
                    Value::Object(object) if Rc::ptr_eq(&self.type_of(target), &self.types().instance) => format!("{} instance has no attribute '{text}'", self.class_name(&object.class())),
                    // An old-style attribute getter raises the name cut at
                    // its first NUL.
                    Value::Object(object) if self.native_getattr(&object.class()).is_some() => text.split('\0').next().unwrap_or_default().to_owned(),
                    _ => format!("'{}' object has no attribute '{text}'", self.type_name(target)),
                };
                Err(self.raise(ExceptionKind::AttributeError, &message))
            }
        }
    }

    /// `getattr` that reports a missing attribute as `None` instead of
    /// raising AttributeError. Exceptions raised by user code propagate,
    /// except AttributeError from `__getattribute__` and `__getattr__` hooks.
    pub fn getattr_opt(&self, target: &Value, name: &PyBytes) -> PyResult<Option<Value>> {
        Ok(match self.lookup_attribute(target, name)? {
            Lookup::Found(value) => Some(value),
            Lookup::Missing(_) => None,
        })
    }

    /// The attribute `name` of `target`, or why it is missing.
    fn lookup_attribute(&self, target: &Value, name: &PyBytes) -> PyResult<Lookup> {
        let text = name.to_string_lossy();

        let object = match target {
            Value::Unknown(unknown) => return Ok(Lookup::Found(Value::Unknown(Rc::clone(unknown)))),
            Value::Object(object) => Rc::clone(object),
            _ => {
                let class = self.type_of(target);
                type_flags::note_lookup(&class, name);
                if text == "__class__" {
                    return Ok(Lookup::Found(Value::Object(class)));
                }
                return Ok(match self.lookup_name(&class, name)? {
                    MroLookup::Found { value, .. } => Lookup::Found(self.descriptor_get(&value, Some(target.clone()), &class)?),
                    MroLookup::Unknown(unknown) => Lookup::Found(Value::Unknown(unknown)),
                    MroLookup::Missing => Lookup::Missing(None),
                });
            }
        };

        if let Some(getattr) = self.native_getattr(&object.class()) {
            return Ok(getattr(self, target, name)?.into());
        }

        // Generic attribute lookup on objects and types first looks the name
        // up on the type of the object; classic classes and instances do not.
        let object_class = object.class();
        let classic = match &object.payload {
            Payload::Class(data) => data.style == ClassStyle::Classic,
            _ => self.is_classic_class(&object_class),
        };
        if !classic {
            type_flags::note_lookup(&object_class, name);
        }

        if let Some(value) = self.intrinsic_attribute(&object, &text)? {
            return Ok(Lookup::Found(value));
        }

        if let Payload::Class(data) = &object.payload {
            return self.class_getattr(&object, data, name);
        }

        if let Payload::Module(module) = &object.payload {
            let dict = object.dict();
            if let Some(dict) = dict {
                if let Some(value) = self.dict_get(&dict, &name.key())? {
                    return Ok(Lookup::Found(value));
                }
            }
            // Generic attribute lookup falls back to the type, such as the
            // methods of `module` and of its subclasses.
            let class = object.class();
            if let MroLookup::Found { value, .. } = self.lookup_name(&class, name)? {
                return Ok(Lookup::Found(self.descriptor_get(&value, Some(target.clone()), &class)?));
            }
            if module.missing_is_unknown() {
                return Ok(Lookup::Found(Value::unknown(format!("{}.{text}", module.name.to_string_lossy()))));
            }
            return Ok(Lookup::Missing(None));
        }

        let class = object.class();
        if self.is_classic_class(&class) {
            return self.classic_instance_getattr(target, &object, &class, name);
        }

        if let MroLookup::Found { value: hook, owner } = self.lookup_mro(&class, "__getattribute__")? {
            if !self.is_builtin_type(&owner) {
                let hook = self.descriptor_get(&hook, Some(target.clone()), &class)?;
                return match self.call1(&hook, name.key()) {
                    Ok(value) => Ok(Lookup::Found(value)),
                    // `__getattr__` replaces an `AttributeError` from
                    // `__getattribute__`; without one the error propagates.
                    Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::AttributeError) => Ok(match self.getattr_hook(target, &class, name)? {
                        Lookup::Missing(None) => Lookup::Missing(Some(error)),
                        lookup => lookup,
                    }),
                    Err(error) => Err(error),
                };
            }
        }

        match self.generic_getattr(target, &object, &class, name)? {
            Some(value) => Ok(Lookup::Found(value)),
            None => self.getattr_hook(target, &class, name),
        }
    }

    /// `object.__getattribute__`.
    pub fn generic_getattr(&self, target: &Value, object: &ObjectRef, class: &ObjectRef, name: &PyBytes) -> PyResult<Option<Value>> {
        let text = name.to_string_lossy();
        let found = self.lookup_name(class, name)?;

        if let MroLookup::Found { value, .. } = &found {
            if self.is_data_descriptor(value)? {
                return Ok(Some(self.descriptor_get(value, Some(target.clone()), class)?));
            }
        }

        if text == "__dict__" {
            let has_dict = class.as_class().is_some_and(|data| data.instance_dict) || object.dict().is_some();
            if has_dict && class.as_class().is_some_and(|data| data.instance_dict) {
                return Ok(Some(Value::Object(self.instance_dict(object)?)));
            }
        }

        if class.as_class().is_some_and(|data| data.instance_dict) {
            if let Some(dict) = object.dict() {
                if let Some(value) = self.dict_get(&dict, &name.key())? {
                    return Ok(Some(value));
                }
            }
        }

        match found {
            MroLookup::Found { value, .. } => Ok(Some(self.descriptor_get(&value, Some(target.clone()), class)?)),
            MroLookup::Unknown(unknown) => Ok(Some(Value::Unknown(unknown))),
            MroLookup::Missing => Ok(None),
        }
    }

    fn getattr_hook(&self, target: &Value, class: &ObjectRef, name: &PyBytes) -> PyResult<Lookup> {
        let MroLookup::Found { value: hook, owner } = self.lookup_mro(class, "__getattr__")? else {
            return Ok(Lookup::Missing(None));
        };

        if self.is_builtin_type(&owner) {
            return Ok(Lookup::Missing(None));
        }

        let hook = self.descriptor_get(&hook, Some(target.clone()), class)?;
        self.call_getattr_hook(&hook, CallArgs::new(vec![name.key()]))
    }

    /// Calls a `__getattr__` hook; its `AttributeError` reports the
    /// attribute missing.
    fn call_getattr_hook(&self, hook: &Value, args: CallArgs) -> PyResult<Lookup> {
        match self.call(hook, args) {
            Ok(value) => Ok(Lookup::Found(value)),
            Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::AttributeError) => Ok(Lookup::Missing(Some(error))),
            Err(error) => Err(error),
        }
    }

    fn classic_instance_getattr(&self, target: &Value, object: &ObjectRef, class: &ObjectRef, name: &PyBytes) -> PyResult<Lookup> {
        let text = name.to_string_lossy();

        if text == "__dict__" {
            return Ok(Lookup::Found(Value::Object(self.instance_dict(object)?)));
        }
        if text == "__class__" {
            return Ok(Lookup::Found(Value::Object(Rc::clone(class))));
        }

        if let Some(dict) = object.dict() {
            if let Some(value) = self.dict_get(&dict, &name.key())? {
                return Ok(Lookup::Found(value));
            }
        }

        match self.lookup_name(class, name)? {
            MroLookup::Found { value, .. } => return Ok(Lookup::Found(self.descriptor_get(&value, Some(target.clone()), class)?)),
            MroLookup::Unknown(unknown) => return Ok(Lookup::Found(Value::Unknown(unknown))),
            MroLookup::Missing => {}
        }

        if text == "__getattr__" {
            return Ok(Lookup::Missing(None));
        }

        let MroLookup::Found { value: hook, .. } = self.lookup_mro(class, "__getattr__")? else {
            return Ok(Lookup::Missing(None));
        };

        // A classic instance calls the class's `__getattr__` as stored, with
        // the instance and name as arguments, without binding it.
        self.call_getattr_hook(&hook, CallArgs::new(vec![target.clone(), name.key()]))
    }

    /// Attribute lookup on a class object, new-style or classic.
    fn class_getattr(&self, class: &ObjectRef, data: &ClassData, name: &PyBytes) -> PyResult<Lookup> {
        self.ready_type(class);

        let text = name.to_string_lossy();
        let target = Value::Object(Rc::clone(class));

        match text.as_str() {
            "__name__" => return Ok(Lookup::Found(Value::Str(data.name()))),
            "__bases__" => return Ok(Lookup::Found(Value::tuple(data.bases()))),
            "__class__" => return Ok(Lookup::Found(Value::Object(class.class()))),
            "__dict__" => {
                if data.style == ClassStyle::Classic {
                    return Ok(Lookup::Found(Value::Object(Rc::clone(&data.dict))));
                }
                let proxy_class = Rc::clone(&self.types().dictproxy);
                return Ok(Lookup::Found(Value::Object(self.alloc(&proxy_class, Payload::DictProxy(Rc::clone(&data.dict)), None))));
            }
            "__mro__" if data.style == ClassStyle::NewStyle => {
                let items = data
                    .mro()
                    .into_iter()
                    .map(|entry| match entry {
                        MroEntry::Class(class) => Value::Object(class),
                        MroEntry::Unknown(unknown) => Value::Unknown(unknown),
                    })
                    .collect();
                return Ok(Lookup::Found(Value::tuple(items)));
            }
            _ => {}
        }

        if data.style == ClassStyle::Classic {
            return Ok(match self.lookup_name(class, name)? {
                MroLookup::Found { value, .. } => Lookup::Found(self.descriptor_get(&value, None, class)?),
                MroLookup::Unknown(unknown) => Lookup::Found(Value::Unknown(unknown)),
                MroLookup::Missing => Lookup::Missing(None),
            });
        }

        let metaclass = class.class();
        let meta_found = self.lookup_name(&metaclass, name)?;
        if let MroLookup::Found { value, .. } = &meta_found {
            if self.is_data_descriptor(value)? {
                return Ok(Lookup::Found(self.descriptor_get(value, Some(target), &metaclass)?));
            }
        }

        // Attribute lookup on a type reaches the class only when the metatype has no
        // data descriptor; CPython's `type` has one for each of these.
        const TYPE_DATA_DESCRIPTORS: [&str; 8] = ["__abstractmethods__", "__base__", "__basicsize__", "__dictoffset__", "__doc__", "__itemsize__", "__module__", "__weakrefoffset__"];
        if !TYPE_DATA_DESCRIPTORS.contains(&text.as_str()) {
            type_flags::note_lookup(class, name);
        }

        match self.lookup_name(class, name)? {
            MroLookup::Found { value, .. } => return Ok(Lookup::Found(self.descriptor_get(&value, None, class)?)),
            MroLookup::Unknown(unknown) => return Ok(Lookup::Found(Value::Unknown(unknown))),
            MroLookup::Missing => {}
        }

        match meta_found {
            MroLookup::Found { value, .. } => Ok(Lookup::Found(self.descriptor_get(&value, Some(target), &metaclass)?)),
            MroLookup::Unknown(unknown) => Ok(Lookup::Found(Value::Unknown(unknown))),
            MroLookup::Missing => self.getattr_hook(&target, &metaclass, name),
        }
    }

    pub fn setattr_str(&self, target: &Value, name: &str, value: Value) -> PyResult<()> {
        self.setattr(target, &PyBytes::from(name), value)
    }

    /// `setattr`: interns `name`, then stores. Assignments to
    /// unknown values are dropped: the interpreter does not track native
    /// object state.
    pub fn setattr(&self, target: &Value, name: &PyBytes, value: Value) -> PyResult<()> {
        let name = &self.intern(name);
        let Value::Object(object) = target else {
            if target.is_unknown() {
                return Ok(());
            }
            return self.value_setattr(target, name, Some(value));
        };

        if let Some(setattr) = self.native_setattr(&object.class()) {
            return setattr(self, target, name, Some(value));
        }

        let text = name.to_string_lossy();

        if self.set_intrinsic_attribute(object, &text, &value)? {
            return Ok(());
        }

        if let Payload::Class(data) = &object.payload {
            return self.class_setattr(object, data, name, value);
        }

        if object.as_module().is_some() {
            type_flags::note_lookup(&object.class(), name);
            let dict = self.instance_dict(object)?;
            return self.dict_set(&dict, name.key(), value);
        }

        let class = object.class();
        if self.is_classic_class(&class) {
            if let MroLookup::Found { value: hook, .. } = self.lookup_mro(&class, "__setattr__")? {
                let hook = self.descriptor_get(&hook, Some(target.clone()), &class)?;
                self.call(&hook, CallArgs::new(vec![name.key(), value]))?;
                return Ok(());
            }
            if text == "__dict__" {
                let Value::Object(dict) = &value else {
                    return Err(self.type_error("__dict__ must be set to a dictionary"));
                };
                *object.dict.borrow_mut() = Some(Rc::clone(dict));
                return Ok(());
            }
            let dict = self.instance_dict(object)?;
            return self.dict_set(&dict, name.key(), value);
        }

        if self.is_type_unready(&class) {
            return Err(self.unready_setattr_error(&class, &text, "assign to"));
        }

        let found = self.lookup_mro(&class, "__setattr__")?;
        type_flags::note_slot_lookup(&class, &found);
        if let MroLookup::Found { value: hook, owner } = found {
            if !self.is_builtin_type(&owner) {
                let hook = self.descriptor_get(&hook, Some(target.clone()), &class)?;
                self.call(&hook, CallArgs::new(vec![name.key(), value]))?;
                return Ok(());
            }
        }

        self.generic_setattr(object, &class, name, Some(value))
    }

    /// Generic attribute assignment on a value without an instance dict; `None`
    /// deletes.
    fn value_setattr(&self, target: &Value, name: &PyBytes, value: Option<Value>) -> PyResult<()> {
        let class = self.class_of(target);
        let text = name.to_string_lossy();

        type_flags::note_lookup(&class, name);
        match self.lookup_name(&class, name)? {
            MroLookup::Found { value: descriptor, .. } if self.is_data_descriptor(&descriptor)? => self.descriptor_set(&descriptor, target, name, value),
            MroLookup::Found { .. } => Err(self.raise(ExceptionKind::AttributeError, &format!("'{}' object attribute '{text}' is read-only", self.type_name(target)))),
            MroLookup::Unknown(_) => Err(self.halt_unsupported("attribute assignment through an unknown class attribute")),
            MroLookup::Missing => Err(self.raise(ExceptionKind::AttributeError, &format!("'{}' object has no attribute '{text}'", self.type_name(target)))),
        }
    }

    /// `object.__setattr__` / `object.__delattr__`.
    pub fn generic_setattr(&self, object: &ObjectRef, class: &ObjectRef, name: &PyBytes, value: Option<Value>) -> PyResult<()> {
        let text = name.to_string_lossy();
        let target = Value::Object(Rc::clone(object));

        type_flags::note_lookup(class, name);
        let found = match self.lookup_name(class, name)? {
            MroLookup::Found { value: descriptor, .. } if self.is_data_descriptor(&descriptor)? => {
                return self.descriptor_set(&descriptor, &target, name, value);
            }
            MroLookup::Unknown(_) if !class.as_class().is_some_and(|data| data.instance_dict) => return Ok(()),
            MroLookup::Found { .. } => true,
            _ => false,
        };

        if !class.as_class().is_some_and(|data| data.instance_dict) {
            let type_name = self.class_name(class);
            let message = if found { format!("'{type_name}' object attribute '{text}' is read-only") } else { format!("'{type_name}' object has no attribute '{text}'") };
            return Err(self.raise(ExceptionKind::AttributeError, &message));
        }

        if text == "__dict__" {
            if let Some(Value::Object(dict)) = &value {
                *object.dict.borrow_mut() = Some(Rc::clone(dict));
                return Ok(());
            }
        }

        let Some(value) = value else {
            // Generic deletion creates no dict to delete from; a
            // missing key in an existing dict reports only the name.
            let Some(dict) = object.dict() else {
                return Err(self.raise(ExceptionKind::AttributeError, &format!("'{}' object has no attribute '{text}'", self.qualified_class_name(class))));
            };
            if !self.dict_delete(&dict, &name.key())? {
                return Err(self.raise(ExceptionKind::AttributeError, &text));
            }
            return Ok(());
        };

        let dict = self.instance_dict(object)?;
        self.dict_set(&dict, name.key(), value)
    }

    /// Attribute assignment on an instance of a type with no attribute setter,
    /// as a static type is before it is readied. The type's own
    /// `__getattribute__` stands for an attribute getter slot.
    fn unready_setattr_error(&self, class: &ObjectRef, name: &str, action: &str) -> Signal {
        let type_name = self.class_name(class);
        let has_getter = self.native_getattr(class).is_some()
            || class.as_class().is_some_and(|data| matches!(self.dict_get_str(&data.dict, "__getattribute__"), Ok(Some(_))));
        let message = if has_getter {
            format!("'{type_name}' object has only read-only attributes ({action} .{name})")
        } else {
            format!("'{type_name}' object has no attributes ({action} .{name})")
        };

        self.type_error(&message)
    }

    pub(crate) fn descriptor_set(&self, descriptor: &Value, target: &Value, name: &PyBytes, value: Option<Value>) -> PyResult<()> {
        let Value::Object(object) = descriptor else {
            return Ok(());
        };

        match &object.payload {
            Payload::Property(property) => {
                let fields = property.fields();
                let (function, args) = match value {
                    Some(value) => (fields.setter, vec![target.clone(), value]),
                    None => (fields.deleter, vec![target.clone()]),
                };
                if function.is_none() {
                    return Err(self.raise(ExceptionKind::AttributeError, "can't set attribute"));
                }
                self.call(&function, CallArgs::new(args))?;
                Ok(())
            }
            Payload::Native(native) if native.as_any().downcast_ref::<SlotDescriptor>().is_some() => {
                let Value::Object(receiver) = target else {
                    return Err(self.raise(ExceptionKind::AttributeError, &format!("'{}' object attribute '{}' is read-only", self.type_name(target), name.to_string_lossy())));
                };
                let Some(slot) = native.as_any().downcast_ref::<SlotDescriptor>() else {
                    return Ok(());
                };
                match (slot.kind, value) {
                    (SlotKind::Member(index), value) => self.member_set(receiver, index, &slot.name, value),
                    (SlotKind::Dict, Some(Value::Object(dict))) if dict.as_dict().is_some() => {
                        *receiver.dict.borrow_mut() = Some(dict);
                        Ok(())
                    }
                    (SlotKind::Dict, Some(value)) => Err(self.type_error(&format!("__dict__ must be set to a dictionary, not a '{}'", self.type_name(&value)))),
                    (SlotKind::Dict, None) => {
                        let previous = receiver.dict.borrow_mut().take();
                        drop(previous);
                        Ok(())
                    }
                    (SlotKind::Class, value) => self.assign_class(receiver, value),
                    (SlotKind::WeakRef, _) => Err(self.raise(ExceptionKind::AttributeError, &format!("attribute '__weakref__' of '{}' objects is not writable", slot.owner.to_string_lossy()))),
                    (SlotKind::IntrinsicMember, Some(value)) => {
                        // Assignment to a read-only member.
                        if !self.set_intrinsic_attribute(receiver, &name.to_string_lossy(), &value)? {
                            return Err(self.type_error("readonly attribute"));
                        }
                        Ok(())
                    }
                    (SlotKind::IntrinsicGetSet, Some(value)) => {
                        if !self.set_intrinsic_attribute(receiver, &name.to_string_lossy(), &value)? {
                            return Err(self.raise(ExceptionKind::AttributeError, &format!("readonly attribute '{}'", name.to_string_lossy())));
                        }
                        Ok(())
                    }
                    (SlotKind::IntrinsicMember, None) => Err(self.type_error("readonly attribute")),
                    (SlotKind::IntrinsicGetSet, None) => Err(self.raise(ExceptionKind::AttributeError, &format!("can't delete attribute '{}'", name.to_string_lossy()))),
                }
            }
            _ => {
                let class = object.class();
                let method = if value.is_some() { "__set__" } else { "__delete__" };
                let MroLookup::Found { value: function, .. } = self.lookup_mro(&class, method)? else {
                    return Err(self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()));
                };
                let function = self.descriptor_get(&function, Some(descriptor.clone()), &class)?;
                let mut args = vec![target.clone()];
                args.extend(value);
                self.call(&function, CallArgs::new(args))?;
                Ok(())
            }
        }
    }

    fn class_setattr(&self, class: &ObjectRef, data: &ClassData, name: &PyBytes, value: Value) -> PyResult<()> {
        self.ready_type(class);

        let text = name.to_string_lossy();

        // Every assignment on a static type is refused.
        if data.builtin && data.style == ClassStyle::NewStyle {
            return Err(self.type_error(&format!("can't set attributes of built-in/extension type '{}'", self.class_name(class))));
        }
        if data.style == ClassStyle::NewStyle {
            type_flags::note_lookup(&class.class(), name);
        }

        match text.as_str() {
            "__name__" => {
                // Assigning `__name__` keeps the given object, on new-style and classic classes.
                let Some(name) = self.as_str_bytes(&value) else {
                    return Err(self.type_error("__name__ must be a string"));
                };
                *data.name.borrow_mut() = name;
                type_flags::type_modified(class);
                return Ok(());
            }
            "__bases__" => {
                let Value::Tuple(bases) = &value else {
                    return Err(self.type_error("__bases__ must be a tuple"));
                };

                for base in bases.iter() {
                    let Value::Object(base_class) = base else {
                        return Err(self.type_error("__bases__ items must be classes"));
                    };
                    if base_class.as_class().is_none() {
                        return Err(self.type_error("__bases__ items must be classes"));
                    }
                    if self.is_subclass(base_class, class)? {
                        return Err(self.type_error("a __bases__ item causes an inheritance cycle"));
                    }
                }

                if data.style == ClassStyle::NewStyle {
                    // Assigning `__bases__` picks the new solid base with `best_base`.
                    for base in bases.iter() {
                        let Value::Object(base_class) = base else {
                            continue;
                        };
                        if !self.is_classic_class(base_class) && !self.is_base_type(base_class) {
                            return Err(self.type_error(&format!("type '{}' is not an acceptable base type", self.class_name(base_class))));
                        }
                    }
                    let new_base = match self.best_base(bases)? {
                        Some(new_base) => Some(new_base),
                        None if bases.iter().any(Value::is_unknown) => None,
                        None => return Err(self.type_error("a new-style class can't have only classic bases")),
                    };
                    if let (Some(layout), Some(new_base)) = (&data.heap_layout, &new_base) {
                        let old_base = Rc::clone(&layout.base.borrow());
                        self.check_layout_compatible(&old_base, new_base, "__bases__")?;
                    }
                    let mro = self.compute_mro(class, bases)?;
                    replace_subclass_links(class, &data.bases(), bases);
                    *data.bases.borrow_mut() = bases.to_vec();
                    *data.mro.borrow_mut() = mro;
                    if let (Some(layout), Some(new_base)) = (&data.heap_layout, new_base) {
                        let previous = layout.base.replace(new_base);
                        drop(previous);
                    }
                    type_flags::mro_modified(class);
                    type_flags::type_modified(class);
                } else {
                    *data.bases.borrow_mut() = bases.to_vec();
                }
                return Ok(());
            }
            _ => {}
        }

        if data.style == ClassStyle::NewStyle {
            let metaclass = class.class();
            if let MroLookup::Found { value: hook, owner } = self.lookup_mro(&metaclass, "__setattr__")? {
                if !self.is_builtin_type(&owner) {
                    let hook = self.descriptor_get(&hook, Some(Value::Object(Rc::clone(class))), &metaclass)?;
                    self.call(&hook, CallArgs::new(vec![name.key(), value]))?;
                    return Ok(());
                }
            }
            if let MroLookup::Found { value: descriptor, .. } = self.lookup_name(&metaclass, name)? {
                if self.is_data_descriptor(&descriptor)? {
                    self.descriptor_set(&descriptor, &Value::Object(Rc::clone(class)), name, Some(value))?;
                    type_flags::type_modified(class);
                    return Ok(());
                }
            }
        }

        self.dict_set(&data.dict, name.key(), value)?;
        type_flags::type_modified(class);

        Ok(())
    }

    /// `delattr`: interns `name`, then deletes.
    pub fn delattr(&self, target: &Value, name: &PyBytes) -> PyResult<()> {
        let name = &self.intern(name);
        let Value::Object(object) = target else {
            if target.is_unknown() {
                return Ok(());
            }
            return self.value_setattr(target, name, None);
        };

        if let Some(setattr) = self.native_setattr(&object.class()) {
            return setattr(self, target, name, None);
        }

        let key = name.key();

        if let Payload::Class(data) = &object.payload {
            self.ready_type(object);
            if data.style == ClassStyle::NewStyle {
                let metaclass = object.class();
                type_flags::note_lookup(&metaclass, name);
                if let MroLookup::Found { value: descriptor, .. } = self.lookup_name(&metaclass, name)?
                    && self.is_data_descriptor(&descriptor)?
                {
                    self.descriptor_set(&descriptor, target, name, None)?;
                    type_flags::type_modified(object);
                    return Ok(());
                }
            }
            if !self.dict_delete(&data.dict, &key)? {
                return Err(self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()));
            }
            type_flags::type_modified(object);
            return Ok(());
        }

        if object.as_module().is_some() {
            type_flags::note_lookup(&object.class(), name);
            // `ModuleType.__new__` creates no dict until a store.
            let Some(dict) = object.dict() else {
                return Err(self.raise(ExceptionKind::AttributeError, &format!("'{}' object has no attribute '{}'", self.class_name(&object.class()), name.to_string_lossy())));
            };
            if !self.dict_delete(&dict, &key)? {
                return Err(self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()));
            }
            return Ok(());
        }

        let class = object.class();
        if !self.is_classic_class(&class) {
            if self.is_type_unready(&class) {
                return Err(self.unready_setattr_error(&class, &name.to_string_lossy(), "del"));
            }
            let found = self.lookup_mro(&class, "__delattr__")?;
            type_flags::note_slot_lookup(&class, &found);
            if let MroLookup::Found { value: hook, owner } = found {
                if !self.is_builtin_type(&owner) {
                    let hook = self.descriptor_get(&hook, Some(target.clone()), &class)?;
                    self.call1(&hook, key)?;
                    return Ok(());
                }
            }
            return self.generic_setattr(object, &class, name, None);
        }

        if let MroLookup::Found { value: hook, .. } = self.lookup_mro(&class, "__delattr__")? {
            let hook = self.descriptor_get(&hook, Some(target.clone()), &class)?;
            self.call1(&hook, key)?;
            return Ok(());
        }

        let dict = self.instance_dict(object)?;
        if !self.dict_delete(&dict, &key)? {
            return Err(self.raise(ExceptionKind::AttributeError, &name.to_string_lossy()));
        }

        Ok(())
    }

    /// C3 linearization. Classic bases contribute their
    /// depth-first order.
    pub fn compute_mro(&self, class: &ObjectRef, bases: &[Value]) -> PyResult<Vec<MroEntry>> {
        let mut sequences: Vec<Vec<MroEntry>> = Vec::new();

        for base in bases {
            match base {
                Value::Object(base_class) => {
                    let Some(data) = base_class.as_class() else {
                        return Err(self.type_error("bases must be types"));
                    };
                    let order = match data.style {
                        ClassStyle::NewStyle => data.mro(),
                        ClassStyle::Classic => self.classic_order(base_class),
                    };
                    sequences.push(order);
                }
                Value::Unknown(unknown) => sequences.push(vec![MroEntry::Unknown(Rc::clone(unknown))]),
                _ => return Err(self.type_error("bases must be types")),
            }
        }

        sequences.push(
            bases
                .iter()
                .filter_map(|base| match base {
                    Value::Object(object) => Some(MroEntry::Class(Rc::clone(object))),
                    Value::Unknown(unknown) => Some(MroEntry::Unknown(Rc::clone(unknown))),
                    _ => None,
                })
                .collect(),
        );

        let mut result = vec![MroEntry::Class(Rc::clone(class))];

        loop {
            sequences.retain(|sequence| !sequence.is_empty());
            if sequences.is_empty() {
                return Ok(result);
            }

            let candidate = sequences.iter().map(|sequence| &sequence[0]).find(|head| !sequences.iter().any(|sequence| sequence[1..].iter().any(|entry| mro_entry_eq(entry, head)))).cloned();

            let Some(candidate) = candidate else {
                return Err(self.type_error("Cannot create a consistent method resolution order (MRO)"));
            };

            for sequence in &mut sequences {
                if mro_entry_eq(&sequence[0], &candidate) {
                    sequence.remove(0);
                }
            }
            result.push(candidate);
        }
    }

    /// `BUILD_CLASS`: picks the metaclass and calls it.
    pub fn build_class(&self, name: &Value, bases: &Value, namespace: &Value, globals: &ObjectRef) -> PyResult<Value> {
        let Value::Object(namespace_dict) = namespace else {
            return Err(self.type_error("class namespace must be a dict"));
        };

        let base_list = match bases {
            Value::Tuple(items) => items.to_vec(),
            _ => return Err(self.type_error("class bases must be a tuple")),
        };

        let explicit = self.dict_get_str(namespace_dict, "__metaclass__")?;
        let metaclass = match explicit {
            Some(metaclass) => metaclass,
            None => match base_list.first() {
                // A base produced by native code: assume its metaclass is
                // `type`, as for the client's native extension types.
                Some(Value::Unknown(_)) => Value::Object(Rc::clone(&self.types().type_)),
                Some(base) => self.getattr_str(base, "__class__")?,
                None => match self.dict_get_str(globals, "__metaclass__")? {
                    Some(metaclass) => metaclass,
                    None => Value::Object(Rc::clone(&self.types().classobj)),
                },
            },
        };

        match self.call(&metaclass, CallArgs::new(vec![name.clone(), bases.clone(), namespace.clone()])) {
            // `build_class` prefixes a TypeError whose value is still the
            // string native code raised it with.
            Err(Signal::Raise(exception)) if self.is_exception(&exception, ExceptionKind::TypeError) => {
                let Some(message) = self.unnormalized_message(&exception) else {
                    return Err(Signal::Raise(exception));
                };
                let mut prefixed = b"Error when calling the metaclass bases\n    ".to_vec();
                prefixed.extend_from_slice(message.as_bytes());
                Err(self.raise_string(&self.class_of(&exception), Value::Str(PyBytes::new(prefixed))))
            }
            result => result,
        }
    }

    /// `classobj(name, bases, dict)`.
    pub fn new_classic_class(&self, name: &Value, bases: Vec<Value>, dict: ObjectRef) -> PyResult<Value> {
        let Some(name_object) = self.as_str_bytes(name) else {
            return Err(self.type_error("PyClass_New: name must be a string"));
        };

        if self.dict_get_str(&dict, "__doc__")?.is_none() {
            self.dict_set_str(&dict, "__doc__", Value::None)?;
        }
        if self.dict_get_str(&dict, "__module__")?.is_none() {
            if let Some(module) = self.current_module_name()? {
                self.dict_set_str(&dict, "__module__", module)?;
            }
        }

        for base in &bases {
            let classic = match base {
                Value::Unknown(_) => true,
                Value::Object(object) => self.is_classic_class(object),
                _ => false,
            };
            if !classic {
                // A classic class statement hands a class with a new-style base to the
                // type of that base. Every type is callable.
                let metatype = Value::Object(self.type_of(base));
                return self.call(&metatype, CallArgs::new(vec![name.clone(), Value::tuple(bases.clone()), Value::Object(dict)]));
            }
        }

        let data = ClassData {
            name: RefCell::new(name_object),
            bases: RefCell::new(bases),
            mro: RefCell::new(Vec::new()),
            dict,
            style: ClassStyle::Classic,
            layout: Layout::Object,
            instance_dict: true,
            builtin: false,
            subclasses: RefCell::new(Vec::new()),
            flags: None,
            heap_layout: None,
        };

        let classobj = Rc::clone(&self.types().classobj);

        Ok(Value::Object(self.alloc(&classobj, Payload::Class(data), None)))
    }

    /// `type.__new__(metatype, name, bases, dict)`.
    pub fn type_new(&self, metatype: &ObjectRef, name: &Value, bases: &Value, namespace: &Value) -> PyResult<Value> {
        let Some(name_object) = self.as_str_bytes(name) else {
            return Err(self.type_error("type() argument 1 must be string"));
        };
        let name_bytes = name_object.as_bytes();
        let Value::Tuple(bases) = bases else {
            return Err(self.type_error("type() argument 2 must be tuple"));
        };
        let Value::Object(namespace) = namespace else {
            return Err(self.type_error("type() argument 3 must be dict"));
        };
        if namespace.as_dict().is_none() {
            return Err(self.type_error("type() argument 3 must be dict"));
        }

        let mut winner = Rc::clone(metatype);
        for base in bases.iter() {
            let Value::Object(base) = base else {
                continue;
            };
            let base_meta = base.class();
            if Rc::ptr_eq(&base_meta, &self.types().classobj) {
                continue;
            }
            if self.is_subclass(&winner, &base_meta)? {
                continue;
            }
            if self.is_subclass(&base_meta, &winner)? {
                winner = base_meta;
                continue;
            }
            return Err(self.type_error("metaclass conflict: the metaclass of a derived class must be a (non-strict) subclass of the metaclasses of all its bases"));
        }

        if !Rc::ptr_eq(&winner, metatype) {
            if let MroLookup::Found { value: new, owner } = self.lookup_mro(&winner, "__new__")? {
                if !Rc::ptr_eq(&owner, &self.types().type_) {
                    let new = self.descriptor_get(&new, None, &winner)?;
                    return self.call(&new, CallArgs::new(vec![Value::Object(winner), name.clone(), Value::Tuple(bases.clone()), Value::Object(Rc::clone(namespace))]));
                }
            }
        }

        let bases: Vec<Value> = if bases.is_empty() { vec![Value::Object(Rc::clone(&self.types().object))] } else { bases.to_vec() };

        let has_unknown_base = bases.iter().any(Value::is_unknown);
        let best_base = match self.best_base(&bases)? {
            Some(best_base) => best_base,
            None if has_unknown_base => Rc::clone(&self.types().object),
            None => return Err(self.type_error("a new-style class can't have only classic bases")),
        };
        let layout = best_base.as_class().map_or(Layout::Object, |data| data.layout);

        let dict = self.dict_copy(namespace)?;

        if self.dict_get_str(&dict, "__module__")?.is_none() {
            if let Some(module) = self.current_module_name()? {
                self.dict_set_str(&dict, "__module__", module)?;
            }
        }

        if let Some(new) = self.dict_get_str(&dict, "__new__")? {
            if new.as_object().is_some_and(|object| matches!(object.payload, Payload::Function(_))) {
                let wrapped = self.new_staticmethod(new);
                self.dict_set_str(&dict, "__new__", wrapped)?;
            }
        }

        let slots = self.dict_get_str(&dict, "__slots__")?;
        let storage = self.slot_storage(name_bytes, slots.as_ref(), &best_base, &bases)?;
        let heap_layout = self.heap_layout(&best_base, &storage)?;
        let members = storage.members.as_deref().unwrap_or_default();

        // Slot and getset descriptors do not replace a class variable of the same
        // name.
        let mut slot_descriptors: Vec<Value> = Vec::new();
        for (position, member) in members.iter().enumerate() {
            // Each slot name is interned as a copy.
            let member = self.intern(&PyBytes::new(member.as_bytes().to_vec()));
            if self.dict_get(&dict, &Value::Str(member.clone()))?.is_some() {
                continue;
            }
            let index = Self::member_index(&heap_layout, position);
            let descriptor = self.new_slot_descriptor(name_bytes, member.clone(), SlotKind::Member(index));
            self.dict_set(&dict, Value::Str(member), descriptor.clone())?;
            slot_descriptors.push(descriptor);
        }
        if storage.add_dict && self.dict_get_str(&dict, "__dict__")?.is_none() {
            let descriptor = self.new_slot_descriptor(name_bytes, PyBytes::from("__dict__"), SlotKind::Dict);
            self.dict_set_str(&dict, "__dict__", descriptor.clone())?;
            slot_descriptors.push(descriptor);
        }
        if storage.add_weak && self.dict_get_str(&dict, "__weakref__")?.is_none() {
            let descriptor = self.new_slot_descriptor(name_bytes, PyBytes::from("__weakref__"), SlotKind::WeakRef);
            self.dict_set_str(&dict, "__weakref__", descriptor.clone())?;
            slot_descriptors.push(descriptor);
        }
        if self.dict_get_str(&dict, "__doc__")?.is_none() {
            self.dict_set_str(&dict, "__doc__", Value::None)?;
        }

        // A base produced by native code may store anything, so its
        // subclasses keep a dict.
        let instance_dict = heap_layout.dict.is_some() || has_unknown_base;
        let flags = type_flags::heap_type_flags(&best_base, &bases, storage.add_dict || storage.add_weak || !members.is_empty());

        let data = ClassData {
            name: RefCell::new(name_object.clone()),
            bases: RefCell::new(bases.clone()),
            mro: RefCell::new(Vec::new()),
            dict,
            style: ClassStyle::NewStyle,
            layout,
            instance_dict,
            builtin: false,
            subclasses: RefCell::new(Vec::new()),
            flags,
            heap_layout: Some(heap_layout),
        };

        let class = self.alloc(metatype, Payload::Class(data), None);
        for descriptor in &slot_descriptors {
            self.set_descriptor_owner(descriptor, &class);
        }
        let mro = self.compute_mro(&class, &bases)?;
        if let Some(data) = class.as_class() {
            *data.mro.borrow_mut() = mro;
        }
        for base in &bases {
            if let Some(base_data) = base.as_object().and_then(|object| object.as_class()) {
                base_data.subclasses.borrow_mut().push(Rc::downgrade(&class));
            }
        }
        type_flags::mro_modified(&class);

        // Class creation looks up every slot name on the class.
        type_flags::note_special_lookup(&class);

        Ok(Value::Object(class))
    }

    pub(crate) fn new_slot_descriptor(&self, owner: &[u8], name: PyBytes, kind: SlotKind) -> Value {
        let class = if kind.is_member() { Rc::clone(&self.types().member_descriptor) } else { Rc::clone(&self.types().getset_descriptor) };
        let payload = Payload::Native(Box::new(SlotDescriptor { owner: PyBytes::new(owner.to_vec()), name, kind }));

        Value::Object(self.alloc(&class, payload, None))
    }

    pub fn new_staticmethod(&self, function: Value) -> Value {
        let class = Rc::clone(&self.types().staticmethod);

        Value::Object(self.alloc(&class, Payload::StaticMethod(function), None))
    }

    /// Text of a `str` or `unicode` value as a Rust string.
    pub fn text_of(&self, value: &Value) -> Option<String> {
        match value {
            Value::Unicode(text) => Some(text.to_string_lossy()),
            Value::Object(object) => match &object.payload {
                Payload::Unicode(text) => Some(text.to_string_lossy()),
                Payload::Str(bytes) => Some(bytes.to_string_lossy()),
                _ => None,
            },
            _ => value.as_bytes().map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
        }
    }

    /// `issubclass(class, base)` for class objects, without hooks.
    pub fn is_subclass(&self, class: &ObjectRef, base: &ObjectRef) -> PyResult<bool> {
        if Rc::ptr_eq(class, base) {
            return Ok(true);
        }

        let Some(data) = class.as_class() else {
            return Ok(false);
        };

        let order = match data.style {
            ClassStyle::NewStyle => data.mro(),
            ClassStyle::Classic => self.classic_order(class),
        };

        for entry in order {
            match entry {
                MroEntry::Class(candidate) if Rc::ptr_eq(&candidate, base) => return Ok(true),
                MroEntry::Class(_) => {}
                MroEntry::Unknown(unknown) => {
                    return Err(Signal::Halt(Halt::UnknownCondition { context: format!("issubclass({}, {})", self.class_name(class), self.class_name(base)), origin: unknown.origin.clone() }));
                }
            }
        }

        Ok(false)
    }

    /// `isinstance(value, class)` for a single class, without hooks.
    pub fn is_instance_of(&self, value: &Value, class: &ObjectRef) -> PyResult<bool> {
        if let Value::Unknown(unknown) = value {
            return Err(Signal::Halt(Halt::UnknownCondition { context: format!("isinstance(..., {})", self.class_name(class)), origin: unknown.origin.clone() }));
        }

        let own = self.class_of(value);
        if self.is_subclass(&own, class)? {
            return Ok(true);
        }

        let actual = self.type_of(value);

        Ok(!Rc::ptr_eq(&actual, &own) && self.is_subclass(&actual, class)?)
    }

    /// `isinstance(value, class_or_tuple)` with `__instancecheck__`.
    /// A tuple, and the metatype's checker, which
    /// is called as a Python call, each take a recursion level.
    pub fn isinstance(&self, value: &Value, class_or_tuple: &Value) -> PyResult<bool> {
        const CONTEXT: &str = " in __instancecheck__";

        match class_or_tuple {
            Value::Tuple(items) => self.with_depth_in(CONTEXT, || {
                for item in items.iter() {
                    if self.isinstance(value, item)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            Value::Object(class) if class.as_class().is_some() => {
                if self.is_classic_class(class) {
                    return self.is_instance_of(value, class);
                }
                if !value.is_unknown() && Rc::ptr_eq(&self.type_of(value), class) {
                    return Ok(true);
                }

                self.with_depth_in(CONTEXT, || {
                    if let Some(check) = self.user_override(&Value::Object(Rc::clone(class)), "__instancecheck__")? {
                        if !self.is_instance_of(value, class).unwrap_or(false) {
                            let result = self.call1(&check, value.clone())?;
                            return self.truthy(&result, "__instancecheck__");
                        }
                        return Ok(true);
                    }
                    self.with_depth_in(" while calling a Python object", || self.is_instance_of(value, class))
                })
            }
            Value::Unknown(unknown) => Err(Signal::Halt(Halt::UnknownCondition { context: "isinstance".to_owned(), origin: unknown.origin.clone() })),
            _ => Err(self.type_error("isinstance() arg 2 must be a class, type, or tuple of classes and types")),
        }
    }

    /// `issubclass(class, class_or_tuple)` with `__subclasscheck__`,
    /// taking recursion levels as `isinstance`
    /// does.
    pub fn issubclass(&self, class: &Value, class_or_tuple: &Value) -> PyResult<bool> {
        const CONTEXT: &str = " in __subclasscheck__";

        let Value::Object(class_object) = class else {
            if let Value::Unknown(unknown) = class {
                return Err(Signal::Halt(Halt::UnknownCondition { context: "issubclass".to_owned(), origin: unknown.origin.clone() }));
            }
            return Err(self.type_error("issubclass() arg 1 must be a class"));
        };

        match class_or_tuple {
            Value::Tuple(items) => self.with_depth_in(CONTEXT, || {
                for item in items.iter() {
                    if self.issubclass(class, item)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            Value::Object(base) if base.as_class().is_some() => {
                if self.is_classic_class(base) {
                    return self.is_subclass(class_object, base);
                }

                self.with_depth_in(CONTEXT, || {
                    if let Some(check) = self.user_override(class_or_tuple, "__subclasscheck__")? {
                        let result = self.call1(&check, class.clone())?;
                        return self.truthy(&result, "__subclasscheck__");
                    }
                    self.with_depth_in(" while calling a Python object", || self.is_subclass(class_object, base))
                })
            }
            Value::Unknown(unknown) => Err(Signal::Halt(Halt::UnknownCondition { context: "issubclass".to_owned(), origin: unknown.origin.clone() })),
            _ => Err(self.type_error("issubclass() arg 2 must be a class or tuple of classes")),
        }
    }

    /// `__name__` of the module whose code is running, for `__module__`.
    pub fn current_module_name(&self) -> PyResult<Option<Value>> {
        let Some(globals) = self.current_globals() else {
            return Ok(None);
        };

        self.dict_get_str(&globals, "__name__")
    }
}

fn mro_entry_eq(left: &MroEntry, right: &MroEntry) -> bool {
    match (left, right) {
        (MroEntry::Class(left), MroEntry::Class(right)) => Rc::ptr_eq(left, right),
        (MroEntry::Unknown(left), MroEntry::Unknown(right)) => Rc::ptr_eq(left, right),
        _ => false,
    }
}

/// Assigning `__bases__` moves `class` from the subclass lists of its old bases
/// to those of its new ones.
fn replace_subclass_links(class: &ObjectRef, old_bases: &[Value], new_bases: &[Value]) {
    for base in old_bases {
        if let Some(base_data) = base.as_object().and_then(|object| object.as_class()) {
            base_data.subclasses.borrow_mut().retain(|subclass| !std::ptr::eq(subclass.as_ptr(), Rc::as_ptr(class)));
        }
    }
    for base in new_bases {
        if let Some(base_data) = base.as_object().and_then(|object| object.as_class()) {
            base_data.subclasses.borrow_mut().push(Rc::downgrade(class));
        }
    }
}
