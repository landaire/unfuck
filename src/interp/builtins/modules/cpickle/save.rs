//! Writing an object graph as pickle opcodes.
//!
//! Saving nests on the native stack, one recursion level per object and
//! one more inside a non-empty list or dict, because the interpreter's
//! recursion limit observes that nesting.
//!
//! A string, tuple, instance, or reduced object is memoized only when it
//! is referenced from somewhere besides the object being saved. The
//! interpreter's reference counts follow the reference interpreter's, so
//! each save receives the number of references this traversal holds beyond
//! those observed there, and subtracts them before deciding.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::Zero;

use super::Stop;
use super::opcodes::Op;
use super::pickler::MemoIndex;
use super::pickler::Pickler;
use super::pickler::Protocol;
use crate::interp::builtins::functions::repr_bytes;
use crate::interp::builtins::modules::codecs::errors::code_points;
use crate::interp::builtins::modules::codecs::unicode::encode_utf8;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const RECURSION_CONTEXT: &str = " while pickling an object";

/// Items per MARK in APPENDS and SETITEMS.
const BATCH_SIZE: usize = 1000;

/// The fast mode nesting of lists, dicts, and instances from which each
/// one is checked against those still open.
const FAST_CYCLE_DEPTH: usize = 50;

pub(super) type SaveResult<T> = Result<T, Stop>;

/// Whether `persistent_id` is asked about a value. The id it returns is
/// saved without asking again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Persistence {
    Ask,
    Skip,
}

/// The iterator a reduction supplies for list items or dict items.
#[derive(Clone, Copy)]
enum ItemsRole {
    List,
    Dict,
}

impl ItemsRole {
    fn ordinal(self) -> &'static str {
        match self {
            Self::List => "Fourth",
            Self::Dict => "Fifth",
        }
    }
}

/// Where the items of a list or dict come from.
enum ItemSource<'a> {
    /// An exact list, read by index as its iterator would.
    List(&'a ObjectRef),
    /// An exact dict at protocol 1 or later, read entry by entry.
    Dict(&'a ObjectRef),
    /// An iterator: list items, or `(key, value)` pairs.
    Iterator(Value),
}

impl Pickler {
    pub(super) fn save(&self, vm: &Vm, value: &Value, surplus: usize) -> SaveResult<()> {
        self.save_with(vm, value, surplus, Persistence::Ask)
    }

    fn save_with(&self, vm: &Vm, value: &Value, surplus: usize, persistence: Persistence) -> SaveResult<()> {
        let outcome = vm.with_depth_in(RECURSION_CONTEXT, || Ok(self.save_object(vm, value, surplus, persistence)))?;

        outcome
    }

    fn save_object(&self, vm: &Vm, value: &Value, surplus: usize, persistence: Persistence) -> SaveResult<()> {
        if let Value::Unknown(unknown) = value {
            return Err(Stop::Unknown { origin: unknown.origin.clone() });
        }

        if persistence == Persistence::Ask {
            let hook = self.persistent_id.borrow().clone();
            if let Some(hook) = hook {
                if self.save_persistent(vm, &hook, value)? {
                    return Ok(());
                }
            }
        }

        let class = vm.type_of(value);
        let types = vm.types();

        // Values that are never memoized.
        if value.is_none() {
            return Ok(self.write(vm, &[Op::None.byte()])?);
        }
        if let Value::Bool(flag) = value {
            return Ok(self.save_bool(vm, *flag)?);
        }
        if Rc::ptr_eq(&class, &types.int) {
            if let Some(Integral::Int(number)) = vm.as_integral(value) {
                return Ok(self.save_int(vm, number)?);
            }
        }
        if Rc::ptr_eq(&class, &types.long) {
            if let Some(number) = vm.as_integral(value) {
                return Ok(self.save_long(vm, &number.to_bigint())?);
            }
        }
        if Rc::ptr_eq(&class, &types.float) {
            if let Some(number) = vm.as_float(value) {
                return Ok(self.save_float(vm, number)?);
            }
        }
        if Rc::ptr_eq(&class, &types.str) {
            if let Some(bytes) = vm.as_str_bytes(value).filter(|bytes| bytes.as_bytes().len() < 2) {
                return Ok(self.write_string(vm, &bytes)?);
            }
        }
        if Rc::ptr_eq(&class, &types.unicode) {
            if let Some(text) = vm.as_text(value).filter(|text| text.units().len() < 2) {
                return Ok(self.write_unicode(vm, text.units())?);
            }
        }
        if Rc::ptr_eq(&class, &types.tuple) && tuple_items(value).is_some_and(<[Value]>::is_empty) {
            return Ok(self.save_empty_tuple(vm)?);
        }

        if let Some(index) = self.memo_lookup(vm, value)? {
            return Ok(self.write_get(vm, index)?);
        }

        if Rc::ptr_eq(&class, &types.str) {
            if let Some(bytes) = vm.as_str_bytes(value) {
                self.write_string(vm, &bytes)?;
                // The clone would count as a reference.
                drop(bytes);
                return self.put(vm, value, surplus);
            }
        }
        if Rc::ptr_eq(&class, &types.unicode) {
            if let Some(text) = vm.as_text(value) {
                self.write_unicode(vm, text.units())?;
                drop(text);
                return self.put(vm, value, surplus);
            }
        }
        if Rc::ptr_eq(&class, &types.tuple) {
            if let Some(items) = tuple_items(value) {
                return self.save_tuple(vm, value, items, surplus);
            }
        }
        if Rc::ptr_eq(&class, &types.list) {
            if let Some(list) = value.as_object().filter(|object| matches!(object.payload, Payload::List(_))) {
                return self.save_list(vm, value, list, surplus);
            }
        }
        if Rc::ptr_eq(&class, &types.dict) {
            if let Some(dict) = value.as_object().filter(|object| object.as_dict().is_some()) {
                return self.save_dict(vm, value, dict, surplus);
            }
        }
        if Rc::ptr_eq(&class, &types.instance) {
            return self.save_instance(vm, value, surplus);
        }
        if Rc::ptr_eq(&class, &types.classobj) || Rc::ptr_eq(&class, &types.type_) || Rc::ptr_eq(&class, &types.builtin_function) {
            return self.save_global(vm, value, None, surplus);
        }
        if Rc::ptr_eq(&class, &types.function) {
            // A function that is not reachable by name falls back to its
            // reduction.
            match self.save_global(vm, value, None, surplus) {
                Err(Stop::Signal(Signal::Raise(error))) if vm.is_subclass(&vm.class_of(&error), &self.state.pickle_error)? => {}
                outcome => return outcome,
            }
        }

        // The id a hook returned is saved without asking either hook.
        let hook = self.inst_persistent_id.borrow().clone().filter(|_| persistence == Persistence::Ask);
        if let Some(hook) = hook {
            if self.save_persistent(vm, &hook, value)? {
                return Ok(());
            }
        }

        self.save_reduced(vm, value, &class, surplus)
    }

    /// Asks `hook` for the persistent id of `value` and writes it when
    /// there is one.
    fn save_persistent(&self, vm: &Vm, hook: &Value, value: &Value) -> SaveResult<bool> {
        let id = self.call_holding(vm, hook, value)?;
        if let Value::Unknown(unknown) = &id {
            return Err(Stop::Unknown { origin: unknown.origin.clone() });
        }
        if id.is_none() {
            return Ok(false);
        }

        if self.is_binary() {
            self.save_with(vm, &id, 0, Persistence::Skip)?;
            self.write(vm, &[Op::BinPersistentId.byte()])?;
            return Ok(true);
        }

        let Some(text) = vm.as_str_bytes(&id) else {
            return Err(self.pickling_error(vm, b"persistent id must be string".to_vec()).into());
        };
        self.write(vm, &[Op::PersistentId.byte()])?;
        self.write(vm, text.as_bytes())?;
        self.write(vm, b"\n")?;

        Ok(true)
    }

    fn save_bool(&self, vm: &Vm, flag: bool) -> PyResult<()> {
        if self.protocol >= Protocol::OBJECTS {
            let op = if flag { Op::NewTrue } else { Op::NewFalse };
            return self.write(vm, &[op.byte()]);
        }

        self.write(vm, if flag { b"I01\n" } else { b"I00\n" })
    }

    fn save_int(&self, vm: &Vm, number: i64) -> PyResult<()> {
        let Some(small) = i32::try_from(number).ok().filter(|_| self.is_binary()) else {
            return self.write(vm, format!("I{number}\n").as_bytes());
        };

        let mut data = Vec::with_capacity(5);
        match u16::try_from(small) {
            Ok(byte @ 0..=0xff) => data.extend_from_slice(&[Op::BinInt1.byte(), byte as u8]),
            Ok(word) => {
                data.push(Op::BinInt2.byte());
                data.extend_from_slice(&word.to_le_bytes());
            }
            Err(_) => {
                data.push(Op::BinInt.byte());
                data.extend_from_slice(&small.to_le_bytes());
            }
        }

        self.write(vm, &data)
    }

    fn save_long(&self, vm: &Vm, number: &BigInt) -> PyResult<()> {
        if self.protocol < Protocol::OBJECTS {
            self.write(vm, &[Op::Long.byte()])?;
            self.write(vm, format!("{number}L").as_bytes())?;
            return self.write(vm, b"\n");
        }

        // Two's complement, little endian, in as few bytes as hold the
        // sign; zero takes none.
        let bytes = if number.is_zero() { Vec::new() } else { number.to_signed_bytes_le() };
        let mut header = Vec::with_capacity(5);
        match u8::try_from(bytes.len()) {
            Ok(length) => header.extend_from_slice(&[Op::Long1.byte(), length]),
            Err(_) => {
                header.push(Op::Long4.byte());
                header.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
        }
        self.write(vm, &header)?;

        self.write(vm, &bytes)
    }

    fn save_float(&self, vm: &Vm, number: f64) -> PyResult<()> {
        if self.is_binary() {
            let mut data = vec![Op::BinFloat.byte()];
            data.extend_from_slice(&number.to_bits().to_be_bytes());
            return self.write(vm, &data);
        }

        self.write(vm, format!("F{}\n", numbers::format_general(number, 17, false, false)).as_bytes())
    }

    fn write_string(&self, vm: &Vm, string: &PyBytes) -> PyResult<()> {
        let bytes = string.as_bytes();
        if !self.is_binary() {
            self.write(vm, &[Op::String.byte()])?;
            self.write(vm, repr_bytes(bytes).as_bytes())?;
            return self.write(vm, b"\n");
        }

        let mut header = Vec::with_capacity(5);
        match u8::try_from(bytes.len()) {
            Ok(length) => header.extend_from_slice(&[Op::ShortBinString.byte(), length]),
            Err(_) => {
                header.push(Op::BinString.byte());
                header.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
        }
        self.write(vm, &header)?;

        self.write_string_data(vm, string)
    }

    fn write_unicode(&self, vm: &Vm, units: &[u16]) -> PyResult<()> {
        if !self.is_binary() {
            self.write(vm, &[Op::Unicode.byte()])?;
            self.write(vm, &escape_unicode(units))?;
            return self.write(vm, b"\n");
        }

        let encoded = encode_utf8(units);
        let mut header = vec![Op::BinUnicode.byte()];
        header.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        self.write(vm, &header)?;

        self.write(vm, &encoded)
    }

    fn save_empty_tuple(&self, vm: &Vm) -> PyResult<()> {
        if self.protocol >= Protocol::BATCHED {
            return self.write(vm, &[Op::EmptyTuple.byte()]);
        }

        self.write(vm, &[Op::Mark.byte(), Op::Tuple.byte()])
    }

    fn save_tuple(&self, vm: &Vm, value: &Value, items: &[Value], surplus: usize) -> SaveResult<()> {
        let sized = match items.len() {
            1 if self.protocol >= Protocol::OBJECTS => Some(Op::Tuple1),
            2 if self.protocol >= Protocol::OBJECTS => Some(Op::Tuple2),
            3 if self.protocol >= Protocol::OBJECTS => Some(Op::Tuple3),
            _ => None,
        };

        if sized.is_none() {
            self.write(vm, &[Op::Mark.byte()])?;
        }
        for item in items {
            self.save(vm, item, 0)?;
        }

        // An item that refers back to this tuple saved it already: drop
        // what is on the stack and read the memoized copy instead.
        if let Some(index) = self.memo_lookup(vm, value)? {
            let pops = match sized {
                Some(_) => vec![Op::Pop.byte(); items.len()],
                None if self.is_binary() => vec![Op::PopMark.byte()],
                None => vec![Op::Pop.byte(); items.len() + 1],
            };
            self.write(vm, &pops)?;
            return Ok(self.write_get(vm, index)?);
        }

        self.write(vm, &[sized.unwrap_or(Op::Tuple).byte()])?;

        self.put(vm, value, surplus)
    }

    fn save_list(&self, vm: &Vm, value: &Value, list: &ObjectRef, surplus: usize) -> SaveResult<()> {
        self.fast_enter(vm, value)?;
        let outcome = self.save_list_body(vm, value, list, surplus);
        self.fast_leave(vm, value);

        outcome
    }

    /// An empty list is memoized only when shared; saving the items of
    /// another references it, so it always is.
    fn save_list_body(&self, vm: &Vm, value: &Value, list: &ObjectRef, surplus: usize) -> SaveResult<()> {
        if self.is_binary() {
            self.write(vm, &[Op::EmptyList.byte()])?;
        } else {
            self.write(vm, &[Op::Mark.byte(), Op::List.byte()])?;
        }

        if list_item(list, 0).is_none() {
            return self.put(vm, value, surplus);
        }
        self.put_always(vm, value)?;

        let outcome = vm.with_depth_in(RECURSION_CONTEXT, || Ok(self.save_items(vm, ItemSource::List(list))))?;

        outcome
    }

    fn save_dict(&self, vm: &Vm, value: &Value, dict: &ObjectRef, surplus: usize) -> SaveResult<()> {
        self.fast_enter(vm, value)?;
        let outcome = self.save_dict_body(vm, value, dict, surplus);
        self.fast_leave(vm, value);

        outcome
    }

    /// Memoized as a list is.
    fn save_dict_body(&self, vm: &Vm, value: &Value, dict: &ObjectRef, surplus: usize) -> SaveResult<()> {
        if self.is_binary() {
            self.write(vm, &[Op::EmptyDict.byte()])?;
        } else {
            self.write(vm, &[Op::Mark.byte(), Op::Dict.byte()])?;
        }

        if vm.dict_len(dict)? == 0 {
            return self.put(vm, value, surplus);
        }
        self.put_always(vm, value)?;

        let source = if self.protocol == Protocol::TEXT {
            ItemSource::Iterator(vm.call_method(value, "iteritems", Vec::new())?)
        } else {
            ItemSource::Dict(dict)
        };
        let outcome = vm.with_depth_in(RECURSION_CONTEXT, || Ok(self.save_dict_items(vm, source)))?;

        outcome
    }

    /// The items of a list, each followed by APPEND at protocol 0 and in
    /// MARK ... APPENDS batches later; a batch of one uses APPEND.
    fn save_items(&self, vm: &Vm, source: ItemSource<'_>) -> SaveResult<()> {
        let mut position = 0;
        let mut next = || -> SaveResult<Option<Value>> {
            match &source {
                ItemSource::List(list) => {
                    let item = list_item(list, position);
                    position += 1;
                    Ok(item)
                }
                ItemSource::Iterator(iterator) => Ok(next_item(vm, iterator)?),
                ItemSource::Dict(_) => Ok(None),
            }
        };

        if self.protocol == Protocol::TEXT {
            while let Some(item) = next()? {
                self.save(vm, &item, 0)?;
                self.write(vm, &[Op::Append.byte()])?;
            }
            return Ok(());
        }

        loop {
            let Some(first) = next()? else {
                return Ok(());
            };
            let Some(second) = next()? else {
                self.save(vm, &first, 0)?;
                self.write(vm, &[Op::Append.byte()])?;
                return Ok(());
            };

            self.write(vm, &[Op::Mark.byte()])?;
            self.save(vm, &first, 0)?;
            drop(first);
            self.save(vm, &second, 0)?;
            drop(second);
            let mut count = 2;
            while count < BATCH_SIZE {
                let Some(item) = next()? else {
                    break;
                };
                self.save(vm, &item, 0)?;
                count += 1;
            }
            self.write(vm, &[Op::Appends.byte()])?;

            if count < BATCH_SIZE {
                return Ok(());
            }
        }
    }

    /// The entries of a dict, each followed by SETITEM at protocol 0. Later
    /// protocols batch them in MARK ... SETITEMS; an exact dict of one
    /// entry, or an iterator batch of one, uses SETITEM.
    fn save_dict_items(&self, vm: &Vm, source: ItemSource<'_>) -> SaveResult<()> {
        match source {
            ItemSource::Dict(dict) => self.save_exact_dict_items(vm, dict),
            ItemSource::Iterator(iterator) => self.save_pair_items(vm, &iterator),
            ItemSource::List(_) => Ok(()),
        }
    }

    /// Entries read in place, which add no references: the key and value
    /// clones are subtracted.
    fn save_exact_dict_items(&self, vm: &Vm, dict: &ObjectRef) -> SaveResult<()> {
        let mut position = 0;
        let mut next = || -> PyResult<Option<(Value, Value)>> {
            let entry = vm.dict_next_entry(dict, position)?;
            Ok(entry.map(|(slot, key, value)| {
                position = slot + 1;
                (key, value)
            }))
        };

        if vm.dict_len(dict)? == 1 {
            if let Some((key, value)) = next()? {
                self.save(vm, &key, 1)?;
                self.save(vm, &value, 1)?;
                self.write(vm, &[Op::SetItem.byte()])?;
            }
            return Ok(());
        }

        loop {
            let Some(first) = next()? else {
                return Ok(());
            };

            self.write(vm, &[Op::Mark.byte()])?;
            let mut entry = Some(first);
            let mut count = 0;
            while let Some((key, value)) = entry.take() {
                self.save(vm, &key, 1)?;
                self.save(vm, &value, 1)?;
                count += 1;
                if count == BATCH_SIZE {
                    break;
                }
                entry = next()?;
            }
            self.write(vm, &[Op::SetItems.byte()])?;

            if count < BATCH_SIZE {
                return Ok(());
            }
        }
    }

    /// Entries from an iterator of `(key, value)` tuples.
    fn save_pair_items(&self, vm: &Vm, iterator: &Value) -> SaveResult<()> {
        let next = || -> SaveResult<Option<Value>> {
            let Some(pair) = next_item(vm, iterator)? else {
                return Ok(None);
            };
            if pair_items(&pair).is_none() {
                return Err(vm.type_error("dict items iterator must return 2-tuples").into());
            }
            Ok(Some(pair))
        };
        let save_pair = |pair: &Value| -> SaveResult<()> {
            let Some([key, value]) = pair_items(pair) else {
                return Err(vm.type_error("dict items iterator must return 2-tuples").into());
            };
            self.save(vm, key, 0)?;
            self.save(vm, value, 0)
        };

        if self.protocol == Protocol::TEXT {
            while let Some(pair) = next()? {
                save_pair(&pair)?;
                self.write(vm, &[Op::SetItem.byte()])?;
            }
            return Ok(());
        }

        loop {
            let Some(first) = next()? else {
                return Ok(());
            };
            let Some(second) = next()? else {
                save_pair(&first)?;
                self.write(vm, &[Op::SetItem.byte()])?;
                return Ok(());
            };

            self.write(vm, &[Op::Mark.byte()])?;
            save_pair(&first)?;
            drop(first);
            save_pair(&second)?;
            drop(second);
            let mut count = 2;
            while count < BATCH_SIZE {
                let Some(pair) = next()? else {
                    break;
                };
                save_pair(&pair)?;
                count += 1;
            }
            self.write(vm, &[Op::SetItems.byte()])?;

            if count < BATCH_SIZE {
                return Ok(());
            }
        }
    }

    /// A classic instance: its class, `__getinitargs__()` items, and the
    /// `__getstate__()` result or `__dict__`.
    fn save_instance(&self, vm: &Vm, value: &Value, surplus: usize) -> SaveResult<()> {
        self.fast_enter(vm, value)?;
        let outcome = self.save_instance_body(vm, value, surplus);
        self.fast_leave(vm, value);

        outcome
    }

    fn save_instance_body(&self, vm: &Vm, value: &Value, surplus: usize) -> SaveResult<()> {
        self.write(vm, &[Op::Mark.byte()])?;

        let class = vm.getattr_str(value, "__class__")?;
        if self.is_binary() {
            self.save(vm, &class, 0)?;
        }

        // A bound `__getinitargs__` references the instance until the
        // instance is memoized.
        let initargs = vm.getattr_opt(value, &PyBytes::from("__getinitargs__"))?;
        if let Some(initargs) = &initargs {
            let arguments = vm.call0(initargs)?;
            let Some(count) = vm.len(&arguments)? else {
                return Err(unknown_stop(&arguments, "cPickle __getinitargs__ result"));
            };
            for index in 0..count {
                let item = vm.getitem(&arguments, &Value::Int(index as i64))?;
                self.save(vm, &item, 0)?;
            }
        }

        if self.is_binary() {
            self.write(vm, &[Op::Obj.byte()])?;
        } else {
            let name = vm.getattr_str(&class, "__name__")?;
            let module = self.which_module(vm, &class, &name)?;
            let module = name_bytes(vm, &module)?;
            let name = name_bytes(vm, &name)?;
            self.write(vm, &[Op::Inst.byte()])?;
            self.write(vm, module.as_bytes())?;
            self.write(vm, b"\n")?;
            self.write(vm, name.as_bytes())?;
            self.write(vm, b"\n")?;
        }

        let getstate = vm.getattr_opt(value, &PyBytes::from("__getstate__"))?;
        if getstate.is_some() {
            self.put_always(vm, value)?;
        } else {
            self.put(vm, value, surplus)?;
        }
        drop(initargs);

        let state = match &getstate {
            Some(getstate) => vm.call0(getstate)?,
            None => vm.getattr_str(value, "__dict__")?,
        };
        self.save(vm, &state, 0)?;

        Ok(self.write(vm, &[Op::Build.byte()])?)
    }

    /// A global by module and name: an extension code at protocol 2 when
    /// `copy_reg` registered one, else GLOBAL.
    fn save_global(&self, vm: &Vm, value: &Value, name: Option<&Value>, surplus: usize) -> SaveResult<()> {
        let name = match name {
            Some(name) => name.clone(),
            None => vm.getattr_str(value, "__name__")?,
        };
        let module = self.which_module(vm, value, &name)?;
        if module.is_unknown() || name.is_unknown() {
            return Err(unknown_stop(if module.is_unknown() { &module } else { &name }, "cPickle global name"));
        }

        let module_text = name_bytes(vm, &module)?;
        let name_text = name_bytes(vm, &name)?;

        let imported = match self.import_module(vm, &module, &module_text) {
            Ok(imported) => imported,
            Err(Signal::Raise(_)) => {
                let message = self.format_message(vm, &[b"Can't pickle ", b": import of module ", b" failed"], &[value, &module])?;
                return Err(self.pickling_error(vm, message).into());
            }
            Err(halt) => return Err(halt.into()),
        };
        let found = match vm.getattr(&imported, &name_text) {
            Ok(found) => found,
            Err(Signal::Raise(_)) => {
                let message = self.format_message(vm, &[b"Can't pickle ", b": attribute lookup ", b".", b" failed"], &[value, &module, &name])?;
                return Err(self.pickling_error(vm, message).into());
            }
            Err(halt) => return Err(halt.into()),
        };
        if let Value::Unknown(unknown) = &found {
            return Err(Stop::Unknown { origin: unknown.origin.clone() });
        }
        if !vm.is_same(&found, value) {
            let message = self.format_message(vm, &[b"Can't pickle ", b": it's not the same object as ", b".", b""], &[value, &module, &name])?;
            return Err(self.pickling_error(vm, message).into());
        }

        if self.protocol >= Protocol::OBJECTS && self.save_extension(vm, value, &module, &name)? {
            return Ok(());
        }

        self.write(vm, &[Op::Global.byte()])?;
        self.write(vm, module_text.as_bytes())?;
        self.write(vm, b"\n")?;
        self.write(vm, name_text.as_bytes())?;
        self.write(vm, b"\n")?;

        self.put(vm, value, surplus)
    }

    /// Writes the extension code `copy_reg` registered for the global, if
    /// any. Extension codes are not memoized.
    fn save_extension(&self, vm: &Vm, value: &Value, module: &Value, name: &Value) -> SaveResult<bool> {
        let key = Value::tuple(vec![module.clone(), name.clone()]);
        let Some(code) = vm.dict_get(&self.state.extension_registry, &key)? else {
            return Ok(false);
        };
        if let Value::Unknown(unknown) = &code {
            return Err(Stop::Unknown { origin: unknown.origin.clone() });
        }

        let Some(code_number) = plain_int(&code) else {
            let message = self.format_message(vm, &[b"Can't pickle ", b": extension code ", b" isn't an integer"], &[value, &code])?;
            return Err(self.pickling_error(vm, message).into());
        };
        let Some(code_number) = u32::try_from(code_number).ok().filter(|code| (1..=0x7fff_ffff).contains(code)) else {
            let mut message = self.format_message(vm, &[b"Can't pickle ", b": extension code "], &[value])?;
            message.extend_from_slice(format!("{code_number} is out of range").as_bytes());
            return Err(self.pickling_error(vm, message).into());
        };

        let mut data = Vec::with_capacity(5);
        if let Ok(byte) = u8::try_from(code_number) {
            data.extend_from_slice(&[Op::Ext1.byte(), byte]);
        } else if let Ok(word) = u16::try_from(code_number) {
            data.push(Op::Ext2.byte());
            data.extend_from_slice(&word.to_le_bytes());
        } else {
            data.push(Op::Ext4.byte());
            data.extend_from_slice(&code_number.to_le_bytes());
        }
        self.write(vm, &data)?;

        Ok(true)
    }

    /// The module of a global: its `__module__`, else the first module in
    /// `sys.modules` holding it under `name`, else `__main__`.
    fn which_module(&self, vm: &Vm, value: &Value, name: &Value) -> SaveResult<Value> {
        if let Some(module) = vm.getattr_opt(value, &PyBytes::from("__module__"))? {
            return Ok(module);
        }

        let Some(name) = vm.as_str_bytes(name) else {
            return Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(name))).into());
        };
        let modules = Rc::clone(vm.modules());
        let mut position = 0;
        while let Some((slot, key, module)) = vm.dict_next_entry(&modules, position)? {
            position = slot + 1;
            if module.is_none() || vm.as_str_bytes(&key).is_some_and(|key| key.as_bytes() == b"__main__") {
                continue;
            }
            match vm.getattr(&module, &name) {
                Ok(found) if vm.is_same(&found, value) => return Ok(key),
                Ok(_) | Err(Signal::Raise(_)) => {}
                Err(halt) => return Err(halt.into()),
            }
        }

        Ok(Value::str("__main__"))
    }

    /// `__import__(name, globals, globals, ['__doc__'], 0)`. A unicode name
    /// does not import.
    fn import_module(&self, vm: &Vm, module: &Value, name: &PyBytes) -> PyResult<Value> {
        if vm.as_text(module).is_some() {
            return Err(vm.raise(ExceptionKind::ImportError, "unicode module name"));
        }

        let globals = vm.current_globals().unwrap_or_else(|| vm.new_dict());
        let fromlist = vm.new_list(vec![Value::str("__doc__")]);

        vm.import_name(name, &globals, Some(&globals), &fromlist, &Value::Int(0))
    }

    /// An object that is not a builtin container, class, or function: its
    /// reduction from `copy_reg.dispatch_table`, `__reduce_ex__`, or
    /// `__reduce__`.
    fn save_reduced(&self, vm: &Vm, value: &Value, class: &ObjectRef, surplus: usize) -> SaveResult<()> {
        let reducer = vm.dict_get(&self.state.dispatch_table, &Value::Object(Rc::clone(class)))?;

        // The reducing callable stays referenced until the object is
        // memoized; a bound method references the object.
        let (reduction, reducer) = match reducer {
            Some(reducer) => (self.call_holding(vm, &reducer, value)?, reducer),
            None if vm.is_subclass(class, &vm.types().type_)? => return self.save_global(vm, value, None, surplus),
            None => match vm.getattr_opt(value, &PyBytes::from("__reduce_ex__"))? {
                Some(method) => (self.call_holding(vm, &method, &Value::Int(i64::from(self.protocol.number())))?, method),
                None => match vm.getattr_opt(value, &PyBytes::from("__reduce__"))? {
                    Some(method) => (vm.call0(&method)?, method),
                    None => return Err(Signal::Raise(vm.instantiate_exception(&self.state.unpickleable_error, vec![value.clone()])?).into()),
                },
            },
        };

        if let Value::Unknown(unknown) = &reduction {
            return Err(Stop::Unknown { origin: unknown.origin.clone() });
        }
        if vm.as_str_bytes(&reduction).is_some() {
            return self.save_global(vm, value, Some(&reduction), surplus);
        }
        let Some(parts) = tuple_items(&reduction) else {
            let message = self.format_message(vm, &[b"Value returned by ", b" must be string or tuple"], &[&reducer])?;
            return Err(self.pickling_error(vm, message).into());
        };
        if !(2..=5).contains(&parts.len()) {
            let message = self.format_message(vm, &[b"tuple returned by ", b" must contain 2 through 5 elements"], &[&reducer])?;
            return Err(self.pickling_error(vm, message).into());
        }

        self.save_reduction(vm, value, parts, &reducer, surplus)
    }

    /// Writes `callable(*args)` with REDUCE, or `cls.__new__(cls, *args)`
    /// with NEWOBJ, then the list items, dict items, and state.
    fn save_reduction(&self, vm: &Vm, value: &Value, parts: &[Value], reducer: &Value, surplus: usize) -> SaveResult<()> {
        let callable = &parts[0];
        let arguments = &parts[1];
        let present = |index: usize| parts.get(index).filter(|part| !part.is_none());
        let state = present(2);
        let list_items = present(3);
        let dict_items = present(4);

        let Some(argument_items) = tuple_items(arguments) else {
            let message = self.format_message(vm, &[b"Second element of tuple returned by ", b" must be a tuple"], &[reducer])?;
            return Err(self.pickling_error(vm, message).into());
        };
        for (items, role) in [(list_items, ItemsRole::List), (dict_items, ItemsRole::Dict)] {
            let Some(items) = items else {
                continue;
            };
            if !vm.has_special(items, "next")? {
                let lead = [role.ordinal().as_bytes(), b" element of tuple returned by "].concat();
                let mut message = self.format_message(vm, &[&lead, b" must be an iterator, not "], &[reducer])?;
                message.extend_from_slice(vm.type_name(items).as_bytes());
                return Err(self.pickling_error(vm, message).into());
            }
        }

        if self.protocol >= Protocol::OBJECTS && is_newobj(vm, callable)? {
            let Some(class) = argument_items.first() else {
                return Err(self.pickling_error(vm, b"__newobj__ arglist is empty".to_vec()).into());
            };
            match vm.getattr_opt(class, &PyBytes::from("__new__")) {
                Ok(Some(_)) => {}
                Ok(None) | Err(Signal::Raise(_)) => return Err(self.pickling_error(vm, b"args[0] from __newobj__ args has no __new__".to_vec()).into()),
                Err(halt) => return Err(halt.into()),
            }
            let actual = vm.getattr_str(value, "__class__")?;
            if !vm.is_same(&actual, class) {
                return Err(self.pickling_error(vm, b"args[0] from __newobj__ args has the wrong class".to_vec()).into());
            }

            self.save(vm, class, 0)?;
            let new_arguments = Value::tuple(argument_items[1..].to_vec());
            self.save(vm, &new_arguments, 0)?;
            drop(new_arguments);
            self.write(vm, &[Op::NewObj.byte()])?;
        } else {
            self.save(vm, callable, 0)?;
            self.save(vm, arguments, 0)?;
            self.write(vm, &[Op::Reduce.byte()])?;
        }

        self.put(vm, value, surplus)?;

        if let Some(items) = list_items {
            self.save_items(vm, ItemSource::Iterator(items.clone()))?;
        }
        if let Some(items) = dict_items {
            self.save_pair_items(vm, items)?;
        }
        if let Some(state) = state {
            self.save(vm, state, 0)?;
            self.write(vm, &[Op::Build.byte()])?;
        }

        Ok(())
    }

    /// The memo index of `value`, if it was memoized.
    fn memo_lookup(&self, vm: &Vm, value: &Value) -> SaveResult<Option<MemoIndex>> {
        let memo = self.memo();
        let Some(entry) = vm.dict_get(&memo, &memo_key(vm, value))? else {
            return Ok(None);
        };
        let Some(fields) = tuple_items(&entry) else {
            return Err(vm.raise(ExceptionKind::SystemError, "..\\Objects\\tupleobject.c:125: bad argument to internal function").into());
        };

        match fields.first().and_then(plain_int) {
            Some(index) => Ok(Some(MemoIndex(index))),
            None => Err(self.pickling_error(vm, b"no int where int expected in memo".to_vec()).into()),
        }
    }

    /// Memoizes `value` unless only the object being saved references it.
    fn put(&self, vm: &Vm, value: &Value, surplus: usize) -> SaveResult<()> {
        let Some(count) = reference_count(value) else {
            return Ok(());
        };
        if count.saturating_sub(surplus) < 2 {
            return Ok(());
        }

        self.put_always(vm, value)
    }

    /// Memoizes `value` under the next index and writes the PUT; fast mode
    /// memoizes nothing.
    fn put_always(&self, vm: &Vm, value: &Value) -> SaveResult<()> {
        if self.fast.get() != 0 {
            return Ok(());
        }

        let memo = self.memo();
        let index = MemoIndex(vm.dict_len(&memo)? as i64 + 1);
        vm.dict_set(&memo, memo_key(vm, value), Value::tuple(vec![Value::Int(index.0), value.clone()]))?;

        Ok(self.write_put(vm, index)?)
    }

    /// Counts a list, dict, or instance being saved in fast mode, and past
    /// `FAST_CYCLE_DEPTH` refuses one that is already open.
    fn fast_enter(&self, vm: &Vm, value: &Value) -> SaveResult<()> {
        if self.fast.get() == 0 {
            return Ok(());
        }

        let nesting = self.fast_nesting.get() + 1;
        self.fast_nesting.set(nesting);
        if nesting < FAST_CYCLE_DEPTH {
            return Ok(());
        }

        let address = vm.value_address(value);
        if self.fast_open.borrow_mut().insert(address) {
            return Ok(());
        }

        // The refused object never opened.
        self.fast_nesting.set(nesting - 1);
        let message = format!("fast mode: can't pickle cyclic objects including object type {} at {}", vm.type_name(value), vm.c_pointer_text(address));
        Err(vm.raise(ExceptionKind::ValueError, &message).into())
    }

    fn fast_leave(&self, vm: &Vm, value: &Value) {
        if self.fast.get() == 0 {
            return;
        }

        let nesting = self.fast_nesting.get();
        if nesting >= FAST_CYCLE_DEPTH {
            self.fast_open.borrow_mut().remove(&vm.value_address(value));
        }
        self.fast_nesting.set(nesting.saturating_sub(1));
    }

    fn pickling_error(&self, vm: &Vm, message: Vec<u8>) -> Signal {
        vm.raise_string(&self.state.pickling_error, Value::Str(PyBytes::new(message)))
    }

    /// `pieces` interleaved with the `str` of each value, as `%s` formats
    /// them.
    fn format_message(&self, vm: &Vm, pieces: &[&[u8]], values: &[&Value]) -> PyResult<Vec<u8>> {
        let mut message = Vec::new();
        for (index, piece) in pieces.iter().enumerate() {
            message.extend_from_slice(piece);
            let Some(value) = values.get(index) else {
                continue;
            };
            let text = vm.to_str(value)?;
            match vm.as_str_bytes(&text) {
                Some(bytes) => message.extend_from_slice(bytes.as_bytes()),
                None => message.extend_from_slice(vm.repr_text(&text)?.as_bytes()),
            }
        }

        Ok(message)
    }
}

/// The items of a `tuple` or tuple subclass instance, borrowed so that the
/// tuple's reference count is unchanged.
fn tuple_items(value: &Value) -> Option<&[Value]> {
    match value {
        Value::Tuple(items) => Some(items),
        Value::Object(object) => match &object.payload {
            Payload::Tuple(items) => Some(items),
            _ => None,
        },
        _ => None,
    }
}

/// The key and value of a `(key, value)` tuple.
fn pair_items(pair: &Value) -> Option<&[Value; 2]> {
    tuple_items(pair).and_then(|items| items.try_into().ok())
}

fn list_item(list: &ObjectRef, index: usize) -> Option<Value> {
    let Payload::List(items) = &list.payload else {
        return None;
    };

    items.borrow().get(index).cloned()
}

fn next_item(vm: &Vm, iterator: &Value) -> PyResult<Option<Value>> {
    vm.next(iterator)
}

/// The value of an `int`, `bool`, or `int` subclass instance; `long`
/// values are not ints.
fn plain_int(value: &Value) -> Option<i64> {
    match value {
        Value::Int(number) => Some(*number),
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Object(object) => match &object.payload {
            Payload::Int(number) => Some(*number),
            _ => None,
        },
        _ => None,
    }
}

/// The reference count of a heap object; `None` for
/// values the interpreter stores inline, which are never memoized.
fn reference_count(value: &Value) -> Option<usize> {
    match value {
        Value::Str(bytes) => Some(bytes.strong_count()),
        Value::Unicode(text) => Some(text.strong_count()),
        Value::Tuple(items) => Some(Rc::strong_count(items.as_rc())),
        Value::Long(number) => Some(Rc::strong_count(number)),
        Value::Object(object) => Some(Rc::strong_count(object)),
        _ => None,
    }
}

/// The memo key of `value`: its `id()`.
fn memo_key(vm: &Vm, value: &Value) -> Value {
    vm.new_int_from_i64(vm.value_address(value) as i64)
}

/// Whether a reduction's callable is named `__newobj__`.
fn is_newobj(vm: &Vm, callable: &Value) -> PyResult<bool> {
    match vm.getattr_str(callable, "__name__") {
        Ok(name) => Ok(vm.as_str_bytes(&name).is_some_and(|name| name.as_bytes() == b"__newobj__")),
        Err(Signal::Raise(_)) => Ok(false),
        Err(halt) => Err(halt),
    }
}

/// The bytes of a module or global name, which must be a string.
fn name_bytes(vm: &Vm, name: &Value) -> PyResult<PyBytes> {
    if let Some(bytes) = vm.as_str_bytes(name) {
        return Ok(bytes);
    }
    if let Some(text) = vm.as_text(name) {
        let encoded = vm.encode_default(&text)?;
        return vm.as_str_bytes(&encoded).ok_or_else(|| vm.type_error("default encoding did not produce a string"));
    }

    Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(name))))
}

fn unknown_stop(value: &Value, context: &str) -> Stop {
    match value {
        Value::Unknown(unknown) => Stop::Unknown { origin: unknown.origin.clone() },
        _ => Stop::Unknown { origin: context.to_owned() },
    }
}

/// Raw-unicode-escape text for UNICODE: Latin-1 characters as bytes,
/// others as `\u` or `\U` escapes, and backslash and newline escaped so
/// that the line stays one line.
fn escape_unicode(units: &[u16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(units.len());

    for code in code_points(units) {
        match code {
            0x5c | 0x0a => output.extend_from_slice(format!("\\u{code:04x}").as_bytes()),
            0..=0xff => output.push(code as u8),
            0x100..=0xffff => output.extend_from_slice(format!("\\u{code:04x}").as_bytes()),
            _ => output.extend_from_slice(format!("\\U{code:08x}").as_bytes()),
        }
    }

    output
}
