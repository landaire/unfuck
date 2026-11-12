//! Reading a pickle: an opcode loop over a value stack and a stack of
//! MARK positions.

use std::rc::Rc;

use num_bigint::BigInt;

use super::HIGHEST_PROTOCOL;
use super::Stop;
use super::opcodes::Op;
use super::unpickler::Unpickler;
use crate::interp::builtins::functions::repr_bytes;
use crate::interp::builtins::modules::codecs::errors::Errors;
use crate::interp::builtins::modules::codecs::unicode::decode_raw_unicode_escape;
use crate::interp::builtins::modules::codecs::unicode::decode_string_escape;
use crate::interp::builtins::modules::codecs::unicode::decode_utf8;
use crate::interp::builtins::modules::has_null_new;
use crate::interp::attr::MroLookup;
use crate::interp::builtins::numeric::parse;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::object::CallArgs;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub(super) type LoadResult<T> = Result<T, Stop>;

/// Whether a load builds objects (`load`) or only walks the opcodes
/// (`noload`), which leaves `None` where a global or a constructed object
/// would be.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Build,
    Skim,
}

/// The stacks of one load.
struct Machine<'a> {
    vm: &'a Vm,
    unpickler: &'a Unpickler,
    mode: Mode,
    stack: Vec<Value>,
    marks: Vec<usize>,
}

impl Unpickler {
    pub(super) fn load(&self, vm: &Vm, mode: Mode) -> LoadResult<Value> {
        let mut machine = Machine { vm, unpickler: self, mode, stack: Vec::new(), marks: Vec::new() };

        machine.run()
    }
}

impl Machine<'_> {
    fn run(&mut self) -> LoadResult<Value> {
        loop {
            let byte = self.read_byte()?;
            // A NUL byte ends the input of `load`, but not of `noload`.
            if byte == 0 && self.mode == Mode::Build {
                return Err(super::unpickler::eof_error(self.vm).into());
            }
            let Some(op) = Op::from_byte(byte) else {
                let mut message = b"invalid load key, '".to_vec();
                message.push(byte);
                message.extend_from_slice(b"'.");
                return Err(self.unpickling_error(message));
            };
            if op == Op::Stop {
                return self.stack.pop().ok_or_else(|| self.unpickling_error(b"bad pickle data".to_vec()));
            }

            self.step(op)?;
        }
    }

    fn step(&mut self, op: Op) -> LoadResult<()> {
        let skim = self.mode == Mode::Skim;

        match op {
            Op::Mark => self.marks.push(self.stack.len()),
            Op::Stop => {}
            Op::Pop => self.pop_one()?,
            Op::PopMark => {
                let start = self.pop_mark()?;
                self.stack.truncate(start);
            }
            Op::Dup => {
                let top = self.top()?.clone();
                self.stack.push(top);
            }
            Op::None => self.stack.push(Value::None),
            Op::NewTrue => self.stack.push(Value::Bool(true)),
            Op::NewFalse => self.stack.push(Value::Bool(false)),
            Op::Int => {
                let line = self.read_line_checked(2)?;
                let value = self.parse_int(&line)?;
                self.stack.push(value);
            }
            Op::BinInt => {
                let bytes = self.read_array::<4>()?;
                self.stack.push(Value::Int(i64::from(i32::from_le_bytes(bytes))));
            }
            Op::BinInt1 => {
                let byte = self.read_byte()?;
                self.stack.push(Value::Int(i64::from(byte)));
            }
            Op::BinInt2 => {
                let bytes = self.read_array::<2>()?;
                self.stack.push(Value::Int(i64::from(u16::from_le_bytes(bytes))));
            }
            Op::Long => {
                let line = self.read_line_checked(2)?;
                let value = self.parse_long(&line)?;
                self.stack.push(value);
            }
            Op::Long1 => {
                let length = usize::from(self.read_byte()?);
                self.load_long_bytes(length)?;
            }
            Op::Long4 => {
                let length = self.read_length(b"LONG pickle has negative byte count")?;
                self.load_long_bytes(length)?;
            }
            Op::Float => {
                let line = self.read_line_checked(2)?;
                let value = self.parse_float(&line)?;
                self.stack.push(Value::Float(value));
            }
            Op::BinFloat => {
                let bytes = self.read_array::<8>()?;
                self.stack.push(Value::Float(f64::from_bits(u64::from_be_bytes(bytes))));
            }
            Op::String => {
                let line = self.read_line_checked(2)?;
                let value = self.parse_string(&line)?;
                self.stack.push(value);
            }
            Op::BinString => {
                let length = self.read_length(b"BINSTRING pickle has negative byte count")?;
                let bytes = self.unpickler.read(self.vm, length)?;
                self.stack.push(Value::Str(PyBytes::new(bytes)));
            }
            Op::ShortBinString => {
                let length = usize::from(self.read_byte()?);
                let bytes = self.unpickler.read(self.vm, length)?;
                self.stack.push(Value::Str(PyBytes::new(bytes)));
            }
            Op::Unicode => {
                let line = self.read_line_checked(1)?;
                let mut errors = Errors::new(self.vm, None);
                let units = decode_raw_unicode_escape(&line[..line.len() - 1], &mut errors)?;
                // Decoders allocate their result: one-character strings are
                // new objects, not the shared ones.
                self.stack.push(Value::Unicode(PyText::new_unshared(units)));
            }
            Op::BinUnicode => {
                let length = self.read_length(b"BINUNICODE pickle has negative byte count")?;
                let bytes = self.unpickler.read(self.vm, length)?;
                let mut errors = Errors::new(self.vm, None);
                let decoded = decode_utf8(&bytes, true, &mut errors)?;
                self.stack.push(Value::Unicode(PyText::new_unshared(decoded.units)));
            }
            Op::EmptyTuple => self.stack.push(Value::tuple(Vec::new())),
            Op::Tuple => {
                let start = self.pop_mark()?;
                let Some(items) = self.split_from(start) else {
                    return Err(self.negative_size("tupleobject.c:54"));
                };
                self.stack.push(Value::tuple(items));
            }
            Op::Tuple1 | Op::Tuple2 | Op::Tuple3 => {
                let count = match op {
                    Op::Tuple1 => 1,
                    Op::Tuple2 => 2,
                    _ => 3,
                };
                let Some(start) = self.stack.len().checked_sub(count) else {
                    return Err(self.underflow());
                };
                let items = self.stack.split_off(start);
                self.stack.push(Value::tuple(items));
            }
            Op::EmptyList => self.stack.push(self.vm.new_list(Vec::new())),
            Op::List => {
                let start = self.pop_mark()?;
                let Some(items) = self.split_from(start) else {
                    return Err(self.negative_size("listobject.c:126"));
                };
                self.stack.push(self.vm.new_list(items));
            }
            Op::EmptyDict => self.stack.push(Value::Object(self.vm.new_dict())),
            Op::Dict => {
                let start = self.pop_mark()?;
                let items = self.split_from(start).unwrap_or_default();
                let dict = self.vm.new_dict();
                // A key without a value is dropped.
                for pair in items.chunks_exact(2) {
                    self.vm.dict_set(&dict, pair[0].clone(), pair[1].clone())?;
                }
                self.stack.push(Value::Object(dict));
            }
            Op::Append if skim => {
                self.require(2)?;
                self.stack.pop();
            }
            Op::Append => {
                self.require(2)?;
                let item = self.pop_value()?;
                let list = self.top()?.clone();
                self.append_items(&list, vec![item])?;
            }
            Op::Appends => {
                let start = self.pop_mark()?;
                if skim {
                    self.stack.truncate(start);
                    return Ok(());
                }
                let Some(list) = start.checked_sub(1).and_then(|index| self.stack.get(index)).cloned() else {
                    return Err(self.underflow());
                };
                let items = self.stack.split_off(start);
                self.append_items(&list, items)?;
            }
            Op::SetItem if skim => {
                self.require(3)?;
                self.stack.truncate(self.stack.len() - 2);
            }
            Op::SetItem => {
                self.require(3)?;
                let value = self.pop_value()?;
                let key = self.pop_value()?;
                let target = self.top()?.clone();
                self.vm.setitem(&target, &key, value)?;
            }
            Op::SetItems => {
                let start = self.pop_mark()?;
                if skim {
                    self.stack.truncate(start);
                    return Ok(());
                }
                let Some(target) = start.checked_sub(1).and_then(|index| self.stack.get(index)).cloned() else {
                    return Err(self.underflow());
                };
                let items = self.stack.split_off(start);
                if items.len() % 2 != 0 {
                    return Err(self.unpickling_error(b"odd number of items for SETITEMS".to_vec()));
                }
                for pair in items.chunks_exact(2) {
                    self.vm.setitem(&target, &pair[0], pair[1].clone())?;
                }
            }
            Op::Build if skim => {
                self.require(2)?;
                self.stack.pop();
            }
            Op::Build => {
                self.require(2)?;
                let state = self.pop_value()?;
                let instance = self.top()?.clone();
                self.build(&instance, state)?;
            }
            Op::Global => {
                let module = self.read_name_line(skim)?;
                let name = self.read_name_line(skim)?;
                let found = if skim { Value::None } else { self.find_class(module, name)? };
                self.stack.push(found);
            }
            Op::Inst => {
                let start = self.pop_mark()?;
                let arguments = self.split_from(start);
                if skim {
                    self.read_name_line(skim)?;
                    self.read_name_line(skim)?;
                    self.stack.push(Value::None);
                    return Ok(());
                }
                let Some(arguments) = arguments else {
                    return Err(self.negative_size("tupleobject.c:54"));
                };
                let module = self.read_name_line(skim)?;
                let name = self.read_name_line(skim)?;
                let class = self.find_class(module, name)?;
                let instance = self.construct(&class, &Value::tuple(arguments))?;
                self.stack.push(instance);
            }
            Op::Obj => {
                let start = self.pop_mark()?;
                if self.stack.len() <= start {
                    return Err(if skim { self.unpickling_error(b"bad pickle data".to_vec()) } else { self.underflow() });
                }
                if skim {
                    self.stack.truncate(start + 1);
                    return Ok(());
                }
                let arguments = self.stack.split_off(start + 1);
                let class = self.pop_value()?;
                let instance = self.construct(&class, &Value::tuple(arguments))?;
                self.stack.push(instance);
            }
            Op::Reduce if skim => {
                self.require(2)?;
                self.stack.pop();
                self.replace_top(Value::None);
            }
            Op::Reduce => {
                if self.stack.len() < 2 {
                    return Err(self.unpickling_error(b"bad pickle data".to_vec()));
                }
                let arguments = self.pop_value()?;
                let callable = self.pop_value()?;
                let result = self.construct(&callable, &arguments)?;
                self.stack.push(result);
            }
            Op::NewObj if skim => {
                if self.stack.len() < 2 {
                    return Err(self.unpickling_error(b"bad pickle data".to_vec()));
                }
                self.stack.pop();
                self.replace_top(Value::None);
            }
            Op::NewObj => self.new_object()?,
            Op::Put => {
                let line = self.read_line_checked(2)?;
                let key = Value::Str(PyBytes::new(line[..line.len() - 1].to_vec()));
                self.memoize(key)?;
            }
            Op::BinPut => {
                let index = self.read_byte()?;
                self.memoize(Value::Int(i64::from(index)))?;
            }
            Op::LongBinPut => {
                let bytes = self.read_array::<4>()?;
                self.memoize(Value::Int(i64::from(i32::from_le_bytes(bytes))))?;
            }
            Op::Get => {
                let line = self.read_line_checked(2)?;
                self.recall(Value::Str(PyBytes::new(line[..line.len() - 1].to_vec())))?;
            }
            Op::BinGet => {
                let index = self.read_byte()?;
                self.recall(Value::Int(i64::from(index)))?;
            }
            Op::LongBinGet => {
                let bytes = self.read_array::<4>()?;
                self.recall(Value::Int(i64::from(i32::from_le_bytes(bytes))))?;
            }
            Op::PersistentId => {
                let line = self.read_line_checked(2)?;
                let id = Value::Str(PyBytes::new(line[..line.len() - 1].to_vec()));
                self.persistent(id)?;
            }
            Op::BinPersistentId => {
                self.persistent_hook()?;
                let Some(id) = self.stack.pop() else {
                    return Err(self.unpickling_error(b"bad pickle data".to_vec()));
                };
                self.persistent(id)?;
            }
            Op::Ext1 => {
                let code = self.read_byte()?;
                self.extension(i64::from(code))?;
            }
            Op::Ext2 => {
                let bytes = self.read_array::<2>()?;
                self.extension(i64::from(u16::from_le_bytes(bytes)))?;
            }
            Op::Ext4 => {
                let bytes = self.read_array::<4>()?;
                self.extension(i64::from(i32::from_le_bytes(bytes)))?;
            }
            Op::Proto => {
                let protocol = self.read_byte()?;
                if i64::from(protocol) > HIGHEST_PROTOCOL {
                    return Err(self.vm.raise(ExceptionKind::ValueError, &format!("unsupported pickle protocol: {protocol}")).into());
                }
            }
        }

        Ok(())
    }

    fn read_byte(&self) -> LoadResult<u8> {
        let [byte] = self.read_array::<1>()?;

        Ok(byte)
    }

    fn read_array<const N: usize>(&self) -> LoadResult<[u8; N]> {
        let bytes = self.unpickler.read(self.vm, N)?;

        bytes.try_into().map_err(|_| super::unpickler::eof_error(self.vm).into())
    }

    /// A signed four-byte length, which must not be negative.
    fn read_length(&self, negative: &[u8]) -> LoadResult<usize> {
        let length = i32::from_le_bytes(self.read_array::<4>()?);

        usize::try_from(length).map_err(|_| self.unpickling_error(negative.to_vec()))
    }

    /// A line of at least `minimum` bytes, its newline included.
    fn read_line_checked(&self, minimum: usize) -> LoadResult<Vec<u8>> {
        let line = self.unpickler.read_line(self.vm)?;
        if line.len() < minimum {
            return Err(self.unpickling_error(b"pickle data was truncated".to_vec()));
        }

        Ok(line)
    }

    /// A module or global name line without its newline. A skimming load
    /// checks nothing.
    fn read_name_line(&self, skim: bool) -> LoadResult<Vec<u8>> {
        if skim {
            self.unpickler.read_line(self.vm)?;
            return Ok(Vec::new());
        }

        let mut line = self.read_line_checked(2)?;
        line.pop();

        Ok(line)
    }

    fn load_long_bytes(&mut self, length: usize) -> LoadResult<()> {
        let number = if length == 0 { BigInt::default() } else { BigInt::from_signed_bytes_le(&self.unpickler.read(self.vm, length)?) };
        self.stack.push(Value::long(number));

        Ok(())
    }

    /// INT: an integer in the range of the platform `int` with optional
    /// `0x` or leading-zero octal prefix, ending at the newline; else a
    /// `long` literal. The lines `00` and `01` (and other three-byte lines
    /// of 0 or 1) are booleans.
    fn parse_int(&self, line: &[u8]) -> LoadResult<Value> {
        let text = c_string(line);
        if let Some((number, end)) = c_strtol(text, self.vm.config.long_width) {
            if text.get(end) == Some(&b'\n') && end + 1 == text.len() {
                if line.len() == 3 && (number == 0 || number == 1) {
                    return Ok(Value::Bool(number == 1));
                }
                return Ok(Value::Int(number));
            }
        }

        match parse::long_from_bytes(text, 0) {
            Ok(number) => Ok(Value::long(number)),
            Err(_) => Err(self.vm.raise(ExceptionKind::ValueError, "could not convert string to int").into()),
        }
    }

    fn parse_long(&self, line: &[u8]) -> LoadResult<Value> {
        let text = c_string(line);

        match parse::long_from_bytes(text, 0) {
            Ok(number) => Ok(Value::long(number)),
            Err(base) => {
                let shown = repr_bytes(&text[..text.len().min(200)]);
                Err(self.vm.raise(ExceptionKind::ValueError, &format!("invalid literal for long() with base {base}: {shown}")).into())
            }
        }
    }

    /// FLOAT: a decimal, infinity, or NaN spelling that ends at the
    /// newline.
    fn parse_float(&self, line: &[u8]) -> LoadResult<f64> {
        let text = c_string(line);
        let Some((value, consumed)) = parse::scan_float(text) else {
            return Err(self.raise_bytes(ExceptionKind::ValueError, [b"could not convert string to float: ".as_slice(), text].concat()));
        };
        if value.is_infinite() && text[..consumed].iter().any(u8::is_ascii_digit) {
            return Err(self.raise_bytes(ExceptionKind::OverflowError, [b"value too large to convert to float: ".as_slice(), text].concat()));
        }
        if text.get(consumed) != Some(&b'\n') {
            return Err(self.vm.raise(ExceptionKind::ValueError, "could not convert string to float").into());
        }

        Ok(value)
    }

    /// STRING: a quoted literal with escapes. Trailing bytes up to the
    /// space character are ignored.
    fn parse_string(&self, line: &[u8]) -> LoadResult<Value> {
        let mut end = line.len();
        while end > 0 && line[end - 1] <= b' ' {
            end -= 1;
        }
        let quoted = &line[..end];

        let Some((first, rest)) = quoted.split_first() else {
            return Err(self.vm.raise(ExceptionKind::ValueError, "insecure string pickle").into());
        };
        let Some(content) = rest.strip_suffix(&[*first]).filter(|_| matches!(first, b'\'' | b'"')) else {
            return Err(self.vm.raise(ExceptionKind::ValueError, "insecure string pickle").into());
        };

        let errors = Errors::new(self.vm, None);
        let bytes = decode_string_escape(content, &errors)?;

        Ok(Value::Str(PyBytes::new(bytes)))
    }

    fn raise_bytes(&self, kind: ExceptionKind, message: Vec<u8>) -> Stop {
        let class = Rc::clone(self.vm.types().exception(kind));

        self.vm.raise_string(&class, Value::Str(PyBytes::new(message))).into()
    }

    fn unpickling_error(&self, message: Vec<u8>) -> Stop {
        self.vm.raise_string(&self.unpickler.state.unpickling_error, Value::Str(PyBytes::new(message))).into()
    }

    fn underflow(&self) -> Stop {
        self.unpickling_error(b"unpickling stack underflow".to_vec())
    }

    fn require(&self, count: usize) -> LoadResult<()> {
        if self.stack.len() < count {
            return Err(self.underflow());
        }

        Ok(())
    }

    fn top(&self) -> LoadResult<&Value> {
        self.stack.last().ok_or_else(|| self.underflow())
    }

    fn pop_value(&mut self) -> LoadResult<Value> {
        self.stack.pop().ok_or_else(|| self.underflow())
    }

    fn replace_top(&mut self, value: Value) {
        if let Some(top) = self.stack.last_mut() {
            *top = value;
        }
    }

    /// POP: the topmost MARK when nothing was pushed after it, else the
    /// top value.
    fn pop_one(&mut self) -> LoadResult<()> {
        if self.marks.last() == Some(&self.stack.len()) {
            self.marks.pop();
            return Ok(());
        }

        self.pop_value().map(drop)
    }

    /// The stack position of the topmost MARK, which is removed. Values
    /// popped since the MARK can leave it past the end of the stack.
    fn pop_mark(&mut self) -> LoadResult<usize> {
        self.marks.pop().ok_or_else(|| self.unpickling_error(b"could not find MARK".to_vec()))
    }

    /// The values from `start` up, which a MARK past the end of the stack
    /// leaves empty-handed.
    fn split_from(&mut self, start: usize) -> Option<Vec<Value>> {
        (start <= self.stack.len()).then(|| self.stack.split_off(start))
    }

    /// The failure of a tuple or list of negative size.
    fn negative_size(&self, file: &str) -> Stop {
        self.vm.raise(ExceptionKind::SystemError, &format!("..\\Objects\\{file}: bad argument to internal function")).into()
    }

    /// Appends to a list directly, or through the `append` method of
    /// another object.
    fn append_items(&self, target: &Value, items: Vec<Value>) -> LoadResult<()> {
        if items.is_empty() {
            return Ok(());
        }
        if target.as_object().is_some_and(|object| matches!(object.payload, Payload::List(_))) {
            for item in items {
                self.vm.list_append(target, item)?;
            }
            return Ok(());
        }

        let append = self.vm.getattr_str(target, "append")?;
        for item in items {
            self.vm.call1(&append, item)?;
        }

        Ok(())
    }

    fn memoize(&mut self, key: Value) -> LoadResult<()> {
        let top = self.top()?.clone();
        let memo = self.unpickler.memo();

        Ok(self.vm.dict_set(&memo, key, top)?)
    }

    fn recall(&mut self, key: Value) -> LoadResult<()> {
        let memo = self.unpickler.memo();
        let Some(value) = self.vm.dict_get(&memo, &key)? else {
            return Err(self.vm.raise_string(&self.unpickler.state.bad_pickle_get, key).into());
        };
        self.stack.push(value);

        Ok(())
    }

    /// The `persistent_load` hook, which must be set.
    fn persistent_hook(&self) -> LoadResult<Value> {
        let hook = self.unpickler.persistent_load.borrow().clone();

        hook.ok_or_else(|| self.unpickling_error(b"A load persistent id instruction was encountered,\nbut no persistent_load function was specified.".to_vec()))
    }

    /// Resolves a persistent id: a list hook collects the id itself, other
    /// hooks are called with it.
    fn persistent(&mut self, id: Value) -> LoadResult<()> {
        let hook = self.persistent_hook()?;
        if hook.as_object().is_some_and(|object| matches!(object.payload, Payload::List(_))) {
            self.vm.list_append(&hook, id.clone())?;
            self.stack.push(id);
            return Ok(());
        }

        let value = self.vm.call1(&hook, id)?;
        self.stack.push(value);

        Ok(())
    }

    /// The object `copy_reg` registered under extension `code`, cached in
    /// `copy_reg._extension_cache`.
    fn extension(&mut self, code: i64) -> LoadResult<()> {
        if self.mode == Mode::Skim {
            self.stack.push(Value::None);
            return Ok(());
        }
        if code <= 0 {
            return Err(self.unpickling_error(b"EXT specifies code <= 0".to_vec()));
        }

        let state = Rc::clone(&self.unpickler.state);
        let key = Value::Int(code);
        if let Some(cached) = self.vm.dict_get(&state.extension_cache, &key)? {
            self.stack.push(cached);
            return Ok(());
        }

        let Some(pair) = self.vm.dict_get(&state.inverted_registry, &key)? else {
            return Err(self.vm.raise(ExceptionKind::ValueError, &format!("unregistered extension code {code}")).into());
        };
        let names = match pair_items(&pair) {
            Some([module, name]) => self.vm.as_str_bytes(module).zip(self.vm.as_str_bytes(name)),
            None => None,
        };
        let Some((module, name)) = names else {
            return Err(self.vm.raise(ExceptionKind::ValueError, &format!("_inverted_registry[{code}] isn't a 2-tuple of strings")).into());
        };

        let found = self.find_class(module.as_bytes().to_vec(), name.as_bytes().to_vec())?;
        self.vm.dict_set(&state.extension_cache, key, found.clone())?;
        self.stack.push(found);

        Ok(())
    }

    /// The global `module.name`, through `find_global` when it is set.
    fn find_class(&self, module: Vec<u8>, name: Vec<u8>) -> LoadResult<Value> {
        let module = Value::Str(PyBytes::new(module));
        let name = Value::Str(PyBytes::new(name));

        let hook = self.unpickler.find_global.borrow().clone();
        match hook {
            Some(hook) if hook.is_none() => Err(self.unpickling_error(b"Global and instance pickles are not supported.".to_vec())),
            Some(hook) => Ok(self.vm.call(&hook, CallArgs::new(vec![module, name]))?),
            None => {
                let loaded = match self.vm.dict_get(self.vm.modules(), &module)? {
                    Some(found) if !found.is_none() => found,
                    _ => import_module(self.vm, &module)?,
                };
                let Some(name) = self.vm.as_str_bytes(&name) else {
                    return Err(self.vm.type_error("global name is not a string").into());
                };

                Ok(self.vm.getattr(&loaded, &name)?)
            }
        }
    }

    /// `callable(*arguments)`. A classic class called without arguments
    /// and without `__getinitargs__` gives an instance whose `__init__`
    /// does not run. A failure carries the callable and the arguments.
    fn construct(&self, callable: &Value, arguments: &Value) -> LoadResult<Value> {
        match self.call_constructor(callable, arguments) {
            Err(Stop::Signal(Signal::Raise(error))) => Err(self.with_construction(&error, callable, arguments).into()),
            outcome => outcome,
        }
    }

    fn call_constructor(&self, callable: &Value, arguments: &Value) -> LoadResult<Value> {
        let vm = self.vm;
        if callable.is_unknown() {
            return Ok(Value::unknown("cPickle object built by an unknown callable"));
        }

        let classic = callable.as_object().filter(|object| object.as_class().is_some() && vm.is_classic_class(object));
        if let Some(class) = classic {
            let Some(count) = vm.len(arguments)? else {
                return Ok(Value::unknown("cPickle object built from unknown arguments"));
            };
            if count == 0 {
                match vm.getattr_opt(callable, &PyBytes::from("__getinitargs__")) {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(Signal::Raise(_)) => return Ok(Value::Object(vm.alloc(class, Payload::Instance, Some(vm.new_dict())))),
                    Err(halt) => return Err(halt.into()),
                }
            }
        }

        if arguments.is_unknown() {
            return Ok(Value::unknown("cPickle object built from unknown arguments"));
        }
        let Some(items) = tuple_items(arguments) else {
            return Err(vm.raise(ExceptionKind::TypeError, "argument list must be a tuple").into());
        };

        Ok(vm.call(callable, CallArgs::new(items.to_vec()))?)
    }

    /// The exception `error` with its value replaced by `(value, callable,
    /// arguments)`; a value raised from native code is its message.
    fn with_construction(&self, error: &Value, callable: &Value, arguments: &Value) -> Signal {
        let vm = self.vm;
        let class = vm.class_of(error);
        let detail = match vm.unnormalized_message(error) {
            Some(message) => Value::Str(message),
            None => error.clone(),
        };

        match vm.instantiate_exception(&class, vec![detail, callable.clone(), arguments.clone()]) {
            Ok(wrapped) => Signal::Raise(wrapped),
            Err(signal) => signal,
        }
    }

    /// NEWOBJ: `cls.__new__(cls, *args)`.
    fn new_object(&mut self) -> LoadResult<()> {
        let vm = self.vm;
        let Some(arguments) = self.stack.pop() else {
            return Err(self.unpickling_error(b"bad pickle data".to_vec()));
        };
        let items = match &arguments {
            Value::Unknown(_) => None,
            value => match tuple_items(value) {
                Some(items) => Some(items.to_vec()),
                None => return Err(self.unpickling_error(b"NEWOBJ expected an arg tuple.".to_vec())),
            },
        };
        let Some(class) = self.stack.pop() else {
            return Err(self.unpickling_error(b"bad pickle data".to_vec()));
        };

        let Some(items) = items.filter(|_| !class.is_unknown()) else {
            self.stack.push(Value::unknown("cPickle NEWOBJ with unknown parts"));
            return Ok(());
        };
        let Some(class_object) = class.as_object().filter(|object| object.as_class().is_some() && !vm.is_classic_class(object)) else {
            return Err(self.unpickling_error(b"NEWOBJ class argument isn't a type object".to_vec()));
        };
        if has_null_new(vm, class_object)? {
            return Err(self.unpickling_error(b"NEWOBJ class argument has NULL tp_new".to_vec()));
        }

        // The constructor comes from the class and its bases only; an
        // attribute of the metaclass named `__new__` is not consulted.
        let new = match vm.lookup_mro(class_object, "__new__")? {
            MroLookup::Found { value, .. } => vm.descriptor_get(&value, None, class_object)?,
            MroLookup::Unknown(unknown) => Value::Unknown(unknown),
            MroLookup::Missing => return Err(self.unpickling_error(b"NEWOBJ class argument has NULL tp_new".to_vec())),
        };
        let mut positional = Vec::with_capacity(items.len() + 1);
        positional.push(class);
        positional.extend(items);
        let instance = vm.call(&new, CallArgs::new(positional))?;
        self.stack.push(instance);

        Ok(())
    }

    /// BUILD: `__setstate__(state)`, else the state dict goes into the
    /// instance `__dict__` with interned keys and a slot state dict is set
    /// attribute by attribute.
    fn build(&self, instance: &Value, state: Value) -> LoadResult<()> {
        let vm = self.vm;
        if instance.is_unknown() {
            return Ok(());
        }

        if let Some(setstate) = vm.getattr_opt(instance, &PyBytes::from("__setstate__"))? {
            vm.call1(&setstate, state)?;
            return Ok(());
        }

        let (state, slot_state) = match pair_items(&state) {
            Some([state, slot_state]) => (state.clone(), slot_state.clone()),
            None => (state, Value::None),
        };

        if !state.is_none() {
            let Some(entries) = state.as_object().filter(|object| object.as_dict().is_some()) else {
                return Err(self.unpickling_error(b"state is not a dictionary".to_vec()));
            };
            let dict = vm.getattr_str(instance, "__dict__")?;
            for (key, value) in vm.dict_items(entries)? {
                let key = match &key {
                    Value::Str(bytes) => Value::Str(vm.intern(bytes)),
                    _ => key,
                };
                vm.setitem(&dict, &key, value)?;
            }
        }

        if !slot_state.is_none() {
            let Some(entries) = slot_state.as_object().filter(|object| object.as_dict().is_some()) else {
                return Err(self.unpickling_error(b"slot state is not a dictionary".to_vec()));
            };
            for (key, value) in vm.dict_items(entries)? {
                let Some(name) = vm.as_str_bytes(&key) else {
                    return Err(vm.type_error(&format!("attribute name must be string, not '{}'", vm.type_name(&key))).into());
                };
                vm.setattr(instance, &name, value)?;
            }
        }

        Ok(())
    }
}

/// `__import__(name, globals, globals, ['__doc__'], 0)`.
fn import_module(vm: &Vm, module: &Value) -> PyResult<Value> {
    let Some(name) = vm.as_str_bytes(module) else {
        return Err(vm.type_error("module name is not a string"));
    };
    let globals = vm.current_globals().unwrap_or_else(|| vm.new_dict());
    let fromlist = vm.new_list(vec![Value::str("__doc__")]);

    vm.import_name(&name, &globals, Some(&globals), &fromlist, &Value::Int(0))
}

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

fn pair_items(value: &Value) -> Option<&[Value; 2]> {
    tuple_items(value).and_then(|items| items.try_into().ok())
}

/// The bytes before the first NUL, which ends a text value.
fn c_string(bytes: &[u8]) -> &[u8] {
    bytes.iter().position(|byte| *byte == 0).map_or(bytes, |end| &bytes[..end])
}

/// The leading integer of `text` with an optional sign and base prefix:
/// its value and the offset after it, or `None` when it does not fit the
/// platform `int` of `width`. Without digits the
/// value is 0 at offset 0.
fn c_strtol(text: &[u8], width: LongWidth) -> Option<(i64, usize)> {
    let mut position = text.iter().position(|byte| !parse::is_space(*byte)).unwrap_or(text.len());
    let negative = match text.get(position) {
        Some(b'-') => {
            position += 1;
            true
        }
        Some(b'+') => {
            position += 1;
            false
        }
        _ => false,
    };

    let hex_follows = text.get(position + 2).is_some_and(u8::is_ascii_hexdigit);
    let radix = match (text.get(position), text.get(position + 1)) {
        (Some(b'0'), Some(b'x' | b'X')) if hex_follows => {
            position += 2;
            16
        }
        (Some(b'0'), _) => 8,
        _ => 10,
    };

    // Every digit is consumed even past an overflow.
    let digits_start = position;
    let mut magnitude: Option<i128> = Some(0);
    while let Some(digit) = text.get(position).and_then(|byte| char::from(*byte).to_digit(radix)) {
        magnitude = magnitude.and_then(|value| value.checked_mul(i128::from(radix))).and_then(|value| value.checked_add(i128::from(digit)));
        position += 1;
    }
    if position == digits_start {
        return Some((0, 0));
    }

    let value = magnitude.map(|magnitude| if negative { -magnitude } else { magnitude })?;
    let (low, high) = crate::interp::numbers::int_bounds(width);
    let value = i64::try_from(value).ok().filter(|value| (low..=high).contains(value))?;

    Some((value, position))
}
