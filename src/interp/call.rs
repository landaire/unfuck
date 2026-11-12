use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::code::CodeFlags;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::frame::Frame;
use crate::interp::frame::FrameExit;
use crate::interp::frame::FrameScope;
use crate::interp::frame::run_frame;
use crate::interp::object::CallArgs;
use crate::interp::object::ClassStyle;
use crate::interp::object::FunctionData;
use crate::interp::object::GeneratorData;
use crate::interp::object::GeneratorState;
use crate::interp::object::NativeBinding;
use crate::interp::object::NativeFunction;
use crate::interp::value::MethodData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

impl Vm {
    /// Calls `callable`, one recursion level deeper.
    pub fn call(&self, callable: &Value, args: CallArgs) -> PyResult<Value> {
        const CONTEXT: &str = " while calling a Python object";

        let object = match callable {
            Value::Object(object) => object,
            Value::Unknown(unknown) => return Ok(Value::Unknown(Rc::clone(unknown))),
            _ => return Err(self.type_error(&format!("'{}' object is not callable", self.type_name(callable)))),
        };

        match &object.payload {
            Payload::Function(function) => self.with_depth_in(CONTEXT, || self.call_function(function, args)),
            Payload::NativeFunction(native) => self.with_depth_in(CONTEXT, || self.call_native(native, args)),
            Payload::Method(method) => self.with_depth_in(CONTEXT, || self.call_bound(method, args)),
            Payload::Class(_) => self.with_depth_in(CONTEXT, || self.call_class(object, args)),
            _ if self.is_classic_class(&object.class()) => self.with_depth_in(CONTEXT, || self.call_classic_instance(object, args)),
            _ => {
                let Some(call) = self.lookup_special(callable, "__call__")? else {
                    return Err(self.type_error(&format!("'{}' object is not callable", self.type_name(callable))));
                };
                self.with_depth_in(CONTEXT, || self.call_slot(&call, args))
            }
        }
    }

    /// Calls `callable` from a `CALL_FUNCTION` opcode. A bound method's function is called with the receiver
    /// first. Builtin functions, and Python functions called without `*` or
    /// `**` arguments (`extended`), skip the generic call path and its recursion
    /// check.
    pub(crate) fn call_from_bytecode(&self, callable: &Value, mut args: CallArgs, extended: bool) -> PyResult<Value> {
        let mut function = callable;
        if let Some(Payload::Method(method)) = callable.as_object().map(|object| &object.payload) {
            if let Some(receiver) = &method.receiver {
                args.positional.insert(0, receiver.clone());
                function = &method.function;
            }
        }

        match function.as_object().map(|object| &object.payload) {
            Some(Payload::NativeFunction(native)) if is_builtin_function(native) => self.call_native(native, args),
            Some(Payload::Function(data)) if !extended => self.call_function(data, args),
            _ => self.call(function, args),
        }
    }

    /// Calls the implementation of a type slot (`__new__`, `__init__`,
    /// `__call__`): a native one runs directly, and a Python one goes
    /// through a generic call.
    pub(crate) fn call_slot(&self, implementation: &Value, args: CallArgs) -> PyResult<Value> {
        match implementation.as_object().map(|object| &object.payload) {
            Some(Payload::NativeFunction(native)) => self.call_native(native, args),
            _ => self.call(implementation, args),
        }
    }

    /// Runs a native function with its bound receiver, if any, first.
    fn call_native(&self, native: &NativeFunction, mut args: CallArgs) -> PyResult<Value> {
        if let Some(receiver) = &native.receiver {
            args.positional.insert(0, receiver.clone());
        }

        (native.function)(self, args)
    }

    /// Looks up `__call__` on a classic instance and calls
    /// it one recursion level deeper.
    fn call_classic_instance(&self, instance: &ObjectRef, args: CallArgs) -> PyResult<Value> {
        let target = Value::Object(Rc::clone(instance));
        let Some(call) = self.getattr_opt(&target, &PyBytes::from("__call__"))? else {
            let class_name = self.class_name(&instance.class());
            return Err(self.raise(ExceptionKind::AttributeError, &format!("{class_name} instance has no __call__ method")));
        };

        self.with_depth_in(" in __call__", || self.call(&call, args))
    }

    pub fn call0(&self, callable: &Value) -> PyResult<Value> {
        self.call(callable, CallArgs::default())
    }

    pub fn call1(&self, callable: &Value, argument: Value) -> PyResult<Value> {
        self.call(callable, CallArgs::new(vec![argument]))
    }

    fn call_bound(&self, method: &MethodData, mut args: CallArgs) -> PyResult<Value> {
        match &method.receiver {
            Some(receiver) => args.positional.insert(0, receiver.clone()),
            None => {
                let Some(class) = &method.class else {
                    return self.call(&method.function, args);
                };
                let first = args.positional.first();
                let accepted = match first {
                    Some(first) => self.isinstance(first, class)?,
                    None => false,
                };
                if !accepted {
                    let instance = match first {
                        Some(first) => format!("{} instance", self.instance_class_name(first)?),
                        None => "nothing".to_owned(),
                    };
                    let name = self.function_name(&method.function);
                    let description = self.function_description(&method.function);
                    let class_name = self.class_name_for_message(class)?;
                    return Err(self.type_error(&format!("unbound method {name}{description} must be called with {class_name} instance as first argument (got {instance} instead)")));
                }
            }
        }

        self.call(&method.function, args)
    }

    /// The class name in call error messages: `__name__` when it is a `str`, else
    /// `?`, cut at its 256-byte buffer.
    fn class_name_for_message(&self, class: &Value) -> PyResult<String> {
        let name = match self.getattr_str(class, "__name__") {
            Ok(name) => self.as_str_bytes(&name),
            Err(Signal::Raise(_)) => None,
            Err(halt) => return Err(halt),
        };
        let Some(name) = name else {
            return Ok("?".to_owned());
        };

        let bytes = name.as_bytes();
        let bytes = &bytes[..bytes.len().min(255)];
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());

        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// The class name of an instance in call error messages.
    fn instance_class_name(&self, instance: &Value) -> PyResult<String> {
        let class = match self.getattr_str(instance, "__class__") {
            Ok(class) => class,
            Err(Signal::Raise(_)) => Value::Object(self.class_of(instance)),
            Err(halt) => return Err(halt),
        };

        self.class_name_for_message(&class)
    }

    /// `repr` of a bound or unbound method.
    pub fn method_repr(&self, method: &MethodData) -> PyResult<String> {
        let function_name = self.str_attribute(&method.function, "__name__")?;
        let class_name = match &method.class {
            Some(class) => self.str_attribute(class, "__name__")?,
            None => None,
        };
        let function_name = function_name.unwrap_or_else(|| "?".to_owned());
        let class_name = class_name.unwrap_or_else(|| "?".to_owned());

        let Some(receiver) = &method.receiver else {
            return Ok(format!("<unbound method {class_name}.{function_name}>"));
        };

        Ok(format!("<bound method {class_name}.{function_name} of {}>", self.repr_text(receiver)?))
    }

    /// An attribute that is a `str`, as `%s` formats it, or `None` when it
    /// is missing or of another type.
    fn str_attribute(&self, target: &Value, name: &str) -> PyResult<Option<String>> {
        match self.getattr_str(target, name) {
            Ok(value) => Ok(self.as_str_bytes(&value).map(|bytes| crate::interp::builtins::core::c_string(bytes.as_bytes(), usize::MAX))),
            Err(Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::AttributeError) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Calls a Python function: binds arguments into a new frame and runs it,
    /// or returns a generator for generator functions.
    fn call_function(&self, function: &FunctionData, args: CallArgs) -> PyResult<Value> {
        self.evaluate(function, None, args)
    }

    /// Runs a code object without arguments in a new
    /// frame with the given namespaces.
    pub fn eval_code(&self, code_object: &ObjectRef, globals: &ObjectRef, locals: &ObjectRef) -> PyResult<Value> {
        let Payload::Code(code) = &code_object.payload else {
            return Err(self.type_error("expected a code object"));
        };

        let function = FunctionData {
            code: Rc::clone(code),
            code_object: Rc::clone(code_object),
            globals: Rc::clone(globals),
            name: RefCell::new(code.name.clone()),
            defaults: RefCell::new(None),
            closure: None,
            module: RefCell::new(Value::None),
            doc: RefCell::new(Value::None),
        };

        self.evaluate(&function, Some(Rc::clone(locals)), CallArgs::default())
    }

    /// Runs a function's code. The frame's `f_locals` is
    /// none for optimized function code, a new dict for other function
    /// code, and otherwise `locals`, defaulting to the globals.
    fn evaluate(&self, function: &FunctionData, locals: Option<ObjectRef>, args: CallArgs) -> PyResult<Value> {
        let code = Rc::clone(&function.code);
        let newlocals = code.flags.contains(CodeFlags::NEWLOCALS);
        let frame_locals = match (newlocals, code.flags.contains(CodeFlags::OPTIMIZED)) {
            (true, true) => None,
            (true, false) => Some(self.new_dict()),
            (false, _) => Some(locals.unwrap_or_else(|| Rc::clone(&function.globals))),
        };
        let builtins = self.frame_builtins(&function.globals)?;

        let mut fast = vec![None; code.nlocals as usize];
        let cells = self.bind_arguments(function, &mut fast, args)?;
        let scope = FrameScope::new(Rc::clone(&code), frame_locals, fast, cells);
        let mut frame = Frame::from_scope(Rc::clone(&function.code_object), Rc::clone(&function.globals), builtins, scope);

        if code.flags.contains(CodeFlags::GENERATOR) {
            let activation = Rc::clone(&frame.activation);
            let data = GeneratorData { state: GeneratorState::Created(Box::new(frame)), name: code.name.clone(), code_object: Rc::clone(&function.code_object), activation: Some(activation) };
            let class = Rc::clone(&self.types().generator);
            return Ok(Value::Object(self.alloc(&class, Payload::Generator(RefCell::new(data)), None)));
        }

        self.execute_frame(&mut frame)
    }

    /// Runs a fresh frame to completion, one
    /// recursion level deeper.
    pub fn execute_frame(&self, frame: &mut Frame) -> PyResult<Value> {
        self.push_handled_slot();
        let result = self.with_depth(|| run_frame(self, frame));
        self.pop_handled_slot();

        match result? {
            FrameExit::Return(value) => Ok(value),
            FrameExit::Yield(_) => Err(self.halt_unsupported("yield outside a generator")),
        }
    }

    /// The `f_builtins` of a new frame with `globals`: the
    /// calling frame's when it shares the globals, else the module dict or
    /// dict named by the globals' `__builtins__`, else a minimal dict
    /// holding only `None`.
    pub fn frame_builtins(&self, globals: &ObjectRef) -> PyResult<ObjectRef> {
        if let Some(builtins) = self.shared_builtins(globals) {
            return Ok(builtins);
        }

        let named = match self.dict_get_str(globals, "__builtins__")? {
            Some(Value::Object(object)) if object.as_module().is_some() => object.dict(),
            Some(Value::Object(object)) if object.as_dict().is_some() => Some(object),
            _ => None,
        };
        if let Some(builtins) = named {
            return Ok(builtins);
        }

        let minimal = self.new_dict();
        self.dict_set_str(&minimal, "None", Value::None)?;

        Ok(minimal)
    }

    /// Binds call arguments into `fast` and returns the frame's cells: the
    /// cell variables, initialized from the arguments they name, followed by
    /// the function's closure.
    fn bind_arguments(&self, function: &FunctionData, fast: &mut [Option<Value>], args: CallArgs) -> PyResult<Vec<ObjectRef>> {
        let code = Rc::clone(&function.code);
        let name = function.name.borrow().to_string_lossy();
        let argcount = code.argcount as usize;
        let has_varargs = code.flags.contains(CodeFlags::VARARGS);
        let has_varkeywords = code.flags.contains(CodeFlags::VARKEYWORDS);
        let defaults = function.defaults.borrow().clone().unwrap_or_default();
        let given = args.positional.len();

        if fast.len() < argcount + usize::from(has_varargs) + usize::from(has_varkeywords) {
            return Err(self.halt_unsupported("code object has fewer locals than arguments"));
        }

        let mut positional = args.positional.into_iter();
        for slot in fast.iter_mut().take(argcount) {
            match positional.next() {
                Some(value) => *slot = Some(value),
                None => break,
            }
        }

        let extra: Vec<Value> = positional.collect();
        if !extra.is_empty() && !has_varargs {
            return Err(self.type_error(&format!("{name}() takes {} {} argument{} ({given} given)", if defaults.is_empty() { "exactly" } else { "at most" }, argcount, if argcount == 1 { "" } else { "s" })));
        }

        let mut next_slot = argcount;
        if has_varargs {
            fast[next_slot] = Some(Value::tuple(extra));
            next_slot += 1;
        }

        let kwargs = if has_varkeywords { Some(self.new_dict()) } else { None };

        // A non-`str` key keeps the original dict, so unicode keyword names
        // reach `**kwargs` as they were given.
        let entries: Vec<(Value, Value)> = match args.keyword_dict {
            Some(dict) => self.dict_items(&dict)?,
            None => args.keywords.into_iter().map(|(keyword, value)| (Value::Str(keyword), value)).collect(),
        };

        for (key, value) in entries {
            let keyword = self.keyword_name(&name, &key)?;
            let position = keyword.as_ref().and_then(|keyword| code.varnames.iter().take(argcount).position(|varname| varname.as_bytes() == keyword.as_bytes()));
            match position {
                Some(index) => {
                    if fast[index].is_some() {
                        return Err(self.type_error(&format!("{name}() got multiple values for keyword argument '{}'", self.keyword_display(&key))));
                    }
                    fast[index] = Some(value);
                }
                None => {
                    let Some(kwargs) = &kwargs else {
                        return Err(self.type_error(&format!("{name}() got an unexpected keyword argument '{}'", self.keyword_display(&key))));
                    };
                    self.dict_set(kwargs, key, value)?;
                }
            }
        }

        if let Some(kwargs) = kwargs {
            fast[next_slot] = Some(Value::Object(kwargs));
        }

        let first_default = argcount.saturating_sub(defaults.len());
        for index in 0..argcount {
            if fast[index].is_some() {
                continue;
            }
            if index >= first_default {
                fast[index] = Some(defaults[index - first_default].clone());
                continue;
            }
            let required = first_default;
            return Err(self.type_error(&format!("{name}() takes {} {required} argument{} ({given} given)", if defaults.is_empty() && !has_varargs { "exactly" } else { "at least" }, if required == 1 { "" } else { "s" })));
        }

        let mut cells = Vec::with_capacity(code.cellvars.len() + function.closure.as_ref().map_or(0, Vec::len));
        for cellvar in &code.cellvars {
            let argument_index = code.varnames.iter().take(next_slot + usize::from(has_varkeywords)).position(|varname| varname.as_bytes() == cellvar.as_bytes());
            let initial = argument_index.and_then(|index| fast.get(index).cloned().flatten());
            cells.push(self.new_cell(initial));
        }
        cells.extend(function.closure.iter().flatten().map(Rc::clone));

        Ok(cells)
    }

    pub fn new_cell(&self, value: Option<Value>) -> ObjectRef {
        let class = Rc::clone(&self.types().cell);

        self.alloc(&class, Payload::Cell(RefCell::new(value)), None)
    }

    /// `MAKE_FUNCTION` / `MAKE_CLOSURE`.
    pub fn make_function(&self, code: &Value, globals: &ObjectRef, defaults: Vec<Value>, closure: Option<Value>) -> PyResult<Value> {
        let Some(code_object) = code.as_object() else {
            return Err(self.type_error("MAKE_FUNCTION expects a code object"));
        };
        let Payload::Code(code) = &code_object.payload else {
            return Err(self.type_error("MAKE_FUNCTION expects a code object"));
        };

        let cells = match closure {
            Some(Value::Tuple(items)) => Some(items
                .iter()
                .map(|item| match item {
                    Value::Object(cell) if matches!(cell.payload, Payload::Cell(_)) => Ok(Rc::clone(cell)),
                    _ => Err(self.type_error("closure items must be cells")),
                })
                .collect::<PyResult<Vec<_>>>()?),
            Some(_) => return Err(self.type_error("closure must be a tuple")),
            None => None,
        };

        let doc = match code.consts.first() {
            Some(value @ (Value::Str(_) | Value::Unicode(_))) => value.clone(),
            _ => Value::None,
        };
        let module = self.dict_get_str(globals, "__name__")?.unwrap_or(Value::None);

        let data = FunctionData {
            code: Rc::clone(code),
            code_object: Rc::clone(code_object),
            globals: Rc::clone(globals),
            name: RefCell::new(code.name.clone()),
            defaults: RefCell::new((!defaults.is_empty()).then_some(defaults)),
            closure: cells,
            module: RefCell::new(module),
            doc: RefCell::new(doc),
        };

        let class = Rc::clone(&self.types().function);
        let dict = self.new_dict();

        Ok(Value::Object(self.alloc(&class, Payload::Function(data), Some(dict))))
    }

    /// Expands `*args` of a call.
    pub fn star_args(&self, function: &Value, extra: &Value) -> PyResult<Vec<Value>> {
        if let Value::Tuple(items) = extra {
            return Ok(items.to_vec());
        }

        match self.collect(extra) {
            Ok(items) => Ok(items),
            Err(crate::interp::error::Signal::Raise(error)) if self.is_exception(&error, ExceptionKind::TypeError) => {
                Err(self.type_error(&format!("{} argument after * must be a sequence, not {}", self.callable_name(function), self.type_name(extra))))
            }
            Err(error) => Err(error),
        }
    }

    /// Whether a call site would take the fast path for Python functions: a
    /// Python function, or a bound method of one.
    pub fn is_python_function(&self, callable: &Value) -> bool {
        let Some(object) = callable.as_object() else {
            return false;
        };

        match &object.payload {
            Payload::Function(_) => true,
            Payload::Method(method) => method.receiver.is_some() && matches!(method.function.as_object().map(|function| &function.payload), Some(Payload::Function(_))),
            _ => false,
        }
    }

    /// Collects keywords into a dict the way a call with `*` or `**`
    /// arguments, or to a non-Python callable, does: a copy of `**mapping` when given, then
    /// the explicit keywords. The callee sees them in that dict's
    /// iteration order.
    pub fn merge_star_kwargs(&self, function: &Value, keywords: Vec<(PyBytes, Value)>, mapping: Option<&Value>, positional: Vec<Value>) -> PyResult<CallArgs> {
        let combined = self.new_dict();

        match mapping {
            None => {}
            Some(mapping @ Value::Object(object)) if object.as_dict().is_some() => self.dict_merge(&combined, mapping, true)?,
            Some(mapping @ Value::Unknown(_)) => return Err(crate::interp::error::Signal::Halt(crate::interp::error::Halt::UnknownIteration { origin: format!("{mapping:?}") })),
            Some(mapping) => {
                if self.lookup_special(mapping, "keys")?.is_none() {
                    return Err(self.type_error(&format!("{} argument after ** must be a mapping, not {}", self.callable_name(function), self.type_name(mapping))));
                }
                self.dict_merge(&combined, mapping, true)?;
            }
        }

        // CPython pops keyword pairs off the value stack, so the
        // last keyword is inserted first.
        for (name, value) in keywords.into_iter().rev() {
            let key = Value::Str(name.clone());
            if self.dict_get(&combined, &key)?.is_some() {
                return Err(self.type_error(&format!("{} got multiple values for keyword argument '{}'", self.callable_name(function), name.to_string_lossy())));
            }
            self.dict_set(&combined, key, value)?;
        }

        self.keyword_args(positional, combined)
    }

    /// Call arguments from a keyword dict in its iteration order. A key
    /// that is not a `str` keeps the whole dict in `keyword_dict` so each
    /// callee can apply its own rule.
    pub fn keyword_args(&self, positional: Vec<Value>, dict: ObjectRef) -> PyResult<CallArgs> {
        let mut keywords = Vec::new();
        let mut all_strings = true;
        for (key, value) in self.dict_items(&dict)? {
            match self.as_str_bytes(&key) {
                Some(name) => keywords.push((name, value)),
                None => all_strings = false,
            }
        }

        let keyword_dict = if all_strings { None } else { Some(dict) };

        Ok(CallArgs { positional, keywords, keyword_dict })
    }

    /// A fresh dict of the keyword arguments, as C callees receive them.
    pub fn keywords_as_dict(&self, keywords: Vec<(PyBytes, Value)>, keyword_dict: Option<ObjectRef>) -> PyResult<ObjectRef> {
        if let Some(dict) = keyword_dict {
            return self.dict_copy(&dict);
        }

        let dict = self.new_dict();
        for (name, value) in keywords {
            self.dict_set(&dict, Value::Str(name), value)?;
        }

        Ok(dict)
    }

    /// Rejects keywords a native function's argument parser cannot
    /// accept: keys that are not `str`.
    pub fn require_string_keywords(&self, args: &CallArgs) -> PyResult<()> {
        if args.keyword_dict.is_some() {
            return Err(self.type_error("keywords must be strings"));
        }

        Ok(())
    }

    pub fn callable_name(&self, function: &Value) -> String {
        let Value::Object(object) = function else {
            return format!("{}()", self.type_name(function));
        };

        match &object.payload {
            Payload::Function(function) => format!("{}()", function.name.borrow().to_string_lossy()),
            Payload::NativeFunction(native) => format!("{}()", native.name),
            Payload::Method(_) => format!("{}()", self.function_name(function)),
            Payload::Class(class) => format!("{}()", class.name().to_string_lossy()),
            _ => format!("{} object", self.type_name(function)),
        }
    }

    /// The function name in call error messages.
    pub fn function_name(&self, function: &Value) -> String {
        let mut current = function.clone();
        loop {
            let Value::Object(object) = &current else {
                return self.type_name(&current);
            };

            match &object.payload {
                Payload::Method(method) => {
                    let inner = method.function.clone();
                    current = inner;
                }
                Payload::Function(function) => return function.name.borrow().to_string_lossy(),
                Payload::NativeFunction(native) => return native.name.to_string(),
                Payload::Class(class) if class.style == ClassStyle::Classic => return class.name().to_string_lossy(),
                Payload::Instance if self.is_classic_class(&object.class()) => {
                    let class = object.class();
                    return class.as_class().map(|data| data.name().to_string_lossy()).unwrap_or_default();
                }
                _ => return self.type_name(&current),
            }
        }
    }

    /// The suffix after the function name in call error messages, such as `()`.
    pub fn function_description(&self, function: &Value) -> &'static str {
        let Value::Object(object) = function else {
            return " object";
        };

        match &object.payload {
            Payload::Method(_) | Payload::Function(_) | Payload::NativeFunction(_) => "()",
            Payload::Class(class) if class.style == ClassStyle::Classic => " constructor",
            Payload::Instance if self.is_classic_class(&object.class()) => " instance",
            _ => " object",
        }
    }

    /// The parameter name a keyword key can match. Identifiers are ASCII, so
    /// a unicode key matches only when it is ASCII and compares equal to
    /// the `str` varname.
    fn keyword_name(&self, function: &str, key: &Value) -> PyResult<Option<PyBytes>> {
        if let Some(name) = self.as_str_bytes(key) {
            return Ok(Some(name));
        }

        let Some(text) = self.as_text(key) else {
            return Err(self.type_error(&format!("{function}() keywords must be strings")));
        };
        let ascii: Option<Vec<u8>> = text.units().iter().map(|unit| u8::try_from(*unit).ok().filter(u8::is_ascii)).collect();

        Ok(ascii.map(PyBytes::new))
    }

    /// A keyword name in error messages: unicode keys print default-encoded with
    /// replacement.
    fn keyword_display(&self, key: &Value) -> String {
        if let Some(name) = self.as_str_bytes(key) {
            return name.to_string_lossy();
        }

        let Some(text) = self.as_text(key) else {
            return String::new();
        };

        text.units().iter().map(|unit| u8::try_from(*unit).ok().filter(u8::is_ascii).map_or('?', char::from)).collect()
    }

    /// Binds a function found on a class to an instance or class
    /// (`instancemethod`).
    pub fn bind_function(&self, function: &Value, receiver: Option<Value>, class: Option<Value>) -> Value {
        let method_class = Rc::clone(&self.types().method);
        let data = MethodData { function: function.clone(), receiver, class };

        Value::Object(self.alloc(&method_class, Payload::Method(data), None))
    }

    /// `instancemethod.__get__`: a bound method stays as is, and an
    /// unbound one binds unless `owner` does not derive from its class.
    pub fn method_descr_get(&self, descriptor: &Value, method: &MethodData, instance: Option<Value>, owner: Option<Value>) -> PyResult<Value> {
        if method.receiver.is_some() {
            return Ok(descriptor.clone());
        }

        if let (Some(class), Some(owner)) = (&method.class, &owner) {
            if !self.issubclass(owner, class)? {
                return Ok(descriptor.clone());
            }
        }

        Ok(self.bind_function(&method.function, instance, owner))
    }

    /// Binds a native method descriptor to a receiver.
    pub fn bind_native(&self, native: &ObjectRef, receiver: Value) -> Value {
        let Payload::NativeFunction(function) = &native.payload else {
            return Value::Object(Rc::clone(native));
        };

        let class = crate::interp::builtins::descriptors::bound_class(self, native);
        let payload = Payload::NativeFunction(crate::interp::object::NativeFunction {
            name: function.name,
            function: function.function,
            binding: NativeBinding::Function,
            receiver: Some(receiver),
            owner: function.owner.as_ref().map(Rc::clone),
        });

        Value::Object(self.alloc(&class, payload, None))
    }
}

/// Whether `native` is a `builtin_function_or_method`: a
/// module function, a bound method, or a type's `__new__`, as opposed to
/// an unbound method descriptor.
fn is_builtin_function(native: &NativeFunction) -> bool {
    native.receiver.is_some() || !matches!(native.binding, NativeBinding::Method)
}
