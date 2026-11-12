use std::rc::Rc;

use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::frame::Frame;
use crate::interp::object::CallArgs;
use crate::interp::object::ModuleData;
use crate::interp::object::ModuleKind;
use crate::interp::object::ModuleState;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::BuiltinModule;
use crate::interp::vm::ImportRecord;
use crate::interp::vm::Vm;

/// Result of `import_submodule`: a module, a negative-cache entry, or not
/// found.
enum Submodule {
    Found(Value),
    Missing,
}

impl Vm {
    pub fn new_module(&self, name: &str, kind: ModuleKind) -> PyResult<ObjectRef> {
        let dict = self.new_dict();
        self.dict_set_str(&dict, "__name__", Value::str(name))?;
        self.dict_set_str(&dict, "__doc__", Value::None)?;
        self.dict_set_str(&dict, "__package__", Value::None)?;

        let class = Rc::clone(&self.types().module);
        let data = ModuleData { name: PyBytes::from(name), kind, state: std::cell::Cell::new(ModuleState::Loading) };

        Ok(self.alloc(&class, Payload::Module(data), Some(dict)))
    }

    /// Imports a module by absolute dotted name, as `import name` at top
    /// level would, and returns the leaf module. The import is a call of
    /// `__import__` made by the host, which takes one recursion level.
    pub fn import_module(&self, name: &str) -> PyResult<Value> {
        let globals = self.new_dict();
        let fromlist = Value::tuple(vec![Value::str("__name__")]);

        let module = self.with_depth_in(" while calling a Python object", || self.import_name_level(name, &globals, &fromlist, 0));
        self.run_finalizers()?;

        // A failing top-level module is reported as the interpreter reports a
        // failing script, which records it in `sys.last_*`.
        let failed = self.import_records.borrow().iter().rev().find(|record| record.module == name).is_some_and(|record| record.failure.is_some());
        let last = self.native_state::<LastFailure>().0.borrow_mut().take();
        if let (true, Some((exception, traceback))) = (failed, last) {
            self.publish_last_exception(exception, traceback);
        }

        module
    }

    /// `IMPORT_NAME`: calls `__import__`, honoring a replaced builtin.
    pub fn import_name(&self, name: &PyBytes, globals: &ObjectRef, locals: Option<&ObjectRef>, fromlist: &Value, level: &Value) -> PyResult<Value> {
        let builtins = self.frame_builtins(globals)?;
        let hook = self.dict_get_str(&builtins, "__import__")?;
        let Some(hook) = hook else {
            return Err(self.raise(ExceptionKind::ImportError, "__import__ not found"));
        };

        let is_native = matches!(hook.as_object().map(|object| &object.payload), Some(Payload::NativeFunction(native)) if native.name == "__import__");
        if !is_native {
            let locals = locals.map(|locals| Value::Object(Rc::clone(locals))).unwrap_or(Value::None);
            let args = vec![Value::Str(name.clone()), Value::Object(Rc::clone(globals)), locals, fromlist.clone(), level.clone()];
            return self.call(&hook, CallArgs::new(args));
        }

        // IMPORT_NAME calls `__import__` as a Python call.
        self.with_depth_in(" while calling a Python object", || {
            let level = self.import_level(level)?;

            self.import_name_level(&name.to_string_lossy(), globals, fromlist, level)
        })
    }

    /// The `level` argument of `__import__`, which must be an int.
    pub fn import_level(&self, level: &Value) -> PyResult<i64> {
        if let Value::Unknown(unknown) = level {
            return Err(Signal::Halt(crate::interp::error::Halt::UnknownCondition { context: "import level".to_owned(), origin: unknown.origin.clone() }));
        }

        self.as_index(level).ok_or_else(|| self.type_error("an integer is required"))
    }

    /// `__import__(name, globals, fromlist, level)`: resolves the package, imports each dotted part, then the `fromlist` names.
    pub fn import_name_level(&self, name: &str, globals: &ObjectRef, fromlist: &Value, level: i64) -> PyResult<Value> {
        let (parent, mut buffer) = self.import_parent(globals, level)?;
        let mut remaining = Some(name.to_owned());

        let alternate = if level < 0 { Value::None } else { parent.clone() };
        let head = self.load_next(&parent, &alternate, &mut remaining, &mut buffer)?;
        let mut tail = head.clone();

        while remaining.is_some() {
            tail = self.load_next(&tail, &tail.clone(), &mut remaining, &mut buffer)?;
        }

        if tail.is_none() {
            return Err(self.raise(ExceptionKind::ValueError, "Empty module name"));
        }

        let wants_fromlist = !fromlist.is_none() && self.truthy(fromlist, "fromlist")?;
        if !wants_fromlist {
            return Ok(head);
        }

        self.ensure_fromlist(&tail, fromlist, &buffer, false)?;

        Ok(tail)
    }

    /// The package a relative import resolves against. Sets
    /// `__package__` in `globals` as CPython does.
    fn import_parent(&self, globals: &ObjectRef, level: i64) -> PyResult<(Value, String)> {
        if level == 0 || globals.as_dict().is_none() {
            return Ok((Value::None, String::new()));
        }

        let mut package = match self.dict_get_str(globals, "__package__")? {
            Some(value) if !value.is_none() => {
                let Some(text) = value.as_bytes().map(|bytes| String::from_utf8_lossy(bytes).into_owned()) else {
                    return Err(self.raise(ExceptionKind::ValueError, "__package__ set to non-string"));
                };
                if text.is_empty() {
                    if level > 0 {
                        return Err(self.raise(ExceptionKind::ValueError, "Attempted relative import in non-package"));
                    }
                    return Ok((Value::None, String::new()));
                }
                text
            }
            _ => {
                let Some(module_name) = self.dict_get_str(globals, "__name__")?.and_then(|value| value.as_bytes().map(|bytes| String::from_utf8_lossy(bytes).into_owned())) else {
                    return Ok((Value::None, String::new()));
                };
                if self.dict_get_str(globals, "__path__")?.is_some() {
                    self.dict_set_str(globals, "__package__", Value::str(&module_name))?;
                    module_name
                } else {
                    let Some((package, _)) = module_name.rsplit_once('.') else {
                        if level > 0 {
                            return Err(self.raise(ExceptionKind::ValueError, "Attempted relative import in non-package"));
                        }
                        self.dict_set_str(globals, "__package__", Value::None)?;
                        return Ok((Value::None, String::new()));
                    };
                    self.dict_set_str(globals, "__package__", Value::str(package))?;
                    package.to_owned()
                }
            }
        };

        for _ in 1..level.max(1) {
            let Some((outer, _)) = package.rsplit_once('.') else {
                return Err(self.raise(ExceptionKind::ValueError, "Attempted relative import beyond toplevel package"));
            };
            package = outer.to_owned();
        }

        match self.dict_get_str(self.modules(), &package)? {
            Some(parent) => Ok((parent, package)),
            None if level < 1 => Ok((Value::None, String::new())),
            None => Err(self.raise(ExceptionKind::SystemError, &format!("Parent module '{package}' not loaded, cannot perform relative import"))),
        }
    }

    /// `load_next`: imports the next dotted component.
    fn load_next(&self, module: &Value, alternate: &Value, remaining: &mut Option<String>, buffer: &mut String) -> PyResult<Value> {
        let Some(name) = remaining.take() else {
            return Ok(module.clone());
        };

        if name.is_empty() {
            return Ok(module.clone());
        }

        let (component, rest) = match name.split_once('.') {
            Some((component, rest)) => (component.to_owned(), Some(rest.to_owned())),
            None => (name.clone(), None),
        };
        *remaining = rest;

        if component.is_empty() {
            return Err(self.raise(ExceptionKind::ValueError, "Empty module name"));
        }

        if !buffer.is_empty() {
            buffer.push('.');
        }
        buffer.push_str(&component);

        let mut result = self.import_submodule(module, &component, buffer)?;

        if matches!(result, Submodule::Missing) && !self.is_same(alternate, module) {
            result = self.import_submodule(alternate, &component, &component)?;
            if let Submodule::Found(found) = &result {
                if !found.is_none() {
                    self.dict_set_str(self.modules(), buffer, Value::None)?;
                    *buffer = component.clone();
                }
            }
        }

        match result {
            Submodule::Found(found) if !found.is_none() => Ok(found),
            _ => Err(self.raise(ExceptionKind::ImportError, &format!("No module named {component}"))),
        }
    }

    /// `import_submodule`: `sys.modules` first, then the module source.
    fn import_submodule(&self, parent: &Value, subname: &str, fullname: &str) -> PyResult<Submodule> {
        if let Some(existing) = self.dict_get_str(self.modules(), fullname)? {
            if existing.is_none() {
                return Ok(Submodule::Missing);
            }
            return Ok(Submodule::Found(existing));
        }

        let top_level = parent.is_none();

        if let Value::Object(parent_module) = parent {
            if let Some(data) = parent_module.as_module() {
                if data.kind == ModuleKind::Opaque {
                    let module = self.opaque_module(fullname)?;
                    self.add_submodule(parent, &module, subname)?;
                    return Ok(Submodule::Found(module));
                }
            }
            let path = self.getattr_opt(parent, &PyBytes::from("__path__"))?;
            if path.is_none() {
                // A module that is not a package only has submodules it
                // registers in sys.modules itself (os.path). When its body
                // stopped early that registration may be missing.
                let incomplete = parent_module.as_module().is_some_and(|data| data.state.get() == ModuleState::Incomplete);
                if incomplete {
                    let module = self.opaque_module(fullname)?;
                    self.add_submodule(parent, &module, subname)?;
                    return Ok(Submodule::Found(module));
                }
                return Ok(Submodule::Missing);
            }
        }

        let builtin = self.source().builtin(fullname);
        let native = self.native_module(fullname).filter(|_| builtin != BuiltinModule::Absent);

        let module = if top_level {
            if let Some(init) = native {
                Some(self.load_native(fullname, init)?)
            } else if self.source().find(fullname).is_some() {
                Some(self.load_source(fullname)?)
            } else if self.is_absent_module(fullname) || builtin == BuiltinModule::Absent {
                None
            } else {
                Some(self.opaque_module(fullname)?)
            }
        } else if self.source().find(fullname).is_some() {
            Some(self.load_source(fullname)?)
        } else if builtin == BuiltinModule::Present {
            // Engine modules registered under dotted names.
            Some(self.opaque_module(fullname)?)
        } else {
            None
        };

        let Some(module) = module else {
            return Ok(Submodule::Missing);
        };

        if let (Some(hook), Value::Object(module_object)) = (self.import_hook(fullname), &module) {
            hook(self, module_object)?;
        }

        self.add_submodule(parent, &module, subname)?;

        Ok(Submodule::Found(module))
    }

    fn add_submodule(&self, parent: &Value, module: &Value, subname: &str) -> PyResult<()> {
        let Value::Object(parent_module) = parent else {
            return Ok(());
        };

        if parent_module.as_module().is_some() {
            let dict = self.instance_dict(parent_module)?;
            return self.dict_set_str(&dict, subname, module.clone());
        }

        self.setattr_str(parent, subname, module.clone())
    }

    /// `ensure_fromlist`: imports submodules named in a `from` list.
    fn ensure_fromlist(&self, module: &Value, fromlist: &Value, buffer: &str, recursive: bool) -> PyResult<()> {
        if self.getattr_opt(module, &PyBytes::from("__path__"))?.is_none() {
            return Ok(());
        }

        for item in self.collect(fromlist)? {
            let Some(name) = item.as_bytes().map(|bytes| String::from_utf8_lossy(bytes).into_owned()) else {
                return Err(self.type_error("Item in ``from list'' not a string"));
            };

            if name == "*" {
                if recursive {
                    continue;
                }
                if let Some(all) = self.getattr_opt(module, &PyBytes::from("__all__"))? {
                    if !all.is_unknown() {
                        self.ensure_fromlist(module, &all, buffer, true)?;
                    }
                }
                continue;
            }

            if self.getattr_opt(module, &PyBytes::from(name.as_str()))?.is_some() {
                continue;
            }

            let fullname = format!("{buffer}.{name}");
            self.import_submodule(module, &name, &fullname)?;
        }

        Ok(())
    }

    fn opaque_module(&self, name: &str) -> PyResult<Value> {
        let module = self.new_module(name, ModuleKind::Opaque)?;
        if let Some(data) = module.as_module() {
            data.state.set(ModuleState::Ready);
        }

        let value = Value::Object(module);
        self.dict_set_str(self.modules(), name, value.clone())?;
        self.import_records.borrow_mut().push(ImportRecord { module: name.to_owned(), failure: Some("not found in the module source; treated as a native client module".to_owned()) });

        Ok(value)
    }

    fn load_native(&self, name: &str, init: crate::interp::vm::NativeModuleInit) -> PyResult<Value> {
        let module = self.new_module(name, ModuleKind::Native)?;
        let value = Value::Object(Rc::clone(&module));
        self.dict_set_str(self.modules(), name, value.clone())?;
        crate::interp::builtins::docs::document_module(self, &module)?;

        init(self, &module)?;
        if let Some(data) = module.as_module() {
            data.state.set(ModuleState::Ready);
        }

        Ok(value)
    }

    /// Executes the bytecode of a source module or package. A
    /// module body that stops early stays in `sys.modules` marked
    /// incomplete instead of raising ImportError in the importer, so code
    /// that never touches the missing parts keeps running.
    fn load_source(&self, name: &str) -> PyResult<Value> {
        let Some(source) = self.source().find(name) else {
            return Err(self.raise(ExceptionKind::ImportError, &format!("No module named {name}")));
        };

        let module = self.new_module(name, ModuleKind::Source)?;
        let value = Value::Object(Rc::clone(&module));
        let dict = self.instance_dict(&module)?;

        if source.is_package {
            let directory = source.filename.rsplit_once('/').map(|(directory, _)| directory.to_owned()).unwrap_or_default();
            let path = self.new_list(vec![Value::str(&directory)]);
            self.dict_set_str(&dict, "__path__", path)?;
        }

        self.dict_set_str(self.modules(), name, value.clone())?;

        let code_object = match crate::interp::marshal::load_code(self, &source.code) {
            Ok(code_object) => code_object,
            Err(error) => {
                self.mark_incomplete(&module, name, format!("unmarshal failed: {error}"));
                return Ok(value);
            }
        };
        let Payload::Code(code) = &code_object.payload else {
            self.mark_incomplete(&module, name, "unmarshal produced a non-code object".to_owned());
            return Ok(value);
        };

        if self.dict_get_str(&dict, "__builtins__")?.is_none() {
            self.dict_set_str(&dict, "__builtins__", Value::Object(self.builtins_dict()))?;
        }
        self.dict_set_str(&dict, "__file__", Value::str(&source.filename))?;

        let mut frame = Frame::new(Rc::clone(code), Rc::clone(&code_object), Rc::clone(&dict), self.builtins_dict(), Some(Rc::clone(&dict)), Vec::new());
        match self.execute_frame(&mut frame) {
            Ok(_) => {
                if let Some(data) = module.as_module() {
                    data.state.set(ModuleState::Ready);
                }
                self.import_records.borrow_mut().push(ImportRecord { module: name.to_owned(), failure: None });
            }
            Err(Signal::Raise(exception)) => {
                self.take_trace();
                let traceback = self.take_traceback(&exception);
                *self.native_state::<LastFailure>().0.borrow_mut() = Some((exception.clone(), traceback.clone().unwrap_or(Value::None)));
                let detail = match traceback {
                    Some(traceback) => {
                        let frames: Vec<String> = self.traceback_entries(&traceback).into_iter().rev().map(|(file, line, function)| format!("{file}:{line} in {function}")).collect();
                        format!("{} at {}", self.describe_exception(&exception), frames.join(" <- "))
                    }
                    None => self.describe_exception(&exception),
                };
                self.mark_incomplete(&module, name, detail);
            }
            Err(Signal::Halt(halt)) => {
                let detail = format!("{halt} at {}", self.take_trace().join(" <- "));
                self.mark_incomplete(&module, name, detail);
            }
        }

        Ok(self.dict_get_str(self.modules(), name)?.unwrap_or(value))
    }

    fn mark_incomplete(&self, module: &ObjectRef, name: &str, detail: String) {
        if let Some(data) = module.as_module() {
            data.state.set(ModuleState::Incomplete);
        }
        if let Some(dict) = module.dict() {
            self.mark_opaque_names(&dict);
        }

        self.import_records.borrow_mut().push(ImportRecord { module: name.to_owned(), failure: Some(detail) });
    }

    /// `IMPORT_FROM`.
    pub fn import_from(&self, module: &Value, name: &PyBytes) -> PyResult<Value> {
        match self.getattr_opt(module, name)? {
            Some(value) => Ok(value),
            None => Err(self.raise(ExceptionKind::ImportError, &format!("cannot import name {}", name.to_string_lossy()))),
        }
    }

    /// `IMPORT_STAR`. Names from an opaque or incomplete module cannot be
    /// enumerated, so lookups of unbound names in the importing namespace
    /// read as unknown afterwards.
    pub fn import_star(&self, module: &Value, locals: &ObjectRef) -> PyResult<()> {
        let Value::Object(module_object) = module else {
            if module.is_unknown() {
                self.mark_opaque_names(locals);
                return Ok(());
            }
            return Err(self.type_error("import * from a non-module"));
        };

        if let Some(data) = module_object.as_module() {
            if data.missing_is_unknown() {
                self.mark_opaque_names(locals);
            }
        }

        let names = match self.getattr_opt(module, &PyBytes::from("__all__"))? {
            Some(all) if !all.is_unknown() => self.collect(&all)?,
            _ => {
                let dict = self.getattr_str(module, "__dict__")?;
                let Value::Object(dict) = dict else {
                    return Ok(());
                };
                self.dict_keys(&dict)?.into_iter().filter(|key| !key.as_bytes().is_some_and(|bytes| bytes.starts_with(b"_"))).collect()
            }
        };

        for name in names {
            let attribute = crate::interp::builtins::core::name_arg(self, &name)?;
            let value = self.getattr(module, &attribute)?;
            self.mapping_store(locals, Value::Str(attribute), value)?;
        }

        Ok(())
    }
}

/// The exception and traceback of the last module whose execution failed.
#[derive(Default)]
struct LastFailure(std::cell::RefCell<Option<(Value, Value)>>);
