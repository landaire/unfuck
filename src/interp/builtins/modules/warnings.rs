//! The `_warnings` module. Filtering, the registries, and display through
//! `warnings.showwarning` follow CPython; a warning without `showwarning`
//! is written to `sys.stderr`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::arguments;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Access;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The module's own `filters`, `onceregistry`, and `default_action`, which
/// track the `warnings` module attributes whenever they are read.
struct WarningsState {
    filters: RefCell<Value>,
    once_registry: RefCell<Value>,
    default_action: RefCell<Value>,
}

impl Default for WarningsState {
    /// Placeholders until `init` stores the module's objects.
    fn default() -> Self {
        Self {
            filters: RefCell::new(Value::None),
            once_registry: RefCell::new(Value::None),
            default_action: RefCell::new(Value::None),
        }
    }
}

/// The matching filter's action and the filter itself.
struct FilterMatch {
    action: Vec<u8>,
    item: Option<Value>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("warn", warnings_warn),
            function("warn_explicit", warnings_warn_explicit),
        ],
    )?;

    let filter = |kind: ExceptionKind| {
        Value::tuple(vec![
            Value::str("ignore"),
            Value::None,
            Value::Object(Rc::clone(vm.types().exception(kind))),
            Value::None,
            Value::Int(0),
        ])
    };
    let filters = vm.new_list(vec![
        filter(ExceptionKind::DeprecationWarning),
        filter(ExceptionKind::PendingDeprecationWarning),
        filter(ExceptionKind::ImportWarning),
        filter(ExceptionKind::BytesWarning),
    ]);
    let once_registry = Value::Object(vm.new_dict());
    let default_action = Value::str("default");

    set_attribute(vm, module, "filters", filters.clone())?;
    set_attribute(vm, module, "once_registry", once_registry.clone())?;
    set_attribute(vm, module, "default_action", default_action.clone())?;

    let state = vm.native_state::<WarningsState>();
    *state.filters.borrow_mut() = filters;
    *state.once_registry.borrow_mut() = once_registry;
    *state.default_action.borrow_mut() = default_action;

    Ok(())
}

/// An attribute of `sys.modules['warnings']`.
fn warnings_attribute(vm: &Vm, name: &str) -> PyResult<Option<Value>> {
    let Some(module) = vm.dict_get_str(vm.modules(), "warnings")? else {
        return Ok(None);
    };

    vm.getattr_opt(&module, &vm.name(name))
}

/// The module state. CPython sets it up at startup; here the `_warnings`
/// module is imported on first use instead, so a warning issued before
/// anything imported it (for example by the compiler) sees the startup
/// filters.
fn state(vm: &Vm) -> PyResult<Rc<WarningsState>> {
    if vm.native_state::<WarningsState>().filters.borrow().is_none() {
        vm.import_module("_warnings")?;
    }

    Ok(vm.native_state::<WarningsState>())
}

/// The string of a filter action.
fn action_text(vm: &Vm, action: &Value) -> PyResult<Vec<u8>> {
    if action.is_unknown() {
        return Err(vm.halt_unsupported("warnings filter with an unknown action"));
    }
    if let Some(bytes) = vm.as_str_bytes(action) {
        return Ok(bytes.as_bytes().to_vec());
    }
    if let Some(text) = vm.as_text(action)
        && text.units().iter().all(|unit| *unit < 0x80)
    {
        return Ok(text.units().iter().map(|unit| *unit as u8).collect());
    }

    Err(vm.type_error(&format!(
        "expected string or Unicode object, {} found",
        vm.type_name(action)
    )))
}

/// Whether a filter's regular expression matches.
fn check_matched(vm: &Vm, pattern: &Value, subject: &Value) -> PyResult<bool> {
    if pattern.is_none() {
        return Ok(true);
    }

    let result = vm.call_method(pattern, "match", vec![subject.clone()])?;

    vm.truthy(&result, "warnings filter match")
}


/// The filter that applies to a warning.
fn get_filter(vm: &Vm, category: &Value, text: &Value, lineno: i64, module: &Value) -> PyResult<FilterMatch> {
    let state = state(vm)?;
    if let Some(filters) = warnings_attribute(vm, "filters")? {
        *state.filters.borrow_mut() = filters;
    }
    let filters = state.filters.borrow().clone();

    let mut index = 0;
    loop {
        // The filter list may change while filters are being matched.
        let Some(items) = vm.as_list(&filters) else {
            return Err(vm.raise(
                ExceptionKind::ValueError,
                "_warnings.filters must be a list",
            ));
        };
        let Some(item) = items.get(index).cloned() else {
            break;
        };

        let Some(fields) = vm.as_tuple(&item).filter(|fields| fields.len() == 5) else {
            return Err(vm.raise(
                ExceptionKind::ValueError,
                &format!("_warnings.filters item {index} isn't a 5-tuple"),
            ));
        };
        let [action, message, filter_category, module_pattern, line] = &*fields else {
            return Err(vm.raise(
                ExceptionKind::ValueError,
                &format!("_warnings.filters item {index} isn't a 5-tuple"),
            ));
        };

        let good_message = check_matched(vm, message, text)?;
        let good_module = check_matched(vm, module_pattern, module)?;
        let is_subclass = vm.issubclass(category, filter_category)?;
        let Some(filter_line) = vm.as_index(line) else {
            return Err(vm.type_error("an integer is required"));
        };

        if good_message && is_subclass && good_module && (filter_line == 0 || lineno == filter_line) {
            return Ok(FilterMatch { action: action_text(vm, action)?, item: Some(item) });
        }

        index += 1;
    }

    if let Some(action) = warnings_attribute(vm, "defaultaction")? {
        *state.default_action.borrow_mut() = action;
    }
    let action = state.default_action.borrow().clone();

    Ok(FilterMatch {
        action: action_text(vm, &action)?,
        item: None,
    })
}

/// `warnings.onceregistry`.
fn once_registry(vm: &Vm) -> PyResult<ObjectRef> {
    let state = state(vm)?;
    if let Some(registry) = warnings_attribute(vm, "onceregistry")? {
        if dict_of(&registry).is_none() {
            return Err(vm.type_error("warnings.onceregistry must be a dict"));
        }
        *state.once_registry.borrow_mut() = registry;
    }

    let registry = state.once_registry.borrow().clone();
    dict_of(&registry).ok_or_else(|| vm.type_error("warnings.onceregistry must be a dict"))
}

/// The dict behind a `dict` or dict subclass value.
fn dict_of(value: &Value) -> Option<ObjectRef> {
    match value {
        Value::Object(object) if matches!(object.payload, Payload::Dict(_)) => {
            Some(Rc::clone(object))
        }
        _ => None,
    }
}

/// Whether `registry[key]` is true, optionally recording
/// the key when it is not.
fn already_warned(vm: &Vm, registry: &ObjectRef, key: Value, should_set: bool) -> PyResult<bool> {
    if let Some(flag) = vm.dict_get(registry, &key)?
        && vm.truthy(&flag, "warning registry entry")?
    {
        return Ok(true);
    }

    if should_set {
        vm.dict_set(registry, key, Value::Bool(true))?;
    }

    Ok(false)
}

/// Where a warning comes from (the calling frame or the explicit arguments).
struct Origin {
    filename: Value,
    lineno: i64,
    module: Value,
    /// `None` keeps no registry; "once" warnings then use the once
    /// registry.
    registry: Option<ObjectRef>,
    /// The source line shown when `showwarning` is absent.
    source_line: Option<Value>,
}

/// `warn_explicit`.
fn warn_explicit(vm: &Vm, category: Value, message: Value, origin: Origin) -> PyResult<Value> {
    let warning_class = Value::Object(Rc::clone(vm.types().exception(ExceptionKind::Warning)));
    let (category, message, text) = if vm.isinstance(&message, &warning_class)? {
        let text = vm.to_str(&message)?;
        (Value::Object(vm.class_of(&message)), message, text)
    } else {
        let instance = vm.call1(&category, message.clone())?;
        (category, instance, message)
    };

    let lineno = Value::Int(origin.lineno);
    let key = Value::tuple(vec![text.clone(), category.clone(), lineno.clone()]);
    if let Some(registry) = &origin.registry
        && already_warned(vm, registry, key.clone(), false)?
    {
        return Ok(Value::None);
    }

    let filter = get_filter(vm, &category, &text, origin.lineno, &origin.module)?;
    if filter.action == b"error" {
        return Err(Signal::Raise(message));
    }

    let mut already = false;
    if filter.action != b"always" {
        if let Some(registry) = &origin.registry {
            vm.dict_set(registry, key, Value::Bool(true))?;
        }
        match filter.action.as_slice() {
            b"ignore" => return Ok(Value::None),
            b"once" => {
                let registry = match &origin.registry {
                    Some(registry) => Rc::clone(registry),
                    None => once_registry(vm)?,
                };
                already = already_warned(vm, &registry, Value::tuple(vec![text.clone(), category.clone()]), true)?;
            }
            b"module" => {
                if let Some(registry) = &origin.registry {
                    already = already_warned(vm, registry, Value::tuple(vec![text.clone(), category.clone()]), true)?;
                }
            }
            b"default" => {}
            action => {
                let item = match filter.item {
                    Some(item) => vm.text_of(&vm.to_str(&item)?).unwrap_or_default(),
                    None => "None".to_owned(),
                };
                let action = String::from_utf8_lossy(action);
                return Err(vm.raise(ExceptionKind::RuntimeError, &format!("Unrecognized action ({action}) in warnings.filters:\n {item}")));
            }
        }
    }
    if already {
        return Ok(Value::None);
    }

    match warnings_attribute(vm, "showwarning")? {
        Some(show) => {
            let is_function = matches!(show.as_object().map(|object| &object.payload), Some(Payload::Function(_) | Payload::Method(_)));
            if !is_function {
                return Err(vm.type_error("warnings.showwarning() must be set to a function or method"));
            }
            if !stock_display_to_stderr(vm, &show, &message)? {
                vm.call(&show, CallArgs::new(vec![message, category, origin.filename, lineno]))?;
            }
        }
        None => show_warning(vm, &origin, &text, &category)?,
    }

    Ok(Value::None)
}

/// The display functions of `warnings` and `linecache` as their modules
/// defined them.
#[derive(Default)]
struct StockDisplay {
    functions: RefCell<Option<StockFunctions>>,
}

struct StockFunctions {
    show: Value,
    format: Value,
    linecache: Value,
    getline: Value,
    getlines: Value,
    updatecache: Value,
}

/// Import hook for `warnings`: records its display functions.
pub fn capture_stock_display(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let module = Value::Object(Rc::clone(module));
    let attribute = |owner: &Value, name: &str| vm.getattr_opt(owner, &vm.name(name));

    let Some(linecache) = attribute(&module, "linecache")? else {
        return Ok(());
    };
    let (Some(show), Some(format), Some(getline), Some(getlines), Some(updatecache)) = (
        attribute(&module, "showwarning")?,
        attribute(&module, "formatwarning")?,
        attribute(&linecache, "getline")?,
        attribute(&linecache, "getlines")?,
        attribute(&linecache, "updatecache")?,
    ) else {
        return Ok(());
    };

    *vm.native_state::<StockDisplay>().functions.borrow_mut() = Some(StockFunctions { show, format, linecache, getline, getlines, updatecache });

    Ok(())
}

/// Whether `show` would run the stock `showwarning`, `formatwarning`, and
/// `linecache` code to write a builtin warning to a standard stream. That
/// output cannot be observed, and `linecache` would read the source line
/// from the host file system, so the call is skipped.
fn stock_display_to_stderr(vm: &Vm, show: &Value, message: &Value) -> PyResult<bool> {
    let state = vm.native_state::<StockDisplay>();
    let stock = state.functions.borrow();
    let Some(stock) = stock.as_ref() else {
        return Ok(false);
    };
    let Some(module) = vm.dict_get_str(vm.modules(), "warnings")? else {
        return Ok(false);
    };
    let attribute = |owner: &Value, name: &str| vm.getattr_opt(owner, &vm.name(name));
    let same = |current: Option<Value>, original: &Value| current.is_some_and(|current| vm.is_same(&current, original));

    if !vm.is_same(show, &stock.show)
        || !same(attribute(&module, "formatwarning")?, &stock.format)
        || !same(attribute(&module, "linecache")?, &stock.linecache)
        || !same(attribute(&stock.linecache, "getline")?, &stock.getline)
        || !same(attribute(&stock.linecache, "getlines")?, &stock.getlines)
        || !same(attribute(&stock.linecache, "updatecache")?, &stock.updatecache)
    {
        return Ok(false);
    }

    // `formatwarning` calls `str(message)`, which may run Python code.
    let str_method = attribute(&Value::Object(vm.class_of(message)), "__str__")?;
    if str_method.is_some_and(|method| matches!(method.as_object().map(|object| &object.payload), Some(Payload::Function(_) | Payload::Method(_)))) {
        return Ok(false);
    }

    let Some(sys) = attribute(&module, "sys")? else {
        return Ok(false);
    };
    let stderr = attribute(&sys, "stderr")?;

    Ok(stderr.is_some_and(|stderr| super::sys::is_standard_stream(&stderr)))
}

/// Prints `filename:lineno: category: text` on `sys.stderr`,
/// then the source line.
fn show_warning(vm: &Vm, origin: &Origin, text: &Value, category: &Value) -> PyResult<()> {
    let Ok(name) = vm.getattr_str(category, "__name__") else {
        return Ok(());
    };
    let Some(stderr) = vm.dict_get_str(vm.modules(), "sys")?.and_then(|sys| vm.getattr_str(&sys, "stderr").ok()) else {
        return Ok(());
    };

    // Write errors are cleared, as they are at the end of showing a warning.
    let write = |value: Value| -> PyResult<()> {
        match vm.call_method(&stderr, "write", vec![value]) {
            Ok(_) => Ok(()),
            Err(Signal::Raise(_)) => {
                vm.discard_traceback();
                Ok(())
            }
            Err(halt) => Err(halt),
        }
    };
    write(vm.to_str(&origin.filename)?)?;
    write(Value::str(&format!(":{}: ", origin.lineno)))?;
    write(vm.to_str(&name)?)?;
    write(Value::str(": "))?;
    write(vm.to_str(text)?)?;
    write(Value::str("\n"))?;

    match &origin.source_line {
        Some(line) => {
            let bytes = vm.as_str_bytes(line).map(|bytes| bytes.as_bytes().to_vec()).unwrap_or_default();
            let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|byte| matches!(byte, b' ' | b'\t' | b'\x0c')).collect();
            write(Value::Str(PyBytes::new(trimmed)))?;
            write(Value::str("\n"))?;
        }
        // Reading the source line reads the file from the host; the line only
        // matters when the stream is visible to Python code. A file that
        // cannot be read shows no line.
        None if super::sys::is_standard_stream(&stderr) => {}
        None if vm.host_access(HostCapability::FileSystem) == Access::Deny => {}
        None => return Err(vm.halt_unsupported("displaying a warning's source line from the host file system")),
    }

    Ok(())
}

/// The category of a warning: the message's class if it is a `Warning`, else `category` or `UserWarning`.
fn warning_category(vm: &Vm, message: &Value, category: Option<Value>) -> PyResult<Value> {
    let warning_class = Value::Object(Rc::clone(vm.types().exception(ExceptionKind::Warning)));
    let category = if vm.isinstance(message, &warning_class)? {
        Value::Object(vm.class_of(message))
    } else {
        category.unwrap_or_else(|| {
            Value::Object(Rc::clone(vm.types().exception(ExceptionKind::UserWarning)))
        })
    };

    if !vm.issubclass(&category, &warning_class)? {
        return Err(vm.raise(
            ExceptionKind::ValueError,
            "category is not a subclass of Warning",
        ));
    }

    Ok(category)
}

/// A `ssize_t` argument (format `n`); `None` when unknown.
fn ssize_argument(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    arguments::ssize_argument(vm, value).map(Some)
}

/// `warnings.warn`.
fn warnings_warn(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "warn", &["message", "category", "stacklevel"], 1, |vm, index, value| match index {
        2 => Ok(ssize_argument(vm, &value)?.map_or(value, Value::Int)),
        _ => Ok(value),
    })?;
    let [Some(message), category, stack_level] = <[Option<Value>; 3]>::try_from(slots).unwrap_or_default() else {
        return Err(vm.type_error("warn() takes at least 1 argument"));
    };
    let stack_level = match stack_level {
        Some(Value::Int(level)) => level,
        Some(_) => return Err(vm.halt_unsupported("warnings.warn with an unknown stack level")),
        None => 1,
    };

    let category = warning_category(vm, &message, category)?;

    do_warn(vm, category, message, stack_level)
}

/// Issues a warning from the frame `stack_level` calls up.
fn do_warn(vm: &Vm, category: Value, message: Value, stack_level: i64) -> PyResult<Value> {
    let origin = setup_context(vm, stack_level)?;

    warn_explicit(vm, category, message, origin)
}

/// The file, line, module, and `__warningregistry__` of
/// the frame `stack_level` calls up.
fn setup_context(vm: &Vm, stack_level: i64) -> PyResult<Origin> {
    let mut frame = vm.current_frame();
    let mut level = stack_level;
    loop {
        level -= 1;
        if level <= 0 {
            break;
        }
        let Some(current) = frame else {
            break;
        };
        frame = current.back();
    }

    let (globals, lineno) = match &frame {
        Some(activation) => (Rc::clone(&activation.globals), i64::from(activation.line_number())),
        None => {
            let sys = vm.import_module("sys")?;
            let Some(dict) = sys.as_object().and_then(|module| module.dict()) else {
                return Err(vm.type_error("sys has no dict"));
            };
            (dict, 1)
        }
    };

    let registry = match vm.dict_get_str(&globals, "__warningregistry__")? {
        Some(registry) => registry,
        None => {
            let registry = Value::Object(vm.new_dict());
            vm.dict_set_str(&globals, "__warningregistry__", registry.clone())?;
            registry
        }
    };
    let registry = dict_of(&registry);

    let module = vm.dict_get_str(&globals, "__name__")?.unwrap_or_else(|| Value::str("<string>"));

    let file = vm.dict_get_str(&globals, "__file__")?;
    let filename = match file.as_ref().and_then(|file| vm.as_str_bytes(file).map(|bytes| (file.clone(), bytes))) {
        Some((file, bytes)) => {
            let name = bytes.as_bytes();
            let compiled = name.len() >= 4 && name[name.len() - 4] == b'.' && name[name.len() - 3..name.len() - 1].eq_ignore_ascii_case(b"py") && matches!(name[name.len() - 1].to_ascii_lowercase(), b'c' | b'o');
            if compiled { Value::Str(PyBytes::new(name[..name.len() - 1].to_vec())) } else { file }
        }
        None if vm.as_str_bytes(&module).is_some_and(|name| name.as_bytes() == b"__main__") => main_filename(vm)?,
        None => module.clone(),
    };

    Ok(Origin { filename, lineno, module, registry, source_line: None })
}

/// The file name of `__main__`: `sys.argv[0]`, or `__main__` when that is
/// false or missing.
fn main_filename(vm: &Vm) -> PyResult<Value> {
    let sys = vm.import_module("sys")?;
    let argv = vm.getattr_opt(&sys, &vm.name("argv"))?;
    let first = argv.as_ref().and_then(|argv| vm.as_list(argv)).and_then(|items| items.first().cloned());
    let Some(first) = first else {
        return Ok(Value::str("__main__"));
    };

    Ok(if vm.truthy(&first, "sys.argv[0]")? { first } else { Value::str("__main__") })
}

/// CPython initializes `_warnings` at startup; its filters live in the
/// module state importing it creates.
fn ensure_initialized(vm: &Vm) -> PyResult<()> {
    vm.import_module("_warnings").map(drop)
}

/// A warning at stack level 1: attributed to the innermost Python frame.
pub(crate) fn warn_caller(vm: &Vm, category: ExceptionKind, text: &str) -> PyResult<()> {
    ensure_initialized(vm)?;
    let category = Value::Object(Rc::clone(vm.types().exception(category)));

    do_warn(vm, category, Value::str(text), 1).map(drop)
}

/// A warning at an explicit file name and line: the module is derived
/// from the file name and no registry is kept.
pub(crate) fn warn_explicit_at(vm: &Vm, category: ExceptionKind, text: &str, filename: &[u8], lineno: i32) -> PyResult<()> {
    ensure_initialized(vm)?;
    let category = Value::Object(Rc::clone(vm.types().exception(category)));
    let filename = Value::Str(PyBytes::new(filename));
    let module = normalize_module(vm, &filename)?;

    warn_explicit(vm, category, Value::str(text), Origin { filename, lineno: i64::from(lineno), module, registry: None, source_line: None }).map(drop)
}

/// The file name without a `.py` suffix.
fn normalize_module(vm: &Vm, filename: &Value) -> PyResult<Value> {
    if !vm.truthy(filename, "warn_explicit filename")? {
        return Ok(Value::str("<unknown>"));
    }

    let Some(bytes) = vm.as_str_bytes(filename) else {
        return Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(filename))));
    };

    Ok(match bytes.as_bytes().strip_suffix(b".py") {
        Some(stem) => Value::Str(PyBytes::new(stem.to_vec())),
        None => filename.clone(),
    })
}

/// `warnings.warn_explicit`. A `module_globals` whose `__loader__` has
/// `get_source` supplies the source line shown.
fn warnings_warn_explicit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "warn_explicit", &["message", "category", "filename", "lineno", "module", "registry", "module_globals"], 4, |vm, index, value| match index {
        3 => Ok(c_int(vm, &value)?.map_or(value, |lineno| Value::Int(i64::from(lineno)))),
        _ => Ok(value),
    })?;
    let [Some(message), Some(category), Some(filename), Some(lineno), module, registry, module_globals] = <[Option<Value>; 7]>::try_from(slots).unwrap_or_default() else {
        return Err(vm.type_error("warn_explicit() takes at least 4 arguments"));
    };

    let Value::Int(lineno) = lineno else {
        return Err(vm.halt_unsupported("_warnings.warn_explicit() with an unknown line"));
    };
    let Ok(lineno) = i32::try_from(lineno) else {
        return Err(vm.halt_unsupported("_warnings.warn_explicit() with an unknown line"));
    };

    let source_line = match module_globals.as_ref().and_then(dict_of) {
        Some(globals) => loader_source_line(vm, &globals, lineno)?,
        None => None,
    };

    let registry = match registry {
        None | Some(Value::None) => None,
        Some(registry) => match dict_of(&registry) {
            Some(dict) => Some(dict),
            None => return Err(vm.type_error("'registry' must be a dict")),
        },
    };

    let module = match module {
        Some(module) => module,
        None => normalize_module(vm, &filename)?,
    };

    warn_explicit(vm, category, message, Origin { filename, lineno: i64::from(lineno), module, registry, source_line })
}

/// The line `lineno` of the source `module_globals['__loader__']` reports
/// for the module, if it has a `get_source`.
fn loader_source_line(vm: &Vm, globals: &ObjectRef, lineno: i32) -> PyResult<Option<Value>> {
    let (Some(loader), Some(name)) = (vm.dict_get_str(globals, "__loader__")?, vm.dict_get_str(globals, "__name__")?) else {
        return Ok(None);
    };
    // A failing attribute lookup counts as absent.
    match vm.getattr_opt(&loader, &vm.name("get_source")) {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(None),
        Err(Signal::Raise(_)) => {
            vm.discard_traceback();
            return Ok(None);
        }
        Err(halt) => return Err(halt),
    }

    let source = vm.call_method(&loader, "get_source", vec![name])?;
    if source.is_none() {
        return Ok(None);
    }
    let splitlines = vm.getattr_str(&Value::Object(Rc::clone(&vm.types().str)), "splitlines")?;
    let lines = vm.call1(&splitlines, source)?;
    // List indexing here does not count from the end.
    if lineno < 1 {
        return Err(vm.raise(ExceptionKind::IndexError, "list index out of range"));
    }

    vm.getitem(&lines, &Value::Int(i64::from(lineno) - 1)).map(Some)
}
