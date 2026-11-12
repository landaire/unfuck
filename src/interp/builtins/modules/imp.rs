//! The `imp` module of the Windows build. Functions that search or load
//! files halt, since the interpreter imports through its own module source
//! rather than the host filesystem.

use std::cell::Cell;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::time::no_arguments;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::ModuleKind;
use crate::interp::object::ModuleState;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The builtin module table of the x64 build. Entries without an init
/// function cannot be reinitialized.
const BUILTIN_MODULES: &[(&str, bool)] = &[
    ("array", true),
    ("_ast", true),
    ("audioop", true),
    ("binascii", true),
    ("cmath", true),
    ("errno", true),
    ("future_builtins", true),
    ("gc", true),
    ("imageop", true),
    ("math", true),
    ("_md5", true),
    ("nt", true),
    ("operator", true),
    ("signal", true),
    ("_sha", true),
    ("_sha256", true),
    ("_sha512", true),
    ("strop", true),
    ("time", true),
    ("thread", true),
    ("cStringIO", true),
    ("cPickle", true),
    ("msvcrt", true),
    ("_locale", true),
    ("_subprocess", true),
    ("_codecs", true),
    ("_weakref", true),
    ("_hotshot", true),
    ("_random", true),
    ("_bisect", true),
    ("_heapq", true),
    ("_lsprof", true),
    ("itertools", true),
    ("_collections", true),
    ("_symtable", true),
    ("mmap", true),
    ("_csv", true),
    ("_sre", true),
    ("parser", true),
    ("_winreg", true),
    ("_struct", true),
    ("datetime", true),
    ("_functools", true),
    ("_json", true),
    ("xxsubtype", true),
    ("zipimport", true),
    ("zlib", true),
    ("_multibytecodec", true),
    ("_codecs_cn", true),
    ("_codecs_hk", true),
    ("_codecs_iso2022", true),
    ("_codecs_jp", true),
    ("_codecs_kr", true),
    ("_codecs_tw", true),
    ("marshal", true),
    ("imp", true),
    ("__main__", false),
    ("__builtin__", false),
    ("sys", false),
    ("exceptions", false),
    ("_warnings", true),
    ("_io", true),
];

/// The frozen test modules every build carries.
const FROZEN_MODULES: [&str; 3] = ["__hello__", "__phello__", "__phello__.spam"];

/// Recursion depth of the import lock taken through `acquire_lock`. The
/// interpreter's own imports do not take it.
#[derive(Default)]
struct ImportLock {
    level: Cell<usize>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("reload", imp_unsupported_reload),
            function("find_module", imp_unsupported_find_module),
            function("get_magic", imp_get_magic),
            function("get_suffixes", imp_get_suffixes),
            function("load_module", imp_unsupported_load_module),
            function("new_module", imp_new_module),
            function("lock_held", imp_lock_held),
            function("acquire_lock", imp_acquire_lock),
            function("release_lock", imp_release_lock),
            function("get_frozen_object", imp_unsupported_get_frozen_object),
            function("init_builtin", imp_unsupported_init_builtin),
            function("init_frozen", imp_unsupported_init_frozen),
            function("is_builtin", imp_is_builtin),
            function("is_frozen", imp_is_frozen),
            function("load_compiled", imp_unsupported_load_compiled),
            function("load_dynamic", imp_unsupported_load_dynamic),
            function("load_package", imp_unsupported_load_package),
            function("load_source", imp_unsupported_load_source),
        ],
    )?;

    let constants = [
        ("SEARCH_ERROR", 0),
        ("PY_SOURCE", 1),
        ("PY_COMPILED", 2),
        ("C_EXTENSION", 3),
        ("PY_RESOURCE", 4),
        ("PKG_DIRECTORY", 5),
        ("C_BUILTIN", 6),
        ("PY_FROZEN", 7),
        ("PY_CODERESOURCE", 8),
        ("IMP_HOOK", 9),
    ];
    for (name, value) in constants {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    set_attribute(
        vm,
        module,
        "NullImporter",
        Value::Object(native_type(
            vm,
            "imp.NullImporter",
            create_null_importer_type,
        )?),
    )?;

    Ok(())
}

fn create_null_importer_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name: "NullImporter",
            module: "imp",
            base: None,
            layout: Layout::Object,
            instance_dict: false,
            methods: &[
                method("__init__", null_importer_init),
                method("find_module", null_importer_find_module),
            ],
        },
    )
}

/// A `char*` argument (format `s`); `None` when unknown.
fn string_argument(
    vm: &Vm,
    value: &Value,
    function: &str,
    position: usize,
) -> PyResult<Option<PyBytes>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let bytes = match vm.as_str_bytes(value) {
        Some(bytes) => bytes,
        None => match vm.as_text(value) {
            Some(text) if text.units().iter().all(|unit| *unit < 0x80) => PyBytes::new(
                text.units()
                    .iter()
                    .map(|unit| *unit as u8)
                    .collect::<Vec<u8>>(),
            ),
            Some(_) => {
                return Err(
                    vm.halt_unsupported(format!("{function}() with a non-ASCII unicode argument"))
                );
            }
            None => {
                let given = if value.is_none() {
                    "None".to_owned()
                } else {
                    vm.type_name(value)
                };
                return Err(vm.type_error(&format!(
                    "{function}() argument {position} must be string, not {given}"
                )));
            }
        },
    };
    if bytes.as_bytes().contains(&0) {
        return Err(vm.type_error(&format!(
            "{function}() argument {position} must be string without null bytes, not {}",
            vm.type_name(value)
        )));
    }

    Ok(Some(bytes))
}

/// The single `s` argument of a varargs function.
fn single_string(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Option<PyBytes>> {
    let args = positional(vm, args, function, 1, 1)?;

    string_argument(vm, &args[0], function, 1)
}

fn imp_get_magic(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_magic")?;

    Ok(Value::Str(PyBytes::new(*b"\x03\xf3\r\n")))
}

/// `imp.get_suffixes`: the extension module suffixes of the Windows build,
/// then the source and bytecode suffixes.
fn imp_get_suffixes(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_suffixes")?;

    let suffixes = [
        (".pyd", "rb", 3),
        (".py", "U", 1),
        (".pyw", "U", 1),
        (".pyc", "rb", 2),
    ];
    let items = suffixes
        .into_iter()
        .map(|(suffix, mode, kind)| {
            Value::tuple(vec![Value::str(suffix), Value::str(mode), Value::Int(kind)])
        })
        .collect();

    Ok(vm.new_list(items))
}

fn imp_new_module(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(name) = single_string(vm, args, "new_module")? else {
        return Ok(Value::unknown("imp.new_module() with an unknown name"));
    };

    let module = vm.new_module(&name.to_string_lossy(), ModuleKind::Source)?;
    if let Some(data) = module.as_module() {
        data.state.set(ModuleState::Ready);
    }

    Ok(Value::Object(module))
}

fn imp_lock_held(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "lock_held")?;

    Ok(Value::Bool(vm.native_state::<ImportLock>().level.get() > 0))
}

fn imp_acquire_lock(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "acquire_lock")?;

    let lock = vm.native_state::<ImportLock>();
    lock.level.set(lock.level.get() + 1);

    Ok(Value::None)
}

fn imp_release_lock(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "release_lock")?;

    let lock = vm.native_state::<ImportLock>();
    let Some(level) = lock.level.get().checked_sub(1) else {
        return Err(vm.raise(ExceptionKind::RuntimeError, "not holding the import lock"));
    };
    lock.level.set(level);

    Ok(Value::None)
}

/// `is_builtin`: 1 for modules with an init function, -1 for those that
/// cannot be reinitialized, 0 otherwise.
fn imp_is_builtin(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(name) = single_string(vm, args, "is_builtin")? else {
        return Ok(Value::unknown("imp.is_builtin() with an unknown name"));
    };

    let result = match BUILTIN_MODULES
        .iter()
        .find(|(builtin, _)| builtin.as_bytes() == name.as_bytes())
    {
        Some((_, true)) => 1,
        Some((_, false)) => -1,
        None => 0,
    };

    Ok(Value::Int(result))
}

fn imp_is_frozen(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(name) = single_string(vm, args, "is_frozen")? else {
        return Ok(Value::unknown("imp.is_frozen() with an unknown name"));
    };

    Ok(Value::Bool(
        FROZEN_MODULES
            .iter()
            .any(|frozen| frozen.as_bytes() == name.as_bytes()),
    ))
}

/// `NullImporter.__init__`: whether a nonempty path names a directory depends
/// on the host filesystem.
fn null_importer_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, args) = crate::interp::builtins::receiver(vm, args, "__init__")?;
    if args.has_keywords() {
        return Err(vm.type_error("NullImporter() does not take keyword arguments"));
    }

    let Some(path) = single_string(vm, args, "NullImporter")? else {
        return Err(vm.halt_unsupported("imp.NullImporter() of an unknown path"));
    };
    if path.as_bytes().is_empty() {
        return Err(vm.raise(ExceptionKind::ImportError, "empty pathname"));
    }

    vm.host_permit(HostCapability::FileSystem, Denial::Native, None)?;
    Err(vm.halt_unsupported("imp.NullImporter() of a filesystem path"))
}

fn null_importer_find_module(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    crate::interp::builtins::receiver(vm, args, "find_module")?;

    Ok(Value::None)
}

fn imp_unsupported_reload(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("imp.reload"))
}

fn imp_unsupported_find_module(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::FileSystem, Denial::Native, None)?;
    Err(vm.halt_unsupported("imp.find_module searches the host filesystem"))
}

fn imp_unsupported_load_module(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::FileSystem, Denial::Crt, args.positional.get(2))?;
    Err(vm.halt_unsupported("imp.load_module reads a host file"))
}

fn imp_unsupported_get_frozen_object(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("imp.get_frozen_object"))
}

fn imp_unsupported_init_builtin(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("imp.init_builtin"))
}

fn imp_unsupported_init_frozen(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("imp.init_frozen"))
}

fn imp_unsupported_load_compiled(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::FileSystem, Denial::Crt, args.positional.get(1))?;
    Err(vm.halt_unsupported("imp.load_compiled reads a host file"))
}

fn imp_unsupported_load_dynamic(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::DynamicLoading, Denial::Native, None)?;
    Err(vm.halt_unsupported("imp.load_dynamic loads a host extension module"))
}

fn imp_unsupported_load_package(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::FileSystem, Denial::Native, None)?;
    Err(vm.halt_unsupported("imp.load_package reads host files"))
}

fn imp_unsupported_load_source(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    vm.host_permit(HostCapability::FileSystem, Denial::Crt, args.positional.get(1))?;
    Err(vm.halt_unsupported("imp.load_source reads a host file"))
}
