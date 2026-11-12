//! The `_winreg` module. Arguments are checked as the Windows build parses
//! them; registry and environment results, including the keys the host
//! opens, are unknown.

use std::cell::Cell;
use std::rc::Rc;

use crate::interp::buffer::Segment;
use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::bind;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrong_receiver;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::host_arguments::exact;
use crate::interp::builtins::modules::host_arguments::from_void_pointer;
use crate::interp::builtins::modules::host_arguments::optional_string;
use crate::interp::builtins::modules::host_arguments::string;
use crate::interp::builtins::modules::host_arguments::unicode;
use crate::interp::builtins::modules::host_arguments::void_pointer;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::hash::hash_pointer;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const KEY_TYPE: &str = "PyHKEY";

/// The predefined keys of `winreg.h`, sign-extended `LONG` values.
const PREDEFINED_KEYS: [(&str, u64); 7] = [
    ("HKEY_CLASSES_ROOT", 0xFFFF_FFFF_8000_0000),
    ("HKEY_CURRENT_USER", 0xFFFF_FFFF_8000_0001),
    ("HKEY_LOCAL_MACHINE", 0xFFFF_FFFF_8000_0002),
    ("HKEY_USERS", 0xFFFF_FFFF_8000_0003),
    ("HKEY_PERFORMANCE_DATA", 0xFFFF_FFFF_8000_0004),
    ("HKEY_CURRENT_CONFIG", 0xFFFF_FFFF_8000_0005),
    ("HKEY_DYN_DATA", 0xFFFF_FFFF_8000_0006),
];

/// Module integer constants in insertion order, with the Windows
/// SDK `winnt.h` values the Visual C++ 2008 build compiles in.
const CONSTANTS: [(&str, i64); 41] = [
    ("KEY_QUERY_VALUE", 0x0001),
    ("KEY_SET_VALUE", 0x0002),
    ("KEY_CREATE_SUB_KEY", 0x0004),
    ("KEY_ENUMERATE_SUB_KEYS", 0x0008),
    ("KEY_NOTIFY", 0x0010),
    ("KEY_CREATE_LINK", 0x0020),
    ("KEY_READ", 0x2_0019),
    ("KEY_WRITE", 0x2_0006),
    ("KEY_EXECUTE", 0x2_0019),
    ("KEY_ALL_ACCESS", 0xF_003F),
    ("KEY_WOW64_64KEY", 0x0100),
    ("KEY_WOW64_32KEY", 0x0200),
    ("REG_OPTION_RESERVED", 0),
    ("REG_OPTION_NON_VOLATILE", 0),
    ("REG_OPTION_VOLATILE", 1),
    ("REG_OPTION_CREATE_LINK", 2),
    ("REG_OPTION_BACKUP_RESTORE", 4),
    ("REG_OPTION_OPEN_LINK", 8),
    ("REG_LEGAL_OPTION", 15),
    ("REG_CREATED_NEW_KEY", 1),
    ("REG_OPENED_EXISTING_KEY", 2),
    ("REG_WHOLE_HIVE_VOLATILE", 1),
    ("REG_REFRESH_HIVE", 2),
    ("REG_NO_LAZY_FLUSH", 4),
    ("REG_NOTIFY_CHANGE_NAME", 1),
    ("REG_NOTIFY_CHANGE_ATTRIBUTES", 2),
    ("REG_NOTIFY_CHANGE_LAST_SET", 4),
    ("REG_NOTIFY_CHANGE_SECURITY", 8),
    ("REG_LEGAL_CHANGE_FILTER", 15),
    ("REG_NONE", REG_NONE),
    ("REG_SZ", REG_SZ),
    ("REG_EXPAND_SZ", REG_EXPAND_SZ),
    ("REG_BINARY", 3),
    ("REG_DWORD", REG_DWORD),
    ("REG_DWORD_LITTLE_ENDIAN", REG_DWORD),
    ("REG_DWORD_BIG_ENDIAN", 5),
    ("REG_LINK", 6),
    ("REG_MULTI_SZ", REG_MULTI_SZ),
    ("REG_RESOURCE_LIST", 8),
    ("REG_FULL_RESOURCE_DESCRIPTOR", 9),
    ("REG_RESOURCE_REQUIREMENTS_LIST", 10),
];

const REG_NONE: i64 = 0;
const REG_SZ: i64 = 1;
const REG_EXPAND_SZ: i64 = 2;
const REG_DWORD: i64 = 4;
const REG_MULTI_SZ: i64 = 7;

/// A key object, holding the `HKEY` pointer value.
struct RegistryKey {
    handle: Cell<u64>,
}

impl_native_data!(RegistryKey, "PyHKEY");

/// `_winreg` functions in table order.
const FUNCTIONS: [MethodSpec; 23] = [
    function("CloseKey", close_key),
    function("ConnectRegistry", connect_registry),
    function("CreateKey", create_key),
    function("CreateKeyEx", create_key_ex),
    function("DeleteKey", delete_key),
    function("DeleteKeyEx", delete_key_ex),
    function("DeleteValue", delete_value),
    function("DisableReflectionKey", disable_reflection_key),
    function("EnableReflectionKey", enable_reflection_key),
    function("EnumKey", enum_key),
    function("EnumValue", enum_value),
    function("ExpandEnvironmentStrings", expand_environment_strings),
    function("FlushKey", flush_key),
    function("LoadKey", load_key),
    function("OpenKey", open_key),
    function("OpenKeyEx", open_key_ex),
    function("QueryValue", query_value),
    function("QueryValueEx", query_value_ex),
    function("QueryInfoKey", query_info_key),
    function("QueryReflectionKey", query_reflection_key),
    function("SaveKey", save_key),
    function("SetValue", set_value),
    function("SetValueEx", set_value_ex),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    set_attribute(vm, module, "HKEYType", Value::Object(key_type(vm)?))?;
    set_attribute(vm, module, "error", Value::Object(Rc::clone(vm.types().exception(ExceptionKind::WindowsError))))?;

    for (name, key) in PREDEFINED_KEYS {
        set_attribute(vm, module, name, from_void_pointer(key))?;
    }
    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }

    Ok(())
}

fn key_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_winreg.PyHKEY", create_key_type)
}

fn create_key_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: KEY_TYPE,
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("Close", key_close),
                method("Detach", key_detach),
                method("__enter__", key_enter),
                method("__exit__", key_exit),
                method("__int__", key_int),
                method("__nonzero__", key_nonzero),
                method("__str__", key_str),
                method("__hash__", key_hash),
                method("__cmp__", key_cmp),
                method("__neg__", |vm, args| key_unary(vm, args, "__neg__")),
                method("__pos__", |vm, args| key_unary(vm, args, "__pos__")),
                method("__abs__", |vm, args| key_unary(vm, args, "__abs__")),
                method("__invert__", |vm, args| key_unary(vm, args, "__invert__")),
                method("__long__", |vm, args| key_unary(vm, args, "__long__")),
                method("__float__", |vm, args| key_unary(vm, args, "__float__")),
                method("__oct__", |vm, args| key_unary(vm, args, "__oct__")),
                method("__hex__", |vm, args| key_unary(vm, args, "__hex__")),
                method("__add__", |vm, args| key_binary(vm, args, "__add__")),
                method("__radd__", |vm, args| key_binary(vm, args, "__radd__")),
                method("__sub__", |vm, args| key_binary(vm, args, "__sub__")),
                method("__rsub__", |vm, args| key_binary(vm, args, "__rsub__")),
                method("__mul__", |vm, args| key_binary(vm, args, "__mul__")),
                method("__rmul__", |vm, args| key_binary(vm, args, "__rmul__")),
                method("__div__", |vm, args| key_binary(vm, args, "__div__")),
                method("__rdiv__", |vm, args| key_binary(vm, args, "__rdiv__")),
                method("__mod__", |vm, args| key_binary(vm, args, "__mod__")),
                method("__rmod__", |vm, args| key_binary(vm, args, "__rmod__")),
                method("__divmod__", |vm, args| key_binary(vm, args, "__divmod__")),
                method("__rdivmod__", |vm, args| key_binary(vm, args, "__rdivmod__")),
                method("__lshift__", |vm, args| key_binary(vm, args, "__lshift__")),
                method("__rlshift__", |vm, args| key_binary(vm, args, "__rlshift__")),
                method("__rshift__", |vm, args| key_binary(vm, args, "__rshift__")),
                method("__rrshift__", |vm, args| key_binary(vm, args, "__rrshift__")),
                method("__and__", |vm, args| key_binary(vm, args, "__and__")),
                method("__rand__", |vm, args| key_binary(vm, args, "__rand__")),
                method("__xor__", |vm, args| key_binary(vm, args, "__xor__")),
                method("__rxor__", |vm, args| key_binary(vm, args, "__rxor__")),
                method("__or__", |vm, args| key_binary(vm, args, "__or__")),
                method("__ror__", |vm, args| key_binary(vm, args, "__ror__")),
                method("__pow__", |vm, args| key_power(vm, args, "__pow__")),
                method("__rpow__", |vm, args| key_power(vm, args, "__rpow__")),
            ],
        },
    )?;
    add_member(vm, &class, GetSet { name: "handle", owner: KEY_TYPE, get: key_handle, set: None })?;

    Ok(class)
}

/// The result of a function that opens a key: a key object on success,
/// `WindowsError` on failure, as the host decides.
fn host_key(vm: &Vm, function: &str) -> PyResult<Value> {
    vm.host_operation(HostCapability::Registry, format!("_winreg.{function}() key (host registry)"))
}

/// The receiver of a key operator and the remaining arguments.
fn key_receiver(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    let (receiver, rest) = bind(vm, args, method, KEY_TYPE)?;
    if native_data::<RegistryKey>(&receiver).is_none() {
        return Err(wrong_receiver(vm, method, KEY_TYPE, &receiver));
    }

    Ok((receiver, rest))
}

fn registry_key(value: &Value) -> Option<&RegistryKey> {
    native_data::<RegistryKey>(value)
}

/// Closes a key: `RegCloseKey` runs for an open handle.
fn close_handle(vm: &Vm, key: &RegistryKey) -> PyResult<Value> {
    if key.handle.get() == 0 {
        return Ok(Value::None);
    }
    vm.host_permit(HostCapability::Registry, Denial::Native, None)?;
    key.handle.set(0);

    Ok(Value::unknown("_winreg RegCloseKey (host registry)"))
}

fn close(vm: &Vm, value: &Value) -> PyResult<Value> {
    if value.is_unknown() {
        return vm.host_operation(HostCapability::Registry, "_winreg.CloseKey() (unknown key)");
    }
    let Some(key) = registry_key(value) else {
        return Err(vm.type_error("bad operand type"));
    };

    close_handle(vm, key)
}

fn key_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let key = this::<RegistryKey>(vm, &args, KEY_TYPE, "Close")?;
    method_arguments(vm, &args, "Close", 0, 0)?;

    close_handle(vm, key)
}

fn key_detach(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let key = this::<RegistryKey>(vm, &args, KEY_TYPE, "Detach")?;
    method_arguments(vm, &args, "Detach", 0, 0)?;

    let previous = key.handle.replace(0);

    Ok(from_void_pointer(previous))
}

fn key_enter(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__enter__")?;
    no_arguments(vm, &rest, "__enter__")?;

    Ok(receiver)
}

/// `__exit__` ignores its arguments.
fn key_exit(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let key = this::<RegistryKey>(vm, &args, KEY_TYPE, "__exit__")?;
    if args.has_keywords() {
        return Err(vm.type_error("__exit__() takes no keyword arguments"));
    }

    close_handle(vm, key)
}

/// The `handle` member, a signed pointer-sized integer.
fn key_handle(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(key) = registry_key(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Int(key.handle.get() as i64))
}

fn key_int(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__int__")?;
    wrapper_arguments(vm, rest, 0)?;
    let Some(key) = registry_key(&receiver) else {
        return Err(wrong_receiver(vm, "__int__", KEY_TYPE, &receiver));
    };

    Ok(from_void_pointer(key.handle.get()))
}

fn key_nonzero(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__nonzero__")?;
    wrapper_arguments(vm, rest, 0)?;
    let Some(key) = registry_key(&receiver) else {
        return Err(wrong_receiver(vm, "__nonzero__", KEY_TYPE, &receiver));
    };

    Ok(Value::Bool(key.handle.get() != 0))
}

/// The `str` of a key: `%p` of the Visual C++ CRT, prefixed with `0x`.
fn key_str(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__str__")?;
    wrapper_arguments(vm, rest, 0)?;
    let Some(key) = registry_key(&receiver) else {
        return Err(wrong_receiver(vm, "__str__", KEY_TYPE, &receiver));
    };

    let pointer = key.handle.get();

    Ok(Value::str(&format!("<PyHKEY:0x{pointer:016X}>")))
}

/// The hash of a key: the object address.
fn key_hash(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__hash__")?;
    wrapper_arguments(vm, rest, 0)?;
    let Value::Object(object) = &receiver else {
        return Err(wrong_receiver(vm, "__hash__", KEY_TYPE, &receiver));
    };

    Ok(Value::Int(hash_pointer(vm.config.long_width, vm.address_of(object)).value()))
}

/// Keys compare by object address. Other operands fall back to the
/// default comparison, as CPython uses the key comparison only for two
/// keys.
fn key_cmp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (receiver, rest) = key_receiver(vm, args, "__cmp__")?;
    let [other] = wrapper_arguments(vm, rest, 1)?.try_into().map_err(|_| vm.type_error("expected 1 arguments"))?;
    let (Value::Object(left), Value::Object(right)) = (&receiver, &other) else {
        return Ok(Value::NotImplemented);
    };
    if registry_key(&other).is_none() {
        return Ok(Value::NotImplemented);
    }

    let ordering = vm.address_of(left).cmp(&vm.address_of(right));

    Ok(Value::Int(ordering as i64))
}

/// The unary operators of a key, which fail.
fn key_unary(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    let (_, rest) = key_receiver(vm, args, method)?;
    wrapper_arguments(vm, rest, 0)?;

    Err(vm.type_error("bad operand type"))
}

/// The binary operators of a key, which fail. The type does not coerce
/// mixed operands, so the operator only runs when both operands are keys;
/// otherwise it returns `NotImplemented`.
fn key_binary(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    let (_, rest) = key_receiver(vm, args, method)?;
    let [other] = wrapper_arguments(vm, rest, 1)?.try_into().map_err(|_| vm.type_error("expected 1 arguments"))?;
    if registry_key(&other).is_none() {
        return Ok(Value::NotImplemented);
    }

    Err(vm.type_error("bad operand type"))
}

/// The ternary operator of a key, which fails, reached for `**` only when
/// every operand is a key or the modulus is absent.
fn key_power(vm: &Vm, args: CallArgs, method: &str) -> PyResult<Value> {
    let (_, rest) = key_receiver(vm, args, method)?;
    if rest.has_keywords() {
        return Err(vm.type_error(&format!("wrapper {method} doesn't take keyword arguments")));
    }
    let operands = rest.positional;
    let (other, modulus) = match operands.as_slice() {
        [other] => (other, None),
        [other, modulus] => (other, Some(modulus)),
        _ => return Err(vm.type_error(&format!("expected 1 or 2 arguments, got {}", operands.len()))),
    };
    let modulus_is_key = modulus.is_none_or(|modulus| modulus.is_none() || registry_key(modulus).is_some());
    if registry_key(other).is_none() || !modulus_is_key {
        return Ok(Value::NotImplemented);
    }

    Err(vm.type_error("bad operand type"))
}

/// A key handle from an argument that may not be `None`. Integers convert
/// as pointers.
fn check_key(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() || registry_key(value).is_some() {
        return Ok(());
    }
    if value.is_none() {
        return Err(vm.type_error("None is not a valid HKEY in this context"));
    }
    if vm.as_integral(value).is_none() {
        return Err(vm.type_error("The object is not a PyHKEY object"));
    }
    void_pointer(vm, value)?;

    Ok(())
}

/// The `i` unit, keeping only errors.
fn check_int(vm: &Vm, value: &Value) -> PyResult<()> {
    c_int(vm, value)?;

    Ok(())
}

fn host_result(vm: &Vm, function: &str) -> PyResult<Value> {
    vm.host_operation(HostCapability::Registry, format!("_winreg.{function}() (host registry)"))
}

fn close_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key] = exact(vm, args, "CloseKey")?;

    close(vm, &key)
}

fn connect_registry(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [computer, key] = exact(vm, args, "ConnectRegistry")?;
    optional_string(vm, &computer, "ConnectRegistry", 1)?;
    check_key(vm, &key)?;

    host_key(vm, "ConnectRegistry")
}

fn create_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, sub_key] = exact(vm, args, "CreateKey")?;
    optional_string(vm, &sub_key, "CreateKey", 2)?;
    check_key(vm, &key)?;

    host_key(vm, "CreateKey")
}

/// A function of the form `O<unit>|ii:name`: a key, a name the unit
/// `check_name` converts, and two optional ints.
fn key_name_and_flags(vm: &Vm, args: CallArgs, function: &str, check_name: fn(&Vm, &Value, &str, usize) -> PyResult<()>) -> PyResult<()> {
    let args = positional(vm, args, function, 2, 4)?;
    let [key, name, flags @ ..] = args.as_slice() else {
        return Err(vm.type_error(&format!("{function}() takes at least 2 arguments ({} given)", args.len())));
    };
    check_name(vm, name, function, 2)?;
    for flag in flags {
        check_int(vm, flag)?;
    }

    check_key(vm, key)
}

fn create_key_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_name_and_flags(vm, args, "CreateKeyEx", optional_string)?;

    host_key(vm, "CreateKeyEx")
}

/// Opens a key, shared by `OpenKey` and `OpenKeyEx`; both use the format
/// name `OpenKey`.
fn open(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }
    key_name_and_flags(vm, args, "OpenKey", optional_string)?;

    host_key(vm, function)
}

fn open_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    open(vm, args, "OpenKey")
}

fn open_key_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    open(vm, args, "OpenKeyEx")
}

fn delete_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, sub_key] = exact(vm, args, "DeleteKey")?;
    string(vm, &sub_key, "DeleteKey", 2)?;
    check_key(vm, &key)?;

    host_result(vm, "DeleteKey")
}

/// `DeleteKeyEx`: `RegDeleteKeyExA` exists on every 64-bit Windows.
fn delete_key_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_name_and_flags(vm, args, "DeleteKeyEx", string)?;

    host_result(vm, "DeleteKeyEx")
}

/// A function of the form `Oz:name`.
fn key_and_optional_string(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Value> {
    let [key, name] = exact(vm, args, function)?;
    optional_string(vm, &name, function, 2)?;
    check_key(vm, &key)?;

    host_result(vm, function)
}

/// A function of the form `Oi:name`.
fn key_and_index(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Value> {
    let [key, index] = exact(vm, args, function)?;
    check_int(vm, &index)?;
    check_key(vm, &key)?;

    host_result(vm, function)
}

/// A function of the form `O:name`.
fn key_only(vm: &Vm, args: CallArgs, function: &str) -> PyResult<Value> {
    let [key] = exact(vm, args, function)?;
    check_key(vm, &key)?;

    host_result(vm, function)
}

fn delete_value(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_and_optional_string(vm, args, "DeleteValue")
}

fn query_value(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_and_optional_string(vm, args, "QueryValue")
}

fn query_value_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_and_optional_string(vm, args, "QueryValueEx")
}

fn enum_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_and_index(vm, args, "EnumKey")
}

fn enum_value(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_and_index(vm, args, "EnumValue")
}

fn flush_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_only(vm, args, "FlushKey")
}

fn query_info_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_only(vm, args, "QueryInfoKey")
}

fn disable_reflection_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_only(vm, args, "DisableReflectionKey")
}

fn enable_reflection_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_only(vm, args, "EnableReflectionKey")
}

fn query_reflection_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    key_only(vm, args, "QueryReflectionKey")
}

fn expand_environment_strings(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [source] = exact(vm, args, "ExpandEnvironmentStrings")?;
    unicode(vm, &source, "ExpandEnvironmentStrings", 1, "unicode")?;

    vm.host_operation(HostCapability::Environment, "_winreg.ExpandEnvironmentStrings() (host environment)")
}

fn load_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, sub_key, file_name] = exact(vm, args, "LoadKey")?;
    string(vm, &sub_key, "LoadKey", 2)?;
    string(vm, &file_name, "LoadKey", 3)?;
    check_key(vm, &key)?;

    host_result(vm, "LoadKey")
}

fn save_key(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, file_name] = exact(vm, args, "SaveKey")?;
    string(vm, &file_name, "SaveKey", 2)?;
    check_key(vm, &key)?;

    host_result(vm, "SaveKey")
}

/// The string data of a value: unicode converts with the default encoding.
fn string_contents(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() || vm.as_str_bytes(value).is_some() {
        return Ok(());
    }
    if let Some(text) = vm.as_text(value) {
        vm.encode_default(&text)?;
        return Ok(());
    }

    Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(value))))
}

fn set_value(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, sub_key, value_type, data] = exact(vm, args, "SetValue")?;
    let value_type = c_int(vm, &value_type)?;
    check_key(vm, &key)?;

    let Some(value_type) = value_type else {
        return host_result(vm, "SetValue");
    };
    if i64::from(value_type) != REG_SZ {
        return Err(vm.type_error("Type must be _winreg.REG_SZ"));
    }
    string_contents(vm, &data)?;
    if !sub_key.is_none() {
        string_contents(vm, &sub_key)?;
    }

    host_result(vm, "SetValue")
}

fn set_value_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let [key, value_name, _reserved, value_type, data] = exact(vm, args, "SetValueEx")?;
    optional_string(vm, &value_name, "SetValueEx", 2)?;
    let value_type = c_int(vm, &value_type)?;
    check_key(vm, &key)?;

    if let Some(value_type) = value_type {
        if !is_registry_data(vm, &data, value_type)? {
            return Err(vm.raise(ExceptionKind::ValueError, "Could not convert the data to the specified type."));
        }
    }

    host_result(vm, "SetValueEx")
}

/// The type checks of a value conversion to registry data. `false` when the value cannot represent
/// `value_type`; other conversion failures raise.
fn is_registry_data(vm: &Vm, value: &Value, value_type: i32) -> PyResult<bool> {
    if value.is_unknown() || value.is_none() {
        return Ok(true);
    }

    let is_text = |item: &Value| item.is_unknown() || vm.as_str_bytes(item).is_some() || vm.as_text(item).is_some();
    match i64::from(value_type) {
        REG_DWORD => Ok(vm.as_integral(value).is_some()),
        REG_SZ | REG_EXPAND_SZ => Ok(is_text(value)),
        REG_MULTI_SZ => {
            let Some(items) = vm.as_list(value) else {
                return Ok(false);
            };
            Ok(items.iter().all(is_text))
        }
        _ => {
            if !vm.has_segment(value, Segment::Read) {
                return Err(vm.type_error(&format!("Objects of type '{}' can not be used as binary registry values", vm.type_name(value))));
            }
            Ok(true)
        }
    }
}
