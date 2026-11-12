//! The `_ssl` module of the client.
//!
//! The client embeds CPython 2.7.12 built against OpenSSL 1.1.1l. The module
//! has the names, messages, and own constants of 2.7.12; constants whose
//! values come from the library are those the client observes. The client
//! has `PROTOCOL_SSLv2`, no `PROTOCOL_SSLv3`, and no `RAND_egd`.
//!
//! Decisions of the linked library are host facts: object lookups, cipher
//! list and ALPN acceptance, curve names, error code names, the library
//! version, and its default certificate paths. Calls that depend on them
//! check their arguments and then yield unknown values.
//!
//! Contexts keep in memory the options, verify mode and flags, and hostname
//! checking. Work on files, certificates, the Windows certificate store, the
//! PRNG, and sockets validates its arguments and then yields unknown values.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::is_callable;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::registered_type;
use crate::interp::builtins::modules::time::argument_prefix;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::modules::time::c_int;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const CONTEXT_TYPE: &str = "_ssl._SSLContext";
const SOCKET_TYPE: &str = "_ssl._SSLSocket";
const SSL_ERROR_KEY: &str = "ssl.SSLError";
/// Shared with `_socket`, which defines the class.
const SOCKET_ERROR_KEY: &str = "_socket.error";
const SOCKET_OBJECT_KEY: &str = "_socket.socket";

/// Protocol numbers of the module.
const PROTOCOL_SSL2: i32 = 0;
const PROTOCOL_SSL23: i32 = 2;
const PROTOCOL_TLS1: i32 = 3;
const PROTOCOL_TLS1_1: i32 = 4;
const PROTOCOL_TLS1_2: i32 = 5;

/// Option bits as the client observes them.
const OP_LEGACY_SERVER_CONNECT: u64 = 0x0000_0004;
const OP_TLSEXT_PADDING: u64 = 0x0000_0010;
const OP_SAFARI_ECDHE_ECDSA_BUG: u64 = 0x0000_0040;
const OP_DONT_INSERT_EMPTY_FRAGMENTS: u64 = 0x0000_0800;
const OP_NO_COMPRESSION: u64 = 0x0002_0000;
const OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 0x0010_0000;
const OP_CIPHER_SERVER_PREFERENCE: u64 = 0x0040_0000;
const OP_NO_SSLV2: u64 = 0;
const OP_NO_SSLV3: u64 = 0x0200_0000;
const OP_NO_TLSV1: u64 = 0x0400_0000;
const OP_NO_TLSV1_2: u64 = 0x0800_0000;
const OP_NO_TLSV1_1: u64 = 0x1000_0000;
const OP_CRYPTOPRO_TLSEXT_BUG: u64 = 0x8000_0000;
const OP_SINGLE_DH_USE: u64 = 0;
const OP_SINGLE_ECDH_USE: u64 = 0;
const OP_ALL: u64 = OP_CRYPTOPRO_TLSEXT_BUG | OP_DONT_INSERT_EMPTY_FRAGMENTS | OP_LEGACY_SERVER_CONNECT | OP_TLSEXT_PADDING | OP_SAFARI_ECDHE_ECDSA_BUG;

/// Certificate verification flags as the client observes them.
const VERIFY_CRL_CHECK: u64 = 0x4;
const VERIFY_CRL_CHECK_ALL: u64 = 0x8;
const VERIFY_X509_STRICT: u64 = 0x20;
const VERIFY_POLICY_CHECK: u64 = 0x80;
const VERIFY_POLICY_MASK: u64 = 0x80 | 0x100 | 0x200 | 0x400;
const VERIFY_TRUSTED_FIRST: u64 = 0x8000;

const ALERT_DESCRIPTIONS: [(&str, i64); 27] = [
    // In the order the module adds them.
    ("CLOSE_NOTIFY", 0),
    ("UNEXPECTED_MESSAGE", 10),
    ("BAD_RECORD_MAC", 20),
    ("RECORD_OVERFLOW", 22),
    ("DECOMPRESSION_FAILURE", 30),
    ("HANDSHAKE_FAILURE", 40),
    ("BAD_CERTIFICATE", 42),
    ("UNSUPPORTED_CERTIFICATE", 43),
    ("CERTIFICATE_REVOKED", 44),
    ("CERTIFICATE_EXPIRED", 45),
    ("CERTIFICATE_UNKNOWN", 46),
    ("ILLEGAL_PARAMETER", 47),
    ("UNKNOWN_CA", 48),
    ("ACCESS_DENIED", 49),
    ("DECODE_ERROR", 50),
    ("DECRYPT_ERROR", 51),
    ("PROTOCOL_VERSION", 70),
    ("INSUFFICIENT_SECURITY", 71),
    ("INTERNAL_ERROR", 80),
    ("USER_CANCELLED", 90),
    ("NO_RENEGOTIATION", 100),
    ("UNSUPPORTED_EXTENSION", 110),
    ("CERTIFICATE_UNOBTAINABLE", 111),
    ("UNRECOGNIZED_NAME", 112),
    ("BAD_CERTIFICATE_STATUS_RESPONSE", 113),
    ("BAD_CERTIFICATE_HASH_VALUE", 114),
    ("UNKNOWN_PSK_IDENTITY", 115),
];

/// Error kinds of the module.
const SSL_ERRORS: [(&str, i64); 9] = [
    ("SSL_ERROR_ZERO_RETURN", 6),
    ("SSL_ERROR_WANT_READ", 2),
    ("SSL_ERROR_WANT_WRITE", 3),
    ("SSL_ERROR_WANT_X509_LOOKUP", 4),
    ("SSL_ERROR_SYSCALL", 5),
    ("SSL_ERROR_SSL", 1),
    ("SSL_ERROR_WANT_CONNECT", 7),
    ("SSL_ERROR_EOF", 8),
    ("SSL_ERROR_INVALID_ERROR_CODE", 10),
];

const ERROR_SUBCLASSES: [&str; 5] = ["SSLZeroReturnError", "SSLWantReadError", "SSLWantWriteError", "SSLSyscallError", "SSLEOFError"];

const FUNCTIONS: [MethodSpec; 8] = [
    function("_test_decode_cert", ssl_test_decode_cert),
    function("RAND_add", ssl_rand_add),
    function("RAND_status", ssl_rand_status),
    function("get_default_verify_paths", ssl_get_default_verify_paths),
    function("enum_certificates", ssl_enum_certificates),
    function("enum_crls", ssl_enum_crls),
    function("txt2obj", ssl_txt2obj),
    function("nid2obj", ssl_nid2obj),
];

/// The certificate requirement of a context.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifyMode {
    None,
    Optional,
    Required,
}

impl VerifyMode {
    fn number(self) -> i64 {
        match self {
            Self::None => 0,
            Self::Optional => 1,
            Self::Required => 2,
        }
    }
}

/// The in-memory state of a context.
struct Context {
    /// The option bits.
    options: Cell<u64>,
    verify_mode: Cell<VerifyMode>,
    /// Flags of the certificate store's verification parameters.
    verify_flags: Cell<u64>,
    check_hostname: Cell<bool>,
    /// Whether the certificate store holds nothing loaded from the host.
    store_known: Cell<bool>,
    /// Whether no socket was wrapped, so the session counters are zero.
    sessions_known: Cell<bool>,
    /// The `set_servername_callback` callable, held for the context's
    /// lifetime.
    _servername_callback: RefCell<Option<Value>>,
}

impl_native_data!(Context, "_ssl._SSLContext");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    let ssl_error = native_type(vm, SSL_ERROR_KEY, create_ssl_error)?;
    set_attribute(vm, module, "SSLError", Value::Object(Rc::clone(&ssl_error)))?;
    for name in ERROR_SUBCLASSES {
        let class = new_exception_class(vm, "ssl", name, &ssl_error)?;
        set_attribute(vm, module, name, Value::Object(class))?;
    }
    set_attribute(vm, module, "_SSLContext", Value::Object(native_type(vm, CONTEXT_TYPE, create_context_type)?))?;
    set_attribute(vm, module, "_SSLSocket", Value::Object(native_type(vm, SOCKET_TYPE, create_socket_type)?))?;

    for (name, value) in SSL_ERRORS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }
    let integers = [
        ("CERT_NONE", 0),
        ("CERT_OPTIONAL", 1),
        ("CERT_REQUIRED", 2),
        ("VERIFY_DEFAULT", 0),
        ("VERIFY_CRL_CHECK_LEAF", c_long(vm, VERIFY_CRL_CHECK)),
        ("VERIFY_CRL_CHECK_CHAIN", c_long(vm, VERIFY_CRL_CHECK | VERIFY_CRL_CHECK_ALL)),
        ("VERIFY_X509_STRICT", c_long(vm, VERIFY_X509_STRICT)),
        ("VERIFY_X509_TRUSTED_FIRST", c_long(vm, VERIFY_TRUSTED_FIRST)),
        ("PROTOCOL_SSLv2", i64::from(PROTOCOL_SSL2)),
        ("PROTOCOL_SSLv23", i64::from(PROTOCOL_SSL23)),
        ("PROTOCOL_TLSv1", i64::from(PROTOCOL_TLS1)),
        ("PROTOCOL_TLSv1_1", i64::from(PROTOCOL_TLS1_1)),
        ("PROTOCOL_TLSv1_2", i64::from(PROTOCOL_TLS1_2)),
        ("OP_ALL", c_long(vm, OP_ALL & !OP_DONT_INSERT_EMPTY_FRAGMENTS)),
        ("OP_NO_SSLv2", c_long(vm, OP_NO_SSLV2)),
        ("OP_NO_SSLv3", c_long(vm, OP_NO_SSLV3)),
        ("OP_NO_TLSv1", c_long(vm, OP_NO_TLSV1)),
        ("OP_NO_TLSv1_1", c_long(vm, OP_NO_TLSV1_1)),
        ("OP_NO_TLSv1_2", c_long(vm, OP_NO_TLSV1_2)),
        ("OP_CIPHER_SERVER_PREFERENCE", c_long(vm, OP_CIPHER_SERVER_PREFERENCE)),
        ("OP_SINGLE_DH_USE", c_long(vm, OP_SINGLE_DH_USE)),
        ("OP_SINGLE_ECDH_USE", c_long(vm, OP_SINGLE_ECDH_USE)),
        ("OP_NO_COMPRESSION", c_long(vm, OP_NO_COMPRESSION)),
    ];
    for (name, value) in integers {
        set_attribute(vm, module, name, Value::Int(value))?;
    }
    for (name, value) in ALERT_DESCRIPTIONS {
        set_attribute(vm, module, &format!("ALERT_DESCRIPTION_{name}"), Value::Int(value))?;
    }
    for name in ["HAS_SNI", "HAS_TLS_UNIQUE", "HAS_ECDH", "HAS_NPN", "HAS_ALPN"] {
        set_attribute(vm, module, name, Value::Bool(true))?;
    }

    install_error_names(vm, module)?;
    install_versions(vm, module)?;

    Ok(())
}

/// The error code name tables, which hold the linked library's codes.
fn install_error_names(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    for name in ["err_codes_to_names", "err_names_to_codes", "lib_codes_to_names"] {
        set_attribute(vm, module, name, Value::unknown(format!("_ssl.{name} (host OpenSSL)")))?;
    }

    Ok(())
}

/// The version attributes, which describe the linked library.
fn install_versions(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let Some(openssl) = vm.config.host.openssl.clone() else {
        for name in ["OPENSSL_VERSION_NUMBER", "OPENSSL_VERSION_INFO", "OPENSSL_VERSION", "_OPENSSL_API_VERSION"] {
            set_attribute(vm, module, name, Value::unknown(format!("_ssl.{name} (host OpenSSL)")))?;
        }
        return Ok(());
    };

    let info = || Value::tuple(version_info(openssl.number).into_iter().map(|part| Value::Int(i64::from(part))).collect());
    set_attribute(vm, module, "OPENSSL_VERSION_NUMBER", Value::Long(Rc::new(BigInt::from(openssl.number))))?;
    set_attribute(vm, module, "OPENSSL_VERSION_INFO", info())?;
    set_attribute(vm, module, "OPENSSL_VERSION", Value::str(&openssl.text))?;
    set_attribute(vm, module, "_OPENSSL_API_VERSION", info())
}

/// A version number split into major, minor, fix, patch, and status.
fn version_info(number: u32) -> [u32; 5] {
    [number >> 28 & 0xFF, number >> 20 & 0xFF, number >> 12 & 0xFF, number >> 4 & 0xFF, number & 0xF]
}

/// A C `long` constant whose bits are `bits`.
fn c_long(vm: &Vm, bits: u64) -> i64 {
    match vm.config.long_width {
        LongWidth::Bits32 => i64::from(bits as u32 as i32),
        LongWidth::Bits64 => bits as i64,
    }
}

/// The bits a C `unsigned long` keeps.
fn unsigned_long_mask(vm: &Vm) -> u64 {
    match vm.config.long_width {
        LongWidth::Bits32 => u64::from(u32::MAX),
        LongWidth::Bits64 => u64::MAX,
    }
}

/// `SSLError`, a subclass of `socket.error`.
fn create_ssl_error(vm: &Vm) -> PyResult<ObjectRef> {
    let socket_error = native_type(vm, SOCKET_ERROR_KEY, create_socket_error)?;

    new_exception_class(vm, "ssl", "SSLError", &socket_error)
}

/// `socket.error` as `_socket` creates it, for when `_ssl` is imported
/// first.
fn create_socket_error(vm: &Vm) -> PyResult<ObjectRef> {
    let io_error = Rc::clone(vm.types().exception(ExceptionKind::IOError));

    new_exception_class(vm, "socket", "error", &io_error)
}

/// The `str` of the `SSLError` classes: the `strerror` attribute as it is
/// when set, else `str(args)`. `None` for other exceptions.
pub fn error_text(vm: &Vm, exception: &ObjectRef, args: &Value) -> Option<PyResult<Value>> {
    let class = registered_type(vm, SSL_ERROR_KEY)?;
    match vm.is_instance_of(&Value::Object(Rc::clone(exception)), &class) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(signal) => return Some(Err(signal)),
    }

    let strerror = crate::interp::builtins::exception_types::field(exception, "strerror");

    Some(match strerror {
        Some(strerror) => Ok(strerror),
        None => vm.to_str(args),
    })
}

fn create_context_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "_SSLContext",
            module: "_ssl",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", context_new),
                method("_wrap_socket", context_wrap_socket),
                method("set_ciphers", context_set_ciphers),
                method("_set_alpn_protocols", context_set_alpn_protocols),
                method("_set_npn_protocols", context_set_npn_protocols),
                method("load_cert_chain", context_load_cert_chain),
                method("load_dh_params", context_load_dh_params),
                method("load_verify_locations", context_load_verify_locations),
                method("session_stats", context_session_stats),
                method("set_default_verify_paths", context_set_default_verify_paths),
                method("set_ecdh_curve", context_set_ecdh_curve),
                method("set_servername_callback", context_set_servername_callback),
                method("cert_store_stats", context_cert_store_stats),
                method("get_ca_certs", context_get_ca_certs),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "check_hostname", owner: CONTEXT_TYPE, get: get_check_hostname, set: Some(set_check_hostname) })?;
    add_getset(vm, &class, GetSet { name: "options", owner: CONTEXT_TYPE, get: get_options, set: Some(set_options) })?;
    add_getset(vm, &class, GetSet { name: "verify_flags", owner: CONTEXT_TYPE, get: get_verify_flags, set: Some(set_verify_flags) })?;
    add_getset(vm, &class, GetSet { name: "verify_mode", owner: CONTEXT_TYPE, get: get_verify_mode, set: Some(set_verify_mode) })?;

    Ok(class)
}

/// `_SSLSocket` objects come only from `_wrap_socket`, which needs a host
/// socket, so no instance exists and its methods only check the receiver.
fn create_socket_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec {
            name: "_SSLSocket",
            module: "_ssl",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                method("do_handshake", socket_do_handshake),
                method("write", socket_write),
                method("read", socket_read),
                method("pending", socket_pending),
                method("peer_certificate", socket_peer_certificate),
                method("cipher", socket_cipher),
                method("version", socket_version),
                method("selected_npn_protocol", socket_selected_npn_protocol),
                method("selected_alpn_protocol", socket_selected_alpn_protocol),
                method("compression", socket_compression),
                method("shutdown", socket_shutdown),
                method("tls_unique_cb", socket_tls_unique_cb),
            ],
        },
    )?;

    add_getset(vm, &class, GetSet { name: "context", owner: SOCKET_TYPE, get: get_socket_context, set: Some(set_socket_context) })?;

    Ok(class)
}

/// Positional arguments of a varargs callable after `skip` receiver
/// values. `format` is the name after `:` in its format, if any.
fn varargs(vm: &Vm, args: &CallArgs, skip: usize, function: &str, format: Option<&str>, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{function}() takes no keyword arguments")));
    }

    let rest: Vec<Value> = args.positional.iter().skip(skip).cloned().collect();
    let given = rest.len();
    if !(minimum..=maximum).contains(&given) {
        let (bound, limit) = if minimum == maximum {
            ("exactly", minimum)
        } else if given < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if limit == 1 { "" } else { "s" };
        let subject = format.map_or_else(|| "function".to_owned(), |name| format!("{name}()"));
        return Err(vm.type_error(&format!("{subject} takes {bound} {limit} argument{plural} ({given} given)")));
    }

    Ok(rest)
}

/// The receiver of a `_SSLContext` method and the arguments after it.
fn context_call<'a>(vm: &Vm, args: &'a CallArgs, name: &str) -> PyResult<(&'a Context, CallArgs)> {
    let context = crate::interp::builtins::modules::this::<Context>(vm, args, CONTEXT_TYPE, name)?;
    let rest = CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };

    Ok((context, rest))
}

fn context_of<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Context> {
    native_data::<Context>(instance).ok_or_else(|| crate::interp::builtins::modules::descriptor_mismatch(vm, getset, instance))
}

/// The `s#` format: a string or an old read buffer without release.
fn check_read_buffer(vm: &Vm, value: &Value, format: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() || vm.as_text(value).is_some() {
        return c_string_like(vm, value, format, position);
    }
    if vm.buffer(value, BufferInterface::Pinned)?.is_some() {
        return Ok(());
    }

    Err(vm.type_error(&format!("{}argument {position} must be string or read-only buffer, not {}", argument_prefix(Some(format)), converted_type_name(vm, value))))
}

/// The `s*` format: a string or any buffer.
fn check_any_buffer(vm: &Vm, value: &Value, format: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() || vm.as_text(value).is_some() {
        return c_string_like(vm, value, format, position);
    }
    if vm.buffer(value, BufferInterface::Any)?.is_some() {
        return Ok(());
    }

    Err(vm.type_error(&format!("{}argument {position} must be string or buffer, not {}", argument_prefix(Some(format)), converted_type_name(vm, value))))
}

/// Unicode through the default encoding, as the `s#` and `s*` formats
/// convert it; embedded null characters are allowed.
fn c_string_like(vm: &Vm, value: &Value, format: &str, position: usize) -> PyResult<()> {
    let Some(text) = vm.as_text(value) else {
        return Ok(());
    };
    if text.units().iter().all(|unit| *unit < 0x80) {
        return Ok(());
    }

    Err(vm.halt_unsupported(format!("{}argument {position} as non-ASCII unicode", argument_prefix(Some(format)))))
}

/// The `et` format with the file system encoding: strings pass as they
/// are, other objects are converted to unicode.
fn check_encoded_path(vm: &Vm, value: &Value, format: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() {
        return Ok(());
    }

    let (contains_null, kind) = match (vm.as_str_bytes(value), vm.as_text(value)) {
        (Some(bytes), _) => (bytes.as_bytes().contains(&0), "str"),
        (None, Some(text)) => (text.units().contains(&0), "unicode"),
        (None, None) => {
            unicode_from_object(vm, value)?;
            (false, "")
        }
    };
    if contains_null {
        return Err(vm.type_error(&format!("{}argument {position} must be encoded string without null bytes, not {kind}", argument_prefix(Some(format)))));
    }

    Ok(())
}

/// The checks of the conversion to unicode on a path argument that is not a
/// string.
fn unicode_from_object(vm: &Vm, value: &Value) -> PyResult<()> {
    if value.is_unknown() || vm.as_str_bytes(value).is_some() || vm.as_text(value).is_some() {
        return Ok(());
    }

    // A TypeError of the character buffer, such as a closed mmap's, is
    // replaced.
    let coercing = || vm.type_error(&format!("coercing to Unicode: need string or buffer, {} found", vm.type_name(value)));
    let bytes = match vm.buffer(value, BufferInterface::Character) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(coercing()),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::TypeError) => return Err(coercing()),
        Err(signal) => return Err(signal),
    };
    if !bytes.as_bytes().is_ascii() {
        return Err(vm.halt_unsupported("decoding a non-ASCII buffer path with the default encoding"));
    }

    Ok(())
}

/// A string, or unicode through the default encoding.
fn string_as_string(vm: &Vm, value: &Value) -> PyResult<Option<PyBytes>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(Some(bytes));
    }

    let Some(text) = vm.as_text(value) else {
        return Err(vm.type_error(&format!("expected string or Unicode object, {} found", vm.type_name(value))));
    };
    let Some(ascii) = text.units().iter().map(|unit| u8::try_from(*unit).ok().filter(u8::is_ascii)).collect::<Option<Vec<u8>>>() else {
        return Err(vm.halt_unsupported("encoding non-ASCII unicode with the default encoding"));
    };

    Ok(Some(PyBytes::new(ascii)))
}

fn ssl_test_decode_cert(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = varargs(vm, &args, 0, "_test_decode_cert", Some("test_decode_certificate"), 1, 1)?;
    for (index, argument) in arguments.iter().enumerate() {
        c_string(vm, argument, Some("test_decode_certificate"), index + 1)?;
    }

    vm.host_operation_on(HostCapability::FileSystem, "_ssl._test_decode_cert() (file read)", Denial::Native, arguments.first())
}

fn ssl_rand_add(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = varargs(vm, &args, 0, "RAND_add", Some("RAND_add"), 2, 2)?;
    let [data, entropy] = arguments.as_slice() else {
        return Err(vm.type_error("RAND_add() takes exactly 2 arguments"));
    };
    check_read_buffer(vm, data, "RAND_add", 1)?;
    c_double(vm, entropy)?;

    // Mixing into the host PRNG has no result the interpreter observes.
    vm.host_permit(HostCapability::Randomness, Denial::Native, None)?;

    Ok(Value::None)
}

fn ssl_rand_status(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "RAND_status")?;

    vm.host_operation(HostCapability::Randomness, "_ssl.RAND_status() (host PRNG)")
}

fn ssl_get_default_verify_paths(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "get_default_verify_paths")?;

    let (file, directory) = match &vm.config.host.openssl_default_paths {
        Some(paths) => (Value::str(&paths.cert_file), Value::str(&paths.cert_dir)),
        None => (Value::unknown("default certificate file (host OpenSSL build)"), Value::unknown("default certificate directory (host OpenSSL build)")),
    };

    Ok(Value::tuple(vec![Value::str("SSL_CERT_FILE"), file, Value::str("SSL_CERT_DIR"), directory]))
}

fn ssl_enum_certificates(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    store_name_argument(vm, args, "enum_certificates")?;

    vm.host_operation(HostCapability::Registry, "_ssl.enum_certificates() (Windows certificate store)")
}

fn ssl_enum_crls(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    store_name_argument(vm, args, "enum_crls")?;

    vm.host_operation(HostCapability::Registry, "_ssl.enum_crls() (Windows certificate store)")
}

/// The `s:<function>` keyword format with `store_name`.
fn store_name_argument(vm: &Vm, args: CallArgs, function: &str) -> PyResult<()> {
    parse_with(vm, args, function, &["store_name"], 1, |vm, index, value| {
        c_string(vm, &value, Some(function), index + 1)?;
        Ok(())
    })?;

    Ok(())
}

fn ssl_txt2obj(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "txt2obj", &["txt", "name"], 1, |vm, index, value| {
        if index == 0 {
            c_string(vm, &value, Some("txt2obj"), 1)?;
        }
        Ok(value)
    })?;
    if let Some(name) = slots.into_iter().nth(1).flatten() {
        vm.truthy(&name, "txt2obj() name argument")?;
    }

    Ok(object_lookup("txt2obj"))
}

fn ssl_nid2obj(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = varargs(vm, &args, 0, "nid2obj", Some("nid2obj"), 1, 1)?;
    let Some(argument) = arguments.first() else {
        return Err(vm.type_error("nid2obj() takes exactly 1 argument (0 given)"));
    };
    let Some(nid) = c_int(vm, argument)? else {
        return Ok(Value::unknown("_ssl.nid2obj() of an unknown NID"));
    };
    if nid < 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "NID must be positive."));
    }

    Ok(object_lookup("nid2obj"))
}

/// A found object as `(nid, shortname, longname, oid)`. The fields come from
/// the linked library's object table.
fn object_lookup(function: &str) -> Value {
    let fields = ["nid", "shortname", "longname", "oid"];

    Value::tuple(fields.iter().map(|field| Value::unknown(format!("_ssl.{function}() {field} (host OpenSSL object table)"))).collect())
}

fn context_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = native_type(vm, CONTEXT_TYPE, create_context_type)?;
    let (class, rest) = new_class(vm, args, &base)?;
    let slots = parse_with(vm, rest, "_SSLContext", &["protocol"], 1, |vm, _, value| c_int(vm, &value))?;
    // The protocol is required, so only an unknown value leaves it unset.
    let Some(protocol) = slots.into_iter().next().flatten().flatten() else {
        return Ok(Value::unknown("_ssl._SSLContext() of an unknown protocol"));
    };

    match protocol {
        PROTOCOL_SSL23 | PROTOCOL_TLS1 | PROTOCOL_TLS1_1 | PROTOCOL_TLS1_2 => {}
        PROTOCOL_SSL2 => {
            return Err(vm.halt_unsupported("_ssl._SSLContext(PROTOCOL_SSLv2) with the client's patched OpenSSL 1.1.1 build"));
        }
        _ => return Err(vm.raise(ExceptionKind::ValueError, "invalid protocol version")),
    }

    // The options the client observes on a new context.
    let library = OP_LEGACY_SERVER_CONNECT | OP_NO_COMPRESSION | OP_ENABLE_MIDDLEBOX_COMPAT;
    let options = library | (OP_ALL & !OP_DONT_INSERT_EMPTY_FRAGMENTS) | OP_NO_SSLV2 | OP_NO_SSLV3;
    let context = Context {
        options: Cell::new(options & unsigned_long_mask(vm)),
        verify_mode: Cell::new(VerifyMode::None),
        verify_flags: Cell::new(VERIFY_TRUSTED_FIRST),
        check_hostname: Cell::new(false),
        store_known: Cell::new(true),
        sessions_known: Cell::new(true),
        _servername_callback: RefCell::new(None),
    };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(context))))
}

fn context_wrap_socket(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, rest) = context_call(vm, &args, "_wrap_socket")?;
    let socket_type = registered_type(vm, SOCKET_OBJECT_KEY);

    // The format "O!i|O!O" with `server_hostname` None, else "O!iet|O",
    // whose errors are the ones reported.
    parse_with(vm, rest, "_wrap_socket", &["sock", "server_side", "server_hostname", "ssl_sock"], 2, |vm, index, value| {
        if value.is_unknown() {
            return Ok(());
        }
        match index {
            0 => {
                let is_socket = match &socket_type {
                    Some(class) => vm.is_instance_of(&value, class)?,
                    None => false,
                };
                if !is_socket {
                    return Err(vm.type_error(&format!("_wrap_socket() argument 1 must be _socket.socket, not {}", converted_type_name(vm, &value))));
                }
            }
            1 => {
                c_int(vm, &value)?;
            }
            2 if !value.is_none() => check_encoded_path(vm, &value, "_wrap_socket", 3)?,
            _ => {}
        }
        Ok(())
    })?;

    vm.host_permit(HostCapability::Network, Denial::Native, None)?;
    context.sessions_known.set(false);

    Ok(Value::unknown("_ssl._SSLContext._wrap_socket() (host socket)"))
}

fn context_set_ciphers(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = context_call(vm, &args, "set_ciphers")?;
    let arguments = varargs(vm, &rest, 0, "set_ciphers", Some("set_ciphers"), 1, 1)?;
    let Some(argument) = arguments.first() else {
        return Err(vm.type_error("set_ciphers() takes exactly 1 argument (0 given)"));
    };
    c_string(vm, argument, Some("set_ciphers"), 1)?;

    Ok(Value::unknown("_ssl._SSLContext.set_ciphers() (host OpenSSL cipher list)"))
}

fn context_set_alpn_protocols(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    check_protocols_argument(vm, &args, "_set_alpn_protocols")?;

    Ok(Value::unknown("_ssl._SSLContext._set_alpn_protocols() (host OpenSSL)"))
}

/// The stored list only matters to handshakes, which are not emulated.
fn context_set_npn_protocols(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    check_protocols_argument(vm, &args, "_set_npn_protocols")?;

    Ok(Value::None)
}

/// The `s*:set_npn_protocols` format both protocol setters use.
fn check_protocols_argument(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<()> {
    let (_, rest) = context_call(vm, args, name)?;
    let arguments = varargs(vm, &rest, 0, name, Some("set_npn_protocols"), 1, 1)?;
    let Some(argument) = arguments.first() else {
        return Err(vm.type_error("set_npn_protocols() takes exactly 1 argument (0 given)"));
    };

    check_any_buffer(vm, argument, "set_npn_protocols", 1)
}

fn context_load_cert_chain(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (_, rest) = context_call(vm, &args, "load_cert_chain")?;
    let slots = parse_with(vm, rest, "load_cert_chain", &["certfile", "keyfile", "password"], 1, |vm, index, value| {
        if index == 0 {
            check_encoded_path(vm, &value, "load_cert_chain", 1)?;
        }
        Ok(value)
    })?;
    let mut slots = slots.into_iter();
    let certfile = slots.next().flatten();
    let keyfile = slots.next().flatten();
    let password = slots.next().flatten();

    if let Some(keyfile) = keyfile.filter(|keyfile| !keyfile.is_none()) {
        unicode_from_object(vm, &keyfile)?;
    }
    if let Some(password) = password.filter(|password| !password.is_none()) {
        if is_callable(vm, &password)? {
            return Err(vm.halt_unsupported("load_cert_chain() with a password callback, which OpenSSL calls while reading host files"));
        }
        let is_password = vm.as_str_bytes(&password).is_some() || vm.as_bytearray(&password).is_some();
        match vm.as_text(&password) {
            Some(text) if !text.units().iter().all(|unit| *unit < 0x80) => {
                return Err(vm.halt_unsupported("load_cert_chain() password as non-ASCII unicode"));
            }
            Some(_) => {}
            None if is_password => {}
            None => return Err(vm.type_error("password should be a string or callable")),
        }
    }

    vm.host_operation_on(HostCapability::FileSystem, "_ssl._SSLContext.load_cert_chain() (host files)", Denial::Native, certfile.as_ref())
}

fn context_load_verify_locations(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, rest) = context_call(vm, &args, "load_verify_locations")?;
    let slots = parse(vm, rest, "load_verify_locations", &["cafile", "capath", "cadata"])?;
    let present = |slot: Option<&Option<Value>>| slot.cloned().flatten().filter(|value| !value.is_none());
    let cafile = present(slots.first());
    let capath = present(slots.get(1));
    let cadata = present(slots.get(2));

    if cafile.is_none() && capath.is_none() && cadata.is_none() {
        return Err(vm.type_error("cafile, capath and cadata cannot be all omitted"));
    }
    for path in cafile.iter().chain(capath.iter()) {
        unicode_from_object(vm, path)?;
    }
    if let Some(cadata) = &cadata {
        check_cadata(vm, cadata)?;
        if !cadata.is_unknown() {
            return Err(vm.halt_unsupported("load_verify_locations() with cadata, which needs X.509 certificate parsing"));
        }
    }

    if let Some(path) = cafile.as_ref().or(capath.as_ref()) {
        vm.host_permit(HostCapability::FileSystem, Denial::Native, Some(path))?;
    }
    context.store_known.set(false);

    Ok(Value::unknown("_ssl._SSLContext.load_verify_locations() (certificate parsing and host files)"))
}

/// The checks `load_verify_locations` makes on `cadata` before the library
/// parses it.
fn check_cadata(vm: &Vm, cadata: &Value) -> PyResult<()> {
    if cadata.is_unknown() {
        return Ok(());
    }

    let buffer = if vm.as_text(cadata).is_none() { vm.buffer(cadata, BufferInterface::New)? } else { None };
    let length = if let Some(bytes) = buffer {
        bytes.as_bytes().len()
    } else {
        let ascii = vm.as_text(cadata).filter(|text| text.units().iter().all(|unit| *unit < 0x80));
        let Some(text) = ascii else {
            return Err(vm.type_error("cadata should be an ASCII string or a bytes-like object"));
        };
        text.units().len()
    };
    if length == 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "Empty certificate data"));
    }

    Ok(())
}

fn context_load_dh_params(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    crate::interp::builtins::modules::this::<Context>(vm, &args, CONTEXT_TYPE, "load_dh_params")?;
    let path = method_one_argument(vm, &args, "load_dh_params")?;
    string_as_string(vm, &path)?;

    vm.host_operation_on(HostCapability::FileSystem, "_ssl._SSLContext.load_dh_params() (host file)", Denial::Native, Some(&path))
}

fn context_session_stats(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, _) = context_call(vm, &args, "session_stats")?;
    method_no_arguments(vm, &args, "session_stats")?;
    if !context.sessions_known.get() {
        return Ok(Value::unknown("_ssl._SSLContext.session_stats() after host connections"));
    }

    let stats = vm.new_dict();
    let names = ["number", "connect", "connect_good", "connect_renegotiate", "accept", "accept_good", "accept_renegotiate", "accept", "hits", "misses", "timeouts", "cache_full"];
    for name in names {
        vm.dict_set_str(&stats, name, Value::Long(Rc::new(BigInt::default())))?;
    }

    Ok(Value::Object(stats))
}

fn context_set_default_verify_paths(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, _) = context_call(vm, &args, "set_default_verify_paths")?;
    method_no_arguments(vm, &args, "set_default_verify_paths")?;

    vm.host_permit(HostCapability::FileSystem, Denial::Native, None)?;
    context.store_known.set(false);

    Ok(Value::unknown("_ssl._SSLContext.set_default_verify_paths() (host files)"))
}

fn context_set_ecdh_curve(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    crate::interp::builtins::modules::this::<Context>(vm, &args, CONTEXT_TYPE, "set_ecdh_curve")?;
    let name = method_one_argument(vm, &args, "set_ecdh_curve")?;
    string_as_string(vm, &name)?;

    Ok(Value::unknown("_ssl._SSLContext.set_ecdh_curve() (host OpenSSL curve names)"))
}

fn context_set_servername_callback(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, rest) = context_call(vm, &args, "set_servername_callback")?;
    let arguments = varargs(vm, &rest, 0, "set_servername_callback", None, 1, 1)?;
    let Some(callback) = arguments.into_iter().next() else {
        return Err(vm.type_error("function takes exactly 1 argument (0 given)"));
    };

    if callback.is_none() {
        context._servername_callback.replace(None);
        return Ok(Value::None);
    }
    if !is_callable(vm, &callback)? {
        context._servername_callback.replace(None);
        return Err(vm.type_error("not a callable object"));
    }
    context._servername_callback.replace(Some(callback));

    Ok(Value::None)
}

fn context_cert_store_stats(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, _) = context_call(vm, &args, "cert_store_stats")?;
    method_no_arguments(vm, &args, "cert_store_stats")?;
    if !context.store_known.get() {
        return Ok(Value::unknown("_ssl._SSLContext.cert_store_stats() after loading host certificates"));
    }

    let stats = vm.new_dict();
    for name in ["x509", "crl", "x509_ca"] {
        // The keys are not interned.
        vm.dict_set(&stats, Value::str(name), Value::Int(0))?;
    }

    Ok(Value::Object(stats))
}

fn context_get_ca_certs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (context, rest) = context_call(vm, &args, "get_ca_certs")?;
    let slots = parse(vm, rest, "get_ca_certs", &["binary_form"])?;
    if let Some(binary_form) = slots.into_iter().next().flatten() {
        vm.truthy(&binary_form, "get_ca_certs() binary_form argument")?;
    }
    if !context.store_known.get() {
        return Ok(Value::unknown("_ssl._SSLContext.get_ca_certs() after loading host certificates"));
    }

    Ok(vm.new_list(Vec::new()))
}

/// `parse` with optional arguments only.
fn parse(vm: &Vm, args: CallArgs, function: &str, names: &[&str]) -> PyResult<Vec<Option<Value>>> {
    crate::interp::builtins::parse(vm, args, function, names, 0)
}

fn get_options(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let context = context_of(vm, getset, instance)?;

    Ok(Value::Long(Rc::new(BigInt::from(c_long(vm, context.options.get())))))
}

fn set_options(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let context = context_of(vm, getset, instance)?;
    let value = setter_argument(vm, value, "_SSLContext.options")?;
    let options = long_argument(vm, &value)?;

    // Clearing and setting the differing bits leaves exactly the new ones.
    context.options.set(options as u64 & unsigned_long_mask(vm));

    Ok(())
}

fn get_verify_flags(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let context = context_of(vm, getset, instance)?;

    Ok(Value::Long(Rc::new(BigInt::from(context.verify_flags.get()))))
}

fn set_verify_flags(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let context = context_of(vm, getset, instance)?;
    let value = setter_argument(vm, value, "_SSLContext.verify_flags")?;

    // The `k` format: an int or long, masked to an `unsigned long`.
    let mask = unsigned_long_mask(vm);
    let new_flags = match vm.as_integral(&value) {
        Some(Integral::Int(number)) => number as u64 & mask,
        Some(Integral::Long(number)) => (&number & BigInt::from(mask)).to_u64().unwrap_or(0),
        None => return Err(vm.type_error(&format!("argument must be an integer, not {}", converted_type_name(vm, &value)))),
    };

    // Bits leaving the set are cleared, then bits entering it are added; any
    // policy flag entering also enables the policy check.
    let flags = context.verify_flags.get();
    let clear = flags & !new_flags;
    let set = !flags & new_flags;
    let mut flags = flags & !clear;
    if set != 0 {
        flags |= set;
        if set & VERIFY_POLICY_MASK != 0 {
            flags |= VERIFY_POLICY_CHECK;
        }
    }
    context.verify_flags.set(flags);

    Ok(())
}

fn get_verify_mode(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let context = context_of(vm, getset, instance)?;

    Ok(Value::Long(Rc::new(BigInt::from(context.verify_mode.get().number()))))
}

fn set_verify_mode(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let context = context_of(vm, getset, instance)?;
    let value = setter_argument(vm, value, "_SSLContext.verify_mode")?;
    let mode = match int_argument(vm, &value)? {
        0 => VerifyMode::None,
        1 => VerifyMode::Optional,
        2 => VerifyMode::Required,
        _ => return Err(vm.raise(ExceptionKind::ValueError, "invalid value for verify_mode")),
    };
    if mode == VerifyMode::None && context.check_hostname.get() {
        return Err(vm.raise(ExceptionKind::ValueError, "Cannot set verify_mode to CERT_NONE when check_hostname is enabled."));
    }

    context.verify_mode.set(mode);

    Ok(())
}

fn get_check_hostname(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let context = context_of(vm, getset, instance)?;

    Ok(Value::Bool(context.check_hostname.get()))
}

fn set_check_hostname(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let context = context_of(vm, getset, instance)?;
    let value = setter_argument(vm, value, "_SSLContext.check_hostname")?;
    let check_hostname = vm.truthy(&value, "_SSLContext.check_hostname value")?;
    if check_hostname && context.verify_mode.get() == VerifyMode::None {
        return Err(vm.raise(ExceptionKind::ValueError, "check_hostname needs a SSL context with either CERT_OPTIONAL or CERT_REQUIRED"));
    }

    context.check_hostname.set(check_hostname);

    Ok(())
}

/// The value given to a context setter. Deletion is rejected as a missing
/// argument.
fn setter_argument(vm: &Vm, value: Option<Value>, context: &str) -> PyResult<Value> {
    let Some(value) = value else {
        return Err(vm.type_error("function takes at least one argument"));
    };
    halt_on_unknown(&value, context)?;

    Ok(value)
}

/// The receiver check of an `_SSLSocket` method.
fn socket_method(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<Value> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{name}' of '{SOCKET_TYPE}' object needs an argument")));
    };
    let class = native_type(vm, SOCKET_TYPE, create_socket_type)?;
    if !vm.is_instance_of(receiver, &class)? {
        return Err(vm.type_error(&format!("descriptor '{name}' requires a '{SOCKET_TYPE}' object but received a '{}'", vm.type_name(receiver))));
    }

    vm.host_operation(HostCapability::Network, format!("_ssl._SSLSocket.{name}() (host socket)"))
}

fn socket_do_handshake(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "do_handshake")
}

fn socket_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "write")
}

fn socket_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "read")
}

fn socket_pending(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "pending")
}

fn socket_peer_certificate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "peer_certificate")
}

fn socket_cipher(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "cipher")
}

fn socket_version(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "version")
}

fn socket_selected_npn_protocol(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "selected_npn_protocol")
}

fn socket_selected_alpn_protocol(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "selected_alpn_protocol")
}

fn socket_compression(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "compression")
}

fn socket_shutdown(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "shutdown")
}

fn socket_tls_unique_cb(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    socket_method(vm, &args, "tls_unique_cb")
}

fn get_socket_context(_vm: &Vm, _getset: &GetSet, _instance: &Value) -> PyResult<Value> {
    Ok(Value::unknown("_ssl._SSLSocket.context (host socket)"))
}

fn set_socket_context(vm: &Vm, _getset: &GetSet, _instance: &Value, value: Option<Value>) -> PyResult<()> {
    let is_context = match &value {
        Some(value) => native_data::<Context>(value).is_some() || value.is_unknown(),
        None => false,
    };
    if !is_context {
        return Err(vm.type_error("The value must be a SSLContext"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_info_splits_the_number() {
        assert_eq!(version_info(0x1000_214f), [1, 0, 2, 20, 15]);
        assert_eq!(version_info(0x1010_10cf), [1, 1, 1, 12, 15]);
    }
}
