//! The `_socket` module of the Windows build.
//! Arguments are checked as the Windows build checks them before it calls
//! Winsock; results of Winsock calls are unknown values. Byte order
//! conversions, `inet_aton`, `inet_ntoa`, timeouts, and the socket
//! object's own fields are computed exactly.

use std::cell::Cell;
use std::rc::Rc;

use num_bigint::Sign;
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
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::capsule::new_capsule;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::time::c_string;
use crate::interp::builtins::modules::time::converted_type_name;
use crate::interp::builtins::numeric::float::float_as_double;
use crate::interp::builtins::numeric::float::float_to_integer;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
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

const TYPE_NAME: &str = "_socket.socket";

/// `AF_INET` and `AF_INET6` of `ws2def.h`, the families socket addresses
/// may use on Windows.
const AF_INET: i32 = 2;
const AF_INET6: i32 = 23;

/// `SIO_RCVALL` and `SIO_KEEPALIVE_VALS` of `mstcpip.h`.
const SIO_RCVALL: u32 = 0x9800_0001;
const SIO_KEEPALIVE_VALS: u32 = 0x9800_0004;

/// Module integer constants in insertion order, with the values the
/// Windows build compiles from the Windows SDK: address families,
/// `SOCK_*`, `SO_*`, `SOMAXCONN`, `MSG_*`, `SOL_SOCKET`, and `AI_*`/`NI_*`
/// from `ws2def.h` and `winsock2.h`; `IPPROTO_*`, `IP_*`, `IPV6_*`, and
/// `INADDR_*` from `ws2def.h`, `ws2ipdef.h`, and `winsock2.h` (the
/// `INADDR_*` values pass through a 32-bit C `long`); `EAI_*` from
/// `ws2tcpip.h` (WSA error codes); `RCVALL_*` from `mstcpip.h`. `SOL_IP`,
/// `SOL_TCP`, `SOL_UDP`, and `SHUT_*` are the fallbacks the module
/// defines when the SDK lacks them.
const CONSTANTS: [(&str, i64); 113] = [
    ("AF_UNSPEC", 0),
    ("AF_INET", 2),
    ("AF_INET6", 23),
    ("AF_IPX", 6),
    ("AF_APPLETALK", 16),
    ("AF_DECnet", 12),
    ("AF_SNA", 11),
    ("AF_IRDA", 26),
    ("SOCK_STREAM", 1),
    ("SOCK_DGRAM", 2),
    ("SOCK_RAW", 3),
    ("SOCK_SEQPACKET", 5),
    ("SOCK_RDM", 4),
    ("SO_DEBUG", 1),
    ("SO_ACCEPTCONN", 2),
    ("SO_REUSEADDR", 4),
    ("SO_EXCLUSIVEADDRUSE", -5),
    ("SO_KEEPALIVE", 8),
    ("SO_DONTROUTE", 16),
    ("SO_BROADCAST", 32),
    ("SO_USELOOPBACK", 64),
    ("SO_LINGER", 128),
    ("SO_OOBINLINE", 256),
    ("SO_SNDBUF", 4097),
    ("SO_RCVBUF", 4098),
    ("SO_SNDLOWAT", 4099),
    ("SO_RCVLOWAT", 4100),
    ("SO_SNDTIMEO", 4101),
    ("SO_RCVTIMEO", 4102),
    ("SO_ERROR", 4103),
    ("SO_TYPE", 4104),
    ("SOMAXCONN", 2_147_483_647),
    ("MSG_OOB", 1),
    ("MSG_PEEK", 2),
    ("MSG_DONTROUTE", 4),
    ("MSG_TRUNC", 256),
    ("MSG_CTRUNC", 512),
    ("SOL_SOCKET", 65535),
    ("SOL_IP", 0),
    ("SOL_TCP", 6),
    ("SOL_UDP", 17),
    ("IPPROTO_IP", 0),
    ("IPPROTO_ICMP", 1),
    ("IPPROTO_TCP", 6),
    ("IPPROTO_UDP", 17),
    ("IPPROTO_RAW", 255),
    ("IPPORT_RESERVED", 1024),
    ("IPPORT_USERRESERVED", 5000),
    ("INADDR_ANY", 0),
    ("INADDR_BROADCAST", -1),
    ("INADDR_LOOPBACK", 2_130_706_433),
    ("INADDR_UNSPEC_GROUP", -536_870_912),
    ("INADDR_ALLHOSTS_GROUP", -536_870_911),
    ("INADDR_MAX_LOCAL_GROUP", -536_870_657),
    ("INADDR_NONE", -1),
    ("IP_OPTIONS", 1),
    ("IP_HDRINCL", 2),
    ("IP_TOS", 3),
    ("IP_TTL", 4),
    ("IP_RECVDSTADDR", 25),
    ("IP_MULTICAST_IF", 9),
    ("IP_MULTICAST_TTL", 10),
    ("IP_MULTICAST_LOOP", 11),
    ("IP_ADD_MEMBERSHIP", 12),
    ("IP_DROP_MEMBERSHIP", 13),
    ("IPV6_JOIN_GROUP", 12),
    ("IPV6_LEAVE_GROUP", 13),
    ("IPV6_MULTICAST_HOPS", 10),
    ("IPV6_MULTICAST_IF", 9),
    ("IPV6_MULTICAST_LOOP", 11),
    ("IPV6_UNICAST_HOPS", 4),
    ("IPV6_V6ONLY", 27),
    ("IPV6_CHECKSUM", 26),
    ("IPV6_DONTFRAG", 14),
    ("IPV6_HOPLIMIT", 21),
    ("IPV6_HOPOPTS", 1),
    ("IPV6_PKTINFO", 19),
    ("IPV6_RECVRTHDR", 38),
    ("IPV6_RECVTCLASS", 40),
    ("IPV6_RTHDR", 32),
    ("IPV6_TCLASS", 39),
    ("TCP_NODELAY", 1),
    ("TCP_MAXSEG", 4),
    ("EAI_AGAIN", 11002),
    ("EAI_BADFLAGS", 10022),
    ("EAI_FAIL", 11003),
    ("EAI_FAMILY", 10047),
    ("EAI_MEMORY", 8),
    ("EAI_NODATA", 11001),
    ("EAI_NONAME", 11001),
    ("EAI_SERVICE", 10109),
    ("EAI_SOCKTYPE", 10044),
    ("AI_PASSIVE", 1),
    ("AI_CANONNAME", 2),
    ("AI_NUMERICHOST", 4),
    ("AI_NUMERICSERV", 8),
    ("AI_ALL", 256),
    ("AI_ADDRCONFIG", 1024),
    ("AI_V4MAPPED", 2048),
    ("NI_MAXHOST", 1025),
    ("NI_MAXSERV", 32),
    ("NI_NOFQDN", 1),
    ("NI_NUMERICHOST", 2),
    ("NI_NAMEREQD", 4),
    ("NI_NUMERICSERV", 8),
    ("NI_DGRAM", 16),
    ("SHUT_RD", 0),
    ("SHUT_WR", 1),
    ("SHUT_RDWR", 2),
    ("RCVALL_OFF", 0),
    ("RCVALL_ON", 1),
    ("RCVALL_SOCKETLEVELONLY", 2),
    ("RCVALL_MAX", 3),
];

/// `_socket` functions in table order for the Windows build.
const FUNCTIONS: [MethodSpec; 17] = [
    function("gethostbyname", socket_gethostbyname),
    function("gethostbyname_ex", socket_gethostbyname_ex),
    function("gethostbyaddr", socket_gethostbyaddr),
    function("gethostname", socket_gethostname),
    function("getservbyname", socket_getservbyname),
    function("getservbyport", socket_getservbyport),
    function("getprotobyname", socket_getprotobyname),
    function("ntohs", socket_ntohs),
    function("ntohl", socket_ntohl),
    function("htons", socket_htons),
    function("htonl", socket_htonl),
    function("inet_aton", socket_inet_aton),
    function("inet_ntoa", socket_inet_ntoa),
    function("getaddrinfo", socket_getaddrinfo),
    function("getnameinfo", socket_getnameinfo),
    function("getdefaulttimeout", socket_getdefaulttimeout),
    function("setdefaulttimeout", socket_setdefaulttimeout),
];

/// `socket` methods in table order for the Windows build, without
/// `dup` and `makefile`.
const METHODS: [MethodSpec; 26] = [
    static_method("__new__", sock_new),
    method("__init__", sock_init),
    method("__repr__", sock_repr),
    method("accept", sock_accept),
    method("bind", sock_bind),
    method("close", sock_close),
    method("connect", sock_connect),
    method("connect_ex", sock_connect_ex),
    method("fileno", sock_fileno),
    method("getpeername", sock_getpeername),
    method("getsockname", sock_getsockname),
    method("getsockopt", sock_getsockopt),
    method("ioctl", sock_ioctl),
    method("listen", sock_listen),
    method("recv", sock_recv),
    method("recv_into", sock_recv_into),
    method("recvfrom", sock_recvfrom),
    method("recvfrom_into", sock_recvfrom_into),
    method("send", sock_send),
    method("sendall", sock_sendall),
    method("sendto", sock_sendto),
    method("setblocking", sock_setblocking),
    method("settimeout", sock_settimeout),
    method("gettimeout", sock_gettimeout),
    method("setsockopt", sock_setsockopt),
    method("shutdown", sock_shutdown),
];

/// The default timeout: negative for no timeout.
struct SocketState {
    default_timeout: Cell<f64>,
}

impl Default for SocketState {
    fn default() -> Self {
        Self { default_timeout: Cell::new(-1.0) }
    }
}

/// The OS socket a socket object holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Descriptor {
    /// `INVALID_SOCKET`: not opened yet, or closed.
    Invalid,
    /// Whatever construction left: a handle the host created, or
    /// `INVALID_SOCKET` when its `socket()` call failed.
    Unknown,
}

/// A socket object. `None` fields are ones construction set or left as
/// they were, depending on the host.
struct Socket {
    descriptor: Cell<Descriptor>,
    family: Cell<Option<i32>>,
    kind: Cell<Option<i32>>,
    protocol: Cell<Option<i32>>,
    /// Negative for no timeout.
    timeout: Cell<Option<f64>>,
}

impl_native_data!(Socket, "_socket.socket");

impl Socket {
    /// The fields `socket.__new__` sets.
    fn new() -> Self {
        Self { descriptor: Cell::new(Descriptor::Invalid), family: Cell::new(Some(0)), kind: Cell::new(Some(0)), protocol: Cell::new(Some(0)), timeout: Cell::new(Some(-1.0)) }
    }
}

/// The arguments of `recv_into` and `recvfrom_into`.
struct ReceiveInto {
    /// `nbytes`: 0 when absent, `None` when unknown.
    length: Option<i64>,
    /// `None` when the buffer is unknown.
    buffer_length: Option<usize>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &FUNCTIONS)?;

    let error = socket_error(vm)?;
    set_attribute(vm, module, "error", Value::Object(error))?;
    set_attribute(vm, module, "herror", Value::Object(socket_herror(vm)?))?;
    set_attribute(vm, module, "gaierror", Value::Object(socket_gaierror(vm)?))?;
    set_attribute(vm, module, "timeout", Value::Object(socket_timeout(vm)?))?;

    let class = socket_type(vm)?;
    set_attribute(vm, module, "SocketType", Value::Object(Rc::clone(&class)))?;
    set_attribute(vm, module, "socket", Value::Object(class))?;

    // IPv6 is enabled in the Windows build.
    set_attribute(vm, module, "has_ipv6", Value::Bool(true))?;
    set_attribute(vm, module, "CAPI", new_capsule(vm, "_socket.CAPI")?)?;

    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, vm.new_int_from_i64(value))?;
    }
    // Converted as an unsigned C `long`, so `long` whatever the value.
    for (name, value) in [("SIO_RCVALL", SIO_RCVALL), ("SIO_KEEPALIVE_VALS", SIO_KEEPALIVE_VALS)] {
        set_attribute(vm, module, name, Value::long(value.into()))?;
    }

    Ok(())
}

/// `socket.error`, the base of the module's exceptions (a subclass of
/// `IOError`).
pub fn socket_error(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_socket.error", |vm| new_exception_class(vm, "socket", "error", vm.types().exception(ExceptionKind::IOError)))
}

fn socket_herror(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_socket.herror", |vm| new_exception_class(vm, "socket", "herror", &socket_error(vm)?))
}

fn socket_gaierror(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_socket.gaierror", |vm| new_exception_class(vm, "socket", "gaierror", &socket_error(vm)?))
}

fn socket_timeout(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_socket.timeout", |vm| new_exception_class(vm, "socket", "timeout", &socket_error(vm)?))
}

/// The `_socket.socket` type.
pub fn socket_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, TYPE_NAME, create_socket_type)
}

fn create_socket_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(vm, TypeSpec { name: "socket", module: "_socket", base: None, layout: Layout::Native, instance_dict: false, methods: &METHODS })?;

    add_member(vm, &class, GetSet { name: "family", owner: TYPE_NAME, get: member_family, set: None })?;
    add_member(vm, &class, GetSet { name: "type", owner: TYPE_NAME, get: member_type, set: None })?;
    add_member(vm, &class, GetSet { name: "proto", owner: TYPE_NAME, get: member_proto, set: None })?;
    add_member(vm, &class, GetSet { name: "timeout", owner: TYPE_NAME, get: member_timeout, set: None })?;

    Ok(class)
}

/// `socket.error` with `message`.
fn error(vm: &Vm, message: &str) -> Signal {
    match socket_error(vm) {
        Ok(class) => vm.raise_string(&class, Value::str(message)),
        Err(signal) => signal,
    }
}

fn host_result(vm: &Vm, name: &str) -> PyResult<Value> {
    vm.host_operation(HostCapability::Network, format!("_socket.{name}() (host operating system)"))
}

fn socket_method_result(vm: &Vm, name: &str) -> PyResult<Value> {
    vm.host_operation(HostCapability::Network, format!("_socket.socket.{name}() (host operating system)"))
}

/// The `i` format; `None` when the argument is unknown.
fn int_value(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    int_argument(vm, value).map(Some)
}

/// C `long` conversion, which converts floats through `__int__` as well;
/// `None` when the argument is unknown.
fn as_long(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let Some(number) = vm.as_float(value) else {
        return long_argument(vm, value).map(Some);
    };
    let integer = float_to_integer(vm, number)?;

    integer.to_i64().filter(|number| crate::interp::numbers::fits_int(vm.config.long_width, *number)).map(Some).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))
}

/// C `int` conversion; `None` when the argument is unknown.
fn as_int(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    let Some(number) = as_long(vm, value)? else {
        return Ok(None);
    };
    if i32::try_from(number).is_err() {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C int"));
    }

    Ok(Some(number))
}

/// The `I` format, an unsigned masked conversion; `None` when unknown.
fn unsigned_int_mask(vm: &Vm, value: &Value) -> PyResult<Option<u32>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if vm.as_float(value).is_some() {
        return Err(vm.type_error("integer argument expected, got float"));
    }

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let Some(convert) = vm.user_override(value, "__int__")? else {
                return Err(vm.type_error("an integer is required"));
            };
            let result = vm.call0(&convert)?;
            halt_on_unknown(&result, "__int__ result")?;
            let Some(integral) = vm.as_integral(&result) else {
                return Err(vm.type_error("nb_int should return int object"));
            };
            integral
        }
    };

    Ok(Some(mask_u32(&integral)))
}

/// The low 32 bits of an integer, as C unsigned conversions keep them.
fn mask_u32(integral: &Integral) -> u32 {
    let bits = match integral {
        Integral::Int(number) => *number,
        Integral::Long(number) => {
            let (sign, digits) = number.to_u32_digits();
            let low = i64::from(digits.first().copied().unwrap_or(0));
            if sign == Sign::Minus { -low } else { low }
        }
    };

    bits as u32
}

/// The `k` format of the Windows build (32-bit `unsigned long`); `None`
/// when unknown.
fn unsigned_long_mask(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<Option<u32>> {
    if value.is_unknown() {
        return Ok(None);
    }

    match vm.as_integral(value) {
        Some(integral) => Ok(Some(mask_u32(&integral))),
        None => Err(vm.type_error(&format!("{function}() argument {position} must be an integer, not {}", converted_type_name(vm, value)))),
    }
}

/// The `s*` format: a string, unicode in the default encoding, or any
/// readable buffer.
fn readable_buffer(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<()> {
    if value.is_unknown() || vm.as_str_bytes(value).is_some() || vm.buffer(value, BufferInterface::Any)?.is_some() {
        return Ok(());
    }
    if let Some(text) = vm.as_text(value) {
        vm.encode_default(&text)?;
        return Ok(());
    }

    Err(vm.type_error(&format!("{function}() argument {position} must be string or buffer, not {}", converted_type_name(vm, value))))
}

/// The `s#` format: a string, unicode in the default encoding, or a read
/// buffer without a release function. `None` when unknown.
fn read_only_buffer(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<Option<PyBytes>> {
    if value.is_unknown() {
        return Ok(None);
    }
    if let Some(bytes) = vm.as_str_bytes(value) {
        return Ok(Some(bytes));
    }
    if let Some(text) = vm.as_text(value) {
        let encoded = vm.encode_default(&text)?;
        return Ok(vm.as_str_bytes(&encoded));
    }
    if let Some(bytes) = vm.buffer(value, BufferInterface::Pinned)? {
        return Ok(Some(bytes));
    }

    Err(vm.type_error(&format!("{function}() argument {position} must be string or read-only buffer, not {}", converted_type_name(vm, value))))
}

/// The `w*` format: a writable buffer of the new protocol. Its length, or
/// `None` when unknown.
fn writable_buffer(vm: &Vm, value: &Value, function: &str) -> PyResult<Option<usize>> {
    if value.is_unknown() {
        return Ok(None);
    }

    let writable = vm.buffer_slots(value).is_some_and(|slots| slots.new && slots.write);
    let contents = if writable { vm.buffer(value, BufferInterface::New)? } else { None };
    match contents {
        Some(bytes) => Ok(Some(bytes.as_bytes().len())),
        None => Err(vm.type_error(&format!("{function}() argument 1 must be read-write buffer, not {}", converted_type_name(vm, value)))),
    }
}

fn socket_gethostname(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "gethostname")?;

    host_result(vm, "gethostname")
}

/// A function whose only argument is a host name (`s:name`).
fn name_query(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let arguments = positional(vm, args, name, 1, 1)?;
    for (index, argument) in arguments.iter().enumerate() {
        c_string(vm, argument, Some(name), index + 1)?;
    }

    host_result(vm, name)
}

/// `gethostbyname(name)`: `"<broadcast>"` and dotted decimal quads
/// resolve without the host, and the address prints in dotted form.
fn socket_gethostbyname(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "gethostbyname", 1, 1)?;
    let Some(name) = c_string(vm, &arguments[0], Some("gethostbyname"), 1)? else {
        return host_result(vm, "gethostbyname");
    };
    let Some([a, b, c, d]) = local_address(name.as_bytes()) else {
        return host_result(vm, "gethostbyname");
    };

    Ok(Value::str(&format!("{a}.{b}.{c}.{d}")))
}

fn socket_gethostbyname_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    name_query(vm, args, "gethostbyname_ex")
}

fn socket_gethostbyaddr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    name_query(vm, args, "gethostbyaddr")
}

fn socket_getprotobyname(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    name_query(vm, args, "getprotobyname")
}

/// `getservbyname(servicename[, protocolname])` (`s|s`).
fn socket_getservbyname(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "getservbyname", 1, 2)?;
    for (index, argument) in arguments.iter().enumerate() {
        c_string(vm, argument, Some("getservbyname"), index + 1)?;
    }

    host_result(vm, "getservbyname")
}

/// `getservbyport(port[, protocolname])` (`i|s`).
fn socket_getservbyport(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "getservbyport", 1, 2)?;

    let port = int_value(vm, &arguments[0])?;
    if let Some(protocol) = arguments.get(1) {
        c_string(vm, protocol, Some("getservbyport"), 2)?;
    }
    if port.is_some_and(|port| !(0..=0xffff).contains(&port)) {
        return Err(vm.raise(ExceptionKind::OverflowError, "getservbyport: port must be 0-65535."));
    }

    host_result(vm, "getservbyport")
}

/// `ntohs` and `htons` (`i:name`): the byte swap of the low 16 bits on
/// little-endian Windows.
fn short_swap(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let arguments = positional(vm, args, name, 1, 1)?;
    let Some(number) = int_value(vm, &arguments[0])? else {
        return Ok(Value::unknown(format!("_socket.{name}() of an unknown value")));
    };
    if number < 0 {
        return Err(vm.raise(ExceptionKind::OverflowError, "can't convert negative number to unsigned long"));
    }

    Ok(vm.new_int_from_i64(i64::from((number as u16).swap_bytes())))
}

fn socket_ntohs(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    short_swap(vm, args, "ntohs")
}

fn socket_htons(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    short_swap(vm, args, "htons")
}

/// `ntohl` and `htonl`: the byte swap of a 32-bit `unsigned long`,
/// returned as a `long`.
fn long_swap(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let argument = one_function_argument(vm, args, name)?;
    if argument.is_unknown() {
        return Ok(Value::unknown(format!("_socket.{name}() of an unknown value")));
    }

    let number = match vm.as_integral(&argument) {
        Some(Integral::Int(number)) if number < 0 => {
            return Err(vm.raise(ExceptionKind::OverflowError, "can't convert negative number to unsigned long"));
        }
        Some(Integral::Int(number)) => u32::try_from(number).ok(),
        Some(Integral::Long(number)) if number.sign() == Sign::Minus => {
            return Err(vm.raise(ExceptionKind::OverflowError, "can't convert negative value to unsigned long"));
        }
        Some(Integral::Long(number)) => number.to_u32(),
        None => return Err(vm.type_error(&format!("expected int/long, {} found", vm.type_name(&argument)))),
    };
    let Some(number) = number else {
        return Err(vm.raise(ExceptionKind::OverflowError, "long int too large to convert"));
    };

    Ok(Value::long(number.swap_bytes().into()))
}

fn socket_ntohl(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    long_swap(vm, args, "ntohl")
}

fn socket_htonl(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    long_swap(vm, args, "htonl")
}

/// The argument of a single-argument function.
fn one_function_argument(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    let Ok([argument]) = <[Value; 1]>::try_from(args.positional) else {
        return Err(vm.type_error(&format!("{name}() takes exactly one argument ({count} given)")));
    };

    Ok(argument)
}

/// `inet_aton(string)` (`s:inet_aton`). The Windows build lacks
/// `inet_aton` and calls Winsock's `inet_addr`, which rejects
/// `INADDR_NONE` except as `"255.255.255.255"`.
fn socket_inet_aton(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "inet_aton", 1, 1)?;
    let Some(text) = c_string(vm, &arguments[0], Some("inet_aton"), 1)? else {
        return Ok(Value::unknown("_socket.inet_aton() of an unknown value"));
    };

    let address = if text.as_bytes() == b"255.255.255.255" {
        Some([0xff; 4])
    } else {
        inet_addr(text.as_bytes()).filter(|address| *address != [0xff; 4])
    };
    let Some(address) = address else {
        return Err(error(vm, "illegal IP address string passed to inet_aton"));
    };

    Ok(Value::Str(PyBytes::new(address.to_vec())))
}

/// Winsock `inet_addr` as the Wine `ws2_32` the reference build runs on
/// implements it: one to four dot-separated `strtoul` numbers (decimal,
/// octal, or hex), each starting with a digit, ending at the end of the
/// string or at white space; the last number fills the remaining bytes.
/// `None` is `INADDR_NONE`. The result is in network byte order.
fn inet_addr(text: &[u8]) -> Option<[u8; 4]> {
    if text == b" " {
        return Some([0; 4]);
    }

    let mut parts = [0_u32; 4];
    let mut count = 0;
    let mut position = 0;
    loop {
        let slot = parts.get_mut(count)?;
        if !text.get(position).is_some_and(u8::is_ascii_digit) {
            return None;
        }
        let (value, end) = strtoul(text, position);
        *slot = value;
        count += 1;
        match text.get(end) {
            None => break,
            Some(byte) if is_c_space(*byte) => break,
            Some(b'.') => position = end + 1,
            Some(_) => return None,
        }
    }

    let mut bytes = [0_u32; 4];
    let (leading, last) = parts.split_at(count - 1);
    bytes[..leading.len()].copy_from_slice(leading);
    let mut remainder = last.first().copied().unwrap_or(0);
    for index in (leading.len()..4).rev() {
        let Some(slot) = bytes.get_mut(index) else {
            return None;
        };
        *slot = if index == leading.len() { remainder } else { remainder & 0xff };
        remainder >>= 8;
    }

    let mut address = [0_u8; 4];
    for (target, value) in address.iter_mut().zip(bytes) {
        *target = u8::try_from(value).ok()?;
    }

    Some(address)
}

/// `strtoul(text + start, &end, 0)` of the 32-bit `unsigned long`, for a
/// number that starts with a digit: the value, saturated at `ULONG_MAX`,
/// and where it ends.
fn strtoul(text: &[u8], start: usize) -> (u32, usize) {
    let rest = text.get(start..).unwrap_or_default();
    let is_hex_prefix = matches!(rest, [b'0', b'x' | b'X', next, ..] if next.is_ascii_hexdigit());
    let (radix, digits_start) = if is_hex_prefix {
        (16, start + 2)
    } else if rest.first() == Some(&b'0') {
        (8, start)
    } else {
        (10, start)
    };

    let mut value = 0_u64;
    let mut end = digits_start;
    while let Some(digit) = text.get(end).and_then(|byte| char::from(*byte).to_digit(radix)) {
        value = (value * u64::from(radix) + u64::from(digit)).min(u64::from(u32::MAX) + 1);
        end += 1;
    }

    (u32::try_from(value).unwrap_or(u32::MAX), end)
}

/// C `isspace` in the "C" locale.
fn is_c_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `inet_ntoa(packed_ip)` (`s#:inet_ntoa`).
fn socket_inet_ntoa(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "inet_ntoa", 1, 1)?;
    let Some(packed) = read_only_buffer(vm, &arguments[0], "inet_ntoa", 1)? else {
        return Ok(Value::unknown("_socket.inet_ntoa() of an unknown value"));
    };
    let [a, b, c, d] = packed.as_bytes() else {
        return Err(error(vm, "packed IP wrong length for inet_ntoa"));
    };

    Ok(Value::str(&format!("{a}.{b}.{c}.{d}")))
}

/// `getaddrinfo(host, port[, family, socktype, proto, flags])`.
fn socket_getaddrinfo(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "getaddrinfo", 2, 6)?;
    for argument in arguments.iter().skip(2) {
        int_value(vm, argument)?;
    }

    let host = &arguments[0];
    if !host.is_unknown() && !host.is_none() && vm.as_str_bytes(host).is_none() {
        if vm.as_text(host).is_none() {
            return Err(vm.type_error("getaddrinfo() argument 1 must be string or None"));
        }
        vm.call_method(host, "encode", vec![Value::str("idna")])?;
    }

    let port = &arguments[1];
    if port.is_unknown() || port.is_none() || vm.as_str_bytes(port).is_some() {
        return host_result(vm, "getaddrinfo");
    }
    match vm.as_integral(port) {
        Some(integral) => {
            let fits = match integral {
                Integral::Int(number) => crate::interp::numbers::fits_int(vm.config.long_width, number),
                Integral::Long(number) => number.to_i64().is_some_and(|number| crate::interp::numbers::fits_int(vm.config.long_width, number)),
            };
            if !fits {
                return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
            }
        }
        None => return Err(error(vm, "getaddrinfo() argument 2 must be integer or string")),
    }

    host_result(vm, "getaddrinfo")
}

/// `getnameinfo(sockaddr, flags)` (`Oi:getnameinfo`, then `si|II` on the
/// address).
fn socket_getnameinfo(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = positional(vm, args, "getnameinfo", 2, 2)?;
    int_value(vm, &arguments[1])?;

    let address = &arguments[0];
    if address.is_unknown() {
        return host_result(vm, "getnameinfo");
    }
    let Some(items) = vm.as_tuple(address) else {
        return Err(vm.type_error("getnameinfo() argument 1 must be a tuple"));
    };
    tuple_count(vm, &items, None, 2, 4)?;
    c_string(vm, &items[0], None, 1)?;
    int_value(vm, &items[1])?;
    let flowinfo = match items.get(2) {
        Some(item) => unsigned_int_mask(vm, item)?,
        None => Some(0),
    };
    if let Some(item) = items.get(3) {
        unsigned_int_mask(vm, item)?;
    }
    if flowinfo.is_some_and(|flowinfo| flowinfo > 0xfffff) {
        return Err(vm.raise(ExceptionKind::OverflowError, "getsockaddrarg: flowinfo must be 0-1048575."));
    }

    host_result(vm, "getnameinfo")
}

/// The count check of format parsing on a tuple argument; `function` is
/// the name after `:` in the format, if any.
fn tuple_count(vm: &Vm, items: &[Value], function: Option<&str>, minimum: usize, maximum: usize) -> PyResult<()> {
    let count = items.len();
    if (minimum..=maximum).contains(&count) {
        return Ok(());
    }

    let (bound, limit) = if minimum == maximum {
        ("exactly", minimum)
    } else if count < minimum {
        ("at least", minimum)
    } else {
        ("at most", maximum)
    };
    let plural = if limit == 1 { "" } else { "s" };
    let subject = function.map_or_else(|| "function".to_owned(), |name| format!("{name}()"));

    Err(vm.type_error(&format!("{subject} takes {bound} {limit} argument{plural} ({count} given)")))
}

fn socket_getdefaulttimeout(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getdefaulttimeout")?;

    Ok(timeout_value(vm.native_state::<SocketState>().default_timeout.get()))
}

fn socket_setdefaulttimeout(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = one_function_argument(vm, args, "setdefaulttimeout")?;
    let timeout = parse_timeout(vm, &argument)?;

    vm.native_state::<SocketState>().default_timeout.set(timeout);

    Ok(Value::None)
}

/// The timeout argument of `settimeout` and `setdefaulttimeout`: `None`
/// is no timeout (-1.0); negative values are rejected.
fn parse_timeout(vm: &Vm, value: &Value) -> PyResult<f64> {
    if value.is_none() {
        return Ok(-1.0);
    }

    halt_on_unknown(value, "socket timeout")?;
    let timeout = float_as_double(vm, value)?;
    if timeout < 0.0 {
        return Err(vm.raise(ExceptionKind::ValueError, "Timeout value out of range"));
    }

    Ok(timeout)
}

fn timeout_value(timeout: f64) -> Value {
    if timeout < 0.0 { Value::None } else { Value::Float(timeout) }
}

/// `socket.__new__`: a socket object without an OS socket.
fn sock_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = socket_type(vm)?;
    let (class, _) = new_class(vm, args, &base)?;

    Ok(new_instance(vm, &class, Payload::Native(Box::new(Socket::new()))))
}

/// Construction: `socket(family=AF_INET, type=SOCK_STREAM, proto=0)`.
/// Winsock's `socket()` may fail, raising `socket.error`, or open a
/// socket whose fields are then set, so after the arguments are
/// checked the outcome and the object's fields are unknown. A call to the
/// class returns this unknown result as the constructed object.
fn sock_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "__init__")?;
    let rest = CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    parse_with(vm, rest, "socket", &["family", "type", "proto"], 0, |vm, _, value| int_value(vm, &value))?;
    let result = vm.host_operation(HostCapability::Network, "_socket.socket() (host operating system)")?;

    socket.descriptor.set(Descriptor::Unknown);
    socket.family.set(None);
    socket.kind.set(None);
    socket.protocol.set(None);
    socket.timeout.set(None);

    Ok(result)
}

/// `socket.__repr__`.
fn sock_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "__repr__")?;
    let (Descriptor::Invalid, Some(family), Some(kind), Some(protocol)) = (socket.descriptor.get(), socket.family.get(), socket.kind.get(), socket.protocol.get()) else {
        return Ok(Value::unknown("_socket.socket.__repr__() (host operating system)"));
    };

    Ok(Value::str(&format!("<socket object, fd=-1, family={family}, type={kind}, protocol={protocol}>")))
}

fn member_socket<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Socket> {
    native_data::<Socket>(instance).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

/// An `int` member; unknown after construction.
fn int_member(field: Option<i32>, name: &str) -> Value {
    field.map_or_else(|| Value::unknown(format!("_socket.socket.{name} (host operating system)")), |value| Value::Int(i64::from(value)))
}

fn member_family(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(int_member(member_socket(vm, getset, instance)?.family.get(), "family"))
}

fn member_type(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(int_member(member_socket(vm, getset, instance)?.kind.get(), "type"))
}

fn member_proto(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(int_member(member_socket(vm, getset, instance)?.protocol.get(), "proto"))
}

fn member_timeout(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(member_socket(vm, getset, instance)?.timeout.get().map_or_else(|| Value::unknown("_socket.socket.timeout (host operating system)"), Value::Float))
}

/// `getsockaddrlen`: only the IP families have socket addresses.
fn check_address_length(vm: &Vm, socket: &Socket) -> PyResult<()> {
    match socket.family.get() {
        None | Some(AF_INET | AF_INET6) => Ok(()),
        Some(_) => Err(error(vm, "getsockaddrlen: bad family")),
    }
}

/// The address argument check. A known family is the 0 of `socket.__new__`, which has no
/// address format; the family of an opened socket is unknown, so its
/// address checks cannot be decided.
fn check_address(vm: &Vm, socket: &Socket) -> PyResult<()> {
    match socket.family.get() {
        None => Ok(()),
        Some(_) => Err(error(vm, "getsockaddrarg: bad family")),
    }
}

/// The names resolved without `getaddrinfo`:
/// `"<broadcast>"` and dotted decimal quads (as `sscanf("%d.%d.%d.%d%c")`
/// reads them). The address in network byte order.
fn local_address(name: &[u8]) -> Option<[u8; 4]> {
    if name == b"<broadcast>" {
        return Some([0xff; 4]);
    }

    let parts = scan_quad(name)?;
    let mut address = [0_u8; 4];
    for (target, part) in address.iter_mut().zip(parts) {
        *target = u8::try_from(part).ok()?;
    }

    Some(address)
}

/// `sscanf(name, "%d.%d.%d.%d%c", ...) == 4`: the four numbers, or `None`
/// when the scan stops early, text follows, or a number's digits do not
/// fit the range whose overflow behavior is known.
fn scan_quad(name: &[u8]) -> Option<[i64; 4]> {
    let mut parts = [0_i64; 4];
    let mut position = 0;
    for (index, part) in parts.iter_mut().enumerate() {
        if index > 0 {
            if name.get(position) != Some(&b'.') {
                return None;
            }
            position += 1;
        }
        let (value, end) = scan_decimal(name, position)?;
        *part = value;
        position = end;
    }

    (position == name.len()).then_some(parts)
}

/// The `%d` conversion: white space, a sign, and decimal digits.
fn scan_decimal(text: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut position = start;
    while text.get(position).is_some_and(|byte| is_c_space(*byte)) {
        position += 1;
    }

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

    let digits_start = position;
    while text.get(position).is_some_and(u8::is_ascii_digit) {
        position += 1;
    }
    let digits = text.get(digits_start..position)?;
    if digits.is_empty() {
        return None;
    }

    let significant = digits.iter().position(|digit| *digit != b'0').map_or(&digits[digits.len()..], |first| &digits[first..]);
    if significant.len() > 9 {
        return None;
    }
    let magnitude = significant.iter().fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'));

    Some((if negative { -magnitude } else { magnitude }, position))
}

fn sock_accept(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "accept")?;
    method_no_arguments(vm, &args, "accept")?;
    check_address_length(vm, socket)?;

    socket_method_result(vm, "accept")
}

fn sock_bind(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    address_method(vm, args, "bind")
}

fn sock_connect(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    address_method(vm, args, "connect")
}

fn sock_connect_ex(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    address_method(vm, args, "connect_ex")
}

/// A single-argument method taking a socket address.
fn address_method(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, name)?;
    method_one_argument(vm, &args, name)?;
    check_address(vm, socket)?;

    socket_method_result(vm, name)
}

/// `socket.close`: the descriptor becomes invalid; the result of the host's
/// `closesocket` is ignored.
fn sock_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "close")?;
    method_no_arguments(vm, &args, "close")?;

    socket.descriptor.set(Descriptor::Invalid);

    Ok(Value::None)
}

/// `socket.fileno`: a 64-bit `SOCKET` handle as a `long`; `INVALID_SOCKET`
/// reads as -1.
fn sock_fileno(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "fileno")?;
    method_no_arguments(vm, &args, "fileno")?;

    match socket.descriptor.get() {
        Descriptor::Invalid => Ok(Value::long((-1).into())),
        Descriptor::Unknown => Ok(Value::unknown("_socket.socket.fileno() (host operating system)")),
    }
}

fn sock_getpeername(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    address_query(vm, args, "getpeername")
}

fn sock_getsockname(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    address_query(vm, args, "getsockname")
}

/// A no-argument method returning a socket address.
fn address_query(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, name)?;
    method_no_arguments(vm, &args, name)?;
    check_address_length(vm, socket)?;

    socket_method_result(vm, name)
}

/// `getsockopt(level, option[, buffersize])` (`ii|i:getsockopt`).
fn sock_getsockopt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, "getsockopt")?;
    let arguments = method_arguments(vm, &args, "getsockopt", 2, 3)?;

    let mut values = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        values.push(int_value(vm, argument)?);
    }
    if let Some(Some(length)) = values.get(2).copied() {
        if length != 0 && !(1..=1024).contains(&length) {
            return Err(error(vm, "getsockopt buflen out of range"));
        }
    }

    socket_method_result(vm, "getsockopt")
}

/// `ioctl(cmd, option)` (`kO:ioctl`, then a format for the command).
fn sock_ioctl(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, "ioctl")?;
    let arguments = method_arguments(vm, &args, "ioctl", 2, 2)?;
    let Some(command) = unsigned_long_mask(vm, &arguments[0], "ioctl", 1)? else {
        return socket_method_result(vm, "ioctl");
    };

    let option = &arguments[1];
    match command {
        SIO_RCVALL => {
            unsigned_int_mask(vm, option)?;
        }
        SIO_KEEPALIVE_VALS => check_keepalive(vm, option)?,
        _ => return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid ioctl command {}", command as i32))),
    }

    socket_method_result(vm, "ioctl")
}

/// The `(kkk)` option of `SIO_KEEPALIVE_VALS`.
fn check_keepalive(vm: &Vm, option: &Value) -> PyResult<()> {
    if option.is_unknown() {
        return Ok(());
    }

    let items = if let Some(items) = vm.as_tuple(option) {
        items.to_vec()
    } else if let Some(items) = vm.as_list(option) {
        items
    } else if let Some(text) = vm.as_text(option) {
        // The items of unicode are unicode, which `k` rejects.
        let length = text.units().len();
        if length != 3 {
            return Err(vm.type_error(&format!("ioctl() argument 2 must be sequence of length 3, not {length}")));
        }
        return Err(vm.type_error("ioctl() argument 2, item 0 must be an integer, not unicode"));
    } else if vm.as_str_bytes(option).is_some() || vm.as_integral(option).is_some() || vm.as_float(option).is_some() || option.is_none() {
        return Err(vm.type_error(&format!("ioctl() argument 2 must be 3-item sequence, not {}", converted_type_name(vm, option))));
    } else {
        return Err(vm.halt_unsupported("ioctl() keepalive option of a non-builtin sequence type"));
    };

    if items.len() != 3 {
        return Err(vm.type_error(&format!("ioctl() argument 2 must be sequence of length 3, not {}", items.len())));
    }
    for (index, item) in items.iter().enumerate() {
        if !item.is_unknown() && vm.as_integral(item).is_none() {
            return Err(vm.type_error(&format!("ioctl() argument 2, item {index} must be an integer, not {}", converted_type_name(vm, item))));
        }
    }

    Ok(())
}

fn sock_listen(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    int_method(vm, args, "listen")
}

fn sock_shutdown(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    int_method(vm, args, "shutdown")
}

/// A single-argument method converting its argument to a C `int`.
fn int_method(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, name)?;
    let argument = method_one_argument(vm, &args, name)?;
    as_int(vm, &argument)?;

    socket_method_result(vm, name)
}

fn sock_recv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receive(vm, args, "recv")
}

fn sock_recvfrom(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    receive(vm, args, "recvfrom")
}

/// `recv` and `recvfrom` (`i|i`).
fn receive(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, name)?;
    let arguments = method_arguments(vm, &args, name, 1, 2)?;

    let length = int_value(vm, &arguments[0])?;
    if let Some(flags) = arguments.get(1) {
        int_value(vm, flags)?;
    }
    if length.is_some_and(|length| length < 0) {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("negative buffersize in {name}")));
    }
    if name == "recvfrom" {
        check_address_length(vm, socket)?;
    }

    socket_method_result(vm, name)
}

/// `recv_into(buffer[, nbytes[, flags]])`: validated, then halts since
/// the host's data would fill the buffer.
fn sock_recv_into(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, "recv_into")?;
    let request = receive_into_arguments(vm, args, "recv_into")?;

    if let (Some(length), Some(buffer_length)) = (request.length, request.buffer_length) {
        if length < 0 {
            return Err(vm.raise(ExceptionKind::ValueError, "negative buffersize in recv_into"));
        }
        let requested = if length == 0 { buffer_length } else { usize::try_from(length).unwrap_or(usize::MAX) };
        if buffer_length < requested {
            return Err(vm.raise(ExceptionKind::ValueError, "buffer too small for requested bytes"));
        }
    }
    vm.host_permit(HostCapability::Network, Denial::Native, None)?;

    Err(vm.halt_unsupported("_socket.socket.recv_into() fills a buffer with host data"))
}

/// `recvfrom_into(buffer[, nbytes[, flags]])`: validated, then halts
/// since the host's data would fill the buffer.
fn sock_recvfrom_into(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "recvfrom_into")?;
    let request = receive_into_arguments(vm, args.clone(), "recvfrom_into")?;

    if let (Some(length), Some(buffer_length)) = (request.length, request.buffer_length) {
        if length < 0 {
            return Err(vm.raise(ExceptionKind::ValueError, "negative buffersize in recvfrom_into"));
        }
        if usize::try_from(length).is_ok_and(|length| length > buffer_length) {
            return Err(vm.raise(ExceptionKind::ValueError, "nbytes is greater than the length of the buffer"));
        }
    }
    check_address_length(vm, socket)?;
    vm.host_permit(HostCapability::Network, Denial::Native, None)?;

    Err(vm.halt_unsupported("_socket.socket.recvfrom_into() fills a buffer with host data"))
}

/// `w*|ii` with keywords `buffer`, `nbytes`, and `flags`, after the
/// receiver.
fn receive_into_arguments(vm: &Vm, args: CallArgs, name: &str) -> PyResult<ReceiveInto> {
    let rest = CallArgs { positional: args.positional[1..].to_vec(), keywords: args.keywords, keyword_dict: args.keyword_dict };

    let mut buffer_length = None;
    let slots = parse_with(vm, rest, name, &["buffer", "nbytes", "flags"], 1, |vm, index, value| {
        if index == 0 {
            buffer_length = writable_buffer(vm, &value, name)?;
            return Ok(Some(0));
        }
        int_value(vm, &value)
    })?;
    let length = match slots.get(1) {
        Some(Some(length)) => *length,
        _ => Some(0),
    };

    Ok(ReceiveInto { length, buffer_length })
}

fn sock_send(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    send(vm, args, "send")
}

fn sock_sendall(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    send(vm, args, "sendall")
}

/// `send` and `sendall` (`s*|i`).
fn send(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, name)?;
    let arguments = method_arguments(vm, &args, name, 1, 2)?;

    readable_buffer(vm, &arguments[0], name, 1)?;
    if let Some(flags) = arguments.get(1) {
        int_value(vm, flags)?;
    }

    socket_method_result(vm, name)
}

/// `sendto(data[, flags], address)`: `s*O` or `s*iO` by argument count.
fn sock_sendto(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "sendto")?;
    if args.has_keywords() {
        return Err(vm.type_error("sendto() takes no keyword arguments"));
    }

    let arguments = &args.positional[1..];
    match arguments {
        [data, _] => readable_buffer(vm, data, "sendto", 1)?,
        [data, flags, _] => {
            readable_buffer(vm, data, "sendto", 1)?;
            int_value(vm, flags)?;
        }
        _ => return Err(vm.type_error(&format!("sendto() takes 2 or 3 arguments ({} given)", arguments.len()))),
    }
    check_address(vm, socket)?;

    socket_method_result(vm, "sendto")
}

/// `socket.setblocking`: blocking is no timeout, non-blocking a zero
/// timeout. The host's `ioctlsocket` result is ignored. An unknown flag
/// leaves the timeout unknown.
fn sock_setblocking(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "setblocking")?;
    let argument = method_one_argument(vm, &args, "setblocking")?;
    let Some(block) = as_long(vm, &argument)? else {
        socket.timeout.set(None);
        return Ok(Value::unknown("_socket.socket.setblocking() of an unknown flag"));
    };

    socket.timeout.set(Some(if block == 0 { 0.0 } else { -1.0 }));

    Ok(Value::None)
}

/// `socket.settimeout`. The host's `ioctlsocket` result is ignored. An
/// unknown timeout leaves the timeout unknown.
fn sock_settimeout(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "settimeout")?;
    let argument = method_one_argument(vm, &args, "settimeout")?;
    if argument.is_unknown() {
        socket.timeout.set(None);
        return Ok(Value::unknown("_socket.socket.settimeout() of an unknown timeout"));
    }
    let timeout = parse_timeout(vm, &argument)?;

    socket.timeout.set(Some(timeout));

    Ok(Value::None)
}

fn sock_gettimeout(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let socket = this::<Socket>(vm, &args, TYPE_NAME, "gettimeout")?;
    method_no_arguments(vm, &args, "gettimeout")?;

    Ok(socket.timeout.get().map_or_else(|| Value::unknown("_socket.socket.gettimeout() (host operating system)"), timeout_value))
}

/// `setsockopt(level, option, value)`: `iii`, or else `iis#`, whose
/// errors are the ones reported.
fn sock_setsockopt(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Socket>(vm, &args, TYPE_NAME, "setsockopt")?;
    let arguments = method_arguments(vm, &args, "setsockopt", 3, 3)?;

    int_value(vm, &arguments[0])?;
    int_value(vm, &arguments[1])?;
    let value = &arguments[2];
    match int_value(vm, value) {
        Ok(_) => {}
        Err(Signal::Raise(_)) => {
            read_only_buffer(vm, value, "setsockopt", 3)?;
        }
        Err(halt) => return Err(halt),
    }

    socket_method_result(vm, "setsockopt")
}
