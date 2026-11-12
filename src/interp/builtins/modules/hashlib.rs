//! `_hashlib`. Only the six digests every OpenSSL build provides are
//! known. Other names depend on the host OpenSSL, so calls naming them
//! return unknown values.

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::binascii::varargs;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::digests::Algorithm;
use crate::interp::builtins::modules::digests::HashState;
use crate::interp::builtins::modules::digests::data_argument;
use crate::interp::builtins::modules::digests::digest_value;
use crate::interp::builtins::modules::digests::hexdigest_value;
use crate::interp::builtins::modules::digests::optional_data_argument;
use crate::interp::builtins::modules::digests;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers::fits_int;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const HASH_TYPE: &str = "_hashlib.HASH";

/// An `EVPobject`.
struct HashObject {
    /// The name object the constructor received, reported as `name`.
    name: Value,
    /// `name` as a C string, for `repr`.
    label: PyBytes,
    algorithm: Algorithm,
    state: RefCell<HashState>,
}

impl_native_data!(HashObject, "_hashlib.HASH");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("new", new),
            function("openssl_md5", openssl_md5),
            function("openssl_sha1", openssl_sha1),
            function("openssl_sha224", openssl_sha224),
            function("openssl_sha256", openssl_sha256),
            function("openssl_sha384", openssl_sha384),
            function("openssl_sha512", openssl_sha512),
            function("pbkdf2_hmac", pbkdf2_hmac),
        ],
    )?;

    // `OBJ_NAME_do_all` lists the digests of the host OpenSSL build.
    set_attribute(vm, module, "openssl_md_meth_names", Value::unknown("_hashlib.openssl_md_meth_names"))
}

fn create_hash_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "HASH",
            module: "_hashlib",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("update", hash_update), method("digest", hash_digest), method("hexdigest", hash_hexdigest), method("copy", hash_copy), method("__repr__", hash_repr)],
        },
    )?;

    add_member(vm, &class, GetSet { name: "name", owner: HASH_TYPE, get: hash_name, set: None })?;
    add_getset(vm, &class, GetSet { name: "digest_size", owner: HASH_TYPE, get: hash_digest_size, set: None })?;
    add_getset(vm, &class, GetSet { name: "block_size", owner: HASH_TYPE, get: hash_block_size, set: None })?;
    add_getset(vm, &class, GetSet { name: "digestsize", owner: HASH_TYPE, get: hash_digest_size, set: None })?;

    Ok(class)
}

/// The name of each `openssl_*` constructor.
fn constructor_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Md5 => "md5",
        Algorithm::Sha1 => "sha1",
        Algorithm::Sha224 => "sha224",
        Algorithm::Sha256 => "sha256",
        Algorithm::Sha384 => "sha384",
        Algorithm::Sha512 => "sha512",
    }
}

/// `EVP_get_digestbyname` for the short and long object names of the six
/// known digests. `None` for every other name, which the host OpenSSL may
/// or may not provide.
fn known_digest(name: &[u8]) -> Option<Algorithm> {
    match name {
        b"md5" | b"MD5" => Some(Algorithm::Md5),
        b"sha1" | b"SHA1" => Some(Algorithm::Sha1),
        b"sha224" | b"SHA224" => Some(Algorithm::Sha224),
        b"sha256" | b"SHA256" => Some(Algorithm::Sha256),
        b"sha384" | b"SHA384" => Some(Algorithm::Sha384),
        b"sha512" | b"SHA512" => Some(Algorithm::Sha512),
        _ => None,
    }
}

/// `EVPnew`. `data` is `None` when it is unknown.
fn new_hash(vm: &Vm, name: Value, label: PyBytes, algorithm: Algorithm, data: Option<PyBytes>) -> PyResult<Value> {
    let mut state = HashState::new(algorithm);
    state.update(data.as_ref().map(PyBytes::as_bytes));

    let class = native_type(vm, HASH_TYPE, create_hash_type)?;
    let object = HashObject { name, label, algorithm, state: RefCell::new(state) };

    Ok(new_native_object(vm, &class, object))
}

/// `_hashlib.new(name, string='')`.
fn new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse_with(vm, args, "new", &["name", "string"], 1, |vm, index, value| match index {
        0 => Ok(value),
        _ => Ok(data_argument(vm, &value, "new", 2)?.map_or(value, Value::Str)),
    })?;
    let mut slots = slots.into_iter();
    let Some(Some(name)) = slots.next() else {
        return Err(vm.type_error("Required argument 'name' (pos 1) not found"));
    };
    let data = match slots.next().flatten() {
        None => Some(PyBytes::from("")),
        Some(Value::Str(bytes)) => Some(bytes),
        Some(_) => None,
    };

    if name.is_unknown() {
        return Ok(Value::unknown("_hashlib.new"));
    }
    let label = match c_string(vm, "new", 1, &name) {
        Ok(label) => label,
        Err(Signal::Raise(_)) => return Err(vm.type_error("name must be a string")),
        Err(signal) => return Err(signal),
    };
    let Some(algorithm) = known_digest(label.as_bytes()) else {
        return Ok(Value::unknown("_hashlib.new"));
    };

    new_hash(vm, name, label, algorithm, data)
}

/// `_hashlib.openssl_<name>`.
fn openssl_constructor(vm: &Vm, args: CallArgs, algorithm: Algorithm) -> PyResult<Value> {
    let name = constructor_name(algorithm);
    let values = varargs(vm, args, &format!("openssl_{name}"), name, 0, 1)?;
    let data = optional_data_argument(vm, values.first(), name, 1)?;

    new_hash(vm, Value::str(name), PyBytes::from(name), algorithm, data)
}

fn openssl_md5(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Md5)
}

fn openssl_sha1(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Sha1)
}

fn openssl_sha224(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Sha224)
}

fn openssl_sha256(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Sha256)
}

fn openssl_sha384(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Sha384)
}

fn openssl_sha512(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    openssl_constructor(vm, args, Algorithm::Sha512)
}

fn the_hash<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a HashObject> {
    this::<HashObject>(vm, args, HASH_TYPE, method)
}

/// `HASH.update`.
fn hash_update(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let hash = the_hash(vm, &args, "update")?;
    let values = method_arguments(vm, &args, "update", 1, 1)?;
    let Some(value) = values.first() else {
        return Err(vm.type_error("update() takes exactly 1 argument (0 given)"));
    };

    let data = data_argument(vm, value, "update", 1)?;
    hash.state.borrow_mut().update(data.as_ref().map(PyBytes::as_bytes));

    Ok(Value::None)
}

/// `HASH.digest`.
fn hash_digest(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let hash = the_hash(vm, &args, "digest")?;
    method_no_arguments(vm, &args, "digest")?;

    Ok(digest_value(&hash.state.borrow(), HASH_TYPE))
}

/// `HASH.hexdigest`.
fn hash_hexdigest(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let hash = the_hash(vm, &args, "hexdigest")?;
    method_no_arguments(vm, &args, "hexdigest")?;

    Ok(hexdigest_value(&hash.state.borrow(), HASH_TYPE))
}

/// `HASH.copy`.
fn hash_copy(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let hash = the_hash(vm, &args, "copy")?;
    method_no_arguments(vm, &args, "copy")?;

    let class = native_type(vm, HASH_TYPE, create_hash_type)?;
    let copy = HashObject { name: hash.name.clone(), label: hash.label.clone(), algorithm: hash.algorithm, state: RefCell::new(hash.state.borrow().clone()) };

    Ok(new_native_object(vm, &class, copy))
}

/// The `repr` of a hash object. `%p` follows the Microsoft C runtime:
/// sixteen uppercase digits without a prefix.
fn hash_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let hash = the_hash(vm, &args, "__repr__")?;
    if args.has_keywords() {
        return Err(vm.type_error("wrapper __repr__ doesn't take keyword arguments"));
    }
    let [Value::Object(object)] = args.positional.as_slice() else {
        return Err(vm.type_error(&format!("expected 0 arguments, got {}", args.positional.len().saturating_sub(1))));
    };

    let mut text = b"<".to_vec();
    text.extend_from_slice(hash.label.as_bytes());
    text.extend_from_slice(format!(" HASH object @ {}>", vm.c_pointer_text(vm.address_of(object))).as_bytes());

    Ok(Value::Str(PyBytes::new(text)))
}

fn hash_of<'a>(vm: &Vm, instance: &'a Value, name: &str) -> PyResult<&'a HashObject> {
    native_data::<HashObject>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{name}' for '{HASH_TYPE}' objects doesn't apply to '{}' object", vm.type_name(instance))))
}

fn hash_name(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    Ok(hash_of(vm, instance, getset.name)?.name.clone())
}

/// `HASH.digest_size`, a `long`.
fn hash_digest_size(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let size = hash_of(vm, instance, getset.name)?.algorithm.digest_size();

    Ok(Value::Long(Rc::new(BigInt::from(size))))
}

/// `HASH.block_size`, a `long`.
fn hash_block_size(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let size = hash_of(vm, instance, getset.name)?.algorithm.block_size();

    Ok(Value::Long(Rc::new(BigInt::from(size))))
}

/// C `long` conversion, through `__int__` for other types. `None` when
/// `__int__` returns an unknown value.
fn c_long_value(vm: &Vm, value: &Value) -> PyResult<Option<i64>> {
    let too_large = || vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long");

    let integral = if let Some(integral) = vm.as_integral(value) {
        integral
    } else if let Some(number) = vm.as_float(value) {
        if number.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        }
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        let Some(number) = BigInt::from_f64(number.trunc()) else {
            return Err(too_large());
        };
        Integral::Long(number)
    } else {
        let Some(method) = vm.user_override(value, "__int__")? else {
            return Err(vm.type_error("an integer is required"));
        };
        let result = vm.call0(&method)?;
        if result.is_unknown() {
            return Ok(None);
        }
        vm.as_integral(&result).ok_or_else(|| vm.type_error("nb_int should return int object"))?
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };

    match number {
        Some(number) if fits_int(vm.config.long_width, number) => Ok(Some(number)),
        _ => Err(too_large()),
    }
}

/// `pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)`.
fn pbkdf2_hmac(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const FUNCTION: &str = "pbkdf2_hmac";
    const INT_MAX: usize = 0x7fff_ffff;

    let unknown = || Ok(Value::unknown("_hashlib.pbkdf2_hmac"));
    // Conversion runs in parameter order, so an unknown value only hides
    // the errors of the conversions after it.
    let mut seen_unknown = false;
    let slots = parse_with(vm, args, FUNCTION, &["hash_name", "password", "salt", "iterations", "dklen"], 4, |vm, index, value| {
        if seen_unknown || value.is_unknown() {
            seen_unknown = true;
            return Ok(value);
        }
        match index {
            0 => c_string(vm, FUNCTION, 1, &value).map(Value::Str),
            1 | 2 => Ok(data_argument(vm, &value, FUNCTION, index + 1)?.map_or(value, Value::Str)),
            3 => long_argument(vm, &value).map(Value::Int),
            _ => Ok(value),
        }
    })?;
    let mut slots = slots.into_iter();
    let (Some(Some(Value::Str(hash_name))), Some(Some(Value::Str(password))), Some(Some(Value::Str(salt))), Some(Some(Value::Int(iterations)))) = (slots.next(), slots.next(), slots.next(), slots.next()) else {
        return unknown();
    };
    let key_length = slots.next().flatten();

    let Some(algorithm) = known_digest(hash_name.as_bytes()) else {
        return unknown();
    };
    if password.as_bytes().len() > INT_MAX {
        return Err(vm.raise(ExceptionKind::OverflowError, "password is too long."));
    }
    if salt.as_bytes().len() > INT_MAX {
        return Err(vm.raise(ExceptionKind::OverflowError, "salt is too long."));
    }
    if iterations < 1 {
        return Err(vm.raise(ExceptionKind::ValueError, "iteration value must be greater than 0."));
    }
    let Some(iterations) = u32::try_from(iterations).ok().filter(|count| *count <= 0x7fff_ffff) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "iteration value is too great."));
    };

    let key_length = match key_length {
        None | Some(Value::None) => usize::from(algorithm.digest_size()),
        Some(value) => {
            if value.is_unknown() {
                return unknown();
            }
            let Some(length) = c_long_value(vm, &value)? else {
                return unknown();
            };
            if length < 1 {
                return Err(vm.raise(ExceptionKind::ValueError, "key length must be greater than 0."));
            }
            let Some(length) = usize::try_from(length).ok().filter(|length| *length <= INT_MAX) else {
                return Err(vm.raise(ExceptionKind::OverflowError, "key length is too great."));
            };
            length
        }
    };

    let key = digests::pbkdf2_hmac(algorithm, password.as_bytes(), salt.as_bytes(), iterations, key_length);

    Ok(Value::Str(PyBytes::new(key)))
}
