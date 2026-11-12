//! `_md5`, `_sha`, `_sha256`, and `_sha512`.

use std::any::Any;
use std::cell::RefCell;
use std::marker::PhantomData;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::binascii::varargs;
use crate::interp::builtins::modules::digests::Algorithm;
use crate::interp::builtins::modules::digests::HashState;
use crate::interp::builtins::modules::digests::data_argument;
use crate::interp::builtins::modules::digests::digest_value;
use crate::interp::builtins::modules::digests::hexdigest_value;
use crate::interp::builtins::modules::digests::optional_data_argument;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// One of the hash object types the four modules define.
trait Flavor: 'static {
    const ALGORITHM: Algorithm;
    /// The type name without the module prefix.
    const NAME: &'static str;
    const MODULE: &'static str;
    /// The full type name.
    const TYPE_NAME: &'static str;
    /// The value of the `name` attribute.
    const LABEL: &'static str;
    /// `digest_size` and `digestsize` are read-only members rather than
    /// getsets without a setter.
    const SIZE_MEMBERS: bool;
}

struct Md5Flavor;

impl Flavor for Md5Flavor {
    const ALGORITHM: Algorithm = Algorithm::Md5;
    const NAME: &'static str = "md5";
    const MODULE: &'static str = "_md5";
    const TYPE_NAME: &'static str = "_md5.md5";
    const LABEL: &'static str = "MD5";
    const SIZE_MEMBERS: bool = false;
}

struct Sha1Flavor;

impl Flavor for Sha1Flavor {
    const ALGORITHM: Algorithm = Algorithm::Sha1;
    const NAME: &'static str = "sha";
    const MODULE: &'static str = "_sha";
    const TYPE_NAME: &'static str = "_sha.sha";
    const LABEL: &'static str = "SHA1";
    const SIZE_MEMBERS: bool = false;
}

struct Sha224Flavor;

impl Flavor for Sha224Flavor {
    const ALGORITHM: Algorithm = Algorithm::Sha224;
    const NAME: &'static str = "sha224";
    const MODULE: &'static str = "_sha256";
    const TYPE_NAME: &'static str = "_sha256.sha224";
    const LABEL: &'static str = "SHA224";
    const SIZE_MEMBERS: bool = true;
}

struct Sha256Flavor;

impl Flavor for Sha256Flavor {
    const ALGORITHM: Algorithm = Algorithm::Sha256;
    const NAME: &'static str = "sha256";
    const MODULE: &'static str = "_sha256";
    const TYPE_NAME: &'static str = "_sha256.sha256";
    const LABEL: &'static str = "SHA256";
    const SIZE_MEMBERS: bool = true;
}

struct Sha384Flavor;

impl Flavor for Sha384Flavor {
    const ALGORITHM: Algorithm = Algorithm::Sha384;
    const NAME: &'static str = "sha384";
    const MODULE: &'static str = "_sha512";
    const TYPE_NAME: &'static str = "_sha512.sha384";
    const LABEL: &'static str = "SHA384";
    const SIZE_MEMBERS: bool = true;
}

struct Sha512Flavor;

impl Flavor for Sha512Flavor {
    const ALGORITHM: Algorithm = Algorithm::Sha512;
    const NAME: &'static str = "sha512";
    const MODULE: &'static str = "_sha512";
    const TYPE_NAME: &'static str = "_sha512.sha512";
    const LABEL: &'static str = "SHA512";
    const SIZE_MEMBERS: bool = true;
}

/// A hash object of type `F`.
struct BuiltinHash<F> {
    state: RefCell<HashState>,
    flavor: PhantomData<F>,
}

impl<F> NativeData for BuiltinHash<F>
where
    F: Flavor,
{
    fn type_name(&self) -> &'static str {
        F::TYPE_NAME
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn init_md5(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("new", md5_new)])?;

    set_attribute(vm, module, "MD5Type", Value::Object(hash_type::<Md5Flavor>(vm)?))?;

    set_attribute(vm, module, "digest_size", Value::Int(16))
}

pub fn init_sha(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("new", keyword_constructor::<Sha1Flavor>)])?;
    set_attribute(vm, module, "blocksize", Value::Int(1))?;
    set_attribute(vm, module, "digestsize", Value::Int(20))?;

    set_attribute(vm, module, "digest_size", Value::Int(20))
}

pub fn init_sha256(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("sha256", keyword_constructor::<Sha256Flavor>), function("sha224", keyword_constructor::<Sha224Flavor>)])
}

pub fn init_sha512(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("sha512", keyword_constructor::<Sha512Flavor>), function("sha384", keyword_constructor::<Sha384Flavor>)])
}

fn hash_type<F>(vm: &Vm) -> PyResult<ObjectRef>
where
    F: Flavor,
{
    native_type(vm, F::TYPE_NAME, create_type::<F>)
}

fn create_type<F>(vm: &Vm) -> PyResult<ObjectRef>
where
    F: Flavor,
{
    let class = new_final_type(
        vm,
        TypeSpec {
            name: F::NAME,
            module: F::MODULE,
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("copy", hash_copy::<F>), method("digest", hash_digest::<F>), method("hexdigest", hash_hexdigest::<F>), method("update", hash_update::<F>)],
        },
    )?;

    // `_sha256` and `_sha512` declare the sizes as struct members.
    let add_size = if F::SIZE_MEMBERS { add_member } else { add_getset };
    add_size(vm, &class, GetSet { name: "digest_size", owner: F::TYPE_NAME, get: hash_digest_size::<F>, set: None })?;
    add_getset(vm, &class, GetSet { name: "block_size", owner: F::TYPE_NAME, get: hash_block_size::<F>, set: None })?;
    add_getset(vm, &class, GetSet { name: "name", owner: F::TYPE_NAME, get: hash_name::<F>, set: None })?;
    add_size(vm, &class, GetSet { name: "digestsize", owner: F::TYPE_NAME, get: hash_digest_size::<F>, set: None })?;

    Ok(class)
}

/// A new hash object; `data` is `None` when it is unknown.
fn new_hash<F>(vm: &Vm, data: Option<PyBytes>) -> PyResult<Value>
where
    F: Flavor,
{
    let mut state = HashState::new(F::ALGORITHM);
    state.update(data.as_ref().map(PyBytes::as_bytes));

    let class = hash_type::<F>(vm)?;
    let hash = BuiltinHash::<F> { state: RefCell::new(state), flavor: PhantomData };

    Ok(new_native_object(vm, &class, hash))
}

/// `_md5.new([string])`, which takes no keywords.
fn md5_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let values = varargs(vm, args, "new", "new", 0, 1)?;
    let data = optional_data_argument(vm, values.first(), "new", 1)?;

    new_hash::<Md5Flavor>(vm, data)
}

/// `_sha.new`, `_sha256.sha256`, and the others: `new(string='')`.
fn keyword_constructor<F>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    F: Flavor,
{
    let slots = parse(vm, args, "new", &["string"], 0)?;
    let data = optional_data_argument(vm, slots.first().and_then(Option::as_ref), "new", 1)?;

    new_hash::<F>(vm, data)
}

fn the_hash<'a, F>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a BuiltinHash<F>>
where
    F: Flavor,
{
    this::<BuiltinHash<F>>(vm, args, F::TYPE_NAME, method)
}

fn hash_update<F>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    F: Flavor,
{
    let hash = the_hash::<F>(vm, &args, "update")?;
    let values = method_arguments(vm, &args, "update", 1, 1)?;
    let Some(value) = values.first() else {
        return Err(vm.type_error("update() takes exactly 1 argument (0 given)"));
    };

    let data = data_argument(vm, value, "update", 1)?;
    hash.state.borrow_mut().update(data.as_ref().map(PyBytes::as_bytes));

    Ok(Value::None)
}

fn hash_digest<F>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    F: Flavor,
{
    let hash = the_hash::<F>(vm, &args, "digest")?;
    method_no_arguments(vm, &args, "digest")?;

    Ok(digest_value(&hash.state.borrow(), F::TYPE_NAME))
}

fn hash_hexdigest<F>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    F: Flavor,
{
    let hash = the_hash::<F>(vm, &args, "hexdigest")?;
    method_no_arguments(vm, &args, "hexdigest")?;

    Ok(hexdigest_value(&hash.state.borrow(), F::TYPE_NAME))
}

fn hash_copy<F>(vm: &Vm, args: CallArgs) -> PyResult<Value>
where
    F: Flavor,
{
    let hash = the_hash::<F>(vm, &args, "copy")?;
    method_no_arguments(vm, &args, "copy")?;

    let class = hash_type::<F>(vm)?;
    let copy = BuiltinHash::<F> { state: RefCell::new(hash.state.borrow().clone()), flavor: PhantomData };

    Ok(new_native_object(vm, &class, copy))
}

fn hash_of<'a, F>(vm: &Vm, instance: &'a Value, name: &str) -> PyResult<&'a BuiltinHash<F>>
where
    F: Flavor,
{
    native_data::<BuiltinHash<F>>(instance).ok_or_else(|| vm.type_error(&format!("descriptor '{name}' for '{}' objects doesn't apply to '{}' object", F::TYPE_NAME, vm.type_name(instance))))
}

fn hash_digest_size<F>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value>
where
    F: Flavor,
{
    hash_of::<F>(vm, instance, getset.name)?;

    Ok(Value::Int(i64::from(F::ALGORITHM.digest_size())))
}

fn hash_block_size<F>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value>
where
    F: Flavor,
{
    hash_of::<F>(vm, instance, getset.name)?;

    Ok(Value::Int(i64::from(F::ALGORITHM.block_size())))
}

fn hash_name<F>(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value>
where
    F: Flavor,
{
    hash_of::<F>(vm, instance, getset.name)?;

    Ok(Value::str(F::LABEL))
}

