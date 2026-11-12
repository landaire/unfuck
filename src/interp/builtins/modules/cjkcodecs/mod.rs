//! The CJK codecs: `_multibytecodec` and the `_codecs_cn`, `_codecs_hk`,
//! `_codecs_iso2022`, `_codecs_jp`, `_codecs_kr`, and `_codecs_tw` modules
//! whose `getcodec` hands it codecs.

mod codec;
mod data;
mod hz;
mod iso2022;
pub mod multibytecodec;
mod sets;
mod stateless;
mod tables;

use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::capsule::new_capsule;
use crate::interp::builtins::modules::capsule::new_capsule_with;
use crate::interp::builtins::modules::cjkcodecs::codec::Family;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::NativeFn;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The name of the capsules `getcodec` passes to `__create_codec` and of
/// the `__map_*` attributes.
const CAPSULE_NAME: &str = "multibytecodec.__map_*";

/// Installs `getcodec` and the `__map_*` capsules a codec module exports.
fn init_family(vm: &Vm, module: &ObjectRef, getcodec: NativeFn, maps: &[&str]) -> PyResult<()> {
    install_functions(vm, module, &[function("getcodec", getcodec)])?;
    for map in maps {
        set_attribute(vm, module, &format!("__map_{map}"), new_capsule(vm, CAPSULE_NAME)?)?;
    }

    Ok(())
}

/// `getcodec(name)`: a codec object for a codec of `family`.
fn getcodec(vm: &Vm, args: CallArgs, family: Family) -> PyResult<Value> {
    let name = args::single(vm, args, "getcodec")?;
    let Some(bytes) = vm.as_str_bytes(&name) else {
        return Err(vm.type_error("encoding name must be a string."));
    };
    let bytes = bytes.as_bytes();
    let name = &bytes[..bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len())];
    let Some(codec) = codec::find(family, name) else {
        return Err(vm.raise(ExceptionKind::LookupError, "no such codec is supported."));
    };

    let module = vm.import_module("_multibytecodec")?;
    let create = vm.getattr_str(&module, "__create_codec")?;
    let capsule = new_capsule_with(vm, CAPSULE_NAME, codec)?;

    vm.call(&create, CallArgs::new(vec![capsule]))
}

pub fn init_cn(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::Chinese), &["gb2312", "gbkext", "gbcommon", "gb18030ext"])
}

pub fn init_hk(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::HongKong), &["big5hkscs", "big5hkscs_bmp", "big5hkscs_nonbmp"])
}

pub fn init_iso2022(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::Iso2022), &[])
}

pub fn init_jp(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let maps = ["jisx0208", "jisx0212", "jisxcommon", "jisx0213_1_bmp", "jisx0213_2_bmp", "jisx0213_bmp", "jisx0213_1_emp", "jisx0213_2_emp", "jisx0213_emp", "jisx0213_pair", "cp932ext"];
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::Japanese), &maps)
}

pub fn init_kr(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::Korean), &["ksx1001", "cp949", "cp949ext"])
}

pub fn init_tw(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    init_family(vm, module, |vm, args| getcodec(vm, args, Family::Taiwanese), &["big5", "cp950ext"])
}
