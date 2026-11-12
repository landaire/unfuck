//! `mmap` of the CPython 2.7.12 Windows build.
//!
//! An anonymous map (`fileno` -1 or 0) is a pagefile-backed section private
//! to the process, so its contents are emulated exactly. A map of a host
//! file, or a section named by `tagname` that other processes may share,
//! has host-dependent contents: creating one validates the arguments and
//! yields an unknown value.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::index_value;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::arguments::set_class_attribute;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::arguments::wrapper_arguments;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::arguments::wrapper_pair;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::array::index_operand;
use crate::interp::builtins::modules::codecs::args::encode_default;
use crate::interp::builtins::modules::codecs::args::read_buffer;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::registered_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::modules::warnings::warn_caller;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::HostCapability;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::MroEntry;
use crate::interp::object::NativeIterator;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const MMAP_TYPE: &str = "mmap.mmap";

/// `dwPageSize` of `GetSystemInfo` on Windows x64.
const PAGE_SIZE: usize = 4096;

/// `dwAllocationGranularity` of `GetSystemInfo` on Windows x64; view
/// offsets must be multiples of it.
const ALLOCATION_GRANULARITY: i64 = 65536;

/// The instance size of `mmap.mmap` in the 64-bit build.
const OBJECT_SIZE: usize = 80;

/// Largest anonymous view the emulator holds in memory; larger views halt.
const EMULATED_VIEW_LIMIT: i64 = 256 * 1024 * 1024;

/// `ERROR_INVALID_PARAMETER` (winerror.h).
const ERROR_INVALID_PARAMETER: i64 = 87;

/// `ERROR_MAPPED_ALIGNMENT` (winerror.h).
const ERROR_MAPPED_ALIGNMENT: i64 = 1132;

/// `EBADF` of the Visual C++ CRT `errno.h`.
const EBADF: i64 = 9;

/// `IOINFO_ARRAYS * IOINFO_ARRAY_ELTS` of the Visual C++ 2008 CRT: the
/// descriptor check rejects descriptors at or above it.
const DESCRIPTOR_LIMIT: i64 = 2048;

/// The `access` argument of `mmap.mmap`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Default,
    Read,
    Write,
    Copy,
}

impl Access {
    fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Default),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Copy),
            _ => None,
        }
    }

    /// Whether writes are permitted.
    fn is_writable(self) -> bool {
        self != Self::Read
    }

    /// Whether `mmap.resize` is permitted.
    fn is_resizable(self) -> bool {
        matches!(self, Self::Write | Self::Default)
    }
}

/// An anonymous map. `data` is `None` once the view is
/// unmapped, which the methods report as a closed map.
struct MmapData {
    data: RefCell<Option<Vec<u8>>>,
    position: Cell<usize>,
    access: Access,
}

impl_native_data!(MmapData, "mmap.mmap");

impl MmapData {
    /// The contents of a mapped view, or the closed map error.
    fn valid<'a>(&'a self, vm: &Vm) -> PyResult<std::cell::RefMut<'a, Vec<u8>>> {
        std::cell::RefMut::filter_map(self.data.borrow_mut(), Option::as_mut).map_err(|_| closed(vm))
    }

    fn size(&self, vm: &Vm) -> PyResult<usize> {
        Ok(self.valid(vm)?.len())
    }
}

/// Per-interpreter state: the module's exception class.
#[derive(Default)]
struct MmapState {
    error: RefCell<Option<ObjectRef>>,
}

/// Whether `value` is an mmap.
pub(crate) fn is_mmap(value: &Value) -> bool {
    native_data::<MmapData>(value).is_some()
}

/// Whether `class` is `mmap.mmap`, once the module is loaded.
pub(crate) fn is_mmap_type(vm: &Vm, class: &ObjectRef) -> bool {
    registered_type(vm, MMAP_TYPE).is_some_and(|mmap| Rc::ptr_eq(&mmap, class))
}

/// An iterator over an mmap: the type defines no `__iter__`, so iteration
/// falls back to item access.
pub(crate) fn sequence_iter(vm: &Vm, object: &ObjectRef) -> Option<Value> {
    let value = Value::Object(Rc::clone(object));
    if !is_mmap(&value) {
        return None;
    }

    Some(vm.new_iterator(NativeIterator::GetItem { target: value, index: 0 }))
}

/// The bytes of an mmap's buffer segment; `None` when `value` is not an
/// mmap. `writable` reads the write segment, which a read-only map
/// refuses.
pub(crate) fn buffer_bytes(vm: &Vm, value: &Value, writable: bool) -> Option<PyResult<PyBytes>> {
    let data = native_data::<MmapData>(value)?;

    Some(segment(vm, data, writable).map(|bytes| PyBytes::new(bytes.clone())))
}

/// Runs `write` over an mmap's write segment; `None` when `value` is not
/// an mmap.
pub(crate) fn write_buffer_bytes<R>(vm: &Vm, value: &Value, write: impl FnOnce(&mut [u8]) -> R) -> Option<PyResult<R>> {
    let data = native_data::<MmapData>(value)?;

    Some(segment(vm, data, true).map(|mut bytes| write(&mut bytes)))
}

/// The buffer of the map for reading or writing; an unmapped view fails.
fn segment<'a>(vm: &Vm, data: &'a MmapData, writable: bool) -> PyResult<std::cell::RefMut<'a, Vec<u8>>> {
    let bytes = data.valid(vm)?;
    if writable && !data.access.is_writable() {
        return Err(readonly(vm));
    }

    Ok(bytes)
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let base = Rc::clone(vm.types().exception(ExceptionKind::EnvironmentError));
    let error = new_exception_class(vm, "mmap", "error", &base)?;
    *vm.native_state::<MmapState>().error.borrow_mut() = Some(Rc::clone(&error));

    set_attribute(vm, module, "error", Value::Object(error))?;
    set_attribute(vm, module, "mmap", Value::Object(mmap_type(vm)?))?;
    set_attribute(vm, module, "PAGESIZE", Value::Int(PAGE_SIZE as i64))?;
    set_attribute(vm, module, "ALLOCATIONGRANULARITY", Value::Int(ALLOCATION_GRANULARITY))?;
    set_attribute(vm, module, "ACCESS_READ", Value::Int(1))?;
    set_attribute(vm, module, "ACCESS_WRITE", Value::Int(2))?;
    set_attribute(vm, module, "ACCESS_COPY", Value::Int(3))
}

fn mmap_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, MMAP_TYPE, create_mmap_type)
}

fn create_mmap_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "mmap",
            module: "mmap",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", mmap_new),
                method("__len__", mmap_len),
                method("__getitem__", mmap_getitem),
                method("__setitem__", mmap_setitem),
                method("__delitem__", mmap_delitem),
                method("__getslice__", mmap_getslice),
                method("__setslice__", mmap_setslice),
                method("__delslice__", mmap_delslice),
                method("__add__", mmap_concat),
                method("__mul__", |vm, args| mmap_repeat(vm, args, "__mul__")),
                method("__rmul__", |vm, args| mmap_repeat(vm, args, "__rmul__")),
                method("close", mmap_close),
                method("find", |vm, args| mmap_find(vm, args, "find", false)),
                method("rfind", |vm, args| mmap_find(vm, args, "rfind", true)),
                method("flush", mmap_flush),
                method("move", mmap_move),
                method("read", mmap_read),
                method("read_byte", mmap_read_byte),
                method("readline", mmap_readline),
                method("resize", mmap_resize),
                method("seek", mmap_seek),
                method("size", mmap_size),
                method("tell", mmap_tell),
                method("write", mmap_write),
                method("write_byte", mmap_write_byte),
                method("__sizeof__", mmap_sizeof),
            ],
        },
    )?;

    // The type sets generic attribute access explicitly, so its own dict
    // holds a `__getattribute__` slot.
    let object = Rc::clone(&vm.types().object);
    if let Some(data) = object.as_class()
        && let Some(getattribute) = vm.dict_get_str(&data.dict, "__getattribute__")?
    {
        set_class_attribute(vm, &class, "__getattribute__", getattribute)?;
    }

    Ok(class)
}

/// The mmap receiver of a method and the arguments after it.
fn bind<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<(&'a MmapData, CallArgs)> {
    let data = this::<MmapData>(vm, args, MMAP_TYPE, method)?;
    let mut rest = args.clone();
    rest.positional.remove(0);

    Ok((data, rest))
}

/// The error for an operation on a closed map.
fn closed(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::ValueError, "mmap closed or invalid")
}

/// The error for a write to a read-only map.
fn readonly(vm: &Vm) -> Signal {
    vm.type_error("mmap can't modify a readonly memory map.")
}

/// A `WindowsError` for `code`. The message comes from `FormatMessage` in
/// the host's language, so it is unknown.
fn windows_error(vm: &Vm, code: i64) -> Signal {
    let class = Rc::clone(vm.types().exception(ExceptionKind::WindowsError));
    let message = Value::unknown(format!("FormatMessage text of Windows error {code} (host language)"));

    match vm.instantiate_exception(&class, vec![Value::Int(code), message]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// `mmap.error` with `errno` `EBADF`.
fn bad_descriptor(vm: &Vm) -> Signal {
    let error = vm.native_state::<MmapState>().error.borrow().clone();
    let Some(error) = error else {
        return vm.raise(ExceptionKind::SystemError, "mmap.error is not initialized");
    };

    match vm.instantiate_exception(&error, vec![Value::Int(EBADF), Value::str("Bad file descriptor")]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// The `L` format, a C `long long`, after a `DeprecationWarning` for a
/// float.
fn long_long_argument(vm: &Vm, value: &Value) -> PyResult<i64> {
    halt_on_unknown(value, "integer argument")?;

    let too_big = || vm.raise(ExceptionKind::OverflowError, "long too big to convert");
    if let Some(number) = vm.as_float(value) {
        warn_caller(vm, ExceptionKind::DeprecationWarning, "integer argument expected, got float")?;
        if number.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        }
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        let truncated = number.trunc();
        if !(-9.223_372_036_854_775_808e18..9.223_372_036_854_775_808e18).contains(&truncated) {
            return Err(too_big());
        }
        return Ok(truncated as i64);
    }

    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => {
            let Some(method) = vm.user_override(value, "__int__")? else {
                return Err(vm.type_error("an integer is required"));
            };
            let result = vm.call0(&method)?;
            halt_on_unknown(&result, "__int__ result")?;
            vm.as_integral(&result).ok_or_else(|| vm.type_error("integer conversion failed"))?
        }
    };

    match integral {
        Integral::Int(number) => Ok(number),
        Integral::Long(number) => number.to_i64().ok_or_else(too_big),
    }
}

/// The `k` format: an `int` or `long` reduced modulo 2 to the width of
/// `unsigned long`.
fn unsigned_long_mask(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<u64> {
    halt_on_unknown(value, "integer argument")?;

    let Some(integral) = vm.as_integral(value) else {
        return Err(vm.type_error(&format!("{function}() argument {position} must be an integer, not {}", vm.type_name(value))));
    };
    let modulus = match vm.config.long_width {
        LongWidth::Bits32 => BigInt::from(1u64 << 32),
        LongWidth::Bits64 => BigInt::from(1u128 << 64),
    };
    let reduced = integral.to_bigint().mod_floor(&modulus);

    Ok(reduced.to_u64().unwrap_or(0))
}

/// The `z` format of a nameless format string.
fn optional_c_string(vm: &Vm, value: Value, position: usize) -> PyResult<Option<PyBytes>> {
    if value.is_none() {
        return Ok(None);
    }

    let bytes = match (vm.as_str_bytes(&value), vm.as_text(&value)) {
        (Some(bytes), _) => bytes,
        (None, Some(text)) => encode_default(vm, &text)?,
        (None, None) => return Err(vm.type_error(&format!("argument {position} must be string or None, not {}", vm.type_name(&value)))),
    };
    if bytes.as_bytes().contains(&0) {
        return Err(vm.type_error(&format!("argument {position} must be string without null bytes or None, not {}", vm.type_name(&value))));
    }

    Ok(Some(bytes))
}

/// The `length` argument of `mmap.mmap` as a size.
fn map_size(vm: &Vm, value: &Value) -> PyResult<i64> {
    let is_index = vm.as_integral(value).is_some() || vm.user_override(value, "__index__")?.is_some();
    if !is_index {
        return Err(vm.type_error("map size must be an integral value"));
    }

    let size = index_value(vm, value)?;
    if size < 0 {
        return Err(vm.raise(ExceptionKind::OverflowError, "memory mapped size must be positive"));
    }

    Ok(size)
}

/// A parsed `mmap()` argument.
enum Argument {
    Integer(i64),
    Object(Value),
    Tag(Option<PyBytes>),
}

/// `mmap.mmap` on Windows: `"iO|ziL"` with keywords
/// `fileno`, `length`, `tagname`, `access`, `offset`.
fn mmap_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = mmap_type(vm)?;
    let (class, rest) = new_class(vm, args, &base)?;

    let unknown = rest.positional.iter().chain(rest.keywords.iter().map(|(_, value)| value)).find(|value| value.is_unknown());
    if let Some(unknown) = unknown {
        return Ok(unknown.clone());
    }

    let names = ["fileno", "length", "tagname", "access", "offset"];
    let slots = parse_with(vm, rest, "", &names, 2, |vm, index, value| match index {
        0 | 3 => int_argument(vm, &value).map(Argument::Integer),
        2 => optional_c_string(vm, value, index + 1).map(Argument::Tag),
        4 => long_long_argument(vm, &value).map(Argument::Integer),
        _ => Ok(Argument::Object(value)),
    })?;
    let mut slots = slots.into_iter();
    let (Some(Some(Argument::Integer(fileno))), Some(Some(Argument::Object(length)))) = (slots.next(), slots.next()) else {
        return Err(vm.type_error("mmap() arguments are missing"));
    };
    let tagname = match slots.next() {
        Some(Some(Argument::Tag(tagname))) => tagname,
        _ => None,
    };
    let access = match slots.next() {
        Some(Some(Argument::Integer(access))) => access,
        _ => 0,
    };
    let offset = match slots.next() {
        Some(Some(Argument::Integer(offset))) => offset,
        _ => 0,
    };

    let Some(access) = Access::from_code(access) else {
        return Err(vm.raise(ExceptionKind::ValueError, "mmap invalid access parameter."));
    };
    let length = map_size(vm, &length)?;
    if offset < 0 {
        return Err(vm.raise(ExceptionKind::OverflowError, "memory mapped offset must be positive"));
    }

    if fileno != -1 && fileno != 0 {
        if !(0..DESCRIPTOR_LIMIT).contains(&fileno) {
            return Err(bad_descriptor(vm));
        }
        return vm.host_operation(HostCapability::SharedMemory, format!("mmap.mmap() of host file descriptor {fileno}"));
    }

    if tagname.as_ref().is_some_and(|tagname| !tagname.as_bytes().is_empty()) {
        return vm.host_operation(HostCapability::SharedMemory, "mmap.mmap() of a named section other processes may share");
    }

    // `CreateFileMapping` of the paging file needs a nonzero section size.
    let Some(section) = offset.checked_add(length) else {
        return Err(vm.halt_unsupported("mmap section size overflowing a 64-bit integer"));
    };
    if section == 0 {
        return Err(windows_error(vm, ERROR_INVALID_PARAMETER));
    }
    // Committing a large section depends on the host's commit limit.
    if section > i64::from(i32::MAX) {
        return Ok(Value::unknown(format!("mmap.mmap() of a {section}-byte section (host commit limit)")));
    }
    if offset % ALLOCATION_GRANULARITY != 0 {
        return Err(windows_error(vm, ERROR_MAPPED_ALIGNMENT));
    }
    if length == 0 {
        return Err(vm.halt_unsupported("mmap view of zero bytes at the end of an anonymous section"));
    }
    if length > EMULATED_VIEW_LIMIT {
        return Err(vm.halt_unsupported(format!("anonymous mmap view of {length} bytes, above the emulation limit of {EMULATED_VIEW_LIMIT} bytes")));
    }
    // The emulator's own memory, not the client's, bounds this allocation.
    let mut contents = Vec::new();
    let size = usize::try_from(length).ok().filter(|size| contents.try_reserve_exact(*size).is_ok());
    let Some(size) = size else {
        return Err(vm.halt_unsupported(format!("allocating {length} bytes for an anonymous mmap")));
    };
    contents.resize(size, 0);

    let data = MmapData { data: RefCell::new(Some(contents)), position: Cell::new(0), access };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(data))))
}

fn mmap_close(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "close")?;
    method_no_arguments(vm, &args, "close")?;
    *data.data.borrow_mut() = None;

    Ok(Value::None)
}

fn mmap_read_byte(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "read_byte")?;
    method_no_arguments(vm, &args, "read_byte")?;

    let bytes = data.valid(vm)?;
    let position = data.position.get();
    let Some(byte) = bytes.get(position) else {
        return Err(vm.raise(ExceptionKind::ValueError, "read byte out of range"));
    };
    data.position.set(position + 1);

    Ok(Value::Str(PyBytes::new(vec![*byte])))
}

fn mmap_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "readline")?;
    method_no_arguments(vm, &args, "readline")?;

    let bytes = data.valid(vm)?;
    let start = data.position.get().min(bytes.len());
    let rest = &bytes[start..];
    let end = rest.iter().position(|byte| *byte == b'\n').map_or(rest.len(), |index| index + 1);
    data.position.set(start + end);

    Ok(Value::Str(PyBytes::new(rest[..end].to_vec())))
}

fn mmap_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "read")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "read", 1, 1)?;
    let requested = ssize_argument(vm, &arguments[0])?;

    let bytes = data.valid(vm)?;
    let start = data.position.get().min(bytes.len());
    let remaining = bytes.len() - start;
    let count = usize::try_from(requested).ok().filter(|count| *count <= remaining).unwrap_or(remaining);
    data.position.set(start + count);

    Ok(Value::Str(PyBytes::new(bytes[start..start + count].to_vec())))
}

/// `mmap.find` and `mmap.rfind`.
fn mmap_find(vm: &Vm, args: CallArgs, name: &str, reverse: bool) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, name)?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, name, 1, 3)?;
    let needle = read_buffer(vm, name, 1, &arguments[0])?;
    let start = arguments.get(1).map(|value| ssize_argument(vm, value)).transpose()?;
    let end = arguments.get(2).map(|value| ssize_argument(vm, value)).transpose()?;

    let bytes = data.valid(vm)?;
    let size = bytes.len() as i64;
    let clamp = |bound: i64| {
        let bound = if bound < 0 { bound + size } else { bound };
        bound.clamp(0, size)
    };
    let start = clamp(start.unwrap_or(data.position.get() as i64));
    let end = clamp(end.unwrap_or(size));

    let needle = needle.as_bytes();
    let length = needle.len() as i64;
    let matches = |at: i64| bytes[at as usize..(at + length) as usize] == *needle;
    let found = if reverse { (start..=end - length).rev().find(|at| matches(*at)) } else { (start..=end - length).find(|at| matches(*at)) };

    Ok(Value::Int(found.unwrap_or(-1)))
}

fn mmap_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "write")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "write", 1, 1)?;
    let source = read_buffer(vm, "write", 1, &arguments[0])?;
    if !data.access.is_writable() {
        return Err(readonly(vm));
    }

    let mut bytes = data.valid(vm)?;
    let start = data.position.get();
    let source = source.as_bytes();
    let Some(target) = bytes.get_mut(start..start + source.len()) else {
        return Err(vm.raise(ExceptionKind::ValueError, "data out of range"));
    };
    target.copy_from_slice(source);
    data.position.set(start + source.len());

    Ok(Value::None)
}

fn mmap_write_byte(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "write_byte")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "write_byte", 1, 1)?;
    halt_on_unknown(&arguments[0], "write_byte argument")?;
    let byte = match vm.as_str_bytes(&arguments[0]) {
        Some(bytes) if bytes.as_bytes().len() == 1 => bytes.as_bytes()[0],
        _ => return Err(vm.type_error(&format!("write_byte() argument 1 must be char, not {}", vm.type_name(&arguments[0])))),
    };
    if !data.access.is_writable() {
        return Err(readonly(vm));
    }

    let mut bytes = data.valid(vm)?;
    let position = data.position.get();
    let Some(slot) = bytes.get_mut(position) else {
        return Err(vm.raise(ExceptionKind::ValueError, "write byte out of range"));
    };
    *slot = byte;
    data.position.set(position + 1);

    Ok(Value::None)
}

/// `mmap.size`: an anonymous map has no file, so it reports the
/// size of the view.
fn mmap_size(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "size")?;
    method_no_arguments(vm, &args, "size")?;

    Ok(Value::Int(data.size(vm)? as i64))
}

/// `mmap.resize`. Remapping an anonymous map creates a paging-file
/// section of size zero, which fails after the old view is unmapped.
fn mmap_resize(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "resize")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "resize", 1, 1)?;
    ssize_argument(vm, &arguments[0])?;
    if !data.access.is_resizable() {
        return Err(vm.type_error("mmap can't resize a readonly or copy-on-write memory map."));
    }

    *data.data.borrow_mut() = None;

    Err(windows_error(vm, ERROR_INVALID_PARAMETER))
}

fn mmap_tell(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "tell")?;
    method_no_arguments(vm, &args, "tell")?;
    data.valid(vm)?;

    Ok(Value::Int(data.position.get() as i64))
}

/// `mmap.flush`. `FlushViewOfFile` over a view of the paging file
/// succeeds; a range that starts outside the view's pages is not emulated.
fn mmap_flush(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "flush")?;
    let size = data.size(vm)?;
    let arguments = method_arguments(vm, &args, "flush", 0, 2)?;
    let offset = arguments.first().map(|value| ssize_argument(vm, value)).transpose()?.unwrap_or(0);
    let count = arguments.get(1).map(|value| ssize_argument(vm, value)).transpose()?.unwrap_or(size as i64);

    if (offset as u64).wrapping_add(count as u64) > size as u64 {
        return Err(vm.raise(ExceptionKind::ValueError, "flush values out of range"));
    }
    if matches!(data.access, Access::Read | Access::Copy) {
        return Ok(Value::Long(Rc::new(BigInt::from(0))));
    }

    let view_end = size.div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let inside = usize::try_from(offset).is_ok_and(|offset| offset < view_end) && count >= 0;
    if !inside {
        return Err(vm.halt_unsupported("FlushViewOfFile of a range outside the mmap view"));
    }

    Ok(Value::Int(1))
}

/// `mmap.seek`.
fn mmap_seek(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "seek")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "seek", 1, 2)?;
    let distance = ssize_argument(vm, &arguments[0])?;
    let whence = arguments.get(1).map(|value| int_argument(vm, value)).transpose()?.unwrap_or(0);

    let size = data.size(vm)? as i64;
    let base = match whence {
        0 => 0,
        1 => data.position.get() as i64,
        2 => size,
        _ => return Err(vm.raise(ExceptionKind::ValueError, "unknown seek type")),
    };
    // The C sum wraps on overflow, which lands out of range either way.
    let target = i128::from(base) + i128::from(distance);
    if whence == 0 && distance < 0 || target < 0 || target > i128::from(size) {
        return Err(vm.raise(ExceptionKind::ValueError, "seek out of range"));
    }
    data.position.set(target as usize);

    Ok(Value::None)
}

/// `mmap.move`: `"kkk:move"` with `unsigned long` arithmetic.
fn mmap_move(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let data = this::<MmapData>(vm, &args, MMAP_TYPE, "move")?;
    data.valid(vm)?;
    let arguments = method_arguments(vm, &args, "move", 3, 3)?;
    let destination = unsigned_long_mask(vm, &arguments[0], "move", 1)?;
    let source = unsigned_long_mask(vm, &arguments[1], "move", 2)?;
    let count = unsigned_long_mask(vm, &arguments[2], "move", 3)?;
    if !data.access.is_writable() {
        return Err(readonly(vm));
    }

    let mask = match vm.config.long_width {
        LongWidth::Bits32 => u64::from(u32::MAX),
        LongWidth::Bits64 => u64::MAX,
    };
    let add = |left: u64, right: u64| left.wrapping_add(right) & mask;
    let mut bytes = data.valid(vm)?;
    let size = bytes.len() as u64;
    let out_of_range = add(count, destination) < count || add(count, source) < count || source > size || add(source, count) > size || destination > size || add(destination, count) > size;
    if out_of_range {
        return Err(vm.raise(ExceptionKind::ValueError, "source, destination, or count out of range"));
    }
    let (source, destination, count) = (source as usize, destination as usize, count as usize);
    bytes.copy_within(source..source + count, destination);

    Ok(Value::None)
}

/// `mmap.__sizeof__`: the instance size of the receiver's type. Maps
/// with a tag name are unknown values, so no tag adds to it.
fn mmap_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<MmapData>(vm, &args, MMAP_TYPE, "__sizeof__")?;
    method_no_arguments(vm, &args, "__sizeof__")?;

    let class = vm.class_of(&args.positional[0]);
    let size = instance_size(vm, &class)?;

    Ok(Value::Long(Rc::new(BigInt::from(size))))
}

/// The instance size of `class`: the mmap struct, one pointer per slot its
/// subclasses declare, and the `__dict__` and `__weakref__` pointers a
/// subclass without `__slots__` adds.
fn instance_size(vm: &Vm, class: &ObjectRef) -> PyResult<usize> {
    const POINTER_SIZE: usize = 8;

    let native = mmap_type(vm)?;
    let Some(data) = class.as_class() else {
        return Ok(OBJECT_SIZE);
    };

    let mut slots = 0;
    let mut has_dict = false;
    let mut has_weakref = false;
    for entry in data.mro() {
        let MroEntry::Class(ancestor) = entry else {
            continue;
        };
        if Rc::ptr_eq(&ancestor, &native) {
            break;
        }
        let Some(ancestor_data) = ancestor.as_class() else {
            continue;
        };
        let Some(declared) = vm.dict_get_str(&ancestor_data.dict, "__slots__")? else {
            has_dict = true;
            has_weakref = true;
            continue;
        };
        let names = if vm.as_str_bytes(&declared).is_some() || vm.as_text(&declared).is_some() { vec![declared] } else { vm.collect(&declared)? };
        for name in &names {
            match vm.text_of(name).as_deref() {
                Some("__dict__") => has_dict = true,
                Some("__weakref__") => has_weakref = true,
                _ => slots += 1,
            }
        }
    }

    Ok(OBJECT_SIZE + POINTER_SIZE * (slots + usize::from(has_dict) + usize::from(has_weakref)))
}

/// `mmap.__len__`.
fn mmap_len(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__len__")?;
    wrapper_arguments(vm, rest, 0)?;

    Ok(Value::Int(data.size(vm)? as i64))
}

/// `mmap.__getitem__`.
fn mmap_getitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__getitem__")?;
    let index = wrapper_operand(vm, rest)?;
    data.valid(vm)?;
    if index.is_unknown() {
        return Ok(index);
    }

    if let Some(position) = index_operand(vm, &index)? {
        let bytes = data.valid(vm)?;
        let position = if position < 0 { position + bytes.len() as i64 } else { position };
        let byte = usize::try_from(position).ok().and_then(|position| bytes.get(position));
        let Some(byte) = byte else {
            return Err(vm.raise(ExceptionKind::IndexError, "mmap index out of range"));
        };
        return Ok(Value::Str(PyBytes::new(vec![*byte])));
    }

    let Some(slice) = vm.slice_of(&index) else {
        return Err(vm.type_error("mmap indices must be integers"));
    };
    let bounds = vm.unpack_slice(&slice)?;
    let bytes = data.valid(vm)?;
    let indices = bounds.adjust(bytes.len() as i64);
    let selected: Vec<u8> = indices.positions().filter_map(|position| bytes.get(position).copied()).collect();

    Ok(Value::Str(PyBytes::new(selected)))
}

fn mmap_setitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__setitem__")?;
    let (index, value) = wrapper_pair(vm, rest)?;
    assign(vm, data, &index, Some(&value))?;

    Ok(Value::None)
}

fn mmap_delitem(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__delitem__")?;
    let index = wrapper_operand(vm, rest)?;
    assign(vm, data, &index, None)?;

    Ok(Value::None)
}

/// Whether the value is a `str` or a subclass.
fn string_value(vm: &Vm, value: &Value) -> PyResult<Option<PyBytes>> {
    halt_on_unknown(value, "mmap assignment value")?;

    Ok(vm.as_str_bytes(value))
}

/// `mmap.__setitem__`; `None` deletes.
fn assign(vm: &Vm, data: &MmapData, index: &Value, value: Option<&Value>) -> PyResult<()> {
    data.valid(vm)?;
    halt_on_unknown(index, "mmap index")?;

    if let Some(position) = index_operand(vm, index)? {
        let size = data.size(vm)? as i64;
        let position = if position < 0 { position + size } else { position };
        if position < 0 || position >= size {
            return Err(vm.raise(ExceptionKind::IndexError, "mmap index out of range"));
        }
        let Some(value) = value else {
            return Err(vm.type_error("mmap object doesn't support item deletion"));
        };
        let byte = match string_value(vm, value)? {
            Some(bytes) if bytes.as_bytes().len() == 1 => bytes.as_bytes()[0],
            _ => return Err(vm.raise(ExceptionKind::IndexError, "mmap assignment must be single-character string")),
        };
        if !data.access.is_writable() {
            return Err(readonly(vm));
        }
        if let Some(slot) = data.valid(vm)?.get_mut(position as usize) {
            *slot = byte;
        }
        return Ok(());
    }

    let Some(slice) = vm.slice_of(index) else {
        return Err(vm.type_error("mmap indices must be integer"));
    };
    let bounds = vm.unpack_slice(&slice)?;
    let indices = bounds.adjust(data.size(vm)? as i64);
    let Some(value) = value else {
        return Err(vm.type_error("mmap object doesn't support slice deletion"));
    };
    let Some(source) = string_value(vm, value)? else {
        return Err(vm.raise(ExceptionKind::IndexError, "mmap slice assignment must be a string"));
    };
    let positions: Vec<usize> = indices.positions().collect();
    if source.as_bytes().len() != positions.len() {
        return Err(vm.raise(ExceptionKind::IndexError, "mmap slice assignment is wrong size"));
    }
    if !data.access.is_writable() {
        return Err(readonly(vm));
    }

    let mut bytes = data.valid(vm)?;
    for (position, byte) in positions.into_iter().zip(source.as_bytes()) {
        if let Some(slot) = bytes.get_mut(position) {
            *slot = *byte;
        }
    }

    Ok(())
}

/// The clamped bounds of a slice read or assignment.
fn clamp_bounds(size: usize, low: i64, high: i64) -> (usize, usize) {
    let size = size as i64;
    let low = low.clamp(0, size);
    let high = high.max(low).min(size);

    (low as usize, high as usize)
}

/// `mmap.__getslice__`.
fn mmap_getslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__getslice__")?;
    let bounds = positional(vm, rest, "__getslice__", 2, 2)?;
    let low = ssize_argument(vm, &bounds[0])?;
    let high = ssize_argument(vm, &bounds[1])?;

    let bytes = data.valid(vm)?;
    let (low, high) = clamp_bounds(bytes.len(), low, high);

    Ok(Value::Str(PyBytes::new(bytes[low..high].to_vec())))
}

fn mmap_setslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__setslice__")?;
    let arguments = positional(vm, rest, "__setslice__", 3, 3)?;
    let low = ssize_argument(vm, &arguments[0])?;
    let high = ssize_argument(vm, &arguments[1])?;
    assign_slice(vm, data, low, high, Some(&arguments[2]))?;

    Ok(Value::None)
}

fn mmap_delslice(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__delslice__")?;
    let bounds = positional(vm, rest, "__delslice__", 2, 2)?;
    let low = ssize_argument(vm, &bounds[0])?;
    let high = ssize_argument(vm, &bounds[1])?;
    assign_slice(vm, data, low, high, None)?;

    Ok(Value::None)
}

/// `mmap.__setslice__`; `None` deletes.
fn assign_slice(vm: &Vm, data: &MmapData, low: i64, high: i64, value: Option<&Value>) -> PyResult<()> {
    let (low, high) = clamp_bounds(data.size(vm)?, low, high);
    let Some(value) = value else {
        return Err(vm.type_error("mmap object doesn't support slice deletion"));
    };
    let Some(source) = string_value(vm, value)? else {
        return Err(vm.raise(ExceptionKind::IndexError, "mmap slice assignment must be a string"));
    };
    if source.as_bytes().len() != high - low {
        return Err(vm.raise(ExceptionKind::IndexError, "mmap slice assignment is wrong size"));
    }
    if !data.access.is_writable() {
        return Err(readonly(vm));
    }
    if let Some(target) = data.valid(vm)?.get_mut(low..high) {
        target.copy_from_slice(source.as_bytes());
    }

    Ok(())
}

/// Concatenation of an mmap.
fn mmap_concat(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, "__add__")?;
    wrapper_operand(vm, rest)?;
    data.valid(vm)?;

    Err(vm.raise(ExceptionKind::SystemError, "mmaps don't support concatenation"))
}

/// Repetition of an mmap, whose count converts through `__index__`.
fn mmap_repeat(vm: &Vm, args: CallArgs, name: &str) -> PyResult<Value> {
    let (data, rest) = bind(vm, &args, name)?;
    let count = wrapper_operand(vm, rest)?;
    index_value(vm, &count)?;
    data.valid(vm)?;

    Err(vm.raise(ExceptionKind::SystemError, "mmaps don't support repeat operation"))
}
