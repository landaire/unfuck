//! `zlib`. Checksums and decompression are exact.
//! Compression halts: no available deflate implementation reproduces the
//! output of zlib 1.2.11 byte for byte.

use std::cell::RefCell;
use std::rc::Rc;

use flate2::Decompress;
use flate2::FlushDecompress;
use flate2::Status;

use crate::interp::builtins::function;
use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::modules::binascii::buffer_argument;
use crate::interp::builtins::modules::binascii::checksum_arguments;
use crate::interp::builtins::modules::binascii::crc32_update;
use crate::interp::builtins::modules::binascii::has_unknown;
use crate::interp::builtins::modules::binascii::int_argument;
use crate::interp::builtins::modules::binascii::raise_class;
use crate::interp::builtins::modules::binascii::ssize_argument;
use crate::interp::builtins::modules::binascii::varargs;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Default)]
struct ZlibState {
    error: RefCell<Option<ObjectRef>>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const CONSTANTS: [(&str, i64); 13] = [
        ("MAX_WBITS", 15),
        ("DEFLATED", 8),
        ("DEF_MEM_LEVEL", 8),
        ("Z_BEST_SPEED", 1),
        ("Z_BEST_COMPRESSION", 9),
        ("Z_DEFAULT_COMPRESSION", -1),
        ("Z_FILTERED", 1),
        ("Z_HUFFMAN_ONLY", 2),
        ("Z_DEFAULT_STRATEGY", 0),
        ("Z_FINISH", 4),
        ("Z_NO_FLUSH", 0),
        ("Z_SYNC_FLUSH", 2),
        ("Z_FULL_FLUSH", 3),
    ];

    install_functions(
        vm,
        module,
        &[
            function("adler32", adler32),
            function("compress", compress),
            function("compressobj", compressobj),
            function("crc32", crc32),
            function("decompress", decompress),
            function("decompressobj", decompressobj),
        ],
    )?;

    for (name, value) in CONSTANTS {
        set_attribute(vm, module, name, Value::Int(value))?;
    }
    set_attribute(vm, module, "ZLIB_VERSION", Value::str("1.2.11"))?;
    set_attribute(vm, module, "__version__", Value::str("1.0"))?;

    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "zlib", "error", &base)?;
    set_attribute(vm, module, "error", Value::Object(Rc::clone(&error)))?;
    *vm.native_state::<ZlibState>().error.borrow_mut() = Some(error);

    Ok(())
}

/// `zlib.error("Error <code> <context>[: <message>]")`.
fn zlib_error(vm: &Vm, code: i32, context: &str, message: Option<&str>) -> Signal {
    let text = match message {
        Some(message) => format!("Error {code} {context}: {message}"),
        None => format!("Error {code} {context}"),
    };

    raise_class(vm, vm.native_state::<ZlibState>().error.borrow().clone(), &text)
}

fn truncated(vm: &Vm) -> Signal {
    zlib_error(vm, -5, "while decompressing data", Some("incomplete or truncated stream"))
}

fn data_error(vm: &Vm, message: &str) -> Signal {
    zlib_error(vm, -3, "while decompressing data", Some(message))
}

/// `zlib.adler32`. 2.7 returns the checksum as a signed C int.
fn adler32(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((data, start)) = checksum_arguments(vm, args, "adler32", BufferInterface::Pinned, 1)? else {
        return Ok(Value::unknown("zlib.adler32"));
    };

    Ok(Value::Int(i64::from(adler32_update(start, data.as_bytes()) as i32)))
}

/// `adler32_z` of zlib 1.2.11, including its partial reductions of
/// out-of-range start values.
fn adler32_update(start: u32, data: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    const NMAX: usize = 5552;

    let mut low = start & 0xffff;
    let mut high = start >> 16;

    if let [byte] = data {
        low += u32::from(*byte);
        if low >= BASE {
            low -= BASE;
        }
        high += low;
        if high >= BASE {
            high -= BASE;
        }
        return low | (high << 16);
    }

    if data.len() < 16 {
        for &byte in data {
            low += u32::from(byte);
            high += low;
        }
        if low >= BASE {
            low -= BASE;
        }
        return low | ((high % BASE) << 16);
    }

    for block in data.chunks(NMAX) {
        for &byte in block {
            low += u32::from(byte);
            high = high.wrapping_add(low);
        }
        low %= BASE;
        high %= BASE;
    }

    low | (high << 16)
}

/// `zlib.crc32`.
fn crc32(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some((data, start)) = checksum_arguments(vm, args, "crc32", BufferInterface::Pinned, 0)? else {
        return Ok(Value::unknown("zlib.crc32"));
    };

    Ok(Value::Int(i64::from(crc32_update(start, data.as_bytes()) as i32)))
}

fn compress(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("zlib.compress (output identical to zlib 1.2.11 is not available)"))
}

fn compressobj(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("zlib.compressobj"))
}

fn decompressobj(vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Err(vm.halt_unsupported("zlib.decompressobj"))
}

/// The container `inflateInit2` selects from `wbits` (`inflateReset2`).
enum Container {
    Raw,
    Zlib { window_bits: u32 },
    Gzip,
    Detect { window_bits: u32 },
}

fn container(wbits: i32) -> Option<Container> {
    if wbits < 0 {
        return (-15..=-8).contains(&wbits).then_some(Container::Raw);
    }

    let wrap = (wbits >> 4) + 5;
    let window_bits = if wbits < 48 { wbits & 15 } else { wbits };
    if window_bits != 0 && !(8..=15).contains(&window_bits) {
        return None;
    }

    let window_bits = window_bits as u32;
    match wrap {
        5 => Some(Container::Zlib { window_bits }),
        6 => Some(Container::Gzip),
        _ => Some(Container::Detect { window_bits }),
    }
}

/// `zlib.decompress`.
fn decompress(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if has_unknown(&args) {
        return Ok(Value::unknown("zlib.decompress"));
    }

    let values = varargs(vm, args, "decompress", "decompress", 1, 3)?;
    let Some(data) = values.first() else {
        return Ok(Value::unknown("zlib.decompress"));
    };
    let data = buffer_argument(vm, data, "decompress", BufferInterface::Pinned)?;
    let wbits = match values.get(1) {
        Some(value) => int_argument(vm, value)?,
        None => Some(15),
    };
    if let Some(bufsize) = values.get(2) {
        ssize_argument(vm, bufsize)?;
    }
    let Some(wbits) = wbits else {
        return Ok(Value::unknown("zlib.decompress"));
    };

    let Some(container) = container(wbits) else {
        return Err(zlib_error(vm, -2, "while preparing to decompress data", Some("inconsistent stream state")));
    };

    let data = data.as_bytes();
    let window_bits = match container {
        Container::Raw => {
            let (output, _) = inflate_raw(vm, data)?;
            return Ok(Value::Str(PyBytes::allocate(output)));
        }
        Container::Detect { .. } | Container::Gzip if data.starts_with(&[0x1f, 0x8b]) => {
            return Err(vm.halt_unsupported("zlib.decompress of gzip data"));
        }
        Container::Gzip => {
            if data.len() < 2 {
                return Err(truncated(vm));
            }
            return Err(data_error(vm, "incorrect header check"));
        }
        Container::Zlib { window_bits } | Container::Detect { window_bits } => window_bits,
    };

    let [method, flags, ..] = *data else {
        return Err(truncated(vm));
    };
    if (u32::from(method) * 256 + u32::from(flags)) % 31 != 0 {
        return Err(data_error(vm, "incorrect header check"));
    }
    if method & 0x0f != 8 {
        return Err(data_error(vm, "unknown compression method"));
    }
    let header_bits = u32::from(method >> 4) + 8;
    if header_bits > 15 || (window_bits != 0 && header_bits > window_bits) {
        return Err(data_error(vm, "invalid window size"));
    }
    if flags & 0x20 != 0 {
        if data.len() < 6 {
            return Err(truncated(vm));
        }
        return Err(zlib_error(vm, 2, "while decompressing data", None));
    }
    if header_bits < 15 {
        // zlib rejects distances beyond a smaller window; miniz does not.
        return Err(vm.halt_unsupported("zlib.decompress with a window smaller than 32 KiB"));
    }

    let body = data.get(2..).unwrap_or_default();
    let (output, consumed) = inflate_raw(vm, body)?;
    let Some(trailer) = body.get(consumed..consumed + 4) else {
        return Err(truncated(vm));
    };
    if trailer != adler32_update(1, &output).to_be_bytes() {
        return Err(data_error(vm, "incorrect data check"));
    }

    Ok(Value::Str(PyBytes::allocate(output)))
}

/// Inflates a raw deflate stream, returning the output and the number of
/// input bytes the stream occupies.
fn inflate_raw(vm: &Vm, data: &[u8]) -> PyResult<(Vec<u8>, usize)> {
    let mut inflater = Decompress::new(false);
    let mut output = Vec::with_capacity(data.len().saturating_mul(4).max(64));

    loop {
        if output.len() == output.capacity() {
            output.reserve(output.capacity());
        }

        let consumed = usize::try_from(inflater.total_in()).unwrap_or(usize::MAX);
        let produced = output.len();
        let input = data.get(consumed..).unwrap_or_default();
        let status = inflater.decompress_vec(input, &mut output, FlushDecompress::None).map_err(|_| vm.halt_unsupported("zlib.decompress of invalid deflate data"))?;

        let consumed_now = usize::try_from(inflater.total_in()).unwrap_or(usize::MAX);
        match status {
            Status::StreamEnd => return Ok((output, consumed_now)),
            Status::Ok | Status::BufError if consumed_now == consumed && output.len() == produced && output.len() < output.capacity() => {
                return Err(truncated(vm));
            }
            Status::Ok | Status::BufError => {}
        }
    }
}
