//! `audioop`.

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;

use crate::interp::buffer::BufferInterface;
use crate::interp::builtins::arguments::memory_error;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::binascii::argument_type_name;
use crate::interp::builtins::modules::binascii::has_unknown;
use crate::interp::builtins::modules::binascii::int_argument;
use crate::interp::builtins::modules::binascii::is_native_object;
use crate::interp::builtins::modules::binascii::raise_class;
use crate::interp::builtins::modules::binascii::varargs;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::time::c_double;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::text::codecs::encode_default;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The exception class `audioop` raises.
#[derive(Default)]
struct AudioopState {
    error: RefCell<Option<ObjectRef>>,
}

/// The byte width of one sample.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Width {
    One,
    Two,
    Four,
}

impl Width {
    /// The sample width check: 1, 2, or 4 bytes.
    fn from_size(vm: &Vm, size: i32) -> PyResult<Self> {
        match size {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            4 => Ok(Self::Four),
            _ => Err(audioop_error(vm, "Size should be 1, 2 or 4")),
        }
    }

    fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    fn size(self) -> i32 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    /// The minimum and maximum sample values.
    fn bounds(self) -> (i32, i32) {
        match self {
            Self::One => (i32::from(i8::MIN), i32::from(i8::MAX)),
            Self::Two => (i32::from(i16::MIN), i32::from(i16::MAX)),
            Self::Four => (i32::MIN, i32::MAX),
        }
    }

    /// The native little-endian samples of `data`, which holds whole frames.
    fn samples(self, data: &[u8]) -> impl Iterator<Item = i32> + '_ {
        data.chunks_exact(self.bytes()).map(move |chunk| self.decode(chunk))
    }

    fn decode(self, chunk: &[u8]) -> i32 {
        match (self, chunk) {
            (Self::One, &[byte]) => i32::from(byte as i8),
            (Self::Two, &[low, high]) => i32::from(i16::from_le_bytes([low, high])),
            (Self::Four, &[b0, b1, b2, b3]) => i32::from_le_bytes([b0, b1, b2, b3]),
            _ => unreachable!("chunks_exact yields chunks of the sample width"),
        }
    }

    /// Stores the low bits of `value` as one sample.
    fn encode(self, output: &mut Vec<u8>, value: i32) {
        match self {
            Self::One => output.push(value as u8),
            Self::Two => output.extend_from_slice(&(value as i16).to_le_bytes()),
            Self::Four => output.extend_from_slice(&value.to_le_bytes()),
        }
    }

    /// A sample scaled to the top bits of a 32-bit value.
    fn to_32(self, sample: i32) -> i32 {
        match self {
            Self::One => sample << 24,
            Self::Two => sample << 16,
            Self::Four => sample,
        }
    }

    fn encode_32(self, output: &mut Vec<u8>, value: i32) {
        match self {
            Self::One => self.encode(output, value >> 24),
            Self::Two => self.encode(output, value >> 16),
            Self::Four => self.encode(output, value),
        }
    }

    /// A sample scaled to 16 bits, as the codecs take it.
    fn to_16(self, sample: i32) -> i32 {
        match self {
            Self::One => sample << 8,
            Self::Two => sample,
            Self::Four => sample >> 16,
        }
    }

    fn encode_16(self, output: &mut Vec<u8>, value: i32) {
        match self {
            Self::One => self.encode(output, value >> 8),
            Self::Two => self.encode(output, value),
            Self::Four => self.encode(output, value << 16),
        }
    }
}

/// A sound fragment argument (`s#`) with its C `int` length.
struct Fragment {
    bytes: PyBytes,
    len: i32,
}

impl Fragment {
    fn data(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("max", |vm, args| run(vm, args, "max", max)),
            function("minmax", |vm, args| run(vm, args, "minmax", minmax)),
            function("avg", |vm, args| run(vm, args, "avg", avg)),
            function("maxpp", |vm, args| run(vm, args, "maxpp", maxpp)),
            function("avgpp", |vm, args| run(vm, args, "avgpp", avgpp)),
            function("rms", |vm, args| run(vm, args, "rms", rms)),
            function("findfit", |vm, args| run(vm, args, "findfit", findfit)),
            function("findmax", |vm, args| run(vm, args, "findmax", findmax)),
            function("findfactor", |vm, args| run(vm, args, "findfactor", findfactor)),
            function("cross", |vm, args| run(vm, args, "cross", cross)),
            function("mul", |vm, args| run(vm, args, "mul", mul)),
            function("add", |vm, args| run(vm, args, "add", add)),
            function("bias", |vm, args| run(vm, args, "bias", bias)),
            function("ulaw2lin", |vm, args| run(vm, args, "ulaw2lin", ulaw2lin)),
            function("lin2ulaw", |vm, args| run(vm, args, "lin2ulaw", lin2ulaw)),
            function("alaw2lin", |vm, args| run(vm, args, "alaw2lin", alaw2lin)),
            function("lin2alaw", |vm, args| run(vm, args, "lin2alaw", lin2alaw)),
            function("lin2lin", |vm, args| run(vm, args, "lin2lin", lin2lin)),
            function("adpcm2lin", |vm, args| run(vm, args, "adpcm2lin", adpcm2lin)),
            function("lin2adpcm", |vm, args| run(vm, args, "lin2adpcm", lin2adpcm)),
            function("tomono", |vm, args| run(vm, args, "tomono", tomono)),
            function("tostereo", |vm, args| run(vm, args, "tostereo", tostereo)),
            function("getsample", |vm, args| run(vm, args, "getsample", getsample)),
            function("reverse", |vm, args| run(vm, args, "reverse", reverse)),
            function("ratecv", |vm, args| run(vm, args, "ratecv", ratecv)),
        ],
    )?;

    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "audioop", "error", &base)?;
    set_attribute(vm, module, "error", Value::Object(Rc::clone(&error)))?;
    *vm.native_state::<AudioopState>().error.borrow_mut() = Some(error);

    Ok(())
}

fn audioop_error(vm: &Vm, message: &str) -> Signal {
    raise_class(vm, vm.native_state::<AudioopState>().error.borrow().clone(), message)
}

/// Calls `body` with the known arguments; the result is unknown when an
/// argument or one of its conversions is.
fn run(vm: &Vm, args: CallArgs, name: &str, body: fn(&Vm, CallArgs) -> PyResult<Option<Value>>) -> PyResult<Value> {
    if has_unknown(&args) {
        return Ok(Value::unknown(format!("audioop.{name}")));
    }

    Ok(body(vm, args)?.unwrap_or_else(|| Value::unknown(format!("audioop.{name}"))))
}

/// The arguments of a format with `N` required and no optional units.
fn exact<const N: usize>(vm: &Vm, args: CallArgs, function: &str) -> PyResult<[Value; N]> {
    let values = varargs(vm, args, function, function, N, N)?;

    <[Value; N]>::try_from(values).map_err(|_| vm.halt_unsupported("audioop argument count after its check"))
}

/// The `s#` format unit at 1-based `position`.
fn fragment(vm: &Vm, value: &Value, function: &str, position: usize) -> PyResult<Fragment> {
    let bytes = match (vm.buffer(value, BufferInterface::Pinned)?, vm.as_text(value)) {
        (Some(bytes), _) => bytes,
        (None, Some(text)) => encode_default(vm, text.units())?,
        (None, None) if is_native_object(vm, value) => return Err(vm.halt_unsupported(format!("{function}() of a native buffer object"))),
        (None, None) => {
            let type_name = argument_type_name(vm, value);
            return Err(vm.type_error(&format!("{function}() argument {position} must be string or read-only buffer, not {type_name}")));
        }
    };

    // The fragment length is stored in a C `int`.
    let Ok(len) = i32::try_from(bytes.as_bytes().len()) else {
        return Err(vm.raise(ExceptionKind::OverflowError, "size does not fit in an int"));
    };

    Ok(Fragment { bytes, len })
}

/// The `i` format unit; `None` when the value or its `__int__` is unknown.
fn int(vm: &Vm, value: &Value) -> PyResult<Option<i32>> {
    if value.is_unknown() {
        return Ok(None);
    }

    int_argument(vm, value)
}

/// The sample width check, then the check that the fragment holds whole frames.
fn frames_width(vm: &Vm, fragment: &Fragment, size: i32) -> PyResult<Width> {
    let width = Width::from_size(vm, size)?;
    if fragment.len % size != 0 {
        return Err(audioop_error(vm, "not a whole number of frames"));
    }

    Ok(width)
}

/// The leading `s#i` units, converted without checking them.
fn fragment_and_size(vm: &Vm, data: &Value, size: &Value, function: &str) -> PyResult<Option<(Fragment, i32)>> {
    let fragment = fragment(vm, data, function, 1)?;
    let Some(size) = int(vm, size)? else {
        return Ok(None);
    };

    Ok(Some((fragment, size)))
}

/// A fragment and width from `s#i` units that end the format.
fn fragment_and_width(vm: &Vm, data: &Value, size: &Value, function: &str) -> PyResult<Option<(Fragment, Width)>> {
    let Some((fragment, size)) = fragment_and_size(vm, data, size, function)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;

    Ok(Some((fragment, width)))
}

/// An `int` result.
fn int_value(value: i32) -> Value {
    Value::Int(i64::from(value))
}

/// An `unsigned int` result: a long when it exceeds `INT_MAX`.
fn unsigned_value(value: u32) -> Value {
    match i32::try_from(value) {
        Ok(value) => int_value(value),
        Err(_) => Value::Long(Rc::new(BigInt::from(value))),
    }
}

fn bytes_value(bytes: Vec<u8>) -> Value {
    Value::Str(PyBytes::new(bytes))
}

fn memory_for_output(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::MemoryError, "not enough memory for output buffer")
}

/// A C `(int)` cast of a double. The x64 conversion instruction yields
/// `INT_MIN` for NaN and values out of range.
fn double_to_int(value: f64) -> i32 {
    let truncated = value.trunc();
    if truncated.is_nan() || truncated < f64::from(i32::MIN) || truncated > f64::from(i32::MAX) {
        return i32::MIN;
    }

    truncated as i32
}

/// `fbound`: clamps, then converts to `int` (rounding towards zero).
fn fbound(value: f64, minimum: f64, maximum: f64) -> i32 {
    let value = if value > maximum {
        maximum
    } else if value < minimum + 1.0 {
        minimum
    } else {
        value
    };

    double_to_int(value)
}

/// Tuple argument parsing of a non-tuple, which the `ratecv` state reaches unchecked.
fn not_a_tuple(vm: &Vm) -> Signal {
    vm.raise(ExceptionKind::SystemError, "new style getargs format but argument is not a tuple")
}

fn bounds_f64(width: Width) -> (f64, f64) {
    let (minimum, maximum) = width.bounds();

    (f64::from(minimum), f64::from(maximum))
}

/// `audioop.getsample`.
fn getsample(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, index] = exact(vm, args, "getsample")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "getsample")? else {
        return Ok(None);
    };
    let Some(index) = int(vm, &index)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;

    let sample = usize::try_from(index).ok().and_then(|index| width.samples(fragment.data()).nth(index));
    let Some(sample) = sample else {
        return Err(audioop_error(vm, "Index out of range"));
    };

    Ok(Some(int_value(sample)))
}

/// `audioop.max`.
fn max(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "max")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "max")? else {
        return Ok(None);
    };

    let maximum = width.samples(fragment.data()).map(i32::unsigned_abs).max().unwrap_or(0);

    Ok(Some(unsigned_value(maximum)))
}

/// `audioop.minmax`.
fn minmax(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "minmax")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "minmax")? else {
        return Ok(None);
    };

    // An empty fragment reports the initial extremes.
    let mut minimum = i32::MAX;
    let mut maximum = i32::MIN;
    for sample in width.samples(fragment.data()) {
        maximum = maximum.max(sample);
        minimum = minimum.min(sample);
    }

    Ok(Some(Value::tuple(vec![int_value(minimum), int_value(maximum)])))
}

/// `audioop.avg`.
fn avg(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "avg")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "avg")? else {
        return Ok(None);
    };

    let sum = width.samples(fragment.data()).fold(0.0, |sum, sample| sum + f64::from(sample));
    let average = if fragment.len == 0 { 0 } else { double_to_int((sum / f64::from(fragment.len / width.size())).floor()) };

    Ok(Some(int_value(average)))
}

/// `audioop.rms`.
fn rms(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "rms")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "rms")? else {
        return Ok(None);
    };

    let sum_squares = width.samples(fragment.data()).fold(0.0, |sum, sample| sum + f64::from(sample) * f64::from(sample));
    // The root is at most 2**31, within `unsigned int`.
    let root = if fragment.len == 0 { 0 } else { (sum_squares / f64::from(fragment.len / width.size())).sqrt() as u32 };

    Ok(Some(unsigned_value(root)))
}

/// The native shorts of an even-sized fragment.
fn shorts(fragment: &Fragment) -> Vec<f64> {
    Width::Two.samples(fragment.data()).map(f64::from).collect()
}

/// The sum of the products of corresponding samples.
fn sum2(first: &[f64], second: &[f64], len: usize) -> f64 {
    first.iter().zip(second).take(len).fold(0.0, |sum, (a, b)| sum + a * b)
}

fn even_sized(vm: &Vm, fragments: &[&Fragment]) -> PyResult<()> {
    if fragments.iter().any(|fragment| fragment.len & 1 != 0) {
        return Err(audioop_error(vm, "Strings should be even-sized"));
    }

    Ok(())
}

/// `audioop.findfit`.
fn findfit(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [first, second] = exact(vm, args, "findfit")?;
    let first = fragment(vm, &first, "findfit", 1)?;
    let second = fragment(vm, &second, "findfit", 2)?;
    even_sized(vm, &[&first, &second])?;

    let signal = shorts(&first);
    let reference = shorts(&second);
    let len2 = reference.len();
    if signal.len() < len2 {
        return Err(audioop_error(vm, "First sample should be longer"));
    }

    let sum_ri_2 = sum2(&reference, &reference, len2);
    let mut sum_aij_2 = sum2(&signal, &signal, len2);
    let sum_aij_ri = sum2(&signal, &reference, len2);
    let mut best_result = (sum_ri_2 * sum_aij_2 - sum_aij_ri * sum_aij_ri) / sum_aij_2;
    let mut best_j = 0;

    for j in 1..=signal.len() - len2 {
        let (Some(aj_m1), Some(aj_lm1), Some(window)) = (signal.get(j - 1), signal.get(j + len2 - 1), signal.get(j..)) else {
            break;
        };

        sum_aij_2 = sum_aij_2 + aj_lm1 * aj_lm1 - aj_m1 * aj_m1;
        let sum_aij_ri = sum2(window, &reference, len2);
        let result = (sum_ri_2 * sum_aij_2 - sum_aij_ri * sum_aij_ri) / sum_aij_2;
        if result < best_result {
            best_result = result;
            best_j = j;
        }
    }

    let window = signal.get(best_j..).unwrap_or_default();
    let factor = sum2(window, &reference, len2) / sum_ri_2;
    let best_j = i32::try_from(best_j).map_err(|_| vm.halt_unsupported("findfit offset beyond a C int"))?;

    Ok(Some(Value::tuple(vec![int_value(best_j), Value::Float(factor)])))
}

/// `audioop.findfactor`.
fn findfactor(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [first, second] = exact(vm, args, "findfactor")?;
    let first = fragment(vm, &first, "findfactor", 1)?;
    let second = fragment(vm, &second, "findfactor", 2)?;
    even_sized(vm, &[&first, &second])?;
    if first.len != second.len {
        return Err(audioop_error(vm, "Samples should be same size"));
    }

    let signal = shorts(&first);
    let reference = shorts(&second);
    let sum_ri_2 = sum2(&reference, &reference, reference.len());
    let sum_aij_ri = sum2(&signal, &reference, reference.len());

    Ok(Some(Value::Float(sum_aij_ri / sum_ri_2)))
}

/// `audioop.findmax`.
fn findmax(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, length] = exact(vm, args, "findmax")?;
    let fragment = fragment(vm, &data, "findmax", 1)?;
    let Some(length) = int(vm, &length)? else {
        return Ok(None);
    };
    even_sized(vm, &[&fragment])?;

    let signal = shorts(&fragment);
    let Some(len2) = usize::try_from(length).ok().filter(|len2| *len2 <= signal.len()) else {
        return Err(audioop_error(vm, "Input sample should be longer"));
    };

    let mut result = sum2(&signal, &signal, len2);
    let mut best_result = result;
    let mut best_j = 0;
    for j in 1..=signal.len() - len2 {
        let (Some(aj_m1), Some(aj_lm1)) = (signal.get(j - 1), signal.get(j + len2 - 1)) else {
            break;
        };

        result = result + aj_lm1 * aj_lm1 - aj_m1 * aj_m1;
        if result > best_result {
            best_result = result;
            best_j = j;
        }
    }

    let best_j = i32::try_from(best_j).map_err(|_| vm.halt_unsupported("findmax offset beyond a C int"))?;

    Ok(Some(int_value(best_j)))
}

/// The differences between successive extremes, as `avgpp` and `maxpp`
/// find them: each pair of the previous extreme and a new one.
fn extremes(samples: impl Iterator<Item = i32>) -> Vec<(i32, i32)> {
    let mut samples = samples;
    let mut pairs = Vec::new();
    let Some(mut previous) = samples.next() else {
        return pairs;
    };

    let mut previous_falling: Option<bool> = None;
    let mut previous_extreme: Option<i32> = None;
    for sample in samples {
        if sample == previous {
            continue;
        }

        let falling = sample < previous;
        if previous_falling == Some(!falling) {
            if let Some(extreme) = previous_extreme {
                pairs.push((extreme, previous));
            }
            previous_extreme = Some(previous);
        }
        previous = sample;
        previous_falling = Some(falling);
    }

    pairs
}

/// `audioop.avgpp`.
fn avgpp(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "avgpp")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "avgpp")? else {
        return Ok(None);
    };
    if fragment.data().len() <= width.bytes() * 2 {
        return Ok(Some(int_value(0)));
    }

    let pairs = extremes(width.samples(fragment.data()));
    let sum = pairs.iter().fold(0.0, |sum, (extreme, value)| sum + (f64::from(*value) - f64::from(*extreme)).abs());
    // The mean difference is below 2**32, within `unsigned int`.
    let average = if pairs.is_empty() { 0 } else { (sum / pairs.len() as f64) as u32 };

    Ok(Some(unsigned_value(average)))
}

/// `audioop.maxpp`.
fn maxpp(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "maxpp")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "maxpp")? else {
        return Ok(None);
    };
    if fragment.data().len() <= width.bytes() {
        return Ok(Some(int_value(0)));
    }

    let maximum = extremes(width.samples(fragment.data())).into_iter().map(|(extreme, value)| value.abs_diff(extreme)).max().unwrap_or(0);

    Ok(Some(unsigned_value(maximum)))
}

/// `audioop.cross`.
fn cross(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "cross")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "cross")? else {
        return Ok(None);
    };

    let mut crossings: i32 = -1;
    let mut previous_negative = None;
    for sample in width.samples(fragment.data()) {
        let negative = sample < 0;
        if previous_negative != Some(negative) {
            crossings += 1;
        }
        previous_negative = Some(negative);
    }

    Ok(Some(int_value(crossings)))
}

/// `audioop.mul`.
fn mul(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, factor] = exact(vm, args, "mul")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "mul")? else {
        return Ok(None);
    };
    let Some(factor) = c_double(vm, &factor)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;

    let (minimum, maximum) = bounds_f64(width);
    let mut output = Vec::with_capacity(fragment.data().len());
    for sample in width.samples(fragment.data()) {
        width.encode(&mut output, fbound(f64::from(sample) * factor, minimum, maximum));
    }

    Ok(Some(bytes_value(output)))
}

/// `audioop.tomono`.
fn tomono(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, left, right] = exact(vm, args, "tomono")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "tomono")? else {
        return Ok(None);
    };
    let Some(left) = c_double(vm, &left)? else {
        return Ok(None);
    };
    let Some(right) = c_double(vm, &right)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;
    if (fragment.len / width.size()) & 1 != 0 {
        return Err(audioop_error(vm, "not a whole number of frames"));
    }

    let (minimum, maximum) = bounds_f64(width);
    let samples: Vec<i32> = width.samples(fragment.data()).collect();
    let mut output = Vec::with_capacity(fragment.data().len() / 2);
    for pair in samples.chunks_exact(2) {
        let &[first, second] = pair else {
            continue;
        };
        let value = f64::from(first) * left + f64::from(second) * right;
        width.encode(&mut output, fbound(value, minimum, maximum));
    }

    Ok(Some(bytes_value(output)))
}

/// `audioop.tostereo`.
fn tostereo(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, left, right] = exact(vm, args, "tostereo")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "tostereo")? else {
        return Ok(None);
    };
    let Some(left) = c_double(vm, &left)? else {
        return Ok(None);
    };
    let Some(right) = c_double(vm, &right)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;
    if fragment.len > i32::MAX / 2 {
        return Err(memory_for_output(vm));
    }

    let (minimum, maximum) = bounds_f64(width);
    let mut output = Vec::with_capacity(fragment.data().len() * 2);
    for sample in width.samples(fragment.data()) {
        width.encode(&mut output, fbound(f64::from(sample) * left, minimum, maximum));
        width.encode(&mut output, fbound(f64::from(sample) * right, minimum, maximum));
    }

    Ok(Some(bytes_value(output)))
}

/// `audioop.add`.
fn add(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [first, second, size] = exact(vm, args, "add")?;
    let first = fragment(vm, &first, "add", 1)?;
    let second = fragment(vm, &second, "add", 2)?;
    let Some(size) = int(vm, &size)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &first, size)?;
    if first.len != second.len {
        return Err(audioop_error(vm, "Lengths should be the same"));
    }

    let (minimum, maximum) = width.bounds();
    let mut output = Vec::with_capacity(first.data().len());
    for (left, right) in width.samples(first.data()).zip(width.samples(second.data())) {
        let sum = if width == Width::Four {
            fbound(f64::from(left) + f64::from(right), f64::from(minimum), f64::from(maximum))
        } else {
            (left + right).clamp(minimum, maximum)
        };
        width.encode(&mut output, sum);
    }

    Ok(Some(bytes_value(output)))
}

/// `audioop.bias`.
fn bias(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, bias] = exact(vm, args, "bias")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "bias")? else {
        return Ok(None);
    };
    let Some(bias) = int(vm, &bias)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;

    // The sum wraps around at the sample width.
    let mut output = Vec::with_capacity(fragment.data().len());
    for sample in width.samples(fragment.data()) {
        width.encode(&mut output, sample.wrapping_add(bias));
    }

    Ok(Some(bytes_value(output)))
}

/// `audioop.reverse`.
fn reverse(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, "reverse")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "reverse")? else {
        return Ok(None);
    };

    let output: Vec<u8> = fragment.data().chunks_exact(width.bytes()).rev().flatten().copied().collect();

    Ok(Some(bytes_value(output)))
}

/// `audioop.lin2lin`.
fn lin2lin(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, new_size] = exact(vm, args, "lin2lin")?;
    let Some((fragment, size)) = fragment_and_size(vm, &data, &size, "lin2lin")? else {
        return Ok(None);
    };
    let Some(new_size) = int(vm, &new_size)? else {
        return Ok(None);
    };
    let width = frames_width(vm, &fragment, size)?;
    let new_width = Width::from_size(vm, new_size)?;
    if fragment.len / width.size() > i32::MAX / new_width.size() {
        return Err(memory_for_output(vm));
    }

    let mut output = Vec::with_capacity(fragment.data().len() / width.bytes() * new_width.bytes());
    for sample in width.samples(fragment.data()) {
        new_width.encode_32(&mut output, width.to_32(sample));
    }

    Ok(Some(bytes_value(output)))
}

fn gcd(a: i32, b: i32) -> i32 {
    let mut a = a;
    let mut b = b;
    while b > 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }

    a
}

/// The `(d, ((prev_i, cur_i), ...))` state of `ratecv`.
struct RateState {
    position: i32,
    previous: Vec<i32>,
    current: Vec<i32>,
}

/// Decodes a non-`None` `ratecv` state.
fn rate_state(vm: &Vm, state: &Value, channels: usize) -> PyResult<Option<RateState>> {
    const ILLEGAL: &str = "audioop.ratecv: illegal state argument";

    let Some(items) = vm.as_tuple(state) else {
        return Err(not_a_tuple(vm));
    };
    let [position, samples] = &items[..] else {
        return Err(vm.type_error(ILLEGAL));
    };
    let Some(position) = int(vm, position)? else {
        return Ok(None);
    };
    if samples.is_unknown() {
        return Ok(None);
    }
    let Some(samples) = vm.as_tuple(samples) else {
        return Err(vm.type_error(ILLEGAL));
    };
    if samples.len() != channels {
        return Err(audioop_error(vm, "illegal state argument"));
    }

    let mut previous = Vec::with_capacity(channels);
    let mut current = Vec::with_capacity(channels);
    for channel in samples.iter() {
        if channel.is_unknown() {
            return Ok(None);
        }
        let Some(pair) = vm.as_tuple(channel) else {
            return Err(not_a_tuple(vm));
        };
        let [first, second] = &pair[..] else {
            return Err(vm.type_error(&format!("ratecv() takes exactly 2 arguments ({} given)", pair.len())));
        };
        let Some(first) = int(vm, first)? else {
            return Ok(None);
        };
        let Some(second) = int(vm, second)? else {
            return Ok(None);
        };
        previous.push(first);
        current.push(second);
    }

    Ok(Some(RateState { position, previous, current }))
}

/// `audioop.ratecv`.
fn ratecv(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let values = varargs(vm, args, "ratecv", "ratecv", 6, 8)?;
    let [data, size, channels, in_rate, out_rate, state, weights @ ..] = &values[..] else {
        return Err(vm.halt_unsupported("ratecv argument count after its check"));
    };
    let fragment = fragment(vm, data, "ratecv", 1)?;
    let (Some(size), Some(channels), Some(in_rate), Some(out_rate)) = (int(vm, size)?, int(vm, channels)?, int(vm, in_rate)?, int(vm, out_rate)?) else {
        return Ok(None);
    };
    let mut weight_a = 1;
    let mut weight_b = 0;
    if let Some(value) = weights.first() {
        let Some(value) = int(vm, value)? else {
            return Ok(None);
        };
        weight_a = value;
    }
    if let Some(value) = weights.get(1) {
        let Some(value) = int(vm, value)? else {
            return Ok(None);
        };
        weight_b = value;
    }

    let width = Width::from_size(vm, size)?;
    if channels < 1 {
        return Err(audioop_error(vm, "# of channels should be >= 1"));
    }
    let bytes_per_frame = size.wrapping_mul(channels);
    if bytes_per_frame / channels != size {
        return Err(vm.raise(ExceptionKind::OverflowError, "width * nchannels too big for a C int"));
    }
    if weight_a < 1 || weight_b < 0 {
        return Err(audioop_error(vm, "weightA should be >= 1, weightB should be >= 0"));
    }
    if fragment.len % bytes_per_frame != 0 {
        return Err(audioop_error(vm, "not a whole number of frames"));
    }
    if in_rate <= 0 || out_rate <= 0 {
        return Err(audioop_error(vm, "sampling rate not > 0"));
    }

    let divisor = gcd(in_rate, out_rate);
    let in_rate = in_rate / divisor;
    let out_rate = out_rate / divisor;
    let divisor = gcd(weight_a, weight_b);
    let weight_a = f64::from(weight_a / divisor);
    let weight_b = f64::from(weight_b / divisor);

    let channel_count = channels.unsigned_abs() as usize;
    let state = if state.is_none() {
        let mut previous = Vec::new();
        let mut current = Vec::new();
        if previous.try_reserve_exact(channel_count).is_err() || current.try_reserve_exact(channel_count).is_err() {
            return Err(memory_error(vm));
        }
        previous.resize(channel_count, 0);
        current.resize(channel_count, 0);
        RateState { position: -out_rate, previous, current }
    } else {
        let Some(state) = rate_state(vm, state, channel_count)? else {
            return Ok(None);
        };
        state
    };
    let RateState { position: mut d, mut previous, mut current } = state;

    let frame_count = fragment.len / bytes_per_frame;
    let capacity = if frame_count == 0 {
        0
    } else {
        let quotient = 1 + (frame_count - 1) / in_rate;
        if out_rate > i32::MAX / quotient / bytes_per_frame {
            return Err(memory_for_output(vm));
        }
        (quotient * out_rate * bytes_per_frame).unsigned_abs() as usize
    };

    let mut output = Vec::with_capacity(capacity);
    let mut frames = fragment.data().chunks_exact(bytes_per_frame.unsigned_abs() as usize);
    loop {
        while d < 0 {
            let Some(frame) = frames.next() else {
                let samples = previous.iter().zip(&current).map(|(previous, current)| Value::tuple(vec![int_value(*previous), int_value(*current)])).collect();
                let state = Value::tuple(vec![int_value(d), Value::tuple(samples)]);
                return Ok(Some(Value::tuple(vec![bytes_value(output), state])));
            };

            for ((previous, current), sample) in previous.iter_mut().zip(current.iter_mut()).zip(width.samples(frame)) {
                *previous = *current;
                let sample = f64::from(width.to_32(sample));
                // The weighted mean is a simple digital filter.
                *current = double_to_int((weight_a * sample + weight_b * f64::from(*previous)) / (weight_a + weight_b));
            }
            d += out_rate;
        }

        while d >= 0 {
            for (previous, current) in previous.iter().zip(&current) {
                let value = double_to_int((f64::from(*previous) * f64::from(d) + f64::from(*current) * f64::from(out_rate - d)) / f64::from(out_rate));
                // CPython overruns its output buffer for states it never returns.
                if output.len() + width.bytes() > capacity {
                    return Err(vm.halt_unsupported("ratecv state that overruns the output buffer"));
                }
                width.encode_32(&mut output, value);
            }
            d -= in_rate;
        }
    }
}

/// Expands a G.711 mu-law code to a 16-bit sample.
fn ulaw_to_linear(code: u8) -> i16 {
    // Bias that makes each segment start at a power of two, at 16-bit scale.
    const BIAS: i16 = 0x84;

    // Codes are stored with every bit inverted.
    let code = !code;
    let segment = (code >> 4) & 0x7;
    let mantissa = i16::from(code & 0xF);

    let magnitude = (((mantissa << 3) + BIAS) << segment) - BIAS;

    if code & 0x80 != 0 { -magnitude } else { magnitude }
}

/// Expands a G.711 A-law code to a 16-bit sample.
fn alaw_to_linear(code: u8) -> i16 {
    // Codes are stored with the even bits inverted; a set sign bit is positive.
    let code = code ^ 0x55;
    let segment = (code >> 4) & 0x7;
    let mantissa = i16::from(code & 0xF);

    // Each value decodes to the middle of its quantization interval.
    // Segments 0 and 1 share a step size; higher segments add the leading bit.
    let magnitude = match segment {
        0 => (mantissa << 4) + 8,
        _ => ((mantissa << 4) + 0x108) << (segment - 1),
    };

    if code & 0x80 != 0 { magnitude } else { -magnitude }
}

/// Compresses a 16-bit sample to a G.711 mu-law code.
fn linear_to_ulaw(sample: i32) -> u8 {
    // The coder works on 14-bit samples with a bias of 33, which puts the
    // segment number at the position of the highest set bit minus five.
    let value = sample >> 2;
    let magnitude = value.unsigned_abs();
    let mask = if value < 0 { 0x7F } else { 0xFF };
    let biased = magnitude + 33;
    let segment = biased.ilog2() - 5;

    // Magnitudes past the last segment saturate to the largest code.
    let code = if segment > 7 { 0x7F } else { (segment << 4) | ((biased >> (segment + 1)) & 0xF) };

    (code ^ mask) as u8
}

/// Compresses a 16-bit sample to a G.711 A-law code.
fn linear_to_alaw(sample: i32) -> u8 {
    // The coder works on 13-bit samples; negative values use the ones'
    // complement magnitude.
    let value = sample >> 3;
    let (magnitude, mask) = if value < 0 { ((!value).unsigned_abs(), 0x55) } else { (value.unsigned_abs(), 0xD5) };

    // Segments 0 and 1 both keep bits 1..4; each higher segment shifts one more.
    let segment = magnitude.checked_ilog2().map_or(0, |bit| bit.saturating_sub(4)).min(7);
    let mantissa = (magnitude >> segment.max(1)) & 0xF;

    (((segment << 4) | mantissa) ^ mask) as u8
}

/// `lin2ulaw` and `lin2alaw`.
fn encode_law(vm: &Vm, args: CallArgs, function: &str, encode: fn(i32) -> u8) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, function)?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, function)? else {
        return Ok(None);
    };

    let output = width.samples(fragment.data()).map(|sample| encode(width.to_16(sample))).collect();

    Ok(Some(bytes_value(output)))
}

/// `ulaw2lin` and `alaw2lin`.
fn decode_law(vm: &Vm, args: CallArgs, function: &str, decode: fn(u8) -> i16) -> PyResult<Option<Value>> {
    let [data, size] = exact(vm, args, function)?;
    let fragment = fragment(vm, &data, function, 1)?;
    let Some(size) = int(vm, &size)? else {
        return Ok(None);
    };
    let width = Width::from_size(vm, size)?;
    if fragment.len > i32::MAX / size {
        return Err(memory_for_output(vm));
    }

    let mut output = Vec::with_capacity(fragment.data().len() * width.bytes());
    for &byte in fragment.data() {
        width.encode_16(&mut output, i32::from(decode(byte)));
    }

    Ok(Some(bytes_value(output)))
}

fn lin2ulaw(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    encode_law(vm, args, "lin2ulaw", linear_to_ulaw)
}

fn ulaw2lin(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    decode_law(vm, args, "ulaw2lin", ulaw_to_linear)
}

fn lin2alaw(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    encode_law(vm, args, "lin2alaw", linear_to_alaw)
}

fn alaw2lin(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    decode_law(vm, args, "alaw2lin", alaw_to_linear)
}

/// IMA ADPCM step sizes, measured from CPython 2.7 by
/// tests/fixtures/interp/generate_audioop_tables.py.
const STEPSIZE_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
    19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
    130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
    876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
    5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
    15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

/// The predicted value and step index of the ADPCM coder.
struct AdpcmState {
    predicted: i32,
    index: usize,
}

impl AdpcmState {
    fn step(&self) -> i32 {
        STEPSIZE_TABLE.get(self.index).copied().unwrap_or(0)
    }

    /// Applies one code to the step index. The sign bit is ignored; small
    /// magnitudes shrink the step and large ones grow it in strides of two.
    fn advance(&mut self, code: usize) {
        let magnitude = (code & 7) as i32;
        let offset = if magnitude < 4 { -1 } else { (magnitude - 3) * 2 };
        self.index = (self.index as i32 + offset).clamp(0, 88) as usize;
    }

    fn result(self, output: Vec<u8>) -> Value {
        let index = int_value(self.index as i32);

        Value::tuple(vec![bytes_value(output), Value::tuple(vec![int_value(self.predicted), index])])
    }
}

/// Decodes an ADPCM state argument.
fn adpcm_state(vm: &Vm, state: &Value) -> PyResult<Option<AdpcmState>> {
    if state.is_none() {
        return Ok(Some(AdpcmState { predicted: 0, index: 0 }));
    }

    let Some(items) = vm.as_tuple(state) else {
        return Err(vm.type_error("state must be a tuple or None"));
    };
    let [predicted, index] = &items[..] else {
        return Err(vm.type_error(&format!("function takes exactly 2 arguments ({} given)", items.len())));
    };
    let (Some(predicted), Some(index)) = (int(vm, predicted)?, int(vm, index)?) else {
        return Ok(None);
    };

    let index = usize::try_from(index).ok().filter(|index| *index < STEPSIZE_TABLE.len());
    let (true, Some(index)) = ((-0x8000..0x8000).contains(&predicted), index) else {
        return Err(vm.raise(ExceptionKind::ValueError, "bad state"));
    };

    Ok(Some(AdpcmState { predicted, index }))
}

/// `audioop.lin2adpcm`.
fn lin2adpcm(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, state] = exact(vm, args, "lin2adpcm")?;
    let Some((fragment, width)) = fragment_and_width(vm, &data, &size, "lin2adpcm")? else {
        return Ok(None);
    };
    let Some(mut state) = adpcm_state(vm, &state)? else {
        return Ok(None);
    };

    let mut output = Vec::with_capacity(fragment.data().len() / (width.bytes() * 2));
    let mut step = state.step();
    let mut high_nibble = None;
    for sample in width.samples(fragment.data()) {
        let mut diff = width.to_16(sample) - state.predicted;
        let sign = if diff < 0 { 8 } else { 0 };
        if sign != 0 {
            diff = -diff;
        }

        // Approximates delta = diff * 4 / step and vpdiff = (delta + 0.5) * step / 4.
        let mut delta = 0;
        let mut vpdiff = step >> 3;
        if diff >= step {
            delta = 4;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if diff >= step {
            delta |= 2;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if diff >= step {
            delta |= 1;
            vpdiff += step;
        }

        let predicted = if sign != 0 { state.predicted - vpdiff } else { state.predicted + vpdiff };
        state.predicted = predicted.clamp(-32768, 32767);

        let delta = delta | sign;
        state.advance(delta);
        step = state.step();

        match high_nibble.take() {
            None => high_nibble = Some(((delta << 4) & 0xF0) as u8),
            Some(high) => output.push((delta & 0x0F) as u8 | high),
        }
    }

    Ok(Some(state.result(output)))
}

/// `audioop.adpcm2lin`.
fn adpcm2lin(vm: &Vm, args: CallArgs) -> PyResult<Option<Value>> {
    let [data, size, state] = exact(vm, args, "adpcm2lin")?;
    let fragment = fragment(vm, &data, "adpcm2lin", 1)?;
    let Some(size) = int(vm, &size)? else {
        return Ok(None);
    };
    let width = Width::from_size(vm, size)?;
    let Some(mut state) = adpcm_state(vm, &state)? else {
        return Ok(None);
    };
    if fragment.len > (i32::MAX / 2) / size {
        return Err(memory_for_output(vm));
    }

    let mut output = Vec::with_capacity(fragment.data().len() * width.bytes() * 2);
    let mut step = state.step();
    let codes = fragment.data().iter().flat_map(|byte| [usize::from(byte >> 4), usize::from(byte & 0xF)]);
    for code in codes {
        state.advance(code);

        let sign = code & 8;
        let delta = code & 7;
        let mut vpdiff = step >> 3;
        if delta & 4 != 0 {
            vpdiff += step;
        }
        if delta & 2 != 0 {
            vpdiff += step >> 1;
        }
        if delta & 1 != 0 {
            vpdiff += step >> 2;
        }

        let predicted = if sign != 0 { state.predicted - vpdiff } else { state.predicted + vpdiff };
        state.predicted = predicted.clamp(-32768, 32767);
        step = state.step();

        width.encode_16(&mut output, state.predicted);
    }

    Ok(Some(state.result(output)))
}
