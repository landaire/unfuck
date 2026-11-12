//! `_random`: the Mersenne Twister generator behind `random.Random`.

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::Sign;
use num_integer::Integer;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::new_class;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::numeric::float::float_to_integer;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::ops::BinaryOp;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Unknown;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const RANDOM_TYPE: &str = "_random.Random";
const STATE_SIZE: usize = 624;
const SHIFT_SIZE: usize = 397;

/// The state vector and position of a generator (`RandomObject`).
struct Twister {
    state: [u32; STATE_SIZE],
    index: usize,
}

impl Twister {
    /// `init_genrand`.
    fn from_seed(seed: u32) -> Self {
        let mut state = [0; STATE_SIZE];
        state[0] = seed;
        for position in 1..STATE_SIZE {
            let previous = state[position - 1];
            // `position` is below `STATE_SIZE`, so the cast is lossless.
            state[position] = 1_812_433_253_u32.wrapping_mul(previous ^ (previous >> 30)).wrapping_add(position as u32);
        }

        Self { state, index: STATE_SIZE }
    }

    /// `init_by_array`. `key` is never empty. The reference implementation keeps 32-bit
    /// values in `unsigned long` and masks after each step, which equals
    /// wrapping 32-bit arithmetic.
    fn from_key(key: &[u32]) -> Self {
        let mut twister = Self::from_seed(19_650_218);
        let state = &mut twister.state;

        let mut position = 1;
        let mut key_index = 0;
        for _ in 0..STATE_SIZE.max(key.len()) {
            let previous = state[position - 1];
            let mixed = state[position] ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525);
            // `j` is an `unsigned int` in C, so the addition wraps.
            state[position] = mixed.wrapping_add(key[key_index]).wrapping_add(key_index as u32);
            position += 1;
            key_index += 1;
            if position >= STATE_SIZE {
                state[0] = state[STATE_SIZE - 1];
                position = 1;
            }
            if key_index >= key.len() {
                key_index = 0;
            }
        }

        for _ in 1..STATE_SIZE {
            let previous = state[position - 1];
            let mixed = state[position] ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941);
            state[position] = mixed.wrapping_sub(position as u32);
            position += 1;
            if position >= STATE_SIZE {
                state[0] = state[STATE_SIZE - 1];
                position = 1;
            }
        }

        state[0] = 0x8000_0000;

        twister
    }

    /// `genrand_int32`.
    fn next_word(&mut self) -> u32 {
        const MATRIX_A: u32 = 0x9908_b0df;
        const UPPER_MASK: u32 = 0x8000_0000;
        const LOWER_MASK: u32 = 0x7fff_ffff;

        let twist = |high: u32, low: u32, far: u32| {
            let mixed = (high & UPPER_MASK) | (low & LOWER_MASK);
            let magic = if mixed & 1 == 0 { 0 } else { MATRIX_A };
            far ^ (mixed >> 1) ^ magic
        };

        if self.index >= STATE_SIZE {
            let state = &mut self.state;
            for position in 0..STATE_SIZE - SHIFT_SIZE {
                state[position] = twist(state[position], state[position + 1], state[position + SHIFT_SIZE]);
            }
            for position in STATE_SIZE - SHIFT_SIZE..STATE_SIZE - 1 {
                state[position] = twist(state[position], state[position + 1], state[position + SHIFT_SIZE - STATE_SIZE]);
            }
            state[STATE_SIZE - 1] = twist(state[STATE_SIZE - 1], state[0], state[SHIFT_SIZE - 1]);
            self.index = 0;
        }

        let mut word = self.state[self.index];
        self.index += 1;

        word ^= word >> 11;
        word ^= (word << 7) & 0x9d2c_5680;
        word ^= (word << 15) & 0xefc6_0000;
        word ^ (word >> 18)
    }

    /// `random()`: 27 high bits of one word and 26 of the next.
    fn next_float(&mut self) -> f64 {
        let high = self.next_word() >> 5;
        let low = self.next_word() >> 6;

        (f64::from(high) * 67_108_864.0 + f64::from(low)) * (1.0 / 9_007_199_254_740_992.0)
    }

    /// `getrandbits` for a positive `bits`: whole words, the last one
    /// shifted down to the remaining bits.
    fn random_bits(&mut self, bits: u32) -> BigUint {
        let words = (bits - 1) / 32 + 1;
        let mut remaining = bits;
        let mut digits = Vec::new();
        for _ in 0..words {
            let mut word = self.next_word();
            if remaining < 32 {
                word >>= 32 - remaining;
            }
            digits.push(word);
            remaining = remaining.saturating_sub(32);
        }

        BigUint::from_slice(&digits)
    }

    /// The final step of `jumpahead`, after the shuffle.
    fn finish_jump(&mut self) {
        let mut nonzero = 0;
        for position in 1..STATE_SIZE {
            self.state[position] = self.state[position].wrapping_add(position as u32 + 1);
            nonzero |= self.state[position];
        }

        // Issue #14591: an all-zero tail would leave the generator stuck.
        self.state[0] = if nonzero == 0 { 0x8000_0000 } else { self.state[0].wrapping_add(1) };
        self.index = STATE_SIZE;
    }
}

/// A generator whose state is either computed or depends on host input
/// (the current time) or on unknown values.
enum Generator {
    Known(Box<Twister>),
    Unknown(Rc<Unknown>),
}

struct RandomData {
    generator: RefCell<Generator>,
}

impl_native_data!(RandomData, "_random.Random");

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let class = native_type(vm, RANDOM_TYPE, create_random_type)?;
    set_attribute(vm, module, "Random", Value::Object(class))
}

fn create_random_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "Random",
            module: "_random",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", random_new),
                method("random", random_random),
                method("seed", random_seed),
                method("getstate", random_getstate),
                method("setstate", random_setstate),
                method("jumpahead", random_jumpahead),
                method("getrandbits", random_getrandbits),
            ],
        },
    )?;

    Ok(class)
}

/// `Random.__new__`: seeds from the arguments as `seed` does.
fn random_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let base = native_type(vm, RANDOM_TYPE, create_random_type)?;
    let (class, rest) = new_class(vm, args, &base)?;
    if Rc::ptr_eq(&class, &base) && rest.has_keywords() {
        return Err(vm.type_error("Random() does not take keyword arguments"));
    }

    let arguments = args::unpack(vm, CallArgs::new(rest.positional), "seed", 0, 1)?;
    let generator = seeded(vm, arguments.first())?;

    Ok(new_instance(vm, &class, Payload::Native(Box::new(RandomData { generator: RefCell::new(generator) }))))
}

/// `Random.seed`: the absolute value of an integer, or of the hash of any
/// other object as a C `unsigned long`, split into 32-bit words.
fn seeded(vm: &Vm, seed: Option<&Value>) -> PyResult<Generator> {
    let Some(seed) = seed.filter(|seed| !seed.is_none()) else {
        return Ok(Generator::Unknown(Rc::new(Unknown::new("_random.Random seeded from the current time"))));
    };
    if let Value::Unknown(origin) = seed {
        return Ok(Generator::Unknown(Rc::clone(origin)));
    }

    let mut key = match vm.as_integral(seed) {
        // Absolute value honors `__abs__` of an int or long subclass.
        Some(integral) => match vm.user_override(seed, "__abs__")? {
            Some(method) => {
                let absolute = vm.call0(&method)?;
                match overridden_key(vm, absolute)? {
                    Ok(key) => key,
                    Err(origin) => return Ok(Generator::Unknown(origin)),
                }
            }
            None => integral.to_bigint().magnitude().to_u32_digits(),
        },
        None => {
            let hash = vm.hash(seed)?.value();
            // The cast reinterprets the signed C `long` hash as unsigned.
            let unsigned = match vm.config.long_width {
                LongWidth::Bits32 => u64::from(hash as u32),
                LongWidth::Bits64 => hash as u64,
            };
            BigUint::from(unsigned).to_u32_digits()
        }
    };

    if key.is_empty() {
        key.push(0);
    }

    Ok(Generator::Known(Box::new(Twister::from_key(&key))))
}

/// The words of a seed returned by an overridden `__abs__`, split off with
/// the generic `&` and `>>` operations as `Random.seed` does. `Err` holds
/// the origin of an unknown operand.
fn overridden_key(vm: &Vm, mut number: Value) -> PyResult<Result<Vec<u32>, Rc<Unknown>>> {
    let mask = Value::long(BigInt::from(u32::MAX));
    let shift = Value::Int(32);

    let mut key = Vec::new();
    loop {
        if let Value::Unknown(origin) = &number {
            return Ok(Err(Rc::clone(origin)));
        }
        if !vm.truthy(&number, "_random.Random.seed()")? {
            break;
        }
        // Shifting a negative number never reaches zero.
        if vm.as_integral(&number).is_some_and(|integral| integral.to_bigint().sign() == Sign::Minus) {
            return Err(Signal::Halt(Halt::Unsupported { feature: "seed() with a negative __abs__ result".to_owned() }));
        }

        let chunk = vm.binary_op(BinaryOp::And, &number, &mask)?;
        if let Value::Unknown(origin) = &chunk {
            return Ok(Err(Rc::clone(origin)));
        }
        key.push((unsigned_long(vm, &chunk)? & 0xffff_ffff) as u32);
        number = vm.binary_op(BinaryOp::RightShift, &number, &shift)?;
    }

    Ok(Ok(key))
}

fn generator<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a RefCell<Generator>> {
    this::<RandomData>(vm, args, RANDOM_TYPE, method).map(|data| &data.generator)
}

fn random_random(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "random")?;
    method_no_arguments(vm, &args, "random")?;

    let value = match &mut *generator.borrow_mut() {
        Generator::Known(twister) => Value::Float(twister.next_float()),
        Generator::Unknown(origin) => Value::Unknown(Rc::clone(origin)),
    };

    Ok(value)
}

fn random_seed(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "seed")?;
    let rest = CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() };
    let arguments = args::unpack(vm, rest, "seed", 0, 1)?;
    if arguments.first().is_none_or(Value::is_none) {
        vm.host_permit(HostCapability::Clock, Denial::Native, None)?;
    }

    let seeded = seeded(vm, arguments.first())?;
    *generator.borrow_mut() = seeded;

    Ok(Value::None)
}

/// `Random.getstate`: the 624 words and the position, all as longs.
fn random_getstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "getstate")?;
    method_no_arguments(vm, &args, "getstate")?;

    let state = match &*generator.borrow() {
        Generator::Known(twister) => {
            let mut items: Vec<Value> = twister.state.iter().map(|word| Value::long(BigInt::from(*word))).collect();
            items.push(Value::long(BigInt::from(twister.index)));
            Value::tuple(items)
        }
        Generator::Unknown(origin) => Value::Unknown(Rc::clone(origin)),
    };

    Ok(state)
}

/// `Random.setstate`. Each word is stored as it is converted, so a failure
/// keeps the words before it. Unknown words or positions leave the state
/// unknown.
fn random_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "setstate")?;
    let state = method_one_argument(vm, &args, "setstate")?;
    if let Value::Unknown(origin) = &state {
        *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
        return Ok(Value::None);
    }

    let Some(items) = vm.as_tuple(&state) else {
        return Err(vm.type_error("state vector must be a tuple"));
    };
    if items.len() != STATE_SIZE + 1 {
        return Err(vm.raise(ExceptionKind::ValueError, "state vector is the wrong size"));
    }

    let mut words = [0; STATE_SIZE];
    for (position, item) in items.iter().take(STATE_SIZE).enumerate() {
        if let Value::Unknown(origin) = item {
            *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
            return Ok(Value::None);
        }
        match unsigned_long(vm, item) {
            // Values wider than 32 bits are masked to keep the state sane.
            Ok(word) => words[position] = (word & 0xffff_ffff) as u32,
            Err(signal) => {
                store_words(generator, &words[..position]);
                return Err(signal);
            }
        }
    }

    let index = &items[STATE_SIZE];
    if let Value::Unknown(origin) = index {
        *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
        return Ok(Value::None);
    }
    let index = match c_long(vm, index) {
        Ok(index) => usize::try_from(index).ok().filter(|index| *index <= STATE_SIZE),
        Err(signal) => {
            store_words(generator, &words);
            return Err(signal);
        }
    };
    let Some(index) = index else {
        store_words(generator, &words);
        return Err(vm.raise(ExceptionKind::ValueError, "invalid state"));
    };

    *generator.borrow_mut() = Generator::Known(Box::new(Twister { state: words, index }));

    Ok(Value::None)
}

/// The leading `words` a failed `setstate` already stored.
fn store_words(generator: &RefCell<Generator>, words: &[u32]) {
    if let Generator::Known(twister) = &mut *generator.borrow_mut() {
        twister.state[..words.len()].copy_from_slice(words);
    }
}

/// `Random.jumpahead`: swaps each word with the one at `n % i`, then
/// perturbs every word. The remainders may run user code, so the state is
/// not borrowed across them.
fn random_jumpahead(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "jumpahead")?;
    let count = method_one_argument(vm, &args, "jumpahead")?;
    if let Value::Unknown(origin) = &count {
        *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
        return Ok(Value::None);
    }
    if vm.as_integral(&count).is_none() {
        return Err(vm.type_error(&format!("jumpahead requires an integer, not '{}'", vm.type_name(&count))));
    }

    let exact = match &count {
        Value::Bool(flag) => Some(BigInt::from(u8::from(*flag))),
        Value::Int(number) => Some(BigInt::from(*number)),
        Value::Long(number) => Some((**number).clone()),
        _ => None,
    };
    for position in (2..STATE_SIZE).rev() {
        let target = match &exact {
            Some(number) => number.mod_floor(&BigInt::from(position)).to_usize(),
            None => {
                let remainder = vm.binary_op(BinaryOp::Modulo, &count, &Value::Int(position as i64))?;
                if let Value::Unknown(origin) = &remainder {
                    *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
                    continue;
                }
                usize::try_from(c_long(vm, &remainder)?).ok()
            }
        };
        // CPython indexes the state with the remainder unchecked.
        let Some(target) = target.filter(|target| *target < STATE_SIZE) else {
            return Err(Signal::Halt(Halt::Unsupported { feature: "jumpahead() with a remainder outside the state vector".to_owned() }));
        };

        if let Generator::Known(twister) = &mut *generator.borrow_mut() {
            twister.state.swap(position, target);
        }
    }

    if let Generator::Known(twister) = &mut *generator.borrow_mut() {
        twister.finish_jump();
    }

    Ok(Value::None)
}

/// `Random.getrandbits`: a long of `k` random bits, `k` parsed with the
/// `i` format.
fn random_getrandbits(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let generator = generator(vm, &args, "getrandbits")?;
    let arguments = method_arguments(vm, &args, "getrandbits", 1, 1)?;
    if let Value::Unknown(origin) = &arguments[0] {
        *generator.borrow_mut() = Generator::Unknown(Rc::clone(origin));
        return Ok(Value::Unknown(Rc::clone(origin)));
    }

    let bits = int_argument(vm, &arguments[0])?;
    let Some(bits) = u32::try_from(bits).ok().filter(|bits| *bits > 0) else {
        return Err(vm.raise(ExceptionKind::ValueError, "number of bits must be greater than zero"));
    };

    let value = match &mut *generator.borrow_mut() {
        Generator::Known(twister) => Value::long(BigInt::from_biguint(Sign::Plus, twister.random_bits(bits))),
        Generator::Unknown(origin) => Value::Unknown(Rc::clone(origin)),
    };

    Ok(value)
}

/// Unsigned C `long` conversion, whose width is that of C `long`.
fn unsigned_long(vm: &Vm, value: &Value) -> PyResult<u64> {
    const NEGATIVE: &str = "can't convert negative value to unsigned long";

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => u64::try_from(number).map_err(|_| vm.raise(ExceptionKind::OverflowError, NEGATIVE)),
        Some(Integral::Long(number)) => {
            if number.sign() == Sign::Minus {
                return Err(vm.raise(ExceptionKind::OverflowError, NEGATIVE));
            }
            let limit = match vm.config.long_width {
                LongWidth::Bits32 => u64::from(u32::MAX),
                LongWidth::Bits64 => u64::MAX,
            };
            number.to_u64().filter(|number| *number <= limit).ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "long int too large to convert"))
        }
        // The internal error reports the source location of the Windows
        // build.
        None => Err(vm.raise(ExceptionKind::SystemError, "..\\Objects\\longobject.c:426: bad argument to internal function")),
    }
}

/// C `long` conversion: integers directly, anything else through `__int__`.
fn c_long(vm: &Vm, value: &Value) -> PyResult<i64> {
    let integral = match vm.as_integral(value) {
        Some(integral) => integral,
        None => number_int(vm, value)?,
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64().filter(|number| numbers::fits_int(vm.config.long_width, *number)),
    };

    number.ok_or_else(|| vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"))
}

/// The `__int__` conversion of a non-integer.
fn number_int(vm: &Vm, value: &Value) -> PyResult<Integral> {
    if let Some(number) = vm.as_float(value) {
        return float_to_integer(vm, number).map(Integral::Long);
    }
    if vm.as_complex(value).is_some() {
        return Err(vm.type_error("can't convert complex to int"));
    }
    let Some(method) = vm.user_override(value, "__int__")? else {
        return Err(vm.type_error("an integer is required"));
    };

    let result = vm.call0(&method)?;
    halt_on_unknown(&result, "__int__ result")?;

    vm.as_integral(&result).ok_or_else(|| vm.type_error("nb_int should return int object"))
}
