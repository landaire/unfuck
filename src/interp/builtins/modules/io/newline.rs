//! `IncrementalNewlineDecoder` and the line-ending search of the text
//! layer.

use std::cell::RefCell;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use super::after_receiver;
use super::allocation_class;
use super::int_argument;
use super::missing_argument;
use super::require_known;

const CR: u16 = b'\r' as u16;
const LF: u16 = b'\n' as u16;

/// The kinds of line ending a decoder has seen.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SeenNewlines(u8);

impl SeenNewlines {
    const CR: Self = Self(1);
    const LF: Self = Self(2);
    const CRLF: Self = Self(4);

    fn insert(&mut self, kind: Self) {
        self.0 |= kind.0;
    }

    /// The `newlines` attribute: one kind as `unicode`, several as a tuple
    /// of `str`.
    pub fn value(self) -> Value {
        let kinds: Vec<&str> = [(Self::CR, "\r"), (Self::LF, "\n"), (Self::CRLF, "\r\n")].into_iter().filter(|(kind, _)| self.0 & kind.0 != 0).map(|(_, text)| text).collect();

        match kinds.as_slice() {
            [] => Value::None,
            [single] => Value::Unicode(PyText::from_str(single)),
            several => Value::tuple(several.iter().map(|text| Value::str(text)).collect()),
        }
    }
}

/// The newline translation state of a decoder, shared with `StringIO`.
#[derive(Clone, Copy)]
pub struct NewlineState {
    pub pending_cr: bool,
    pub translate: bool,
    pub seen: SeenNewlines,
}

impl NewlineState {
    pub fn new(translate: bool) -> Self {
        Self { pending_cr: false, translate, seen: SeenNewlines::default() }
    }

    /// The newline step after the wrapped decoder ran: holds back a final
    /// `\r` until the next call, records the line endings, and translates
    /// them when asked.
    pub fn decode(&mut self, mut output: Vec<u16>, is_final: bool) -> Vec<u16> {
        if self.pending_cr && (is_final || !output.is_empty()) {
            output.insert(0, CR);
            self.pending_cr = false;
        }
        if !is_final && output.last() == Some(&CR) {
            output.pop();
            self.pending_cr = true;
        }

        let mut translated = Vec::with_capacity(output.len());
        let mut index = 0;
        while let Some(&unit) = output.get(index) {
            index += 1;
            match unit {
                LF => {
                    self.seen.insert(SeenNewlines::LF);
                    translated.push(LF);
                }
                CR if output.get(index) == Some(&LF) => {
                    self.seen.insert(SeenNewlines::CRLF);
                    index += 1;
                    if self.translate {
                        translated.push(LF);
                    } else {
                        translated.extend([CR, LF]);
                    }
                }
                CR => {
                    self.seen.insert(SeenNewlines::CR);
                    translated.push(if self.translate { LF } else { CR });
                }
                _ => translated.push(unit),
            }
        }

        translated
    }
}

/// How the line-ending search recognizes the end of a line.
pub enum LineEnding {
    /// Newlines are already translated to `\n`.
    Translated,
    /// Any of `\r`, `\r\n`, and `\n`.
    Universal,
    /// One fixed separator.
    Fixed(Vec<u16>),
}

impl LineEnding {
    /// The length of the first line of `text`, or `None` when it has no
    /// line ending.
    pub fn line_length(&self, text: &[u16]) -> Option<usize> {
        match self {
            Self::Translated => text.iter().position(|unit| *unit == LF).map(|index| index + 1),
            Self::Universal => {
                let index = text.iter().position(|unit| *unit == LF || *unit == CR)?;
                let crlf = text[index] == CR && text.get(index + 1) == Some(&LF);

                Some(index + if crlf { 2 } else { 1 })
            }
            Self::Fixed(separator) => {
                let length = separator.len();
                if length == 0 || text.len() < length {
                    return None;
                }

                text.windows(length).position(|window| window == separator.as_slice()).map(|index| index + length)
            }
        }
    }

    /// How much of `text`, which has no line ending, can be set aside: all
    /// of it, except a trailing prefix of a multi-character separator.
    pub fn consumed(&self, text: &[u16]) -> usize {
        let Self::Fixed(separator) = self else {
            return text.len();
        };
        let (Some(first), true) = (separator.first(), separator.len() > 1) else {
            return text.len();
        };

        let tail = (text.len() + 1).saturating_sub(separator.len());
        text[tail..].iter().position(|unit| unit == first).map_or(text.len(), |index| tail + index)
    }
}

/// An `IncrementalNewlineDecoder`. The wrapped decoder is `None` until
/// `__init__` runs.
struct Decoder {
    inner: RefCell<Option<Value>>,
    state: RefCell<NewlineState>,
}

impl_native_data!(Decoder, "_io.IncrementalNewlineDecoder");

pub fn decoder_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, "_io.IncrementalNewlineDecoder", create_decoder_type)
}

fn create_decoder_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "IncrementalNewlineDecoder",
            module: "_io",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[
                static_method("__new__", decoder_new),
                method("__init__", decoder_init),
                method("decode", decoder_decode),
                method("getstate", decoder_getstate),
                method("setstate", decoder_setstate),
                method("reset", decoder_reset),
            ],
        },
    )?;
    add_getset(vm, &class, GetSet { name: "newlines", owner: "_io.IncrementalNewlineDecoder", get: decoder_newlines, set: None })?;

    Ok(class)
}

fn receiver<'a>(vm: &Vm, args: &'a CallArgs, method: &str) -> PyResult<&'a Decoder> {
    this::<Decoder>(vm, args, "_io.IncrementalNewlineDecoder", method)
}

/// The wrapped decoder; CPython calls through a null pointer when
/// `__init__` never ran.
fn initialized_inner(vm: &Vm, decoder: &Decoder) -> PyResult<Value> {
    decoder.inner.borrow().clone().ok_or_else(|| vm.raise(ExceptionKind::SystemError, "null argument to internal routine"))
}

fn decoder_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &decoder_type(vm)?)?;

    Ok(new_native_object(vm, &class, Decoder { inner: RefCell::new(None), state: RefCell::new(NewlineState::new(false)) }))
}

fn decoder_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = receiver(vm, &args, "__init__")?;
    let slots = parse(vm, after_receiver(&args), "IncrementalNewlineDecoder", &["decoder", "translate", "errors"], 0)?;

    let Some(inner) = slots[0].clone() else {
        return Err(missing_argument(vm, "decoder", 1));
    };
    let Some(translate) = &slots[1] else {
        return Err(missing_argument(vm, "translate", 2));
    };
    let translate = int_argument(vm, translate, "IncrementalNewlineDecoder translate")? != 0;

    *decoder.inner.borrow_mut() = Some(inner);
    *decoder.state.borrow_mut() = NewlineState::new(translate);

    Ok(Value::None)
}

/// Decodes through a decoder object.
fn decode_with(vm: &Vm, decoder: &Decoder, input: Value, is_final: bool) -> PyResult<Value> {
    let Some(inner) = decoder.inner.borrow().clone() else {
        return Err(vm.raise(ExceptionKind::ValueError, "IncrementalNewlineDecoder.__init__ not called"));
    };

    let output = if inner.is_none() { input } else { vm.call_method(&inner, "decode", vec![input, Value::Bool(is_final)])? };
    require_known(&output, "decoded text")?;
    let Some(text) = vm.as_text(&output) else {
        return Err(vm.type_error(&format!("decoder should return a string result, not '{}'", vm.type_name(&output))));
    };

    let units = decoder.state.borrow_mut().decode(text.units().to_vec(), is_final);

    Ok(Value::Unicode(PyText::new(units)))
}

fn decoder_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = receiver(vm, &args, "decode")?;
    let slots = parse(vm, after_receiver(&args), "IncrementalNewlineDecoder", &["input", "final"], 0)?;

    let Some(input) = slots[0].clone() else {
        return Err(missing_argument(vm, "input", 1));
    };
    let is_final = match &slots[1] {
        Some(flag) => int_argument(vm, flag, "IncrementalNewlineDecoder final")? != 0,
        None => false,
    };

    decode_with(vm, decoder, input, is_final)
}

/// The `K` conversion: any integer, reduced modulo 2**64.
fn unsigned_mask(vm: &Vm, value: &Value) -> PyResult<u64> {
    require_known(value, "decoder state flag")?;

    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Ok(number as u64),
        Some(Integral::Long(number)) => {
            let modulus = BigInt::from(1u8) << 64;
            let reduced: BigInt = ((number % &modulus) + &modulus) % &modulus;
            Ok(reduced.to_u64().unwrap_or(0))
        }
        None => Err(vm.type_error(&format!("argument 2 must be an integer, not {}", vm.type_name(value)))),
    }
}

/// A state tuple `(OK)`: a buffer and a flag word.
fn parse_state(vm: &Vm, state: &Value) -> PyResult<(Value, u64)> {
    require_known(state, "decoder state")?;

    let is_sequence = vm.as_str_bytes(state).is_none() && (vm.as_tuple(state).is_some() || vm.as_list(state).is_some() || vm.as_text(state).is_some() || vm.user_override(state, "__getitem__")?.is_some());
    if !is_sequence {
        return Err(vm.type_error(&format!("argument must be 2-item sequence, not {}", vm.type_name(state))));
    }

    let length = match vm.len(state)? {
        Some(length) => length,
        None => return Err(vm.type_error(&format!("object of type '{}' has no len()", vm.type_name(state)))),
    };
    if length != 2 {
        return Err(vm.type_error(&format!("argument must be sequence of length 2, not {length}")));
    }

    let buffer = vm.getitem(state, &Value::Int(0))?;
    let flag = vm.getitem(state, &Value::Int(1))?;

    Ok((buffer, unsigned_mask(vm, &flag)?))
}

fn decoder_getstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = receiver(vm, &args, "getstate")?;
    method_no_arguments(vm, &args, "getstate")?;

    let inner = initialized_inner(vm, decoder)?;
    let (buffer, flag) = if inner.is_none() {
        (Value::str(""), 0)
    } else {
        let state = vm.call_method(&inner, "getstate", Vec::new())?;
        parse_state(vm, &state)?
    };

    let flag = (flag << 1) | u64::from(decoder.state.borrow().pending_cr);

    Ok(Value::tuple(vec![buffer, Value::Long(Rc::new(BigInt::from(flag)))]))
}

fn decoder_setstate(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = receiver(vm, &args, "setstate")?;
    let state = method_one_argument(vm, &args, "setstate")?;

    let (buffer, flag) = parse_state(vm, &state)?;
    decoder.state.borrow_mut().pending_cr = flag & 1 != 0;

    let inner = initialized_inner(vm, decoder)?;
    if inner.is_none() {
        return Ok(Value::None);
    }

    let inner_state = Value::tuple(vec![buffer, Value::Long(Rc::new(BigInt::from(flag >> 1)))]);

    vm.call_method(&inner, "setstate", vec![inner_state])
}

fn decoder_reset(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = receiver(vm, &args, "reset")?;
    method_no_arguments(vm, &args, "reset")?;

    {
        let mut state = decoder.state.borrow_mut();
        state.seen = SeenNewlines::default();
        state.pending_cr = false;
    }

    let inner = initialized_inner(vm, decoder)?;
    if inner.is_none() {
        return Ok(Value::None);
    }

    vm.call_method(&inner, "reset", Vec::new())
}

fn decoder_newlines(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(decoder) = native_data::<Decoder>(instance) else {
        return Err(vm.type_error(&format!("descriptor '{}' for '{}' objects doesn't apply to '{}' object", getset.name, getset.owner, vm.type_name(instance))));
    };

    Ok(decoder.state.borrow().seen.value())
}
