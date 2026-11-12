//! `_multibytecodec`: the codec objects `getcodec` returns, and the
//! incremental and stream classes the `encodings` modules derive from.

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::new_instance;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::capsule::capsule_pointer;
use crate::interp::builtins::modules::cjkcodecs::CAPSULE_NAME;
use crate::interp::builtins::modules::cjkcodecs::codec::Codec;
use crate::interp::builtins::modules::cjkcodecs::codec::DecoderState;
use crate::interp::builtins::modules::cjkcodecs::codec::EncoderState;
use crate::interp::builtins::modules::cjkcodecs::codec::Fault;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::codecs::errors::DecodeFault;
use crate::interp::builtins::modules::codecs::errors::EncodeFault;
use crate::interp::builtins::modules::codecs::errors::new_decode_exception;
use crate::interp::builtins::modules::codecs::errors::new_encode_exception;
use crate::interp::builtins::modules::codecs::registry;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::method_one_argument;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::operator::is_sequence;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::static_method;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const ILLEGAL: &str = "illegal multibyte sequence";
const INCOMPLETE: &str = "incomplete multibyte sequence";

/// Units an incremental encoder or stream writer may hold back.
const MAX_PENDING_UNITS: usize = 2;
/// Bytes an incremental decoder or stream reader may hold back.
const MAX_PENDING_BYTES: usize = 8;

const CODEC_TYPE: &str = "MultibyteCodec";
const ENCODER_TYPE: &str = "MultibyteIncrementalEncoder";
const DECODER_TYPE: &str = "MultibyteIncrementalDecoder";
const READER_TYPE: &str = "MultibyteStreamReader";
const WRITER_TYPE: &str = "MultibyteStreamWriter";

struct CodecObject {
    codec: Codec,
}

impl_native_data!(CodecObject, "MultibyteCodec");

struct IncrementalEncoder {
    codec: Codec,
    errors: RefCell<PyBytes>,
    state: Cell<EncoderState>,
    pending: RefCell<Vec<u16>>,
}

impl_native_data!(IncrementalEncoder, "MultibyteIncrementalEncoder");

struct IncrementalDecoder {
    codec: Codec,
    errors: RefCell<PyBytes>,
    state: Cell<DecoderState>,
    pending: RefCell<Vec<u8>>,
}

impl_native_data!(IncrementalDecoder, "MultibyteIncrementalDecoder");

struct StreamReader {
    codec: Codec,
    errors: RefCell<PyBytes>,
    state: Cell<DecoderState>,
    pending: RefCell<Vec<u8>>,
    stream: Value,
}

impl_native_data!(StreamReader, "MultibyteStreamReader");

struct StreamWriter {
    codec: Codec,
    errors: RefCell<PyBytes>,
    state: Cell<EncoderState>,
    pending: RefCell<Vec<u16>>,
    stream: Value,
}

impl_native_data!(StreamWriter, "MultibyteStreamWriter");

/// How one call handles coding errors.
enum Policy {
    Strict,
    Ignore,
    Replace,
    /// A handler from the registry, looked up at the first error.
    Registered(Vec<u8>),
}

impl Policy {
    /// The policy for an `errors` C string; `None` means strict.
    fn new(errors: Option<&[u8]>) -> Self {
        match errors {
            None | Some(b"strict") => Self::Strict,
            Some(b"ignore") => Self::Ignore,
            Some(b"replace") => Self::Replace,
            Some(name) => Self::Registered(name.to_vec()),
        }
    }
}

/// The error state of one encode or decode call: the handler once looked
/// up, and the exception object it receives, reused for later errors.
struct Handling<'a> {
    vm: &'a Vm,
    codec: Codec,
    policy: Policy,
    handler: Option<Value>,
    exception: Option<Value>,
}

/// A coding error at `start..end` of the input.
struct ErrorSpan {
    start: usize,
    end: usize,
    reason: &'static str,
}

impl ErrorSpan {
    /// The span of a fault; an internal fault is not a coding error.
    fn new(vm: &Vm, fault: Fault, position: usize, length: usize) -> PyResult<Self> {
        match fault {
            Fault::Illegal(size) => Ok(Self { start: position, end: position + size, reason: ILLEGAL }),
            Fault::Incomplete => Ok(Self { start: position, end: length, reason: INCOMPLETE }),
            Fault::Internal => Err(vm.raise(ExceptionKind::RuntimeError, "internal codec error")),
        }
    }
}

impl<'a> Handling<'a> {
    fn new(vm: &'a Vm, codec: Codec, errors: Option<&[u8]>) -> Self {
        Self { vm, codec, policy: Policy::new(errors), handler: None, exception: None }
    }

    fn handler(&mut self) -> PyResult<Value> {
        if let Some(handler) = &self.handler {
            return Ok(handler.clone());
        }
        let Policy::Registered(name) = &self.policy else {
            return Err(self.vm.raise(ExceptionKind::SystemError, "no registered error handler"));
        };

        let handler = registry::lookup_error(self.vm, name)?;
        self.handler = Some(handler.clone());

        Ok(handler)
    }

    /// The exception for an error: the one this call made before, updated,
    /// or a new one.
    fn exception(&mut self, span: &ErrorSpan, create: impl FnOnce() -> PyResult<Value>) -> PyResult<Value> {
        let Some(exception) = self.exception.clone() else {
            let exception = create()?;
            self.exception = Some(exception.clone());
            return Ok(exception);
        };

        self.vm.setattr_str(&exception, "start", args::index_value(span.start))?;
        self.vm.setattr_str(&exception, "end", args::index_value(span.end))?;
        self.vm.setattr_str(&exception, "reason", Value::str(span.reason))?;

        Ok(exception)
    }

    /// Calls the registered handler; returns its replacement and the
    /// position it asks to resume at, not yet checked against the input.
    fn call_handler(&mut self, exception: Value, message: &str) -> PyResult<(PyText, Resume)> {
        let handler = self.handler()?;
        let result = self.vm.call(&handler, CallArgs::new(vec![exception]))?;
        if result.is_unknown() {
            return Err(Signal::Halt(Halt::UnknownCondition { context: "codec error handler result".to_owned(), origin: format!("{result:?}") }));
        }

        let replacement = self.vm.as_tuple(&result).and_then(|items| match &items[..] {
            [text, position] if self.vm.as_float(position).is_none() => {
                let text = self.vm.as_text(text)?;
                let resume = match self.vm.as_integral(position)? {
                    Integral::Int(number) => Resume::At(number),
                    Integral::Long(number) => number.to_i64().map_or(Resume::OutOfRange, Resume::At),
                };
                Some((text, resume))
            }
            _ => None,
        });
        let Some((text, position)) = replacement else {
            return Err(self.vm.type_error(message));
        };

        Ok((text, position))
    }

    /// Handles an encoding error; returns where encoding resumes.
    fn encode_error(&mut self, state: &Cell<EncoderState>, input: &[u16], span: ErrorSpan, output: &mut Vec<u8>) -> PyResult<usize> {
        match self.policy {
            Policy::Strict => {
                let exception = new_encode_exception(self.vm, &EncodeFault { encoding: self.codec.name(), reason: span.reason, input, start: span.start, end: span.end })?;
                Err(Signal::Raise(exception))
            }
            Policy::Ignore => Ok(span.end),
            Policy::Replace => {
                encode_strict(self.vm, self.codec, state, &[u16::from(b'?')], output)?;
                Ok(span.end)
            }
            Policy::Registered(_) => {
                let vm = self.vm;
                let codec = self.codec;
                let exception = self.exception(&span, || new_encode_exception(vm, &EncodeFault { encoding: codec.name(), reason: span.reason, input, start: span.start, end: span.end }))?;
                let (replacement, position) = self.call_handler(exception, "encoding error handler must return (unicode, int) tuple")?;
                // The replacement is encoded, changing the state, before the
                // position is checked.
                encode_strict(self.vm, self.codec, state, replacement.units(), output)?;
                position_in(self.vm, position, input.len())
            }
        }
    }

    /// Handles a decoding error; returns where decoding resumes.
    fn decode_error(&mut self, input: &[u8], span: ErrorSpan, output: &mut Vec<u16>) -> PyResult<usize> {
        match self.policy {
            Policy::Strict => {
                let exception = new_decode_exception(self.vm, &DecodeFault { encoding: self.codec.name(), reason: span.reason, input, start: span.start, end: span.end })?;
                Err(Signal::Raise(exception))
            }
            Policy::Ignore => Ok(span.end.min(input.len())),
            Policy::Replace => {
                output.push(0xfffd);
                Ok(span.end.min(input.len()))
            }
            Policy::Registered(_) => {
                let vm = self.vm;
                let codec = self.codec;
                let exception = self.exception(&span, || new_decode_exception(vm, &DecodeFault { encoding: codec.name(), reason: span.reason, input, start: span.start, end: span.end }))?;
                let (replacement, position) = self.call_handler(exception, "decoding error handler must return (unicode, int) tuple")?;
                output.extend_from_slice(replacement.units());
                position_in(self.vm, position, input.len())
            }
        }
    }
}

/// The position an error handler returns.
#[derive(Clone, Copy)]
enum Resume {
    At(i64),
    /// An integer too large for a 64-bit position.
    OutOfRange,
}

/// A handler's resume position: negative counts from the end. A position
/// beyond 64 bits reports as -1, which is not resolved against the end.
fn position_in(vm: &Vm, position: Resume, length: usize) -> PyResult<usize> {
    let Resume::At(position) = position else {
        return Err(vm.raise(ExceptionKind::IndexError, "position -1 from error handler out of bounds"));
    };
    let length = i64::try_from(length).unwrap_or(i64::MAX);
    let resolved = if position < 0 { position + length } else { position };

    usize::try_from(resolved).ok().filter(|_| resolved <= length).ok_or_else(|| vm.raise(ExceptionKind::IndexError, &format!("position {resolved} from error handler out of bounds")))
}

/// Encodes a handler's replacement in the current state; any error raises.
fn encode_strict(vm: &Vm, codec: Codec, state: &Cell<EncoderState>, input: &[u16], output: &mut Vec<u8>) -> PyResult<()> {
    let mut current = state.get();
    let mut position = 0;
    let result = codec.encode(&mut current, input, &mut position, true, output);
    state.set(current);

    let Err(fault) = result else {
        return Ok(());
    };
    let span = ErrorSpan::new(vm, fault, position, input.len())?;
    let exception = new_encode_exception(vm, &EncodeFault { encoding: codec.name(), reason: span.reason, input, start: span.start, end: span.end })?;

    Err(Signal::Raise(exception))
}

/// Encodes `input` from `state`; returns the bytes and the units used.
/// With `flush`, nothing is held back and the output returns to the
/// initial state.
fn encode_with(vm: &Vm, codec: Codec, state: &Cell<EncoderState>, input: &[u16], errors: Option<&[u8]>, flush: bool) -> PyResult<(Vec<u8>, usize)> {
    let mut handling = Handling::new(vm, codec, errors);
    let mut output = Vec::with_capacity(input.len() * 2);
    let mut position = 0;

    loop {
        let mut current = state.get();
        let result = codec.encode(&mut current, input, &mut position, flush, &mut output);
        state.set(current);

        let fault = match result {
            Ok(()) => break,
            Err(Fault::Incomplete) if !flush => break,
            Err(fault) => fault,
        };
        let span = ErrorSpan::new(vm, fault, position, input.len())?;
        position = handling.encode_error(state, input, span, &mut output)?;
    }

    if flush {
        let mut current = state.get();
        codec.encode_reset(&mut current, &mut output);
        state.set(current);
    }

    Ok((output, position))
}

/// How a decoding pass treats a sequence the input ends inside.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// More input may follow: the bytes stay unconsumed.
    Pending,
    /// One-shot decoding: an error, after which decoding resumes.
    Error,
    /// The last call of an incremental decoder or stream reader: an error,
    /// after which the pass ends and the bytes from where the handler
    /// resumes stay unconsumed.
    ErrorThenStop,
}

/// Decodes `input` from `state`; returns the text and the bytes used.
fn decode_pass(handling: &mut Handling<'_>, state: &Cell<DecoderState>, input: &[u8], ending: Ending) -> PyResult<(Vec<u16>, usize)> {
    let vm = handling.vm;
    let codec = handling.codec;
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;

    loop {
        let mut current = state.get();
        let result = codec.decode(&mut current, input, &mut position, &mut output);
        state.set(current);

        let fault = match result {
            Ok(()) => break,
            Err(Fault::Incomplete) if ending == Ending::Pending => break,
            Err(fault) => fault,
        };
        let span = ErrorSpan::new(vm, fault, position, input.len())?;
        position = handling.decode_error(input, span, &mut output)?;
        if fault == Fault::Incomplete && ending == Ending::ErrorThenStop {
            break;
        }
    }

    Ok((output, position))
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("__create_codec", create_codec)])?;

    let dict = vm.instance_dict(module)?;
    vm.dict_set_str(&dict, "MultibyteIncrementalEncoder", Value::Object(encoder_type(vm)?))?;
    vm.dict_set_str(&dict, "MultibyteIncrementalDecoder", Value::Object(decoder_type(vm)?))?;
    vm.dict_set_str(&dict, "MultibyteStreamReader", Value::Object(reader_type(vm)?))?;
    vm.dict_set_str(&dict, "MultibyteStreamWriter", Value::Object(writer_type(vm)?))?;

    Ok(())
}

/// `__create_codec(capsule)`: the codec object for a capsule `getcodec`
/// made.
fn create_codec(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = args::single(vm, args, "__create_codec")?;
    let Some(codec) = capsule_pointer::<Codec>(&argument, CAPSULE_NAME).copied() else {
        return Err(vm.raise(ExceptionKind::ValueError, "argument type invalid"));
    };

    let class = native_type(vm, CODEC_TYPE, create_codec_type)?;

    Ok(new_native_object(vm, &class, CodecObject { codec }))
}

fn create_codec_type(vm: &Vm) -> PyResult<ObjectRef> {
    new_final_type(vm, TypeSpec { name: CODEC_TYPE, module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: &[method("encode", codec_encode), method("decode", codec_decode)] })
}

/// The arguments after a method's receiver.
fn rest_of(args: &CallArgs) -> CallArgs {
    CallArgs { positional: args.positional.iter().skip(1).cloned().collect(), keywords: args.keywords.clone(), keyword_dict: args.keyword_dict.clone() }
}

/// An encoder's input converted as `unicode(input)` converts it.
fn unicode_input(vm: &Vm, value: &Value) -> PyResult<PyText> {
    halt_on_unknown(value, "multibyte codec input")?;
    let converted = vm.to_unicode(value)?;

    vm.as_text(&converted).ok_or_else(|| vm.type_error("coercing to Unicode: need string or buffer"))
}

/// `encode(input, errors=None)`: the bytes and the input length.
fn codec_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let codec = this::<CodecObject>(vm, &args, CODEC_TYPE, "encode")?.codec;
    let slots = parse(vm, rest_of(&args), "encode", &["input", "errors"], 1)?;
    let Some(input) = &slots[0] else {
        return Err(vm.type_error("Required argument 'input' (pos 1) not found"));
    };
    if input.is_unknown() {
        return Ok(input.clone());
    }
    let errors = args::optional_string(vm, "encode", 2, slots[1].as_ref())?;

    let text = unicode_input(vm, input)?;
    let state = Cell::new(codec.encoder_state());
    let (output, _) = encode_with(vm, codec, &state, text.units(), errors.as_ref().map(PyBytes::as_bytes), true)?;

    Ok(Value::tuple(vec![Value::Str(PyBytes::new(output)), args::index_value(text.units().len())]))
}

/// `decode(input, errors=None)`: the text and the input length.
fn codec_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let codec = this::<CodecObject>(vm, &args, CODEC_TYPE, "decode")?.codec;
    let slots = parse(vm, rest_of(&args), "decode", &["input", "errors"], 1)?;
    let Some(input) = &slots[0] else {
        return Err(vm.type_error("Required argument 'input' (pos 1) not found"));
    };
    if input.is_unknown() {
        return Ok(input.clone());
    }
    let bytes = args::string_or_buffer(vm, "decode", 1, input)?;
    let errors = args::optional_string(vm, "decode", 2, slots[1].as_ref())?;

    let state = Cell::new(codec.decoder_state());
    let mut handling = Handling::new(vm, codec, errors.as_ref().map(PyBytes::as_bytes));
    let (output, _) = decode_pass(&mut handling, &state, bytes.as_bytes(), Ending::Error)?;

    Ok(Value::tuple(vec![Value::Unicode(PyText::new(output)), args::index_value(bytes.as_bytes().len())]))
}

/// The `errors` C string: a `str` up to its first NUL.
fn c_string_prefix(bytes: &PyBytes) -> PyBytes {
    let data = bytes.as_bytes();
    let end = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());

    PyBytes::new(&data[..end])
}

/// The `codec` class attribute of an incremental or stream class.
fn class_codec(vm: &Vm, class: &ObjectRef) -> PyResult<Codec> {
    let codec = vm.getattr_str(&Value::Object(Rc::clone(class)), "codec")?;

    native_data::<CodecObject>(&codec).map(|object| object.codec).ok_or_else(|| vm.type_error("codec is unexpected type"))
}

/// The class a native `__new__` allocates, which must derive from `base`.
fn allocation_class(vm: &Vm, args: &CallArgs, base: &ObjectRef) -> PyResult<ObjectRef> {
    let name = vm.class_name(base);
    let Some(first) = args.positional.first() else {
        return Err(vm.type_error(&format!("{name}.__new__(): not enough arguments")));
    };
    let Value::Object(class) = first.clone() else {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    };
    if class.as_class().is_none() {
        return Err(vm.type_error(&format!("{name}.__new__(X): X is not a type object ({})", vm.type_name(first))));
    }
    if !vm.is_subclass(&class, base)? {
        let given = vm.class_name(&class);
        return Err(vm.type_error(&format!("{name}.__new__({given}): {given} is not a subtype of {name}")));
    }

    Ok(class)
}

/// The `errors` argument of a constructor (`s` format), 'strict' when
/// absent.
fn constructor_errors(vm: &Vm, function: &str, position: usize, value: Option<&Value>) -> PyResult<PyBytes> {
    match value {
        Some(value) => args::c_string(vm, function, position, value),
        None => Ok(PyBytes::from("strict")),
    }
}

/// The receiver's `errors` as the `Option` the coding functions take.
fn errors_of(errors: &RefCell<PyBytes>) -> Vec<u8> {
    errors.borrow().as_bytes().to_vec()
}

fn no_init(_vm: &Vm, _args: CallArgs) -> PyResult<Value> {
    Ok(Value::None)
}

fn errors_getset(owner: &'static str, get: fn(&Vm, &GetSet, &Value) -> PyResult<Value>, set: fn(&Vm, &GetSet, &Value, Option<Value>) -> PyResult<()>) -> GetSet {
    GetSet { name: "errors", owner, get, set: Some(set) }
}

/// Stores a new `errors` string, which must be a `str`.
fn store_errors(vm: &Vm, errors: &RefCell<PyBytes>, value: Option<Value>) -> PyResult<()> {
    let Some(bytes) = value.as_ref().and_then(|value| vm.as_str_bytes(value)) else {
        return Err(vm.type_error("errors must be a string"));
    };
    *errors.borrow_mut() = c_string_prefix(&bytes);

    Ok(())
}

fn encoder_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, ENCODER_TYPE, |vm| {
        let class = new_type(
            vm,
            TypeSpec {
                name: ENCODER_TYPE,
                module: "__builtin__",
                base: None,
                layout: Layout::Native,
                instance_dict: false,
                methods: &[static_method("__new__", encoder_new), method("__init__", no_init), method("encode", encoder_encode), method("reset", encoder_reset)],
            },
        )?;
        add_getset(vm, &class, errors_getset(ENCODER_TYPE, encoder_errors_get, encoder_errors_set))?;
        Ok(class)
    })
}

fn encoder_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &encoder_type(vm)?)?;
    let slots = parse(vm, rest_of(&args), "IncrementalEncoder", &["errors"], 0)?;
    let errors = constructor_errors(vm, "IncrementalEncoder", 1, slots[0].as_ref())?;
    let codec = class_codec(vm, &class)?;

    let encoder = IncrementalEncoder { codec, errors: RefCell::new(errors), state: Cell::new(codec.encoder_state()), pending: RefCell::new(Vec::new()) };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(encoder))))
}

fn encoder_errors_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(encoder) = native_data::<IncrementalEncoder>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Str(encoder.errors.borrow().clone()))
}

fn encoder_errors_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Some(encoder) = native_data::<IncrementalEncoder>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    store_errors(vm, &encoder.errors, value)
}

/// `encode(input, final=0)`: units that may combine with the next call's
/// input stay pending unless `final`.
fn encoder_encode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let encoder = this::<IncrementalEncoder>(vm, &args, ENCODER_TYPE, "encode")?;
    let slots = parse(vm, rest_of(&args), "encode", &["input", "final"], 1)?;
    let Some(input) = &slots[0] else {
        return Err(vm.type_error("Required argument 'input' (pos 1) not found"));
    };
    let text = unicode_input(vm, input)?;
    let last = match &slots[1] {
        Some(value) => args::c_int(vm, value)? != 0,
        None => false,
    };

    let mut units = encoder.pending.borrow().clone();
    units.extend_from_slice(text.units());
    let errors = errors_of(&encoder.errors);
    let (output, used) = encode_with(vm, encoder.codec, &encoder.state, &units, Some(&errors), last)?;
    hold_units(vm, &encoder.pending, &units[used..])?;

    Ok(Value::Str(PyBytes::new(output)))
}

/// Keeps the units an encoder could not finish for its next call.
fn hold_units(vm: &Vm, pending: &RefCell<Vec<u16>>, rest: &[u16]) -> PyResult<()> {
    if rest.len() > MAX_PENDING_UNITS {
        return Err(vm.raise(ExceptionKind::UnicodeError, "pending buffer overflow"));
    }
    *pending.borrow_mut() = rest.to_vec();

    Ok(())
}

/// Keeps the bytes a decoder could not finish for its next call.
fn hold_bytes(vm: &Vm, pending: &RefCell<Vec<u8>>, rest: &[u8]) -> PyResult<()> {
    if rest.len() > MAX_PENDING_BYTES {
        return Err(vm.raise(ExceptionKind::UnicodeError, "pending buffer overflow"));
    }
    *pending.borrow_mut() = rest.to_vec();

    Ok(())
}

fn encoder_reset(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let encoder = this::<IncrementalEncoder>(vm, &args, ENCODER_TYPE, "reset")?;
    method_no_arguments(vm, &args, "reset")?;

    let mut state = encoder.state.get();
    encoder.codec.reset_encoder(&mut state);
    encoder.state.set(state);
    encoder.pending.borrow_mut().clear();

    Ok(Value::None)
}

fn decoder_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, DECODER_TYPE, |vm| {
        let class = new_type(
            vm,
            TypeSpec {
                name: DECODER_TYPE,
                module: "__builtin__",
                base: None,
                layout: Layout::Native,
                instance_dict: false,
                methods: &[static_method("__new__", decoder_new), method("__init__", no_init), method("decode", decoder_decode), method("reset", decoder_reset)],
            },
        )?;
        add_getset(vm, &class, errors_getset(DECODER_TYPE, decoder_errors_get, decoder_errors_set))?;
        Ok(class)
    })
}

fn decoder_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &decoder_type(vm)?)?;
    let slots = parse(vm, rest_of(&args), "IncrementalDecoder", &["errors"], 0)?;
    let errors = constructor_errors(vm, "IncrementalDecoder", 1, slots[0].as_ref())?;
    let codec = class_codec(vm, &class)?;

    let decoder = IncrementalDecoder { codec, errors: RefCell::new(errors), state: Cell::new(codec.decoder_state()), pending: RefCell::new(Vec::new()) };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(decoder))))
}

fn decoder_errors_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(decoder) = native_data::<IncrementalDecoder>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Str(decoder.errors.borrow().clone()))
}

fn decoder_errors_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Some(decoder) = native_data::<IncrementalDecoder>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    store_errors(vm, &decoder.errors, value)
}

/// `decode(input, final=0)`: bytes of an unfinished sequence stay pending
/// unless `final`.
fn decoder_decode(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = this::<IncrementalDecoder>(vm, &args, DECODER_TYPE, "decode")?;
    let slots = parse(vm, rest_of(&args), "decode", &["input", "final"], 1)?;
    let Some(input) = &slots[0] else {
        return Err(vm.type_error("Required argument 'input' (pos 1) not found"));
    };
    halt_on_unknown(input, "multibyte decoder input")?;
    let bytes = args::string_or_buffer(vm, "decode", 1, input)?;
    let last = match &slots[1] {
        Some(value) => args::c_int(vm, value)? != 0,
        None => false,
    };

    let mut data = std::mem::take(&mut *decoder.pending.borrow_mut());
    data.extend_from_slice(bytes.as_bytes());
    let errors = errors_of(&decoder.errors);
    let mut handling = Handling::new(vm, decoder.codec, Some(&errors));
    let ending = if last { Ending::ErrorThenStop } else { Ending::Pending };
    let (output, used) = decode_pass(&mut handling, &decoder.state, &data, ending)?;
    hold_bytes(vm, &decoder.pending, &data[used..])?;

    Ok(Value::Unicode(PyText::new(output)))
}

fn decoder_reset(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let decoder = this::<IncrementalDecoder>(vm, &args, DECODER_TYPE, "reset")?;
    method_no_arguments(vm, &args, "reset")?;

    let mut state = decoder.state.get();
    decoder.codec.reset_decoder(&mut state);
    decoder.state.set(state);
    decoder.pending.borrow_mut().clear();

    Ok(Value::None)
}

fn stream_member(owner: &'static str, get: fn(&Vm, &GetSet, &Value) -> PyResult<Value>) -> GetSet {
    GetSet { name: "stream", owner, get, set: None }
}

fn reader_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, READER_TYPE, |vm| {
        let class = new_type(
            vm,
            TypeSpec {
                name: READER_TYPE,
                module: "__builtin__",
                base: None,
                layout: Layout::Native,
                instance_dict: false,
                methods: &[
                    static_method("__new__", reader_new),
                    method("__init__", no_init),
                    method("read", reader_read),
                    method("readline", reader_readline),
                    method("readlines", reader_readlines),
                    method("reset", reader_reset),
                ],
            },
        )?;
        add_getset(vm, &class, errors_getset(READER_TYPE, reader_errors_get, reader_errors_set))?;
        add_member(vm, &class, stream_member(READER_TYPE, reader_stream))?;
        Ok(class)
    })
}

fn reader_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &reader_type(vm)?)?;
    let slots = parse(vm, rest_of(&args), "StreamReader", &["stream", "errors"], 1)?;
    let Some(stream) = slots[0].clone() else {
        return Err(vm.type_error("Required argument 'stream' (pos 1) not found"));
    };
    let errors = constructor_errors(vm, "StreamReader", 2, slots[1].as_ref())?;
    let codec = class_codec(vm, &class)?;

    let reader = StreamReader { codec, errors: RefCell::new(errors), state: Cell::new(codec.decoder_state()), pending: RefCell::new(Vec::new()), stream };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(reader))))
}

fn reader_errors_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(reader) = native_data::<StreamReader>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Str(reader.errors.borrow().clone()))
}

fn reader_errors_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Some(reader) = native_data::<StreamReader>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    store_errors(vm, &reader.errors, value)
}

fn reader_stream(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(reader) = native_data::<StreamReader>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(reader.stream.clone())
}

/// The optional size argument of `read`, `readline`, and `readlines`:
/// `None` or absent means everything; only `int` is accepted.
fn size_argument(vm: &Vm, args: &CallArgs, name: &str) -> PyResult<i64> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }
    let rest = &args.positional[1.min(args.positional.len())..];
    if rest.len() > 1 {
        return Err(vm.type_error(&format!("{name} expected at most 1 arguments, got {}", rest.len())));
    }

    match rest.first() {
        None => Ok(-1),
        Some(value) if value.is_none() => Ok(-1),
        Some(value) => args::plain_int(value).ok_or_else(|| vm.type_error("arg 1 must be an integer")),
    }
}

/// Reads through `method` of the stream and decodes: everything at once
/// for a negative `size`, else until some text decodes or the stream ends
/// with nothing left over. Errors of one call share an exception object.
fn reader_iread(vm: &Vm, reader: &StreamReader, method: &str, size: i64) -> PyResult<Vec<u16>> {
    let mut output = Vec::new();
    if size == 0 {
        return Ok(output);
    }

    let errors = errors_of(&reader.errors);
    let mut handling = Handling::new(vm, reader.codec, Some(&errors));
    let mut size = size;
    loop {
        let chunk = if size < 0 { vm.call_method(&reader.stream, method, Vec::new())? } else { vm.call_method(&reader.stream, method, vec![Value::Int(size)])? };
        halt_on_unknown(&chunk, "stream read result")?;
        let Some(chunk) = vm.as_str_bytes(&chunk) else {
            return Err(vm.type_error("stream function returned a non-string object"));
        };
        let end_of_file = chunk.as_bytes().is_empty();

        let mut data = std::mem::take(&mut *reader.pending.borrow_mut());
        data.extend_from_slice(chunk.as_bytes());
        // Reading everything leaves nothing to complete a sequence later.
        let ending = if end_of_file || size < 0 { Ending::ErrorThenStop } else { Ending::Pending };
        let (text, used) = decode_pass(&mut handling, &reader.state, &data, ending)?;
        hold_bytes(vm, &reader.pending, &data[used..])?;
        output.extend_from_slice(&text);

        if size < 0 || !output.is_empty() || (end_of_file && reader.pending.borrow().is_empty()) {
            break;
        }
        size = 1;
    }

    Ok(output)
}

fn reader_read(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reader = this::<StreamReader>(vm, &args, READER_TYPE, "read")?;
    let size = size_argument(vm, &args, "read")?;

    Ok(Value::Unicode(PyText::new(reader_iread(vm, reader, "read", size)?)))
}

fn reader_readline(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reader = this::<StreamReader>(vm, &args, READER_TYPE, "readline")?;
    let size = size_argument(vm, &args, "readline")?;

    Ok(Value::Unicode(PyText::new(reader_iread(vm, reader, "readline", size)?)))
}

fn reader_readlines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reader = this::<StreamReader>(vm, &args, READER_TYPE, "readlines")?;
    let size = size_argument(vm, &args, "readlines")?;

    let text = Value::Unicode(PyText::new(reader_iread(vm, reader, "read", size)?));

    vm.call_method(&text, "splitlines", vec![Value::Bool(true)])
}

fn reader_reset(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let reader = this::<StreamReader>(vm, &args, READER_TYPE, "reset")?;
    method_no_arguments(vm, &args, "reset")?;

    let mut state = reader.state.get();
    reader.codec.reset_decoder(&mut state);
    reader.state.set(state);
    reader.pending.borrow_mut().clear();

    Ok(Value::None)
}

fn writer_type(vm: &Vm) -> PyResult<ObjectRef> {
    native_type(vm, WRITER_TYPE, |vm| {
        let class = new_type(
            vm,
            TypeSpec {
                name: WRITER_TYPE,
                module: "__builtin__",
                base: None,
                layout: Layout::Native,
                instance_dict: false,
                methods: &[static_method("__new__", writer_new), method("__init__", no_init), method("write", writer_write), method("writelines", writer_writelines), method("reset", writer_reset)],
            },
        )?;
        add_getset(vm, &class, errors_getset(WRITER_TYPE, writer_errors_get, writer_errors_set))?;
        add_member(vm, &class, stream_member(WRITER_TYPE, writer_stream))?;
        Ok(class)
    })
}

fn writer_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let class = allocation_class(vm, &args, &writer_type(vm)?)?;
    let slots = parse(vm, rest_of(&args), "StreamWriter", &["stream", "errors"], 1)?;
    let Some(stream) = slots[0].clone() else {
        return Err(vm.type_error("Required argument 'stream' (pos 1) not found"));
    };
    let errors = constructor_errors(vm, "StreamWriter", 2, slots[1].as_ref())?;
    let codec = class_codec(vm, &class)?;

    let writer = StreamWriter { codec, errors: RefCell::new(errors), state: Cell::new(codec.encoder_state()), pending: RefCell::new(Vec::new()), stream };

    Ok(new_instance(vm, &class, Payload::Native(Box::new(writer))))
}

fn writer_errors_get(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(writer) = native_data::<StreamWriter>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(Value::Str(writer.errors.borrow().clone()))
}

fn writer_errors_set(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let Some(writer) = native_data::<StreamWriter>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    store_errors(vm, &writer.errors, value)
}

fn writer_stream(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let Some(writer) = native_data::<StreamWriter>(instance) else {
        return Err(descriptor_mismatch(vm, getset, instance));
    };

    Ok(writer.stream.clone())
}

/// Encodes one item without flushing and writes the bytes, even when
/// there are none.
fn writer_iwrite(vm: &Vm, writer: &StreamWriter, item: &Value) -> PyResult<()> {
    let text = unicode_input(vm, item)?;

    let mut units = writer.pending.borrow().clone();
    units.extend_from_slice(text.units());
    let errors = errors_of(&writer.errors);
    let (output, used) = encode_with(vm, writer.codec, &writer.state, &units, Some(&errors), false)?;
    hold_units(vm, &writer.pending, &units[used..])?;

    vm.call_method(&writer.stream, "write", vec![Value::Str(PyBytes::new(output))])?;

    Ok(())
}

fn writer_write(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let writer = this::<StreamWriter>(vm, &args, WRITER_TYPE, "write")?;
    let item = method_one_argument(vm, &args, "write")?;

    writer_iwrite(vm, writer, &item)?;

    Ok(Value::None)
}

fn writer_writelines(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let writer = this::<StreamWriter>(vm, &args, WRITER_TYPE, "writelines")?;
    let lines = method_one_argument(vm, &args, "writelines")?;
    if !is_sequence(vm, &lines)? {
        return Err(vm.type_error("arg must be a sequence object"));
    }

    let mut index = 0;
    loop {
        let Some(length) = vm.len(&lines)? else {
            return Err(Signal::Halt(Halt::UnknownCondition { context: "writelines length".to_owned(), origin: format!("{lines:?}") }));
        };
        if index >= length {
            break;
        }
        let item = vm.getitem(&lines, &args::index_value(index))?;
        writer_iwrite(vm, writer, &item)?;
        index += 1;
    }

    Ok(Value::None)
}

/// `reset()`: flushes held-back units and returns to the initial state,
/// writing only when that produces bytes.
fn writer_reset(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let writer = this::<StreamWriter>(vm, &args, WRITER_TYPE, "reset")?;
    method_no_arguments(vm, &args, "reset")?;

    // The held-back units go even when encoding them fails.
    let units = std::mem::take(&mut *writer.pending.borrow_mut());
    let errors = errors_of(&writer.errors);
    let (output, _) = encode_with(vm, writer.codec, &writer.state, &units, Some(&errors), true)?;
    if !output.is_empty() {
        vm.call_method(&writer.stream, "write", vec![Value::Str(PyBytes::new(output))])?;
    }

    Ok(Value::None)
}
