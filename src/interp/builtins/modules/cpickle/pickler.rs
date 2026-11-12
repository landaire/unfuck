//! The `Pickler` type, its output destinations, and the `dump` and
//! `dumps` functions.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use num_traits::ToPrimitive;

use super::HIGHEST_PROTOCOL;
use super::ModuleState;
use super::module_state;
use super::opcodes::Op;
use super::Stop;
use super::save::SaveResult;
use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_getset;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::cstringio::StringIo;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::method_arguments;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse_with;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub(super) const PICKLER_TYPE: &str = "cPickle.Pickler";

/// How many bytes a pickler writing to a Python object collects before it
/// calls `write`.
const WRITE_CHUNK: usize = 256;

/// A pickle protocol number, 0 through `HIGHEST_PROTOCOL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Protocol(u8);

impl Protocol {
    pub(super) const TEXT: Self = Self(0);
    pub(super) const BATCHED: Self = Self(1);
    pub(super) const OBJECTS: Self = Self(2);

    /// The protocol a caller asked for: negative numbers select the
    /// highest one.
    fn parse(vm: &Vm, requested: i32) -> PyResult<Self> {
        if requested < 0 {
            return Ok(Self::OBJECTS);
        }
        let Some(protocol) = u8::try_from(requested).ok().filter(|protocol| i64::from(*protocol) <= HIGHEST_PROTOCOL) else {
            return Err(vm.raise(ExceptionKind::ValueError, &format!("pickle protocol {requested} asked for; the highest available protocol is {HIGHEST_PROTOCOL}")));
        };

        Ok(Self(protocol))
    }

    pub(super) fn number(self) -> u8 {
        self.0
    }
}

/// The index a memo entry records, which PUT and GET opcodes carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MemoIndex(pub(super) i64);

/// A part of the output of a pickler without a file: bytes, or a memo
/// reference whose encoding `getvalue` decides.
enum Piece {
    Bytes(Vec<u8>),
    /// The data of a long string, kept by reference: the string counts
    /// as referenced while the output holds it.
    Shared(PyBytes),
    Put(MemoIndex),
    Get(MemoIndex),
}

/// Where a pickler's bytes go.
enum Output {
    /// `dumps`: the bytes become the result.
    Bytes(RefCell<Vec<u8>>),
    /// `Pickler([protocol])`: kept until `getvalue`.
    Pieces(RefCell<Vec<Piece>>),
    /// A `cStringIO` output stream, written directly.
    Stream(Value),
    /// An object with a `write` method, called with chunks of at least
    /// `WRITE_CHUNK` bytes or with what remains at the end of a dump.
    Writer { write: Value, pending: RefCell<Vec<u8>> },
    /// A real file: the bytes leave the interpreter.
    HostFile,
    /// `None` as the file: the bytes are dropped.
    Discard,
}

impl Output {
    /// The destination for `file`. Unknown files have none.
    fn for_file(vm: &Vm, file: &Value) -> PyResult<Option<Self>> {
        if file.is_unknown() {
            return Ok(None);
        }
        if file.is_none() {
            return Ok(Some(Self::Discard));
        }
        if vm.is_instance_of(file, &vm.types().file)? {
            return Ok(Some(Self::HostFile));
        }
        if native_data::<StringIo>(file).is_some_and(|stream| stream.output) {
            return Ok(Some(Self::Stream(file.clone())));
        }

        match vm.getattr_opt(file, &PyBytes::from("write")) {
            Ok(Some(write)) => Ok(Some(Self::Writer { write, pending: RefCell::new(Vec::new()) })),
            Ok(None) | Err(Signal::Raise(_)) => Err(vm.type_error("argument must have 'write' attribute")),
            Err(halt) => Err(halt),
        }
    }

    /// Whether the bytes are lost to the interpreter anyway, so that an
    /// unknown value in them changes nothing it can observe.
    fn is_unobserved(&self) -> bool {
        matches!(self, Self::HostFile | Self::Discard)
    }
}

/// A `cPickle.Pickler`, and the state of a `dump` or `dumps` call.
pub(super) struct Pickler {
    pub(super) state: Rc<ModuleState>,
    pub(super) protocol: Protocol,
    binary: Cell<i32>,
    pub(super) fast: Cell<i32>,
    memo: RefCell<ObjectRef>,
    pub(super) persistent_id: RefCell<Option<Value>>,
    pub(super) inst_persistent_id: RefCell<Option<Value>>,
    output: Output,

    /// The argument of the last one-argument call the pickler made. It
    /// stays referenced until the next such call, which the reference
    /// counts that decide memoization observe.
    held_argument: RefCell<Option<Value>>,
    /// Lists, dicts, and instances being saved in fast mode.
    pub(super) fast_nesting: Cell<usize>,
    /// Addresses of the containers being saved once fast mode nesting is
    /// deep enough to look for cycles.
    pub(super) fast_open: RefCell<HashSet<u64>>,
}

impl_native_data!(Pickler, "cPickle.Pickler");

impl Pickler {
    fn new(vm: &Vm, state: Rc<ModuleState>, protocol: Protocol, output: Output) -> Self {
        Self {
            state,
            protocol,
            binary: Cell::new(i32::from(protocol > Protocol::TEXT)),
            fast: Cell::new(0),
            memo: RefCell::new(vm.new_dict()),
            persistent_id: RefCell::new(None),
            inst_persistent_id: RefCell::new(None),
            output,
            held_argument: RefCell::new(None),
            fast_nesting: Cell::new(0),
            fast_open: RefCell::new(HashSet::new()),
        }
    }

    /// Whether opcodes take their binary forms.
    pub(super) fn is_binary(&self) -> bool {
        self.binary.get() != 0
    }

    pub(super) fn memo(&self) -> ObjectRef {
        Rc::clone(&self.memo.borrow())
    }

    /// One complete pickle of `value`: the protocol header, the object,
    /// STOP, and a flush of buffered output.
    fn dump(&self, vm: &Vm, value: &Value) -> SaveResult<()> {
        if self.protocol >= Protocol::OBJECTS {
            self.write(vm, &[Op::Proto.byte(), self.protocol.number()])?;
        }
        self.save(vm, value, 0)?;
        self.write(vm, &[Op::Stop.byte()])?;
        self.flush(vm)?;

        Ok(())
    }

    /// Calls `callable` with the single argument `argument`, which stays
    /// referenced afterwards as the argument of the last such call.
    pub(super) fn call_holding(&self, vm: &Vm, callable: &Value, argument: &Value) -> PyResult<Value> {
        drop(self.held_argument.borrow_mut().take());
        let result = vm.call(callable, CallArgs::new(vec![argument.clone()]));
        *self.held_argument.borrow_mut() = Some(argument.clone());

        result
    }

    pub(super) fn write(&self, vm: &Vm, data: &[u8]) -> PyResult<()> {
        match &self.output {
            Output::Bytes(bytes) => bytes.borrow_mut().extend_from_slice(data),
            Output::Pieces(pieces) => append_bytes(&mut pieces.borrow_mut(), data),
            Output::Stream(stream) => {
                let Some(stream) = native_data::<StringIo>(stream) else {
                    return Err(vm.type_error("cPickle output is not a cStringIO stream"));
                };
                stream.write(vm, data)?;
            }
            Output::Writer { write, pending } => {
                let buffered = pending.borrow().len();
                if buffered + data.len() <= WRITE_CHUNK {
                    pending.borrow_mut().extend_from_slice(data);
                    return Ok(());
                }

                self.flush(vm)?;
                if data.len() > WRITE_CHUNK {
                    self.call_holding(vm, write, &Value::Str(PyBytes::new(data)))?;
                } else {
                    pending.borrow_mut().extend_from_slice(data);
                }
            }
            Output::HostFile => vm.host_permit(HostCapability::FileSystem, Denial::Crt, None)?,
            Output::Discard => {}
        }

        Ok(())
    }

    /// Passes buffered bytes to a Python `write` method.
    fn flush(&self, vm: &Vm) -> PyResult<()> {
        let Output::Writer { write, pending } = &self.output else {
            return Ok(());
        };
        let chunk = std::mem::take(&mut *pending.borrow_mut());
        if chunk.is_empty() {
            return Ok(());
        }

        self.call_holding(vm, write, &Value::Str(PyBytes::new(chunk)))?;

        Ok(())
    }

    /// The data of a string. A pickler without a file keeps a binary
    /// string longer than 128 bytes by reference.
    pub(super) fn write_string_data(&self, vm: &Vm, string: &PyBytes) -> PyResult<()> {
        const SHARED_LENGTH: usize = 128;

        if let Output::Pieces(pieces) = &self.output {
            if self.is_binary() && string.as_bytes().len() > SHARED_LENGTH {
                pieces.borrow_mut().push(Piece::Shared(string.clone()));
                return Ok(());
            }
        }

        self.write(vm, string.as_bytes())
    }

    /// Writes a PUT of `index`. A pickler without a file records the
    /// reference so that `getvalue` can drop PUTs nothing reads.
    pub(super) fn write_put(&self, vm: &Vm, index: MemoIndex) -> PyResult<()> {
        if !self.is_binary() {
            return self.write(vm, format!("p{}\n", index.0).as_bytes());
        }
        if let Output::Pieces(pieces) = &self.output {
            pieces.borrow_mut().push(Piece::Put(index));
            return Ok(());
        }

        self.write(vm, &memo_opcode(index, Op::BinPut, Op::LongBinPut))
    }

    pub(super) fn write_get(&self, vm: &Vm, index: MemoIndex) -> PyResult<()> {
        if !self.is_binary() {
            return self.write(vm, format!("g{}\n", index.0).as_bytes());
        }
        if let Output::Pieces(pieces) = &self.output {
            pieces.borrow_mut().push(Piece::Get(index));
            return Ok(());
        }

        self.write(vm, &memo_opcode(index, Op::BinGet, Op::LongBinGet))
    }

    /// The output of a pickler without a file, with a PUT only where a GET
    /// reads it; `clear` empties the output afterwards.
    fn collected_output(&self, vm: &Vm, clear: bool) -> PyResult<Vec<u8>> {
        let Output::Pieces(pieces) = &self.output else {
            return Err(vm.raise_string(&self.state.pickling_error, Value::str("Attempt to getvalue() a non-list-based pickler")));
        };
        let entries = vm.dict_len(&self.memo())?;

        let output = {
            let pieces = pieces.borrow();
            let mut read = HashSet::new();
            for piece in pieces.iter() {
                let (Piece::Put(index) | Piece::Get(index)) = piece else {
                    continue;
                };
                let in_range = usize::try_from(index.0).is_ok_and(|position| (1..=entries).contains(&position));
                if !in_range {
                    return Err(vm.raise_string(&self.state.pickling_error, Value::str("Invalid get data")));
                }
                if let Piece::Get(index) = piece {
                    read.insert(index.0);
                }
            }

            let mut output = Vec::new();
            for piece in pieces.iter() {
                match piece {
                    Piece::Bytes(bytes) => output.extend_from_slice(bytes),
                    Piece::Shared(string) => output.extend_from_slice(string.as_bytes()),
                    Piece::Put(index) if read.contains(&index.0) => output.extend_from_slice(&memo_opcode(*index, Op::BinPut, Op::LongBinPut)),
                    // No GET reads this entry.
                    Piece::Put(_) => {}
                    Piece::Get(index) => output.extend_from_slice(&memo_opcode(*index, Op::BinGet, Op::LongBinGet)),
                }
            }
            output
        };

        if clear {
            pieces.borrow_mut().clear();
        }

        Ok(output)
    }
}

/// A one-byte or four-byte memo opcode for `index`. Indices below 256,
/// negative ones included, take the short form with the low byte.
fn memo_opcode(index: MemoIndex, short: Op, long: Op) -> Vec<u8> {
    if index.0 < 256 {
        return vec![short.byte(), index.0 as u8];
    }

    let mut bytes = vec![long.byte()];
    bytes.extend_from_slice(&(index.0 as i32).to_le_bytes());
    bytes
}

fn append_bytes(pieces: &mut Vec<Piece>, data: &[u8]) {
    if let Some(Piece::Bytes(bytes)) = pieces.last_mut() {
        bytes.extend_from_slice(data);
        return;
    }

    pieces.push(Piece::Bytes(data.to_vec()));
}

/// The value standing for a pickle that contains an unknown value, or the
/// halt when the destination already received part of it.
fn unknown_output(vm: &Vm, output: &Output, origin: &str, function: &str) -> PyResult<Value> {
    let text = format!("{function} of a value containing {origin}");
    if matches!(output, Output::HostFile) {
        vm.host_permit(HostCapability::FileSystem, Denial::Crt, None)?;
    }
    if matches!(output, Output::Bytes(_)) || output.is_unobserved() {
        return Ok(Value::unknown(text));
    }

    Err(vm.halt_unsupported(text))
}

/// The `i` conversion of a protocol argument; `None` when it is unknown.
fn protocol_number(vm: &Vm, value: Option<&Value>) -> PyResult<Option<i32>> {
    match value {
        None => Ok(Some(0)),
        Some(value) if value.is_unknown() => Ok(None),
        Some(value) => int_argument(vm, value).map(Some),
    }
}

/// `dumps(obj, protocol=0)`.
pub(super) fn module_dumps(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut slots = parse_with(vm, args, "dumps", &["obj", "protocol"], 1, |_, _, value| Ok(value))?.into_iter();
    let Some(object) = slots.next().flatten() else {
        return Err(vm.type_error("dumps() requires an object"));
    };
    let Some(requested) = protocol_number(vm, slots.next().flatten().as_ref())? else {
        return Ok(Value::unknown("cPickle.dumps with an unknown protocol"));
    };

    let protocol = Protocol::parse(vm, requested)?;
    let pickler = Pickler::new(vm, module_state(vm)?, protocol, Output::Bytes(RefCell::new(Vec::new())));
    match pickler.dump(vm, &object) {
        Ok(()) => {}
        Err(Stop::Signal(signal)) => return Err(signal),
        Err(Stop::Unknown { origin }) => return unknown_output(vm, &pickler.output, &origin, "cPickle.dumps"),
    }
    let Output::Bytes(bytes) = pickler.output else {
        return Err(vm.type_error("cPickle.dumps lost its output"));
    };

    Ok(Value::Str(PyBytes::new(bytes.into_inner())))
}

/// `dump(obj, file, protocol=0)`.
pub(super) fn module_dump(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut slots = parse_with(vm, args, "dump", &["obj", "file", "protocol"], 2, |_, _, value| Ok(value))?.into_iter();
    let (Some(object), Some(file)) = (slots.next().flatten(), slots.next().flatten()) else {
        return Err(vm.type_error("dump() requires an object and a file"));
    };
    let Some(requested) = protocol_number(vm, slots.next().flatten().as_ref())? else {
        return Ok(Value::unknown("cPickle.dump with an unknown protocol"));
    };

    let protocol = Protocol::parse(vm, requested)?;
    let Some(output) = Output::for_file(vm, &file)? else {
        return Ok(Value::unknown("cPickle.dump to an unknown file"));
    };
    let pickler = Pickler::new(vm, module_state(vm)?, protocol, output);
    match pickler.dump(vm, &object) {
        Ok(()) if matches!(pickler.output, Output::HostFile) => Ok(Value::unknown("cPickle.dump to a host file")),
        Ok(()) => Ok(Value::None),
        Err(Stop::Signal(signal)) => Err(signal),
        Err(Stop::Unknown { origin }) => unknown_output(vm, &pickler.output, &origin, "cPickle.dump"),
    }
}

/// `Pickler([protocol])` for output kept until `getvalue`, or
/// `Pickler(file, protocol=0)`.
pub(super) fn new_pickler(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let collected = match args.positional.as_slice() {
        [] => Some(0),
        [Value::Unknown(_)] => return Ok(Value::unknown("cPickle.Pickler with an unknown argument")),
        // A failed conversion selects the form with a file.
        [only] => match int_argument(vm, only) {
            Ok(protocol) => Some(protocol),
            Err(Signal::Raise(_)) => None,
            Err(halt) => return Err(halt),
        },
        _ => None,
    };

    let (protocol, output) = match collected {
        Some(requested) => (Protocol::parse(vm, requested)?, Some(Output::Pieces(RefCell::new(Vec::new())))),
        None => {
            let mut slots = parse_with(vm, args, "Pickler", &["file", "protocol"], 1, |_, _, value| Ok(value))?.into_iter();
            let Some(file) = slots.next().flatten() else {
                return Err(vm.type_error("Pickler() requires a file"));
            };
            let Some(requested) = protocol_number(vm, slots.next().flatten().as_ref())? else {
                return Ok(Value::unknown("cPickle.Pickler with an unknown protocol"));
            };
            (Protocol::parse(vm, requested)?, Output::for_file(vm, &file)?)
        }
    };

    let Some(output) = output else {
        return Ok(Value::unknown("cPickle.Pickler on an unknown file"));
    };
    let class = native_type(vm, PICKLER_TYPE, create_pickler_type)?;
    let pickler = Pickler::new(vm, module_state(vm)?, protocol, output);

    Ok(new_native_object(vm, &class, pickler))
}

fn create_pickler_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[method("dump", pickler_dump), method("clear_memo", pickler_clear_memo), method("getvalue", pickler_getvalue)];

    let class = new_type(vm, TypeSpec { name: "Pickler", module: "cPickle", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    add_member(vm, &class, GetSet { name: "binary", owner: PICKLER_TYPE, get: get_binary, set: Some(set_binary) })?;
    add_member(vm, &class, GetSet { name: "fast", owner: PICKLER_TYPE, get: get_fast, set: Some(set_fast) })?;
    add_getset(vm, &class, GetSet { name: "persistent_id", owner: PICKLER_TYPE, get: get_persistent_id, set: Some(set_persistent_id) })?;
    add_getset(vm, &class, GetSet { name: "inst_persistent_id", owner: PICKLER_TYPE, get: get_inst_persistent_id, set: Some(set_inst_persistent_id) })?;
    add_getset(vm, &class, GetSet { name: "memo", owner: PICKLER_TYPE, get: get_memo, set: Some(set_memo) })?;
    add_getset(vm, &class, GetSet { name: "PicklingError", owner: PICKLER_TYPE, get: get_pickling_error, set: None })?;

    Ok(class)
}

/// `Pickler.dump(obj[, get])`: returns the pickler, or with a true `get`
/// the collected output.
fn pickler_dump(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    if args.has_keywords() {
        return Err(vm.type_error("dump() takes no keyword arguments"));
    }
    let given = args.positional.len().saturating_sub(1);
    if given == 0 {
        return Err(vm.type_error("dump() takes at least 1 argument (0 given)"));
    }
    if given > 2 {
        return Err(vm.type_error(&format!("dump() takes at most 2 arguments ({given} given)")));
    }

    // The object is taken out of the arguments so that this call holds
    // one reference to it, as an argument tuple would.
    let mut positional = args.positional.into_iter();
    let (Some(receiver), Some(object)) = (positional.next(), positional.next()) else {
        return Err(vm.type_error("dump() takes at least 1 argument (0 given)"));
    };
    let get = match positional.next() {
        Some(flag) if flag.is_unknown() => return Ok(Value::unknown("cPickle.Pickler.dump with an unknown flag")),
        Some(flag) => int_argument(vm, &flag)? != 0,
        None => false,
    };
    let Some(pickler) = native_data::<Pickler>(&receiver) else {
        return Err(vm.type_error(&format!("descriptor 'dump' requires a '{PICKLER_TYPE}' object but received a '{}'", vm.type_name(&receiver))));
    };

    match pickler.dump(vm, &object) {
        Ok(()) => {}
        Err(Stop::Signal(signal)) => return Err(signal),
        Err(Stop::Unknown { origin }) => return unknown_output(vm, &pickler.output, &origin, "cPickle.Pickler.dump"),
    }
    drop(object);

    if get {
        return Ok(Value::Str(PyBytes::new(pickler.collected_output(vm, true)?)));
    }

    Ok(receiver)
}

fn pickler_clear_memo(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let pickler = this::<Pickler>(vm, &args, PICKLER_TYPE, "clear_memo")?;
    method_no_arguments(vm, &args, "clear_memo")?;

    let memo = pickler.memo();
    let entries = vm.dict_cell(&memo)?;
    entries.try_borrow_mut().map_err(|_| vm.raise(ExceptionKind::RuntimeError, "dictionary changed size during lookup"))?.clear();

    Ok(Value::None)
}

/// `getvalue([clear])`.
fn pickler_getvalue(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let pickler = this::<Pickler>(vm, &args, PICKLER_TYPE, "getvalue")?;
    let rest = method_arguments(vm, &args, "getvalue", 0, 1)?;
    let clear = match rest.first() {
        Some(flag) if flag.is_unknown() => return Ok(Value::unknown("cPickle.Pickler.getvalue with an unknown flag")),
        Some(flag) => int_argument(vm, flag)? != 0,
        None => true,
    };

    Ok(Value::Str(PyBytes::new(pickler.collected_output(vm, clear)?)))
}

/// The pickler a descriptor of `getset` applies to.
fn descriptor_pickler<'a>(vm: &Vm, getset: &GetSet, instance: &'a Value) -> PyResult<&'a Pickler> {
    native_data::<Pickler>(instance).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

/// An integer assigned to a member: an `int` or `long` directly, another
/// object through its `__int__`, a float truncated; the low 32 bits are
/// kept.
fn member_int(vm: &Vm, value: Option<Value>) -> PyResult<i32> {
    let Some(value) = value else {
        return Err(vm.type_error("can't delete numeric/char attribute"));
    };
    if value.is_unknown() {
        return Err(vm.halt_unsupported("unknown value assigned to a cPickle.Pickler member"));
    }

    let direct = is_direct_integer(vm, &value)?;
    let integral = if let Some(integral) = vm.as_integral(&value).filter(|_| direct) {
        integral
    } else if let Some(method) = vm.user_override(&value, "__int__")? {
        integer_result(vm, vm.call0(&method)?)?
    } else if let Some(integral) = vm.as_integral(&value) {
        integral
    } else if let Some(number) = vm.as_float(&value) {
        if number.is_nan() {
            return Err(vm.raise(ExceptionKind::ValueError, "cannot convert float NaN to integer"));
        }
        if number.is_infinite() {
            return Err(vm.raise(ExceptionKind::OverflowError, "cannot convert float infinity to integer"));
        }
        match number.trunc().to_i64() {
            Some(number) => Integral::Int(number),
            None => return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
        }
    } else {
        return Err(vm.type_error("an integer is required"));
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };
    match number {
        Some(number) if numbers::fits_int(vm.config.long_width, number) => Ok(number as i32),
        _ => Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long")),
    }
}

/// Whether `value` converts from its stored number without consulting
/// `__int__`: an `int` (subclasses and `bool` included) or an exact
/// `long`.
fn is_direct_integer(vm: &Vm, value: &Value) -> PyResult<bool> {
    let class = vm.type_of(value);
    let types = vm.types();
    if Rc::ptr_eq(&class, &types.long) {
        return Ok(true);
    }

    vm.is_subclass(&class, &types.int)
}

/// The integer an `__int__` method returned.
fn integer_result(vm: &Vm, result: Value) -> PyResult<Integral> {
    if result.is_unknown() {
        return Err(vm.halt_unsupported("unknown __int__ result in a cPickle integer argument"));
    }

    vm.as_integral(&result).ok_or_else(|| vm.type_error("__int__ method should return an integer"))
}

/// An integer argument in the C `int` range: an integer, or the result of
/// `__int__`, which a `long` subclass may override. Floats are refused.
fn int_argument(vm: &Vm, value: &Value) -> PyResult<i32> {
    if vm.as_float(value).is_some() || is_direct_integer(vm, value)? {
        return args::c_int(vm, value);
    }
    let Some(method) = vm.user_override(value, "__int__")? else {
        if vm.as_integral(value).is_some() {
            return args::c_int(vm, value);
        }
        return Err(vm.type_error("an integer is required"));
    };

    let result = integer_result(vm, vm.call0(&method)?)?;
    let number = match result {
        Integral::Int(number) => Value::Int(number),
        Integral::Long(number) => Value::long(number),
    };

    args::c_int(vm, &number)
}

fn get_binary(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let pickler = descriptor_pickler(vm, getset, instance)?;

    Ok(Value::Int(i64::from(pickler.binary.get())))
}

fn set_binary(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    pickler.binary.set(member_int(vm, value)?);

    Ok(())
}

fn get_fast(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let pickler = descriptor_pickler(vm, getset, instance)?;

    Ok(Value::Int(i64::from(pickler.fast.get())))
}

fn set_fast(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    pickler.fast.set(member_int(vm, value)?);

    Ok(())
}

fn get_persistent_id(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    let hook = pickler.persistent_id.borrow().clone();

    hook.ok_or_else(|| vm.raise(ExceptionKind::AttributeError, "persistent_id"))
}

fn set_persistent_id(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("attribute deletion is not supported"));
    };
    let previous = pickler.persistent_id.borrow_mut().replace(value);
    drop(previous);

    Ok(())
}

fn get_inst_persistent_id(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    descriptor_pickler(vm, getset, instance)?;

    Err(vm.raise(ExceptionKind::AttributeError, &format!("attribute 'inst_persistent_id' of '{PICKLER_TYPE}' objects is not readable")))
}

fn set_inst_persistent_id(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("attribute deletion is not supported"));
    };
    let previous = pickler.inst_persistent_id.borrow_mut().replace(value);
    drop(previous);

    Ok(())
}

fn get_memo(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let pickler = descriptor_pickler(vm, getset, instance)?;

    Ok(Value::Object(pickler.memo()))
}

fn set_memo(vm: &Vm, getset: &GetSet, instance: &Value, value: Option<Value>) -> PyResult<()> {
    let pickler = descriptor_pickler(vm, getset, instance)?;
    let Some(value) = value else {
        return Err(vm.type_error("attribute deletion is not supported"));
    };
    let Some(memo) = value.as_object().filter(|object| object.as_dict().is_some()) else {
        return Err(vm.type_error("memo must be a dictionary"));
    };
    let previous = std::mem::replace(&mut *pickler.memo.borrow_mut(), Rc::clone(memo));
    drop(previous);

    Ok(())
}

fn get_pickling_error(vm: &Vm, getset: &GetSet, instance: &Value) -> PyResult<Value> {
    let pickler = descriptor_pickler(vm, getset, instance)?;

    Ok(Value::Object(Rc::clone(&pickler.state.pickling_error)))
}
