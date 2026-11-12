//! Source codecs backed by the interpreter's codec registry, so a coding
//! declaration resolves as `unicode.decode` resolves it, and the default
//! encoding is the one `sys.setdefaultencoding` set.

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::compile::parse_error;
use crate::interp::builtins::modules::codecs::registry;
use crate::interp::builtins::text::codecs::decode_default;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::Parsed;
use crate::interp::compiler::parse_with_codecs;
use crate::interp::compiler::source::BuiltinCodecs;
use crate::interp::compiler::source::CodecError;
use crate::interp::compiler::source::CodecErrorKind;
use crate::interp::compiler::source::EncodeErrors;
use crate::interp::compiler::source::SourceCodecs;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// `SourceCodecs` over a VM. A halt inside a codec is kept and wins over
/// the parse error it causes.
pub struct VmSourceCodecs<'a> {
    vm: &'a Vm,
    halt: Option<Signal>,
}

impl<'a> VmSourceCodecs<'a> {
    pub fn new(vm: &'a Vm) -> Self {
        Self { vm, halt: None }
    }

    /// The halt a codec ran into, which wins over the error it caused.
    pub fn take_halt(&mut self) -> Option<Signal> {
        self.halt.take()
    }

    /// The codec exception as the parser sees it, or a kept halt.
    fn failure(&mut self, signal: Signal) -> CodecError {
        let vm = self.vm;
        let Signal::Raise(exception) = &signal else {
            self.halt = Some(signal);
            return CodecError { kind: CodecErrorKind::Other("halt".to_owned()), message: String::new() };
        };

        let kind = if vm.is_exception(exception, ExceptionKind::UnicodeError) {
            CodecErrorKind::Unicode
        } else if vm.is_exception(exception, ExceptionKind::LookupError) {
            CodecErrorKind::Lookup
        } else {
            CodecErrorKind::Other(vm.class_name(&vm.class_of(exception)))
        };

        match vm.to_str(exception) {
            Ok(text) => {
                let message = vm.as_str_bytes(&text).map(|bytes| bytes.to_string_lossy()).unwrap_or_default();
                CodecError { kind, message }
            }
            Err(signal) => self.failure(signal),
        }
    }

    /// Decoding or encoding through the registry: the first item of the codec
    /// function's `(object, length)` result.
    fn call_codec(&self, encoding: &str, which: usize, argument: Value, errors: Option<&str>) -> PyResult<Value> {
        let vm = self.vm;
        let entry = registry::lookup(vm, encoding.as_bytes())?;
        halt_on_unknown(&entry, "codec lookup")?;
        let Some(function) = vm.as_tuple(&entry).and_then(|items| items.get(which).cloned()) else {
            return Err(vm.type_error("codec search functions must return 4-tuples"));
        };

        let mut arguments = vec![argument];
        if let Some(errors) = errors {
            arguments.push(Value::str(errors));
        }
        let result = vm.call(&function, CallArgs::new(arguments))?;
        halt_on_unknown(&result, "codec result")?;

        match vm.as_tuple(&result) {
            Some(items) if items.len() == 2 => Ok(items[0].clone()),
            _ if which == 0 => Err(vm.type_error("encoder must return a tuple (object,integer)")),
            _ => Err(vm.type_error("decoder must return a tuple (object,integer)")),
        }
    }
}

impl SourceCodecs for VmSourceCodecs<'_> {
    fn decode(&mut self, encoding: &str, input: &[u8]) -> Result<Vec<u16>, CodecError> {
        // These names decode without the registry.
        if matches!(encoding, "utf-8" | "latin-1" | "ascii") {
            return BuiltinCodecs.decode(encoding, input);
        }

        let vm = self.vm;
        let decoded = self.call_codec(encoding, 1, Value::Str(PyBytes::new(input.to_vec())), None).and_then(|value| match vm.as_text(&value) {
            Some(text) => Ok(text.units().to_vec()),
            None => Err(vm.type_error(&format!("decoder did not return an unicode object (type={})", vm.type_name(&value)))),
        });

        decoded.map_err(|signal| self.failure(signal))
    }

    fn encode(&mut self, encoding: &str, input: &[u16], errors: EncodeErrors) -> Result<Vec<u8>, CodecError> {
        // These names encode without the registry when no error handler is
        // named.
        if errors == EncodeErrors::Strict && matches!(encoding, "utf-8" | "latin-1" | "ascii") {
            return BuiltinCodecs.encode(encoding, input, errors);
        }

        let vm = self.vm;
        let errors = match errors {
            EncodeErrors::Strict => None,
            EncodeErrors::Replace => Some("replace"),
        };
        let encoded = self.call_codec(encoding, 0, Value::Unicode(PyText::new(input.to_vec())), errors).and_then(|value| match vm.as_str_bytes(&value) {
            Some(bytes) => Ok(bytes.as_bytes().to_vec()),
            None => Err(vm.type_error(&format!("encoder did not return a string object (type={})", vm.type_name(&value)))),
        });

        encoded.map_err(|signal| self.failure(signal))
    }

    fn decode_default(&mut self, input: &[u8]) -> Result<Vec<u16>, CodecError> {
        decode_default(self.vm, input).map(|text| text.units().to_vec()).map_err(|signal| self.failure(signal))
    }
}

/// Parses source text with the VM's codecs, raising what the reference
/// interpreter raises.
pub fn parse_in_vm(vm: &Vm, source: &[u8], filename: &[u8], mode: Mode, flags: CompilerFlags) -> PyResult<Parsed> {
    let mut codecs = VmSourceCodecs::new(vm);
    let parsed = parse_with_codecs(source, filename, mode, flags, &mut codecs);

    if let Some(halt) = codecs.halt.take() {
        return Err(halt);
    }

    parsed.map_err(|error| parse_error(vm, error))
}
