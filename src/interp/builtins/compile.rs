//! The `compile` builtin and the exceptions a failed parse raises.

use crate::interp::builtins::arguments::long_argument;
use crate::interp::builtins::exec::compile_module;
use crate::interp::builtins::modules::ast::ast_to_object;
use crate::interp::builtins::modules::ast::is_ast_node;
use crate::interp::builtins::modules::ast::object_to_ast;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::unicode::encode_utf8;
use crate::interp::builtins::parse;
use crate::interp::builtins::source_codecs::parse_in_vm;
use crate::interp::code::CodeFlags;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::ParseError;
use crate::interp::compiler::SyntaxError;
use crate::interp::compiler::SyntaxErrorKind;
use crate::interp::compiler::ast;
use crate::interp::compiler::source::CodecErrorKind;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The compiler flag and future feature bits `compile` accepts.
const ACCEPTED_FLAGS: u32 = CompilerFlags::FUTURE_DIVISION
    | CompilerFlags::FUTURE_ABSOLUTE_IMPORT
    | CompilerFlags::FUTURE_WITH_STATEMENT
    | CompilerFlags::FUTURE_PRINT_FUNCTION
    | CompilerFlags::FUTURE_UNICODE_LITERALS
    | CodeFlags::NESTED
    | CompilerFlags::DONT_IMPLY_DEDENT
    | CompilerFlags::ONLY_AST;

/// The future features a code object passes on.
const FUTURE_MASK: u32 = CompilerFlags::FUTURE_DIVISION
    | CompilerFlags::FUTURE_ABSOLUTE_IMPORT
    | CompilerFlags::FUTURE_WITH_STATEMENT
    | CompilerFlags::FUTURE_PRINT_FUNCTION
    | CompilerFlags::FUTURE_UNICODE_LITERALS;

/// What to compile into a code object.
pub enum CompileSource {
    /// Source bytes; UTF-8 with `SOURCE_IS_UTF8` in the flags when they
    /// came from a `unicode`.
    Text(Vec<u8>),
    /// A tree converted from `_ast` nodes.
    Tree(ast::Mod),
}

/// A request to compile a code object, after argument checks.
pub struct CompileRequest {
    pub source: CompileSource,
    pub filename: Vec<u8>,
    pub mode: Mode,
    pub flags: CompilerFlags,
}

/// `compile(source, filename, mode[, flags[, dont_inherit]])`.
pub fn builtin_compile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse(vm, args, "compile", &["source", "filename", "mode", "flags", "dont_inherit"], 3)?;
    let (Some(source), Some(filename), Some(mode)) = (&slots[0], &slots[1], &slots[2]) else {
        return Err(vm.type_error("compile() takes at least 3 arguments"));
    };

    let filename = c_string(vm, "compile", 2, filename)?.as_bytes().to_vec();
    let mode_text = c_string(vm, "compile", 3, mode)?;
    let supplied = match &slots[3] {
        Some(flags) => int_argument(vm, flags)?,
        None => 0,
    };
    let dont_inherit = match &slots[4] {
        Some(value) => int_argument(vm, value)? != 0,
        None => false,
    };

    if supplied as u32 & !ACCEPTED_FLAGS != 0 {
        return Err(vm.raise(ExceptionKind::ValueError, "compile(): unrecognised flags"));
    }
    let mut flags = CompilerFlags(supplied as u32);
    if !dont_inherit {
        flags.0 |= current_future_flags(vm);
    }

    let mode = match mode_text.as_bytes() {
        b"exec" => Mode::Exec,
        b"eval" => Mode::Eval,
        b"single" => Mode::Single,
        _ => return Err(vm.raise(ExceptionKind::ValueError, "compile() arg 3 must be 'exec', 'eval' or 'single'")),
    };

    if is_ast_node(vm, source)? {
        if flags.contains(CompilerFlags::ONLY_AST) {
            return Ok(source.clone());
        }
        let tree = object_to_ast(vm, source, mode)?;
        return compile_code(vm, CompileRequest { source: CompileSource::Tree(tree), filename, mode, flags });
    }

    let text = if let Some(bytes) = vm.as_str_bytes(source) {
        bytes.as_bytes().to_vec()
    } else if let Some(text) = vm.as_text(source) {
        flags.0 |= CompilerFlags::SOURCE_IS_UTF8;
        encode_utf8(text.units())
    } else if let Some(bytes) = vm.as_bytearray(source) {
        bytes.to_vec()
    } else {
        return Err(vm.type_error("expected a readable buffer object"));
    };
    if text.contains(&0) {
        return Err(vm.type_error("compile() expected string without null bytes"));
    }

    if !flags.contains(CompilerFlags::ONLY_AST) {
        return compile_code(vm, CompileRequest { source: CompileSource::Text(text), filename, mode, flags });
    }

    let parsed = parse_in_vm(vm, &text, &filename, mode, flags)?;
    ast_to_object(vm, &parsed.module)
}

/// Compiles a request, source or tree, into a code object.
pub fn compile_code(vm: &Vm, request: CompileRequest) -> PyResult<Value> {
    match request.source {
        CompileSource::Text(text) => {
            let parsed = parse_in_vm(vm, &text, &request.filename, request.mode, request.flags)?;
            compile_module(vm, &parsed.module, &request.filename, parsed.flags)
        }
        CompileSource::Tree(tree) => compile_module(vm, &tree, &request.filename, request.flags),
    }
}

/// The exception a failed parse raises.
pub fn parse_error(vm: &Vm, error: ParseError) -> Signal {
    match error {
        ParseError::Syntax(error) => syntax_error(vm, error),
        ParseError::Value { message } => vm.raise(ExceptionKind::ValueError, &message),
        ParseError::Memory => {
            let class = std::rc::Rc::clone(vm.types().exception(ExceptionKind::MemoryError));
            match vm.instantiate_exception(&class, Vec::new()) {
                Ok(exception) => Signal::Raise(exception),
                Err(signal) => signal,
            }
        }
        ParseError::Codec(error) => {
            let kind = match &error.kind {
                CodecErrorKind::Unicode => ExceptionKind::UnicodeError,
                CodecErrorKind::Lookup => ExceptionKind::LookupError,
                CodecErrorKind::Other(name) => match name.as_str() {
                    "ValueError" => ExceptionKind::ValueError,
                    "AssertionError" => ExceptionKind::AssertionError,
                    _ => ExceptionKind::TypeError,
                },
            };
            vm.raise(kind, &error.message)
        }
        ParseError::System { message } => vm.raise(ExceptionKind::SystemError, &message),
        ParseError::Unsupported { feature } => vm.halt_unsupported(feature),
    }
}

/// The `SyntaxError` subclass for `kind`.
pub fn syntax_error_class(kind: SyntaxErrorKind) -> ExceptionKind {
    match kind {
        SyntaxErrorKind::SyntaxError => ExceptionKind::SyntaxError,
        SyntaxErrorKind::IndentationError => ExceptionKind::IndentationError,
        SyntaxErrorKind::TabError => ExceptionKind::TabError,
    }
}

/// `SyntaxError(msg, (filename, lineno, offset, text))`.
pub fn syntax_error(vm: &Vm, error: SyntaxError) -> Signal {
    let kind = syntax_error_class(error.kind);
    let offset = error.offset.map_or(Value::None, |offset| Value::Int(i64::from(offset)));
    let text = error.text.map_or(Value::None, |text| Value::Str(PyBytes::new(text)));
    let location = Value::tuple(vec![Value::Str(PyBytes::new(error.filename)), Value::Int(i64::from(error.lineno)), offset, text]);

    let class = std::rc::Rc::clone(vm.types().exception(kind));
    match vm.instantiate_exception(&class, vec![Value::str(&error.message), location]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// Merges in the future features of the calling frame.
pub fn current_future_flags(vm: &Vm) -> u32 {
    let Some(code_object) = vm.current_code_object() else {
        return 0;
    };
    let Payload::Code(code) = &code_object.payload else {
        return 0;
    };

    code.flags.0 & FUTURE_MASK
}

/// The `i` argument format: a C `int`.
fn int_argument(vm: &Vm, value: &Value) -> PyResult<i32> {
    let number = long_argument(vm, value)?;
    if number > i64::from(i32::MAX) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is greater than maximum"));
    }
    if number < i64::from(i32::MIN) {
        return Err(vm.raise(ExceptionKind::OverflowError, "signed integer is less than minimum"));
    }

    Ok(number as i32)
}
