//! Running code produced at runtime: the `exec` statement, `eval`,
//! `execfile`, and `locals`, and the source compiler entry points.

use std::rc::Rc;

use crate::interp::builtins::arguments::no_arguments;
use crate::interp::builtins::arguments::unpack;
use crate::interp::builtins::compile::CompileRequest;
use crate::interp::builtins::compile::CompileSource;
use crate::interp::builtins::compile::compile_code;
use crate::interp::builtins::compile::current_future_flags;
use crate::interp::builtins::compile::syntax_error;
use crate::interp::builtins::compile::syntax_error_class;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::unicode::encode_utf8;
use crate::interp::builtins::modules::operator::is_mapping;
use crate::interp::builtins::modules::warnings::warn_caller;
use crate::interp::builtins::modules::warnings::warn_explicit_at;
use crate::interp::builtins::positional;
use crate::interp::code::CodeFlags;
use crate::interp::code::CodeObject;
use crate::interp::compiler::CompileContext;
use crate::interp::compiler::CompileError;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::SyntaxError;
use crate::interp::compiler::ast;
use crate::interp::compiler::context::CompileWarning;
use crate::interp::compiler::context::WarningCategory;
use crate::interp::compiler::context::WarningRaised;
use crate::interp::compiler::unit::CodeUnit;
use crate::interp::compiler::unit::Constant;
use crate::interp::complex::Complex;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::frame::Frame;
use crate::interp::hash::LongWidth;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The host interpreter state a compilation reads, and the exception a
/// warning raised during it.
pub struct VmCompileContext<'vm> {
    vm: &'vm Vm,
    raised: Option<Signal>,
}

impl<'vm> VmCompileContext<'vm> {
    pub fn new(vm: &'vm Vm) -> Self {
        Self { vm, raised: None }
    }

    /// The Python exception for a failed compilation.
    pub fn into_signal(self, error: CompileError) -> Signal {
        let vm = self.vm;

        match error {
            CompileError::Syntax(error) => syntax_error(vm, error),
            CompileError::SyntaxLocated(error) => located_syntax_error(vm, &error),
            CompileError::SyntaxUnlocated { message } => vm.raise(ExceptionKind::SyntaxError, &message),
            CompileError::System { message } => vm.raise(ExceptionKind::SystemError, &message),
            CompileError::WarningRaised => match self.raised {
                Some(signal) => signal,
                None => vm.raise(ExceptionKind::SystemError, "error return without exception set"),
            },
        }
    }
}

impl CompileContext for VmCompileContext<'_> {
    fn long_width(&self) -> LongWidth {
        self.vm.config.long_width
    }

    fn warn(&mut self, warning: &CompileWarning) -> Result<(), WarningRaised> {
        let vm = self.vm;
        let category = match warning.category {
            WarningCategory::SyntaxWarning => ExceptionKind::SyntaxWarning,
            WarningCategory::DeprecationWarning => ExceptionKind::DeprecationWarning,
        };

        let result = match &warning.location {
            Some(location) => warn_explicit_at(vm, category, &warning.message, &location.filename, location.lineno),
            None => warn_caller(vm, category, &warning.message),
        };
        let Err(signal) = result else {
            return Ok(());
        };

        let is_syntax_warning = match &signal {
            Signal::Raise(exception) => vm.is_exception(exception, ExceptionKind::SyntaxWarning),
            Signal::Halt(_) => false,
        };
        self.raised = Some(signal);

        Err(WarningRaised { is_syntax_warning })
    }

    fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>> {
        self.vm.decode_default(&PyBytes::new(bytes)).map(|text| text.units().to_vec())
    }
}

/// What the `exec` statement or `eval` runs.
enum Program {
    Code(ObjectRef),
    Source { bytes: PyBytes, flags: CompilerFlags },
    /// A file object or an unknown value: its contents depend on the host.
    Host,
}

/// The `exec` statement, run by `frame`.
pub fn exec_statement(vm: &Vm, frame: &Frame, program: Value, globals: Value, locals: Value) -> PyResult<()> {
    let (program, globals, locals) = match vm.as_tuple(&program) {
        Some(items) if globals.is_none() && locals.is_none() && matches!(items.len(), 2 | 3) => (items[0].clone(), items[1].clone(), items.get(2).cloned().unwrap_or(Value::None)),
        _ => (program, globals, locals),
    };

    let plain = globals.is_none() && locals.is_none();
    let (globals, locals) = match (globals, locals) {
        (Value::None, Value::None) => (Value::Object(Rc::clone(&frame.globals)), Value::Object(frame.scope.fast_to_locals(vm)?)),
        (Value::None, locals) => (Value::Object(Rc::clone(&frame.globals)), locals),
        (globals, Value::None) => (globals.clone(), globals),
        pair => pair,
    };

    let Some(program) = classify_program(vm, &program)? else {
        return Err(vm.type_error("exec: arg 1 must be a string, file, or code object"));
    };
    let Some(globals) = dict_argument(&globals, "exec globals")? else {
        return Err(vm.type_error("exec: arg 2 must be a dictionary or None"));
    };
    let Some(locals) = mapping_argument(vm, &locals, "exec locals")? else {
        return Err(vm.type_error("exec: arg 3 must be a mapping or None"));
    };

    if vm.dict_get_str(&globals, "__builtins__")?.is_none() {
        vm.dict_set_str(&globals, "__builtins__", Value::Object(Rc::clone(&frame.builtins)))?;
    }

    let result = match program {
        Program::Code(code) => {
            if has_free_variables(&code) {
                return Err(vm.type_error("code object passed to exec may not contain free variables"));
            }
            vm.eval_code(&code, &globals, &locals).map(drop)
        }
        Program::Source { bytes, flags } => run_string(vm, &bytes, Mode::Exec, flags, &globals, &locals).map(drop),
        Program::Host => {
            mark_host_namespaces(vm, &globals, &locals);
            Ok(())
        }
    };

    if plain {
        frame.scope.locals_to_fast(vm)?;
    }

    result
}

/// `eval(source, globals=None, locals=None)`.
pub fn builtin_eval(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut args = unpack(vm, args, "eval", 1, 3)?.into_iter();
    let Some(command) = args.next() else {
        return Err(vm.type_error("eval expected at least 1 arguments, got 0"));
    };
    let globals = args.next().unwrap_or(Value::None);
    let locals = args.next().unwrap_or(Value::None);

    let (globals, locals) = namespace_arguments(vm, globals, locals)?;
    let (Some(globals), Some(locals)) = (globals, locals) else {
        return Err(vm.type_error("eval must be given globals and locals when called without a frame"));
    };

    if vm.dict_get_str(&globals, "__builtins__")?.is_none() {
        vm.dict_set_str(&globals, "__builtins__", Value::Object(vm.current_builtins()))?;
    }

    match classify_program(vm, &command)? {
        Some(Program::Code(code)) => {
            if has_free_variables(&code) {
                return Err(vm.type_error("code object passed to eval() may not contain free variables"));
            }
            vm.eval_code(&code, &globals, &locals)
        }
        Some(Program::Source { bytes, flags }) => {
            let source = bytes.as_bytes();
            let start = source.iter().position(|byte| *byte != b' ' && *byte != b'\t').unwrap_or(source.len());
            let stripped = PyBytes::new(&source[start..]);
            run_string(vm, &stripped, Mode::Eval, flags, &globals, &locals)
        }
        Some(Program::Host) if command.is_unknown() => Ok(Value::unknown(format!("eval({command:?})"))),
        Some(Program::Host) | None => Err(vm.type_error("eval() arg 1 must be a string or code object")),
    }
}

/// `execfile(filename, globals=None, locals=None)`. The file comes from
/// the host file system, so after the arguments are checked the namespaces
/// read as opaque and the result is unknown.
pub fn builtin_execfile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut args = positional(vm, args, "execfile", 1, 3)?.into_iter();
    let Some(filename) = args.next() else {
        return Err(vm.type_error("execfile() takes at least 1 argument (0 given)"));
    };
    if !filename.is_unknown() {
        c_string(vm, "execfile", 1, &filename)?;
    }

    let globals = match args.next() {
        Some(globals) => match dict_argument(&globals, "execfile globals")? {
            Some(dict) => Value::Object(dict),
            None => {
                let shown = if globals.is_none() { "None".to_owned() } else { vm.type_name(&globals) };
                return Err(vm.type_error(&format!("execfile() argument 2 must be dict, not {shown}")));
            }
        },
        None => Value::None,
    };
    let locals = args.next().unwrap_or(Value::None);

    let (globals, locals) = namespace_arguments(vm, globals, locals)?;
    let (Some(globals), Some(locals)) = (globals, locals) else {
        return Err(vm.raise(ExceptionKind::SystemError, "error return without exception set"));
    };

    // CPython installs `__builtins__` before it opens the file.
    if vm.dict_get_str(&globals, "__builtins__")?.is_none() {
        vm.dict_set_str(&globals, "__builtins__", Value::Object(vm.current_builtins()))?;
    }

    vm.host_permit(HostCapability::FileSystem, Denial::Crt, Some(&filename))?;
    mark_host_namespaces(vm, &globals, &locals);

    Ok(Value::unknown(format!("execfile({filename:?})")))
}

/// `locals()`: the local namespace of the innermost frame.
pub fn builtin_locals(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, args, "locals")?;

    match vm.current_locals()? {
        Some(locals) => Ok(Value::Object(locals)),
        None => Err(vm.raise(ExceptionKind::SystemError, "error return without exception set")),
    }
}

/// Compiles a parsed module to a code object.
pub fn compile_module(vm: &Vm, module: &ast::Mod, filename: &[u8], flags: CompilerFlags) -> PyResult<Value> {
    let mut context = VmCompileContext::new(vm);
    let unit = match crate::interp::compiler::compile_ast(module, filename, flags, &mut context) {
        Ok(unit) => unit,
        Err(error) => return Err(context.into_signal(error)),
    };

    Ok(code_value(vm, &unit))
}

/// The code object built for `unit`. Nesting follows the source, which
/// the parser bounds.
fn code_value(vm: &Vm, unit: &CodeUnit) -> Value {
    let names = |names: &[Vec<u8>]| names.iter().map(|name| PyBytes::new_unshared(name.as_slice())).collect();
    let name = PyBytes::new_unshared(unit.name.as_slice());
    let name = if unit.name_interned { vm.intern(&name) } else { name };

    let code = CodeObject {
        argcount: unit.argcount,
        nlocals: unit.nlocals,
        stacksize: unit.stacksize,
        flags: CodeFlags(unit.flags),
        code: unit.code.as_slice().into(),
        consts: unit.consts.iter().map(|constant| constant_value(vm, constant)).collect(),
        names: names(&unit.names),
        varnames: names(&unit.varnames),
        freevars: names(&unit.freevars),
        cellvars: names(&unit.cellvars),
        // A fresh string, which is shared only when it is at most one byte.
        filename: PyBytes::new(unit.filename.as_slice()),
        name,
        firstlineno: unit.firstlineno as u32,
        // Resized from a larger buffer, so distinct even when empty.
        lnotab: PyBytes::allocate(unit.lnotab.as_slice()),
    };

    vm.new_code(code)
}

fn constant_value(vm: &Vm, constant: &Constant) -> Value {
    match constant {
        Constant::None => Value::None,
        Constant::Ellipsis => Value::Ellipsis,
        Constant::Int(value) => Value::Int(*value),
        Constant::Long(value) => Value::Long(Rc::new(value.clone())),
        Constant::Float(value) => Value::Float(*value),
        Constant::Complex { real, imag } => vm.new_complex(Complex::new(*real, *imag)),
        Constant::Str { value, interned } => {
            let string = PyBytes::new_unshared(value.as_slice());
            Value::Str(if *interned { vm.intern(&string) } else { string })
        }
        // The compiler decodes literals into a freshly allocated unicode object.
        Constant::Unicode(units) => Value::Unicode(PyText::new_unshared(units.as_slice())),
        Constant::Tuple(items) => Value::tuple(items.iter().map(|item| constant_value(vm, item)).collect()),
        Constant::Code(code) => code_value(vm, code),
    }
}

/// A SyntaxError with a location: `args` is `(msg,)` and the location is
/// set as attributes. `text` is set only when known, since reading it
/// requires the file from the host.
fn located_syntax_error(vm: &Vm, error: &SyntaxError) -> Signal {
    let exception = match vm.instantiate_exception(vm.types().exception(syntax_error_class(error.kind)), vec![Value::str(&error.message)]) {
        Ok(exception) => exception,
        Err(signal) => return signal,
    };

    let mut attributes = vec![("lineno", Value::Int(i64::from(error.lineno))), ("filename", Value::Str(PyBytes::new(error.filename.as_slice())))];
    if let Some(text) = &error.text {
        attributes.push(("text", Value::Str(PyBytes::new(text.as_slice()))));
    }
    attributes.push(("offset", Value::None));

    for (name, value) in attributes {
        match vm.setattr(&exception, &PyBytes::from(name), value) {
            Ok(()) | Err(Signal::Raise(_)) => {}
            Err(halt) => return halt,
        }
    }

    Signal::Raise(exception)
}

/// Runs source text with filename `<string>`, after checking it for NUL
/// bytes.
fn run_string(vm: &Vm, source: &PyBytes, mode: Mode, flags: CompilerFlags, globals: &ObjectRef, locals: &ObjectRef) -> PyResult<Value> {
    if source.as_bytes().contains(&0) {
        return Err(vm.type_error("expected string without null bytes"));
    }

    let request = CompileRequest { source: CompileSource::Text(source.as_bytes().to_vec()), filename: b"<string>".to_vec(), mode, flags: CompilerFlags(flags.0 | current_future_flags(vm)) };
    let Value::Object(code) = compile_code(vm, request)? else {
        return Err(vm.raise(ExceptionKind::SystemError, "compilation did not produce a code object"));
    };

    vm.eval_code(&code, globals, locals)
}

/// The type checks `exec` and `eval` apply to their program; `None` when
/// it is not a string, code object, or file. A `unicode` source is encoded
/// as UTF-8 and flagged so.
fn classify_program(vm: &Vm, program: &Value) -> PyResult<Option<Program>> {
    if program.is_unknown() {
        return Ok(Some(Program::Host));
    }

    if let Some(bytes) = vm.as_str_bytes(program) {
        return Ok(Some(Program::Source { bytes, flags: CompilerFlags::default() }));
    }
    if let Some(text) = vm.as_text(program) {
        return Ok(Some(Program::Source { bytes: PyBytes::new(encode_utf8(text.units())), flags: CompilerFlags(CompilerFlags::SOURCE_IS_UTF8) }));
    }

    if let Value::Object(object) = program {
        if matches!(object.payload, Payload::Code(_)) {
            return Ok(Some(Program::Code(Rc::clone(object))));
        }
    }

    if vm.is_instance_of(program, &vm.types().file)? {
        return Ok(Some(Program::Host));
    }

    Ok(None)
}

/// Whether the code object has free variables.
fn has_free_variables(code: &ObjectRef) -> bool {
    match &code.payload {
        Payload::Code(code) => !code.freevars.is_empty(),
        _ => false,
    }
}

/// Whether the value is a dict; an unknown value halts.
fn dict_argument(value: &Value, context: &str) -> PyResult<Option<ObjectRef>> {
    if let Value::Unknown(unknown) = value {
        return Err(Signal::Halt(Halt::UnknownCondition { context: context.to_owned(), origin: unknown.origin.clone() }));
    }

    match value {
        Value::Object(object) if object.as_dict().is_some() => Ok(Some(Rc::clone(object))),
        _ => Ok(None),
    }
}

/// Whether the value is a mapping; an unknown value halts.
fn mapping_argument(vm: &Vm, value: &Value, context: &str) -> PyResult<Option<ObjectRef>> {
    if let Value::Unknown(unknown) = value {
        return Err(Signal::Halt(Halt::UnknownCondition { context: context.to_owned(), origin: unknown.origin.clone() }));
    }

    match value {
        Value::Object(object) if is_mapping(vm, value)? => Ok(Some(Rc::clone(object))),
        _ => Ok(None),
    }
}

/// The namespace checks and defaults of `eval` and `execfile`: `locals`
/// must be a mapping and `globals` a dict; omitted ones default to the
/// innermost frame's, and `locals` to `globals`.
fn namespace_arguments(vm: &Vm, globals: Value, locals: Value) -> PyResult<(Option<ObjectRef>, Option<ObjectRef>)> {
    let locals = if locals.is_none() {
        None
    } else {
        let Some(locals) = mapping_argument(vm, &locals, "eval locals")? else {
            return Err(vm.type_error("locals must be a mapping"));
        };
        Some(locals)
    };

    if globals.is_none() {
        let globals = vm.current_globals();
        let locals = match locals {
            Some(locals) => Some(locals),
            None => vm.current_locals()?,
        };
        return Ok((globals, locals));
    }

    let Some(globals) = dict_argument(&globals, "eval globals")? else {
        let message = if is_mapping(vm, &globals)? { "globals must be a real dict; try eval(expr, {}, mapping)" } else { "globals must be a dict" };
        return Err(vm.type_error(message));
    };
    let locals = locals.unwrap_or_else(|| Rc::clone(&globals));

    Ok((Some(globals), Some(locals)))
}

/// Code from the host ran in these namespaces: names it may have bound
/// read as unknown afterwards, as after `import *` of an opaque module.
fn mark_host_namespaces(vm: &Vm, globals: &ObjectRef, locals: &ObjectRef) {
    vm.mark_opaque_names(globals);
    vm.mark_opaque_names(locals);
}
