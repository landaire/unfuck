//! The `_sre` module: compiled patterns built from the code lists that
//! `sre_compile` produces, and the match and scanner objects they return.
//! Code units are 32 bits wide and `unicode` subjects are UTF-16, as in
//! the Windows build the client embeds.

mod classify;
mod engine;
mod matches;
mod opcode;
mod pattern;
mod program;
mod scan;
mod scanner;
mod subject;
mod validate;

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::int_argument;
use crate::interp::builtins::arguments::ssize_argument;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::locale::ctype_is_c;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::sre::classify::Fold;
use crate::interp::builtins::modules::sre::opcode::FLAG_LOCALE;
use crate::interp::builtins::modules::sre::opcode::MAXREPEAT;
use crate::interp::builtins::modules::sre::pattern::Compiled;
use crate::interp::builtins::modules::sre::pattern::PatternData;
use crate::interp::builtins::modules::sre::program::Program;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash::LongWidth;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A numeric argument of `_sre.compile`, or the unknown value given in
/// its place.
enum Given {
    Known(i64),
    Unknown(Value),
}

impl Given {
    fn into_value(self, vm: &Vm) -> Value {
        match self {
            Given::Known(number) => vm.new_int_from_i64(number),
            Given::Unknown(value) => value,
        }
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, &[function("compile", sre_compile), function("getcodesize", sre_getcodesize), function("getlower", sre_getlower)])?;

    set_attribute(vm, module, "MAGIC", Value::Int(20_031_017))?;
    set_attribute(vm, module, "CODESIZE", Value::Int(4))?;
    // Built as a long whatever the platform's long width.
    set_attribute(vm, module, "MAXREPEAT", Value::long(BigInt::from(MAXREPEAT)))?;
    set_attribute(vm, module, "copyright", Value::unknown("_sre.copyright text"))?;

    Ok(())
}

/// Positional arguments of a varargs function whose format names no
/// function, so counts report as "function takes ...".
fn anonymous_arguments(vm: &Vm, args: CallArgs, name: &str, minimum: usize, maximum: usize) -> PyResult<Vec<Value>> {
    if args.has_keywords() {
        return Err(vm.type_error(&format!("{name}() takes no keyword arguments")));
    }

    let count = args.positional.len();
    if count < minimum || count > maximum {
        let (bound, limit) = if minimum == maximum {
            ("exactly", minimum)
        } else if count < minimum {
            ("at least", minimum)
        } else {
            ("at most", maximum)
        };
        let plural = if limit == 1 { "" } else { "s" };
        return Err(vm.type_error(&format!("function takes {bound} {limit} argument{plural} ({count} given)")));
    }

    Ok(args.positional)
}

/// `compile(pattern, flags, code, groups=0, groupindex, indexgroup)`.
fn sre_compile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let mut arguments = anonymous_arguments(vm, args, "compile", 3, 6)?.into_iter();
    let (Some(pattern), Some(flags), Some(code)) = (arguments.next(), arguments.next(), arguments.next()) else {
        return Err(vm.type_error("function takes at least 3 arguments"));
    };
    let groups = arguments.next();
    let groupindex = arguments.next();
    let indexgroup = arguments.next();

    let flags = if flags.is_unknown() { Given::Unknown(flags) } else { Given::Known(int_argument(vm, &flags)?) };
    let Some(items) = vm.as_list(&code) else {
        return Err(vm.type_error(&format!("argument 3 must be list, not {}", vm.type_name(&code))));
    };
    let groups = match groups {
        Some(groups) if groups.is_unknown() => Given::Unknown(groups),
        Some(groups) => Given::Known(ssize_argument(vm, &groups)?),
        None => Given::Known(0),
    };

    let mut words = Some(Vec::with_capacity(items.len()));
    for item in &items {
        if item.is_unknown() {
            words = None;
            continue;
        }
        let word = code_word(vm, item)?;
        if let Some(words) = words.as_mut() {
            words.push(word);
        }
    }

    // The matcher runs only code whose every input is known.
    let compiled = match (&flags, &groups, words) {
        (Given::Known(flags), Given::Known(groups), Some(words)) => {
            let program = Program::parse(words, *groups).map_err(|error| vm.raise(ExceptionKind::RuntimeError, &error.to_string()))?;
            let groups = usize::try_from(*groups).map_err(|_| vm.raise(ExceptionKind::RuntimeError, "invalid SRE code"))?;
            Some(Compiled { program: Rc::new(program), flags: *flags, groups })
        }
        _ => None,
    };

    let data = PatternData { pattern, flags: flags.into_value(vm), groups: groups.into_value(vm), groupindex, indexgroup, compiled };

    pattern::new_pattern(vm, data)
}

/// A code list item as a 32-bit word: an `int` passes through a C
/// `unsigned long`, a `long` must fit one, and the result must fit 32
/// bits.
fn code_word(vm: &Vm, item: &Value) -> PyResult<u32> {
    let too_large = || vm.raise(ExceptionKind::OverflowError, "regular expression code size limit exceeded");
    let Some(integral) = vm.as_integral(item) else {
        return Err(vm.raise(ExceptionKind::SystemError, "..\\Objects\\longobject.c:426: bad argument to internal function"));
    };

    let unsigned = match (integral, vm.config.long_width) {
        (Integral::Int(number), LongWidth::Bits32) => u64::from(number as i32 as u32),
        (Integral::Int(number), LongWidth::Bits64) => number as u64,
        (Integral::Long(number), LongWidth::Bits32) => u64::from(number.to_u32().ok_or_else(too_large)?),
        (Integral::Long(number), LongWidth::Bits64) => number.to_u64().ok_or_else(too_large)?,
    };

    u32::try_from(unsigned).map_err(|_| too_large())
}

fn sre_getcodesize(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "getcodesize")?;

    Ok(Value::Int(4))
}

/// `getlower(character, flags)`: the character as the given flags fold
/// it.
fn sre_getlower(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = anonymous_arguments(vm, args, "getlower", 2, 2)?;
    let [character, flags] = arguments.as_slice() else {
        return Err(vm.type_error("function takes exactly 2 arguments"));
    };
    if character.is_unknown() || flags.is_unknown() {
        return Ok(Value::unknown("_sre.getlower() of an unknown argument"));
    }

    let character = int_argument(vm, character)?;
    let flags = int_argument(vm, flags)?;
    if flags & FLAG_LOCALE != 0 && !ctype_is_c(vm) {
        return Ok(Value::unknown("_sre.getlower() under the host locale"));
    }

    // The character passes as a C unsigned int and returns as an int.
    let lowered = Fold::from_flags(flags).lower(character as u32);

    Ok(Value::Int(i64::from(lowered as i32)))
}
