//! `future_builtins`: Python 3 versions of builtins that conflict with
//! Python 2 ones.

use num_bigint::Sign;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::operator::number_index;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// The bases `hex` and `oct` format in.
#[derive(Clone, Copy)]
enum Radix {
    Hexadecimal,
    Octal,
}

const FUNCTIONS: &[MethodSpec] = &[
    function("hex", |vm, args| to_base(vm, args, "hex", Radix::Hexadecimal)),
    function("oct", |vm, args| to_base(vm, args, "oct", Radix::Octal)),
    function("ascii", future_ascii),
];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(vm, module, FUNCTIONS)?;

    let itertools = vm.import_module("itertools")?;
    for (source, name) in [("imap", "map"), ("ifilter", "filter"), ("izip", "zip")] {
        let function = vm.getattr_str(&itertools, source)?;
        set_attribute(vm, module, name, function)?;
    }

    Ok(())
}

/// Base conversion with Python 3 prefixes and no `L` suffix.
fn to_base(vm: &Vm, args: CallArgs, name: &str, radix: Radix) -> PyResult<Value> {
    let argument = args::single(vm, args, name)?;
    let index = number_index(vm, &argument)?;
    if index.is_unknown() {
        return Ok(index);
    }
    let Some(integral) = vm.as_integral(&index) else {
        return Err(vm.type_error(&format!("__index__ returned non-(int,long) (type {})", vm.type_name(&index))));
    };

    let number = integral.to_bigint();
    let sign = if number.sign() == Sign::Minus { "-" } else { "" };
    let text = match radix {
        Radix::Hexadecimal => format!("{sign}0x{:x}", number.magnitude()),
        Radix::Octal => format!("{sign}0o{:o}", number.magnitude()),
    };

    Ok(Value::str(&text))
}

fn future_ascii(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let argument = args::single(vm, args, "ascii")?;

    vm.repr(&argument)
}
