//! `str._formatter_parser` and `str._formatter_field_name_split`, the
//! parsing hooks `string.Formatter` builds on.

use std::cell::Cell;

use crate::interp::builtins::core::object_getattribute;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::iterator_result;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::no_arguments;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::text::chars::CodeUnit;
use crate::interp::builtins::text::format::field_index;
use crate::interp::builtins::text::format::first_part_end;
use crate::interp::builtins::text::format::index_key;
use crate::interp::builtins::text::format::next_field_part;
use crate::interp::builtins::text::format::next_markup;
use crate::interp::error::PyResult;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::object::NativeFn;
use crate::interp::value::NativeData;
use crate::interp::value::ObjectRef;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const FORMATTER_ITERATOR: &str = "formatteriterator";
const FIELD_NAME_ITERATOR: &str = "fieldnameiterator";

/// Yields `(literal, field_name, format_spec, conversion)` for each piece
/// of a format string.
struct FormatterIterator<T> {
    format: Box<[T]>,
    position: Cell<usize>,
}

/// Yields `(is_attribute, key)` for each access after the first part of
/// a field name.
struct FieldNameIterator<T> {
    name: Box<[T]>,
    position: Cell<usize>,
}

impl<T: CodeUnit> NativeData for FormatterIterator<T> {
    fn type_name(&self) -> &'static str {
        FORMATTER_ITERATOR
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl<T: CodeUnit> NativeData for FieldNameIterator<T> {
    fn type_name(&self) -> &'static str {
        FIELD_NAME_ITERATOR
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `str._formatter_parser()`.
pub(crate) fn formatter_parser<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "_formatter_parser")?;

    let class = if T::UNICODE { native_type(vm, "unicode formatteriterator", create_formatter_type::<u16>)? } else { native_type(vm, "str formatteriterator", create_formatter_type::<u8>)? };

    Ok(new_native_object(vm, &class, FormatterIterator { format: units.into(), position: Cell::new(0) }))
}

/// `str._formatter_field_name_split()`: the first part of a field name,
/// as a `long` when it is all digits, and an iterator over the rest.
pub(crate) fn formatter_field_name_split<T: CodeUnit>(vm: &Vm, units: &[T], args: CallArgs) -> PyResult<Value> {
    no_arguments(vm, &args, "_formatter_field_name_split")?;

    let first_end = first_part_end(units);
    let first = match field_index(vm, &units[..first_end])? {
        Some(index) => index_key(index),
        None => T::new_value(units[..first_end].to_vec()),
    };

    let class = if T::UNICODE { native_type(vm, "unicode fieldnameiterator", create_field_name_type::<u16>)? } else { native_type(vm, "str fieldnameiterator", create_field_name_type::<u8>)? };
    let rest = new_native_object(vm, &class, FieldNameIterator { name: units.into(), position: Cell::new(first_end) });

    Ok(Value::tuple(vec![first, rest]))
}

fn create_formatter_type<T: CodeUnit>(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, FORMATTER_ITERATOR, formatter_iter::<T>, formatter_next::<T>)
}

fn create_field_name_type<T: CodeUnit>(vm: &Vm) -> PyResult<ObjectRef> {
    iterator_type(vm, FIELD_NAME_ITERATOR, field_name_iter::<T>, field_name_next::<T>)
}

fn iterator_type(vm: &Vm, name: &'static str, iter: NativeFn, next: NativeFn) -> PyResult<ObjectRef> {
    new_final_type(
        vm,
        TypeSpec {
            name,
            module: "__builtin__",
            base: None,
            layout: Layout::Native,
            instance_dict: false,
            methods: &[method("__getattribute__", object_getattribute), method("__iter__", iter), method("next", next)],
        },
    )
}

fn formatter_iter<T: CodeUnit>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<FormatterIterator<T>>(vm, &args, FORMATTER_ITERATOR, "__iter__")?;
    method_no_arguments(vm, &args, "__iter__")?;

    Ok(args.positional[0].clone())
}

fn field_name_iter<T: CodeUnit>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<FieldNameIterator<T>>(vm, &args, FIELD_NAME_ITERATOR, "__iter__")?;
    method_no_arguments(vm, &args, "__iter__")?;

    Ok(args.positional[0].clone())
}

/// A piece of a format string; the parts of a literal without a field
/// are `None`.
fn formatter_next<T: CodeUnit>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let iterator = this::<FormatterIterator<T>>(vm, &args, FORMATTER_ITERATOR, "next")?;
    method_no_arguments(vm, &args, "next")?;

    let mut position = iterator.position.get();
    let markup = next_markup(vm, &iterator.format, &mut position);
    iterator.position.set(position);
    let Some(markup) = markup? else {
        return iterator_result(vm, None);
    };

    let literal = T::new_value(markup.literal.to_vec());
    let item = match markup.field {
        None => vec![literal, Value::None, Value::None, Value::None],
        Some(field) => {
            let conversion = field.conversion.map_or(Value::None, |unit| T::new_value(vec![unit]));
            vec![literal, T::new_value(field.name.to_vec()), T::new_value(field.spec.to_vec()), conversion]
        }
    };

    iterator_result(vm, Some(Value::tuple(item)))
}

/// The next attribute or item access of a field name. An item key made
/// of digits is a `long`.
fn field_name_next<T: CodeUnit>(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let iterator = this::<FieldNameIterator<T>>(vm, &args, FIELD_NAME_ITERATOR, "next")?;
    method_no_arguments(vm, &args, "next")?;

    let mut position = iterator.position.get();
    let part = next_field_part(vm, &iterator.name, &mut position);
    iterator.position.set(position);
    let Some(part) = part? else {
        return iterator_result(vm, None);
    };

    let key = match part.is_attribute {
        true => T::new_value(part.key.to_vec()),
        false => match field_index(vm, part.key)? {
            Some(index) => index_key(index),
            None => T::new_value(part.key.to_vec()),
        },
    };

    iterator_result(vm, Some(Value::tuple(vec![Value::Bool(part.is_attribute), key])))
}
