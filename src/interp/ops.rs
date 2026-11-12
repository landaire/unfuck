use std::cmp::Ordering;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::Signed;
use num_traits::ToPrimitive;
use num_traits::Zero;

use crate::interp::attr::MroLookup;
use crate::interp::code::CodeObject;
use crate::interp::complex::Complex;
use crate::interp::complex::Errno;
use crate::interp::error::Halt;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::hash;
use crate::interp::hash::PyHash;
use crate::interp::numbers;
use crate::interp::numbers::Integral;
use crate::interp::object::CallArgs;
use crate::interp::pyset::PySet;
use crate::interp::type_flags;
use crate::interp::value::Payload;
use crate::interp::value::PyBytes;
use crate::interp::value::PyText;
use crate::interp::value::TupleItems;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    TrueDivide,
    FloorDivide,
    Modulo,
    Power,
    LeftShift,
    RightShift,
    And,
    Xor,
    Or,
}

impl BinaryOp {
    fn names(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Add => ("__add__", "__radd__", "__iadd__"),
            Self::Subtract => ("__sub__", "__rsub__", "__isub__"),
            Self::Multiply => ("__mul__", "__rmul__", "__imul__"),
            Self::Divide => ("__div__", "__rdiv__", "__idiv__"),
            Self::TrueDivide => ("__truediv__", "__rtruediv__", "__itruediv__"),
            Self::FloorDivide => ("__floordiv__", "__rfloordiv__", "__ifloordiv__"),
            Self::Modulo => ("__mod__", "__rmod__", "__imod__"),
            Self::Power => ("__pow__", "__rpow__", "__ipow__"),
            Self::LeftShift => ("__lshift__", "__rlshift__", "__ilshift__"),
            Self::RightShift => ("__rshift__", "__rrshift__", "__irshift__"),
            Self::And => ("__and__", "__rand__", "__iand__"),
            Self::Xor => ("__xor__", "__rxor__", "__ixor__"),
            Self::Or => ("__or__", "__ror__", "__ior__"),
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Subtract => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::TrueDivide => "/",
            Self::FloorDivide => "//",
            Self::Modulo => "%",
            Self::Power => "** or pow()",
            Self::LeftShift => "<<",
            Self::RightShift => ">>",
            Self::And => "&",
            Self::Xor => "^",
            Self::Or => "|",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOp {
    Less,
    LessEqual,
    Equal,
    NotEqual,
    Greater,
    GreaterEqual,
    In,
    NotIn,
    Is,
    IsNot,
}

impl CompareOp {
    pub fn from_arg(arg: usize) -> Option<Self> {
        let operation = match arg {
            0 => Self::Less,
            1 => Self::LessEqual,
            2 => Self::Equal,
            3 => Self::NotEqual,
            4 => Self::Greater,
            5 => Self::GreaterEqual,
            6 => Self::In,
            7 => Self::NotIn,
            8 => Self::Is,
            9 => Self::IsNot,
            _ => return None,
        };

        Some(operation)
    }

    fn method_names(self) -> (&'static str, &'static str) {
        match self {
            Self::Less => ("__lt__", "__gt__"),
            Self::LessEqual => ("__le__", "__ge__"),
            Self::Equal => ("__eq__", "__eq__"),
            Self::NotEqual => ("__ne__", "__ne__"),
            Self::Greater => ("__gt__", "__lt__"),
            Self::GreaterEqual => ("__ge__", "__le__"),
            _ => ("", ""),
        }
    }

    pub(crate) fn holds(self, ordering: Ordering) -> bool {
        match self {
            Self::Less => ordering == Ordering::Less,
            Self::LessEqual => ordering != Ordering::Greater,
            Self::Equal => ordering == Ordering::Equal,
            Self::NotEqual => ordering != Ordering::Equal,
            Self::Greater => ordering == Ordering::Greater,
            Self::GreaterEqual => ordering != Ordering::Less,
            _ => false,
        }
    }
}

/// Numeric operand after Python 2 coercion.
enum Number {
    Integral(Integral, bool),
    Float(f64),
    Complex(Complex),
}

impl Vm {
    pub fn new_int(&self, value: BigInt) -> Value {
        match value.to_i64() {
            Some(small) if numbers::fits_int(self.config.long_width, small) => Value::Int(small),
            _ => Value::long(value),
        }
    }

    pub fn new_int_from_i64(&self, value: i64) -> Value {
        if numbers::fits_int(self.config.long_width, value) {
            return Value::Int(value);
        }

        Value::long(BigInt::from(value))
    }

    /// Integer content of `int`, `long`, `bool`, and their subclasses.
    pub fn as_integral(&self, value: &Value) -> Option<Integral> {
        match value {
            Value::Bool(flag) => Some(Integral::Int(i64::from(*flag))),
            Value::Int(number) => Some(Integral::Int(*number)),
            Value::Long(number) => Some(Integral::Long((**number).clone())),
            Value::Object(object) => match &object.payload {
                Payload::Int(number) => Some(Integral::Int(*number)),
                Payload::Long(number) => Some(Integral::Long((**number).clone())),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_index(&self, value: &Value) -> Option<i64> {
        match self.as_integral(value)? {
            Integral::Int(number) => Some(number),
            Integral::Long(number) => number.to_i64(),
        }
    }

    pub fn as_float(&self, value: &Value) -> Option<f64> {
        match value {
            Value::Float(number) => Some(*number),
            Value::Object(object) => match &object.payload {
                Payload::Float(number) => Some(*number),
                _ => None,
            },
            _ => None,
        }
    }

    /// The value of a `complex` or subclass instance.
    pub fn as_complex(&self, value: &Value) -> Option<Complex> {
        match value.as_object().map(|object| &object.payload) {
            Some(Payload::Complex(number)) => Some(*number),
            _ => None,
        }
    }

    /// A new `complex`.
    pub fn new_complex(&self, number: Complex) -> Value {
        let class = Rc::clone(&self.types().complex);

        Value::Object(self.alloc(&class, Payload::Complex(number), None))
    }

    fn as_number(&self, value: &Value) -> Option<Number> {
        if let Some(number) = self.as_complex(value) {
            return Some(Number::Complex(number));
        }
        if let Some(number) = self.as_float(value) {
            return Some(Number::Float(number));
        }

        let is_bool = matches!(value, Value::Bool(_));

        self.as_integral(value).map(|integral| Number::Integral(integral, is_bool))
    }

    pub fn is_number(&self, value: &Value) -> bool {
        self.as_number(value).is_some()
    }

    /// Text payload of a `str` or `unicode` (or subclass) value.
    pub fn as_text(&self, value: &Value) -> Option<PyText> {
        match value {
            Value::Unicode(text) => Some(text.clone()),
            Value::Object(object) => match &object.payload {
                Payload::Unicode(text) => Some(text.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_str_bytes(&self, value: &Value) -> Option<PyBytes> {
        match value {
            Value::Str(bytes) => Some(bytes.clone()),
            Value::Object(object) => match &object.payload {
                Payload::Str(bytes) => Some(bytes.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// Contents of a `bytearray` (or subclass) value.
    pub fn as_bytearray(&self, value: &Value) -> Option<Vec<u8>> {
        match value.as_object().map(|object| &object.payload) {
            Some(Payload::ByteArray(data)) => Some(data.borrow().bytes.clone()),
            _ => None,
        }
    }

    /// Items of a `tuple` or tuple subclass.
    pub fn as_tuple(&self, value: &Value) -> Option<TupleItems> {
        match value {
            Value::Tuple(items) => Some(items.clone()),
            Value::Object(object) => match &object.payload {
                Payload::Tuple(items) => Some(items.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_list(&self, value: &Value) -> Option<Vec<Value>> {
        match value {
            Value::Object(object) => match &object.payload {
                Payload::List(items) => Some(items.borrow().clone()),
                _ => None,
            },
            _ => None,
        }
    }

    fn unknown_condition(&self, context: &str, value: &Value) -> Signal {
        let origin = match value {
            Value::Unknown(unknown) => unknown.origin.clone(),
            _ => String::new(),
        };

        Signal::Halt(Halt::UnknownCondition { context: context.to_owned(), origin })
    }

    /// Truth value. Branching on an unknown value halts.
    pub fn truthy(&self, value: &Value, context: &str) -> PyResult<bool> {
        match value {
            Value::None => Ok(false),
            Value::NotImplemented | Value::Ellipsis => Ok(true),
            Value::Bool(flag) => Ok(*flag),
            Value::Int(number) => Ok(*number != 0),
            Value::Long(number) => Ok(!number.is_zero()),
            Value::Float(number) => Ok(*number != 0.0),
            Value::Str(bytes) => Ok(!bytes.as_bytes().is_empty()),
            Value::Unicode(text) => Ok(!text.units().is_empty()),
            Value::Tuple(items) => Ok(!items.is_empty()),
            Value::Unknown(_) => Err(self.unknown_condition(context, value)),
            Value::Object(object) => {
                if let Some(method) = self.user_override(value, "__nonzero__")? {
                    let result = self.call0(&method)?;
                    return match result {
                        Value::Bool(flag) => Ok(flag),
                        Value::Int(number) => Ok(number != 0),
                        Value::Unknown(_) => Err(self.unknown_condition(context, &result)),
                        _ => Err(self.type_error("__nonzero__ should return bool or int")),
                    };
                }
                if let Some(method) = self.user_override(value, "__len__")? {
                    let result = self.call0(&method)?;
                    return match self.as_index(&result) {
                        Some(length) => Ok(length != 0),
                        None if result.is_unknown() => Err(self.unknown_condition(context, &result)),
                        None => Err(self.type_error("__len__ should return an int")),
                    };
                }
                match &object.payload {
                    Payload::Int(number) => Ok(*number != 0),
                    Payload::Long(number) => Ok(!number.is_zero()),
                    Payload::Float(number) => Ok(*number != 0.0),
                    Payload::Complex(number) => Ok(number.real != 0.0 || number.imag != 0.0),
                    Payload::Str(bytes) => Ok(!bytes.as_bytes().is_empty()),
                    Payload::Unicode(text) => Ok(!text.units().is_empty()),
                    Payload::Tuple(items) => Ok(!items.is_empty()),
                    Payload::List(items) => Ok(!items.borrow().is_empty()),
                    Payload::Dict(table) => Ok(!table.borrow().is_empty()),
                    Payload::Set(table) => Ok(!table.borrow().is_empty()),
                    Payload::FrozenSet(table) => Ok(!table.is_empty()),
                    Payload::DictProxy(dict) => Ok(self.dict_len(dict)? != 0),
                    Payload::XRange(range) => Ok(range.length != 0),
                    Payload::Native(_) => match self.native_len(value)? {
                        Some(length) => Ok(length != 0),
                        None => Ok(true),
                    },
                    _ => Ok(true),
                }
            }
        }
    }

    /// Identity (`is`) as the equality shortcut for `==` tests it. Inline
    /// numbers compare by value; `str` and `unicode` objects by pointer.
    pub fn is_same(&self, left: &Value, right: &Value) -> bool {
        match (left, right) {
            (Value::None, Value::None) | (Value::NotImplemented, Value::NotImplemented) | (Value::Ellipsis, Value::Ellipsis) => true,
            (Value::Bool(left), Value::Bool(right)) => left == right,
            (Value::Int(left), Value::Int(right)) => left == right,
            (Value::Long(left), Value::Long(right)) => left.ptr_eq(right),
            (Value::Float(left), Value::Float(right)) => left.to_bits() == right.to_bits(),
            (Value::Str(left), Value::Str(right)) => left.ptr_eq(right),
            (Value::Unicode(left), Value::Unicode(right)) => left.ptr_eq(right),
            (Value::Tuple(left), Value::Tuple(right)) => left.ptr_eq(right) || (left.is_empty() && right.is_empty()),
            (Value::Object(left), Value::Object(right)) => Rc::ptr_eq(left, right),
            (Value::Unknown(left), Value::Unknown(right)) => Rc::ptr_eq(left, right),
            _ => false,
        }
    }

    /// `hash(value)`.
    pub fn hash(&self, value: &Value) -> PyResult<PyHash> {
        let width = self.config.long_width;

        match value {
            Value::None | Value::NotImplemented | Value::Ellipsis => {
                let class = self.type_of(value);
                Ok(hash::hash_pointer(width, self.address_of(&class)))
            }
            Value::Bool(flag) => Ok(hash::hash_int(width, i64::from(*flag))),
            Value::Int(number) => Ok(hash::hash_int(width, *number)),
            Value::Long(number) => Ok(hash::hash_long(width, number)),
            Value::Float(number) => Ok(hash::hash_float(width, *number)),
            Value::Str(bytes) => {
                if let Some(hash) = bytes.cached_hash().get() {
                    return Ok(hash);
                }
                let hash = hash::hash_bytes(width, bytes.as_bytes());
                bytes.cached_hash().set(Some(hash));
                Ok(hash)
            }
            Value::Unicode(text) => {
                if let Some(hash) = text.cached_hash().get() {
                    return Ok(hash);
                }
                let hash = hash::hash_unicode(width, text.units());
                text.cached_hash().set(Some(hash));
                Ok(hash)
            }
            Value::Tuple(items) => {
                let hashes = items.iter().map(|item| self.hash(item)).collect::<PyResult<Vec<_>>>()?;
                Ok(hash::hash_tuple(width, hashes, items.len()))
            }
            Value::Unknown(unknown) => Err(Signal::Halt(Halt::UnknownHash { origin: unknown.origin.clone() })),
            Value::Object(object) => {
                let class = object.class();
                // Hashing readies a type that has no attribute dict yet.
                self.ready_type(&class);
                if !self.is_classic_class(&class) {
                    if let crate::interp::attr::MroLookup::Found { value: hook, owner } = self.lookup_mro(&class, "__hash__")? {
                        if hook.is_none() {
                            return Err(self.type_error(&format!("unhashable type: '{}'", self.class_name(&class))));
                        }
                        if !self.is_builtin_type(&owner) {
                            // `__hash__` of a heap class is looked up on the type.
                            if owner.as_class().is_some_and(|data| !data.builtin) {
                                type_flags::note_special_lookup(&class);
                            }
                            let hook = self.descriptor_get(&hook, Some(value.clone()), &class)?;
                            return self.hash_result(&self.call0(&hook)?);
                        }
                    }
                } else if let Some(hook) = self.getattr_opt(value, &PyBytes::from("__hash__"))? {
                    return self.hash_result(&self.call0(&hook)?);
                } else if self.getattr_opt(value, &PyBytes::from("__eq__"))?.is_some() || self.getattr_opt(value, &PyBytes::from("__cmp__"))?.is_some() {
                    return Err(self.type_error("unhashable instance"));
                }

                match &object.payload {
                    Payload::Int(number) => Ok(hash::hash_int(width, *number)),
                    Payload::Long(number) => Ok(hash::hash_long(width, number)),
                    Payload::Float(number) => Ok(hash::hash_float(width, *number)),
                    Payload::Complex(number) => Ok(number.hash(width)),
                    Payload::Str(bytes) => self.hash(&Value::Str(bytes.clone())),
                    Payload::Unicode(text) => self.hash(&Value::Unicode(text.clone())),
                    Payload::Tuple(items) => self.hash(&Value::Tuple(items.clone())),
                    Payload::FrozenSet(table) => Ok(self.frozenset_hash(table)),
                    Payload::List(_) | Payload::Dict(_) | Payload::Set(_) | Payload::DictProxy(_) => {
                        Err(self.type_error(&format!("unhashable type: '{}'", self.class_name(&class))))
                    }
                    Payload::Slice(_) => Err(self.type_error("unhashable type")),
                    Payload::Code(code) => self.code_hash(code),
                    Payload::Method(method) => {
                        let receiver = match &method.receiver {
                            Some(receiver) => self.hash(receiver)?.value(),
                            None => 0,
                        };
                        let function = self.hash(&method.function)?.value();
                        Ok(PyHash::from_long(width, function ^ receiver))
                    }
                    _ => Ok(hash::hash_pointer(width, self.address_of(object))),
                }
            }
        }
    }

    fn hash_result(&self, result: &Value) -> PyResult<PyHash> {
        let width = self.config.long_width;

        match self.as_integral(result) {
            Some(Integral::Int(number)) => Ok(PyHash::from_long(width, number)),
            Some(Integral::Long(number)) => Ok(hash::hash_long(width, &number)),
            None if result.is_unknown() => Err(self.unknown_condition("__hash__", result)),
            None => Err(self.type_error("__hash__() should return an int")),
        }
    }

    /// `hash(frozenset)` of CPython 2.7, in C `long` arithmetic.
    pub fn frozenset_hash(&self, table: &PySet) -> PyHash {
        let width = self.config.long_width;
        let wrap = |value: i64| PyHash::from_long(width, value).value();
        let mut result = wrap(1927868237i64.wrapping_mul(table.len() as i64 + 1));

        for entry in table.entries() {
            let item = entry.hash.value();
            let mixed = wrap(item ^ wrap(item << 16) ^ 89869747);
            result ^= wrap(mixed.wrapping_mul(3644798167u32 as i64));
            result = wrap(result);
        }

        result = wrap(result.wrapping_mul(69069).wrapping_add(907133923));
        if result == -1 {
            result = 590923713;
        }

        PyHash::from_long(width, result)
    }

    /// `left == right` as a boolean.
    pub fn equals(&self, left: &Value, right: &Value) -> PyResult<bool> {
        if let (Value::Str(a), Value::Str(b)) = (left, right) {
            return Ok(a.as_bytes() == b.as_bytes());
        }
        if let (Value::Int(a), Value::Int(b)) = (left, right) {
            return Ok(a == b);
        }

        let result = self.compare(left, right, CompareOp::Equal)?;

        self.truthy(&result, "==")
    }

    /// Rich comparison (comparison operators and `COMPARE_OP`).
    pub fn compare(&self, left: &Value, right: &Value, operation: CompareOp) -> PyResult<Value> {
        match operation {
            CompareOp::Is => return Ok(self.identity_result(left, right, false)),
            CompareOp::IsNot => return Ok(self.identity_result(left, right, true)),
            CompareOp::In | CompareOp::NotIn => {
                let contained = self.contains(right, left)?;
                return Ok(match contained {
                    Value::Bool(flag) => Value::Bool(flag != (operation == CompareOp::NotIn)),
                    other => other,
                });
            }
            _ => {}
        }

        if left.is_unknown() {
            return Ok(left.clone());
        }
        if right.is_unknown() {
            return Ok(right.clone());
        }

        self.with_depth_in(" in cmp", || self.rich_compare(left, right, operation))
    }

    /// Rich comparison past its recursion check.
    pub(crate) fn rich_compare(&self, left: &Value, right: &Value, operation: CompareOp) -> PyResult<Value> {
        let (forward, reflected) = operation.method_names();
        let left_class = self.type_of(left);
        let right_class = self.type_of(right);
        let right_first = !std::rc::Rc::ptr_eq(&left_class, &right_class) && self.is_subclass(&right_class, &left_class)?;

        if right_first {
            if let Some(result) = self.try_rich(right, reflected, left)? {
                return Ok(result);
            }
        }
        if let Some(result) = self.try_rich(left, forward, right)? {
            return Ok(result);
        }
        if !right_first {
            if let Some(result) = self.try_rich(right, reflected, left)? {
                return Ok(result);
            }
        }

        if let Some(ordering) = self.try_cmp_hook(left, right)? {
            return Ok(Value::Bool(operation.holds(ordering)));
        }

        match self.builtin_compare(left, right, operation)? {
            Some(result) => Ok(result),
            None => {
                let ordering = self.default_order(left, right);
                Ok(Value::Bool(operation.holds(ordering)))
            }
        }
    }

    /// `left is right`. Inline values carry no object identity, so equal
    /// values whose identity CPython leaves to caching or interning give an
    /// unknown result rather than a guess.
    fn identity_result(&self, left: &Value, right: &Value, negate: bool) -> Value {
        let indeterminate = || Value::unknown("identity of equal values without tracked object identity");

        let same = match (left, right) {
            (Value::Unknown(a), Value::Unknown(b)) if Rc::ptr_eq(a, b) => true,
            (Value::Unknown(_), _) => return left.clone(),
            (_, Value::Unknown(_)) => return right.clone(),
            (Value::None, Value::None) | (Value::NotImplemented, Value::NotImplemented) | (Value::Ellipsis, Value::Ellipsis) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => {
                if a != b {
                    false
                } else if (-5..=256).contains(a) {
                    true
                } else {
                    return indeterminate();
                }
            }
            (Value::Long(a), Value::Long(b)) => {
                if a.ptr_eq(b) {
                    true
                } else if **a == **b {
                    return indeterminate();
                } else {
                    false
                }
            }
            (Value::Float(a), Value::Float(b)) => {
                if a.to_bits() == b.to_bits() {
                    return indeterminate();
                }
                false
            }
            (Value::Str(a), Value::Str(b)) => a.ptr_eq(b),
            (Value::Unicode(a), Value::Unicode(b)) => a.ptr_eq(b),
            (Value::Tuple(a), Value::Tuple(b)) => {
                if a.ptr_eq(b) || (a.is_empty() && b.is_empty()) {
                    true
                } else if a.len() == b.len() {
                    return indeterminate();
                } else {
                    false
                }
            }
            (Value::Object(a), Value::Object(b)) => Rc::ptr_eq(a, b),
            _ => false,
        };

        Value::Bool(same != negate)
    }

    fn try_rich(&self, receiver: &Value, name: &str, other: &Value) -> PyResult<Option<Value>> {
        let Some(method) = self.user_override(receiver, name)? else {
            return Ok(None);
        };

        let result = self.call1(&method, other.clone())?;

        Ok(if matches!(result, Value::NotImplemented) { None } else { Some(result) })
    }

    fn try_cmp_hook(&self, left: &Value, right: &Value) -> PyResult<Option<Ordering>> {
        for (receiver, other, flip) in [(left, right, false), (right, left, true)] {
            if self.unshared_native_compare(receiver, other)? {
                continue;
            }
            let Some(method) = self.user_override(receiver, "__cmp__")? else {
                continue;
            };
            let result = self.call1(&method, other.clone())?;
            if matches!(result, Value::NotImplemented) {
                continue;
            }
            let Some(number) = self.as_index(&result) else {
                if result.is_unknown() {
                    return Err(self.unknown_condition("__cmp__", &result));
                }
                return Err(self.type_error("comparison did not return an int"));
            };
            let ordering = number.cmp(&0);
            return Ok(Some(if flip { ordering.reverse() } else { ordering }));
        }

        Ok(None)
    }

    /// Whether the `__cmp__` of `receiver` is a native type's comparison
    /// that `other`'s type does not share. Three-way comparison calls a
    /// native comparison only when both operands have it.
    fn unshared_native_compare(&self, receiver: &Value, other: &Value) -> PyResult<bool> {
        let Value::Object(object) = receiver else {
            return Ok(false);
        };
        let class = object.class();
        if self.is_classic_class(&class) {
            return Ok(false);
        }
        let MroLookup::Found { value: compare, owner } = self.lookup_mro(&class, "__cmp__")? else {
            return Ok(false);
        };
        if !self.is_extension_type(&owner) {
            return Ok(false);
        }

        let other_class = self.type_of(other);
        if self.is_classic_class(&other_class) {
            return Ok(true);
        }
        let shared = match self.lookup_mro(&other_class, "__cmp__")? {
            MroLookup::Found { value, .. } => match (&value, &compare) {
                (Value::Object(a), Value::Object(b)) => Rc::ptr_eq(a, b),
                _ => false,
            },
            _ => false,
        };

        Ok(!shared)
    }

    /// Comparison of builtin values. `None` when the types have no builtin
    /// comparison and Python 2's default ordering applies.
    fn builtin_compare(&self, left: &Value, right: &Value, operation: CompareOp) -> PyResult<Option<Value>> {
        if let (Some(a), Some(b)) = (self.as_number(left), self.as_number(right)) {
            if matches!(a, Number::Complex(_)) || matches!(b, Number::Complex(_)) {
                let (forward, reflected) = operation.method_names();
                if !self.complex_slot_available(left, right, forward, reflected)? {
                    return Ok(None);
                }
                return self.complex_compare(&a, &b, operation).map(Some);
            }
            let ordering = compare_numbers(&a, &b);
            return Ok(Some(Value::Bool(match ordering {
                Some(ordering) => operation.holds(ordering),
                None => operation == CompareOp::NotEqual,
            })));
        }

        if let (Some(a), Some(b)) = (self.as_str_bytes(left), self.as_str_bytes(right)) {
            return Ok(Some(Value::Bool(operation.holds(a.as_bytes().cmp(b.as_bytes())))));
        }

        let left_text = self.as_text(left).or_else(|| self.as_str_bytes(left).and_then(|bytes| self.decode_default(&bytes)));
        let right_text = self.as_text(right).or_else(|| self.as_str_bytes(right).and_then(|bytes| self.decode_default(&bytes)));
        let either_unicode = self.as_text(left).is_some() || self.as_text(right).is_some();
        if either_unicode {
            if let (Some(a), Some(b)) = (&left_text, &right_text) {
                return Ok(Some(Value::Bool(operation.holds(a.units().cmp(b.units())))));
            }
            if self.as_str_bytes(left).is_some() || self.as_str_bytes(right).is_some() {
                return Ok(Some(Value::Bool(operation == CompareOp::NotEqual)));
            }
        }

        if let (Some(a), Some(b)) = (self.as_tuple(left), self.as_tuple(right)) {
            return self.compare_sequences(&a, &b, operation).map(Some);
        }

        if let (Some(a), Some(b)) = (self.as_list(left), self.as_list(right)) {
            return self.compare_sequences(&a, &b, operation).map(Some);
        }

        if let (Some(a), Some(b)) = (self.set_snapshot(left), self.set_snapshot(right)) {
            let eq = |stored: &Value, probe: &Value| self.keys_equal(stored, probe);
            let subset = a.is_subset(&b, eq)?;
            let superset = b.is_subset(&a, |stored, probe| self.keys_equal(stored, probe))?;
            let result = match operation {
                CompareOp::Equal => subset && superset,
                CompareOp::NotEqual => !(subset && superset),
                CompareOp::LessEqual => subset,
                CompareOp::Less => subset && a.len() < b.len(),
                CompareOp::GreaterEqual => superset,
                CompareOp::Greater => superset && a.len() > b.len(),
                _ => false,
            };
            return Ok(Some(Value::Bool(result)));
        }

        if let (Value::Object(a), Value::Object(b)) = (left, right)
            && let (Payload::Code(a), Payload::Code(b)) = (&a.payload, &b.payload)
            && matches!(operation, CompareOp::Equal | CompareOp::NotEqual)
        {
            let equal = self.codes_equal(a, b)?;
            return Ok(Some(Value::Bool(equal == (operation == CompareOp::Equal))));
        }

        if let (Value::Object(a), Value::Object(b)) = (left, right) {
            if let (Payload::Dict(_), Payload::Dict(_)) = (&a.payload, &b.payload) {
                if matches!(operation, CompareOp::Equal | CompareOp::NotEqual) {
                    let equal = self.dicts_equal(a, b)?;
                    return Ok(Some(Value::Bool(equal == (operation == CompareOp::Equal))));
                }
                let ordering = self.dict_three_way(a, b)?;
                return Ok(Some(Value::Bool(operation.holds(ordering))));
            }
        }

        // A dict proxy compares the proxied dict with the other
        // operand, from either side.
        let proxied = |value: &Value| match value.as_object().map(|object| &object.payload) {
            Some(Payload::DictProxy(dict)) => Some(Value::Object(Rc::clone(dict))),
            _ => None,
        };
        if let Some(dict) = proxied(left) {
            return self.compare(&dict, right, operation).map(Some);
        }
        if let Some(dict) = proxied(right) {
            return self.compare(left, &dict, operation).map(Some);
        }

        if let Some(result) = crate::interp::builtins::containers::view_compare(self, left, right, operation)? {
            return Ok(Some(result));
        }

        Ok(None)
    }

    pub(crate) fn dicts_equal(&self, left: &crate::interp::value::ObjectRef, right: &crate::interp::value::ObjectRef) -> PyResult<bool> {
        if self.dict_len(left)? != self.dict_len(right)? {
            return Ok(false);
        }

        for (key, value) in self.dict_items(left)? {
            let Some(other) = self.dict_get(right, &key)? else {
                return Ok(false);
            };
            if !self.equals(&value, &other)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Python 2 dict ordering (`dict_compare`): by size, then by the
    /// smallest key whose entry differs, then by that key's values.
    fn dict_three_way(&self, left: &crate::interp::value::ObjectRef, right: &crate::interp::value::ObjectRef) -> PyResult<Ordering> {
        let (left_len, right_len) = (self.dict_len(left)?, self.dict_len(right)?);
        if left_len != right_len {
            return Ok(left_len.cmp(&right_len));
        }

        let Some((left_key, left_value)) = self.dict_characterize(left, right)? else {
            return Ok(Ordering::Equal);
        };
        let right_diff = self.dict_characterize(right, left)?;

        let Some((right_key, right_value)) = right_diff else {
            return Ok(Ordering::Equal);
        };

        let by_key = self.ordering_of(&self.three_way_compare(&left_key, &right_key)?)?;
        if by_key != Ordering::Equal {
            return Ok(by_key);
        }

        self.ordering_of(&self.three_way_compare(&left_value, &right_value)?)
    }

    /// The smallest key of `dict` whose value is missing
    /// from or different in `other`, with its value.
    fn dict_characterize(&self, dict: &crate::interp::value::ObjectRef, other: &crate::interp::value::ObjectRef) -> PyResult<Option<(Value, Value)>> {
        let mut smallest: Option<(Value, Value)> = None;

        for (key, value) in self.dict_items(dict)? {
            if let Some((current, _)) = &smallest {
                if self.less_than(current, &key)? {
                    continue;
                }
            }
            let matches = match self.dict_get(other, &key)? {
                Some(other_value) => self.equals(&value, &other_value)?,
                None => false,
            };
            if !matches {
                smallest = Some((key, value));
            }
        }

        Ok(smallest)
    }

    fn ordering_of(&self, result: &Value) -> PyResult<Ordering> {
        match self.as_index(result) {
            Some(number) => Ok(number.cmp(&0)),
            None => Err(self.unknown_condition("comparison", result)),
        }
    }

    pub(crate) fn compare_sequences(&self, left: &[Value], right: &[Value], operation: CompareOp) -> PyResult<Value> {
        let shared = left.len().min(right.len());
        let mut index = 0;

        while index < shared {
            if !self.is_same(&left[index], &right[index]) && !self.equals(&left[index], &right[index])? {
                break;
            }
            index += 1;
        }

        if index >= shared {
            return Ok(Value::Bool(operation.holds(left.len().cmp(&right.len()))));
        }

        match operation {
            CompareOp::Equal => Ok(Value::Bool(false)),
            CompareOp::NotEqual => Ok(Value::Bool(true)),
            _ => self.compare(&left[index], &right[index], operation),
        }
    }

    /// Python 2's fallback ordering of unrelated types.
    fn default_order(&self, left: &Value, right: &Value) -> Ordering {
        let left_class = self.type_of(left);
        let right_class = self.type_of(right);

        if std::rc::Rc::ptr_eq(&left_class, &right_class) {
            return self.value_address(left).cmp(&self.value_address(right));
        }

        if left.is_none() {
            return Ordering::Less;
        }
        if right.is_none() {
            return Ordering::Greater;
        }

        let left_name = if self.is_number(left) { String::new() } else { self.class_name(&left_class) };
        let right_name = if self.is_number(right) { String::new() } else { self.class_name(&right_class) };

        match left_name.cmp(&right_name) {
            Ordering::Equal => self.address_of(&left_class).cmp(&self.address_of(&right_class)),
            ordering => ordering,
        }
    }

    pub fn value_address(&self, value: &Value) -> u64 {
        let assign = || self.next_object_id();

        match value {
            Value::Object(object) => self.address_of(object),
            Value::Tuple(items) => items.identity(assign).address(),
            Value::Str(bytes) => bytes.identity(assign).address(),
            Value::Unicode(text) => text.identity(assign).address(),
            Value::Long(number) => number.identity(assign).address(),
            Value::None => inline_address(0, 0),
            Value::NotImplemented => inline_address(1, 0),
            Value::Ellipsis => inline_address(2, 0),
            Value::Bool(flag) => inline_address(3, u64::from(*flag)),
            Value::Int(number) => inline_address(4, *number as u64),
            Value::Float(number) => inline_address(5, number.to_bits()),
            Value::Unknown(unknown) => unknown.identity(assign).address(),
        }
    }

    /// Python 2 ordering for `sorted`, `min`, and `max`: `left < right`.
    pub fn less_than(&self, left: &Value, right: &Value) -> PyResult<bool> {
        let result = self.compare(left, right, CompareOp::Less)?;

        self.truthy(&result, "<")
    }

    pub fn binary_op(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Value> {
        if left.is_unknown() {
            return Ok(left.clone());
        }
        if right.is_unknown() {
            return Ok(right.clone());
        }

        if self.uses_sequence_slots(operation, left, right)? {
            return self.sequence_binary(operation, left, right);
        }

        let (forward, reflected, _) = operation.names();
        let left_class = self.type_of(left);
        let right_class = self.type_of(right);
        let different = !std::rc::Rc::ptr_eq(&left_class, &right_class);
        let right_first = different && self.is_subclass(&right_class, &left_class)?;

        if right_first {
            if let Some(result) = self.try_rich(right, reflected, left)? {
                return Ok(result);
            }
        }
        if let Some(result) = self.try_rich(left, forward, right)? {
            return Ok(result);
        }

        if let Some(result) = self.builtin_binary(operation, left, right)? {
            return Ok(result);
        }

        if different && !right_first {
            if let Some(result) = self.try_rich(right, reflected, left)? {
                return Ok(result);
            }
        }

        // Sequence repetition, which `*` tries after the numeric
        // slots, the left operand's first.
        if operation == BinaryOp::Multiply {
            if self.has_repeat(left)? {
                return self.sequence_repeat(left, right);
            }
            if self.has_repeat(right)? {
                return self.sequence_repeat(right, left);
            }
        }

        if let Some(error) = self.sequence_operand_error(operation, left, right) {
            return Err(error);
        }

        Err(self.type_error(&format!("unsupported operand type(s) for {}: '{}' and '{}'", operation.symbol(), self.type_name(left), self.type_name(right))))
    }

    /// Whether `value`'s `name` method is the wrapper of a native type's
    /// sequence slot (concatenation, repetition, and their in-place forms).
    /// A Python class defining the method replaces the slot.
    fn sequence_slot(&self, value: &Value, name: &str) -> PyResult<bool> {
        let Value::Object(object) = value else {
            return Ok(false);
        };
        let class = object.class();
        if self.is_classic_class(&class) {
            return Ok(false);
        }

        Ok(match self.lookup_mro(&class, name)? {
            crate::interp::attr::MroLookup::Found { owner, .. } => crate::interp::builtins::has_sequence_operators(self, &owner),
            _ => false,
        })
    }

    /// Whether `operation` on these operands goes through a native type's
    /// sequence slots, which `+` and `*` reach
    /// only after every numeric slot declines: `+` with such a left
    /// operand, `*` with either.
    fn uses_sequence_slots(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<bool> {
        match operation {
            BinaryOp::Add => self.sequence_slot(left, "__add__"),
            BinaryOp::Multiply => Ok(self.sequence_slot(left, "__mul__")? || self.sequence_slot(right, "__mul__")?),
            _ => Ok(false),
        }
    }

    /// Whether `value` has a native sequence repetition slot.
    fn has_repeat(&self, value: &Value) -> PyResult<bool> {
        let builtin = matches!(value.as_object().map(|object| &object.payload), Some(Payload::List(_))) || self.as_tuple(value).is_some() || self.as_str_bytes(value).is_some() || self.as_text(value).is_some();

        Ok(builtin || self.sequence_slot(value, "__mul__")?)
    }

    /// The count of a sequence repetition: an object with `__index__`, or the
    /// operator's type error.
    fn repeat_count(&self, count: &Value) -> PyResult<i64> {
        if !count.is_unknown() && !self.is_index(count)? {
            return Err(self.type_error(&format!("can't multiply sequence by non-int of type '{}'", self.type_name(count))));
        }

        self.index_as_ssize(count, Some(ExceptionKind::OverflowError))
    }

    /// Repeats `sequence` through its native repetition slot.
    fn sequence_repeat(&self, sequence: &Value, count: &Value) -> PyResult<Value> {
        let count = self.repeat_count(count)?;
        if self.sequence_slot(sequence, "__mul__")? {
            let method = self.getattr_str(sequence, "__mul__")?;
            return self.call1(&method, Value::Int(count));
        }

        match self.repeat(sequence, count)? {
            Some(result) => Ok(result),
            None => Err(self.type_error(&format!("can't multiply sequence by non-int of type '{}'", self.type_name(sequence)))),
        }
    }

    /// `+` and `*` when a native type's sequence
    /// slot applies: the operands' numeric methods first, then the slot.
    fn sequence_binary(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Value> {
        let (forward, reflected, _) = operation.names();
        if !self.sequence_slot(left, forward)?
            && let Some(result) = self.try_rich(left, forward, right)?
        {
            return Ok(result);
        }
        let different = !Rc::ptr_eq(&self.type_of(left), &self.type_of(right));
        if different
            && !self.sequence_slot(right, reflected)?
            && let Some(result) = self.try_rich(right, reflected, left)?
        {
            return Ok(result);
        }

        if operation == BinaryOp::Add {
            let method = self.getattr_str(left, "__add__")?;
            return self.call1(&method, right.clone());
        }
        if self.has_repeat(left)? {
            return self.sequence_repeat(left, right);
        }

        self.sequence_repeat(right, left)
    }

    /// `+=` and `*=` for a native
    /// sequence's in-place slot: the right operand's numeric method, then
    /// the slot.
    fn sequence_inplace(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Value> {
        let (_, reflected, inplace) = operation.names();
        let different = !Rc::ptr_eq(&self.type_of(left), &self.type_of(right));
        if different
            && !self.sequence_slot(right, reflected)?
            && let Some(result) = self.try_rich(right, reflected, left)?
        {
            return Ok(result);
        }

        let method = self.getattr_str(left, inplace)?;
        if operation == BinaryOp::Multiply {
            let count = self.repeat_count(right)?;
            return self.call1(&method, Value::Int(count));
        }

        self.call1(&method, right.clone())
    }

    /// The errors of sequence concatenation, which `+`
    /// tries after both operands' numeric slots decline.
    fn sequence_operand_error(&self, operation: BinaryOp, left: &Value, right: &Value) -> Option<Signal> {
        let is_list = |value: &Value| matches!(value.as_object().map(|object| &object.payload), Some(Payload::List(_)));
        let right_name = self.type_name(right);

        let message = match operation {
            BinaryOp::Add if is_list(left) => format!("can only concatenate list (not \"{right_name}\") to list"),
            BinaryOp::Add if self.as_tuple(left).is_some() => format!("can only concatenate tuple (not \"{right_name}\") to tuple"),
            BinaryOp::Add if self.as_str_bytes(left).is_some() => format!("cannot concatenate '{}' and '{right_name}' objects", self.type_name(left)),
            BinaryOp::Add if self.as_text(left).is_some() => format!("coercing to Unicode: need string or buffer, {right_name} found"),
            _ => return None,
        };

        Some(self.type_error(&message))
    }

    pub fn inplace_op(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Value> {
        if left.is_unknown() {
            return Ok(left.clone());
        }
        if right.is_unknown() {
            return Ok(right.clone());
        }

        let (_, _, inplace) = operation.names();
        if matches!(operation, BinaryOp::Add | BinaryOp::Multiply) && self.sequence_slot(left, inplace)? {
            return self.sequence_inplace(operation, left, right);
        }
        if let Some(result) = self.try_rich(left, inplace, right)? {
            return Ok(result);
        }

        if let Value::Object(object) = left {
            match (&object.payload, operation) {
                (Payload::List(items), BinaryOp::Add) => {
                    let extra = self.collect(right)?;
                    items.borrow_mut().extend(extra);
                    return Ok(left.clone());
                }
                (Payload::List(items), BinaryOp::Multiply) => {
                    let count = self.repeat_count(right)?;
                    let copy = items.borrow().clone();
                    let mut repeated = Vec::new();
                    for _ in 0..count.max(0) {
                        repeated.extend(copy.iter().cloned());
                    }
                    *items.borrow_mut() = repeated;
                    return Ok(left.clone());
                }
                (Payload::Set(_), BinaryOp::Or | BinaryOp::And | BinaryOp::Xor | BinaryOp::Subtract) if self.set_snapshot(right).is_some() => {
                    let method = match operation {
                        BinaryOp::Or => "update",
                        BinaryOp::And => "intersection_update",
                        BinaryOp::Xor => "symmetric_difference_update",
                        _ => "difference_update",
                    };
                    let bound = self.getattr_str(left, method)?;
                    self.call1(&bound, right.clone())?;
                    return Ok(left.clone());
                }
                _ => {}
            }
        }

        self.binary_op(operation, left, right)
    }

    fn builtin_binary(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Option<Value>> {
        if let (Some(a), Some(b)) = (self.as_number(left), self.as_number(right)) {
            let integer_only = matches!(operation, BinaryOp::LeftShift | BinaryOp::RightShift | BinaryOp::And | BinaryOp::Xor | BinaryOp::Or);
            let integral = |number: &Number| matches!(number, Number::Integral(..));
            if integer_only && !(integral(&a) && integral(&b)) {
                return Ok(None);
            }
            if matches!(a, Number::Complex(_)) || matches!(b, Number::Complex(_)) {
                let (forward, reflected, _) = operation.names();
                if !self.complex_slot_available(left, right, forward, reflected)? {
                    return Ok(None);
                }
            }
            return self.numeric_binary(operation, a, b).map(Some);
        }

        match operation {
            BinaryOp::Add => self.concatenate(left, right),
            BinaryOp::Multiply => {
                if let Some(count) = self.as_index(right) {
                    if let Some(result) = self.repeat(left, count)? {
                        return Ok(Some(result));
                    }
                }
                if let Some(count) = self.as_index(left) {
                    return self.repeat(right, count);
                }
                Ok(None)
            }
            BinaryOp::Modulo => {
                if self.as_str_bytes(left).is_some() || self.as_text(left).is_some() {
                    return self.format_percent(left, right).map(Some);
                }
                Ok(None)
            }
            BinaryOp::Or | BinaryOp::And | BinaryOp::Xor | BinaryOp::Subtract => self.set_binary(operation, left, right),
            _ => Ok(None),
        }
    }

    fn set_binary(&self, operation: BinaryOp, left: &Value, right: &Value) -> PyResult<Option<Value>> {
        crate::interp::builtins::containers::set_binary(self, operation, left, right)
    }

    pub(crate) fn concatenate(&self, left: &Value, right: &Value) -> PyResult<Option<Value>> {
        if let (Some(a), Some(b)) = (self.as_str_bytes(left), self.as_str_bytes(right)) {
            // `str` concatenation returns an empty operand's partner when both are exact.
            if matches!((left, right), (Value::Str(_), Value::Str(_))) {
                if a.as_bytes().is_empty() {
                    return Ok(Some(right.clone()));
                }
                if b.as_bytes().is_empty() {
                    return Ok(Some(left.clone()));
                }
            }
            let mut joined = a.as_bytes().to_vec();
            joined.extend_from_slice(b.as_bytes());
            return Ok(Some(Value::Str(PyBytes::allocate(joined))));
        }

        // `str + bytearray` gives a bytearray; `unicode + bytearray`
        // refuses to decode the bytearray.
        if let (Some(a), Some(b)) = (self.as_str_bytes(left), self.as_bytearray(right)) {
            let mut joined = a.as_bytes().to_vec();
            joined.extend_from_slice(&b);
            return Ok(Some(self.new_bytearray(joined)));
        }
        if self.as_text(left).is_some() && self.as_bytearray(right).is_some() {
            return Err(self.type_error("decoding bytearray is not supported"));
        }

        if self.as_text(left).is_some() || self.as_text(right).is_some() {
            // Concatenation with a unicode left operand takes any
            // character buffer on the right.
            let right_text = if self.as_text(left).is_some() { self.unicode_from_object(right)? } else { self.coerce_text(right)? };
            let (Some(a), Some(b)) = (self.coerce_text(left)?, right_text) else {
                return Ok(None);
            };

            // Conversion to unicode copies a subclass instance, and
            // concatenation returns one operand when the other is empty.
            let converted = |value: &Value, text: PyText| if matches!(value, Value::Object(_)) { PyText::new(text.units()) } else { text };
            let (a, b) = (converted(left, a), converted(right, b));
            if b.is_shared_empty() {
                return Ok(Some(Value::Unicode(a)));
            }
            if a.is_shared_empty() {
                return Ok(Some(Value::Unicode(b)));
            }
            let mut joined = a.units().to_vec();
            joined.extend_from_slice(b.units());
            return Ok(Some(Value::Unicode(PyText::new_unshared(joined))));
        }

        if let (Some(a), Some(b)) = (self.as_tuple(left), self.as_tuple(right)) {
            let mut joined = a.to_vec();
            joined.extend(b.iter().cloned());
            return Ok(Some(Value::tuple(joined)));
        }

        if let (Some(a), Some(b)) = (self.as_list(left), self.as_list(right)) {
            let mut joined = a;
            joined.extend(b);
            return Ok(Some(self.new_list(joined)));
        }

        Ok(None)
    }

    fn repeat(&self, sequence: &Value, count: i64) -> PyResult<Option<Value>> {
        let count = usize::try_from(count).unwrap_or(0);

        if let Some(bytes) = self.as_str_bytes(sequence) {
            // `str` repetition returns an exact string whose length would not change.
            if matches!(sequence, Value::Str(_)) && (count == 1 || bytes.as_bytes().is_empty()) {
                return Ok(Some(sequence.clone()));
            }
            return Ok(Some(Value::Str(PyBytes::allocate(bytes.as_bytes().repeat(count)))));
        }
        if let Some(text) = self.as_text(sequence) {
            // `unicode` repetition returns an exact string repeated once.
            if matches!(sequence, Value::Unicode(_)) && count == 1 {
                return Ok(Some(sequence.clone()));
            }
            return Ok(Some(Value::Unicode(PyText::new_unshared(text.units().repeat(count)))));
        }
        if let Some(items) = self.as_tuple(sequence) {
            return Ok(Some(Value::tuple(repeat_values(&items, count))));
        }
        if let Some(items) = self.as_list(sequence) {
            return Ok(Some(self.new_list(repeat_values(&items, count))));
        }

        Ok(None)
    }

    fn numeric_binary(&self, operation: BinaryOp, left: Number, right: Number) -> PyResult<Value> {
        match (left, right) {
            (Number::Integral(a, a_bool), Number::Integral(b, b_bool)) => {
                if a_bool && b_bool && matches!(operation, BinaryOp::And | BinaryOp::Or | BinaryOp::Xor) {
                    let a = !a.to_bigint().is_zero();
                    let b = !b.to_bigint().is_zero();
                    let result = match operation {
                        BinaryOp::And => a & b,
                        BinaryOp::Or => a | b,
                        _ => a ^ b,
                    };
                    return Ok(Value::Bool(result));
                }
                let long_result = a.is_long() || b.is_long();
                self.integer_binary(operation, &a.to_bigint(), &b.to_bigint(), long_result)
            }
            (a @ Number::Complex(_), b) | (a, b @ Number::Complex(_)) => {
                let a = self.number_to_complex(a)?;
                let b = self.number_to_complex(b)?;
                self.complex_binary(operation, a, b)
            }
            (a, b) => {
                let a = self.number_to_float(a)?;
                let b = self.number_to_float(b)?;
                self.float_binary(operation, a, b)
            }
        }
    }

    /// Whether a builtin `complex` slot still handles an operation: an
    /// operand typed `complex` whose class does not override the method for
    /// its side. A subclass override that declined replaces the slot.
    fn complex_slot_available(&self, left: &Value, right: &Value, forward: &str, reflected: &str) -> PyResult<bool> {
        if self.as_complex(left).is_some() && self.user_override(left, forward)?.is_none() {
            return Ok(true);
        }

        Ok(self.as_complex(right).is_some() && self.user_override(right, reflected)?.is_none())
    }

    /// `to_complex`: an operand of a `complex` slot.
    fn number_to_complex(&self, number: Number) -> PyResult<Complex> {
        match number {
            Number::Complex(value) => Ok(value),
            other => Ok(Complex::new(self.number_to_float(other)?, 0.0)),
        }
    }

    /// The binary arithmetic operators of `complex`.
    fn complex_binary(&self, operation: BinaryOp, a: Complex, b: Complex) -> PyResult<Value> {
        let value = match operation {
            BinaryOp::Add => a.sum(b),
            BinaryOp::Subtract => a.diff(b),
            BinaryOp::Multiply => a.prod(b),
            BinaryOp::Divide | BinaryOp::TrueDivide => {
                let quotient = a.quot(b);
                if quotient.errno == Errno::Domain {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "complex division by zero"));
                }
                quotient.value
            }
            BinaryOp::Modulo => {
                self.complex_divmod_warning()?;
                let Some((_, remainder)) = a.divmod(b) else {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "complex remainder"));
                };
                remainder
            }
            BinaryOp::FloorDivide => {
                // `//` warns, then computes `divmod`,
                // which warns again.
                self.complex_divmod_warning()?;
                return self.complex_divmod(a, b).map(|(quotient, _)| quotient);
            }
            BinaryOp::Power => {
                let power = a.power(b);
                match power.errno {
                    Errno::Domain => return Err(self.raise(ExceptionKind::ZeroDivisionError, "0.0 to a negative or complex power")),
                    Errno::Range => return Err(self.raise(ExceptionKind::OverflowError, "complex exponentiation")),
                    Errno::Ok => power.value,
                }
            }
            _ => return Err(self.type_error(&format!("unsupported operand type(s) for {}: 'complex' and 'complex'", operation.symbol()))),
        };

        Ok(self.new_complex(value))
    }

    fn complex_divmod_warning(&self) -> PyResult<()> {
        crate::interp::builtins::modules::warnings::warn_caller(self, ExceptionKind::DeprecationWarning, "complex divmod(), // and % are deprecated")
    }

    /// `complex_divmod`.
    fn complex_divmod(&self, a: Complex, b: Complex) -> PyResult<(Value, Value)> {
        self.complex_divmod_warning()?;
        let Some((quotient, remainder)) = a.divmod(b) else {
            return Err(self.raise(ExceptionKind::ZeroDivisionError, "complex divmod()"));
        };

        Ok((self.new_complex(quotient), self.new_complex(remainder)))
    }

    /// `divmod(left, right)` for builtin numbers.
    /// `None` when an operand is not one.
    pub fn number_divmod(&self, left: &Value, right: &Value) -> PyResult<Option<Value>> {
        let (Some(a), Some(b)) = (self.as_number(left), self.as_number(right)) else {
            return Ok(None);
        };

        if !matches!(a, Number::Complex(_)) && !matches!(b, Number::Complex(_)) {
            let quotient = self.binary_op(BinaryOp::FloorDivide, left, right)?;
            let remainder = self.binary_op(BinaryOp::Modulo, left, right)?;
            return Ok(Some(Value::tuple(vec![quotient, remainder])));
        }

        let a = self.number_to_complex(a)?;
        let b = self.number_to_complex(b)?;
        let (quotient, remainder) = self.complex_divmod(a, b)?;

        Ok(Some(Value::tuple(vec![quotient, remainder])))
    }

    /// Comparison of complex numbers: only equality is defined; ordering against a
    /// builtin number is an error.
    fn complex_compare(&self, a: &Number, b: &Number, operation: CompareOp) -> PyResult<Value> {
        if !matches!(operation, CompareOp::Equal | CompareOp::NotEqual) {
            return Err(self.type_error("no ordering relation is defined for complex numbers"));
        }

        let equal = match (a, b) {
            (Number::Complex(x), Number::Complex(y)) => x.real == y.real && x.imag == y.imag,
            (Number::Complex(x), Number::Float(y)) | (Number::Float(y), Number::Complex(x)) => x.real == *y && x.imag == 0.0,
            (Number::Complex(x), integral @ Number::Integral(..)) | (integral @ Number::Integral(..), Number::Complex(x)) => {
                x.imag == 0.0 && compare_numbers(&Number::Float(x.real), integral) == Some(Ordering::Equal)
            }
            _ => false,
        };

        Ok(Value::Bool(equal == (operation == CompareOp::Equal)))
    }

    fn number_to_float(&self, number: Number) -> PyResult<f64> {
        match number {
            Number::Complex(_) => Err(self.type_error("can't convert complex to float")),
            Number::Float(value) => Ok(value),
            Number::Integral(Integral::Int(value), _) => Ok(value as f64),
            Number::Integral(Integral::Long(value), _) => numbers::bigint_to_f64(&value).ok_or_else(|| self.raise(ExceptionKind::OverflowError, "long int too large to convert to float")),
        }
    }

    /// Result of an integer operation: `long` when an operand was a `long`,
    /// otherwise `int` unless it overflows C `long`.
    fn integer_result(&self, value: BigInt, long_result: bool) -> Value {
        if long_result {
            return Value::long(value);
        }

        self.new_int(value)
    }

    fn integer_binary(&self, operation: BinaryOp, a: &BigInt, b: &BigInt, long_result: bool) -> PyResult<Value> {
        let zero_division = || self.raise(ExceptionKind::ZeroDivisionError, if long_result { "long division or modulo by zero" } else { "integer division or modulo by zero" });

        let value = match operation {
            BinaryOp::Add => a + b,
            BinaryOp::Subtract => a - b,
            BinaryOp::Multiply => a * b,
            BinaryOp::Divide | BinaryOp::FloorDivide => numbers::floor_divmod(a, b).ok_or_else(zero_division)?.0,
            BinaryOp::Modulo => numbers::floor_divmod(a, b).ok_or_else(zero_division)?.1,
            BinaryOp::TrueDivide => {
                if b.is_zero() {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "division by zero"));
                }
                let Some(quotient) = numbers::true_divide(a, b) else {
                    return Err(self.raise(ExceptionKind::OverflowError, "integer division result too large for a float"));
                };
                return Ok(Value::Float(quotient));
            }
            BinaryOp::Power => match numbers::int_pow(a, b) {
                Some(value) => value,
                None => {
                    let (Some(x), Some(y)) = (numbers::bigint_to_f64(a), numbers::bigint_to_f64(b)) else {
                        return Err(self.raise(ExceptionKind::OverflowError, "long int too large to convert to float"));
                    };
                    if x == 0.0 {
                        return Err(self.raise(ExceptionKind::ZeroDivisionError, "0.0 cannot be raised to a negative power"));
                    }
                    return Ok(Value::Float(x.powf(y)));
                }
            },
            BinaryOp::LeftShift | BinaryOp::RightShift => {
                if b.is_negative() {
                    return Err(self.raise(ExceptionKind::ValueError, "negative shift count"));
                }
                let Some(shift) = b.to_usize() else {
                    return Err(self.raise(ExceptionKind::OverflowError, "shift count too large"));
                };
                if operation == BinaryOp::LeftShift { a << shift } else { a >> shift }
            }
            BinaryOp::And => a & b,
            BinaryOp::Or => a | b,
            BinaryOp::Xor => a ^ b,
        };

        Ok(self.integer_result(value, long_result))
    }

    fn float_binary(&self, operation: BinaryOp, a: f64, b: f64) -> PyResult<Value> {
        let value = match operation {
            BinaryOp::Add => a + b,
            BinaryOp::Subtract => a - b,
            BinaryOp::Multiply => a * b,
            BinaryOp::Divide | BinaryOp::TrueDivide => {
                if b == 0.0 {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "float division by zero"));
                }
                a / b
            }
            BinaryOp::FloorDivide => {
                if b == 0.0 {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "float divmod()"));
                }
                numbers::float_floor_div(a, b)
            }
            BinaryOp::Modulo => {
                if b == 0.0 {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "float modulo"));
                }
                numbers::float_mod(a, b)
            }
            BinaryOp::Power => {
                // `float.__pow__` returns a NaN operand itself; libm `pow` may not.
                if b != 0.0 && a.is_nan() {
                    return Ok(Value::Float(a));
                }
                if b.is_nan() {
                    return Ok(Value::Float(if a == 1.0 { 1.0 } else { b }));
                }
                if a == 0.0 && b < 0.0 {
                    return Err(self.raise(ExceptionKind::ZeroDivisionError, "0.0 cannot be raised to a negative power"));
                }
                if a < 0.0 && b.fract() != 0.0 {
                    return Err(self.raise(ExceptionKind::ValueError, "negative number cannot be raised to a fractional power"));
                }
                a.powf(b)
            }
            _ => return Err(self.type_error(&format!("unsupported operand type(s) for {}: 'float' and 'float'", operation.symbol()))),
        };

        Ok(Value::Float(value))
    }

    pub fn positive(&self, operand: &Value) -> PyResult<Value> {
        if operand.is_unknown() {
            return Ok(operand.clone());
        }
        if let Some(method) = self.user_override(operand, "__pos__")? {
            return self.call0(&method);
        }

        match self.as_number(operand) {
            // Unary `+` returns an exact complex itself.
            Some(Number::Complex(_)) if Rc::ptr_eq(&self.type_of(operand), &self.types().complex) => Ok(operand.clone()),
            Some(Number::Complex(value)) => Ok(self.new_complex(value)),
            Some(Number::Float(value)) => Ok(Value::Float(value)),
            Some(Number::Integral(Integral::Int(value), _)) => Ok(Value::Int(value)),
            Some(Number::Integral(Integral::Long(value), _)) => Ok(Value::long(value)),
            None => Err(self.type_error(&format!("bad operand type for unary +: '{}'", self.type_name(operand)))),
        }
    }

    pub fn negative(&self, operand: &Value) -> PyResult<Value> {
        if operand.is_unknown() {
            return Ok(operand.clone());
        }
        if let Some(method) = self.user_override(operand, "__neg__")? {
            return self.call0(&method);
        }

        match self.as_number(operand) {
            Some(Number::Complex(value)) => Ok(self.new_complex(-value)),
            Some(Number::Float(value)) => Ok(Value::Float(-value)),
            Some(Number::Integral(Integral::Int(value), _)) => Ok(self.new_int(-BigInt::from(value))),
            Some(Number::Integral(Integral::Long(value), _)) => Ok(Value::long(-value)),
            None => Err(self.type_error(&format!("bad operand type for unary -: '{}'", self.type_name(operand)))),
        }
    }

    pub fn invert(&self, operand: &Value) -> PyResult<Value> {
        if operand.is_unknown() {
            return Ok(operand.clone());
        }
        if let Some(method) = self.user_override(operand, "__invert__")? {
            return self.call0(&method);
        }

        match self.as_integral(operand) {
            Some(Integral::Int(value)) => Ok(Value::Int(!value)),
            Some(Integral::Long(value)) => Ok(Value::long(-value - 1)),
            None => Err(self.type_error(&format!("bad operand type for unary ~: '{}'", self.type_name(operand)))),
        }
    }

    /// Decodes a byte string with the default encoding; `None` when it does
    /// not decode, where CPython's comparisons warn and treat the operands
    /// as unequal.
    pub fn decode_default(&self, bytes: &PyBytes) -> Option<PyText> {
        if bytes.as_bytes().is_ascii() {
            return Some(PyText::new(bytes.as_bytes().iter().map(|byte| u16::from(*byte)).collect::<Vec<u16>>()));
        }

        crate::interp::builtins::text::codecs::decode_default(self, bytes.as_bytes()).ok()
    }

    /// `unicode` coercion of a `str` or `unicode` operand for mixed
    /// operations; `None` for other types.
    pub fn coerce_text(&self, value: &Value) -> PyResult<Option<PyText>> {
        if let Some(text) = self.as_text(value) {
            return Ok(Some(text));
        }

        let Some(bytes) = self.as_str_bytes(value) else {
            return Ok(None);
        };

        crate::interp::builtins::text::codecs::decode_default(self, bytes.as_bytes()).map(Some)
    }
}

fn repeat_values(items: &[Value], count: usize) -> Vec<Value> {
    let mut repeated = Vec::with_capacity(items.len() * count);

    for _ in 0..count {
        repeated.extend(items.iter().cloned());
    }

    repeated
}

fn compare_numbers(left: &Number, right: &Number) -> Option<Ordering> {
    match (left, right) {
        (Number::Integral(a, _), Number::Integral(b, _)) => Some(a.to_bigint().cmp(&b.to_bigint())),
        (Number::Float(a), Number::Float(b)) => a.partial_cmp(b),
        (Number::Float(a), Number::Integral(b, _)) => compare_float_integral(*a, &b.to_bigint()),
        (Number::Integral(a, _), Number::Float(b)) => compare_float_integral(*b, &a.to_bigint()).map(Ordering::reverse),
        // Complex numbers have no ordering.
        (Number::Complex(_), _) | (_, Number::Complex(_)) => None,
    }
}

/// Exact comparison of a float with an integer, without converting either.
fn compare_float_integral(float: f64, integer: &BigInt) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float.is_infinite() {
        return Some(if float > 0.0 { Ordering::Greater } else { Ordering::Less });
    }

    let floor = float.floor();
    let whole = num_bigint::BigInt::from(floor as i128);
    let whole = if (floor as i128) as f64 == floor { whole } else { num_traits::FromPrimitive::from_f64(floor).unwrap_or(whole) };

    match whole.cmp(integer) {
        Ordering::Equal if float > floor => Some(Ordering::Greater),
        ordering => Some(ordering),
    }
}

impl Vm {
    /// Calls a method by name with positional arguments.
    pub fn call_method(&self, target: &Value, name: &str, positional: Vec<Value>) -> PyResult<Value> {
        let method = self.getattr_str(target, name)?;

        self.call(&method, CallArgs::new(positional))
    }
}

/// An address for a value the interpreter stores inline. Equal values share
/// it, as CPython's cached small ints and singletons do. The range lies
/// above the addresses of values with an `ObjectId`.
fn inline_address(tag: u64, bits: u64) -> u64 {
    let mut mixed = bits.wrapping_add(tag.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^= mixed >> 31;

    0x4000_0000_0000_0000 | (mixed & 0x3FFF_FFFF_FFFF_FFF0)
}

impl Vm {
    /// `==` on code objects.
    fn codes_equal(&self, a: &CodeObject, b: &CodeObject) -> PyResult<bool> {
        let names_equal = |a: &[PyBytes], b: &[PyBytes]| a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.as_bytes() == b.as_bytes());
        if a.name.as_bytes() != b.name.as_bytes() || a.argcount != b.argcount || a.nlocals != b.nlocals || a.flags != b.flags || a.firstlineno != b.firstlineno || a.code != b.code {
            return Ok(false);
        }
        let consts_a = self.code_constant_key(&Value::tuple(a.consts.clone()))?;
        let consts_b = self.code_constant_key(&Value::tuple(b.consts.clone()))?;
        if !self.keys_equal(&consts_a, &consts_b)? {
            return Ok(false);
        }

        Ok(names_equal(&a.names, &b.names) && names_equal(&a.varnames, &b.varnames) && names_equal(&a.freevars, &b.freevars) && names_equal(&a.cellvars, &b.cellvars))
    }

    /// The key that deduplicates code constants: tags each constant with its type so that
    /// `0`, `0.0`, `-0.0` and `False` compare unequal; other objects
    /// compare by identity.
    fn code_constant_key(&self, value: &Value) -> PyResult<Value> {
        let class = self.type_value(value);
        let negative_zero = |number: f64| number == 0.0 && number.is_sign_negative();
        let key = match value {
            Value::None | Value::Int(_) | Value::Long(_) | Value::Bool(_) | Value::Str(_) | Value::Unicode(_) => vec![class, value.clone()],
            Value::Float(number) if negative_zero(*number) => vec![class, value.clone(), Value::None],
            Value::Float(_) => vec![class, value.clone()],
            Value::Tuple(items) => {
                let keys = items.iter().map(|item| self.code_constant_key(item)).collect::<PyResult<Vec<_>>>()?;
                vec![class, value.clone(), Value::tuple(keys)]
            }
            Value::Object(object) => match &object.payload {
                Payload::Code(_) => vec![class, value.clone()],
                Payload::Complex(number) if self.is_builtin_type(&object.class()) => {
                    let tag = match (negative_zero(number.real), negative_zero(number.imag)) {
                        (true, true) => Some(Value::Bool(true)),
                        (false, true) => Some(Value::Bool(false)),
                        (true, false) => Some(Value::None),
                        (false, false) => None,
                    };
                    let mut key = vec![class, value.clone()];
                    key.extend(tag);
                    key
                }
                Payload::FrozenSet(_) if Rc::ptr_eq(&object.class(), &self.types().frozenset) => {
                    let items = self.set_items(value).unwrap_or_default();
                    let keys = items.iter().map(|item| self.code_constant_key(item)).collect::<PyResult<Vec<_>>>()?;
                    let set = self.new_frozenset_from(&Value::tuple(keys))?;
                    vec![class, value.clone(), set]
                }
                _ => vec![class, value.clone(), self.new_int_from_i64(self.value_address(value) as i64)],
            },
            _ => vec![class, value.clone(), self.new_int_from_i64(self.value_address(value) as i64)],
        };

        Ok(Value::tuple(key))
    }

    /// `code_hash`.
    fn code_hash(&self, code: &CodeObject) -> PyResult<PyHash> {
        let names = |names: &[PyBytes]| Value::tuple(names.iter().cloned().map(Value::Str).collect());
        let parts = [
            Value::Str(code.name.clone()),
            Value::Str(PyBytes::new(code.code.clone())),
            Value::tuple(code.consts.clone()),
            names(&code.names),
            names(&code.varnames),
            names(&code.freevars),
            names(&code.cellvars),
        ];
        let mut hash = i64::from(code.argcount) ^ i64::from(code.nlocals) ^ i64::from(code.flags.0.cast_signed());
        for part in &parts {
            hash ^= self.hash(part)?.value();
        }

        Ok(PyHash::from_long(self.config.long_width, hash))
    }
}
