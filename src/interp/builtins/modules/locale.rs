//! `_locale` of the Windows build. The process starts in the C locale; any
//! other locale depends on the host, so its results are unknown.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::rc::Rc;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::modules::codecs::args;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::set_attribute;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::host::Denial;
use crate::interp::host::HostCapability;
use crate::interp::object::CallArgs;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// Locale categories with the values of the Microsoft C runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    All,
    Collate,
    Ctype,
    Monetary,
    Numeric,
    Time,
}

impl Category {
    /// The categories `LC_ALL` comprises, in index order.
    const SINGLE: [Self; 5] = [Self::Collate, Self::Ctype, Self::Monetary, Self::Numeric, Self::Time];

    fn from_number(number: i32) -> Option<Self> {
        match number {
            0 => Some(Self::All),
            1 => Some(Self::Collate),
            2 => Some(Self::Ctype),
            3 => Some(Self::Monetary),
            4 => Some(Self::Numeric),
            5 => Some(Self::Time),
            _ => None,
        }
    }

    fn number(self) -> i64 {
        match self {
            Self::All => 0,
            Self::Collate => 1,
            Self::Ctype => 2,
            Self::Monetary => 3,
            Self::Numeric => 4,
            Self::Time => 5,
        }
    }

    /// The slot of a single category in `LocaleState::categories`.
    fn index(self) -> Option<usize> {
        Self::SINGLE.iter().position(|category| *category == self)
    }
}

/// The locale a category is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setting {
    C,
    /// A locale whose behavior and name depend on the host.
    Host,
}

/// The C runtime locale of the interpreter's process.
struct LocaleState {
    categories: RefCell<[Setting; 5]>,
    error: RefCell<Option<ObjectRef>>,
}

impl Default for LocaleState {
    fn default() -> Self {
        Self { categories: RefCell::new([Setting::C; 5]), error: RefCell::new(None) }
    }
}

impl LocaleState {
    fn setting(&self, category: Category) -> Setting {
        let categories = self.categories.borrow();
        match category.index() {
            Some(index) => categories[index],
            None if categories.iter().all(|setting| *setting == Setting::C) => Setting::C,
            None => Setting::Host,
        }
    }

    fn set(&self, category: Category, setting: Setting) {
        let mut categories = self.categories.borrow_mut();
        match category.index() {
            Some(index) => categories[index] = setting,
            None => *categories = [setting; 5],
        }
    }
}

/// Whether `LC_CTYPE` is the C locale, so character classification is
/// ASCII.
pub fn ctype_is_c(vm: &Vm) -> bool {
    vm.native_state::<LocaleState>().setting(Category::Ctype) == Setting::C
}

/// Whether `LC_TIME` is the C locale, whose `strftime` names are fixed.
pub fn time_is_c(vm: &Vm) -> bool {
    vm.native_state::<LocaleState>().setting(Category::Time) == Setting::C
}

/// The characters of the C locale's `isupper`, `islower`, and `isalpha`.
pub const C_UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const C_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const C_LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `CHAR_MAX` of a signed `char`.
const CHAR_MAX: i64 = 127;

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    const FUNCTIONS: &[MethodSpec] = &[function("setlocale", setlocale), function("localeconv", localeconv), function("strcoll", strcoll), function("strxfrm", strxfrm), function("_getdefaultlocale", getdefaultlocale)];
    install_functions(vm, module, FUNCTIONS)?;

    for (name, category) in [("LC_CTYPE", Category::Ctype), ("LC_TIME", Category::Time), ("LC_COLLATE", Category::Collate), ("LC_MONETARY", Category::Monetary), ("LC_NUMERIC", Category::Numeric), ("LC_ALL", Category::All)] {
        set_attribute(vm, module, name, Value::Int(category.number()))?;
    }
    set_attribute(vm, module, "CHAR_MAX", Value::Int(CHAR_MAX))?;

    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "locale", "Error", &base)?;
    *vm.native_state::<LocaleState>().error.borrow_mut() = Some(Rc::clone(&error));
    set_attribute(vm, module, "Error", Value::Object(error))
}

/// A `locale.Error`.
fn locale_error(vm: &Vm, message: &str) -> Signal {
    let Some(class) = vm.native_state::<LocaleState>().error.borrow().clone() else {
        return vm.halt_unsupported("locale.Error before _locale initialization");
    };

    vm.raise_string(&class, Value::str(message))
}

/// `setlocale(category[, locale])`: queries or sets a category. Only the C
/// locale has a known name and behavior.
fn setlocale(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "setlocale", 1, 2)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let number = args::c_int(vm, &args[0])?;
    let locale = args::optional_string(vm, "setlocale", 2, args.get(1))?;
    let Some(category) = Category::from_number(number) else {
        return Err(locale_error(vm, "invalid locale category"));
    };

    let state = vm.native_state::<LocaleState>();
    let Some(locale) = locale else {
        return Ok(match state.setting(category) {
            Setting::C => Value::str("C"),
            Setting::Host => Value::unknown("setlocale: host locale name"),
        });
    };

    let setting = if locale.as_bytes() == b"C" { Setting::C } else { Setting::Host };
    if setting == Setting::Host {
        vm.host_permit(HostCapability::Environment, Denial::Native, None)?;
    }
    state.set(category, setting);
    if matches!(category, Category::Ctype | Category::All) {
        fixup_ulcase(vm, setting)?;
    }

    Ok(match setting {
        Setting::C => Value::str("C"),
        Setting::Host => Value::unknown("setlocale: host locale"),
    })
}

/// Refreshes the case tables of `string` and `strop` after
/// `LC_CTYPE` changes.
fn fixup_ulcase(vm: &Vm, setting: Setting) -> PyResult<()> {
    let modules = vm.modules();
    let module_dict = |name: &str| -> PyResult<Option<ObjectRef>> {
        match vm.dict_get_str(modules, name)? {
            Some(Value::Object(module)) if module.as_module().is_some() => Ok(Some(vm.instance_dict(&module)?)),
            _ => Ok(None),
        }
    };
    let string = module_dict("string")?;
    let strop = module_dict("strop")?;

    let table = |text: &str| match setting {
        Setting::C => Value::str(text),
        Setting::Host => Value::unknown("character classes of the host locale"),
    };
    for dict in [&string, &strop].into_iter().flatten() {
        vm.dict_set_str(dict, "uppercase", table(C_UPPERCASE))?;
        vm.dict_set_str(dict, "lowercase", table(C_LOWERCASE))?;
    }
    if let Some(string) = &string {
        vm.dict_set_str(string, "letters", table(C_LETTERS))?;
    }

    Ok(())
}

/// `localeconv()`: the numeric and monetary conventions of the C locale.
fn localeconv(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    args::no_arguments(vm, &args, 0, "localeconv")?;

    let state = vm.native_state::<LocaleState>();
    if state.setting(Category::Numeric) == Setting::Host || state.setting(Category::Monetary) == Setting::Host {
        return Ok(Value::unknown("localeconv of the host locale"));
    }

    let dict = vm.new_dict();
    let strings = [("decimal_point", "."), ("thousands_sep", "")];
    for (key, value) in strings {
        vm.dict_set_str(&dict, key, Value::str(value))?;
    }
    vm.dict_set_str(&dict, "grouping", vm.new_list(Vec::new()))?;

    let monetary = [("int_curr_symbol", ""), ("currency_symbol", ""), ("mon_decimal_point", ""), ("mon_thousands_sep", "")];
    for (key, value) in monetary {
        vm.dict_set_str(&dict, key, Value::str(value))?;
    }
    vm.dict_set_str(&dict, "mon_grouping", vm.new_list(Vec::new()))?;
    for key in ["positive_sign", "negative_sign"] {
        vm.dict_set_str(&dict, key, Value::str(""))?;
    }
    for key in ["int_frac_digits", "frac_digits", "p_cs_precedes", "p_sep_by_space", "n_cs_precedes", "n_sep_by_space", "p_sign_posn", "n_sign_posn"] {
        vm.dict_set_str(&dict, key, Value::Int(CHAR_MAX))?;
    }

    Ok(Value::Object(dict))
}

fn ordering_value(ordering: Ordering) -> Value {
    Value::Int(match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    })
}

/// The part of a C string before its first NUL.
fn before_nul<T: Copy + Default + PartialEq>(items: &[T]) -> &[T] {
    let end = items.iter().position(|item| *item == T::default()).unwrap_or(items.len());

    &items[..end]
}

/// `strcoll(a, b)`: `strcoll` for two byte strings, `wcscoll` otherwise;
/// in the C locale both compare code values.
fn strcoll(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::unpack(vm, args, "strcoll", 2, 2)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }
    if vm.native_state::<LocaleState>().setting(Category::Collate) == Setting::Host {
        return Ok(Value::unknown("strcoll in the host locale"));
    }

    if let (Some(left), Some(right)) = (vm.as_str_bytes(&args[0]), vm.as_str_bytes(&args[1])) {
        return Ok(ordering_value(before_nul(left.as_bytes()).cmp(before_nul(right.as_bytes()))));
    }

    let left = args::to_unicode(vm, &args[0])?;
    let right = args::to_unicode(vm, &args[1])?;

    Ok(ordering_value(before_nul(left.units()).cmp(before_nul(right.units()))))
}

/// `strxfrm(s)`: the identity in the C locale.
fn strxfrm(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = args::varargs(vm, args, "strxfrm", 1, 1)?;
    if let Some(unknown) = args::first_unknown(&args) {
        return Ok(unknown);
    }

    let string = args::c_string(vm, "strxfrm", 1, &args[0])?;
    if vm.native_state::<LocaleState>().setting(Category::Collate) == Setting::Host {
        return Ok(Value::unknown("strxfrm in the host locale"));
    }

    Ok(Value::Str(PyBytes::new(string.as_bytes())))
}

/// `_getdefaultlocale()`: the user's language and ANSI code page.
fn getdefaultlocale(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    args::no_arguments(vm, &args, 0, "_getdefaultlocale")?;

    vm.host_operation(HostCapability::Environment, "_getdefaultlocale depends on the host")
}
