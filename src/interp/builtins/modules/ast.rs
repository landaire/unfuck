//! `_ast`: the node classes of the Python 2.7 grammar's abstract syntax
//! and the conversions between them and the compiler's `ast` types.

mod from_object;
mod to_object;

use std::cell::RefCell;
use std::rc::Rc;

use crate::interp::builtins::core::name_arg;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::new_type;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::static_method;
use crate::interp::compiler::CompilerFlags;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

pub use from_object::object_to_ast;
pub use to_object::ast_to_object;

/// How a field of a node class is converted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldType {
    /// A node of the given abstract (sum) or product class.
    Node(NodeClass),
    Identifier,
    Int,
    Bool,
    /// The `object n` of `Num`.
    Object,
    /// The `string s` of `Str`.
    String,
}

/// The ASDL multiplicity of a field: `T`, `T?`, or `T*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arity {
    Required,
    Optional,
    Sequence,
}

#[derive(Debug)]
struct Field {
    name: &'static str,
    kind: FieldType,
    arity: Arity,
}

struct ClassSpec {
    class: NodeClass,
    name: &'static str,
    base: NodeClass,
    /// `_attributes` stored on the class, if any.
    attributes: Option<&'static [&'static str]>,
    fields: &'static [Field],
}

const fn required(name: &'static str, kind: FieldType) -> Field {
    Field { name, kind, arity: Arity::Required }
}

const fn optional(name: &'static str, kind: FieldType) -> Field {
    Field { name, kind, arity: Arity::Optional }
}

const fn sequence(name: &'static str, kind: FieldType) -> Field {
    Field { name, kind, arity: Arity::Sequence }
}

const STMT: FieldType = FieldType::Node(NodeClass::StmtSum);
const EXPR: FieldType = FieldType::Node(NodeClass::ExprSum);
const EXPR_CONTEXT: FieldType = FieldType::Node(NodeClass::ExprContextSum);
const SLICE: FieldType = FieldType::Node(NodeClass::SliceSum);
const BOOLOP: FieldType = FieldType::Node(NodeClass::BoolOpSum);
const OPERATOR: FieldType = FieldType::Node(NodeClass::OperatorSum);
const UNARYOP: FieldType = FieldType::Node(NodeClass::UnaryOpSum);
const CMPOP: FieldType = FieldType::Node(NodeClass::CmpOpSum);
const COMPREHENSION: FieldType = FieldType::Node(NodeClass::Comprehension);
const EXCEPTHANDLER: FieldType = FieldType::Node(NodeClass::ExceptHandlerSum);
const ARGUMENTS: FieldType = FieldType::Node(NodeClass::Arguments);
const KEYWORD: FieldType = FieldType::Node(NodeClass::Keyword);
const ALIAS: FieldType = FieldType::Node(NodeClass::Alias);
const IDENTIFIER: FieldType = FieldType::Identifier;

const LOCATION: Option<&[&str]> = Some(&["lineno", "col_offset"]);
const NO_ATTRIBUTES: Option<&[&str]> = Some(&[]);

macro_rules! node_classes {
    ($($class:ident = $name:literal, $base:ident, $attributes:expr, $fields:expr;)*) => {
        /// The classes of `_ast`, in creation order.
        /// Abstract classes of ASDL sums carry a `Sum` suffix.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum NodeClass {
            $($class,)*
        }

        const CLASSES: &[ClassSpec] = &[$(ClassSpec { class: NodeClass::$class, name: $name, base: NodeClass::$base, attributes: $attributes, fields: $fields },)*];
    };
}

node_classes! {
    Ast = "AST", Ast, None, &[];
    ModSum = "mod", Ast, NO_ATTRIBUTES, &[];
    Module = "Module", ModSum, None, &[sequence("body", STMT)];
    Interactive = "Interactive", ModSum, None, &[sequence("body", STMT)];
    Expression = "Expression", ModSum, None, &[required("body", EXPR)];
    Suite = "Suite", ModSum, None, &[sequence("body", STMT)];
    StmtSum = "stmt", Ast, LOCATION, &[];
    FunctionDef = "FunctionDef", StmtSum, None, &[required("name", IDENTIFIER), required("args", ARGUMENTS), sequence("body", STMT), sequence("decorator_list", EXPR)];
    ClassDef = "ClassDef", StmtSum, None, &[required("name", IDENTIFIER), sequence("bases", EXPR), sequence("body", STMT), sequence("decorator_list", EXPR)];
    Return = "Return", StmtSum, None, &[optional("value", EXPR)];
    Delete = "Delete", StmtSum, None, &[sequence("targets", EXPR)];
    Assign = "Assign", StmtSum, None, &[sequence("targets", EXPR), required("value", EXPR)];
    AugAssign = "AugAssign", StmtSum, None, &[required("target", EXPR), required("op", OPERATOR), required("value", EXPR)];
    Print = "Print", StmtSum, None, &[optional("dest", EXPR), sequence("values", EXPR), required("nl", FieldType::Bool)];
    For = "For", StmtSum, None, &[required("target", EXPR), required("iter", EXPR), sequence("body", STMT), sequence("orelse", STMT)];
    While = "While", StmtSum, None, &[required("test", EXPR), sequence("body", STMT), sequence("orelse", STMT)];
    If = "If", StmtSum, None, &[required("test", EXPR), sequence("body", STMT), sequence("orelse", STMT)];
    With = "With", StmtSum, None, &[required("context_expr", EXPR), optional("optional_vars", EXPR), sequence("body", STMT)];
    Raise = "Raise", StmtSum, None, &[optional("type", EXPR), optional("inst", EXPR), optional("tback", EXPR)];
    TryExcept = "TryExcept", StmtSum, None, &[sequence("body", STMT), sequence("handlers", EXCEPTHANDLER), sequence("orelse", STMT)];
    TryFinally = "TryFinally", StmtSum, None, &[sequence("body", STMT), sequence("finalbody", STMT)];
    Assert = "Assert", StmtSum, None, &[required("test", EXPR), optional("msg", EXPR)];
    Import = "Import", StmtSum, None, &[sequence("names", ALIAS)];
    ImportFrom = "ImportFrom", StmtSum, None, &[optional("module", IDENTIFIER), sequence("names", ALIAS), optional("level", FieldType::Int)];
    Exec = "Exec", StmtSum, None, &[required("body", EXPR), optional("globals", EXPR), optional("locals", EXPR)];
    Global = "Global", StmtSum, None, &[sequence("names", IDENTIFIER)];
    Expr = "Expr", StmtSum, None, &[required("value", EXPR)];
    Pass = "Pass", StmtSum, None, &[];
    Break = "Break", StmtSum, None, &[];
    Continue = "Continue", StmtSum, None, &[];
    ExprSum = "expr", Ast, LOCATION, &[];
    BoolOp = "BoolOp", ExprSum, None, &[required("op", BOOLOP), sequence("values", EXPR)];
    BinOp = "BinOp", ExprSum, None, &[required("left", EXPR), required("op", OPERATOR), required("right", EXPR)];
    UnaryOp = "UnaryOp", ExprSum, None, &[required("op", UNARYOP), required("operand", EXPR)];
    Lambda = "Lambda", ExprSum, None, &[required("args", ARGUMENTS), required("body", EXPR)];
    IfExp = "IfExp", ExprSum, None, &[required("test", EXPR), required("body", EXPR), required("orelse", EXPR)];
    Dict = "Dict", ExprSum, None, &[sequence("keys", EXPR), sequence("values", EXPR)];
    Set = "Set", ExprSum, None, &[sequence("elts", EXPR)];
    ListComp = "ListComp", ExprSum, None, &[required("elt", EXPR), sequence("generators", COMPREHENSION)];
    SetComp = "SetComp", ExprSum, None, &[required("elt", EXPR), sequence("generators", COMPREHENSION)];
    DictComp = "DictComp", ExprSum, None, &[required("key", EXPR), required("value", EXPR), sequence("generators", COMPREHENSION)];
    GeneratorExp = "GeneratorExp", ExprSum, None, &[required("elt", EXPR), sequence("generators", COMPREHENSION)];
    Yield = "Yield", ExprSum, None, &[optional("value", EXPR)];
    Compare = "Compare", ExprSum, None, &[required("left", EXPR), sequence("ops", CMPOP), sequence("comparators", EXPR)];
    Call = "Call", ExprSum, None, &[required("func", EXPR), sequence("args", EXPR), sequence("keywords", KEYWORD), optional("starargs", EXPR), optional("kwargs", EXPR)];
    Repr = "Repr", ExprSum, None, &[required("value", EXPR)];
    Num = "Num", ExprSum, None, &[required("n", FieldType::Object)];
    Str = "Str", ExprSum, None, &[required("s", FieldType::String)];
    Attribute = "Attribute", ExprSum, None, &[required("value", EXPR), required("attr", IDENTIFIER), required("ctx", EXPR_CONTEXT)];
    Subscript = "Subscript", ExprSum, None, &[required("value", EXPR), required("slice", SLICE), required("ctx", EXPR_CONTEXT)];
    Name = "Name", ExprSum, None, &[required("id", IDENTIFIER), required("ctx", EXPR_CONTEXT)];
    List = "List", ExprSum, None, &[sequence("elts", EXPR), required("ctx", EXPR_CONTEXT)];
    Tuple = "Tuple", ExprSum, None, &[sequence("elts", EXPR), required("ctx", EXPR_CONTEXT)];
    ExprContextSum = "expr_context", Ast, NO_ATTRIBUTES, &[];
    Load = "Load", ExprContextSum, None, &[];
    Store = "Store", ExprContextSum, None, &[];
    Del = "Del", ExprContextSum, None, &[];
    AugLoad = "AugLoad", ExprContextSum, None, &[];
    AugStore = "AugStore", ExprContextSum, None, &[];
    Param = "Param", ExprContextSum, None, &[];
    SliceSum = "slice", Ast, NO_ATTRIBUTES, &[];
    Ellipsis = "Ellipsis", SliceSum, None, &[];
    Slice = "Slice", SliceSum, None, &[optional("lower", EXPR), optional("upper", EXPR), optional("step", EXPR)];
    ExtSlice = "ExtSlice", SliceSum, None, &[sequence("dims", SLICE)];
    Index = "Index", SliceSum, None, &[required("value", EXPR)];
    BoolOpSum = "boolop", Ast, NO_ATTRIBUTES, &[];
    And = "And", BoolOpSum, None, &[];
    Or = "Or", BoolOpSum, None, &[];
    OperatorSum = "operator", Ast, NO_ATTRIBUTES, &[];
    Add = "Add", OperatorSum, None, &[];
    Sub = "Sub", OperatorSum, None, &[];
    Mult = "Mult", OperatorSum, None, &[];
    Div = "Div", OperatorSum, None, &[];
    Mod = "Mod", OperatorSum, None, &[];
    Pow = "Pow", OperatorSum, None, &[];
    LShift = "LShift", OperatorSum, None, &[];
    RShift = "RShift", OperatorSum, None, &[];
    BitOr = "BitOr", OperatorSum, None, &[];
    BitXor = "BitXor", OperatorSum, None, &[];
    BitAnd = "BitAnd", OperatorSum, None, &[];
    FloorDiv = "FloorDiv", OperatorSum, None, &[];
    UnaryOpSum = "unaryop", Ast, NO_ATTRIBUTES, &[];
    Invert = "Invert", UnaryOpSum, None, &[];
    Not = "Not", UnaryOpSum, None, &[];
    UAdd = "UAdd", UnaryOpSum, None, &[];
    USub = "USub", UnaryOpSum, None, &[];
    CmpOpSum = "cmpop", Ast, NO_ATTRIBUTES, &[];
    Eq = "Eq", CmpOpSum, None, &[];
    NotEq = "NotEq", CmpOpSum, None, &[];
    Lt = "Lt", CmpOpSum, None, &[];
    LtE = "LtE", CmpOpSum, None, &[];
    Gt = "Gt", CmpOpSum, None, &[];
    GtE = "GtE", CmpOpSum, None, &[];
    Is = "Is", CmpOpSum, None, &[];
    IsNot = "IsNot", CmpOpSum, None, &[];
    In = "In", CmpOpSum, None, &[];
    NotIn = "NotIn", CmpOpSum, None, &[];
    Comprehension = "comprehension", Ast, None, &[required("target", EXPR), required("iter", EXPR), sequence("ifs", EXPR)];
    ExceptHandlerSum = "excepthandler", Ast, LOCATION, &[];
    ExceptHandler = "ExceptHandler", ExceptHandlerSum, None, &[optional("type", EXPR), optional("name", EXPR), sequence("body", STMT)];
    Arguments = "arguments", Ast, None, &[sequence("args", EXPR), optional("vararg", IDENTIFIER), optional("kwarg", IDENTIFIER), sequence("defaults", EXPR)];
    Keyword = "keyword", Ast, None, &[required("arg", IDENTIFIER), required("value", EXPR)];
    Alias = "alias", Ast, None, &[required("name", IDENTIFIER), optional("asname", IDENTIFIER)];
}

impl NodeClass {
    fn spec(self) -> &'static ClassSpec {
        &CLASSES[self as usize]
    }

    /// A sum whose constructors have no fields: its values are shared
    /// singleton instances.
    fn is_simple_sum(self) -> bool {
        matches!(self, Self::ExprContextSum | Self::BoolOpSum | Self::OperatorSum | Self::UnaryOpSum | Self::CmpOpSum)
    }

    /// An ASDL product type: converted without an `isinstance` dispatch.
    fn is_product(self) -> bool {
        matches!(self, Self::Comprehension | Self::Arguments | Self::Keyword | Self::Alias)
    }

    /// The constructors of a sum, in the order conversion from objects tests them.
    fn constructors(self) -> impl Iterator<Item = &'static ClassSpec> {
        CLASSES.iter().filter(move |spec| spec.base == self && spec.class != Self::Ast)
    }
}

/// The classes and singletons of `_ast`, created once per interpreter as
/// the `_ast` module does once per process.
pub(crate) struct AstTypes {
    classes: Vec<ObjectRef>,
    singletons: Vec<Option<Value>>,
}

impl AstTypes {
    fn class(&self, class: NodeClass) -> &ObjectRef {
        &self.classes[class as usize]
    }

    /// The shared instance of a constructor of a simple sum.
    fn singleton(&self, vm: &Vm, class: NodeClass) -> PyResult<Value> {
        let Some(singleton) = &self.singletons[class as usize] else {
            return Err(internal_error(vm, &format!("_ast.{} has no singleton instance", class.spec().name)));
        };

        Ok(singleton.clone())
    }
}

#[derive(Default)]
struct AstState {
    types: RefCell<Option<Rc<AstTypes>>>,
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    let types = ast_types(vm)?;

    set_attribute(vm, module, "AST", Value::Object(Rc::clone(types.class(NodeClass::Ast))))?;
    set_attribute(vm, module, "PyCF_ONLY_AST", Value::Int(i64::from(CompilerFlags::ONLY_AST)))?;
    set_attribute(vm, module, "__version__", Value::str("82160"))?;
    for spec in CLASSES.iter().filter(|spec| spec.class != NodeClass::Ast) {
        set_attribute(vm, module, spec.name, Value::Object(Rc::clone(types.class(spec.class))))?;
    }

    Ok(())
}

fn ast_types(vm: &Vm) -> PyResult<Rc<AstTypes>> {
    let state = vm.native_state::<AstState>();
    if let Some(types) = state.types.borrow().as_ref() {
        return Ok(Rc::clone(types));
    }

    let types = Rc::new(create_types(vm)?);
    *state.types.borrow_mut() = Some(Rc::clone(&types));

    Ok(types)
}

/// Creates the classes and singletons of `_ast`.
fn create_types(vm: &Vm) -> PyResult<AstTypes> {
    let mut classes: Vec<ObjectRef> = Vec::with_capacity(CLASSES.len());
    let mut singletons = Vec::with_capacity(CLASSES.len());

    for spec in CLASSES {
        let class = if spec.class == NodeClass::Ast {
            create_ast_type(vm)?
        } else {
            let Some(base) = classes.get(spec.base as usize) else {
                return Err(vm.raise(ExceptionKind::SystemError, &format!("_ast.{} precedes its base", spec.name)));
            };
            make_type(vm, spec, base)?
        };

        if let Some(attributes) = spec.attributes {
            let names = attributes.iter().map(|name| Value::str(name)).collect();
            vm.setattr_str(&Value::Object(Rc::clone(&class)), "_attributes", Value::tuple(names))?;
        }

        let singleton = if spec.base.is_simple_sum() { Some(new_node(vm, &class)) } else { None };
        classes.push(class);
        singletons.push(singleton);
    }

    Ok(AstTypes { classes, singletons })
}

/// `_ast.AST` with its `_fields` and `_attributes`.
fn create_ast_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_type(
        vm,
        TypeSpec {
            name: "AST",
            module: "_ast",
            base: None,
            layout: Layout::Object,
            instance_dict: false,
            methods: &[static_method("__new__", ast_new), method("__init__", ast_init), method("__reduce__", ast_reduce)],
        },
    )?;
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("_ast.AST is not a class"));
    };

    vm.dict_set_str(&data.dict, "_fields", Value::tuple(Vec::new()))?;
    vm.dict_set_str(&data.dict, "_attributes", Value::tuple(Vec::new()))?;

    Ok(class)
}

/// A node class: `type(name, (base,), {'_fields': fields, '__module__': '_ast'})`.
fn make_type(vm: &Vm, spec: &ClassSpec, base: &ObjectRef) -> PyResult<ObjectRef> {
    let namespace = vm.new_dict();
    let fields = spec.fields.iter().map(|field| Value::str(field.name)).collect();
    vm.dict_set_str(&namespace, "_fields", Value::tuple(fields))?;
    vm.dict_set_str(&namespace, "__module__", Value::str("_ast"))?;

    let bases = Value::tuple(vec![Value::Object(Rc::clone(base))]);
    match vm.type_new(&vm.types().type_, &Value::str(spec.name), &bases, &Value::Object(namespace))? {
        Value::Object(class) => Ok(class),
        _ => Err(vm.type_error("_ast class creation failed")),
    }
}

/// Generic allocation for a class whose instances own a `__dict__`.
fn new_node(vm: &Vm, class: &ObjectRef) -> Value {
    Value::Object(vm.alloc(class, Payload::Instance, Some(vm.new_dict())))
}

/// `AST.__new__`.
fn ast_new(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let Some(subtype) = args.positional.first() else {
        return Err(vm.type_error("_ast.AST.__new__(): not enough arguments"));
    };
    let Some(class) = subtype.as_object().filter(|object| object.as_class().is_some()) else {
        return Err(vm.type_error(&format!("_ast.AST.__new__(X): X is not a type object ({})", vm.type_name(subtype))));
    };

    let types = ast_types(vm)?;
    if !vm.is_subclass(class, types.class(NodeClass::Ast))? {
        let name = vm.class_name(class);
        return Err(vm.type_error(&format!("_ast.AST.__new__({name}): {name} is not a subtype of _ast.AST")));
    }

    let instance_dict = class.as_class().is_some_and(|data| data.instance_dict);
    let dict = if instance_dict { Some(vm.new_dict()) } else { None };

    Ok(Value::Object(vm.alloc(class, Payload::Instance, dict)))
}

/// The instance an `AST` method is called on.
fn ast_receiver(vm: &Vm, args: &CallArgs, method: &str) -> PyResult<Value> {
    let Some(receiver) = args.positional.first() else {
        return Err(vm.type_error(&format!("descriptor '{method}' of '_ast.AST' object needs an argument")));
    };

    let types = ast_types(vm)?;
    if !vm.is_instance_of(receiver, types.class(NodeClass::Ast))? {
        return Err(vm.type_error(&format!("descriptor '{method}' requires a '_ast.AST' object but received a '{}'", vm.type_name(receiver))));
    }

    Ok(receiver.clone())
}

/// `AST.__init__`: positional arguments fill `_fields` in order, keyword
/// arguments set attributes of any name.
fn ast_init(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let receiver = ast_receiver(vm, &args, "__init__")?;
    let positional = &args.positional[1..];

    // A failing `_fields` lookup is cleared: the class has no fields.
    let class = Value::Object(vm.class_of(&receiver));
    let fields = match vm.getattr_str(&class, "_fields") {
        Ok(fields) => Some(fields),
        Err(Signal::Raise(_)) => None,
        Err(halt) => return Err(halt),
    };
    let field_count = match &fields {
        Some(fields) => match vm.len(fields)? {
            Some(count) => count,
            None => return Err(vm.halt_unsupported("_ast node with unknown _fields")),
        },
        None => 0,
    };

    if !positional.is_empty() {
        let Some(fields) = fields.filter(|_| field_count == positional.len()) else {
            let either = if field_count == 0 { "" } else { "either 0 or " };
            let plural = if field_count == 1 { "" } else { "s" };
            return Err(vm.type_error(&format!("{} constructor takes {either}{field_count} positional argument{plural}", truncated(&vm.type_name(&receiver), 400))));
        };

        for (index, value) in positional.iter().enumerate() {
            let name = vm.getitem(&fields, &Value::Int(index as i64))?;
            vm.setattr(&receiver, &name_arg(vm, &name)?, value.clone())?;
        }
    }

    // The keywords arrive in the iteration order of the call's keyword
    // dict.
    match &args.keyword_dict {
        Some(keywords) => {
            for (name, value) in vm.dict_items(keywords)? {
                vm.setattr(&receiver, &name_arg(vm, &name)?, value)?;
            }
        }
        None => {
            for (name, value) in &args.keywords {
                vm.setattr(&receiver, name, value.clone())?;
            }
        }
    }

    Ok(Value::None)
}

/// `AST.__reduce__`: `(type(self), (), self.__dict__)`, without the dict
/// when there is none.
fn ast_reduce(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let receiver = ast_receiver(vm, &args, "__reduce__")?;
    method_no_arguments(vm, &args, "__reduce__")?;

    let class = Value::Object(vm.class_of(&receiver));
    match vm.getattr_str(&receiver, "__dict__") {
        Ok(dict) => Ok(Value::tuple(vec![class, Value::tuple(Vec::new()), dict])),
        Err(Signal::Raise(error)) if vm.is_exception(&error, ExceptionKind::AttributeError) => Ok(Value::tuple(vec![class, Value::tuple(Vec::new())])),
        Err(error) => Err(error),
    }
}

/// Whether `value` is an instance of `_ast.AST`.
pub fn is_ast_node(vm: &Vm, value: &Value) -> PyResult<bool> {
    let types = ast_types(vm)?;

    vm.isinstance(value, &Value::Object(Rc::clone(types.class(NodeClass::Ast))))
}

/// A `%.<limit>s` conversion of a type name.
fn truncated(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// A broken invariant of the conversion tables, reported as CPython
/// reports internal errors.
fn internal_error(vm: &Vm, detail: &str) -> Signal {
    vm.raise(ExceptionKind::SystemError, &format!("_ast conversion: {detail}"))
}

#[cfg(test)]
mod tests;
