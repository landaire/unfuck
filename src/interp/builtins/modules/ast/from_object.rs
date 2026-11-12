//! Conversion of `ast` node objects to the compiler's types. A stack of
//! partly read nodes stands in for recursion, so fields are read, and
//! errors raised, in field order without growing the native stack.

use std::rc::Rc;

use num_traits::ToPrimitive;

use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::modules::ast::Arity;
use crate::interp::builtins::modules::ast::AstTypes;
use crate::interp::builtins::modules::ast::ClassSpec;
use crate::interp::builtins::modules::ast::FieldType;
use crate::interp::builtins::modules::ast::NodeClass;
use crate::interp::builtins::modules::ast::ast_types;
use crate::interp::builtins::modules::ast::internal_error;
use crate::interp::builtins::modules::ast::truncated;
use crate::interp::compiler::Mode;
use crate::interp::compiler::ast;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers::fits_int;
use crate::interp::value::ObjectRef;
use crate::interp::value::Payload;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

/// A converted field value. `Null` is the NULL pointer `obj2ast_*` stores
/// for `None` or an absent optional field.
enum Item {
    Null,
    Mod(ast::Mod),
    Stmt(ast::Stmt),
    Expr(ast::Expr),
    Slice(ast::Slice),
    ExprContext(ast::ExprContext),
    BoolOp(ast::BoolOp),
    Operator(ast::Operator),
    UnaryOp(ast::UnaryOp),
    CmpOp(ast::CmpOp),
    Comprehension(ast::Comprehension),
    ExceptHandler(ast::ExceptHandler),
    Arguments(ast::Arguments),
    Keyword(ast::Keyword),
    Alias(ast::Alias),
    Identifier(ast::Identifier),
    Int(i32),
    Bool(bool),
    Number(ast::Number),
    String(ast::StrLiteral),
    List(Vec<Item>),
}

/// A node whose fields are being read.
struct Frame {
    class: NodeClass,
    object: Value,
    location: Option<ast::Location>,
    /// Converted fields, in `_fields` order.
    items: Vec<Item>,
    /// The list field being read, if any.
    sequence: Option<Sequence>,
}

struct Sequence {
    list: ObjectRef,
    /// Length when reading began; a change raises RuntimeError.
    length: usize,
    element: FieldType,
    items: Vec<Item>,
}

enum Begin {
    Leaf(Item),
    Node(Frame),
}

enum Step {
    Child(Value, FieldType),
    Finish,
}

struct Converter<'v> {
    vm: &'v Vm,
    types: Rc<AstTypes>,
    /// The first value CPython accepts without error that the `ast` types
    /// cannot hold. Conversion continues so a later Python error still
    /// wins, as it would in CPython; success then halts.
    unsupported: Option<String>,
}

impl Converter<'_> {
    fn convert(&mut self, root: Value, kind: FieldType) -> PyResult<Item> {
        let mut stack = match self.begin(root, kind)? {
            Begin::Leaf(item) => return Ok(item),
            Begin::Node(frame) => vec![frame],
        };
        let mut delivered = None;

        loop {
            let Some(frame) = stack.last_mut() else {
                return Err(internal_error(self.vm, "conversion stack underflow"));
            };
            if let Some(item) = delivered.take() {
                self.accept(frame, item)?;
            }

            match self.next_step(frame)? {
                Step::Child(value, kind) => match self.begin(value, kind)? {
                    Begin::Leaf(item) => delivered = Some(item),
                    Begin::Node(child) => stack.push(child),
                },
                Step::Finish => {
                    let Some(frame) = stack.pop() else {
                        return Err(internal_error(self.vm, "conversion stack underflow"));
                    };
                    let item = self.finish(frame)?;
                    if stack.is_empty() {
                        return Ok(item);
                    }
                    delivered = Some(item);
                }
            }
        }
    }

    /// The entry of `obj2ast_<kind>`: scalars convert at once; nodes are
    /// checked for `None`, location attributes, and their class.
    fn begin(&mut self, value: Value, kind: FieldType) -> PyResult<Begin> {
        halt_on_unknown(&value, "_ast node field")?;

        let item = match kind {
            FieldType::Identifier => identifier(self.vm, &value)?,
            FieldType::Int => Item::Int(c_int(self.vm, &value)?),
            FieldType::Bool => match value {
                Value::Bool(flag) => Item::Bool(flag),
                _ => return Err(self.vm.raise(ExceptionKind::ValueError, &format!("invalid boolean value: {}", repr(self.vm, &value)?))),
            },
            FieldType::Object => self.number(&value),
            FieldType::String => string(self.vm, &value)?,
            FieldType::Node(class) => return self.begin_node(value, class),
        };

        Ok(Begin::Leaf(item))
    }

    fn begin_node(&mut self, value: Value, sum: NodeClass) -> PyResult<Begin> {
        if sum.is_product() {
            return Ok(Begin::Node(Frame::new(sum, value, None)));
        }

        if sum.is_simple_sum() {
            for spec in sum.constructors() {
                if self.is_instance(&value, spec.class)? {
                    return Ok(Begin::Leaf(simple_item(self.vm, spec.class)?));
                }
            }
            return Err(self.not_a(&value, sum));
        }

        if value.is_none() {
            return Ok(Begin::Leaf(Item::Null));
        }

        let location = match sum.spec().attributes {
            Some(attributes) if !attributes.is_empty() => Some(self.location(&value, sum.spec())?),
            _ => None,
        };
        for spec in sum.constructors() {
            if self.is_instance(&value, spec.class)? {
                return Ok(Begin::Node(Frame::new(spec.class, value, location)));
            }
        }

        Err(self.not_a(&value, sum))
    }

    /// `lineno` and `col_offset`, read before the class dispatch.
    fn location(&self, value: &Value, sum: &ClassSpec) -> PyResult<ast::Location> {
        let read = |name: &str| -> PyResult<i32> {
            let Some(attribute) = field_value(self.vm, value, name)? else {
                return Err(self.vm.type_error(&format!("required field \"{name}\" missing from {}", sum.name)));
            };
            c_int(self.vm, &attribute)
        };

        let lineno = read("lineno")?;
        let col_offset = read("col_offset")?;

        Ok(ast::Location { lineno, col_offset })
    }

    fn is_instance(&self, value: &Value, class: NodeClass) -> PyResult<bool> {
        self.vm.isinstance(value, &Value::Object(Rc::clone(self.types.class(class))))
    }

    /// `expected some sort of <sum>, but got <repr>`.
    fn not_a(&self, value: &Value, sum: NodeClass) -> Signal {
        match repr(self.vm, value) {
            Ok(text) => self.vm.type_error(&format!("expected some sort of {}, but got {text}", sum.spec().name)),
            Err(signal) => signal,
        }
    }

    /// `Num.n`, which accepts any object.
    fn number(&mut self, value: &Value) -> Item {
        let number = match value {
            Value::None => return Item::Null,
            Value::Int(number) => ast::Number::Int(*number),
            Value::Long(number) => ast::Number::Long((**number).clone()),
            Value::Float(number) => ast::Number::Float(*number),
            Value::Object(object) if matches!(object.payload, Payload::Complex(_)) => {
                let Payload::Complex(number) = &object.payload else {
                    return Item::Null;
                };
                ast::Number::Complex { real: number.real, imag: number.imag }
            }
            _ => {
                self.record_unsupported(format!("Num node holding a '{}' object", self.vm.type_name(value)));
                ast::Number::Int(0)
            }
        };

        Item::Number(number)
    }

    fn record_unsupported(&mut self, feature: String) {
        if self.unsupported.is_none() {
            self.unsupported = Some(feature);
        }
    }

    /// Reads fields until one needs a node converted or none remain.
    fn next_step(&self, frame: &mut Frame) -> PyResult<Step> {
        let spec = frame.class.spec();

        loop {
            if let Some(sequence) = &frame.sequence {
                let index = sequence.items.len();
                if index < sequence.length {
                    let element = list_item(&sequence.list, index);
                    let Some(element) = element else {
                        return Err(self.changed_size(frame));
                    };
                    return Ok(Step::Child(element, sequence.element));
                }

                if let Some(done) = frame.sequence.take() {
                    frame.items.push(Item::List(done.items));
                }
                continue;
            }

            let Some(field) = spec.fields.get(frame.items.len()) else {
                return Ok(Step::Finish);
            };

            let Some(value) = field_value(self.vm, &frame.object, field.name)? else {
                if field.arity != Arity::Optional {
                    return Err(self.vm.type_error(&format!("required field \"{}\" missing from {}", field.name, spec.name)));
                }
                // An absent `int?` is 0: `ImportFrom.level` is a C int.
                let item = if field.kind == FieldType::Int { Item::Int(0) } else { Item::Null };
                frame.items.push(item);
                continue;
            };

            if field.arity != Arity::Sequence {
                return Ok(Step::Child(value, field.kind));
            }

            let list = match &value {
                Value::Object(object) if matches!(object.payload, Payload::List(_)) => Rc::clone(object),
                _ => return Err(self.vm.type_error(&format!("{} field \"{}\" must be a list, not a {}", spec.name, field.name, truncated(&self.vm.type_name(&value), 200)))),
            };
            let length = list_length(&list);
            frame.sequence = Some(Sequence { list, length, element: field.kind, items: Vec::with_capacity(length) });
        }
    }

    fn accept(&self, frame: &mut Frame, item: Item) -> PyResult<()> {
        let Some(sequence) = &mut frame.sequence else {
            frame.items.push(item);
            return Ok(());
        };

        sequence.items.push(item);
        if list_length(&sequence.list) != sequence.length {
            return Err(self.changed_size(frame));
        }

        Ok(())
    }

    fn changed_size(&self, frame: &Frame) -> Signal {
        let spec = frame.class.spec();
        let field = spec.fields.get(frame.items.len()).map_or("", |field| field.name);

        self.vm.raise(ExceptionKind::RuntimeError, &format!("{} field \"{field}\" changed size during iteration", spec.name))
    }

    /// The node constructor (`Module(...)`, `FunctionDef(...)`) applied to
    /// the converted fields.
    fn finish(&mut self, frame: Frame) -> PyResult<Item> {
        let class = frame.class;
        let spec = class.spec();

        // A product constructor given NULL for a required field returns NULL
        // with a pending ValueError that `obj2ast_*` does not check, so
        // conversion goes on as if the node were absent.
        if class.is_product() {
            let null_field = spec.fields.iter().zip(&frame.items).find(|(field, item)| field.arity == Arity::Required && matches!(item, Item::Null));
            if let Some((field, _)) = null_field {
                self.record_unsupported(format!("_ast.{} with {} set to None", spec.name, field.name));
                return Ok(Item::Null);
            }
        }

        let location = frame.location;
        let mut fields = Fields { vm: self.vm, spec, items: frame.items.into_iter(), index: 0, unsupported: &mut self.unsupported };

        let item = match class {
            NodeClass::Module => Item::Mod(ast::Mod::Module { body: fields.sequence()? }),
            NodeClass::Interactive => Item::Mod(ast::Mod::Interactive { body: fields.sequence()? }),
            NodeClass::Expression => Item::Mod(ast::Mod::Expression { body: Box::new(fields.required()?) }),
            NodeClass::Suite => Item::Mod(ast::Mod::Suite { body: fields.sequence()? }),
            NodeClass::Ellipsis => Item::Slice(ast::Slice::Ellipsis),
            NodeClass::Slice => Item::Slice(ast::Slice::Slice { lower: fields.optional()?, upper: fields.optional()?, step: fields.optional()? }),
            NodeClass::ExtSlice => Item::Slice(ast::Slice::ExtSlice { dims: fields.sequence()? }),
            NodeClass::Index => Item::Slice(ast::Slice::Index { value: fields.required()? }),
            NodeClass::Comprehension => Item::Comprehension(ast::Comprehension { target: fields.required()?, iter: fields.required()?, ifs: fields.sequence()? }),
            NodeClass::ExceptHandler => {
                let type_ = fields.optional()?;
                let name = fields.optional()?;
                let body = fields.sequence()?;
                Item::ExceptHandler(ast::ExceptHandler { type_, name, body, location: required_location(self.vm, location)? })
            }
            NodeClass::Arguments => Item::Arguments(ast::Arguments { args: fields.sequence()?, vararg: fields.optional()?, kwarg: fields.optional()?, defaults: fields.sequence()? }),
            NodeClass::Keyword => Item::Keyword(ast::Keyword { arg: fields.required()?, value: fields.required()? }),
            NodeClass::Alias => Item::Alias(ast::Alias { name: fields.required()?, asname: fields.optional()? }),
            _ if class.spec().base == NodeClass::StmtSum => {
                let kind = stmt_kind(class, &mut fields)?;
                Item::Stmt(ast::Stmt { kind, location: required_location(self.vm, location)? })
            }
            _ if class.spec().base == NodeClass::ExprSum => {
                let kind = expr_kind(class, &mut fields)?;
                Item::Expr(ast::Expr { kind, location: required_location(self.vm, location)? })
            }
            _ => return Err(internal_error(self.vm, &format!("no constructor for {}", class.spec().name))),
        };

        Ok(item)
    }
}

impl Frame {
    fn new(class: NodeClass, object: Value, location: Option<ast::Location>) -> Self {
        Self { class, object, location, items: Vec::with_capacity(class.spec().fields.len()), sequence: None }
    }
}

/// Converted fields of one node, consumed in `_fields` order with the
/// checks of its C constructor.
struct Fields<'c> {
    vm: &'c Vm,
    spec: &'static ClassSpec,
    items: std::vec::IntoIter<Item>,
    index: usize,
    unsupported: &'c mut Option<String>,
}

impl Fields<'_> {
    fn next(&mut self) -> PyResult<(Item, &'static str)> {
        let name = self.spec.fields.get(self.index).map(|field| field.name);
        self.index += 1;

        match (self.items.next(), name) {
            (Some(item), Some(name)) => Ok((item, name)),
            _ => Err(internal_error(self.vm, &format!("{} has fewer converted fields than its constructor reads", self.spec.name))),
        }
    }

    fn extract<T: FromItem>(&self, item: Item, name: &str) -> PyResult<T> {
        T::from_item(item).ok_or_else(|| internal_error(self.vm, &format!("{}.{name} converted to the wrong type", self.spec.name)))
    }

    /// A field the constructor rejects when NULL.
    fn required<T: FromItem>(&mut self) -> PyResult<T> {
        let (item, name) = self.next()?;
        if matches!(item, Item::Null) {
            return Err(self.vm.raise(ExceptionKind::ValueError, &format!("field {name} is required for {}", self.spec.name)));
        }

        self.extract(item, name)
    }

    fn optional<T: FromItem>(&mut self) -> PyResult<Option<T>> {
        let (item, name) = self.next()?;

        match item {
            Item::Null => Ok(None),
            item => self.extract(item, name).map(Some),
        }
    }

    /// A list field. CPython stores a `None` element as a NULL entry that
    /// the compiler later dereferences.
    fn sequence<T: FromItem>(&mut self) -> PyResult<Vec<T>> {
        let (item, name) = self.next()?;
        let Item::List(items) = item else {
            return Err(internal_error(self.vm, &format!("{}.{name} converted to the wrong type", self.spec.name)));
        };

        let mut values = Vec::with_capacity(items.len());
        for item in items {
            if matches!(item, Item::Null) {
                if self.unsupported.is_none() {
                    *self.unsupported = Some(format!("None in the {name} list of _ast.{}", self.spec.name));
                }
                continue;
            }
            values.push(self.extract(item, name)?);
        }

        Ok(values)
    }

    fn level(&mut self) -> PyResult<Option<u32>> {
        let (item, name) = self.next()?;
        let level: i32 = self.extract(item, name)?;

        match u32::try_from(level) {
            Ok(level) => Ok(Some(level)),
            Err(_) => {
                if self.unsupported.is_none() {
                    *self.unsupported = Some(format!("ImportFrom with level {level}"));
                }
                Ok(Some(0))
            }
        }
    }
}

/// The value of an ASDL type held by a converted `Item`.
trait FromItem: Sized {
    fn from_item(item: Item) -> Option<Self>;
}

macro_rules! from_item {
    ($($variant:ident => $type:ty;)*) => {
        $(
            impl FromItem for $type {
                fn from_item(item: Item) -> Option<Self> {
                    match item {
                        Item::$variant(value) => Some(value),
                        _ => None,
                    }
                }
            }
        )*
    };
}

from_item! {
    Stmt => ast::Stmt;
    Expr => ast::Expr;
    Slice => ast::Slice;
    ExprContext => ast::ExprContext;
    BoolOp => ast::BoolOp;
    Operator => ast::Operator;
    UnaryOp => ast::UnaryOp;
    CmpOp => ast::CmpOp;
    Comprehension => ast::Comprehension;
    ExceptHandler => ast::ExceptHandler;
    Arguments => ast::Arguments;
    Keyword => ast::Keyword;
    Alias => ast::Alias;
    Identifier => ast::Identifier;
    Int => i32;
    Bool => bool;
    Number => ast::Number;
    String => ast::StrLiteral;
}

impl<T: FromItem> FromItem for Box<T> {
    fn from_item(item: Item) -> Option<Self> {
        T::from_item(item).map(Box::new)
    }
}

/// Converts a module object to the compiler's `ast` types.
pub fn object_to_ast(vm: &Vm, value: &Value, mode: Mode) -> PyResult<ast::Mod> {
    let types = ast_types(vm)?;

    let required = match mode {
        Mode::Exec => NodeClass::Module,
        Mode::Eval => NodeClass::Expression,
        Mode::Single => NodeClass::Interactive,
    };
    if !vm.isinstance(value, &Value::Object(Rc::clone(types.class(required))))? {
        return Err(vm.type_error(&format!("expected {} node, got {}", required.spec().name, truncated(&vm.type_name(value), 400))));
    }

    let mut converter = Converter { vm, types, unsupported: None };
    let item = converter.convert(value.clone(), FieldType::Node(NodeClass::ModSum))?;
    if let Some(feature) = converter.unsupported {
        return Err(vm.halt_unsupported(feature));
    }

    match item {
        Item::Mod(module) => Ok(module),
        _ => Err(internal_error(vm, "module conversion produced no module")),
    }
}

fn stmt_kind(class: NodeClass, fields: &mut Fields<'_>) -> PyResult<ast::StmtKind> {
    let kind = match class {
        NodeClass::FunctionDef => ast::StmtKind::FunctionDef { name: fields.required()?, args: fields.required()?, body: fields.sequence()?, decorator_list: fields.sequence()? },
        NodeClass::ClassDef => ast::StmtKind::ClassDef { name: fields.required()?, bases: fields.sequence()?, body: fields.sequence()?, decorator_list: fields.sequence()? },
        NodeClass::Return => ast::StmtKind::Return { value: fields.optional()? },
        NodeClass::Delete => ast::StmtKind::Delete { targets: fields.sequence()? },
        NodeClass::Assign => ast::StmtKind::Assign { targets: fields.sequence()?, value: fields.required()? },
        NodeClass::AugAssign => ast::StmtKind::AugAssign { target: fields.required()?, op: fields.required()?, value: fields.required()? },
        NodeClass::Print => ast::StmtKind::Print { dest: fields.optional()?, values: fields.sequence()?, nl: fields.required()? },
        NodeClass::For => ast::StmtKind::For { target: fields.required()?, iter: fields.required()?, body: fields.sequence()?, orelse: fields.sequence()? },
        NodeClass::While => ast::StmtKind::While { test: fields.required()?, body: fields.sequence()?, orelse: fields.sequence()? },
        NodeClass::If => ast::StmtKind::If { test: fields.required()?, body: fields.sequence()?, orelse: fields.sequence()? },
        NodeClass::With => ast::StmtKind::With { context_expr: fields.required()?, optional_vars: fields.optional()?, body: fields.sequence()? },
        NodeClass::Raise => ast::StmtKind::Raise { type_: fields.optional()?, inst: fields.optional()?, tback: fields.optional()? },
        NodeClass::TryExcept => ast::StmtKind::TryExcept { body: fields.sequence()?, handlers: fields.sequence()?, orelse: fields.sequence()? },
        NodeClass::TryFinally => ast::StmtKind::TryFinally { body: fields.sequence()?, finalbody: fields.sequence()? },
        NodeClass::Assert => ast::StmtKind::Assert { test: fields.required()?, msg: fields.optional()? },
        NodeClass::Import => ast::StmtKind::Import { names: fields.sequence()? },
        NodeClass::ImportFrom => ast::StmtKind::ImportFrom { module: fields.optional()?, names: fields.sequence()?, level: fields.level()? },
        NodeClass::Exec => ast::StmtKind::Exec { body: fields.required()?, globals: fields.optional()?, locals: fields.optional()? },
        NodeClass::Global => ast::StmtKind::Global { names: fields.sequence()? },
        NodeClass::Expr => ast::StmtKind::Expr { value: fields.required()? },
        NodeClass::Pass => ast::StmtKind::Pass,
        NodeClass::Break => ast::StmtKind::Break,
        NodeClass::Continue => ast::StmtKind::Continue,
        _ => return Err(internal_error(fields.vm, &format!("{} is not a statement", class.spec().name))),
    };

    Ok(kind)
}

fn expr_kind(class: NodeClass, fields: &mut Fields<'_>) -> PyResult<ast::ExprKind> {
    let kind = match class {
        NodeClass::BoolOp => ast::ExprKind::BoolOp { op: fields.required()?, values: fields.sequence()? },
        NodeClass::BinOp => ast::ExprKind::BinOp { left: fields.required()?, op: fields.required()?, right: fields.required()? },
        NodeClass::UnaryOp => ast::ExprKind::UnaryOp { op: fields.required()?, operand: fields.required()? },
        NodeClass::Lambda => ast::ExprKind::Lambda { args: fields.required()?, body: fields.required()? },
        NodeClass::IfExp => ast::ExprKind::IfExp { test: fields.required()?, body: fields.required()?, orelse: fields.required()? },
        NodeClass::Dict => ast::ExprKind::Dict { keys: fields.sequence()?, values: fields.sequence()? },
        NodeClass::Set => ast::ExprKind::Set { elts: fields.sequence()? },
        NodeClass::ListComp => ast::ExprKind::ListComp { elt: fields.required()?, generators: fields.sequence()? },
        NodeClass::SetComp => ast::ExprKind::SetComp { elt: fields.required()?, generators: fields.sequence()? },
        NodeClass::DictComp => ast::ExprKind::DictComp { key: fields.required()?, value: fields.required()?, generators: fields.sequence()? },
        NodeClass::GeneratorExp => ast::ExprKind::GeneratorExp { elt: fields.required()?, generators: fields.sequence()? },
        NodeClass::Yield => ast::ExprKind::Yield { value: fields.optional()? },
        NodeClass::Compare => ast::ExprKind::Compare { left: fields.required()?, ops: fields.sequence()?, comparators: fields.sequence()? },
        NodeClass::Call => ast::ExprKind::Call { func: fields.required()?, args: fields.sequence()?, keywords: fields.sequence()?, starargs: fields.optional()?, kwargs: fields.optional()? },
        NodeClass::Repr => ast::ExprKind::Repr { value: fields.required()? },
        NodeClass::Num => ast::ExprKind::Num { n: fields.required()? },
        NodeClass::Str => ast::ExprKind::Str { s: fields.required()? },
        NodeClass::Attribute => ast::ExprKind::Attribute { value: fields.required()?, attr: fields.required()?, ctx: fields.required()? },
        NodeClass::Subscript => ast::ExprKind::Subscript { value: fields.required()?, slice: fields.required()?, ctx: fields.required()? },
        NodeClass::Name => ast::ExprKind::Name { id: fields.required()?, ctx: fields.required()? },
        NodeClass::List => ast::ExprKind::List { elts: fields.sequence()?, ctx: fields.required()? },
        NodeClass::Tuple => ast::ExprKind::Tuple { elts: fields.sequence()?, ctx: fields.required()? },
        _ => return Err(internal_error(fields.vm, &format!("{} is not an expression", class.spec().name))),
    };

    Ok(kind)
}

/// The value of a constructor of a simple sum.
fn simple_item(vm: &Vm, class: NodeClass) -> PyResult<Item> {
    let item = match class {
        NodeClass::Load => Item::ExprContext(ast::ExprContext::Load),
        NodeClass::Store => Item::ExprContext(ast::ExprContext::Store),
        NodeClass::Del => Item::ExprContext(ast::ExprContext::Del),
        NodeClass::AugLoad => Item::ExprContext(ast::ExprContext::AugLoad),
        NodeClass::AugStore => Item::ExprContext(ast::ExprContext::AugStore),
        NodeClass::Param => Item::ExprContext(ast::ExprContext::Param),
        NodeClass::And => Item::BoolOp(ast::BoolOp::And),
        NodeClass::Or => Item::BoolOp(ast::BoolOp::Or),
        NodeClass::Add => Item::Operator(ast::Operator::Add),
        NodeClass::Sub => Item::Operator(ast::Operator::Sub),
        NodeClass::Mult => Item::Operator(ast::Operator::Mult),
        NodeClass::Div => Item::Operator(ast::Operator::Div),
        NodeClass::Mod => Item::Operator(ast::Operator::Mod),
        NodeClass::Pow => Item::Operator(ast::Operator::Pow),
        NodeClass::LShift => Item::Operator(ast::Operator::LShift),
        NodeClass::RShift => Item::Operator(ast::Operator::RShift),
        NodeClass::BitOr => Item::Operator(ast::Operator::BitOr),
        NodeClass::BitXor => Item::Operator(ast::Operator::BitXor),
        NodeClass::BitAnd => Item::Operator(ast::Operator::BitAnd),
        NodeClass::FloorDiv => Item::Operator(ast::Operator::FloorDiv),
        NodeClass::Invert => Item::UnaryOp(ast::UnaryOp::Invert),
        NodeClass::Not => Item::UnaryOp(ast::UnaryOp::Not),
        NodeClass::UAdd => Item::UnaryOp(ast::UnaryOp::UAdd),
        NodeClass::USub => Item::UnaryOp(ast::UnaryOp::USub),
        NodeClass::Eq => Item::CmpOp(ast::CmpOp::Eq),
        NodeClass::NotEq => Item::CmpOp(ast::CmpOp::NotEq),
        NodeClass::Lt => Item::CmpOp(ast::CmpOp::Lt),
        NodeClass::LtE => Item::CmpOp(ast::CmpOp::LtE),
        NodeClass::Gt => Item::CmpOp(ast::CmpOp::Gt),
        NodeClass::GtE => Item::CmpOp(ast::CmpOp::GtE),
        NodeClass::Is => Item::CmpOp(ast::CmpOp::Is),
        NodeClass::IsNot => Item::CmpOp(ast::CmpOp::IsNot),
        NodeClass::In => Item::CmpOp(ast::CmpOp::In),
        NodeClass::NotIn => Item::CmpOp(ast::CmpOp::NotIn),
        _ => return Err(internal_error(vm, &format!("{} is not a constructor of a simple sum", class.spec().name))),
    };

    Ok(item)
}

fn required_location(vm: &Vm, location: Option<ast::Location>) -> PyResult<ast::Location> {
    location.ok_or_else(|| internal_error(vm, "node read without its location"))
}

/// An attribute lookup preceded by a presence check: any exception from
/// the first lookup counts as absence.
fn field_value(vm: &Vm, object: &Value, name: &str) -> PyResult<Option<Value>> {
    match vm.getattr_str(object, name) {
        Ok(_) => {}
        Err(Signal::Raise(_)) => return Ok(None),
        Err(halt) => return Err(halt),
    }

    vm.getattr_str(object, name).map(Some)
}

/// An identifier field: an exact `str`, or `None` for NULL.
fn identifier(vm: &Vm, value: &Value) -> PyResult<Item> {
    if value.is_none() {
        return Ok(Item::Null);
    }

    match exact_str(vm, value) {
        Some(bytes) => Ok(Item::Identifier(ast::Identifier(bytes))),
        None => Err(vm.type_error("AST identifier must be of type str")),
    }
}

/// A string field: an exact `str` or `unicode`.
fn string(vm: &Vm, value: &Value) -> PyResult<Item> {
    if let Some(bytes) = exact_str(vm, value) {
        // Every string of length 0 or 1 is interned.
        let interned = bytes.len() <= 1;
        return Ok(Item::String(ast::StrLiteral::Bytes { value: bytes, interned }));
    }

    let text = match value {
        Value::Unicode(text) => Some(text.clone()),
        Value::Object(object) if Rc::ptr_eq(&object.class(), &vm.types().unicode) => vm.as_text(value),
        _ => None,
    };
    match text {
        Some(text) => Ok(Item::String(ast::StrLiteral::Unicode(text.units().to_vec()))),
        None => Err(vm.type_error("AST string must be of type str or unicode")),
    }
}

fn exact_str(vm: &Vm, value: &Value) -> Option<Vec<u8>> {
    let bytes = match value {
        Value::Str(bytes) => bytes.clone(),
        Value::Object(object) if Rc::ptr_eq(&object.class(), &vm.types().str) => vm.as_str_bytes(value)?,
        _ => return None,
    };

    Some(bytes.as_bytes().to_vec())
}

/// An `int` or `long` field narrowed to a C `int` after a C `long` conversion.
fn c_int(vm: &Vm, value: &Value) -> PyResult<i32> {
    halt_on_unknown(value, "_ast integer field")?;

    let Some(integral) = vm.as_integral(value) else {
        return Err(vm.raise(ExceptionKind::ValueError, &format!("invalid integer value: {}", repr(vm, value)?)));
    };
    let long = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64().filter(|number| fits_int(vm.config.long_width, *number)),
    };
    let Some(long) = long else {
        return Err(vm.raise(ExceptionKind::OverflowError, "Python int too large to convert to C long"));
    };

    // The C cast keeps the low 32 bits where a C long is wider than an int.
    Ok(long as i32)
}

/// The repr formatted as `%.400s`: at most 400 bytes, ending at a NUL.
fn repr(vm: &Vm, value: &Value) -> PyResult<String> {
    let text = vm.repr(value)?;
    halt_on_unknown(&text, "repr in an _ast error")?;

    let Some(bytes) = vm.as_str_bytes(&text) else {
        return Err(internal_error(vm, "repr returned a non-str"));
    };
    let bytes = bytes.as_bytes();
    let end = bytes.iter().take(400).position(|byte| *byte == 0).unwrap_or(bytes.len().min(400));

    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn list_length(list: &ObjectRef) -> usize {
    match &list.payload {
        Payload::List(items) => items.borrow().len(),
        _ => 0,
    }
}

fn list_item(list: &ObjectRef, index: usize) -> Option<Value> {
    match &list.payload {
        Payload::List(items) => items.borrow().get(index).cloned(),
        _ => None,
    }
}
