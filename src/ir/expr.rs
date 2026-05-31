//! Value and statement IR.
//!
//! Expressions are kept in an arena and referenced by [`ValueId`] so that later
//! passes (SSA, simplification) can share and rewrite sub-expressions without
//! cloning trees. Expressions are pure; anything with an effect is a [`Stmt`].

use std::fmt;

/// Index of an expression in an [`ExprArena`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(pub u32);

/// Index into `co_varnames` (local slots used by `LOAD_FAST`/`STORE_FAST`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(pub u16);

/// Index into `co_names` (attributes, globals, imported names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameId(pub u16);

/// Index into `co_consts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstId(pub u16);

/// Index into the concatenation of `co_cellvars` and `co_freevars`, as used by
/// `LOAD_DEREF`/`STORE_DEREF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerefId(pub u16);

/// A bytecode offset. Wraps the raw integer so offset arithmetic is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Offset(pub u32);

/// Binary operators with no short-circuit behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    TrueDivide,
    Modulo,
    Power,
    LeftShift,
    RightShift,
    And,
    Or,
    Xor,
}

impl BinOp {
    /// The Python source spelling of the operator.
    pub fn symbol(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Subtract => "-",
            BinOp::Multiply => "*",
            BinOp::Divide => "/",
            BinOp::FloorDivide => "//",
            BinOp::TrueDivide => "/",
            BinOp::Modulo => "%",
            BinOp::Power => "**",
            BinOp::LeftShift => "<<",
            BinOp::RightShift => ">>",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
        }
    }
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Negate,
    Positive,
    Invert,
    Not,
}

impl UnaryOp {
    pub fn symbol(self) -> &'static str {
        match self {
            UnaryOp::Negate => "-",
            UnaryOp::Positive => "+",
            UnaryOp::Invert => "~",
            UnaryOp::Not => "not ",
        }
    }
}

/// The short-circuit boolean operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolKind {
    And,
    Or,
}

impl BoolKind {
    pub fn symbol(self) -> &'static str {
        match self {
            BoolKind::And => "and",
            BoolKind::Or => "or",
        }
    }
}

/// Comparison operators, indexed by the `COMPARE_OP` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Le,
    Eq,
    Ne,
    Gt,
    Ge,
    In,
    NotIn,
    Is,
    IsNot,
    ExceptionMatch,
}

impl CmpOp {
    /// Maps a `COMPARE_OP` operand to its operator.
    pub fn from_arg(arg: u16) -> Option<CmpOp> {
        Some(match arg {
            0 => CmpOp::Lt,
            1 => CmpOp::Le,
            2 => CmpOp::Eq,
            3 => CmpOp::Ne,
            4 => CmpOp::Gt,
            5 => CmpOp::Ge,
            6 => CmpOp::In,
            7 => CmpOp::NotIn,
            8 => CmpOp::Is,
            9 => CmpOp::IsNot,
            10 => CmpOp::ExceptionMatch,
            _ => return None,
        })
    }

    pub fn symbol(self) -> &'static str {
        match self {
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
            CmpOp::In => "in",
            CmpOp::NotIn => "not in",
            CmpOp::Is => "is",
            CmpOp::IsNot => "is not",
            CmpOp::ExceptionMatch => "except",
        }
    }
}

/// A pure expression. Operands reference other arena entries by [`ValueId`].
#[derive(Debug, Clone)]
pub enum Expr {
    Const(ConstId),
    Local(VarId),
    Deref(DerefId),
    Global(NameId),
    Name(NameId),
    Attr(ValueId, NameId),
    Subscript(ValueId, ValueId),
    /// A two-element slice `lower:upper` (from the `SLICE_*` opcodes). Only valid as
    /// the key of a [`Expr::Subscript`] or [`LValue::Subscript`].
    Slice {
        lower: Option<ValueId>,
        upper: Option<ValueId>,
    },
    BinOp(BinOp, ValueId, ValueId),
    /// An in-place binary op result (`INPLACE_*`), kept distinct from `BinOp` so a
    /// store back to the operand recovers as an augmented assignment (`x += y`).
    Inplace(BinOp, ValueId, ValueId),
    Unary(UnaryOp, ValueId),
    Compare(CmpOp, ValueId, ValueId),
    /// A flattened short-circuit chain, e.g. `a and b and c`. Always two or more
    /// operands of the same kind.
    BoolOp(BoolKind, Vec<ValueId>),
    /// A conditional expression: `then if cond else otherwise`.
    Ternary {
        cond: ValueId,
        then: ValueId,
        otherwise: ValueId,
    },
    Call {
        func: ValueId,
        args: Vec<ValueId>,
        /// Keyword arguments, each `(name, value)`. The name is a `Const` string.
        kwargs: Vec<(ValueId, ValueId)>,
        /// `*args` splat, if present.
        star: Option<ValueId>,
        /// `**kwargs` splat, if present.
        kwstar: Option<ValueId>,
    },
    Tuple(Vec<ValueId>),
    List(Vec<ValueId>),
    Dict(Vec<(ValueId, ValueId)>),
    Set(Vec<ValueId>),
    /// A transient placeholder pushed by `UNPACK_SEQUENCE`; consumed by the stores
    /// that follow to build a tuple-assignment target. Never reaches emission.
    UnpackSlot,
    /// A function object built from a nested code constant by `MAKE_FUNCTION`.
    /// Becomes a `def` when stored to a name. `defaults` are the default values for
    /// the trailing positional parameters.
    MakeFunction {
        code: ConstId,
        defaults: Vec<ValueId>,
    },
    /// `yield value`. `YIELD_VALUE` pushes the value the generator receives, which
    /// a statement-level yield then pops.
    Yield(ValueId),
    /// An inline list comprehension `[element for target in iter if cond ...]`.
    /// Python 2.7 builds these in place rather than in a nested code object, so the
    /// whole `BUILD_LIST`/`FOR_ITER`/`LIST_APPEND` region is recovered as one value.
    ListComp {
        element: ValueId,
        target: LValue,
        iter: ValueId,
        conds: Vec<ValueId>,
    },
    /// The module object produced by `IMPORT_NAME`. Consumed by a following store
    /// (an `import` statement) or by `IMPORT_FROM`/`IMPORT_STAR`.
    Import(NameId),
    /// A name pulled from an imported module by `IMPORT_FROM`, awaiting its store.
    ImportFrom(NameId),
    /// The class namespace dict produced by `LOAD_LOCALS` at the end of a class
    /// body. Consumed by the body's `RETURN_VALUE`; never emitted directly.
    Locals,
    /// A class object built by `BUILD_CLASS` from its name, base tuple, and body
    /// code object. Becomes a `class` statement when stored.
    BuildClass {
        name: ValueId,
        bases: ValueId,
        code: ConstId,
    },
}

/// The target of an assignment.
#[derive(Debug, Clone)]
pub enum LValue {
    Local(VarId),
    Deref(DerefId),
    Name(NameId),
    Global(NameId),
    Attr(ValueId, NameId),
    Subscript(ValueId, ValueId),
    Tuple(Vec<LValue>),
}

/// A statement. Control-flow variants are populated by the structuring pass; the
/// unstack pass only produces the straight-line variants.
#[derive(Debug, Clone)]
pub enum Stmt {
    Assign(LValue, ValueId),
    /// `target op= value`, recovered from an `INPLACE_*` op stored back to its
    /// left operand.
    AugAssign(LValue, BinOp, ValueId),
    /// `del target`.
    Delete(LValue),
    Expr(ValueId),
    Return(Option<ValueId>),
    Print {
        values: Vec<ValueId>,
        newline: bool,
    },
    If {
        cond: ValueId,
        then: Vec<Stmt>,
        els: Vec<Stmt>,
    },
    /// `raise`, `raise exc`, `raise exc, value`, or `raise exc, value, tb`.
    Raise(Vec<ValueId>),
    /// A nested function definition: `def name(...): ...`, decompiled from the
    /// code constant `code` and bound to `target`.
    FunctionDef {
        target: LValue,
        code: ConstId,
        /// Default values for the trailing positional parameters.
        defaults: Vec<ValueId>,
    },
    /// A class definition: `class name(bases): ...`, with the body decompiled from
    /// the code constant `code`. `name` is the class-name constant and `bases` the
    /// base-class tuple, both in the enclosing scope's arena.
    ClassDef {
        target: LValue,
        name: ValueId,
        bases: ValueId,
        code: ConstId,
    },
    While {
        cond: ValueId,
        /// True when the loop continues while `cond` is false (`while not cond`).
        negated: bool,
        body: Vec<Stmt>,
    },
    For {
        target: LValue,
        iter: ValueId,
        body: Vec<Stmt>,
    },
    /// `try: ... except [type [as name]]: ...`. The handlers are emitted in source
    /// order; a handler with no `exc_type` is a bare `except:`.
    Try {
        body: Vec<Stmt>,
        handlers: Vec<ExceptHandler>,
    },
    /// `import module [as target]`. `target` is the bound name; when it matches the
    /// module's top component no `as` clause is emitted.
    Import {
        module: NameId,
        target: LValue,
    },
    /// `from module import name [as target], ...`, or `from module import *` when
    /// `star` is set (and `names` is empty).
    FromImport {
        module: NameId,
        names: Vec<(NameId, LValue)>,
        star: bool,
    },
    /// `SET_ADD`: appends an element to a set comprehension's accumulator. Only
    /// produced when lowering a comprehension code object, where it is folded into
    /// the comprehension element rather than emitted as a statement.
    SetAdd(ValueId),
    /// `MAP_ADD`: inserts `key: value` into a dict comprehension's accumulator.
    /// Like [`Stmt::SetAdd`], only produced inside a comprehension code object.
    DictAdd {
        key: ValueId,
        value: ValueId,
    },
    Break,
    Continue,
}

/// One `except` clause of a [`Stmt::Try`].
#[derive(Debug, Clone)]
pub struct ExceptHandler {
    /// The matched exception type, or `None` for a bare `except:`.
    pub exc_type: Option<ValueId>,
    /// The `as name` binding, if the clause names the caught exception.
    pub name: Option<LValue>,
    pub body: Vec<Stmt>,
}

/// Owns every expression for one function. [`ValueId`]s index into it.
#[derive(Debug, Default)]
pub struct ExprArena {
    exprs: Vec<Expr>,
}

impl ExprArena {
    pub fn new() -> ExprArena {
        ExprArena { exprs: Vec::new() }
    }

    /// Interns an expression and returns its id.
    pub fn alloc(&mut self, expr: Expr) -> ValueId {
        let id = ValueId(self.exprs.len() as u32);
        self.exprs.push(expr);
        id
    }

    pub fn get(&self, id: ValueId) -> &Expr {
        &self.exprs[id.0 as usize]
    }

    /// Replaces an expression in place. Used to grow a container literal (a dict
    /// built by `BUILD_MAP`/`STORE_MAP`) while it sits on the stack, before any
    /// other expression can reference it.
    pub fn set(&mut self, id: ValueId, expr: Expr) {
        self.exprs[id.0 as usize] = expr;
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}
