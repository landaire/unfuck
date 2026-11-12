//! Scope analysis. Every module, class body, function, lambda, generator
//! expression, and set or dict comprehension gets a block that records the
//! names it uses and the scope each one resolves to.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::interp::compiler::ast;
use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::context::CompileError;
use crate::interp::compiler::context::CompileWarning;
use crate::interp::compiler::context::WarningCategory;
use crate::interp::compiler::context::WarningLocation;
use crate::interp::compiler::context::WarningRaised;
use crate::interp::compiler::future::c_str;
use crate::interp::compiler::future::syntax_located;
use crate::interp::compiler::future::truncate;
use crate::interp::hash::LongWidth;
use crate::interp::hash::hash_bytes;
use crate::interp::table::PyDictTable;

/// How a block uses a name. The values are those of the `_symtable`
/// constants `DEF_GLOBAL` through `DEF_BOUND` and `USE`.
pub mod def {
    pub const GLOBAL: u32 = 1;
    pub const LOCAL: u32 = 2;
    pub const PARAM: u32 = 2 << 1;
    pub const USE: u32 = 2 << 2;
    pub const FREE: u32 = 2 << 3;
    pub const FREE_CLASS: u32 = 2 << 4;
    pub const IMPORT: u32 = 2 << 5;
    pub const BOUND: u32 = LOCAL | PARAM | IMPORT;
}

/// Why a block keeps its locals in a dict. The values are those of the
/// `_symtable` constants `OPT_IMPORT_STAR`, `OPT_EXEC`, and `OPT_BARE_EXEC`;
/// `TOPLEVEL` marks the module.
pub mod opt {
    pub const IMPORT_STAR: u32 = 1;
    pub const EXEC: u32 = 2;
    pub const BARE_EXEC: u32 = 4;
    pub const TOPLEVEL: u32 = 8;
}

/// Position and width of the resolved `Scope` in a symbol's flags.
pub const SCOPE_OFF: u32 = 11;
pub const SCOPE_MASK: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockType {
    Function,
    Class,
    Module,
}

/// The scope a name resolves to. The values are those of the `_symtable`
/// constants `LOCAL` through `CELL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Local = 1,
    GlobalExplicit = 2,
    GlobalImplicit = 3,
    Free = 4,
    Cell = 5,
}

impl Scope {
    fn from_flags(flags: u32) -> Option<Self> {
        match (flags >> SCOPE_OFF) & SCOPE_MASK {
            1 => Some(Self::Local),
            2 => Some(Self::GlobalExplicit),
            3 => Some(Self::GlobalImplicit),
            4 => Some(Self::Free),
            5 => Some(Self::Cell),
            _ => None,
        }
    }

    /// `flags` with this scope in place of any earlier one.
    fn apply(self, flags: u32) -> u32 {
        (flags & !(SCOPE_MASK << SCOPE_OFF)) | ((self as u32) << SCOPE_OFF)
    }
}

/// Identifies the AST node that opens a block by its address. The analysis
/// and the code generator borrow the same tree, so the addresses agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeKey(usize);

impl NodeKey {
    pub fn of_mod(node: &ast::Mod) -> Self {
        Self(std::ptr::from_ref(node).addr())
    }

    pub fn of_stmt(node: &ast::Stmt) -> Self {
        Self(std::ptr::from_ref(node).addr())
    }

    pub fn of_expr(node: &ast::Expr) -> Self {
        Self(std::ptr::from_ref(node).addr())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockId(pub usize);

/// One scope: the module, a class body, a function or lambda, or a
/// comprehension, which runs as a function of its own.
#[derive(Clone, Debug)]
pub struct Block {
    pub kind: BlockType,
    pub name: Vec<u8>,
    /// Each name's `def` flags, with its `Scope` at `SCOPE_OFF`.
    pub symbols: HashMap<Vec<u8>, u32>,
    /// The names of `symbols` in the order they were added, which is the
    /// order of the `_symtable` symbols dict.
    pub symbol_order: Vec<Vec<u8>>,
    /// The parameters in order, including `.N` for the tuple parameter at
    /// position N and then the names inside tuple parameters.
    pub varnames: Vec<Vec<u8>>,
    pub children: Vec<BlockId>,

    /// `opt` bits.
    pub unoptimized: u32,
    /// Line of the first `exec`, or of the first import once `unoptimized`
    /// is set. A recorded line 0, which only trees built through `_ast`
    /// carry, is replaced by the next one like an absent line.
    pub unoptimized_line: Option<i32>,

    /// Inside a function, so names can come from enclosing functions.
    pub nested: bool,
    /// Uses a name bound in an enclosing function, or, when nested, a name
    /// no scope declares global.
    pub has_free: bool,
    /// Some block inside this one has `has_free`.
    pub child_has_free: bool,

    pub generator: bool,
    pub varargs: bool,
    pub varkeywords: bool,
    pub lineno: i32,
}

impl Block {
    /// The resolved scope of `name`, if the block uses it.
    pub fn scope(&self, name: &[u8]) -> Option<Scope> {
        Scope::from_flags(self.flags(name)?)
    }

    /// The symbol's flags, if the block has it.
    pub fn flags(&self, name: &[u8]) -> Option<u32> {
        self.symbols.get(name).copied()
    }
}

pub struct SymbolTable {
    blocks: Vec<Block>,
    by_key: HashMap<NodeKey, BlockId>,
    top: BlockId,
    /// Every identifier in the AST. The parser interns each one, so they
    /// are all in the interned-string table before compilation.
    pub identifiers: HashSet<Vec<u8>>,
}

impl SymbolTable {
    pub fn build(module: &ast::Mod, filename: &[u8], context: &mut dyn CompileContext) -> Result<Self, CompileError> {
        let mut builder = Builder::new(module, filename, context);

        match module {
            ast::Mod::Module { body } | ast::Mod::Interactive { body } => builder.tasks.extend(body.iter().rev().map(Task::Stmt)),
            ast::Mod::Expression { body } => builder.tasks.push(Task::Expr(body)),
            ast::Mod::Suite { .. } => {
                // Reported as the internal error CPython raises as a RuntimeError.
                return Err(CompileError::System { message: "this compiler does not handle Suites".to_owned() });
            }
        }

        builder.record()?;
        builder.resolve()?;

        Ok(Self { blocks: builder.blocks, by_key: builder.by_key, top: BlockId(0), identifiers: collect_identifiers(module) })
    }

    pub fn top(&self) -> BlockId {
        self.top
    }

    /// The block the node opens.
    pub fn lookup(&self, key: NodeKey) -> Option<BlockId> {
        self.by_key.get(&key).copied()
    }

    pub fn block(&self, id: BlockId) -> &Block {
        &self.blocks[id.0]
    }
}

type NameSet = HashSet<Vec<u8>>;

/// Names in a table that iterates like a Python dict. Wherever names are
/// visited in turn, that order decides which error is reported first and
/// the order free names are added to a block.
type NameDict<V> = PyDictTable<Vec<u8>, V>;

/// One step of the walk that records how each block uses its names. A
/// step pushes the steps for its node's parts in source order; the walk
/// loop then reverses them so they run in that order.
enum Task<'t> {
    Stmt(&'t ast::Stmt),
    Expr(&'t ast::Expr),
    Slice(&'t ast::Slice),
    Open(Opening<'t>),
    Close,
    /// A `return` with a value at this line, once the value is recorded.
    ReturnedValue(i32),
    /// A `yield` at this line, once its value is recorded.
    Yielded(i32),
}

/// A block the walk enters.
enum Opening<'t> {
    Function { name: &'t [u8], key: NodeKey, lineno: i32, arguments: &'t ast::Arguments },
    Class { name: &'t [u8], key: NodeKey, lineno: i32 },
    Comprehension { kind: Comprehension, key: NodeKey },
}

/// The comprehensions that run in a block of their own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Comprehension {
    Generator,
    Set,
    Dict,
}

impl Comprehension {
    fn block_name(self) -> &'static [u8] {
        match self {
            Self::Generator => b"genexpr",
            Self::Set => b"setcomp",
            Self::Dict => b"dictcomp",
        }
    }
}

/// The block and private name in effect around an open block.
struct Enclosing<'t> {
    block: BlockId,
    private: Option<&'t [u8]>,
}

/// Per-block state used only while the walk runs.
#[derive(Default)]
struct Recording {
    symbols: NameDict<u32>,
    returns_value: bool,
}

/// The names a block sees while its own names are resolved.
struct Environment {
    /// Names bound in enclosing functions; `None` for the module.
    enclosing: Option<NameSet>,
    /// Names declared or known to be global.
    global: NameSet,
    /// Names the block binds.
    local: NameSet,
    /// Names the block takes from enclosing functions.
    free: NameDict<()>,
}

/// The sets a block hands to each of its children.
#[derive(Default)]
struct Inherited {
    enclosing: NameSet,
    global: NameSet,
}

/// A block whose children are being resolved.
struct Pending {
    block: BlockId,
    enclosing: Option<NameSet>,
    free: NameDict<()>,
    /// Names free in the children, merged in child order.
    children_free: NameDict<()>,
}

struct Builder<'a, 't> {
    filename: &'a [u8],
    width: LongWidth,
    context: &'a mut dyn CompileContext,

    blocks: Vec<Block>,
    recordings: Vec<Recording>,
    by_key: HashMap<NodeKey, BlockId>,

    tasks: Vec<Task<'t>>,
    current: BlockId,
    enclosing: Vec<Enclosing<'t>>,
    /// The name of the innermost enclosing class, which mangles private
    /// names.
    private: Option<&'t [u8]>,
}

impl<'a, 't> Builder<'a, 't> {
    fn new(module: &'t ast::Mod, filename: &'a [u8], context: &'a mut dyn CompileContext) -> Self {
        let width = context.long_width();
        let mut builder = Self {
            filename,
            width,
            context,
            blocks: Vec::new(),
            recordings: Vec::new(),
            by_key: HashMap::new(),
            tasks: Vec::new(),
            current: BlockId(0),
            enclosing: Vec::new(),
            private: None,
        };

        let top = builder.add_block(b"top".to_vec(), BlockType::Module, NodeKey::of_mod(module), 0, false);
        builder.blocks[top.0].unoptimized = opt::TOPLEVEL;

        builder
    }

    fn add_block(&mut self, name: Vec<u8>, kind: BlockType, key: NodeKey, lineno: i32, nested: bool) -> BlockId {
        let id = BlockId(self.blocks.len());
        self.blocks.push(Block {
            kind,
            name,
            symbols: HashMap::new(),
            symbol_order: Vec::new(),
            varnames: Vec::new(),
            children: Vec::new(),
            unoptimized: 0,
            unoptimized_line: None,
            nested,
            has_free: false,
            child_has_free: false,
            generator: false,
            varargs: false,
            varkeywords: false,
            lineno,
        });
        self.recordings.push(Recording::default());
        self.by_key.insert(key, id);

        id
    }

    fn current(&mut self) -> &mut Block {
        &mut self.blocks[self.current.0]
    }

    fn error(&self, message: String, lineno: i32) -> CompileError {
        syntax_located(message, self.filename, lineno)
    }

    /// Issues a SyntaxWarning at `lineno`, or at the line of the current
    /// block.
    fn warn(&mut self, message: Vec<u8>, lineno: Option<i32>) -> Result<(), CompileError> {
        let block_lineno = self.current().lineno;
        let warning = CompileWarning {
            category: WarningCategory::SyntaxWarning,
            message: String::from_utf8_lossy(&message).into_owned(),
            location: Some(WarningLocation { filename: self.filename.to_vec(), lineno: lineno.unwrap_or(block_lineno) }),
        };

        match self.context.warn(&warning) {
            Ok(()) => Ok(()),
            // A warning the filter turns into an error is reported as a
            // SyntaxError at the line of the current block.
            Err(WarningRaised { is_syntax_warning: true }) => Err(self.error(warning.message, block_lineno)),
            Err(WarningRaised { is_syntax_warning: false }) => Err(CompileError::WarningRaised),
        }
    }

    /// Records a use of `name` in the current block. Parameters also go to
    /// `varnames`, and `global` declarations also to the module block.
    fn bind(&mut self, name: &[u8], flag: u32) -> Result<(), CompileError> {
        let mangled = mangle(self.private, name);
        let current = self.current.0;
        let symbols = &mut self.recordings[current].symbols;

        let earlier = dict_get(symbols, self.width, &mangled);
        if earlier.is_some_and(|earlier| earlier & flag & def::PARAM != 0) {
            let mut message = b"duplicate argument '".to_vec();
            message.extend_from_slice(c_str(name));
            message.extend_from_slice(b"' in function definition");

            return Err(self.error(String::from_utf8_lossy(&message).into_owned(), self.blocks[current].lineno));
        }

        if dict_set(symbols, self.width, &mangled, earlier.map_or(flag, |earlier| earlier | flag)) {
            self.blocks[current].symbol_order.push(mangled.to_vec());
        }

        if flag & def::PARAM != 0 {
            self.blocks[current].varnames.push(mangled.into_owned());
        } else if flag & def::GLOBAL != 0 {
            let module = &mut self.recordings[0].symbols;
            let flags = dict_get(module, self.width, &mangled).map_or(flag, |earlier| earlier | flag);
            if dict_set(module, self.width, &mangled, flags) {
                self.blocks[0].symbol_order.push(mangled.into_owned());
            }
        }

        Ok(())
    }

    /// Runs the walk until no task is left.
    fn record(&mut self) -> Result<(), CompileError> {
        while let Some(task) = self.tasks.pop() {
            let first_pushed = self.tasks.len();
            match task {
                Task::Stmt(statement) => self.record_stmt(statement)?,
                Task::Expr(expression) => self.record_expr(expression)?,
                Task::Slice(slice) => self.record_slice(slice),
                Task::Open(opening) => self.open(opening)?,
                Task::Close => self.close(),
                Task::ReturnedValue(lineno) => {
                    self.recordings[self.current.0].returns_value = true;
                    if self.current().generator {
                        return Err(self.error("'return' with argument inside generator".to_owned(), lineno));
                    }
                }
                Task::Yielded(lineno) => {
                    self.current().generator = true;
                    if self.recordings[self.current.0].returns_value {
                        return Err(self.error("'return' with argument inside generator".to_owned(), lineno));
                    }
                }
            }

            // The parts just pushed run in source order.
            self.tasks[first_pushed..].reverse();
        }

        Ok(())
    }

    fn push_exprs(&mut self, expressions: &'t [ast::Expr]) {
        self.tasks.extend(expressions.iter().map(Task::Expr));
    }

    fn push_stmts(&mut self, statements: &'t [ast::Stmt]) {
        self.tasks.extend(statements.iter().map(Task::Stmt));
    }

    fn push_optional(&mut self, expression: Option<&'t ast::Expr>) {
        self.tasks.extend(expression.map(Task::Expr));
    }

    fn record_stmt(&mut self, statement: &'t ast::Stmt) -> Result<(), CompileError> {
        let lineno = statement.location.lineno;
        let key = NodeKey::of_stmt(statement);

        match &statement.kind {
            ast::StmtKind::FunctionDef { name, args, body, decorator_list } => {
                self.bind(&name.0, def::LOCAL)?;
                self.push_exprs(&args.defaults);
                self.push_exprs(decorator_list);
                self.tasks.push(Task::Open(Opening::Function { name: &name.0, key, lineno, arguments: args }));
                self.push_stmts(body);
                self.tasks.push(Task::Close);
            }
            ast::StmtKind::ClassDef { name, bases, body, decorator_list } => {
                self.bind(&name.0, def::LOCAL)?;
                self.push_exprs(bases);
                self.push_exprs(decorator_list);
                self.tasks.push(Task::Open(Opening::Class { name: &name.0, key, lineno }));
                self.push_stmts(body);
                self.tasks.push(Task::Close);
            }
            ast::StmtKind::Return { value } => {
                if let Some(value) = value {
                    self.tasks.push(Task::Expr(value));
                    self.tasks.push(Task::ReturnedValue(lineno));
                }
            }
            ast::StmtKind::Delete { targets } => self.push_exprs(targets),
            ast::StmtKind::Assign { targets, value } => {
                self.push_exprs(targets);
                self.tasks.push(Task::Expr(value));
            }
            ast::StmtKind::AugAssign { target, value, .. } => {
                self.tasks.push(Task::Expr(target));
                self.tasks.push(Task::Expr(value));
            }
            ast::StmtKind::Print { dest, values, .. } => {
                self.push_optional(dest.as_ref());
                self.push_exprs(values);
            }
            ast::StmtKind::For { target, iter, body, orelse } => {
                self.tasks.push(Task::Expr(target));
                self.tasks.push(Task::Expr(iter));
                self.push_stmts(body);
                self.push_stmts(orelse);
            }
            ast::StmtKind::While { test, body, orelse } | ast::StmtKind::If { test, body, orelse } => {
                self.tasks.push(Task::Expr(test));
                self.push_stmts(body);
                self.push_stmts(orelse);
            }
            ast::StmtKind::Raise { type_, inst, tback } => {
                // The instance and traceback only count after a type.
                if let Some(type_) = type_ {
                    self.tasks.push(Task::Expr(type_));
                    if let Some(inst) = inst {
                        self.tasks.push(Task::Expr(inst));
                        self.push_optional(tback.as_ref());
                    }
                }
            }
            ast::StmtKind::TryExcept { body, handlers, orelse } => {
                self.push_stmts(body);
                self.push_stmts(orelse);
                for handler in handlers {
                    self.push_optional(handler.type_.as_ref());
                    self.push_optional(handler.name.as_ref());
                    self.push_stmts(&handler.body);
                }
            }
            ast::StmtKind::TryFinally { body, finalbody } => {
                self.push_stmts(body);
                self.push_stmts(finalbody);
            }
            ast::StmtKind::Assert { test, msg } => {
                self.tasks.push(Task::Expr(test));
                self.push_optional(msg.as_ref());
            }
            ast::StmtKind::Import { names } | ast::StmtKind::ImportFrom { names, .. } => {
                for alias in names {
                    self.record_import(alias)?;
                }

                let block = self.current();
                if block.unoptimized != 0 && block.unoptimized_line.is_none_or(|line| line == 0) {
                    block.unoptimized_line = Some(lineno);
                }
            }
            ast::StmtKind::Exec { body, globals, locals } => {
                let block = self.current();
                if block.unoptimized_line.is_none_or(|line| line == 0) {
                    block.unoptimized_line = Some(lineno);
                }
                block.unoptimized |= if globals.is_some() { opt::EXEC } else { opt::BARE_EXEC };

                self.tasks.push(Task::Expr(body));
                if let Some(globals) = globals {
                    self.tasks.push(Task::Expr(globals));
                    self.push_optional(locals.as_ref());
                }
            }
            ast::StmtKind::Global { names } => {
                for name in names {
                    self.declare_global(&name.0, lineno)?;
                }
            }
            ast::StmtKind::Expr { value } => self.tasks.push(Task::Expr(value)),
            ast::StmtKind::Pass | ast::StmtKind::Break | ast::StmtKind::Continue => {
                // No names.
            }
            ast::StmtKind::With { context_expr, optional_vars, body } => {
                self.tasks.push(Task::Expr(context_expr));
                self.push_optional(optional_vars.as_ref());
                self.push_stmts(body);
            }
        }

        Ok(())
    }

    fn record_expr(&mut self, expression: &'t ast::Expr) -> Result<(), CompileError> {
        let lineno = expression.location.lineno;
        let key = NodeKey::of_expr(expression);

        match &expression.kind {
            ast::ExprKind::BoolOp { values, .. } => self.push_exprs(values),
            ast::ExprKind::BinOp { left, right, .. } => {
                self.tasks.push(Task::Expr(left));
                self.tasks.push(Task::Expr(right));
            }
            ast::ExprKind::UnaryOp { operand, .. } => self.tasks.push(Task::Expr(operand)),
            ast::ExprKind::Lambda { args, body } => {
                self.push_exprs(&args.defaults);
                self.tasks.push(Task::Open(Opening::Function { name: b"lambda", key, lineno, arguments: args }));
                self.tasks.push(Task::Expr(body));
                self.tasks.push(Task::Close);
            }
            ast::ExprKind::IfExp { test, body, orelse } => {
                self.tasks.push(Task::Expr(test));
                self.tasks.push(Task::Expr(body));
                self.tasks.push(Task::Expr(orelse));
            }
            ast::ExprKind::Dict { keys, values } => {
                self.push_exprs(keys);
                self.push_exprs(values);
            }
            ast::ExprKind::Set { elts } | ast::ExprKind::List { elts, .. } | ast::ExprKind::Tuple { elts, .. } => self.push_exprs(elts),
            ast::ExprKind::ListComp { elt, generators } => {
                // A list comprehension runs in the enclosing block.
                self.tasks.push(Task::Expr(elt));
                for generator in generators {
                    self.tasks.push(Task::Expr(&generator.target));
                    self.tasks.push(Task::Expr(&generator.iter));
                    self.push_exprs(&generator.ifs);
                }
            }
            ast::ExprKind::GeneratorExp { elt, generators } => self.push_comprehension(Comprehension::Generator, key, generators, None, elt)?,
            ast::ExprKind::SetComp { elt, generators } => self.push_comprehension(Comprehension::Set, key, generators, None, elt)?,
            ast::ExprKind::DictComp { key: item_key, value, generators } => self.push_comprehension(Comprehension::Dict, key, generators, Some(value), item_key)?,
            ast::ExprKind::Yield { value } => {
                self.push_optional(value.as_deref());
                self.tasks.push(Task::Yielded(lineno));
            }
            ast::ExprKind::Compare { left, comparators, .. } => {
                self.tasks.push(Task::Expr(left));
                self.push_exprs(comparators);
            }
            ast::ExprKind::Call { func, args, keywords, starargs, kwargs } => {
                self.tasks.push(Task::Expr(func));
                self.push_exprs(args);
                self.tasks.extend(keywords.iter().map(|keyword| Task::Expr(&keyword.value)));
                self.push_optional(starargs.as_deref());
                self.push_optional(kwargs.as_deref());
            }
            ast::ExprKind::Repr { value } | ast::ExprKind::Attribute { value, .. } => self.tasks.push(Task::Expr(value)),
            ast::ExprKind::Num { .. } | ast::ExprKind::Str { .. } => {
                // No names.
            }
            ast::ExprKind::Subscript { value, slice, .. } => {
                self.tasks.push(Task::Expr(value));
                self.tasks.push(Task::Slice(slice));
            }
            ast::ExprKind::Name { id, ctx } => {
                let flag = if *ctx == ast::ExprContext::Load { def::USE } else { def::LOCAL };
                self.bind(&id.0, flag)?;
            }
        }

        Ok(())
    }

    fn record_slice(&mut self, slice: &'t ast::Slice) {
        match slice {
            ast::Slice::Slice { lower, upper, step } => {
                self.push_optional(lower.as_ref());
                self.push_optional(upper.as_ref());
                self.push_optional(step.as_ref());
            }
            ast::Slice::ExtSlice { dims } => self.tasks.extend(dims.iter().map(Task::Slice)),
            ast::Slice::Index { value } => self.tasks.push(Task::Expr(value)),
            ast::Slice::Ellipsis => {
                // No names.
            }
        }
    }

    /// The first iterable is evaluated in the enclosing block; everything
    /// else runs in the comprehension's own block. A dict comprehension's
    /// value comes before its key.
    fn push_comprehension(
        &mut self,
        kind: Comprehension,
        key: NodeKey,
        generators: &'t [ast::Comprehension],
        value: Option<&'t ast::Expr>,
        element: &'t ast::Expr,
    ) -> Result<(), CompileError> {
        let Some((first, rest)) = generators.split_first() else {
            return Err(CompileError::System { message: "comprehension with no generators".to_owned() });
        };

        self.tasks.push(Task::Expr(&first.iter));
        self.tasks.push(Task::Open(Opening::Comprehension { kind, key }));
        self.tasks.push(Task::Expr(&first.target));
        self.push_exprs(&first.ifs);
        for generator in rest {
            self.tasks.push(Task::Expr(&generator.target));
            self.tasks.push(Task::Expr(&generator.iter));
            self.push_exprs(&generator.ifs);
        }
        self.push_optional(value);
        self.tasks.push(Task::Expr(element));
        self.tasks.push(Task::Close);

        Ok(())
    }

    fn open(&mut self, opening: Opening<'t>) -> Result<(), CompileError> {
        match opening {
            Opening::Function { name, key, lineno, arguments } => {
                self.enter(name, BlockType::Function, key, lineno);
                self.bind_parameters(arguments)
            }
            Opening::Class { name, key, lineno } => {
                self.enter(name, BlockType::Class, key, lineno);
                self.private = Some(name);

                Ok(())
            }
            Opening::Comprehension { kind, key } => {
                self.enter(kind.block_name(), BlockType::Function, key, 0);

                // The first iterable arrives as the hidden argument `.0`, and
                // a set or dict under construction lives in the local `_[1]`.
                self.bind(b".0", def::PARAM)?;
                match kind {
                    Comprehension::Generator => self.current().generator = true,
                    Comprehension::Set | Comprehension::Dict => self.bind(b"_[1]", def::LOCAL)?,
                }

                Ok(())
            }
        }
    }

    fn enter(&mut self, name: &[u8], kind: BlockType, key: NodeKey, lineno: i32) {
        let parent = self.current;
        let nested = self.blocks[parent.0].nested || self.blocks[parent.0].kind == BlockType::Function;
        let id = self.add_block(name.to_vec(), kind, key, lineno, nested);

        self.blocks[parent.0].children.push(id);
        self.enclosing.push(Enclosing { block: parent, private: self.private });
        self.current = id;
    }

    fn close(&mut self) {
        if let Some(enclosing) = self.enclosing.pop() {
            self.current = enclosing.block;
            self.private = enclosing.private;
        }
    }

    /// Binds the parameters of the block just opened: the plain names and
    /// a `.N` placeholder for each tuple, then `*args` and `**kwargs`, then
    /// the names inside the tuples, depth first.
    fn bind_parameters(&mut self, arguments: &'t ast::Arguments) -> Result<(), CompileError> {
        for (position, parameter) in arguments.args.iter().enumerate() {
            match &parameter.kind {
                ast::ExprKind::Name { id, .. } => self.bind(&id.0, def::PARAM)?,
                ast::ExprKind::Tuple { .. } => self.bind(format!(".{position}").as_bytes(), def::PARAM)?,
                _ => return Err(self.invalid_parameter()),
            }
        }

        if let Some(vararg) = &arguments.vararg {
            self.bind(&vararg.0, def::PARAM)?;
            self.current().varargs = true;
        }

        if let Some(kwarg) = &arguments.kwarg {
            self.bind(&kwarg.0, def::PARAM)?;
            self.current().varkeywords = true;
        }

        let mut tuples: Vec<&[ast::Expr]> = arguments.args.iter().rev().filter_map(tuple_elements).collect();
        while let Some(elements) = tuples.pop() {
            for element in elements {
                match &element.kind {
                    ast::ExprKind::Name { id, .. } => self.bind(&id.0, def::PARAM)?,
                    ast::ExprKind::Tuple { .. } => {
                        // Bound when this tuple's turn comes.
                    }
                    _ => return Err(self.invalid_parameter()),
                }
            }
            tuples.extend(elements.iter().rev().filter_map(tuple_elements));
        }

        Ok(())
    }

    fn invalid_parameter(&mut self) -> CompileError {
        let lineno = self.current().lineno;

        self.error("invalid expression in parameter list".to_owned(), lineno)
    }

    /// An import binds the first component of the module name, or the `as`
    /// name. `import *` only marks the block, warning outside the module.
    fn record_import(&mut self, alias: &ast::Alias) -> Result<(), CompileError> {
        let name = c_str(&alias.asname.as_ref().unwrap_or(&alias.name).0);

        if name != b"*" {
            let first = name.iter().position(|&byte| byte == b'.').map_or(name, |dot| &name[..dot]);

            return self.bind(first, def::IMPORT);
        }

        if self.current().kind != BlockType::Module {
            self.warn(b"import * only allowed at module level".to_vec(), None)?;
        }
        self.current().unoptimized |= opt::IMPORT_STAR;

        Ok(())
    }

    /// A `global` name, with a warning if the block already assigned or
    /// used it.
    fn declare_global(&mut self, name: &[u8], lineno: i32) -> Result<(), CompileError> {
        let earlier = dict_get(&self.recordings[self.current.0].symbols, self.width, &mangle(self.private, name));
        let complaint: Option<&[u8]> = match earlier {
            Some(flags) if flags & def::LOCAL != 0 => Some(b"' is assigned to before global declaration"),
            Some(flags) if flags & def::USE != 0 => Some(b"' is used prior to global declaration"),
            _ => None,
        };

        if let Some(complaint) = complaint {
            const MAX_MESSAGE: usize = 255;

            let mut message = b"name '".to_vec();
            message.extend_from_slice(c_str(name));
            message.extend_from_slice(complaint);
            message.truncate(MAX_MESSAGE);

            self.warn(message, Some(lineno))?;
        }

        self.bind(name, def::GLOBAL)
    }

    /// Resolves every block, parents before children. A block is finished
    /// once all its children are, since their free names decide its cells.
    fn resolve(&mut self) -> Result<(), CompileError> {
        enum Step {
            Start { block: BlockId, enclosing: Option<NameSet>, global: NameSet },
            Finish,
        }

        let mut steps = vec![Step::Start { block: BlockId(0), enclosing: None, global: NameSet::new() }];
        let mut pending: Vec<Pending> = Vec::new();

        while let Some(step) = steps.pop() {
            match step {
                Step::Start { block, enclosing, global } => {
                    let (started, inherited) = self.resolve_names(block, enclosing, global)?;

                    steps.push(Step::Finish);
                    steps.extend(self.blocks[block.0].children.iter().rev().map(|&child| Step::Start {
                        block: child,
                        enclosing: Some(inherited.enclosing.clone()),
                        global: inherited.global.clone(),
                    }));
                    pending.push(started);
                }
                Step::Finish => {
                    let Some(finished) = pending.pop() else {
                        return Err(CompileError::System { message: "symbol table block finished twice".to_owned() });
                    };

                    let block = finished.block;
                    let free = self.finish(finished)?;
                    let Some(parent) = pending.last_mut() else {
                        continue;
                    };

                    dict_merge(&mut parent.children_free, &free);
                    let child = &self.blocks[block.0];
                    if child.has_free || child.child_has_free {
                        self.blocks[parent.block.0].child_has_free = true;
                    }
                }
            }
        }

        Ok(())
    }

    /// Gives each name of `block` its scope, and works out what its
    /// children see. Class bindings are invisible to the children, so a
    /// class hands down the sets it received.
    fn resolve_names(&mut self, block: BlockId, enclosing: Option<NameSet>, global: NameSet) -> Result<(Pending, Inherited), CompileError> {
        let kind = self.blocks[block.0].kind;
        let mut inherited = match kind {
            BlockType::Class => Inherited { enclosing: enclosing.clone().unwrap_or_default(), global: global.clone() },
            BlockType::Function | BlockType::Module => Inherited::default(),
        };

        let mut environment = Environment { enclosing, global, local: NameSet::new(), free: NameDict::new() };
        let recorded = std::mem::take(&mut self.recordings[block.0].symbols);
        let mut symbols = HashMap::with_capacity(recorded.len());
        for (name, &flags) in recorded.iter() {
            let scope = self.scope_of(block, name, flags, &mut environment)?;
            symbols.insert(name.clone(), scope.apply(flags));
        }
        self.blocks[block.0].symbols = symbols;

        let Environment { enclosing, global, local, free } = environment;
        if kind != BlockType::Class {
            if kind == BlockType::Function {
                inherited.enclosing.extend(local);
            }
            if let Some(enclosing) = &enclosing {
                inherited.enclosing.extend(enclosing.iter().cloned());
            }
            inherited.global.extend(global);
        }

        Ok((Pending { block, enclosing, free, children_free: NameDict::new() }, inherited))
    }

    /// The scope of one name of `block`, with the name recorded in the
    /// environment's sets.
    fn scope_of(&mut self, block: BlockId, name: &[u8], flags: u32, environment: &mut Environment) -> Result<Scope, CompileError> {
        let entry = &mut self.blocks[block.0];

        if flags & def::GLOBAL != 0 {
            if flags & def::PARAM != 0 {
                let mut message = b"name '".to_vec();
                message.extend_from_slice(c_str(name));
                message.extend_from_slice(b"' is local and global");
                let lineno = entry.lineno;

                return Err(self.error(String::from_utf8_lossy(&message).into_owned(), lineno));
            }

            environment.global.insert(name.to_vec());
            if let Some(enclosing) = &mut environment.enclosing {
                enclosing.remove(name);
            }

            return Ok(Scope::GlobalExplicit);
        }

        if flags & def::BOUND != 0 {
            environment.local.insert(name.to_vec());
            environment.global.remove(name);

            return Ok(Scope::Local);
        }

        if environment.enclosing.as_ref().is_some_and(|enclosing| enclosing.contains(name)) {
            entry.has_free = true;
            dict_set(&mut environment.free, self.width, name, ());

            return Ok(Scope::Free);
        }

        if !environment.global.contains(name) && entry.nested {
            entry.has_free = true;
        }

        Ok(Scope::GlobalImplicit)
    }

    /// Completes a block after its children: a function local that a child
    /// takes becomes a cell, and a name free in a child but not used here
    /// is added as free so the closure can pass through. Returns the names
    /// free in the block or below it that it does not bind.
    fn finish(&mut self, finished: Pending) -> Result<NameDict<()>, CompileError> {
        let Pending { block: id, enclosing, mut free, children_free } = finished;
        let width = self.width;

        // A fresh dict, whose layout decides the order of the free names below.
        let Ok(mut passed) = children_free.copy(|left: &Vec<u8>, right: &Vec<u8>| Ok::<bool, std::convert::Infallible>(left == right));

        let block = &mut self.blocks[id.0];
        if block.kind == BlockType::Function {
            for (name, flags) in block.symbols.iter_mut() {
                if Scope::from_flags(*flags) == Some(Scope::Local) && dict_remove(&mut passed, width, name) {
                    *flags = Scope::Cell.apply(*flags);
                }
            }
        }

        for name in passed.keys() {
            if let Some(flags) = block.symbols.get_mut(name) {
                // A method may take a name that the class body also binds.
                if block.kind == BlockType::Class && *flags & (def::BOUND | def::GLOBAL) != 0 {
                    *flags |= def::FREE_CLASS;
                }
                continue;
            }

            if enclosing.as_ref().is_some_and(|enclosing| enclosing.contains(name)) {
                block.symbols.insert(name.clone(), Scope::Free.apply(0));
                block.symbol_order.push(name.clone());
            }
        }

        self.reject_dynamic_locals(id)?;
        dict_merge(&mut free, &passed);

        Ok(free)
    }

    /// `import *` and bare `exec` need a dict of locals, which a function
    /// that is nested or holds closures cannot have.
    fn reject_dynamic_locals(&self, id: BlockId) -> Result<(), CompileError> {
        let block = &self.blocks[id.0];
        if block.kind != BlockType::Function || !(block.has_free || block.child_has_free) {
            return Ok(());
        }

        let name = truncate(c_str(&block.name), 100);
        let mut message = Vec::new();
        match block.unoptimized {
            0 | opt::TOPLEVEL | opt::EXEC => return Ok(()),
            opt::IMPORT_STAR => {
                message.extend_from_slice(b"import * is not allowed in function '");
                message.extend_from_slice(name);
                message.extend_from_slice(b"' because it ");
            }
            opt::BARE_EXEC => {
                message.extend_from_slice(b"unqualified exec is not allowed in function '");
                message.extend_from_slice(name);
                message.extend_from_slice(b"' because it ");
            }
            _ => {
                message.extend_from_slice(b"function '");
                message.extend_from_slice(name);
                message.extend_from_slice(b"' uses import * and bare exec, which are illegal because it ");
            }
        }
        let reason: &[u8] = if block.child_has_free { b"contains a nested function with free variables" } else { b"is a nested function" };
        message.extend_from_slice(reason);

        // Both flags are only set by statements that also record the line.
        let Some(line) = block.unoptimized_line else {
            return Err(CompileError::System { message: "dynamic locals without a line".to_owned() });
        };

        Err(self.error(String::from_utf8_lossy(&message).into_owned(), line))
    }
}

/// A node still to be searched for identifiers.
enum Node<'t> {
    Stmt(&'t ast::Stmt),
    Expr(&'t ast::Expr),
    Slice(&'t ast::Slice),
}

/// Private name mangling: `__spam` inside class `_Ham` becomes
/// `_Ham__spam`. Dunder names, dotted names, and classes named only with
/// underscores are left alone.
pub fn mangle<'a>(private: Option<&[u8]>, name: &'a [u8]) -> Cow<'a, [u8]> {
    let Some(private) = private else {
        return Cow::Borrowed(name);
    };

    let name_text = c_str(name);
    if !name_text.starts_with(b"__") || name_text.ends_with(b"__") || name_text.contains(&b'.') {
        return Cow::Borrowed(name);
    }

    let class = c_str(private);
    let Some(start) = class.iter().position(|&byte| byte != b'_') else {
        return Cow::Borrowed(name);
    };
    let class = &class[start..];

    let mut mangled = Vec::with_capacity(1 + class.len() + name_text.len());
    mangled.push(b'_');
    mangled.extend_from_slice(class);
    mangled.extend_from_slice(name_text);

    Cow::Owned(mangled)
}

fn dict_get<V>(dict: &NameDict<V>, width: LongWidth, name: &[u8]) -> Option<V>
where
    V: Copy,
{
    let Ok(entry) = dict.lookup(hash_bytes(width, name), |stored: &Vec<u8>| Ok::<bool, std::convert::Infallible>(stored.as_slice() == name));

    entry.map(|entry| *entry.value)
}

/// Returns whether `name` was not yet in the dict.
fn dict_set<V>(dict: &mut NameDict<V>, width: LongWidth, name: &[u8], value: V) -> bool {
    let hash = hash_bytes(width, name);
    let Ok(previous) = dict.set_item(hash, name.to_vec(), value, |stored: &Vec<u8>| Ok::<bool, std::convert::Infallible>(stored.as_slice() == name));

    previous.is_none()
}

/// Returns whether `name` was in the dict.
fn dict_remove<V>(dict: &mut NameDict<V>, width: LongWidth, name: &[u8]) -> bool {
    let Ok(removed) = dict.del_item(hash_bytes(width, name), |stored: &Vec<u8>| Ok::<bool, std::convert::Infallible>(stored.as_slice() == name));

    removed.is_some()
}

/// Adds every entry of `source` to `target`, as `dict.update` does.
fn dict_merge<V>(target: &mut NameDict<V>, source: &NameDict<V>)
where
    V: Clone,
{
    let Ok(()) = target.merge_from_dict(source, |left: &Vec<u8>, right: &Vec<u8>| Ok::<bool, std::convert::Infallible>(left == right));
}

fn tuple_elements(expression: &ast::Expr) -> Option<&[ast::Expr]> {
    match &expression.kind {
        ast::ExprKind::Tuple { elts, .. } => Some(elts),
        _ => None,
    }
}

/// Every identifier in the tree: names, attributes, keywords, parameters,
/// imported and declared names.
fn collect_identifiers(module: &ast::Mod) -> NameSet {
    let mut identifiers = NameSet::new();
    let mut nodes: Vec<Node<'_>> = match module {
        ast::Mod::Module { body } | ast::Mod::Interactive { body } | ast::Mod::Suite { body } => body.iter().map(Node::Stmt).collect(),
        ast::Mod::Expression { body } => vec![Node::Expr(body)],
    };

    let mut add = |identifier: &ast::Identifier| {
        if !identifiers.contains(&identifier.0) {
            identifiers.insert(identifier.0.clone());
        }
    };

    while let Some(node) = nodes.pop() {
        match node {
            Node::Stmt(statement) => statement_identifiers(statement, &mut add, &mut nodes),
            Node::Expr(expression) => expression_identifiers(expression, &mut add, &mut nodes),
            Node::Slice(slice) => match slice {
                ast::Slice::Slice { lower, upper, step } => push_exprs(&mut nodes, lower.iter().chain(upper).chain(step)),
                ast::Slice::ExtSlice { dims } => nodes.extend(dims.iter().map(Node::Slice)),
                ast::Slice::Index { value } => nodes.push(Node::Expr(value)),
                ast::Slice::Ellipsis => {
                    // No identifiers.
                }
            },
        }
    }

    identifiers
}

fn push_exprs<'t>(nodes: &mut Vec<Node<'t>>, expressions: impl IntoIterator<Item = &'t ast::Expr>) {
    nodes.extend(expressions.into_iter().map(Node::Expr));
}

fn push_stmts<'t>(nodes: &mut Vec<Node<'t>>, statements: &'t [ast::Stmt]) {
    nodes.extend(statements.iter().map(Node::Stmt));
}

fn arguments_identifiers<'t>(arguments: &'t ast::Arguments, add: &mut impl FnMut(&ast::Identifier), nodes: &mut Vec<Node<'t>>) {
    push_exprs(nodes, arguments.args.iter().chain(&arguments.defaults));
    arguments.vararg.iter().chain(&arguments.kwarg).for_each(add);
}

fn statement_identifiers<'t>(statement: &'t ast::Stmt, add: &mut impl FnMut(&ast::Identifier), nodes: &mut Vec<Node<'t>>) {
    match &statement.kind {
        ast::StmtKind::FunctionDef { name, args, body, decorator_list } => {
            add(name);
            arguments_identifiers(args, add, nodes);
            push_stmts(nodes, body);
            push_exprs(nodes, decorator_list);
        }
        ast::StmtKind::ClassDef { name, bases, body, decorator_list } => {
            add(name);
            push_exprs(nodes, bases.iter().chain(decorator_list));
            push_stmts(nodes, body);
        }
        ast::StmtKind::Return { value } => push_exprs(nodes, value),
        ast::StmtKind::Delete { targets } => push_exprs(nodes, targets),
        ast::StmtKind::Assign { targets, value } => push_exprs(nodes, targets.iter().chain([value])),
        ast::StmtKind::AugAssign { target, value, .. } => push_exprs(nodes, [target, value]),
        ast::StmtKind::Print { dest, values, .. } => push_exprs(nodes, dest.iter().chain(values)),
        ast::StmtKind::For { target, iter, body, orelse } => {
            push_exprs(nodes, [target, iter]);
            push_stmts(nodes, body);
            push_stmts(nodes, orelse);
        }
        ast::StmtKind::While { test, body, orelse } | ast::StmtKind::If { test, body, orelse } => {
            nodes.push(Node::Expr(test));
            push_stmts(nodes, body);
            push_stmts(nodes, orelse);
        }
        ast::StmtKind::With { context_expr, optional_vars, body } => {
            push_exprs(nodes, [context_expr].into_iter().chain(optional_vars));
            push_stmts(nodes, body);
        }
        ast::StmtKind::Raise { type_, inst, tback } => push_exprs(nodes, type_.iter().chain(inst).chain(tback)),
        ast::StmtKind::TryExcept { body, handlers, orelse } => {
            push_stmts(nodes, body);
            for handler in handlers {
                push_exprs(nodes, handler.type_.iter().chain(&handler.name));
                push_stmts(nodes, &handler.body);
            }
            push_stmts(nodes, orelse);
        }
        ast::StmtKind::TryFinally { body, finalbody } => {
            push_stmts(nodes, body);
            push_stmts(nodes, finalbody);
        }
        ast::StmtKind::Assert { test, msg } => push_exprs(nodes, [test].into_iter().chain(msg)),
        ast::StmtKind::Import { names } => alias_identifiers(names, add),
        ast::StmtKind::ImportFrom { module, names, .. } => {
            module.iter().for_each(&mut *add);
            alias_identifiers(names, add);
        }
        ast::StmtKind::Exec { body, globals, locals } => push_exprs(nodes, [body].into_iter().chain(globals).chain(locals)),
        ast::StmtKind::Global { names } => names.iter().for_each(add),
        ast::StmtKind::Expr { value } => nodes.push(Node::Expr(value)),
        ast::StmtKind::Pass | ast::StmtKind::Break | ast::StmtKind::Continue => {
            // No identifiers.
        }
    }
}

fn alias_identifiers(names: &[ast::Alias], add: &mut impl FnMut(&ast::Identifier)) {
    for alias in names {
        add(&alias.name);
        alias.asname.iter().for_each(&mut *add);
    }
}

fn expression_identifiers<'t>(expression: &'t ast::Expr, add: &mut impl FnMut(&ast::Identifier), nodes: &mut Vec<Node<'t>>) {
    let push_generators = |nodes: &mut Vec<Node<'t>>, generators: &'t [ast::Comprehension]| {
        for generator in generators {
            push_exprs(nodes, [&generator.target, &generator.iter].into_iter().chain(&generator.ifs));
        }
    };

    match &expression.kind {
        ast::ExprKind::BoolOp { values: elts, .. } | ast::ExprKind::Set { elts } | ast::ExprKind::List { elts, .. } | ast::ExprKind::Tuple { elts, .. } => push_exprs(nodes, elts),
        ast::ExprKind::BinOp { left, right, .. } => push_exprs(nodes, [&**left, &**right]),
        ast::ExprKind::UnaryOp { operand: value, .. } | ast::ExprKind::Repr { value } => nodes.push(Node::Expr(value)),
        ast::ExprKind::Lambda { args, body } => {
            arguments_identifiers(args, add, nodes);
            nodes.push(Node::Expr(body));
        }
        ast::ExprKind::IfExp { test, body, orelse } => push_exprs(nodes, [&**test, &**body, &**orelse]),
        ast::ExprKind::Dict { keys, values } => push_exprs(nodes, keys.iter().chain(values)),
        ast::ExprKind::ListComp { elt, generators } | ast::ExprKind::SetComp { elt, generators } | ast::ExprKind::GeneratorExp { elt, generators } => {
            nodes.push(Node::Expr(elt));
            push_generators(nodes, generators);
        }
        ast::ExprKind::DictComp { key, value, generators } => {
            push_exprs(nodes, [&**key, &**value]);
            push_generators(nodes, generators);
        }
        ast::ExprKind::Yield { value } => push_exprs(nodes, value.as_deref()),
        ast::ExprKind::Compare { left, comparators, .. } => push_exprs(nodes, [&**left].into_iter().chain(comparators)),
        ast::ExprKind::Call { func, args, keywords, starargs, kwargs } => {
            for keyword in keywords {
                add(&keyword.arg);
                nodes.push(Node::Expr(&keyword.value));
            }
            push_exprs(nodes, [&**func].into_iter().chain(args).chain(starargs.as_deref()).chain(kwargs.as_deref()));
        }
        ast::ExprKind::Num { .. } | ast::ExprKind::Str { .. } => {
            // No identifiers.
        }
        ast::ExprKind::Attribute { value, attr, .. } => {
            add(attr);
            nodes.push(Node::Expr(value));
        }
        ast::ExprKind::Subscript { value, slice, .. } => {
            nodes.push(Node::Expr(value));
            nodes.push(Node::Slice(slice));
        }
        ast::ExprKind::Name { id, .. } => add(id),
    }
}

/// Expected values come from CPython 2.7.18. Each dump is the output of
/// this script for the source in the test's comment:
///
/// ```python
/// import _symtable, sys, warnings
/// KINDS = {0: 'function', 1: 'class', 2: 'module'}
/// def dump(src):
///     out = []
///     with warnings.catch_warnings(record=True) as caught:
///         warnings.simplefilter('always')
///         try:
///             top = _symtable.symtable(src, '<t>', 'exec')
///         except SyntaxError as e:
///             for w in caught:
///                 out.append('warning %d %s' % (w.lineno, w.message))
///             out.append('error %d %s' % (e.lineno, e.msg))
///             return '\n'.join(out)
///     for w in caught:
///         out.append('warning %d %s' % (w.lineno, w.message))
///     def walk(ste):
///         out.append('%s %s line=%d nested=%d opt=%d varnames=%s' % (
///             KINDS[ste.type], ste.name, ste.lineno, ste.nested,
///             ste.optimized, ','.join(ste.varnames)))
///         for name in sorted(ste.symbols):
///             out.append('  %s %d' % (name, ste.symbols[name]))
///         for child in ste.children:
///             walk(child)
///     walk(top)
///     return '\n'.join(out)
/// print(dump(sys.stdin.read()))
/// ```
#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::compiler::SyntaxError;
    use crate::interp::compiler::SyntaxErrorKind;
    use crate::interp::compiler::context::TestContext;

    fn location(line: i32) -> ast::Location {
        ast::Location { lineno: line, col_offset: 0 }
    }

    fn ident(name: &str) -> ast::Identifier {
        ast::Identifier(name.as_bytes().to_vec())
    }

    fn expr(line: i32, kind: ast::ExprKind) -> ast::Expr {
        ast::Expr { kind, location: location(line) }
    }

    fn stmt(line: i32, kind: ast::StmtKind) -> ast::Stmt {
        ast::Stmt { kind, location: location(line) }
    }

    fn name(line: i32, id: &str, ctx: ast::ExprContext) -> ast::Expr {
        expr(line, ast::ExprKind::Name { id: ident(id), ctx })
    }

    fn load(line: i32, id: &str) -> ast::Expr {
        name(line, id, ast::ExprContext::Load)
    }

    fn store(line: i32, id: &str) -> ast::Expr {
        name(line, id, ast::ExprContext::Store)
    }

    fn param(line: i32, id: &str) -> ast::Expr {
        name(line, id, ast::ExprContext::Param)
    }

    fn num(line: i32) -> ast::Expr {
        expr(line, ast::ExprKind::Num { n: ast::Number::Int(1) })
    }

    fn string(line: i32) -> ast::Expr {
        expr(line, ast::ExprKind::Str { s: ast::StrLiteral::Bytes { value: b"x".to_vec(), interned: true } })
    }

    fn tuple(line: i32, elts: Vec<ast::Expr>, ctx: ast::ExprContext) -> ast::Expr {
        expr(line, ast::ExprKind::Tuple { elts, ctx })
    }

    fn add(line: i32, left: ast::Expr, right: ast::Expr) -> ast::Expr {
        expr(line, ast::ExprKind::BinOp { left: Box::new(left), op: ast::Operator::Add, right: Box::new(right) })
    }

    fn call(line: i32, func: ast::Expr, args: Vec<ast::Expr>, keywords: Vec<ast::Keyword>) -> ast::Expr {
        expr(line, ast::ExprKind::Call { func: Box::new(func), args, keywords, starargs: None, kwargs: None })
    }

    fn attribute(line: i32, value: ast::Expr, attr: &str, ctx: ast::ExprContext) -> ast::Expr {
        expr(line, ast::ExprKind::Attribute { value: Box::new(value), attr: ident(attr), ctx })
    }

    fn generator(target: ast::Expr, iter: ast::Expr, ifs: Vec<ast::Expr>) -> ast::Comprehension {
        ast::Comprehension { target, iter, ifs }
    }

    fn arguments(args: Vec<ast::Expr>, vararg: Option<&str>, kwarg: Option<&str>, defaults: Vec<ast::Expr>) -> ast::Arguments {
        ast::Arguments { args, vararg: vararg.map(ident), kwarg: kwarg.map(ident), defaults }
    }

    fn function(line: i32, name: &str, args: ast::Arguments, body: Vec<ast::Stmt>) -> ast::Stmt {
        stmt(line, ast::StmtKind::FunctionDef { name: ident(name), args, body, decorator_list: Vec::new() })
    }

    fn simple_function(line: i32, name: &str, params: &[&str], body: Vec<ast::Stmt>) -> ast::Stmt {
        let params = params.iter().map(|id| param(line, id)).collect();

        function(line, name, arguments(params, None, None, Vec::new()), body)
    }

    fn class(line: i32, name: &str, bases: Vec<ast::Expr>, body: Vec<ast::Stmt>) -> ast::Stmt {
        stmt(line, ast::StmtKind::ClassDef { name: ident(name), bases, body, decorator_list: Vec::new() })
    }

    fn assign(line: i32, target: ast::Expr, value: ast::Expr) -> ast::Stmt {
        stmt(line, ast::StmtKind::Assign { targets: vec![target], value })
    }

    fn expr_stmt(line: i32, value: ast::Expr) -> ast::Stmt {
        stmt(line, ast::StmtKind::Expr { value })
    }

    fn ret(line: i32, value: ast::Expr) -> ast::Stmt {
        stmt(line, ast::StmtKind::Return { value: Some(value) })
    }

    fn pass(line: i32) -> ast::Stmt {
        stmt(line, ast::StmtKind::Pass)
    }

    fn global(line: i32, names: &[&str]) -> ast::Stmt {
        stmt(line, ast::StmtKind::Global { names: names.iter().map(|id| ident(id)).collect() })
    }

    fn exec(line: i32, globals: Option<ast::Expr>) -> ast::Stmt {
        stmt(line, ast::StmtKind::Exec { body: string(line), globals, locals: None })
    }

    fn alias(name: &str, asname: Option<&str>) -> ast::Alias {
        ast::Alias { name: ident(name), asname: asname.map(ident) }
    }

    fn import_star(line: i32) -> ast::Stmt {
        stmt(line, ast::StmtKind::ImportFrom { module: Some(ident("os")), names: vec![alias("*", None)], level: Some(0) })
    }

    fn yield_one(line: i32) -> ast::Stmt {
        expr_stmt(line, expr(line, ast::ExprKind::Yield { value: Some(Box::new(num(line))) }))
    }

    fn module(body: Vec<ast::Stmt>) -> ast::Mod {
        ast::Mod::Module { body }
    }

    fn dump_block(table: &SymbolTable, id: BlockId, out: &mut Vec<String>) {
        let block = table.block(id);
        let kind = match block.kind {
            BlockType::Function => "function",
            BlockType::Class => "class",
            BlockType::Module => "module",
        };
        let varnames: Vec<String> = block.varnames.iter().map(|name| String::from_utf8_lossy(name).into_owned()).collect();
        out.push(format!(
            "{kind} {} line={} nested={} opt={} varnames={}",
            String::from_utf8_lossy(&block.name),
            block.lineno,
            u8::from(block.nested),
            block.unoptimized,
            varnames.join(",")
        ));

        let mut symbols: Vec<(&Vec<u8>, &u32)> = block.symbols.iter().collect();
        symbols.sort();
        for (name, flags) in symbols {
            out.push(format!("  {} {flags}", String::from_utf8_lossy(name)));
        }

        for &child in &block.children {
            dump_block(table, child, out);
        }
    }

    /// The table, or the error, after the recorded warnings, in the format
    /// of the reference script.
    fn dump(module: &ast::Mod) -> String {
        let mut context = TestContext::new();
        let result = SymbolTable::build(module, b"<t>", &mut context);

        let mut out: Vec<String> = context
            .warnings
            .iter()
            .map(|warning| {
                let lineno = warning.location.as_ref().map_or(-1, |location| location.lineno);
                format!("warning {lineno} {}", warning.message)
            })
            .collect();
        match result {
            Ok(table) => dump_block(&table, table.top(), &mut out),
            Err(CompileError::SyntaxLocated(error)) => {
                assert_eq!((error.kind, error.filename.as_slice(), error.offset, error.text.as_deref()), (SyntaxErrorKind::SyntaxError, b"<t>".as_slice(), None, None));
                out.push(format!("error {} {}", error.lineno, error.message));
            }
            Err(error) => panic!("unexpected error {error:?}"),
        }

        out.join("\n")
    }

    // def f(a):
    //     b = 1
    //     def g():
    //         return a + b + c
    //     return g
    #[test]
    fn closure_cells_and_free_variables() {
        let module = module(vec![simple_function(
            1,
            "f",
            &["a"],
            vec![
                assign(2, store(2, "b"), num(2)),
                simple_function(3, "g", &[], vec![ret(4, add(4, add(4, load(4, "a"), load(4, "b")), load(4, "c")))]),
                ret(5, load(5, "g")),
            ],
        )]);

        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  f 2050
function f line=1 nested=0 opt=0 varnames=a
  a 10244
  b 10242
  g 2058
function g line=3 nested=1 opt=0 varnames=
  a 8200
  b 8200
  c 6152"
        );
    }

    // def outer():
    //     x = 1
    //     class C:
    //         x = 2
    //         y = 3
    //         def m(self):
    //             return x, y
    //     return C
    #[test]
    fn class_names_are_not_visible_to_methods() {
        let method = simple_function(6, "m", &["self"], vec![ret(7, tuple(7, vec![load(7, "x"), load(7, "y")], ast::ExprContext::Load))]);
        let module = module(vec![simple_function(
            1,
            "outer",
            &[],
            vec![
                assign(2, store(2, "x"), num(2)),
                class(3, "C", Vec::new(), vec![assign(4, store(4, "x"), num(4)), assign(5, store(5, "y"), num(5)), method]),
                ret(8, load(8, "C")),
            ],
        )]);

        let dumped = dump(&module);

        assert_eq!(
            dumped,
            "module top line=0 nested=0 opt=8 varnames=
  outer 2050
function outer line=1 nested=0 opt=0 varnames=
  C 2058
  x 10242
class C line=3 nested=1 opt=0 varnames=
  m 2050
  x 2082
  y 2050
function m line=6 nested=1 opt=0 varnames=self
  self 2052
  x 8200
  y 6152"
        );
    }

    // x = 1
    // def f():
    //     global y
    //     y = x
    //     def g():
    //         return y, z
    #[test]
    fn explicit_and_implicit_globals() {
        let module = module(vec![
            assign(1, store(1, "x"), num(1)),
            simple_function(
                2,
                "f",
                &[],
                vec![
                    global(3, &["y"]),
                    assign(4, store(4, "y"), load(4, "x")),
                    simple_function(5, "g", &[], vec![ret(6, tuple(6, vec![load(6, "y"), load(6, "z")], ast::ExprContext::Load))]),
                ],
            ),
        ]);

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        let f = table.block(table.block(table.top()).children[0]);
        let g = table.block(f.children[0]);

        assert_eq!((f.scope(b"y"), f.scope(b"x"), g.scope(b"y"), g.scope(b"q")), (Some(Scope::GlobalExplicit), Some(Scope::GlobalImplicit), Some(Scope::GlobalImplicit), None));
        // `g` is nested and uses `z`, which no scope declares global.
        assert_eq!((f.has_free, f.child_has_free, g.has_free), (false, true, true));
        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  f 2050
  x 2050
  y 4097
function f line=2 nested=0 opt=0 varnames=
  g 2050
  x 6152
  y 4099
function g line=5 nested=1 opt=0 varnames=
  y 6152
  z 6152"
        );
    }

    // def f():
    //     a = 1
    //     b
    //     global a, b
    fn global_after_use() -> ast::Mod {
        module(vec![simple_function(1, "f", &[], vec![assign(2, store(2, "a"), num(2)), expr_stmt(3, load(3, "b")), global(4, &["a", "b"])])])
    }

    #[test]
    fn global_after_assignment_or_use_warns() {
        assert_eq!(
            dump(&global_after_use()),
            "warning 4 name 'a' is assigned to before global declaration
warning 4 name 'b' is used prior to global declaration
module top line=0 nested=0 opt=8 varnames=
  a 4097
  b 4097
  f 2050
function f line=1 nested=0 opt=0 varnames=
  a 4099
  b 4105"
        );
    }

    struct RaisingContext {
        inner: TestContext,
        is_syntax_warning: bool,
    }

    impl CompileContext for RaisingContext {
        fn long_width(&self) -> LongWidth {
            self.inner.long_width()
        }

        fn warn(&mut self, _warning: &CompileWarning) -> Result<(), WarningRaised> {
            Err(WarningRaised { is_syntax_warning: self.is_syntax_warning })
        }

        fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>> {
            self.inner.decode_default(bytes)
        }
    }

    // With `warnings.simplefilter('error')`, CPython 2.7.12's `compile`
    // raises SyntaxError("name 'a' is assigned to before global
    // declaration",) at line 1, the line of `f`'s block, with no offset or
    // text.
    #[test]
    fn raised_syntax_warning_becomes_syntax_error() {
        let mut context = RaisingContext { inner: TestContext::new(), is_syntax_warning: true };
        let result = SymbolTable::build(&global_after_use(), b"<t>", &mut context);

        assert_eq!(
            result.err(),
            Some(CompileError::SyntaxLocated(SyntaxError {
                kind: SyntaxErrorKind::SyntaxError,
                message: "name 'a' is assigned to before global declaration".to_owned(),
                filename: b"<t>".to_vec(),
                lineno: 1,
                offset: None,
                text: None,
            }))
        );

        let mut context = RaisingContext { inner: TestContext::new(), is_syntax_warning: false };
        let result = SymbolTable::build(&global_after_use(), b"<t>", &mut context);

        assert_eq!(result.err(), Some(CompileError::WarningRaised));
    }

    // def f(n):
    //     l = lambda x, y=n: x + n
    //     g = (i * n for i in range(n) if i)
    //     s = {i for i in n}
    //     d = {k: v for k, v in n}
    //     return [j for j in n for k in j]
    #[test]
    fn lambda_and_comprehension_blocks() {
        let lambda = expr(
            2,
            ast::ExprKind::Lambda {
                args: Box::new(arguments(vec![param(2, "x"), param(2, "y")], None, None, vec![load(2, "n")])),
                body: Box::new(add(2, load(2, "x"), load(2, "n"))),
            },
        );
        let genexp = expr(
            3,
            ast::ExprKind::GeneratorExp {
                elt: Box::new(add(3, load(3, "i"), load(3, "n"))),
                generators: vec![generator(store(3, "i"), call(3, load(3, "range"), vec![load(3, "n")], Vec::new()), vec![load(3, "i")])],
            },
        );
        let setcomp = expr(4, ast::ExprKind::SetComp { elt: Box::new(load(4, "i")), generators: vec![generator(store(4, "i"), load(4, "n"), Vec::new())] });
        let dictcomp = expr(
            5,
            ast::ExprKind::DictComp {
                key: Box::new(load(5, "k")),
                value: Box::new(load(5, "v")),
                generators: vec![generator(tuple(5, vec![store(5, "k"), store(5, "v")], ast::ExprContext::Store), load(5, "n"), Vec::new())],
            },
        );
        let listcomp = expr(
            6,
            ast::ExprKind::ListComp {
                elt: Box::new(load(6, "j")),
                generators: vec![generator(store(6, "j"), load(6, "n"), Vec::new()), generator(store(6, "k"), load(6, "j"), Vec::new())],
            },
        );
        let module = module(vec![simple_function(
            1,
            "f",
            &["n"],
            vec![
                assign(2, store(2, "l"), lambda),
                assign(3, store(3, "g"), genexp),
                assign(4, store(4, "s"), setcomp),
                assign(5, store(5, "d"), dictcomp),
                ret(6, listcomp),
            ],
        )]);

        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  f 2050
function f line=1 nested=0 opt=0 varnames=n
  d 2050
  g 2050
  j 2058
  k 2050
  l 2050
  n 10252
  range 6152
  s 2050
function lambda line=2 nested=1 opt=0 varnames=x,y
  n 8200
  x 2060
  y 2052
function genexpr line=0 nested=1 opt=0 varnames=.0
  .0 2052
  i 2058
  n 8200
function setcomp line=0 nested=1 opt=0 varnames=.0
  .0 2052
  _[1] 2050
  i 2058
function dictcomp line=0 nested=1 opt=0 varnames=.0
  .0 2052
  _[1] 2050
  k 2058
  v 2058"
        );

        // `co_flags & CO_GENERATOR` of the nested code objects.
        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        let f = table.block(table.block(table.top()).children[0]);
        let generators: Vec<bool> = f.children.iter().map(|&child| table.block(child).generator).collect();
        assert_eq!((f.generator, generators), (false, vec![false, true, false, false]));
    }

    // def f(a, (b, (c, d)), e, (g, h), *args, **kw):
    //     pass
    #[test]
    fn nested_tuple_parameters() {
        let store_tuple = |elts| tuple(1, elts, ast::ExprContext::Store);
        let params = vec![
            param(1, "a"),
            store_tuple(vec![store(1, "b"), store_tuple(vec![store(1, "c"), store(1, "d")])]),
            param(1, "e"),
            store_tuple(vec![store(1, "g"), store(1, "h")]),
        ];
        let module = module(vec![function(1, "f", arguments(params, Some("args"), Some("kw"), Vec::new()), vec![pass(2)])]);

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        let f = table.block(table.block(table.top()).children[0]);
        assert_eq!((f.varargs, f.varkeywords), (true, true));
        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  f 2050
function f line=1 nested=0 opt=0 varnames=a,.1,e,.3,args,kw,b,c,d,g,h
  .1 2052
  .3 2052
  a 2052
  args 2052
  b 2052
  c 2052
  d 2052
  e 2052
  g 2052
  h 2052
  kw 2052"
        );
    }

    // class _Foo:
    //     __x = 1
    //     __y__ = 2
    //     def __m(self, __a):
    //         import __b.c
    //         return self.__x, __z
    // __x = 3
    #[test]
    fn private_names_are_mangled() {
        let import = stmt(5, ast::StmtKind::Import { names: vec![alias("__b.c", None)] });
        let method = simple_function(
            4,
            "__m",
            &["self", "__a"],
            vec![import, ret(6, tuple(6, vec![attribute(6, load(6, "self"), "__x", ast::ExprContext::Load), load(6, "__z")], ast::ExprContext::Load))],
        );
        let module = module(vec![
            class(1, "_Foo", Vec::new(), vec![assign(2, store(2, "__x"), num(2)), assign(3, store(3, "__y__"), num(3)), method]),
            assign(7, store(7, "__x"), num(7)),
        ]);

        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  _Foo 2050
  __x 2050
class _Foo line=1 nested=0 opt=0 varnames=
  _Foo__m 2050
  _Foo__x 2050
  __y__ 2050
function __m line=4 nested=0 opt=0 varnames=self,_Foo__a
  _Foo__a 2052
  _Foo__b 2112
  _Foo__z 6152
  self 2060"
        );
    }

    #[test]
    fn mangle_rules() {
        assert_eq!(mangle(Some(b"__Ham"), b"__spam").as_ref(), b"_Ham__spam");
        assert_eq!(mangle(Some(b"Ham"), b"__spam__").as_ref(), b"__spam__");
        assert_eq!(mangle(Some(b"Ham"), b"__a.b").as_ref(), b"__a.b");
        assert_eq!(mangle(Some(b"___"), b"__spam").as_ref(), b"__spam");
        assert_eq!(mangle(Some(b"Ham"), b"_spam").as_ref(), b"_spam");
        assert_eq!(mangle(None, b"__spam").as_ref(), b"__spam");
    }

    // def f():
    //     from os import *
    //     def g():
    //         return path
    #[test]
    fn import_star_with_free_child() {
        let module = module(vec![simple_function(1, "f", &[], vec![import_star(2), simple_function(3, "g", &[], vec![ret(4, load(4, "path"))])])]);

        assert_eq!(
            dump(&module),
            "warning 1 import * only allowed at module level
error 2 import * is not allowed in function 'f' because it contains a nested function with free variables"
        );
    }

    // def f():
    //     x = 1
    //     def g():
    //         from os import *
    //         return x
    #[test]
    fn import_star_in_nested_function() {
        let module = module(vec![simple_function(
            1,
            "f",
            &[],
            vec![assign(2, store(2, "x"), num(2)), simple_function(3, "g", &[], vec![import_star(4), ret(5, load(5, "x"))])],
        )]);

        assert_eq!(
            dump(&module),
            "warning 3 import * only allowed at module level
error 4 import * is not allowed in function 'g' because it is a nested function"
        );
    }

    // def f():
    //     exec "x"
    //     def g():
    //         return x
    #[test]
    fn bare_exec_with_free_child() {
        let module = module(vec![simple_function(1, "f", &[], vec![exec(2, None), simple_function(3, "g", &[], vec![ret(4, load(4, "x"))])])]);

        assert_eq!(dump(&module), "error 2 unqualified exec is not allowed in function 'f' because it contains a nested function with free variables");
    }

    // def f():
    //     def g():
    //         exec "x"
    //         return len
    #[test]
    fn bare_exec_in_nested_function_using_a_global() {
        let module = module(vec![simple_function(1, "f", &[], vec![simple_function(2, "g", &[], vec![exec(3, None), ret(4, load(4, "len"))])])]);

        assert_eq!(dump(&module), "error 3 unqualified exec is not allowed in function 'g' because it is a nested function");
    }

    // def f():
    //     y = 1
    //     exec "y"
    //     from os import *
    //     def g():
    //         return y
    #[test]
    fn import_star_and_bare_exec() {
        let module = module(vec![simple_function(
            1,
            "f",
            &[],
            vec![assign(2, store(2, "y"), num(2)), exec(3, None), import_star(4), simple_function(5, "g", &[], vec![ret(6, load(6, "y"))])],
        )]);

        assert_eq!(
            dump(&module),
            "warning 1 import * only allowed at module level
error 3 function 'f' uses import * and bare exec, which are illegal because it contains a nested function with free variables"
        );
    }

    // def f():
    //     exec "y" in {}
    //     def g():
    //         return y
    #[test]
    fn qualified_exec_is_allowed() {
        let globals = expr(2, ast::ExprKind::Dict { keys: Vec::new(), values: Vec::new() });
        let module = module(vec![simple_function(1, "f", &[], vec![exec(2, Some(globals)), simple_function(3, "g", &[], vec![ret(4, load(4, "y"))])])]);

        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=8 varnames=
  f 2050
function f line=1 nested=0 opt=2 varnames=
  g 2050
function g line=3 nested=1 opt=0 varnames=
  y 6152"
        );
    }

    // class C:
    //     from os import *
    #[test]
    fn import_star_in_class_warns() {
        let module = module(vec![class(1, "C", Vec::new(), vec![import_star(2)])]);

        assert_eq!(
            dump(&module),
            "warning 1 import * only allowed at module level
module top line=0 nested=0 opt=8 varnames=
  C 2050
class C line=1 nested=0 opt=1 varnames="
        );
    }

    // from os import *
    // exec "x"
    // import sys
    #[test]
    fn module_level_import_star_and_exec() {
        let import = stmt(3, ast::StmtKind::Import { names: vec![alias("sys", None)] });
        let module = module(vec![import_star(1), exec(2, None), import]);

        assert_eq!(
            dump(&module),
            "module top line=0 nested=0 opt=13 varnames=
  sys 2112"
        );

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        assert_eq!(table.block(table.top()).unoptimized_line, Some(1));
    }

    // def f():
    //     yield 1
    //     return 2
    #[test]
    fn return_value_after_yield() {
        let module = module(vec![simple_function(1, "f", &[], vec![yield_one(2), ret(3, num(3))])]);

        assert_eq!(dump(&module), "error 3 'return' with argument inside generator");
    }

    // def f():
    //     return 2
    //     yield 1
    #[test]
    fn yield_after_return_value() {
        let module = module(vec![simple_function(1, "f", &[], vec![ret(2, num(2)), yield_one(3)])]);

        assert_eq!(dump(&module), "error 3 'return' with argument inside generator");
    }

    // def f(a, b, a):
    //     pass
    #[test]
    fn duplicate_argument() {
        let module = module(vec![simple_function(1, "f", &["a", "b", "a"], vec![pass(2)])]);

        assert_eq!(dump(&module), "error 1 duplicate argument 'a' in function definition");
    }

    // def f(a, (b, a)):
    //     pass
    #[test]
    fn duplicate_nested_argument() {
        let params = vec![param(1, "a"), tuple(1, vec![store(1, "b"), store(1, "a")], ast::ExprContext::Store)];
        let module = module(vec![function(1, "f", arguments(params, None, None, Vec::new()), vec![pass(2)])]);

        assert_eq!(dump(&module), "error 1 duplicate argument 'a' in function definition");
    }

    // def f(foo, bar, baz, qux, quux, corge, grault, garply, waldo):
    //     global foo, bar, baz, qux, quux, corge, grault, garply, waldo
    //
    // The first name in dict order, not in source order, is reported.
    #[test]
    fn parameter_declared_global() {
        let names = ["foo", "bar", "baz", "qux", "quux", "corge", "grault", "garply", "waldo"];
        let module = module(vec![simple_function(1, "f", &names, vec![global(2, &names)])]);

        assert_eq!(dump(&module), "error 1 name 'bar' is local and global");
    }

    // import os.path as p, sys
    // from __future__ import division
    // x.attr(kw=1)
    // def f((t, u), *a, **k):
    //     global g
    // class C(B):
    //     try: pass
    //     except E as e: lambda q=1: q
    // from . import m
    //
    // Expected: the str fields of every node in ast.walk(ast.parse(src))
    // named id, attr, name, arg, asname, module, vararg, or kwarg, and the
    // names of Global nodes.
    #[test]
    fn identifiers_cover_the_tree() {
        let import = stmt(1, ast::StmtKind::Import { names: vec![alias("os.path", Some("p")), alias("sys", None)] });
        let future = stmt(2, ast::StmtKind::ImportFrom { module: Some(ident("__future__")), names: vec![alias("division", None)], level: Some(0) });
        let keyword = ast::Keyword { arg: ident("kw"), value: num(3) };
        let method_call = expr_stmt(3, call(3, attribute(3, load(3, "x"), "attr", ast::ExprContext::Load), Vec::new(), vec![keyword]));
        let params = vec![tuple(4, vec![store(4, "t"), store(4, "u")], ast::ExprContext::Store)];
        let function = function(4, "f", arguments(params, Some("a"), Some("k"), Vec::new()), vec![global(5, &["g"])]);
        let lambda = expr(8, ast::ExprKind::Lambda { args: Box::new(arguments(vec![param(8, "q")], None, None, vec![num(8)])), body: Box::new(load(8, "q")) });
        let handler = ast::ExceptHandler { type_: Some(load(8, "E")), name: Some(store(8, "e")), body: vec![expr_stmt(8, lambda)], location: location(8) };
        let try_except = stmt(7, ast::StmtKind::TryExcept { body: vec![pass(7)], handlers: vec![handler], orelse: Vec::new() });
        let class = class(6, "C", vec![load(6, "B")], vec![try_except]);
        let relative = stmt(9, ast::StmtKind::ImportFrom { module: None, names: vec![alias("m", None)], level: Some(1) });
        let module = module(vec![import, future, method_call, function, class, relative]);

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        let mut identifiers: Vec<String> = table.identifiers.iter().map(|name| String::from_utf8_lossy(name).into_owned()).collect();
        identifiers.sort();

        assert_eq!(identifiers, ["B", "C", "E", "__future__", "a", "attr", "division", "e", "f", "g", "k", "kw", "m", "os.path", "p", "q", "sys", "t", "u", "x"]);
    }

    #[test]
    fn blocks_are_keyed_by_node() {
        let module = module(vec![simple_function(1, "f", &[], vec![pass(2)])]);

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        let ast::Mod::Module { body } = &module else {
            unreachable!("built as a module");
        };

        assert_eq!(table.lookup(NodeKey::of_mod(&module)), Some(table.top()));
        assert_eq!(table.lookup(NodeKey::of_stmt(&body[0])), Some(table.block(table.top()).children[0]));
    }

    #[test]
    fn deep_expression_does_not_overflow() {
        let mut deep = load(1, "x");
        for _ in 0..100_000 {
            deep = expr(1, ast::ExprKind::UnaryOp { op: ast::UnaryOp::Not, operand: Box::new(deep) });
        }
        let module = module(vec![expr_stmt(1, deep)]);

        let mut context = TestContext::new();
        let table = SymbolTable::build(&module, b"<t>", &mut context).unwrap();
        assert_eq!(table.block(table.top()).scope(b"x"), Some(Scope::GlobalImplicit));
    }
}
