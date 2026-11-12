//! Code generation: walks a module's syntax tree with its symbol table and
//! emits basic blocks for every code object. `assemble` and `peephole` then
//! produce the bytecode the reference compiler emits.

mod expressions;
mod functions;
mod pools;
mod statements;

use crate::interp::code::CodeFlags;
use crate::interp::code::op;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::SyntaxError;
use crate::interp::compiler::SyntaxErrorKind;
use crate::interp::compiler::assemble;
use crate::interp::compiler::assemble::BasicBlock;
use crate::interp::compiler::assemble::BlockIndex;
use crate::interp::compiler::assemble::Instruction;
use crate::interp::compiler::assemble::Jump;
use crate::interp::compiler::ast;
use crate::interp::compiler::ast::ExprContext;
use crate::interp::compiler::context::CompileContext;
use crate::interp::compiler::context::CompileError;
use crate::interp::compiler::future::FutureFeatures;
use crate::interp::compiler::object::Object;
use crate::interp::compiler::peephole;
use crate::interp::compiler::symtable::BlockId;
use crate::interp::compiler::symtable::BlockType;
use crate::interp::compiler::symtable::Scope;
use crate::interp::compiler::symtable::SymbolTable;
use crate::interp::compiler::symtable::def;
use crate::interp::compiler::symtable::mangle;
use crate::interp::compiler::unit::CodeUnit;

use self::pools::ConstantPool;
use self::pools::NamePool;

/// A statement that changes where `break` and `continue` go, or whether
/// they are allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Control {
    /// A `for` or `while` loop; `continue` jumps to `start`.
    Loop { start: BlockIndex },
    /// The body of `try`/`except`.
    TryExcept,
    /// The body of `try`/`finally` or `with`.
    TryFinally,
    /// A `finally` suite, or the cleanup of `with`.
    FinallyBody,
}

/// The name tuple an instruction argument indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameList {
    /// `co_names`: globals, attributes, and names of unoptimized scopes.
    Names,
    /// `co_varnames`: fast locals.
    Locals,
    /// `co_cellvars`.
    Cells,
    /// `co_freevars`.
    Frees,
}

/// One code object under construction.
struct CodeBuilder {
    symbols: BlockId,
    name: Vec<u8>,
    name_interned: bool,

    constants: ConstantPool,
    names: NamePool,
    locals: NamePool,
    cells: NamePool,
    frees: NamePool,

    /// Inside a class, the class name that `__private` names are mangled
    /// with.
    class_name: Option<Vec<u8>>,
    argcount: u32,

    blocks: Vec<BasicBlock>,
    current: BlockIndex,
    control: Vec<Control>,

    /// The line of the `def`, `class`, or expression that starts the code
    /// object; `None` for modules, which start at their first instruction.
    definition_line: Option<i32>,
    line: i32,
    /// An instruction already starts `line`.
    line_started: bool,
}

impl CodeBuilder {
    fn new(symtable: &SymbolTable, symbols: BlockId, name: Vec<u8>, name_interned: bool, definition_line: Option<i32>) -> Self {
        let entry = symtable.block(symbols);

        // Cell and free variables are numbered in sorted name order, the
        // free ones after the cells.
        let mut sorted: Vec<&Vec<u8>> = entry.symbols.keys().collect();
        sorted.sort();
        let cells: NamePool = sorted.iter().filter(|name| entry.scope(name) == Some(Scope::Cell)).map(|name| name.to_vec()).collect();
        let mut frees = NamePool::starting_at(cells.len() as i32);
        for name in sorted {
            let class_free = entry.flags(name).is_some_and(|flags| flags & def::FREE_CLASS != 0);
            if entry.scope(name) == Some(Scope::Free) || class_free {
                frees.index_of(name);
            }
        }

        Self {
            symbols,
            name,
            name_interned,
            constants: ConstantPool::default(),
            names: NamePool::default(),
            locals: entry.varnames.iter().cloned().collect(),
            cells,
            frees,
            class_name: None,
            argcount: 0,
            blocks: vec![BasicBlock::default()],
            current: 0,
            control: Vec::new(),
            definition_line,
            line: 0,
            line_started: false,
        }
    }

    fn pool(&mut self, list: NameList) -> &mut NamePool {
        match list {
            NameList::Names => &mut self.names,
            NameList::Locals => &mut self.locals,
            NameList::Cells => &mut self.cells,
            NameList::Frees => &mut self.frees,
        }
    }
}

struct Compiler<'a> {
    filename: &'a [u8],
    symtable: &'a SymbolTable,
    /// The line of the last `from __future__` import at the top of the
    /// module.
    future_import_line: Option<i32>,
    /// The `compile()` flags merged with the module's `__future__` features.
    flags: u32,
    /// `single` mode: expression statements of the module print their value.
    interactive: bool,
    unit: CodeBuilder,
    /// The code objects the current one is nested in, innermost last.
    enclosing: Vec<CodeBuilder>,
    context: &'a mut dyn CompileContext,
}

impl Compiler<'_> {
    fn module(&mut self, module: &ast::Mod) -> Result<CodeUnit, CompileError> {
        let returns_none = match module {
            ast::Mod::Module { body } => {
                self.body_with_docstring(body)?;
                true
            }
            ast::Mod::Interactive { body } => {
                self.interactive = true;
                self.statements(body)?;
                true
            }
            ast::Mod::Expression { body } => {
                self.expression(body)?;
                false
            }
            ast::Mod::Suite { .. } => return Err(system_error("suite should not be possible")),
        };

        self.finish_unit(returns_none)
    }

    fn syntax_error(&self, message: &str) -> CompileError {
        CompileError::Syntax(SyntaxError { kind: SyntaxErrorKind::SyntaxError, message: message.to_owned(), filename: self.filename.to_vec(), lineno: self.unit.line, offset: None, text: None })
    }

    fn has_future(&self, feature: u32) -> bool {
        self.flags & feature != 0
    }

    fn scope_kind(&self) -> BlockType {
        self.symtable.block(self.unit.symbols).kind
    }

    /// Starts attributing instructions to a new statement's line.
    fn set_line(&mut self, line: i32) {
        self.unit.line = line;
        self.unit.line_started = false;
    }

    /// An expression on a later line than the statement moves the line
    /// forward; it never moves back.
    fn advance_line(&mut self, line: i32) {
        if line > self.unit.line {
            self.set_line(line);
        }
    }

    fn allocate_block(&mut self) -> BlockIndex {
        self.unit.blocks.push(BasicBlock::default());

        self.unit.blocks.len() - 1
    }

    /// Makes `block` the fall-through successor of the current block and
    /// continues emitting into it.
    fn continue_in(&mut self, block: BlockIndex) {
        let current = self.unit.current;
        self.unit.blocks[current].next = Some(block);
        self.unit.current = block;
    }

    fn continue_in_new_block(&mut self) {
        let block = self.allocate_block();
        self.continue_in(block);
    }

    fn push(&mut self, mut instruction: Instruction) {
        if !self.unit.line_started {
            self.unit.line_started = true;
            instruction.line = Some(self.unit.line);
        }

        let current = self.unit.current;
        let block = &mut self.unit.blocks[current];
        if instruction.opcode == op::RETURN_VALUE {
            block.returns = true;
        }
        block.instructions.push(instruction);
    }

    fn emit(&mut self, opcode: u8) {
        self.push(Instruction { opcode, arg: None, jump: None, line: None });
    }

    fn emit_arg(&mut self, opcode: u8, arg: i32) {
        self.push(Instruction { opcode, arg: Some(arg), jump: None, line: None });
    }

    fn emit_jump(&mut self, opcode: u8, jump: Jump) {
        self.push(Instruction { opcode, arg: Some(0), jump: Some(jump), line: None });
    }

    fn load_constant(&mut self, object: Object) {
        let index = self.unit.constants.index_of(object);
        self.emit_arg(op::LOAD_CONST, index);
    }

    /// An instruction indexing `name` in one of the name tuples, unmangled.
    fn emit_name(&mut self, opcode: u8, list: NameList, name: &[u8]) {
        let index = self.unit.pool(list).index_of(name);
        self.emit_arg(opcode, index);
    }

    /// An instruction indexing `co_names` with a name subject to private
    /// name mangling.
    fn emit_mangled(&mut self, opcode: u8, name: &[u8]) {
        let mangled = mangle(self.unit.class_name.as_deref(), name);
        self.emit_name(opcode, NameList::Names, &mangled);
    }

    fn enter_control(&mut self, control: Control) -> Result<(), CompileError> {
        // The interpreter's block stack has 20 entries per frame.
        const MAX_NESTING: usize = 20;

        if self.unit.control.len() >= MAX_NESTING {
            return Err(system_error("too many statically nested blocks"));
        }
        self.unit.control.push(control);

        Ok(())
    }

    fn leave_control(&mut self) {
        self.unit.control.pop();
    }

    /// Loads, stores, or deletes a variable with the opcode its scope
    /// calls for.
    fn access_name(&mut self, name: &[u8], ctx: ExprContext) -> Result<(), CompileError> {
        /// How the scope of a name is accessed.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Access {
            /// A cell or free variable of a closure.
            Cell,
            /// An optimized function local.
            Fast,
            Global,
            /// Looked up by name at run time.
            Dynamic,
        }

        let mangled = mangle(self.unit.class_name.as_deref(), name);
        let entry = self.symtable.block(self.unit.symbols);
        let in_function = entry.kind == BlockType::Function;

        let (access, list) = match entry.scope(&mangled) {
            Some(Scope::Free) => (Access::Cell, NameList::Frees),
            Some(Scope::Cell) => (Access::Cell, NameList::Cells),
            Some(Scope::Local) if in_function => (Access::Fast, NameList::Locals),
            Some(Scope::GlobalImplicit) if in_function && entry.unoptimized == 0 => (Access::Global, NameList::Names),
            Some(Scope::GlobalExplicit) => (Access::Global, NameList::Names),
            _ => (Access::Dynamic, NameList::Names),
        };

        let opcode = match (access, ctx) {
            // Trees from the parser never put names in these contexts;
            // the reference then emits opcode 0.
            (_, ExprContext::AugLoad | ExprContext::AugStore) => 0,
            (Access::Cell, ExprContext::Load) => op::LOAD_DEREF,
            (Access::Cell, ExprContext::Store) => op::STORE_DEREF,
            (Access::Cell, ExprContext::Del) => {
                let name = String::from_utf8_lossy(name);
                return Err(CompileError::SyntaxUnlocated { message: format!("can not delete variable '{name}' referenced in nested scope") });
            }
            (Access::Cell, ExprContext::Param) => return Err(system_error("param invalid for deref variable")),
            (Access::Fast, ExprContext::Load) => op::LOAD_FAST,
            (Access::Fast, ExprContext::Store) => op::STORE_FAST,
            (Access::Fast, ExprContext::Del) => op::DELETE_FAST,
            (Access::Fast, ExprContext::Param) => return Err(system_error("param invalid for local variable")),
            (Access::Global, ExprContext::Load) => op::LOAD_GLOBAL,
            (Access::Global, ExprContext::Store) => op::STORE_GLOBAL,
            (Access::Global, ExprContext::Del) => op::DELETE_GLOBAL,
            (Access::Global, ExprContext::Param) => return Err(system_error("param invalid for global variable")),
            (Access::Dynamic, ExprContext::Load) => op::LOAD_NAME,
            (Access::Dynamic, ExprContext::Store) => op::STORE_NAME,
            (Access::Dynamic, ExprContext::Del) => op::DELETE_NAME,
            (Access::Dynamic, ExprContext::Param) => return Err(system_error("param invalid for name variable")),
        };

        self.emit_name(opcode, list, &mangled);

        Ok(())
    }

    /// Ends the current code object: adds the implicit return, lays out and
    /// optimizes the bytecode, and builds the code object.
    fn finish_unit(&mut self, returns_none: bool) -> Result<CodeUnit, CompileError> {
        let current = self.unit.current;
        if !self.unit.blocks[current].returns {
            self.continue_in_new_block();
            if returns_none {
                self.load_constant(Object::None);
            }
            self.emit(op::RETURN_VALUE);
        }

        // Without a definition line, the code object starts at the line of
        // its first instruction, or at line 1 if the entry block is empty.
        let first_line = match self.unit.definition_line {
            Some(line) => line,
            None => self.unit.blocks.first().and_then(|entry| entry.instructions.first()).and_then(|instruction| instruction.line).unwrap_or(1),
        };

        let assembly = assemble::assemble(&mut self.unit.blocks, first_line);
        let mut lnotab = assembly.lnotab;

        let mut consts = self.unit.constants.objects().to_vec();
        let names = self.unit.names.names().to_vec();
        let code = peephole::optimize(assembly.code, &mut consts, &names, &mut lnotab, &mut *self.context);
        pools::intern_identifier_like(&consts);
        let stacksize = assemble::stack_depth(&self.unit.blocks)?;

        Ok(CodeUnit {
            argcount: self.unit.argcount,
            nlocals: self.unit.locals.len() as u32,
            stacksize: stacksize as u32,
            flags: self.code_flags(),
            code,
            consts: consts.into_iter().map(Object::into_constant).collect(),
            names,
            varnames: self.unit.locals.names().to_vec(),
            freevars: self.unit.frees.names().to_vec(),
            cellvars: self.unit.cells.names().to_vec(),
            filename: self.filename.to_vec(),
            name: self.unit.name.clone(),
            name_interned: self.unit.name_interned,
            firstlineno: first_line,
            lnotab,
        })
    }

    fn code_flags(&self) -> u32 {
        const FUTURE_FLAGS: u32 = CompilerFlags::FUTURE_DIVISION
            | CompilerFlags::FUTURE_ABSOLUTE_IMPORT
            | CompilerFlags::FUTURE_WITH_STATEMENT
            | CompilerFlags::FUTURE_PRINT_FUNCTION
            | CompilerFlags::FUTURE_UNICODE_LITERALS;

        let entry = self.symtable.block(self.unit.symbols);
        let mut flags = self.flags & FUTURE_FLAGS;

        if entry.kind != BlockType::Module {
            flags |= CodeFlags::NEWLOCALS;
        }
        if entry.kind == BlockType::Function {
            let function_flags = [
                (entry.unoptimized == 0, CodeFlags::OPTIMIZED),
                (entry.nested, CodeFlags::NESTED),
                (entry.generator, CodeFlags::GENERATOR),
                (entry.varargs, CodeFlags::VARARGS),
                (entry.varkeywords, CodeFlags::VARKEYWORDS),
            ];
            for (set, flag) in function_flags {
                if set {
                    flags |= flag;
                }
            }
        }
        if self.unit.frees.is_empty() && self.unit.cells.is_empty() {
            flags |= CodeFlags::NOFREE;
        }

        flags
    }
}

/// Compiles a module tree to its code object. `flags` holds the
/// `compile()` flags, including `__future__` features inherited from the
/// caller.
pub fn compile_ast(module: &ast::Mod, filename: &[u8], flags: CompilerFlags, context: &mut dyn CompileContext) -> Result<CodeUnit, CompileError> {
    let future = FutureFeatures::from_ast(module, filename)?;

    let symtable = SymbolTable::build(module, filename, context)?;
    let unit = CodeBuilder::new(&symtable, symtable.top(), b"<module>".to_vec(), true, None);
    let mut compiler =
        Compiler { filename, symtable: &symtable, future_import_line: future.last_import_line, flags: future.features | flags.0, interactive: false, unit, enclosing: Vec::new(), context };

    compiler.module(module)
}

fn system_error(message: &str) -> CompileError {
    CompileError::System { message: message.to_owned() }
}

/// Expected bytes come from the reference CPython 2.7.18:
///
/// ```python
/// import ast, marshal
/// print marshal.dumps(compile(ast.parse('if x:\n    y\n'), '<t>', 'exec')).encode('hex')
/// print marshal.dumps(compile(ast.Interactive(ast.parse('print x\nx + 1\n').body), '<t>', 'single')).encode('hex')
/// print marshal.dumps(compile(ast.Expression(ast.parse('a and b', mode='eval').body), '<t>', 'eval')).encode('hex')
/// m = ast.Module([ast.Expr(ast.Name('x', ast.Param(), lineno=1, col_offset=0), lineno=1, col_offset=0)])
/// compile(m, '<t>', 'exec')  # SystemError: param invalid for name variable
/// ```
#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::compiler::ast::ExprKind;
    use crate::interp::compiler::ast::StmtKind;
    use crate::interp::compiler::context::TestContext;
    use crate::interp::compiler::marshal;

    fn location(lineno: i32, col_offset: i32) -> ast::Location {
        ast::Location { lineno, col_offset }
    }

    fn name(lineno: i32, col_offset: i32, id: &str, ctx: ExprContext) -> ast::Expr {
        ast::Expr { kind: ExprKind::Name { id: ast::Identifier(id.as_bytes().to_vec()), ctx }, location: location(lineno, col_offset) }
    }

    fn expression_statement(lineno: i32, value: ast::Expr) -> ast::Stmt {
        ast::Stmt { kind: StmtKind::Expr { value }, location: location(lineno, 0) }
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default()).collect()
    }

    fn compile(module: &ast::Mod) -> Result<Vec<u8>, CompileError> {
        let code = compile_ast(module, b"<t>", CompilerFlags(0), &mut TestContext::new())?;

        Ok(marshal::dump(&code).expect("the code object marshals"))
    }

    #[test]
    fn if_without_else_from_ast_objects() {
        // A tree built through `_ast` has an empty `orelse` list; the bytes
        // match the parsed source.
        let test = name(1, 3, "x", ExprContext::Load);
        let body = vec![expression_statement(2, name(2, 4, "y", ExprContext::Load))];
        let module = ast::Mod::Module { body: vec![ast::Stmt { kind: StmtKind::If { test, body, orelse: Vec::new() }, location: location(1, 0) }] };

        let expected = hex(
            "63000000000000000001000000400000007311000000650000720d00650100016e00006400005328010000004e280200000074010000007874010000007928000000002800000000280000000073030000003c743e74080000003c6d6f64756c653e0100000073020000000601",
        );
        assert_eq!(compile(&module), Ok(expected));
    }

    #[test]
    fn interactive_prints_expression_statements() {
        let print = ast::Stmt { kind: StmtKind::Print { dest: None, values: vec![name(1, 6, "x", ExprContext::Load)], nl: true }, location: location(1, 0) };
        let one = ast::Expr { kind: ExprKind::Num { n: ast::Number::Int(1) }, location: location(2, 4) };
        let sum = ast::Expr { kind: ExprKind::BinOp { left: Box::new(name(2, 0, "x", ExprContext::Load)), op: ast::Operator::Add, right: Box::new(one) }, location: location(2, 0) };
        let module = ast::Mod::Interactive { body: vec![print, expression_statement(2, sum)] };

        let expected = hex(
            "630000000000000000020000004000000073110000006500004748650000640000174664010053280200000069010000004e280100000074010000007828000000002800000000280000000073030000003c743e74080000003c6d6f64756c653e0100000073020000000501",
        );
        assert_eq!(compile(&module), Ok(expected));
    }

    #[test]
    fn expression_mode_returns_the_value() {
        let values = vec![name(1, 0, "a", ExprContext::Load), name(1, 6, "b", ExprContext::Load)];
        let body = ast::Expr { kind: ExprKind::BoolOp { op: ast::BoolOp::And, values }, location: location(1, 0) };
        let module = ast::Mod::Expression { body: Box::new(body) };

        let expected = hex(
            "6300000000000000000100000040000000730a0000006500006f0900650100532800000000280200000074010000006174010000006228000000002800000000280000000073030000003c743e74080000003c6d6f64756c653e010000007400000000",
        );
        assert_eq!(compile(&module), Ok(expected));
    }

    #[test]
    fn param_context_outside_arguments_is_a_system_error() {
        let module = ast::Mod::Module { body: vec![expression_statement(1, name(1, 0, "x", ExprContext::Param))] };

        assert_eq!(compile(&module), Err(CompileError::System { message: "param invalid for name variable".to_owned() }));
    }

    #[test]
    fn many_generator_clauses_do_not_overflow() {
        const CLAUSES: usize = 20_000;

        let clause = || ast::Comprehension { target: name(1, 0, "x", ExprContext::Store), iter: name(1, 0, "y", ExprContext::Load), ifs: Vec::new() };
        let generators = (0..CLAUSES).map(|_| clause()).collect();
        let comprehension = ast::Expr { kind: ExprKind::ListComp { elt: Box::new(name(1, 0, "x", ExprContext::Load)), generators }, location: location(1, 0) };
        let module = ast::Mod::Module { body: vec![expression_statement(1, comprehension)] };

        let code = compile_ast(&module, b"<t>", CompilerFlags(0), &mut TestContext::new()).map(|unit| unit.code);

        // `LIST_APPEND` reaches the list below one iterator per clause.
        let append = [op::LIST_APPEND, (CLAUSES + 1) as u8, ((CLAUSES + 1) >> 8) as u8];
        assert!(code.is_ok_and(|code| code.windows(3).any(|window| window == append)));
    }
}
