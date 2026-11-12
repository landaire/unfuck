//! The `parser` module of CPython 2.7.12: concrete syntax
//! trees as `parser.st` objects, their tuple and list forms, the validation
//! of trees built from those forms, and their compilation.
//!
//! Where CPython reads past a node's children, reads the string of a
//! nonterminal, or returns with an exception still pending, its behavior is
//! undefined and this module halts instead.

mod validate;

use std::cell::RefCell;
use std::cmp::Ordering;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::arguments::halt_on_unknown;
use crate::interp::builtins::arguments::wrapper_operand;
use crate::interp::builtins::compile::parse_error;
use crate::interp::builtins::compile::syntax_error_class;
use crate::interp::builtins::exec::compile_module;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::method_no_arguments;
use crate::interp::builtins::modules::new_exception_class;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::operator::is_sequence;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::parse;
use crate::interp::builtins::parse_with;
use crate::interp::builtins::positional;
use crate::interp::builtins::receiver;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::source_codecs::VmSourceCodecs;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::ParseError;
use crate::interp::compiler::parser::Cst;
use crate::interp::compiler::parser::CstNode;
use crate::interp::compiler::parser::MAX_DEPTH;
use crate::interp::compiler::parser::cst_to_module;
use crate::interp::compiler::parser::parse_cst;
use crate::interp::compiler::source::SourceEncoding;
use crate::interp::compiler::symbol;
use crate::interp::compiler::tokenizer as token;
use crate::interp::error::PyResult;
use crate::interp::error::Signal;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::numbers::Integral;
use crate::interp::numbers::fits_int;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

use validate::Validator;

/// The type name of the tree type.
const TYPE_NAME: &str = "parser.st";

/// The `__future__` compiler flags a tree keeps from parsing.
const FUTURE_MASK: u32 = CompilerFlags::FUTURE_DIVISION
    | CompilerFlags::FUTURE_ABSOLUTE_IMPORT
    | CompilerFlags::FUTURE_WITH_STATEMENT
    | CompilerFlags::FUTURE_PRINT_FUNCTION
    | CompilerFlags::FUTURE_UNICODE_LITERALS;

#[derive(Default)]
struct ParserState {
    error: RefCell<Option<ObjectRef>>,
    tree_type: RefCell<Option<ObjectRef>>,
    /// `pickle_constructor`: the module's `sequence2st`.
    pickle_constructor: RefCell<Option<Value>>,
}

/// The start symbol a tree was created from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeKind {
    Expression,
    Suite,
}

/// A `parser.st` object.
struct SyntaxTree {
    /// The tree below any `encoding_decl` root.
    cst: Cst,
    /// The encoding name of an `encoding_decl` root.
    encoding: Option<Vec<u8>>,
    kind: TreeKind,
    /// The compiler flags the tree was parsed with.
    flags: CompilerFlags,
}

impl_native_data!(SyntaxTree, "parser.st");

/// A node of a `SyntaxTree`, including its `encoding_decl` root.
#[derive(Clone, Copy)]
enum NodeRef {
    EncodingDecl,
    Node(u32),
}

impl SyntaxTree {
    fn root(&self) -> NodeRef {
        if self.encoding.is_some() { NodeRef::EncodingDecl } else { NodeRef::Node(0) }
    }

    /// `TYPE(n)`.
    fn kind(&self, node: NodeRef) -> i32 {
        match node {
            NodeRef::EncodingDecl => i32::from(symbol::ENCODING_DECL),
            NodeRef::Node(id) => node_kind(&self.cst.nodes[id as usize]),
        }
    }

    fn children(&self, node: NodeRef) -> &[u32] {
        const TREE: [u32; 1] = [0];

        match node {
            NodeRef::EncodingDecl => &TREE,
            NodeRef::Node(id) => &self.cst.nodes[id as usize].children,
        }
    }

    /// `STR(n)`: the token of a terminal or the encoding of the
    /// `encoding_decl` root.
    fn string(&self, node: NodeRef) -> Option<&[u8]> {
        match node {
            NodeRef::EncodingDecl => self.encoding.as_deref(),
            NodeRef::Node(id) => {
                let data = &self.cst.nodes[id as usize];
                is_terminal(node_kind(data)).then(|| &self.cst.text[data.start..data.end])
            }
        }
    }

    fn data(&self, node: NodeRef) -> Option<&CstNode> {
        match node {
            NodeRef::EncodingDecl => None,
            NodeRef::Node(id) => Some(&self.cst.nodes[id as usize]),
        }
    }
}

/// Which sequence `totuple` and `tolist` build.
#[derive(Clone, Copy)]
enum SequenceForm {
    Tuple,
    List,
}

/// A tree built from a sequence before validation: its root is node 0.
struct BuiltTree {
    cst: Cst,
    /// The encoding of an `encoding_decl` root, if the root's number was
    /// `encoding_decl`.
    encoding: Option<Vec<u8>>,
}

/// Builds the children of a tree from its sequence form, over a worklist.
struct TreeBuilder {
    nodes: Vec<CstNode>,
    text: Vec<u8>,
    /// The current line number.
    line: i32,
}

/// A nonterminal whose children are being built.
struct Frame {
    sequence: Value,
    node: u32,
    index: usize,
    len: usize,
}

/// One child of a nonterminal, checked as the tree builder checks it.
struct Element {
    /// The type as a C `long`.
    kind: i64,
    /// The terminal's string; `None` for a nonterminal.
    text: Option<Vec<u8>>,
    value: Value,
}

impl TreeBuilder {
    fn new(root_kind: u16) -> Self {
        let root = CstNode { kind: root_kind, start: 0, end: 0, lineno: 0, col_offset: 0, children: Vec::new() };

        Self { nodes: vec![root], text: Vec::new(), line: 0 }
    }

    /// Builds the children of the root from items `1..len` of `sequence`,
    /// with at most `max_depth` nonterminals on any path.
    fn build(&mut self, vm: &Vm, sequence: Value, len: usize, max_depth: usize) -> PyResult<()> {
        let mut frames = vec![Frame { sequence, node: 0, index: 1, len }];

        while let Some(frame) = frames.last_mut() {
            if frame.index >= frame.len {
                frames.pop();
                continue;
            }
            let index = frame.index;
            frame.index += 1;
            let sequence = frame.sequence.clone();
            let parent = frame.node;

            let element = self.element(vm, &sequence, index)?;

            // CPython stores the node type as a 16-bit integer; where that
            // changes whether it is a terminal, CPython builds a node it
            // cannot read back.
            let stored = element.kind as i16;
            let terminal = element.kind < i64::from(token::NT_OFFSET);
            if terminal != is_terminal(i32::from(stored)) {
                return Err(vm.halt_unsupported("parse tree node type that does not fit a C short"));
            }

            let start = self.text.len();
            if let Some(text) = &element.text {
                self.text.extend_from_slice(text);
            }
            let id = self.nodes.len() as u32;
            self.nodes.push(CstNode { kind: stored as u16, start, end: self.text.len(), lineno: self.line, col_offset: 0, children: Vec::new() });
            self.nodes[parent as usize].children.push(id);

            if terminal {
                // The line number counts from after the newline.
                if element.kind == i64::from(token::NEWLINE) {
                    self.line = self.line.wrapping_add(1);
                }
                continue;
            }

            if frames.len() >= max_depth {
                return Err(vm.halt_unsupported("parse tree deeper than the parser stack"));
            }
            let len = sequence_size(vm, &element.value)?;
            frames.push(Frame { sequence: element.value, node: id, index: 1, len });
        }

        Ok(())
    }

    /// Item `index` of `sequence`, checked as a node.
    fn element(&mut self, vm: &Vm, sequence: &Value, index: usize) -> PyResult<Element> {
        let Some(element) = caught(item(vm, sequence, index))? else {
            return Err(parser_error(vm, None));
        };
        if !is_sequence(vm, &element)? {
            return Err(parser_error(vm, None));
        }
        let Some(first) = caught(item(vm, &element, 0))? else {
            return Err(parser_error(vm, None));
        };
        let Some(kind) = int_value(vm, &first) else {
            return Err(parser_error(vm, None));
        };

        if kind >= i64::from(token::NT_OFFSET) {
            return Ok(Element { kind, text: None, value: element });
        }

        let len = caught(vm.len(&element))?.flatten();
        if !matches!(len, Some(2 | 3)) {
            return Err(parser_error(vm, Some(b"terminal nodes must have 2 or 3 entries".to_vec())));
        }

        let string = item(vm, &element, 1)?;
        let Some(text) = vm.as_str_bytes(&string) else {
            let message = format!("second item in terminal node must be a string, found {}", vm.type_name(&string));
            return Err(parser_error(vm, Some(message.into_bytes())));
        };

        if len == Some(3) {
            let Some(line) = caught(item(vm, &element, 2))? else {
                return Err(vm.halt_unsupported("parse tree terminal whose line number cannot be read"));
            };
            let Some(line) = int_value(vm, &line) else {
                // CPython names the type of the string, not of the line.
                let message = format!("third item in terminal node must be an integer, found {}", vm.type_name(&string));
                return Err(parser_error(vm, Some(message.into_bytes())));
            };
            self.line = line as i32;
        }

        Ok(Element { kind, text: Some(c_text(text.as_bytes()).to_vec()), value: element })
    }
}

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    install_functions(
        vm,
        module,
        &[
            function("ast2tuple", st2tuple),
            function("ast2list", st2list),
            function("compileast", compilest),
            function("compilest", compilest),
            function("expr", expr),
            function("isexpr", isexpr),
            function("issuite", issuite),
            function("suite", suite),
            function("sequence2ast", sequence2st),
            function("sequence2st", sequence2st),
            function("st2tuple", st2tuple),
            function("st2list", st2list),
            function("tuple2ast", sequence2st),
            function("tuple2st", sequence2st),
            function("_pickler", pickler),
        ],
    )?;

    let state = vm.native_state::<ParserState>();
    let base = Rc::clone(vm.types().exception(ExceptionKind::Exception));
    let error = new_exception_class(vm, "parser", "ParserError", &base)?;
    set_attribute(vm, module, "ParserError", Value::Object(Rc::clone(&error)))?;
    *state.error.borrow_mut() = Some(error);

    let tree_type = create_tree_type(vm)?;
    set_attribute(vm, module, "ASTType", Value::Object(Rc::clone(&tree_type)))?;
    set_attribute(vm, module, "STType", Value::Object(Rc::clone(&tree_type)))?;
    *state.tree_type.borrow_mut() = Some(Rc::clone(&tree_type));

    set_attribute(vm, module, "__copyright__", Value::unknown("parser.__copyright__ text"))?;

    set_attribute(vm, module, "__version__", Value::str("0.5"))?;

    let module_value = Value::Object(Rc::clone(module));
    let constructor = vm.getattr_str(&module_value, "sequence2st")?;
    let pickler = vm.getattr_str(&module_value, "_pickler")?;
    *state.pickle_constructor.borrow_mut() = Some(constructor.clone());

    let copy_reg = vm.import_module("copy_reg")?;
    let register = vm.getattr_str(&copy_reg, "pickle")?;
    vm.call(&register, CallArgs::new(vec![Value::Object(tree_type), pickler, constructor]))?;

    Ok(())
}

fn create_tree_type(vm: &Vm) -> PyResult<ObjectRef> {
    const METHODS: &[MethodSpec] = &[
        method("compile", st_compile),
        method("isexpr", st_isexpr),
        method("issuite", st_issuite),
        method("tolist", st_tolist),
        method("totuple", st_totuple),
        method("__sizeof__", st_sizeof),
        method("__cmp__", st_cmp),
    ];

    let class = new_final_type(vm, TypeSpec { name: "st", module: "parser", base: None, layout: Layout::Native, instance_dict: false, methods: METHODS })?;
    let Some(data) = class.as_class() else {
        return Err(vm.type_error("parser.st is not a class"));
    };

    // A comparison without a hash makes the type unhashable.
    vm.dict_set_str(&data.dict, "__hash__", Value::None)?;
    vm.register_native_getattr(&class, st_getattr);
    // The module never readies the type; the first attribute lookup
    // on the type does.
    vm.mark_type_unready(&class);

    Ok(class)
}

/// Attribute lookup on a tree: only the
/// methods, `__methods__`, and `__doc__` exist on a tree.
fn st_getattr(vm: &Vm, target: &Value, name: &PyBytes) -> PyResult<Option<Value>> {
    /// The tree methods.
    const TREE_METHODS: [&str; 6] = ["compile", "isexpr", "issuite", "tolist", "totuple", "__sizeof__"];

    // The name arrives as a C string.
    let name = c_text(name.as_bytes());

    match name {
        b"__methods__" => {
            let mut names = TREE_METHODS;
            names.sort_unstable();
            Ok(Some(vm.new_list(names.iter().map(|&name| Value::str(name)).collect())))
        }
        b"__doc__" => Ok(Some(Value::None)),
        _ if TREE_METHODS.iter().any(|method| method.as_bytes() == name) => {
            let class = vm.type_of(target);
            let Some(data) = class.as_class() else {
                return Ok(None);
            };
            let Some(function) = vm.dict_get(&data.dict, &Value::Str(PyBytes::new(name.to_vec())))? else {
                return Ok(None);
            };

            vm.descriptor_get(&function, Some(target.clone()), &class).map(Some)
        }
        _ => Ok(None),
    }
}

/// `parser.expr(source)`.
fn expr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    parse_source(vm, args, "expr", TreeKind::Expression)
}

/// `parser.suite(source)`.
fn suite(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    parse_source(vm, args, "suite", TreeKind::Suite)
}

/// `parser.expr(source)` and `parser.suite(source)`.
fn parse_source(vm: &Vm, args: CallArgs, function: &str, kind: TreeKind) -> PyResult<Value> {
    let slots = parse(vm, args, function, &["source"], 1)?;
    let Some(Some(source)) = slots.first() else {
        return Err(vm.type_error("Required argument 'source' (pos 1) not found"));
    };
    let source = c_string(vm, function, 1, source)?;

    let mode = match kind {
        TreeKind::Expression => Mode::Eval,
        TreeKind::Suite => Mode::Exec,
    };
    let mut codecs = VmSourceCodecs::new(vm);
    let parsed = parse_cst(source.as_bytes(), b"", mode, CompilerFlags::default(), &mut codecs);
    if let Some(halt) = codecs.take_halt() {
        return Err(halt);
    }
    let parsed = parsed.map_err(|error| source_error(vm, error))?;

    let encoding = parsed.encoding.as_ref().map(|encoding| encoding.name().as_bytes().to_vec());
    let flags = CompilerFlags(parsed.flags.0 & FUTURE_MASK);

    new_tree(vm, SyntaxTree { cst: parsed.cst, encoding, kind, flags })
}

/// The `SyntaxError` for a parse without a file name.
fn source_error(vm: &Vm, error: ParseError) -> Signal {
    let ParseError::Syntax(error) = error else {
        return parse_error(vm, error);
    };

    let offset = error.offset.map_or(Value::None, |offset| Value::Int(i64::from(offset)));
    let text = error.text.map_or(Value::None, |text| Value::Str(PyBytes::new(text)));
    let location = Value::tuple(vec![Value::None, Value::Int(i64::from(error.lineno)), offset, text]);

    let class = Rc::clone(vm.types().exception(syntax_error_class(error.kind)));
    match vm.instantiate_exception(&class, vec![Value::str(&error.message), location]) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// `parser.st2tuple(ast[, line_info[, col_info]])`.
fn st2tuple(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = function_arguments(vm, args, "st2tuple", &["line_info", "col_info"])?;
    to_sequence(vm, &tree, SequenceForm::Tuple, &options)
}

/// `parser.st2list(ast[, line_info[, col_info]])`.
fn st2list(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = function_arguments(vm, args, "st2list", &["line_info", "col_info"])?;
    to_sequence(vm, &tree, SequenceForm::List, &options)
}

fn st_totuple(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = method_arguments(vm, args, "totuple", &["line_info", "col_info"])?;
    to_sequence(vm, &tree, SequenceForm::Tuple, &options)
}

fn st_tolist(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = method_arguments(vm, args, "tolist", &["line_info", "col_info"])?;
    to_sequence(vm, &tree, SequenceForm::List, &options)
}

/// `parser.compilest(ast[, filename])`.
fn compilest(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = function_arguments(vm, args, "compilest", &["filename"])?;
    compile_tree(vm, &tree, options[0].as_ref(), "compilest", 2)
}

fn st_compile(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, options) = method_arguments(vm, args, "compile", &["filename"])?;
    compile_tree(vm, &tree, options[0].as_ref(), "compile", 1)
}

/// `parser.isexpr(ast)`.
fn isexpr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, _) = function_arguments(vm, args, "isexpr", &[])?;
    Ok(Value::Bool(tree_data(vm, &tree)?.kind == TreeKind::Expression))
}

/// `parser.issuite(ast)`.
fn issuite(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, _) = function_arguments(vm, args, "issuite", &[])?;
    Ok(Value::Bool(tree_data(vm, &tree)?.kind == TreeKind::Suite))
}

fn st_isexpr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, _) = method_arguments(vm, args, "isexpr", &[])?;
    Ok(Value::Bool(tree_data(vm, &tree)?.kind == TreeKind::Expression))
}

fn st_issuite(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (tree, _) = method_arguments(vm, args, "issuite", &[])?;
    Ok(Value::Bool(tree_data(vm, &tree)?.kind == TreeKind::Suite))
}

/// `__sizeof__`: the size of the tree object plus the size of each
/// Windows x64 node (40 bytes).
fn st_sizeof(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    const OBJECT_SIZE: usize = 32;
    const NODE_SIZE: usize = 40;

    let tree = this::<SyntaxTree>(vm, &args, TYPE_NAME, "__sizeof__")?;
    method_no_arguments(vm, &args, "__sizeof__")?;

    let mut size = OBJECT_SIZE + NODE_SIZE;
    let mut pending = vec![tree.root()];
    while let Some(node) = pending.pop() {
        let children = tree.children(node);
        if !children.is_empty() {
            size += child_capacity(children.len()) * NODE_SIZE;
        }
        if let Some(text) = tree.string(node) {
            size += text.len() + 1;
        }
        pending.extend(children.iter().map(|&child| NodeRef::Node(child)));
    }

    Ok(Value::Long(Rc::new(BigInt::from(size))))
}

/// `__cmp__`. Comparison operators
/// call it only for two trees, as three-way comparison uses a native
/// comparison only when both operands share it.
fn st_cmp(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let (left, rest) = receiver_tree(vm, args, "__cmp__")?;
    let right = wrapper_operand(vm, rest)?;
    halt_on_unknown(&right, "parser.st.__cmp__ operand")?;
    let (Some(left), Some(right)) = (native_data::<SyntaxTree>(&left), native_data::<SyntaxTree>(&right)) else {
        return Err(vm.type_error(&format!("{TYPE_NAME}.__cmp__(x,y) requires y to be a '{TYPE_NAME}', not a '{}'", vm.type_name(&right))));
    };

    let ordering = compare_trees(left, right);

    Ok(Value::Int(match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }))
}

/// `parser.sequence2st(sequence)`.
fn sequence2st(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let slots = parse(vm, args, "sequence2st", &["sequence"], 1)?;
    let Some(Some(sequence)) = slots.first() else {
        return Err(vm.type_error("Required argument 'sequence' (pos 1) not found"));
    };
    halt_on_unknown(sequence, "parser.sequence2st argument")?;
    if !is_sequence(vm, sequence)? {
        return Err(vm.raise(ExceptionKind::ValueError, "sequence2st() requires a single sequence argument"));
    }

    let built = build_tree(vm, sequence)?;

    let start = node_kind(&built.cst.nodes[0]);
    let mut validator = Validator::new(&built.cst);
    let (outcome, kind) = match start {
        _ if start == i32::from(symbol::EVAL_INPUT) => (validator.expr_tree(0), TreeKind::Expression),
        _ if start == i32::from(symbol::FILE_INPUT) => (validator.file_input_tree(0), TreeKind::Suite),
        _ if start == i32::from(symbol::ENCODING_DECL) => (validator.encoding_decl(0), TreeKind::Suite),
        _ => return Err(parser_error(vm, Some(b"parse tree does not use a valid start symbol".to_vec()))),
    };
    let Ok(valid) = outcome else {
        return Err(vm.halt_unsupported("parse tree validation that reads past a node"));
    };
    let pending = validator.into_error();
    if !valid {
        return Err(parser_error(vm, Some(pending.unwrap_or_else(|| b"unspecified ST error occurred".to_vec()))));
    }
    if pending.is_some() {
        return Err(vm.halt_unsupported("parse tree validation that succeeds with a ParserError pending"));
    }

    let (cst, encoding) = if start == i32::from(symbol::ENCODING_DECL) {
        let Some(encoding) = built.encoding else {
            return Err(vm.halt_unsupported("encoding_decl parse tree root without an encoding"));
        };
        (without_root(built.cst), Some(encoding))
    } else {
        (built.cst, None)
    };

    new_tree(vm, SyntaxTree { cst, encoding, kind, flags: CompilerFlags::default() })
}

/// `parser._pickler(ast)`: the `copy_reg` reduction of a tree.
fn pickler(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let args = positional(vm, args, "_pickler", 1, 1)?;
    let tree = &args[0];
    check_tree_argument(vm, "_pickler", tree)?;

    let line_info = [Some(Value::Int(1))];
    let sequence = to_sequence(vm, tree, SequenceForm::Tuple, &line_info)?;
    let Some(constructor) = vm.native_state::<ParserState>().pickle_constructor.borrow().clone() else {
        return Err(vm.type_error("parser module is not initialized"));
    };

    Ok(Value::tuple(vec![constructor, Value::tuple(vec![sequence])]))
}

/// The tree and other arguments of a module function taking the tree as
/// first argument.
fn function_arguments(vm: &Vm, args: CallArgs, function: &str, names: &[&str]) -> PyResult<(Value, Vec<Option<Value>>)> {
    let mut all = vec!["ast"];
    all.extend_from_slice(names);

    let mut slots = parse_with(vm, args, function, &all, 1, |vm, index, value| {
        if index == 0 {
            check_tree_argument(vm, function, &value)?;
        }
        Ok(value)
    })?;

    let options = slots.split_off(1);
    let Some(Some(tree)) = slots.pop() else {
        return Err(vm.type_error("Required argument 'ast' (pos 1) not found"));
    };

    Ok((tree, options))
}

/// The receiver and other arguments of a tree method.
fn method_arguments(vm: &Vm, args: CallArgs, method: &str, names: &[&str]) -> PyResult<(Value, Vec<Option<Value>>)> {
    let (tree, rest) = receiver_tree(vm, args, method)?;
    let options = parse(vm, rest, method, names, 0)?;

    Ok((tree, options))
}

fn receiver_tree(vm: &Vm, args: CallArgs, method: &str) -> PyResult<(Value, CallArgs)> {
    this::<SyntaxTree>(vm, &args, TYPE_NAME, method)?;

    receiver(vm, args, method)
}

/// Checks that `value` is a `parser.st` object.
fn check_tree_argument(vm: &Vm, function: &str, value: &Value) -> PyResult<()> {
    halt_on_unknown(value, "parse tree argument")?;
    if native_data::<SyntaxTree>(value).is_some() {
        return Ok(());
    }

    Err(vm.type_error(&format!("{function}() argument 1 must be {TYPE_NAME}, not {}", vm.type_name(value))))
}

fn tree_data<'a>(vm: &Vm, value: &'a Value) -> PyResult<&'a SyntaxTree> {
    native_data::<SyntaxTree>(value).ok_or_else(|| vm.type_error(&format!("expected a {TYPE_NAME} object")))
}

fn new_tree(vm: &Vm, tree: SyntaxTree) -> PyResult<Value> {
    let Some(class) = vm.native_state::<ParserState>().tree_type.borrow().clone() else {
        return Err(vm.type_error("parser module is not initialized"));
    };

    Ok(new_native_object(vm, &class, tree))
}

/// A `parser.ParserError` with `message`, or with no
/// value when `message` is `None`.
fn parser_error(vm: &Vm, message: Option<Vec<u8>>) -> Signal {
    let Some(class) = vm.native_state::<ParserState>().error.borrow().clone() else {
        return vm.type_error("parser module is not initialized");
    };

    let args = message.map(|message| vec![Value::Str(PyBytes::new(message))]).unwrap_or_default();
    match vm.instantiate_exception(&class, args) {
        Ok(exception) => Signal::Raise(exception),
        Err(signal) => signal,
    }
}

/// The tuple or list form of a tree. `options` holds the
/// `line_info` and `col_info` arguments.
fn to_sequence(vm: &Vm, value: &Value, form: SequenceForm, options: &[Option<Value>]) -> PyResult<Value> {
    let tree = tree_data(vm, value)?;
    let mut flags = [false; 2];
    for (flag, option) in flags.iter_mut().zip(options) {
        if let Some(option) = option {
            *flag = vm.truthy(option, "parse tree option")?;
        }
    }
    let [line_info, col_info] = flags;

    // 2.7.12 stores the column at index 3 of a three-item sequence, which
    // leaves an item unset.
    if col_info && !line_info {
        return Err(vm.halt_unsupported("parse tree sequence with col_info but not line_info"));
    }

    let make = |items: Vec<Value>| match form {
        SequenceForm::Tuple => Value::tuple(items),
        SequenceForm::List => vm.new_list(items),
    };

    let mut done: Vec<Value> = Vec::new();
    let mut pending = vec![(tree.root(), 0)];
    while let Some((node, next)) = pending.last_mut() {
        let node = *node;
        let kind = Value::Int(i64::from(tree.kind(node)));

        if let Some(data) = tree.data(node)
            && is_terminal(node_kind(data))
        {
            pending.pop();
            let mut items = vec![kind, Value::Str(PyBytes::new(tree.cst.text[data.start..data.end].to_vec()))];
            if line_info {
                items.push(Value::Int(i64::from(data.lineno)));
            }
            if col_info {
                items.push(Value::Int(i64::from(data.col_offset)));
            }
            done.push(make(items));
            continue;
        }

        let children = tree.children(node);
        if let Some(&child) = children.get(*next) {
            *next += 1;
            pending.push((NodeRef::Node(child), 0));
            continue;
        }

        pending.pop();
        let mut items = Vec::with_capacity(children.len() + 2);
        items.push(kind);
        items.extend(done.split_off(done.len() - children.len()));
        if let (NodeRef::EncodingDecl, Some(encoding)) = (node, &tree.encoding) {
            items.push(Value::Str(PyBytes::new(encoding.clone())));
        }
        done.push(make(items));
    }

    done.pop().ok_or_else(|| vm.type_error("empty parse tree"))
}

/// `parser.compilest(tree, filename)`.
fn compile_tree(vm: &Vm, value: &Value, filename: Option<&Value>, function: &str, position: usize) -> PyResult<Value> {
    let filename = match filename {
        Some(filename) => c_string(vm, function, position, filename)?.as_bytes().to_vec(),
        None => b"<syntax-tree>".to_vec(),
    };
    let tree = tree_data(vm, value)?;

    let encoding = match &tree.encoding {
        None => None,
        Some(name) => match name.as_slice() {
            b"utf-8" => Some(SourceEncoding::Utf8),
            b"iso-8859-1" => Some(SourceEncoding::Latin1),
            other => match String::from_utf8(other.to_vec()) {
                Ok(name) => Some(SourceEncoding::Other(name)),
                Err(_) => return Err(vm.halt_unsupported("parse tree encoding name that is not UTF-8")),
            },
        },
    };

    let mut codecs = VmSourceCodecs::new(vm);
    let module = cst_to_module(&tree.cst, encoding.as_ref(), &filename, tree.flags, &mut codecs);
    if let Some(halt) = codecs.take_halt() {
        return Err(halt);
    }
    let module = module.map_err(|error| parse_error(vm, error))?;

    compile_module(vm, &module, &filename, tree.flags)
}

/// Compares two trees: node types, then terminal strings, then child counts, depth first.
fn compare_trees(left: &SyntaxTree, right: &SyntaxTree) -> Ordering {
    let mut pending = vec![(left.root(), right.root())];

    while let Some((a, b)) = pending.pop() {
        let kinds = left.kind(a).cmp(&right.kind(b));
        if kinds != Ordering::Equal {
            return kinds;
        }

        if is_terminal(left.kind(a)) {
            let texts = left.string(a).cmp(&right.string(b));
            if texts != Ordering::Equal {
                return texts;
            }
            continue;
        }

        let (a_children, b_children) = (left.children(a), right.children(b));
        let counts = a_children.len().cmp(&b_children.len());
        if counts != Ordering::Equal {
            return counts;
        }
        pending.extend(a_children.iter().zip(b_children).rev().map(|(&a, &b)| (NodeRef::Node(a), NodeRef::Node(b))));
    }

    Ordering::Equal
}

/// The tree a sequence form describes.
fn build_tree(vm: &Vm, sequence: &Value) -> PyResult<BuiltTree> {
    let number = match caught(item(vm, sequence, 0))? {
        Some(first) => int_as_long(vm, &first)?,
        None => -1,
    };
    if number < i64::from(token::NT_OFFSET) {
        return Err(parser_error(vm, None));
    }

    let encoding_decl = number == i64::from(symbol::ENCODING_DECL);
    let encoding = if encoding_decl { Some(caught(item(vm, sequence, 2))?) } else { None };
    let len = sequence_size(vm, sequence)?;
    let len = if encoding_decl { len.min(2) } else { len };

    // The parser's trees are at most `MAX_DEPTH` deep below an `encoding_decl`.
    let max_depth = if encoding_decl { MAX_DEPTH + 1 } else { MAX_DEPTH };
    let mut builder = TreeBuilder::new(number as i16 as u16);
    builder.build(vm, sequence.clone(), len, max_depth)?;

    let encoding = match encoding {
        None => None,
        Some(value) => match value.as_ref().and_then(|value| vm.as_str_bytes(value)) {
            Some(name) => Some(c_text(name.as_bytes()).to_vec()),
            None => return Err(vm.halt_unsupported("encoding_decl parse tree whose encoding is not a string")),
        },
    };

    Ok(BuiltTree { cst: Cst::new(builder.nodes, builder.text), encoding })
}

/// The tree below the root of `cst`, whose only child is node 1.
fn without_root(cst: Cst) -> Cst {
    let mut nodes = cst.nodes;
    nodes.remove(0);
    for node in &mut nodes {
        for child in &mut node.children {
            *child -= 1;
        }
    }

    Cst::new(nodes, cst.text)
}

/// `sequence[index]`.
fn item(vm: &Vm, sequence: &Value, index: usize) -> PyResult<Value> {
    let item = vm.getitem(sequence, &Value::Int(index as i64))?;
    halt_on_unknown(&item, "parse tree item")?;

    Ok(item)
}

/// The length of a sequence the tree is built from. CPython 2.7.12
/// does not check it for failure, which leaves an exception pending.
fn sequence_size(vm: &Vm, sequence: &Value) -> PyResult<usize> {
    match caught(vm.len(sequence))? {
        Some(Some(len)) => Ok(len),
        Some(None) => Err(vm.halt_unsupported("parse tree sequence of unknown length")),
        None => Err(vm.halt_unsupported("parse tree sequence whose length raises")),
    }
}

/// A Python exception as `None`; halts pass through.
fn caught<T>(result: PyResult<T>) -> PyResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Signal::Raise(_)) => Ok(None),
        Err(halt) => Err(halt),
    }
}

/// The value of an `int`; `None` for anything else.
fn int_value(vm: &Vm, value: &Value) -> Option<i64> {
    match vm.as_integral(value) {
        Some(Integral::Int(number)) => Some(number),
        _ => None,
    }
}

/// An integer conversion that returns `-1` for any failure: the caller cannot tell
/// failure from a value of `-1`, and both are a terminal type.
fn int_as_long(vm: &Vm, value: &Value) -> PyResult<i64> {
    halt_on_unknown(value, "parse tree node type")?;

    let integral = if let Some(integral) = vm.as_integral(value) {
        integral
    } else if let Some(number) = vm.as_float(value) {
        let number = number.trunc().to_i64().filter(|&number| fits_int(vm.config.long_width, number));
        return Ok(number.unwrap_or(-1));
    } else {
        let Some(hook) = vm.user_override(value, "__int__")? else {
            return Ok(-1);
        };
        let Some(result) = caught(vm.call0(&hook))? else {
            return Ok(-1);
        };
        halt_on_unknown(&result, "__int__ result")?;
        let Some(integral) = vm.as_integral(&result) else {
            return Ok(-1);
        };
        integral
    };

    let number = match integral {
        Integral::Int(number) => Some(number),
        Integral::Long(number) => number.to_i64(),
    };

    Ok(number.filter(|&number| fits_int(vm.config.long_width, number)).unwrap_or(-1))
}

/// The bytes CPython keeps of a string it copies into a node: up to the
/// first NUL, as every reader treats it as a C string.
fn c_text(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());

    &bytes[..end]
}

/// The children a node has room for: exact up to one, rounded up to a
/// multiple of four up to 128, else the next power of two.
fn child_capacity(count: usize) -> usize {
    match count {
        0 | 1 => count,
        2..=128 => (count + 3) & !3,
        _ => count.next_power_of_two().max(256),
    }
}

/// The node type as the 16-bit integer it is stored in.
fn node_kind(node: &CstNode) -> i32 {
    i32::from(node.kind as i16)
}

/// Whether `kind` is a token type rather than a grammar symbol.
fn is_terminal(kind: i32) -> bool {
    kind < i32::from(token::NT_OFFSET)
}
