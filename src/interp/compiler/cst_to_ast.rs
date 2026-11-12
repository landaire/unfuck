//! Builds the AST from a concrete syntax tree.
//!
//! Positions, the checks on assignment targets and calls, and the order in
//! which subtrees are converted (which decides the error reported when a
//! statement has several) follow CPython 2.7 as observed from its
//! `compile`. The `parser` module can also hand over trees the parser never
//! builds, as long as its validator accepts them. Those convert the way
//! CPython converts them where that is known; elsewhere the conversion stops
//! with `BuildError::Unsupported`.

use crate::interp::compiler::ast;
use crate::interp::compiler::ast::Expr;
use crate::interp::compiler::ast::ExprContext;
use crate::interp::compiler::ast::ExprKind;
use crate::interp::compiler::ast::Identifier;
use crate::interp::compiler::ast::Location;
use crate::interp::compiler::ast::Stmt;
use crate::interp::compiler::ast::StmtKind;
use crate::interp::compiler::literals;
use crate::interp::compiler::literals::LiteralError;
use crate::interp::compiler::literals::StringContext;
use crate::interp::compiler::parser::Cst;
use crate::interp::compiler::parser::NodeRef;
use crate::interp::compiler::source::CodecError;
use crate::interp::compiler::source::SourceCodecs;
use crate::interp::compiler::source::SourceEncoding;
use crate::interp::compiler::symbol;
use crate::interp::compiler::tokenizer;
use crate::interp::compiler::tokenizer::Tokenizer;

/// Stack the recursive conversions may use before more is allocated.
const RED_ZONE: usize = 64 * 1024;
const STACK_GROWTH: usize = 2 * 1024 * 1024;

/// Why a tree could not be converted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A `SyntaxError` located only by line.
    Syntax { message: String, lineno: i32 },
    /// `ValueError` from a string literal.
    Value { message: String },
    /// An exception a source codec raised.
    Codec(CodecError),
    /// `SystemError` for a tree shape the parser does not produce.
    System { message: String },
    /// A failure CPython returns without setting an exception.
    NoException,
    /// A tree whose conversion CPython leaves undefined.
    Unsupported { feature: String },
}

type Built<T> = Result<T, BuildError>;

/// Builds the module of a tree whose source declared `encoding`.
/// `future_unicode` makes plain string literals unicode.
pub fn build(
    cst: &Cst,
    encoding: Option<&SourceEncoding>,
    future_unicode: bool,
    codecs: &mut dyn SourceCodecs,
) -> Built<ast::Mod> {
    let mut builder = Builder {
        encoding,
        future_unicode,
        tokenized: cst.is_tokenized(),
        codecs,
    };
    let root = cst.root();

    match root.kind() {
        symbol::FILE_INPUT => {
            // The last child is the end marker.
            let mut body = Vec::new();
            for child in root.children().take(root.len().saturating_sub(1)) {
                if child.kind() != tokenizer::NEWLINE {
                    builder.statements_into(child, &mut body)?;
                }
            }
            Ok(ast::Mod::Module { body })
        }
        symbol::EVAL_INPUT => {
            let body = builder.testlist(child(root, 0)?)?;
            Ok(ast::Mod::Expression {
                body: Box::new(body),
            })
        }
        symbol::SINGLE_INPUT => {
            let first = child(root, 0)?;
            if first.kind() == tokenizer::NEWLINE {
                let pass = Stmt {
                    kind: StmtKind::Pass,
                    location: root.location(),
                };
                return Ok(ast::Mod::Interactive { body: vec![pass] });
            }
            let mut body = Vec::new();
            builder.statements_into(first, &mut body)?;
            Ok(ast::Mod::Interactive { body })
        }
        _ => Err(unsupported("a tree whose root is not a start symbol")),
    }
}

fn unsupported(feature: &str) -> BuildError {
    BuildError::Unsupported {
        feature: feature.to_owned(),
    }
}

fn syntax_error(node: NodeRef<'_>, message: impl Into<String>) -> BuildError {
    BuildError::Syntax {
        message: message.into(),
        lineno: node.lineno(),
    }
}

/// A node's type as CPython prints it: the parser module stores types as
/// signed 16-bit values.
fn type_number(node: NodeRef<'_>) -> i32 {
    i32::from(node.kind() as i16)
}

fn child(node: NodeRef<'_>, index: usize) -> Built<NodeRef<'_>> {
    node.child(index)
        .ok_or_else(|| unsupported("a tree node with fewer children than its type needs"))
}

fn last_child(node: NodeRef<'_>) -> Built<NodeRef<'_>> {
    child(node, node.len().wrapping_sub(1))
}

fn token_text(node: NodeRef<'_>) -> Built<&[u8]> {
    node.text()
        .ok_or_else(|| unsupported("a tree with a nonterminal where a token belongs"))
}

fn identifier(node: NodeRef<'_>) -> Built<Identifier> {
    Ok(Identifier(token_text(node)?.to_vec()))
}

/// The children at even positions: the items of a separated list.
fn items(node: NodeRef<'_>) -> impl Iterator<Item = NodeRef<'_>> {
    node.children().step_by(2)
}

fn expr(kind: ExprKind, location: Location) -> Expr {
    Expr { kind, location }
}

fn stmt(kind: StmtKind, location: Location) -> Stmt {
    Stmt { kind, location }
}

/// Rejects binding a name that cannot be rebound.
fn check_binding(node: NodeRef<'_>, name: &[u8]) -> Built<()> {
    match name {
        b"None" => Err(syntax_error(node, "cannot assign to None")),
        b"__debug__" => Err(syntax_error(node, "cannot assign to __debug__")),
        _ => Ok(()),
    }
}

/// Marks `target` as stored or deleted, rejecting expressions that cannot
/// be. Errors name `node`'s line.
fn set_context(target: &mut Expr, context: ExprContext, node: NodeRef<'_>) -> Built<()> {
    let store = context == ExprContext::Store;
    let description = match &mut target.kind {
        ExprKind::Name { id, ctx } => {
            if store {
                check_binding(node, &id.0)?;
            }
            *ctx = context;
            return Ok(());
        }
        ExprKind::Attribute { attr, ctx, .. } => {
            if store {
                check_binding(node, &attr.0)?;
            }
            *ctx = context;
            return Ok(());
        }
        ExprKind::Subscript { ctx, .. } => {
            *ctx = context;
            return Ok(());
        }
        ExprKind::List { elts, ctx } => {
            *ctx = context;
            for element in elts {
                set_context(element, context, node)?;
            }
            return Ok(());
        }
        ExprKind::Tuple { elts, ctx } if !elts.is_empty() => {
            *ctx = context;
            for element in elts {
                set_context(element, context, node)?;
            }
            return Ok(());
        }
        ExprKind::Tuple { .. } => "()",
        ExprKind::Lambda { .. } => "lambda",
        ExprKind::Call { .. } => "function call",
        ExprKind::BoolOp { .. } | ExprKind::BinOp { .. } | ExprKind::UnaryOp { .. } => "operator",
        ExprKind::GeneratorExp { .. } => "generator expression",
        ExprKind::Yield { .. } => "yield expression",
        ExprKind::ListComp { .. } => "list comprehension",
        ExprKind::SetComp { .. } => "set comprehension",
        ExprKind::DictComp { .. } => "dict comprehension",
        ExprKind::Dict { .. }
        | ExprKind::Set { .. }
        | ExprKind::Num { .. }
        | ExprKind::Str { .. } => "literal",
        ExprKind::Compare { .. } => "comparison",
        ExprKind::Repr { .. } => "repr",
        ExprKind::IfExp { .. } => "conditional expression",
    };

    let verb = if store { "assign to" } else { "delete" };
    Err(syntax_error(node, format!("can't {verb} {description}")))
}

/// The operator of a binary operator token, if it is one.
fn binary_operator(node: NodeRef<'_>) -> Option<ast::Operator> {
    let operator = match node.kind() {
        tokenizer::VBAR => ast::Operator::BitOr,
        tokenizer::CIRCUMFLEX => ast::Operator::BitXor,
        tokenizer::AMPER => ast::Operator::BitAnd,
        tokenizer::LEFTSHIFT => ast::Operator::LShift,
        tokenizer::RIGHTSHIFT => ast::Operator::RShift,
        tokenizer::PLUS => ast::Operator::Add,
        tokenizer::MINUS => ast::Operator::Sub,
        tokenizer::STAR => ast::Operator::Mult,
        tokenizer::SLASH => ast::Operator::Div,
        tokenizer::DOUBLESLASH => ast::Operator::FloorDiv,
        tokenizer::PERCENT => ast::Operator::Mod,
        _ => return None,
    };

    Some(operator)
}

/// The operator of an `augassign` node, told apart by its first characters.
fn augmented_operator(node: NodeRef<'_>) -> Built<ast::Operator> {
    let text = token_text(child(node, 0)?)?;
    let doubled = text.get(1) == text.first();

    let operator = match text.first() {
        Some(b'+') => ast::Operator::Add,
        Some(b'-') => ast::Operator::Sub,
        Some(b'/') if doubled => ast::Operator::FloorDiv,
        Some(b'/') => ast::Operator::Div,
        Some(b'%') => ast::Operator::Mod,
        Some(b'<') => ast::Operator::LShift,
        Some(b'>') => ast::Operator::RShift,
        Some(b'&') => ast::Operator::BitAnd,
        Some(b'^') => ast::Operator::BitXor,
        Some(b'|') => ast::Operator::BitOr,
        Some(b'*') if doubled => ast::Operator::Pow,
        Some(b'*') => ast::Operator::Mult,
        _ => {
            return Err(unsupported(
                "an augmented assignment with an unknown operator",
            ));
        }
    };

    Ok(operator)
}

fn comparison_operator(node: NodeRef<'_>) -> Built<ast::CmpOp> {
    let first = child(node, 0)?;
    if node.len() == 2 {
        let second = child(node, 1)?;
        return match (token_text(first)?, token_text(second)?) {
            (b"not", b"in") => Ok(ast::CmpOp::NotIn),
            (b"is", b"not") => Ok(ast::CmpOp::IsNot),
            _ => Err(unsupported("a comparison with an unknown operator")),
        };
    }

    let operator = match first.kind() {
        tokenizer::LESS => ast::CmpOp::Lt,
        tokenizer::GREATER => ast::CmpOp::Gt,
        tokenizer::EQEQUAL => ast::CmpOp::Eq,
        tokenizer::LESSEQUAL => ast::CmpOp::LtE,
        tokenizer::GREATEREQUAL => ast::CmpOp::GtE,
        tokenizer::NOTEQUAL => ast::CmpOp::NotEq,
        tokenizer::NAME => match token_text(first)? {
            b"in" => ast::CmpOp::In,
            b"is" => ast::CmpOp::Is,
            _ => return Err(unsupported("a comparison with an unknown operator")),
        },
        _ => return Err(unsupported("a comparison with an unknown operator")),
    };

    Ok(operator)
}

/// How many statements a statement-level node holds.
fn statement_count(node: NodeRef<'_>) -> Built<usize> {
    match node.kind() {
        symbol::STMT => statement_count(child(node, 0)?),
        symbol::SIMPLE_STMT => Ok(node.len() / 2),
        symbol::COMPOUND_STMT => Ok(1),
        _ => Err(unsupported(
            "a statement list holding a node that is not a statement",
        )),
    }
}

/// One argument of a call, by form.
enum CallArgument<'a> {
    /// A positional argument: its `argument` node.
    Plain(NodeRef<'a>),
    /// `name=value`: its `argument` node.
    Keyword(NodeRef<'a>),
    /// An unparenthesized generator expression: its `argument` node.
    Generator(NodeRef<'a>),
    /// The expression after `*`.
    Star(NodeRef<'a>),
    /// The expression after `**`.
    DoubleStar(NodeRef<'a>),
}

/// The arguments of an `arglist` in order. Separators, and any other node
/// a built tree may hold there, are skipped.
fn call_arguments(node: NodeRef<'_>) -> Built<Vec<CallArgument<'_>>> {
    let mut arguments = Vec::new();
    let mut parts = node.children();

    while let Some(part) = parts.next() {
        let argument = match part.kind() {
            symbol::ARGUMENT if part.len() == 1 => CallArgument::Plain(part),
            symbol::ARGUMENT if child(part, 1)?.kind() == symbol::COMP_FOR => {
                CallArgument::Generator(part)
            }
            symbol::ARGUMENT => CallArgument::Keyword(part),
            tokenizer::STAR | tokenizer::DOUBLESTAR => {
                let Some(value) = parts.next() else {
                    return Err(unsupported("a star in a call without an expression"));
                };
                if part.kind() == tokenizer::STAR {
                    CallArgument::Star(value)
                } else {
                    CallArgument::DoubleStar(value)
                }
            }
            _ => continue,
        };
        arguments.push(argument);
    }

    Ok(arguments)
}

/// The `for` clauses of a comprehension, each with its `if` conditions.
struct Clause<'a> {
    for_clause: NodeRef<'a>,
    conditions: Vec<NodeRef<'a>>,
}

/// The node types of one comprehension form.
struct ComprehensionKinds {
    for_clause: u16,
    if_clause: u16,
    /// The `SystemError` for a chain holding something else.
    malformed: &'static str,
}

const LIST_COMPREHENSION: ComprehensionKinds = ComprehensionKinds {
    for_clause: symbol::LIST_FOR,
    if_clause: symbol::LIST_IF,
    malformed: "logic error in count_list_fors",
};

const COMPREHENSION: ComprehensionKinds = ComprehensionKinds {
    for_clause: symbol::COMP_FOR,
    if_clause: symbol::COMP_IF,
    malformed: "logic error in count_comp_fors",
};

/// Splits the clause chain starting at `first` into `for` clauses. A
/// clause continues into its fifth child, whose first child is the next
/// `for` or an `if`; an `if` continues into its third child the same way.
fn comprehension_clauses<'a>(
    first: NodeRef<'a>,
    kinds: &ComprehensionKinds,
) -> Built<Vec<Clause<'a>>> {
    let mut clauses = Vec::new();
    let mut for_clause = first;

    loop {
        let mut clause = Clause {
            for_clause,
            conditions: Vec::new(),
        };
        if for_clause.len() != 5 {
            clauses.push(clause);
            return Ok(clauses);
        }

        let mut link = child(for_clause, 4)?;
        let next = loop {
            let inner = child(link, 0)?;
            if inner.kind() == kinds.for_clause {
                break Some(inner);
            }
            if inner.kind() != kinds.if_clause {
                return Err(BuildError::System {
                    message: kinds.malformed.to_owned(),
                });
            }
            clause.conditions.push(inner);
            if inner.len() != 3 {
                break None;
            }
            link = child(inner, 2)?;
        };
        clauses.push(clause);

        let Some(next) = next else {
            return Ok(clauses);
        };
        for_clause = next;
    }
}

struct Builder<'b> {
    encoding: Option<&'b SourceEncoding>,
    future_unicode: bool,
    /// Whether literal tokens came from the tokenizer and need no check.
    tokenized: bool,
    codecs: &'b mut dyn SourceCodecs,
}

impl Builder<'_> {
    /// Appends the statements of a statement-level node: one compound
    /// statement, or every small statement of a line.
    fn statements_into(&mut self, node: NodeRef<'_>, out: &mut Vec<Stmt>) -> Built<()> {
        let count = statement_count(node)?;
        if count == 1 {
            out.push(self.statement(node)?);
            return Ok(());
        }

        let line = if node.kind() == symbol::STMT {
            child(node, 0)?
        } else {
            node
        };
        for small in items(line).take(count) {
            out.push(self.statement(small)?);
        }

        Ok(())
    }

    fn suite(&mut self, node: NodeRef<'_>) -> Built<Vec<Stmt>> {
        let mut body = Vec::new();

        let first = child(node, 0)?;
        if first.kind() == symbol::SIMPLE_STMT {
            self.statements_into(first, &mut body)?;
            return Ok(body);
        }

        // NEWLINE INDENT statements DEDENT
        for statement in node.children().take(node.len().saturating_sub(1)).skip(2) {
            self.statements_into(statement, &mut body)?;
        }

        Ok(body)
    }

    fn statement(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.statement_inner(node))
    }

    fn statement_inner(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let mut node = node;
        if node.kind() == symbol::STMT {
            node = child(node, 0)?;
        }
        if node.kind() == symbol::SIMPLE_STMT {
            node = child(node, 0)?;
        }

        if node.kind() == symbol::SMALL_STMT {
            let small = child(node, 0)?;
            return match small.kind() {
                symbol::EXPR_STMT => self.expr_stmt(small),
                symbol::PRINT_STMT => self.print_stmt(small),
                symbol::DEL_STMT => {
                    let targets = self.expr_list(child(small, 1)?, ExprContext::Del)?;
                    Ok(stmt(StmtKind::Delete { targets }, small.location()))
                }
                symbol::PASS_STMT => Ok(stmt(StmtKind::Pass, small.location())),
                symbol::FLOW_STMT => self.flow_stmt(small),
                symbol::IMPORT_STMT => self.import_stmt(small),
                symbol::GLOBAL_STMT => {
                    let names = small
                        .children()
                        .skip(1)
                        .step_by(2)
                        .map(identifier)
                        .collect::<Built<Vec<_>>>()?;
                    Ok(stmt(StmtKind::Global { names }, small.location()))
                }
                symbol::EXEC_STMT => self.exec_stmt(small),
                symbol::ASSERT_STMT => self.assert_stmt(small),
                _ => Err(BuildError::System {
                    message: format!(
                        "unhandled small_stmt: TYPE={} NCH={}\n",
                        type_number(small),
                        small.len()
                    ),
                }),
            };
        }

        let compound = child(node, 0)?;
        match compound.kind() {
            symbol::IF_STMT => self.if_stmt(compound),
            symbol::WHILE_STMT => self.while_stmt(compound),
            symbol::FOR_STMT => self.for_stmt(compound),
            symbol::TRY_STMT => self.try_stmt(compound),
            symbol::WITH_STMT => self.with_stmt(compound),
            symbol::FUNCDEF => self.funcdef(compound, Vec::new(), compound.location()),
            symbol::CLASSDEF => self.classdef(compound, Vec::new(), compound.location()),
            symbol::DECORATED => self.decorated(compound),
            _ => Err(BuildError::System {
                message: format!(
                    "unhandled small_stmt: TYPE={} NCH={}\n",
                    type_number(node),
                    node.len()
                ),
            }),
        }
    }

    /// The right side of an assignment: a test list or a `yield`.
    fn assigned_value(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        if node.kind() == symbol::TESTLIST {
            return self.testlist(node);
        }

        self.expr(node)
    }

    fn expr_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let location = node.location();
        if node.len() == 1 {
            let value = self.testlist(child(node, 0)?)?;
            return Ok(stmt(StmtKind::Expr { value }, location));
        }

        let operator_node = child(node, 1)?;
        if operator_node.kind() == symbol::AUGASSIGN {
            let target_node = child(node, 0)?;
            let mut target = self.testlist(target_node)?;
            set_context(&mut target, ExprContext::Store, target_node)?;
            if !matches!(
                target.kind,
                ExprKind::Name { .. } | ExprKind::Attribute { .. } | ExprKind::Subscript { .. }
            ) {
                return Err(syntax_error(
                    target_node,
                    "illegal expression for augmented assignment",
                ));
            }

            let value = self.assigned_value(child(node, 2)?)?;
            let op = augmented_operator(operator_node)?;
            return Ok(stmt(StmtKind::AugAssign { target, op, value }, location));
        }

        // Targets and `=` alternate up to the value.
        let mut targets = Vec::new();
        for target_node in node
            .children()
            .take(node.len().saturating_sub(2))
            .step_by(2)
        {
            if target_node.kind() == symbol::YIELD_EXPR {
                return Err(syntax_error(
                    target_node,
                    "assignment to yield expression not possible",
                ));
            }
            let mut target = self.testlist(target_node)?;
            set_context(&mut target, ExprContext::Store, target_node)?;
            targets.push(target);
        }
        let value = self.assigned_value(last_child(node)?)?;

        Ok(stmt(StmtKind::Assign { targets, value }, location))
    }

    fn print_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let redirected = node
            .child(1)
            .is_some_and(|second| second.kind() == tokenizer::RIGHTSHIFT);
        let (dest, first_value) = if redirected {
            (Some(self.expr(child(node, 2)?)?), 4)
        } else {
            (None, 1)
        };

        let mut values = Vec::new();
        for value in node.children().skip(first_value).step_by(2) {
            values.push(self.expr(value)?);
        }
        let nl = last_child(node)?.kind() != tokenizer::COMMA;

        Ok(stmt(StmtKind::Print { dest, values, nl }, node.location()))
    }

    fn flow_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let location = node.location();
        let flow = child(node, 0)?;

        let kind = match flow.kind() {
            symbol::BREAK_STMT => StmtKind::Break,
            symbol::CONTINUE_STMT => StmtKind::Continue,
            symbol::YIELD_STMT => StmtKind::Expr {
                value: self.expr(child(flow, 0)?)?,
            },
            symbol::RETURN_STMT => {
                let value = if flow.len() == 1 {
                    None
                } else {
                    Some(self.testlist(child(flow, 1)?)?)
                };
                StmtKind::Return { value }
            }
            symbol::RAISE_STMT => {
                if !matches!(flow.len(), 1 | 2 | 4 | 6) {
                    return Err(unsupported(
                        "a raise statement with an unexpected number of parts",
                    ));
                }
                let mut parts = Vec::new();
                for part in flow.children().skip(1).step_by(2) {
                    parts.push(self.expr(part)?);
                }
                let mut parts = parts.into_iter();
                StmtKind::Raise {
                    type_: parts.next(),
                    inst: parts.next(),
                    tback: parts.next(),
                }
            }
            _ => return Err(unsupported("a flow statement of an unknown type")),
        };

        Ok(stmt(kind, location))
    }

    fn exec_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        if !matches!(node.len(), 2 | 4 | 6) {
            return Err(unsupported(
                "an exec statement with an unexpected number of parts",
            ));
        }

        let mut body = self.expr(child(node, 1)?)?;
        let globals = if node.len() >= 4 {
            Some(self.expr(child(node, 3)?)?)
        } else {
            None
        };
        let locals = if node.len() == 6 {
            Some(self.expr(child(node, 5)?)?)
        } else {
            None
        };

        // `exec(code, globals[, locals])` reads as the statement's parts.
        if node.len() == 2
            && let ExprKind::Tuple { elts, .. } = &mut body.kind
            && let [code, rest @ ..] = elts.as_mut_slice()
            && matches!(rest.len(), 1 | 2)
        {
            let code = std::mem::replace(code, Expr::placeholder());
            let mut rest = rest
                .iter_mut()
                .map(|part| std::mem::replace(part, Expr::placeholder()));
            return Ok(stmt(
                StmtKind::Exec {
                    body: code,
                    globals: rest.next(),
                    locals: rest.next(),
                },
                node.location(),
            ));
        }

        Ok(stmt(
            StmtKind::Exec {
                body,
                globals,
                locals,
            },
            node.location(),
        ))
    }

    fn assert_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let msg = match node.len() {
            2 => None,
            4 => Some(child(node, 3)?),
            _ => {
                return Err(unsupported(
                    "an assert statement with an unexpected number of parts",
                ));
            }
        };

        let test = self.expr(child(node, 1)?)?;
        let msg = match msg {
            Some(msg) => Some(self.expr(msg)?),
            None => None,
        };

        Ok(stmt(StmtKind::Assert { test, msg }, node.location()))
    }

    /// The name an import binds or imports. `store` when the name is bound.
    fn alias(&mut self, node: NodeRef<'_>, store: bool) -> Built<ast::Alias> {
        match node.kind() {
            symbol::IMPORT_AS_NAME => {
                let name_node = child(node, 0)?;
                let asname = if node.len() == 3 {
                    let asname_node = child(node, 2)?;
                    let asname = identifier(asname_node)?;
                    if store {
                        check_binding(asname_node, &asname.0)?;
                    }
                    Some(asname)
                } else {
                    check_binding(name_node, token_text(name_node)?)?;
                    None
                };
                Ok(ast::Alias {
                    name: identifier(name_node)?,
                    asname,
                })
            }
            symbol::DOTTED_AS_NAME => {
                if node.len() == 1 {
                    return self.alias(child(node, 0)?, store);
                }
                let name = self.alias(child(node, 0)?, false)?.name;
                let asname_node = child(node, 2)?;
                let asname = identifier(asname_node)?;
                if store {
                    check_binding(asname_node, &asname.0)?;
                }
                Ok(ast::Alias {
                    name,
                    asname: Some(asname),
                })
            }
            symbol::DOTTED_NAME => {
                if node.len() == 1 {
                    let name_node = child(node, 0)?;
                    let name = identifier(name_node)?;
                    if store {
                        check_binding(name_node, &name.0)?;
                    }
                    return Ok(ast::Alias { name, asname: None });
                }
                let mut name = Vec::new();
                for (index, part) in items(node).enumerate() {
                    if index > 0 {
                        name.push(b'.');
                    }
                    name.extend_from_slice(token_text(part)?);
                }
                Ok(ast::Alias {
                    name: Identifier(name),
                    asname: None,
                })
            }
            tokenizer::STAR => Ok(ast::Alias {
                name: Identifier(b"*".to_vec()),
                asname: None,
            }),
            _ => Err(unsupported("an import of an unknown node type")),
        }
    }

    fn import_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let location = node.location();
        let import = child(node, 0)?;

        if import.kind() == symbol::IMPORT_NAME {
            let mut names = Vec::new();
            for name in items(child(import, 1)?) {
                names.push(self.alias(name, true)?);
            }
            return Ok(stmt(StmtKind::Import { names }, location));
        }
        if import.kind() != symbol::IMPORT_FROM {
            return Err(unsupported("an import statement of an unknown type"));
        }

        // Leading dots give the level; a dotted name, if any, the module.
        let mut level = 0;
        let mut module = None;
        let mut index = 1;
        while let Some(part) = import.child(index) {
            if part.kind() == symbol::DOTTED_NAME {
                module = Some(self.alias(part, false)?.name);
                index += 1;
                break;
            }
            if part.kind() != tokenizer::DOT {
                break;
            }
            level += 1;
            index += 1;
        }

        // Past the `import` keyword come the names.
        let after = child(import, index + 1)?;
        let names_node = match after.kind() {
            tokenizer::STAR => after,
            tokenizer::LPAR => child(import, index + 2)?,
            symbol::IMPORT_AS_NAMES => {
                if after.len() % 2 == 0 {
                    return Err(syntax_error(
                        after,
                        "trailing comma not allowed without surrounding parentheses",
                    ));
                }
                after
            }
            _ => return Err(syntax_error(import, "Unexpected node-type in from-import")),
        };

        let mut names = Vec::new();
        if names_node.kind() == tokenizer::STAR {
            names.push(self.alias(names_node, true)?);
        } else {
            for name in items(names_node) {
                names.push(self.alias(name, true)?);
            }
        }

        Ok(stmt(
            StmtKind::ImportFrom {
                module,
                names,
                level: Some(level),
            },
            location,
        ))
    }

    /// `if`, its `elif` clauses as nested `If` statements, and `else`. The
    /// last `elif` is converted first, then the others back to the `if`.
    fn if_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let count = node.len();
        let has_else = count >= 7 && {
            let keyword = child(node, count - 3)?;
            keyword.kind() == tokenizer::NAME && token_text(keyword)? == b"else"
        };
        let clause_end = if has_else { count - 3 } else { count };
        let elif_count = clause_end.saturating_sub(4) / 4;

        let mut orelse = Vec::new();
        let mut else_pending = has_else;
        for clause in (1..=elif_count).rev() {
            let start = clause * 4;
            if token_text(child(node, start)?)? != b"elif" {
                return Err(unsupported(
                    "an if statement with an unknown clause keyword",
                ));
            }
            let test_node = child(node, start + 1)?;
            let test = self.expr(test_node)?;
            let body = self.suite(child(node, start + 3)?)?;
            if else_pending {
                orelse = self.suite(last_child(node)?)?;
                else_pending = false;
            }
            let nested = stmt(
                StmtKind::If {
                    test,
                    body,
                    orelse: std::mem::take(&mut orelse),
                },
                test_node.location(),
            );
            orelse = vec![nested];
        }

        let test = self.expr(child(node, 1)?)?;
        let body = self.suite(child(node, 3)?)?;
        if else_pending {
            orelse = self.suite(last_child(node)?)?;
        }

        Ok(stmt(StmtKind::If { test, body, orelse }, node.location()))
    }

    fn while_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let test = self.expr(child(node, 1)?)?;
        let body = self.suite(child(node, 3)?)?;
        let orelse = match node.len() {
            4 => Vec::new(),
            7 => self.suite(child(node, 6)?)?,
            _ => {
                return Err(unsupported(
                    "a while statement with an unexpected number of parts",
                ));
            }
        };

        Ok(stmt(
            StmtKind::While { test, body, orelse },
            node.location(),
        ))
    }

    /// A target list: one target, or a tuple of them located at the first.
    fn target(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let mut targets = self.expr_list(node, ExprContext::Store)?;
        if node.len() == 1 {
            return targets
                .pop()
                .ok_or_else(|| unsupported("an empty target list"));
        }

        let location = targets
            .first()
            .map_or(node.location(), |first| first.location);
        Ok(expr(
            ExprKind::Tuple {
                elts: targets,
                ctx: ExprContext::Store,
            },
            location,
        ))
    }

    fn for_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let orelse = match node.len() {
            6 => Vec::new(),
            9 => self.suite(child(node, 8)?)?,
            _ => {
                return Err(unsupported(
                    "a for statement with an unexpected number of parts",
                ));
            }
        };
        let target = self.target(child(node, 1)?)?;
        let iter = self.testlist(child(node, 3)?)?;
        let body = self.suite(child(node, 5)?)?;

        Ok(stmt(
            StmtKind::For {
                target,
                iter,
                body,
                orelse,
            },
            node.location(),
        ))
    }

    /// `try` with handlers, `else`, and `finally`. The body is converted
    /// first, then `else`, `finally`, and the handlers.
    fn try_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let location = node.location();
        let count = node.len();
        let body = self.suite(child(node, 2)?)?;

        let mut handler_count = count.saturating_sub(3) / 3;
        let mut orelse = Vec::new();
        let mut finalbody = Vec::new();
        let mut has_finally = false;
        let closing = child(node, count.wrapping_sub(3))?;
        if closing.kind() == tokenizer::NAME {
            if token_text(closing)? == b"finally" {
                if count >= 9 && child(node, count - 6)?.kind() == tokenizer::NAME {
                    orelse = self.suite(child(node, count - 4)?)?;
                    handler_count = handler_count.saturating_sub(1);
                }
                finalbody = self.suite(last_child(node)?)?;
                has_finally = true;
            } else {
                orelse = self.suite(last_child(node)?)?;
            }
            handler_count = handler_count.saturating_sub(1);
        } else if closing.kind() != symbol::EXCEPT_CLAUSE {
            return Err(unsupported(
                "a try statement whose clauses are not recognized",
            ));
        }

        if handler_count == 0 {
            return Ok(stmt(StmtKind::TryFinally { body, finalbody }, location));
        }

        let mut handlers = Vec::new();
        for index in 0..handler_count {
            let clause = child(node, 3 + index * 3)?;
            let handler_body = child(node, 5 + index * 3)?;
            handlers.push(self.except_handler(clause, handler_body)?);
        }
        let handled = stmt(
            StmtKind::TryExcept {
                body,
                handlers,
                orelse,
            },
            location,
        );

        if !has_finally {
            return Ok(handled);
        }

        Ok(stmt(
            StmtKind::TryFinally {
                body: vec![handled],
                finalbody,
            },
            location,
        ))
    }

    fn except_handler(
        &mut self,
        clause: NodeRef<'_>,
        body: NodeRef<'_>,
    ) -> Built<ast::ExceptHandler> {
        let (type_, name) = match clause.len() {
            1 => (None, None),
            2 => (Some(self.expr(child(clause, 1)?)?), None),
            // The bound name is converted before the exception type.
            4 => {
                let name_node = child(clause, 3)?;
                let mut name = self.expr(name_node)?;
                set_context(&mut name, ExprContext::Store, name_node)?;
                let type_ = self.expr(child(clause, 1)?)?;
                (Some(type_), Some(name))
            }
            _ => {
                return Err(unsupported(
                    "an except clause with an unexpected number of parts",
                ));
            }
        };
        let body = self.suite(body)?;

        Ok(ast::ExceptHandler {
            type_,
            name,
            body,
            location: clause.location(),
        })
    }

    /// One `With` per item, the last innermost. The body is converted
    /// first, then the items from the last.
    fn with_stmt(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let mut body = self.suite(last_child(node)?)?;

        let item_count = node.len().saturating_sub(2) / 2;
        for index in (0..item_count).rev() {
            let item = child(node, 1 + index * 2)?;
            let context_expr = self.expr(child(item, 0)?)?;
            let optional_vars = if item.len() == 3 {
                let mut target = self.expr(child(item, 2)?)?;
                set_context(&mut target, ExprContext::Store, item)?;
                Some(target)
            } else {
                None
            };
            body = vec![stmt(
                StmtKind::With {
                    context_expr,
                    optional_vars,
                    body,
                },
                item.location(),
            )];
        }

        body.pop()
            .ok_or_else(|| unsupported("a with statement without items"))
    }

    fn decorated(&mut self, node: NodeRef<'_>) -> Built<Stmt> {
        let mut decorator_list = Vec::new();
        for decorator in child(node, 0)?.children() {
            decorator_list.push(self.decorator(decorator)?);
        }

        let definition = child(node, 1)?;
        match definition.kind() {
            symbol::FUNCDEF => self.funcdef(definition, decorator_list, node.location()),
            symbol::CLASSDEF => self.classdef(definition, decorator_list, node.location()),
            _ => Err(unsupported(
                "a decorated statement that is not a definition",
            )),
        }
    }

    fn decorator(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let name = self.dotted_name(child(node, 1)?)?;

        match node.len() {
            3 => Ok(name),
            // A call without arguments is located at the `@`, one with
            // arguments at the name.
            5 => Ok(expr(
                ExprKind::Call {
                    func: Box::new(name),
                    args: Vec::new(),
                    keywords: Vec::new(),
                    starargs: None,
                    kwargs: None,
                },
                node.location(),
            )),
            _ => self.call(child(node, 3)?, name),
        }
    }

    /// A dotted name as attribute lookups on a name, all located at the
    /// dotted name.
    fn dotted_name(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let location = node.location();
        let mut parts = items(node);
        let Some(first) = parts.next() else {
            return Err(unsupported("an empty dotted name"));
        };

        let mut result = expr(
            ExprKind::Name {
                id: identifier(first)?,
                ctx: ExprContext::Load,
            },
            location,
        );
        for part in parts {
            result = expr(
                ExprKind::Attribute {
                    value: Box::new(result),
                    attr: identifier(part)?,
                    ctx: ExprContext::Load,
                },
                location,
            );
        }

        Ok(result)
    }

    fn funcdef(
        &mut self,
        node: NodeRef<'_>,
        decorator_list: Vec<Expr>,
        location: Location,
    ) -> Built<Stmt> {
        let name_node = child(node, 1)?;
        let name = identifier(name_node)?;
        check_binding(name_node, &name.0)?;

        let args = self.arguments(child(node, 2)?)?;
        let body = self.suite(child(node, 4)?)?;

        Ok(stmt(
            StmtKind::FunctionDef {
                name,
                args,
                body,
                decorator_list,
            },
            location,
        ))
    }

    fn classdef(
        &mut self,
        node: NodeRef<'_>,
        decorator_list: Vec<Expr>,
        location: Location,
    ) -> Built<Stmt> {
        let name = identifier(child(node, 1)?)?;
        check_binding(node, &name.0)?;

        let bases = if node.len() == 4 || child(node, 3)?.kind() == tokenizer::RPAR {
            Vec::new()
        } else {
            let bases = child(node, 3)?;
            let mut list = Vec::new();
            for base in items(bases) {
                list.push(self.expr(base)?);
            }
            list
        };
        let body = self.suite(last_child(node)?)?;

        Ok(stmt(
            StmtKind::ClassDef {
                name,
                bases,
                body,
                decorator_list,
            },
            location,
        ))
    }

    /// Parameters of a function or lambda, from its `parameters` or
    /// `varargslist` node.
    fn arguments(&mut self, node: NodeRef<'_>) -> Built<ast::Arguments> {
        let mut arguments = ast::Arguments {
            args: Vec::new(),
            vararg: None,
            kwarg: None,
            defaults: Vec::new(),
        };

        let list = if node.kind() == symbol::PARAMETERS {
            if node.len() == 2 {
                return Ok(arguments);
            }
            child(node, 1)?
        } else {
            node
        };

        let mut seen_default = false;
        let mut index = 0;
        while let Some(part) = list.child(index) {
            match part.kind() {
                symbol::FPDEF => {
                    let has_default = list
                        .child(index + 1)
                        .is_some_and(|next| next.kind() == tokenizer::EQUAL);
                    if has_default {
                        arguments.defaults.push(self.expr(child(list, index + 2)?)?);
                        index += 2;
                        seen_default = true;
                    } else if seen_default {
                        return Err(syntax_error(
                            list,
                            "non-default argument follows default argument",
                        ));
                    }
                    arguments
                        .args
                        .push(self.parameter(list, part, has_default)?);
                    index += 2;
                }
                tokenizer::STAR | tokenizer::DOUBLESTAR => {
                    let name_node = child(list, index + 1)?;
                    let name = identifier(name_node)?;
                    check_binding(name_node, &name.0)?;
                    if part.kind() == tokenizer::STAR {
                        arguments.vararg = Some(name);
                    } else {
                        arguments.kwarg = Some(name);
                    }
                    index += 3;
                }
                _ => {
                    let message = format!(
                        "unexpected node in varargslist: {} @ {index}",
                        type_number(part)
                    );
                    return Err(BuildError::System { message });
                }
            }
        }

        Ok(arguments)
    }

    /// One parameter. Parentheses around a single name are dropped; a
    /// parenthesized list unpacks into a tuple of stored names.
    fn parameter(
        &mut self,
        list: NodeRef<'_>,
        fpdef: NodeRef<'_>,
        has_default: bool,
    ) -> Built<Expr> {
        let mut fpdef = fpdef;
        let mut parenthesized = false;

        while fpdef.len() == 3 {
            let inner = child(fpdef, 1)?;
            if inner.len() != 1 {
                return self.unpacked_parameters(inner);
            }
            parenthesized = true;
            fpdef = child(inner, 0)?;
        }
        if parenthesized && has_default {
            return Err(syntax_error(list, "parenthesized arg with default"));
        }

        let name_node = child(fpdef, 0)?;
        let name = identifier(name_node)?;
        check_binding(list, &name.0)?;

        Ok(expr(
            ExprKind::Name {
                id: name,
                ctx: ExprContext::Param,
            },
            fpdef.location(),
        ))
    }

    /// A parenthesized parameter list: a tuple of names to store.
    fn unpacked_parameters(&mut self, fplist: NodeRef<'_>) -> Built<Expr> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || {
            let mut elements = Vec::new();
            for element in items(fplist) {
                let mut fpdef = element;
                let resolved = loop {
                    if fpdef.len() != 3 {
                        let name_node = child(fpdef, 0)?;
                        let name = identifier(name_node)?;
                        check_binding(fplist, &name.0)?;
                        break expr(
                            ExprKind::Name {
                                id: name,
                                ctx: ExprContext::Store,
                            },
                            name_node.location(),
                        );
                    }
                    let inner = child(fpdef, 1)?;
                    if inner.len() != 1 {
                        break self.unpacked_parameters(inner)?;
                    }
                    fpdef = child(inner, 0)?;
                };
                elements.push(resolved);
            }

            let mut tuple = expr(
                ExprKind::Tuple {
                    elts: elements,
                    ctx: ExprContext::Store,
                },
                fplist.location(),
            );
            set_context(&mut tuple, ExprContext::Store, fplist)?;

            Ok(tuple)
        })
    }

    /// The items of a list node, each stored or deleted per `context` and
    /// checked against its own node.
    fn expr_list(&mut self, node: NodeRef<'_>, context: ExprContext) -> Built<Vec<Expr>> {
        let mut list = Vec::new();
        for item in items(node) {
            let mut value = self.expr(item)?;
            set_context(&mut value, context, item)?;
            list.push(value);
        }

        Ok(list)
    }

    /// A test list: its single test, or a tuple located at the list.
    fn testlist(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        if node.len() == 1 {
            return self.expr(child(node, 0)?);
        }

        let mut elements = Vec::new();
        for item in items(node) {
            elements.push(self.expr(item)?);
        }

        Ok(expr(
            ExprKind::Tuple {
                elts: elements,
                ctx: ExprContext::Load,
            },
            node.location(),
        ))
    }

    fn expr(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.expr_inner(node))
    }

    /// Converts any expression-level node. A node with a single child
    /// stands for that child.
    fn expr_inner(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let mut node = node;
        loop {
            match node.kind() {
                symbol::TEST | symbol::OLD_TEST => {
                    let first = child(node, 0)?;
                    if first.kind() == symbol::LAMBDEF || first.kind() == symbol::OLD_LAMBDEF {
                        return self.lambda(first);
                    }
                    if node.len() > 1 {
                        return self.conditional(node);
                    }
                    node = first;
                }
                symbol::OR_TEST | symbol::AND_TEST if node.len() != 1 => return self.boolean(node),
                symbol::NOT_TEST if node.len() != 1 => {
                    let operand = self.expr(child(node, 1)?)?;
                    return Ok(expr(
                        ExprKind::UnaryOp {
                            op: ast::UnaryOp::Not,
                            operand: Box::new(operand),
                        },
                        node.location(),
                    ));
                }
                symbol::COMPARISON if node.len() != 1 => return self.comparison(node),
                symbol::EXPR
                | symbol::XOR_EXPR
                | symbol::AND_EXPR
                | symbol::SHIFT_EXPR
                | symbol::ARITH_EXPR
                | symbol::TERM
                    if node.len() != 1 =>
                {
                    return self.binary(node);
                }
                symbol::FACTOR if node.len() != 1 => return self.factor(node),
                symbol::OR_TEST
                | symbol::AND_TEST
                | symbol::NOT_TEST
                | symbol::COMPARISON
                | symbol::EXPR
                | symbol::XOR_EXPR
                | symbol::AND_EXPR
                | symbol::SHIFT_EXPR
                | symbol::ARITH_EXPR
                | symbol::TERM
                | symbol::FACTOR => node = child(node, 0)?,
                symbol::YIELD_EXPR => {
                    let value = if node.len() == 2 {
                        Some(Box::new(self.testlist(child(node, 1)?)?))
                    } else {
                        None
                    };
                    return Ok(expr(ExprKind::Yield { value }, node.location()));
                }
                symbol::POWER => return self.power(node),
                _ => {
                    return Err(BuildError::System {
                        message: format!("unhandled expr: {}", type_number(node)),
                    });
                }
            }
        }
    }

    fn lambda(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let (args, body) = if node.len() == 3 {
            let args = ast::Arguments {
                args: Vec::new(),
                vararg: None,
                kwarg: None,
                defaults: Vec::new(),
            };
            (args, self.expr(child(node, 2)?)?)
        } else {
            let args = self.arguments(child(node, 1)?)?;
            (args, self.expr(child(node, 3)?)?)
        };

        Ok(expr(
            ExprKind::Lambda {
                args: Box::new(args),
                body: Box::new(body),
            },
            node.location(),
        ))
    }

    /// `body if test else orelse`, converted in that order.
    fn conditional(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let body = self.expr(child(node, 0)?)?;
        let test = self.expr(child(node, 2)?)?;
        let orelse = self.expr(child(node, 4)?)?;

        Ok(expr(
            ExprKind::IfExp {
                test: Box::new(test),
                body: Box::new(body),
                orelse: Box::new(orelse),
            },
            node.location(),
        ))
    }

    /// `and` or `or` over the operands, as the first operator token spells.
    fn boolean(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let mut values = Vec::new();
        for operand in items(node) {
            values.push(self.expr(operand)?);
        }

        let op = if token_text(child(node, 1)?)? == b"and" {
            ast::BoolOp::And
        } else {
            ast::BoolOp::Or
        };

        Ok(expr(ExprKind::BoolOp { op, values }, node.location()))
    }

    /// A comparison chain. The operands right of the first are converted
    /// before the first.
    fn comparison(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let mut ops = Vec::new();
        let mut comparators = Vec::new();
        let mut index = 1;
        while let Some(operator) = node.child(index) {
            ops.push(comparison_operator(operator)?);
            comparators.push(self.expr(child(node, index + 1)?)?);
            index += 2;
        }
        let left = self.expr(child(node, 0)?)?;

        Ok(expr(
            ExprKind::Compare {
                left: Box::new(left),
                ops,
                comparators,
            },
            node.location(),
        ))
    }

    /// A left-associative chain of binary operators. The first operation is
    /// located at the chain, each later one at its operator.
    fn binary(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let left = self.expr(child(node, 0)?)?;
        let right = self.expr(child(node, 2)?)?;
        let Some(op) = binary_operator(child(node, 1)?) else {
            return Err(BuildError::NoException);
        };
        let mut result = expr(
            ExprKind::BinOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            },
            node.location(),
        );

        let mut index = 3;
        while let Some(operator) = node.child(index) {
            let Some(op) = binary_operator(operator) else {
                return Err(BuildError::NoException);
            };
            let right = self.expr(child(node, index + 1)?)?;
            result = expr(
                ExprKind::BinOp {
                    left: Box::new(result),
                    op,
                    right: Box::new(right),
                },
                operator.location(),
            );
            index += 2;
        }

        Ok(result)
    }

    /// A unary operator. Minus applied directly to a number literal yields
    /// the negative number.
    fn factor(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let operator = child(node, 0)?;
        let operand = child(node, 1)?;

        if operator.kind() == tokenizer::MINUS
            && node.len() == 2
            && let Some(number) = plain_number(operand)
        {
            return Ok(expr(
                ExprKind::Num {
                    n: self.number(number, true)?,
                },
                node.location(),
            ));
        }

        let operand = self.expr(operand)?;
        let op = match operator.kind() {
            tokenizer::PLUS => ast::UnaryOp::UAdd,
            tokenizer::MINUS => ast::UnaryOp::USub,
            tokenizer::TILDE => ast::UnaryOp::Invert,
            _ => {
                return Err(BuildError::System {
                    message: format!("unhandled factor: {}", type_number(operator)),
                });
            }
        };

        Ok(expr(
            ExprKind::UnaryOp {
                op,
                operand: Box::new(operand),
            },
            node.location(),
        ))
    }

    /// The value of a NUMBER token, negated when a unary minus was folded
    /// into it.
    fn number(&self, token: NodeRef<'_>, negative: bool) -> Built<ast::Number> {
        let text = token_text(token)?;
        if !self.tokenized && !is_single_token(text, tokenizer::NUMBER) {
            return Err(malformed_number(text, negative));
        }

        if !negative {
            return Ok(literals::parse_number(text));
        }
        let mut signed = Vec::with_capacity(text.len() + 1);
        signed.push(b'-');
        signed.extend_from_slice(text);

        Ok(literals::parse_number(&signed))
    }
    /// An atom with trailers, then an optional power. Each trailer's result
    /// is located at the atom's expression.
    fn power(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let mut value = self.atom(child(node, 0)?)?;
        let location = value.location;

        for trailer in node.children().skip(1) {
            if trailer.kind() != symbol::TRAILER {
                break;
            }
            value = self.trailer(trailer, value)?;
            value.location = location;
        }

        let last = last_child(node)?;
        if last.kind() == symbol::FACTOR {
            let exponent = self.expr(last)?;
            value = expr(
                ExprKind::BinOp {
                    left: Box::new(value),
                    op: ast::Operator::Pow,
                    right: Box::new(exponent),
                },
                node.location(),
            );
        }

        Ok(value)
    }

    fn trailer(&mut self, node: NodeRef<'_>, value: Expr) -> Built<Expr> {
        let location = node.location();
        let opener = child(node, 0)?;

        match opener.kind() {
            tokenizer::LPAR if node.len() == 2 => Ok(expr(
                ExprKind::Call {
                    func: Box::new(value),
                    args: Vec::new(),
                    keywords: Vec::new(),
                    starargs: None,
                    kwargs: None,
                },
                location,
            )),
            tokenizer::LPAR => self.call(child(node, 1)?, value),
            tokenizer::DOT => {
                let attr = identifier(child(node, 1)?)?;
                Ok(expr(
                    ExprKind::Attribute {
                        value: Box::new(value),
                        attr,
                        ctx: ExprContext::Load,
                    },
                    location,
                ))
            }
            tokenizer::LSQB => {
                let subscripts = child(node, 1)?;
                let slice = self.subscripts(subscripts)?;
                Ok(expr(
                    ExprKind::Subscript {
                        value: Box::new(value),
                        slice: Box::new(slice),
                        ctx: ExprContext::Load,
                    },
                    location,
                ))
            }
            _ => Err(unsupported("a trailer of an unknown type")),
        }
    }

    /// The slice of a subscript list. Several plain indexes form one tuple
    /// index; any slice among them makes an extended slice.
    fn subscripts(&mut self, node: NodeRef<'_>) -> Built<ast::Slice> {
        if node.len() == 1 {
            return self.slice(child(node, 0)?);
        }

        let mut dims = Vec::new();
        for subscript in items(node) {
            dims.push(self.slice(subscript)?);
        }
        if !dims
            .iter()
            .all(|dim| matches!(dim, ast::Slice::Index { .. }))
        {
            return Ok(ast::Slice::ExtSlice { dims });
        }

        let mut values = Vec::new();
        for dim in &mut dims {
            if let ast::Slice::Index { value } = dim {
                values.push(std::mem::replace(value, Expr::placeholder()));
            }
        }

        Ok(ast::Slice::Index {
            value: expr(
                ExprKind::Tuple {
                    elts: values,
                    ctx: ExprContext::Load,
                },
                node.location(),
            ),
        })
    }

    /// One subscript: `...`, an index, or a slice with optional lower and
    /// upper bounds and an optional step.
    /// A step colon without a step gives the name `None` at that colon.
    fn slice(&mut self, node: NodeRef<'_>) -> Built<ast::Slice> {
        let first = child(node, 0)?;
        if first.kind() == tokenizer::DOT {
            return Ok(ast::Slice::Ellipsis);
        }
        if node.len() == 1 && first.kind() == symbol::TEST {
            return Ok(ast::Slice::Index {
                value: self.expr(first)?,
            });
        }

        let lower = if first.kind() == symbol::TEST {
            Some(self.expr(first)?)
        } else {
            None
        };

        let upper_position = if first.kind() == tokenizer::COLON {
            1
        } else {
            2
        };
        let upper = match node.child(upper_position) {
            Some(candidate) if candidate.kind() == symbol::TEST => Some(self.expr(candidate)?),
            _ => None,
        };

        let last = last_child(node)?;
        let step = if last.kind() != symbol::SLICEOP {
            None
        } else if last.len() == 1 {
            let colon = child(last, 0)?;
            Some(expr(
                ExprKind::Name {
                    id: Identifier(b"None".to_vec()),
                    ctx: ExprContext::Load,
                },
                colon.location(),
            ))
        } else {
            let candidate = child(last, 1)?;
            if candidate.kind() == symbol::TEST {
                Some(self.expr(candidate)?)
            } else {
                None
            }
        };

        Ok(ast::Slice::Slice { lower, upper, step })
    }

    /// A call of `func` with the arguments of an `arglist`. The call is
    /// located at `func`. The shape of the whole list is checked before any
    /// argument is converted.
    fn call(&mut self, node: NodeRef<'_>, func: Expr) -> Built<Expr> {
        let arguments = call_arguments(node)?;

        let named = arguments
            .iter()
            .filter(|argument| {
                matches!(argument, CallArgument::Plain(_) | CallArgument::Keyword(_))
            })
            .count();
        let generators = arguments
            .iter()
            .filter(|argument| matches!(argument, CallArgument::Generator(_)))
            .count();
        if generators > 1 || (generators == 1 && named > 0) {
            return Err(syntax_error(
                node,
                "Generator expression must be parenthesized if not sole argument",
            ));
        }
        if named + generators > 255 {
            return Err(syntax_error(node, "more than 255 arguments"));
        }

        let location = func.location;
        let mut args = Vec::new();
        let mut keywords = Vec::new();
        let mut starargs = None;
        let mut kwargs = None;

        for argument in arguments {
            match argument {
                CallArgument::Plain(value) => {
                    if !keywords.is_empty() {
                        return Err(syntax_error(value, "non-keyword arg after keyword arg"));
                    }
                    if starargs.is_some() {
                        return Err(syntax_error(
                            value,
                            "only named arguments may follow *expression",
                        ));
                    }
                    args.push(self.expr(child(value, 0)?)?);
                }
                CallArgument::Generator(generator) => args.push(self.generator(generator)?),
                CallArgument::Keyword(pair) => {
                    let keyword = self.keyword_argument(pair, &keywords)?;
                    keywords.push(keyword);
                }
                CallArgument::Star(value) => starargs = Some(Box::new(self.expr(value)?)),
                CallArgument::DoubleStar(value) => kwargs = Some(Box::new(self.expr(value)?)),
            }
        }

        Ok(expr(
            ExprKind::Call {
                func: Box::new(func),
                args,
                keywords,
                starargs,
                kwargs,
            },
            location,
        ))
    }

    /// `name=value` in a call, checked against the keywords before it.
    fn keyword_argument(
        &mut self,
        pair: NodeRef<'_>,
        earlier: &[ast::Keyword],
    ) -> Built<ast::Keyword> {
        let key = self.expr(child(pair, 0)?)?;
        let arg = match key.kind {
            ExprKind::Lambda { .. } => {
                return Err(syntax_error(pair, "lambda cannot contain assignment"));
            }
            ExprKind::Name { ref id, .. } => id.clone(),
            _ => return Err(syntax_error(pair, "keyword can't be an expression")),
        };
        check_binding(pair, &arg.0)?;
        if earlier.iter().any(|existing| existing.arg == arg) {
            return Err(syntax_error(pair, "keyword argument repeated"));
        }
        let value = self.expr(child(pair, 2)?)?;

        Ok(ast::Keyword { arg, value })
    }

    fn atom(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let location = node.location();
        let first = child(node, 0)?;

        let kind = match first.kind() {
            tokenizer::NAME => ExprKind::Name {
                id: identifier(first)?,
                ctx: ExprContext::Load,
            },
            tokenizer::NUMBER => ExprKind::Num {
                n: self.number(first, false)?,
            },
            tokenizer::STRING => ExprKind::Str {
                s: self.strings(node)?,
            },
            tokenizer::LPAR => {
                let inner = child(node, 1)?;
                match inner.kind() {
                    tokenizer::RPAR => ExprKind::Tuple {
                        elts: Vec::new(),
                        ctx: ExprContext::Load,
                    },
                    symbol::YIELD_EXPR => return self.expr(inner),
                    _ if inner.len() > 1 && child(inner, 1)?.kind() == symbol::COMP_FOR => {
                        return self.generator(inner);
                    }
                    _ => return self.testlist(inner),
                }
            }
            tokenizer::LSQB => {
                let inner = child(node, 1)?;
                if inner.kind() == tokenizer::RSQB {
                    ExprKind::List {
                        elts: Vec::new(),
                        ctx: ExprContext::Load,
                    }
                } else if inner.len() == 1 || child(inner, 1)?.kind() == tokenizer::COMMA {
                    let mut elements = Vec::new();
                    for item in items(inner) {
                        elements.push(self.expr(item)?);
                    }
                    ExprKind::List {
                        elts: elements,
                        ctx: ExprContext::Load,
                    }
                } else {
                    return self.list_comprehension(inner);
                }
            }
            tokenizer::LBRACE => {
                let inner = child(node, 1)?;
                if inner.kind() == tokenizer::RBRACE {
                    ExprKind::Dict {
                        keys: Vec::new(),
                        values: Vec::new(),
                    }
                } else if inner.len() == 1 || child(inner, 1)?.kind() == tokenizer::COMMA {
                    let mut elements = Vec::new();
                    for item in items(inner) {
                        elements.push(self.expr(item)?);
                    }
                    ExprKind::Set { elts: elements }
                } else if child(inner, 1)?.kind() == symbol::COMP_FOR {
                    return self.set_comprehension(inner);
                } else if inner.len() > 3 && child(inner, 3)?.kind() == symbol::COMP_FOR {
                    return self.dict_comprehension(inner);
                } else {
                    let mut keys = Vec::new();
                    let mut values = Vec::new();
                    for (pair, key) in inner.children().step_by(4).enumerate() {
                        keys.push(self.expr(key)?);
                        values.push(self.expr(child(inner, pair * 4 + 2)?)?);
                    }
                    ExprKind::Dict { keys, values }
                }
            }
            tokenizer::BACKQUOTE => ExprKind::Repr {
                value: Box::new(self.testlist(child(node, 1)?)?),
            },
            _ => {
                return Err(BuildError::System {
                    message: format!("unhandled atom {}", type_number(first)),
                });
            }
        };

        Ok(expr(kind, location))
    }

    /// The value of the adjacent string tokens of an atom.
    fn strings(&mut self, node: NodeRef<'_>) -> Built<ast::StrLiteral> {
        let mut tokens = Vec::new();
        for token in node.children() {
            let text = token_text(token)?;
            if !self.tokenized && !is_single_token(text, tokenizer::STRING) {
                return Err(unsupported("a string token that is not a string literal"));
            }
            tokens.push(text);
        }

        let mut context = StringContext {
            encoding: self.encoding,
            future_unicode: self.future_unicode,
            codecs: &mut *self.codecs,
        };
        literals::parse_strings(&tokens, &mut context).map_err(|error| match error {
            LiteralError::Unicode(message) => {
                syntax_error(node, format!("(unicode error) {message}"))
            }
            LiteralError::Value(message) => BuildError::Value { message },
            LiteralError::Codec(error) => BuildError::Codec(error),
        })
    }

    /// The `for` and `if` clauses of a comprehension whose first `for`
    /// clause is `first`. The iterable of a list comprehension's clause is a
    /// test list.
    fn generators(
        &mut self,
        first: NodeRef<'_>,
        kinds: &ComprehensionKinds,
    ) -> Built<Vec<ast::Comprehension>> {
        let clauses = comprehension_clauses(first, kinds)?;

        let mut generators = Vec::new();
        for clause in clauses {
            let target = self.target(child(clause.for_clause, 1)?)?;
            let iterable = child(clause.for_clause, 3)?;
            let iter = if kinds.for_clause == symbol::LIST_FOR {
                self.testlist(iterable)?
            } else {
                self.expr(iterable)?
            };
            let mut ifs = Vec::new();
            for condition in clause.conditions {
                ifs.push(self.expr(child(condition, 1)?)?);
            }
            generators.push(ast::Comprehension { target, iter, ifs });
        }

        Ok(generators)
    }

    fn list_comprehension(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let elt = self.expr(child(node, 0)?)?;
        let generators = self.generators(child(node, 1)?, &LIST_COMPREHENSION)?;

        Ok(expr(
            ExprKind::ListComp {
                elt: Box::new(elt),
                generators,
            },
            node.location(),
        ))
    }

    fn generator(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let elt = self.expr(child(node, 0)?)?;
        let generators = self.generators(child(node, 1)?, &COMPREHENSION)?;

        Ok(expr(
            ExprKind::GeneratorExp {
                elt: Box::new(elt),
                generators,
            },
            node.location(),
        ))
    }

    fn set_comprehension(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let elt = self.expr(child(node, 0)?)?;
        let generators = self.generators(child(node, 1)?, &COMPREHENSION)?;

        Ok(expr(
            ExprKind::SetComp {
                elt: Box::new(elt),
                generators,
            },
            node.location(),
        ))
    }

    fn dict_comprehension(&mut self, node: NodeRef<'_>) -> Built<Expr> {
        let key = self.expr(child(node, 0)?)?;
        let value = self.expr(child(node, 2)?)?;
        let generators = self.generators(child(node, 3)?, &COMPREHENSION)?;

        Ok(expr(
            ExprKind::DictComp {
                key: Box::new(key),
                value: Box::new(value),
                generators,
            },
            node.location(),
        ))
    }
}

/// The NUMBER token of a factor operand that is a bare number literal.
fn plain_number(operand: NodeRef<'_>) -> Option<NodeRef<'_>> {
    if operand.kind() != symbol::FACTOR || operand.len() != 1 {
        return None;
    }
    let power = operand.child(0)?;
    if power.kind() != symbol::POWER || power.len() != 1 {
        return None;
    }
    let atom = power.child(0)?;
    if atom.kind() != symbol::ATOM {
        return None;
    }
    let number = atom.child(0)?;

    (number.kind() == tokenizer::NUMBER).then_some(number)
}

/// Whether `text` reads as exactly one token of type `kind`.
fn is_single_token(text: &[u8], kind: u16) -> bool {
    let token = Tokenizer::new(text).next_token();

    token.kind == kind && token.span == Some((0, text.len()))
}

/// The error for a NUMBER token that is not a number literal, `negative`
/// when a unary minus was folded into it. Text with no digit and no suffix
/// is neither an integer nor a float; other text is not converted here.
fn malformed_number(text: &[u8], negative: bool) -> BuildError {
    const MESSAGE_LIMIT: usize = 200;

    let lowered = text.to_ascii_lowercase();
    let numeric_word = lowered
        .windows(3)
        .any(|window| window == b"inf" || window == b"nan");
    let suffixed = matches!(text.last(), Some(b'l' | b'L' | b'j' | b'J'));
    if text.is_empty() || suffixed || numeric_word || text.iter().any(u8::is_ascii_digit) {
        return unsupported("a number token that is not a number literal");
    }

    // The message holds at most the first 200 bytes of the text.
    let mut shown = Vec::with_capacity(text.len() + 1);
    if negative {
        shown.push(b'-');
    }
    shown.extend_from_slice(text);
    shown.truncate(MESSAGE_LIMIT);
    let Ok(shown) = String::from_utf8(shown) else {
        return unsupported("a number token that is not UTF-8 text");
    };

    BuildError::Value {
        message: format!("could not convert string to float: {shown}"),
    }
}
