//! A recursive-descent parser for the Python 2.7 grammar. Each rule opens
//! a nonterminal node, consumes its tokens and subrules in source order, and
//! closes the node, so the tree holds one node per rule application with its
//! terminals and subrules as children, in the order they were read.
//!
//! A rule is entered only once the next token is known to begin it, and the
//! next token is read only when a rule needs to look at it. That keeps the
//! point where an error is reported, and the token it is reported at, the
//! same as for any parser that reads one token at a time and decides on it.

use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::parser::CstNode;
use crate::interp::compiler::parser::MAX_DEPTH;
use crate::interp::compiler::symbol;
use crate::interp::compiler::tokenizer;
use crate::interp::compiler::tokenizer::Status;
use crate::interp::compiler::tokenizer::Tokenizer;

/// The reserved words of the grammar. A NAME token spelling one of them is
/// that keyword wherever it appears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keyword {
    And,
    As,
    Assert,
    Break,
    Class,
    Continue,
    Def,
    Del,
    Elif,
    Else,
    Except,
    Exec,
    Finally,
    For,
    From,
    Global,
    If,
    Import,
    In,
    Is,
    Lambda,
    Not,
    Or,
    Pass,
    Print,
    Raise,
    Return,
    Try,
    While,
    With,
    Yield,
}

impl Keyword {
    fn from_text(text: &[u8]) -> Option<Self> {
        let keyword = match text {
            b"and" => Self::And,
            b"as" => Self::As,
            b"assert" => Self::Assert,
            b"break" => Self::Break,
            b"class" => Self::Class,
            b"continue" => Self::Continue,
            b"def" => Self::Def,
            b"del" => Self::Del,
            b"elif" => Self::Elif,
            b"else" => Self::Else,
            b"except" => Self::Except,
            b"exec" => Self::Exec,
            b"finally" => Self::Finally,
            b"for" => Self::For,
            b"from" => Self::From,
            b"global" => Self::Global,
            b"if" => Self::If,
            b"import" => Self::Import,
            b"in" => Self::In,
            b"is" => Self::Is,
            b"lambda" => Self::Lambda,
            b"not" => Self::Not,
            b"or" => Self::Or,
            b"pass" => Self::Pass,
            b"print" => Self::Print,
            b"raise" => Self::Raise,
            b"return" => Self::Return,
            b"try" => Self::Try,
            b"while" => Self::While,
            b"with" => Self::With,
            b"yield" => Self::Yield,
            _ => return None,
        };

        Some(keyword)
    }
}

/// What the grammar sees of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Terminal {
    /// A NAME that is not a keyword.
    Name,
    Keyword(Keyword),
    /// Any other token, by type.
    Token(u16),
}

/// A token with the position its node records.
#[derive(Clone, Copy, Debug)]
struct Located {
    kind: u16,
    span: Option<(usize, usize)>,
    lineno: i32,
    col_offset: i32,
}

/// The next token and what the grammar makes of it.
#[derive(Clone, Copy, Debug)]
struct Lookahead {
    terminal: Terminal,
    token: Located,
}

/// Why parsing stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// The next token cannot continue the input. `expected_indent` when an
    /// indented block had to begin there.
    Syntax { token: u16, expected_indent: bool },
    /// Nonterminals nested deeper than `MAX_DEPTH`.
    Overflow,
    /// The tokenizer failed.
    Token(Status),
}

/// The tokenizer's position when parsing stopped, as error reports use it.
#[derive(Clone, Debug)]
pub(super) struct Failure {
    pub stop: Stop,
    pub lineno: i32,
    pub offset: usize,
    pub line: Vec<u8>,
    /// Whether the tokenizer had reached the end of the input.
    pub at_eof: bool,
}

/// A finished parse: the nodes, root first, and the `__future__` features
/// the parser detected.
pub(super) struct Parsed {
    pub nodes: Vec<CstNode>,
    pub features: u32,
}

/// Tokens as the grammar receives them. The end of input that follows any
/// other token is first delivered as an empty NEWLINE, and then, unless
/// `imply_dedent` is off, the tokenizer closes every open indented block.
struct TokenSource<'t> {
    tokenizer: Tokenizer<'t>,
    text: &'t [u8],
    started: bool,
    imply_dedent: bool,
}

impl TokenSource<'_> {
    fn next(&mut self) -> Result<Located, Status> {
        let token = self.tokenizer.next_token();
        if token.kind == tokenizer::ERRORTOKEN {
            return Err(self.tokenizer.done);
        }

        let lineno = self.tokenizer.lineno;
        let line_start = self.tokenizer.line_start();
        let col_offset = match token.span {
            Some((start, _)) if start >= line_start => {
                i32::try_from(start - line_start).unwrap_or(i32::MAX)
            }
            _ => -1,
        };

        if token.kind == tokenizer::ENDMARKER && self.started {
            self.started = false;
            if self.imply_dedent {
                self.tokenizer.imply_dedents();
            }
            return Ok(Located {
                kind: tokenizer::NEWLINE,
                span: None,
                lineno,
                col_offset,
            });
        }
        self.started = true;

        Ok(Located {
            kind: token.kind,
            span: token.span,
            lineno,
            col_offset,
        })
    }
}

struct Parser<'t> {
    source: TokenSource<'t>,
    lookahead: Option<Lookahead>,
    nodes: Vec<CstNode>,
    /// The nonterminals entered and not yet left, outermost first.
    open: Vec<u32>,
    print_function: bool,
    features: u32,
}

/// Parses `text` in `mode`. `flags` are compiler flags: the `__future__`
/// features given and whether to close indented blocks at the end of input.
pub(super) fn parse(text: &[u8], mode: Mode, flags: CompilerFlags) -> Result<Parsed, Failure> {
    let source = TokenSource {
        tokenizer: Tokenizer::new(text),
        text,
        started: false,
        imply_dedent: !flags.contains(CompilerFlags::DONT_IMPLY_DEDENT),
    };
    let mut parser = Parser {
        source,
        lookahead: None,
        nodes: Vec::new(),
        open: Vec::new(),
        print_function: flags.contains(CompilerFlags::FUTURE_PRINT_FUNCTION),
        features: 0,
    };

    let outcome = match mode {
        Mode::Exec => parser.file_input(),
        Mode::Eval => parser.eval_input(),
        Mode::Single => parser.single_input(),
    };

    match outcome {
        Ok(()) => Ok(Parsed {
            nodes: parser.nodes,
            features: parser.features,
        }),
        Err(stop) => {
            let tokenizer = &parser.source.tokenizer;
            Err(Failure {
                stop,
                lineno: tokenizer.lineno,
                offset: tokenizer.error_offset(),
                line: tokenizer.error_line().to_vec(),
                at_eof: tokenizer.done == Status::Eof,
            })
        }
    }
}

/// Whether a token type can follow an expression as an augmented
/// assignment operator.
fn is_augassign(kind: u16) -> bool {
    matches!(
        kind,
        tokenizer::PLUSEQUAL..=tokenizer::DOUBLESTAREQUAL | tokenizer::DOUBLESLASHEQUAL
    )
}

impl Parser<'_> {
    fn peek(&mut self) -> Result<Terminal, Stop> {
        if let Some(lookahead) = self.lookahead {
            return Ok(lookahead.terminal);
        }

        let token = self.source.next().map_err(Stop::Token)?;
        let terminal = match (token.kind, token.span) {
            (tokenizer::NAME, Some((start, end))) => {
                match Keyword::from_text(&self.source.text[start..end]) {
                    Some(Keyword::Print) if self.print_function => Terminal::Name,
                    Some(keyword) => Terminal::Keyword(keyword),
                    None => Terminal::Name,
                }
            }
            (tokenizer::NAME, None) => Terminal::Name,
            (kind, _) => Terminal::Token(kind),
        };
        self.lookahead = Some(Lookahead { terminal, token });

        Ok(terminal)
    }

    fn at(&mut self, terminal: Terminal) -> Result<bool, Stop> {
        Ok(self.peek()? == terminal)
    }

    fn at_token(&mut self, kind: u16) -> Result<bool, Stop> {
        self.at(Terminal::Token(kind))
    }

    fn at_keyword(&mut self, keyword: Keyword) -> Result<bool, Stop> {
        self.at(Terminal::Keyword(keyword))
    }

    /// The error for the next token, which nothing here accepts.
    fn reject(&mut self) -> Stop {
        self.reject_with(false)
    }

    fn reject_with(&mut self, expected_indent: bool) -> Stop {
        match self.peek() {
            Ok(_) => {
                let token = self
                    .lookahead
                    .map_or(tokenizer::ENDMARKER, |lookahead| lookahead.token.kind);
                // A token no rule mentions is rejected before any rule sees it.
                let expected_indent = expected_indent && token < tokenizer::OP;
                Stop::Syntax {
                    token,
                    expected_indent,
                }
            }
            Err(stop) => stop,
        }
    }

    fn position(&self) -> (i32, i32) {
        self.lookahead.map_or((0, 0), |lookahead| {
            (lookahead.token.lineno, lookahead.token.col_offset)
        })
    }

    fn enter(&mut self, kind: u16) -> Result<(), Stop> {
        if self.open.len() >= MAX_DEPTH {
            return Err(Stop::Overflow);
        }

        let (lineno, col_offset) = if self.open.is_empty() {
            (0, 0)
        } else {
            self.position()
        };
        let id = self.nodes.len() as u32;
        self.nodes.push(CstNode {
            kind,
            start: 0,
            end: 0,
            lineno,
            col_offset,
            children: Vec::new(),
        });
        if let Some(&parent) = self.open.last() {
            self.nodes[parent as usize].children.push(id);
        }
        self.open.push(id);

        Ok(())
    }

    fn leave(&mut self) {
        self.open.pop();
    }

    /// Adds the next token to the innermost open node.
    fn shift(&mut self) {
        let Some(lookahead) = self.lookahead.take() else {
            return;
        };
        let Some(&parent) = self.open.last() else {
            return;
        };

        let token = lookahead.token;
        let (start, end) = token.span.unwrap_or((0, 0));
        let id = self.nodes.len() as u32;
        self.nodes.push(CstNode {
            kind: token.kind,
            start,
            end,
            lineno: token.lineno,
            col_offset: token.col_offset,
            children: Vec::new(),
        });
        self.nodes[parent as usize].children.push(id);
    }

    fn expect(&mut self, terminal: Terminal) -> Result<(), Stop> {
        if !self.at(terminal)? {
            return Err(self.reject());
        }
        self.shift();

        Ok(())
    }

    fn expect_token(&mut self, kind: u16) -> Result<(), Stop> {
        self.expect(Terminal::Token(kind))
    }

    fn expect_keyword(&mut self, keyword: Keyword) -> Result<(), Stop> {
        self.expect(Terminal::Keyword(keyword))
    }

    fn expect_name(&mut self) -> Result<(), Stop> {
        self.expect(Terminal::Name)
    }

    /// Shifts the next token if it is `terminal`.
    fn accept(&mut self, terminal: Terminal) -> Result<bool, Stop> {
        let found = self.at(terminal)?;
        if found {
            self.shift();
        }

        Ok(found)
    }

    fn accept_token(&mut self, kind: u16) -> Result<bool, Stop> {
        self.accept(Terminal::Token(kind))
    }

    fn accept_keyword(&mut self, keyword: Keyword) -> Result<bool, Stop> {
        self.accept(Terminal::Keyword(keyword))
    }

    /// Wraps a rule in its node.
    fn node(
        &mut self,
        kind: u16,
        body: impl FnOnce(&mut Self) -> Result<(), Stop>,
    ) -> Result<(), Stop> {
        self.enter(kind)?;
        body(self)?;
        self.leave();

        Ok(())
    }

    fn starts_atom(&mut self) -> Result<bool, Stop> {
        let starts = match self.peek()? {
            Terminal::Name => true,
            Terminal::Token(kind) => matches!(
                kind,
                tokenizer::LPAR
                    | tokenizer::LSQB
                    | tokenizer::LBRACE
                    | tokenizer::BACKQUOTE
                    | tokenizer::NUMBER
                    | tokenizer::STRING
            ),
            Terminal::Keyword(_) => false,
        };

        Ok(starts)
    }

    fn starts_expr(&mut self) -> Result<bool, Stop> {
        if matches!(
            self.peek()?,
            Terminal::Token(tokenizer::PLUS | tokenizer::MINUS | tokenizer::TILDE)
        ) {
            return Ok(true);
        }

        self.starts_atom()
    }

    fn starts_or_test(&mut self) -> Result<bool, Stop> {
        Ok(self.at_keyword(Keyword::Not)? || self.starts_expr()?)
    }

    fn starts_test(&mut self) -> Result<bool, Stop> {
        Ok(self.at_keyword(Keyword::Lambda)? || self.starts_or_test()?)
    }

    fn starts_arglist(&mut self) -> Result<bool, Stop> {
        Ok(self.at_token(tokenizer::STAR)?
            || self.at_token(tokenizer::DOUBLESTAR)?
            || self.starts_test()?)
    }

    fn starts_varargslist(&mut self) -> Result<bool, Stop> {
        let starts = match self.peek()? {
            Terminal::Name => true,
            Terminal::Token(kind) => matches!(
                kind,
                tokenizer::LPAR | tokenizer::STAR | tokenizer::DOUBLESTAR
            ),
            Terminal::Keyword(_) => false,
        };

        Ok(starts)
    }

    fn starts_subscript(&mut self) -> Result<bool, Stop> {
        Ok(self.at_token(tokenizer::DOT)?
            || self.at_token(tokenizer::COLON)?
            || self.starts_test()?)
    }

    fn starts_small_stmt(&mut self) -> Result<bool, Stop> {
        if let Terminal::Keyword(keyword) = self.peek()? {
            let starts = matches!(
                keyword,
                Keyword::Print
                    | Keyword::Del
                    | Keyword::Pass
                    | Keyword::Break
                    | Keyword::Continue
                    | Keyword::Return
                    | Keyword::Raise
                    | Keyword::Yield
                    | Keyword::Import
                    | Keyword::From
                    | Keyword::Global
                    | Keyword::Exec
                    | Keyword::Assert
            );
            if starts {
                return Ok(true);
            }
        }

        self.starts_test()
    }

    fn starts_compound_stmt(&mut self) -> Result<bool, Stop> {
        let starts = match self.peek()? {
            Terminal::Keyword(keyword) => matches!(
                keyword,
                Keyword::If
                    | Keyword::While
                    | Keyword::For
                    | Keyword::Try
                    | Keyword::With
                    | Keyword::Def
                    | Keyword::Class
            ),
            Terminal::Token(kind) => kind == tokenizer::AT,
            Terminal::Name => false,
        };

        Ok(starts)
    }

    fn starts_stmt(&mut self) -> Result<bool, Stop> {
        Ok(self.starts_compound_stmt()? || self.starts_small_stmt()?)
    }

    fn require(&mut self, starts: bool) -> Result<(), Stop> {
        if starts {
            return Ok(());
        }

        Err(self.reject())
    }

    fn file_input(&mut self) -> Result<(), Stop> {
        self.node(symbol::FILE_INPUT, |p| {
            loop {
                if p.accept_token(tokenizer::NEWLINE)? {
                    continue;
                }
                if p.accept_token(tokenizer::ENDMARKER)? {
                    return Ok(());
                }
                let starts = p.starts_stmt()?;
                p.require(starts)?;
                p.stmt()?;
            }
        })
    }

    fn single_input(&mut self) -> Result<(), Stop> {
        self.node(symbol::SINGLE_INPUT, |p| {
            if p.accept_token(tokenizer::NEWLINE)? {
                return Ok(());
            }
            if p.starts_compound_stmt()? {
                p.compound_stmt()?;
                return p.expect_token(tokenizer::NEWLINE);
            }
            let starts = p.starts_small_stmt()?;
            p.require(starts)?;

            p.simple_stmt()
        })
    }

    fn eval_input(&mut self) -> Result<(), Stop> {
        self.node(symbol::EVAL_INPUT, |p| {
            let starts = p.starts_test()?;
            p.require(starts)?;
            p.testlist()?;

            while p.accept_token(tokenizer::NEWLINE)? {}

            p.expect_token(tokenizer::ENDMARKER)
        })
    }

    fn decorator(&mut self) -> Result<(), Stop> {
        self.node(symbol::DECORATOR, |p| {
            p.shift();
            p.dotted_name()?;

            if p.accept_token(tokenizer::LPAR)? {
                if p.starts_arglist()? {
                    p.arglist()?;
                }
                p.expect_token(tokenizer::RPAR)?;
            }

            p.expect_token(tokenizer::NEWLINE)
        })
    }

    fn decorated(&mut self) -> Result<(), Stop> {
        self.node(symbol::DECORATED, |p| {
            p.node(symbol::DECORATORS, |p| {
                while p.at_token(tokenizer::AT)? {
                    p.decorator()?;
                }
                Ok(())
            })?;

            if p.at_keyword(Keyword::Class)? {
                return p.classdef();
            }
            if p.at_keyword(Keyword::Def)? {
                return p.funcdef();
            }

            Err(p.reject())
        })
    }

    fn funcdef(&mut self) -> Result<(), Stop> {
        self.node(symbol::FUNCDEF, |p| {
            p.shift();
            p.expect_name()?;

            if !p.at_token(tokenizer::LPAR)? {
                return Err(p.reject());
            }
            p.node(symbol::PARAMETERS, |p| {
                p.shift();
                if p.starts_varargslist()? {
                    p.varargslist()?;
                }
                p.expect_token(tokenizer::RPAR)
            })?;

            p.expect_token(tokenizer::COLON)?;
            p.suite()
        })
    }

    /// Parameters of a function or lambda: plain and parenthesized names
    /// with optional defaults, then `*name` and `**name`.
    fn varargslist(&mut self) -> Result<(), Stop> {
        self.node(symbol::VARARGSLIST, |p| {
            loop {
                if p.accept_token(tokenizer::STAR)? {
                    p.expect_name()?;
                    if p.accept_token(tokenizer::COMMA)? {
                        p.expect_token(tokenizer::DOUBLESTAR)?;
                        p.expect_name()?;
                    }
                    return Ok(());
                }
                if p.accept_token(tokenizer::DOUBLESTAR)? {
                    return p.expect_name();
                }

                p.fpdef()?;
                if p.accept_token(tokenizer::EQUAL)? {
                    let starts = p.starts_test()?;
                    p.require(starts)?;
                    p.test()?;
                }
                if !p.accept_token(tokenizer::COMMA)? || !p.starts_varargslist()? {
                    return Ok(());
                }
            }
        })
    }

    fn fpdef(&mut self) -> Result<(), Stop> {
        if !self.at(Terminal::Name)? && !self.at_token(tokenizer::LPAR)? {
            return Err(self.reject());
        }

        self.node(symbol::FPDEF, |p| {
            if p.accept(Terminal::Name)? {
                return Ok(());
            }
            p.shift();
            if !p.at(Terminal::Name)? && !p.at_token(tokenizer::LPAR)? {
                return Err(p.reject());
            }

            p.node(symbol::FPLIST, |p| {
                p.fpdef()?;
                while p.accept_token(tokenizer::COMMA)? {
                    if !p.at(Terminal::Name)? && !p.at_token(tokenizer::LPAR)? {
                        break;
                    }
                    p.fpdef()?;
                }
                Ok(())
            })?;

            p.expect_token(tokenizer::RPAR)
        })
    }

    fn stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::STMT, |p| {
            if p.starts_compound_stmt()? {
                p.compound_stmt()
            } else {
                p.simple_stmt()
            }
        })
    }

    fn simple_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::SIMPLE_STMT, |p| {
            p.small_stmt()?;
            while p.accept_token(tokenizer::SEMI)? {
                if !p.starts_small_stmt()? {
                    break;
                }
                p.small_stmt()?;
            }

            p.expect_token(tokenizer::NEWLINE)
        })
    }

    fn small_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::SMALL_STMT, |p| {
            let Terminal::Keyword(keyword) = p.peek()? else {
                return p.expr_stmt();
            };

            match keyword {
                Keyword::Print => p.print_stmt(),
                Keyword::Del => p.node(symbol::DEL_STMT, |p| {
                    p.shift();
                    let starts = p.starts_expr()?;
                    p.require(starts)?;
                    p.exprlist()
                }),
                Keyword::Pass => p.node(symbol::PASS_STMT, |p| {
                    p.shift();
                    Ok(())
                }),
                Keyword::Break
                | Keyword::Continue
                | Keyword::Return
                | Keyword::Raise
                | Keyword::Yield => p.flow_stmt(keyword),
                Keyword::Import | Keyword::From => p.import_stmt(),
                Keyword::Global => p.node(symbol::GLOBAL_STMT, |p| {
                    p.shift();
                    p.expect_name()?;
                    while p.accept_token(tokenizer::COMMA)? {
                        p.expect_name()?;
                    }
                    Ok(())
                }),
                Keyword::Exec => p.node(symbol::EXEC_STMT, |p| {
                    p.shift();
                    let starts = p.starts_expr()?;
                    p.require(starts)?;
                    p.expr()?;
                    if p.accept_keyword(Keyword::In)? {
                        p.required_test()?;
                        if p.accept_token(tokenizer::COMMA)? {
                            p.required_test()?;
                        }
                    }
                    Ok(())
                }),
                Keyword::Assert => p.node(symbol::ASSERT_STMT, |p| {
                    p.shift();
                    p.required_test()?;
                    if p.accept_token(tokenizer::COMMA)? {
                        p.required_test()?;
                    }
                    Ok(())
                }),
                _ => p.expr_stmt(),
            }
        })
    }

    fn required_test(&mut self) -> Result<(), Stop> {
        let starts = self.starts_test()?;
        self.require(starts)?;

        self.test()
    }

    /// A `yield` expression or a test list, as the right side of an
    /// assignment.
    fn assigned_value(&mut self) -> Result<(), Stop> {
        if self.at_keyword(Keyword::Yield)? {
            return self.yield_expr();
        }
        let starts = self.starts_test()?;
        self.require(starts)?;

        self.testlist()
    }

    fn expr_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::EXPR_STMT, |p| {
            p.testlist()?;

            let operator = match p.peek()? {
                Terminal::Token(kind) => is_augassign(kind),
                _ => false,
            };
            if operator {
                p.node(symbol::AUGASSIGN, |p| {
                    p.shift();
                    Ok(())
                })?;
                return p.assigned_value();
            }

            while p.accept_token(tokenizer::EQUAL)? {
                p.assigned_value()?;
            }

            Ok(())
        })
    }

    fn print_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::PRINT_STMT, |p| {
            p.shift();

            if p.accept_token(tokenizer::RIGHTSHIFT)? {
                p.required_test()?;
                if !p.accept_token(tokenizer::COMMA)? {
                    return Ok(());
                }
                p.required_test()?;
            } else if p.starts_test()? {
                p.test()?;
            } else {
                return Ok(());
            }

            while p.accept_token(tokenizer::COMMA)? {
                if !p.starts_test()? {
                    break;
                }
                p.test()?;
            }

            Ok(())
        })
    }

    fn flow_stmt(&mut self, keyword: Keyword) -> Result<(), Stop> {
        self.node(symbol::FLOW_STMT, |p| match keyword {
            Keyword::Break => p.node(symbol::BREAK_STMT, |p| {
                p.shift();
                Ok(())
            }),
            Keyword::Continue => p.node(symbol::CONTINUE_STMT, |p| {
                p.shift();
                Ok(())
            }),
            Keyword::Return => p.node(symbol::RETURN_STMT, |p| {
                p.shift();
                if p.starts_test()? {
                    p.testlist()?;
                }
                Ok(())
            }),
            Keyword::Raise => p.node(symbol::RAISE_STMT, |p| {
                p.shift();
                if !p.starts_test()? {
                    return Ok(());
                }
                p.test()?;
                if p.accept_token(tokenizer::COMMA)? {
                    p.required_test()?;
                    if p.accept_token(tokenizer::COMMA)? {
                        p.required_test()?;
                    }
                }
                Ok(())
            }),
            _ => p.node(symbol::YIELD_STMT, |p| p.yield_expr()),
        })
    }

    fn import_stmt(&mut self) -> Result<(), Stop> {
        let statement = self.nodes.len() as u32;
        self.node(symbol::IMPORT_STMT, |p| {
            if p.at_keyword(Keyword::Import)? {
                p.import_name()
            } else {
                p.import_from()
            }
        })?;

        self.note_future_features(statement);

        Ok(())
    }

    fn import_name(&mut self) -> Result<(), Stop> {
        self.node(symbol::IMPORT_NAME, |p| {
            p.shift();
            if !p.at(Terminal::Name)? {
                return Err(p.reject());
            }

            p.node(symbol::DOTTED_AS_NAMES, |p| {
                p.dotted_as_name()?;
                while p.accept_token(tokenizer::COMMA)? {
                    p.dotted_as_name()?;
                }
                Ok(())
            })
        })
    }

    fn dotted_as_name(&mut self) -> Result<(), Stop> {
        if !self.at(Terminal::Name)? {
            return Err(self.reject());
        }

        self.node(symbol::DOTTED_AS_NAME, |p| {
            p.dotted_name()?;
            if p.accept_keyword(Keyword::As)? {
                p.expect_name()?;
            }
            Ok(())
        })
    }

    fn dotted_name(&mut self) -> Result<(), Stop> {
        if !self.at(Terminal::Name)? {
            return Err(self.reject());
        }

        self.node(symbol::DOTTED_NAME, |p| {
            p.shift();
            while p.accept_token(tokenizer::DOT)? {
                p.expect_name()?;
            }
            Ok(())
        })
    }

    fn import_from(&mut self) -> Result<(), Stop> {
        self.node(symbol::IMPORT_FROM, |p| {
            p.shift();

            let mut dots = false;
            while p.accept_token(tokenizer::DOT)? {
                dots = true;
            }
            if !dots || p.at(Terminal::Name)? {
                p.dotted_name()?;
            }
            p.expect_keyword(Keyword::Import)?;

            if p.accept_token(tokenizer::STAR)? {
                return Ok(());
            }
            if p.accept_token(tokenizer::LPAR)? {
                p.import_as_names()?;
                return p.expect_token(tokenizer::RPAR);
            }

            p.import_as_names()
        })
    }

    fn import_as_names(&mut self) -> Result<(), Stop> {
        if !self.at(Terminal::Name)? {
            return Err(self.reject());
        }

        self.node(symbol::IMPORT_AS_NAMES, |p| {
            p.import_as_name()?;
            while p.accept_token(tokenizer::COMMA)? {
                if !p.at(Terminal::Name)? {
                    break;
                }
                p.import_as_name()?;
            }
            Ok(())
        })
    }

    fn import_as_name(&mut self) -> Result<(), Stop> {
        self.node(symbol::IMPORT_AS_NAME, |p| {
            p.shift();
            if p.accept_keyword(Keyword::As)? {
                p.expect_name()?;
            }
            Ok(())
        })
    }

    /// Records the features a completed `from ... import` names. Any module
    /// counts except a plain single name other than `__future__`, and the
    /// imported names count whether or not they are renamed.
    fn note_future_features(&mut self, statement: u32) {
        let Some(&from) = self.nodes[statement as usize].children.first() else {
            return;
        };
        let from = &self.nodes[from as usize];
        if from.kind != symbol::IMPORT_FROM || from.children.len() < 4 {
            return;
        }

        let module = &self.nodes[from.children[1] as usize];
        if module.kind == symbol::DOTTED_NAME && module.children.len() == 1 {
            let name = &self.nodes[module.children[0] as usize];
            if &self.source.text[name.start..name.end] != b"__future__" {
                return;
            }
        }

        let names = match self.nodes[from.children[3] as usize].kind {
            tokenizer::STAR => return,
            tokenizer::LPAR => from.children.get(4).copied(),
            _ => Some(from.children[3]),
        };
        let Some(names) = names else {
            return;
        };

        let mut features = 0;
        for &alias in self.nodes[names as usize].children.iter().step_by(2) {
            let Some(&name) = self.nodes[alias as usize].children.first() else {
                continue;
            };
            let name = &self.nodes[name as usize];
            if name.kind != tokenizer::NAME {
                continue;
            }
            features |= match &self.source.text[name.start..name.end] {
                b"with_statement" => CompilerFlags::FUTURE_WITH_STATEMENT,
                b"print_function" => CompilerFlags::FUTURE_PRINT_FUNCTION,
                b"unicode_literals" => CompilerFlags::FUTURE_UNICODE_LITERALS,
                _ => 0,
            };
        }

        self.features |= features;
        if features & CompilerFlags::FUTURE_PRINT_FUNCTION != 0 {
            self.print_function = true;
        }
    }

    fn compound_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::COMPOUND_STMT, |p| match p.peek()? {
            Terminal::Keyword(Keyword::If) => p.if_stmt(),
            Terminal::Keyword(Keyword::While) => p.while_stmt(),
            Terminal::Keyword(Keyword::For) => p.for_stmt(),
            Terminal::Keyword(Keyword::Try) => p.try_stmt(),
            Terminal::Keyword(Keyword::With) => p.with_stmt(),
            Terminal::Keyword(Keyword::Def) => p.funcdef(),
            Terminal::Keyword(Keyword::Class) => p.classdef(),
            _ => p.decorated(),
        })
    }

    /// The colon and block that end every clause header.
    fn block(&mut self) -> Result<(), Stop> {
        self.expect_token(tokenizer::COLON)?;

        self.suite()
    }

    /// An optional `else` clause.
    fn else_clause(&mut self) -> Result<(), Stop> {
        if self.accept_keyword(Keyword::Else)? {
            self.block()?;
        }

        Ok(())
    }

    fn if_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::IF_STMT, |p| {
            p.shift();
            p.required_test()?;
            p.block()?;

            while p.accept_keyword(Keyword::Elif)? {
                p.required_test()?;
                p.block()?;
            }

            p.else_clause()
        })
    }

    fn while_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::WHILE_STMT, |p| {
            p.shift();
            p.required_test()?;
            p.block()?;

            p.else_clause()
        })
    }

    fn for_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::FOR_STMT, |p| {
            p.shift();
            let starts = p.starts_expr()?;
            p.require(starts)?;
            p.exprlist()?;
            p.expect_keyword(Keyword::In)?;
            let starts = p.starts_test()?;
            p.require(starts)?;
            p.testlist()?;
            p.block()?;

            p.else_clause()
        })
    }

    fn try_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::TRY_STMT, |p| {
            p.shift();
            p.block()?;

            if p.accept_keyword(Keyword::Finally)? {
                return p.block();
            }
            if !p.at_keyword(Keyword::Except)? {
                return Err(p.reject());
            }

            while p.at_keyword(Keyword::Except)? {
                p.node(symbol::EXCEPT_CLAUSE, |p| {
                    p.shift();
                    if !p.starts_test()? {
                        return Ok(());
                    }
                    p.test()?;
                    if p.accept_keyword(Keyword::As)? || p.accept_token(tokenizer::COMMA)? {
                        p.required_test()?;
                    }
                    Ok(())
                })?;
                p.block()?;
            }

            p.else_clause()?;
            if p.accept_keyword(Keyword::Finally)? {
                p.block()?;
            }

            Ok(())
        })
    }

    fn with_stmt(&mut self) -> Result<(), Stop> {
        self.node(symbol::WITH_STMT, |p| {
            p.shift();
            p.with_item()?;
            while p.accept_token(tokenizer::COMMA)? {
                p.with_item()?;
            }

            p.block()
        })
    }

    fn with_item(&mut self) -> Result<(), Stop> {
        let starts = self.starts_test()?;
        self.require(starts)?;

        self.node(symbol::WITH_ITEM, |p| {
            p.test()?;
            if p.accept_keyword(Keyword::As)? {
                let starts = p.starts_expr()?;
                p.require(starts)?;
                p.expr()?;
            }
            Ok(())
        })
    }

    fn suite(&mut self) -> Result<(), Stop> {
        if !self.at_token(tokenizer::NEWLINE)? {
            let starts = self.starts_small_stmt()?;
            self.require(starts)?;
            return self.node(symbol::SUITE, |p| p.simple_stmt());
        }

        self.node(symbol::SUITE, |p| {
            p.shift();
            if !p.at_token(tokenizer::INDENT)? {
                return Err(p.reject_with(true));
            }
            p.shift();

            loop {
                let starts = p.starts_stmt()?;
                p.require(starts)?;
                p.stmt()?;
                if p.accept_token(tokenizer::DEDENT)? {
                    return Ok(());
                }
            }
        })
    }

    fn testlist_safe(&mut self) -> Result<(), Stop> {
        self.node(symbol::TESTLIST_SAFE, |p| {
            p.old_test()?;
            if !p.accept_token(tokenizer::COMMA)? {
                return Ok(());
            }

            let starts = p.starts_test()?;
            p.require(starts)?;
            p.old_test()?;
            while p.accept_token(tokenizer::COMMA)? {
                if !p.starts_test()? {
                    break;
                }
                p.old_test()?;
            }

            Ok(())
        })
    }

    fn old_test(&mut self) -> Result<(), Stop> {
        self.node(symbol::OLD_TEST, |p| {
            if !p.at_keyword(Keyword::Lambda)? {
                return p.or_test();
            }

            p.node(symbol::OLD_LAMBDEF, |p| {
                p.shift();
                if p.starts_varargslist()? {
                    p.varargslist()?;
                }
                p.expect_token(tokenizer::COLON)?;
                let starts = p.starts_test()?;
                p.require(starts)?;
                p.old_test()
            })
        })
    }

    fn test(&mut self) -> Result<(), Stop> {
        self.node(symbol::TEST, |p| {
            if p.at_keyword(Keyword::Lambda)? {
                return p.node(symbol::LAMBDEF, |p| {
                    p.shift();
                    if p.starts_varargslist()? {
                        p.varargslist()?;
                    }
                    p.expect_token(tokenizer::COLON)?;
                    p.required_test()
                });
            }

            p.or_test()?;
            if p.accept_keyword(Keyword::If)? {
                let starts = p.starts_or_test()?;
                p.require(starts)?;
                p.or_test()?;
                p.expect_keyword(Keyword::Else)?;
                p.required_test()?;
            }

            Ok(())
        })
    }

    fn or_test(&mut self) -> Result<(), Stop> {
        self.node(symbol::OR_TEST, |p| {
            p.and_test()?;
            while p.accept_keyword(Keyword::Or)? {
                let starts = p.starts_or_test()?;
                p.require(starts)?;
                p.and_test()?;
            }
            Ok(())
        })
    }

    fn and_test(&mut self) -> Result<(), Stop> {
        self.node(symbol::AND_TEST, |p| {
            p.not_test()?;
            while p.accept_keyword(Keyword::And)? {
                let starts = p.starts_or_test()?;
                p.require(starts)?;
                p.not_test()?;
            }
            Ok(())
        })
    }

    fn not_test(&mut self) -> Result<(), Stop> {
        self.node(symbol::NOT_TEST, |p| {
            if !p.accept_keyword(Keyword::Not)? {
                return p.comparison();
            }

            let starts = p.starts_or_test()?;
            p.require(starts)?;
            p.not_test()
        })
    }

    fn comparison(&mut self) -> Result<(), Stop> {
        self.node(symbol::COMPARISON, |p| {
            p.expr()?;

            loop {
                let operator = match p.peek()? {
                    Terminal::Token(kind) => matches!(
                        kind,
                        tokenizer::LESS
                            | tokenizer::GREATER
                            | tokenizer::EQEQUAL
                            | tokenizer::GREATEREQUAL
                            | tokenizer::LESSEQUAL
                            | tokenizer::NOTEQUAL
                    ),
                    Terminal::Keyword(keyword) => {
                        matches!(keyword, Keyword::In | Keyword::Not | Keyword::Is)
                    }
                    Terminal::Name => false,
                };
                if !operator {
                    return Ok(());
                }

                p.node(symbol::COMP_OP, |p| {
                    if p.accept_keyword(Keyword::Not)? {
                        return p.expect_keyword(Keyword::In);
                    }
                    if p.accept_keyword(Keyword::Is)? {
                        p.accept_keyword(Keyword::Not)?;
                        return Ok(());
                    }
                    p.shift();
                    Ok(())
                })?;

                let starts = p.starts_expr()?;
                p.require(starts)?;
                p.expr()?;
            }
        })
    }

    /// A rule of operands of `operand` separated by the operator tokens
    /// `operators`.
    fn operator_chain(
        &mut self,
        kind: u16,
        operators: &[u16],
        operand: fn(&mut Self) -> Result<(), Stop>,
    ) -> Result<(), Stop> {
        self.node(kind, |p| {
            operand(p)?;

            loop {
                let found = match p.peek()? {
                    Terminal::Token(kind) => operators.contains(&kind),
                    _ => false,
                };
                if !found {
                    return Ok(());
                }
                p.shift();

                let starts = p.starts_expr()?;
                p.require(starts)?;
                operand(p)?;
            }
        })
    }

    fn expr(&mut self) -> Result<(), Stop> {
        self.operator_chain(symbol::EXPR, &[tokenizer::VBAR], Self::xor_expr)
    }

    fn xor_expr(&mut self) -> Result<(), Stop> {
        self.operator_chain(symbol::XOR_EXPR, &[tokenizer::CIRCUMFLEX], Self::and_expr)
    }

    fn and_expr(&mut self) -> Result<(), Stop> {
        self.operator_chain(symbol::AND_EXPR, &[tokenizer::AMPER], Self::shift_expr)
    }

    fn shift_expr(&mut self) -> Result<(), Stop> {
        self.operator_chain(
            symbol::SHIFT_EXPR,
            &[tokenizer::LEFTSHIFT, tokenizer::RIGHTSHIFT],
            Self::arith_expr,
        )
    }

    fn arith_expr(&mut self) -> Result<(), Stop> {
        self.operator_chain(
            symbol::ARITH_EXPR,
            &[tokenizer::PLUS, tokenizer::MINUS],
            Self::term,
        )
    }

    fn term(&mut self) -> Result<(), Stop> {
        self.operator_chain(
            symbol::TERM,
            &[
                tokenizer::STAR,
                tokenizer::SLASH,
                tokenizer::PERCENT,
                tokenizer::DOUBLESLASH,
            ],
            Self::factor,
        )
    }

    fn factor(&mut self) -> Result<(), Stop> {
        self.node(symbol::FACTOR, |p| {
            if !matches!(
                p.peek()?,
                Terminal::Token(tokenizer::PLUS | tokenizer::MINUS | tokenizer::TILDE)
            ) {
                return p.power();
            }
            p.shift();

            let starts = p.starts_expr()?;
            p.require(starts)?;
            p.factor()
        })
    }

    fn power(&mut self) -> Result<(), Stop> {
        self.node(symbol::POWER, |p| {
            p.atom()?;

            while matches!(
                p.peek()?,
                Terminal::Token(tokenizer::LPAR | tokenizer::LSQB | tokenizer::DOT)
            ) {
                p.trailer()?;
            }

            if p.accept_token(tokenizer::DOUBLESTAR)? {
                let starts = p.starts_expr()?;
                p.require(starts)?;
                p.factor()?;
            }

            Ok(())
        })
    }

    fn atom(&mut self) -> Result<(), Stop> {
        self.node(symbol::ATOM, |p| {
            let Terminal::Token(kind) = p.peek()? else {
                p.shift();
                return Ok(());
            };
            p.shift();

            match kind {
                tokenizer::LPAR => {
                    if p.at_keyword(Keyword::Yield)? {
                        p.yield_expr()?;
                    } else if p.starts_test()? {
                        p.node(symbol::TESTLIST_COMP, |p| {
                            p.test()?;
                            p.comprehension_or_list(Self::comp_for)
                        })?;
                    }
                    p.expect_token(tokenizer::RPAR)
                }
                tokenizer::LSQB => {
                    if p.starts_test()? {
                        p.node(symbol::LISTMAKER, |p| {
                            p.test()?;
                            p.comprehension_or_list(Self::list_for)
                        })?;
                    }
                    p.expect_token(tokenizer::RSQB)
                }
                tokenizer::LBRACE => {
                    if p.starts_test()? {
                        p.dictorsetmaker()?;
                    }
                    p.expect_token(tokenizer::RBRACE)
                }
                tokenizer::BACKQUOTE => {
                    let starts = p.starts_test()?;
                    p.require(starts)?;
                    p.node(symbol::TESTLIST1, |p| {
                        p.test()?;
                        while p.accept_token(tokenizer::COMMA)? {
                            p.required_test()?;
                        }
                        Ok(())
                    })?;
                    p.expect_token(tokenizer::BACKQUOTE)
                }
                tokenizer::STRING => {
                    while p.accept_token(tokenizer::STRING)? {}
                    Ok(())
                }
                _ => Ok(()),
            }
        })
    }

    /// After the first item of a display: a comprehension, or more items
    /// separated by commas with an optional trailing comma.
    fn comprehension_or_list(
        &mut self,
        comprehension: fn(&mut Self) -> Result<(), Stop>,
    ) -> Result<(), Stop> {
        if self.at_keyword(Keyword::For)? {
            return comprehension(self);
        }

        self.more_tests()
    }

    /// Further tests after a first one, each after a comma, with an optional
    /// trailing comma.
    fn more_tests(&mut self) -> Result<(), Stop> {
        while self.accept_token(tokenizer::COMMA)? {
            if !self.starts_test()? {
                break;
            }
            self.test()?;
        }

        Ok(())
    }

    fn trailer(&mut self) -> Result<(), Stop> {
        self.node(symbol::TRAILER, |p| {
            let opener = p.peek()?;
            p.shift();

            match opener {
                Terminal::Token(tokenizer::LPAR) => {
                    if p.starts_arglist()? {
                        p.arglist()?;
                    }
                    p.expect_token(tokenizer::RPAR)
                }
                Terminal::Token(tokenizer::LSQB) => {
                    let starts = p.starts_subscript()?;
                    p.require(starts)?;
                    p.node(symbol::SUBSCRIPTLIST, |p| {
                        p.subscript()?;
                        while p.accept_token(tokenizer::COMMA)? {
                            if !p.starts_subscript()? {
                                break;
                            }
                            p.subscript()?;
                        }
                        Ok(())
                    })?;
                    p.expect_token(tokenizer::RSQB)
                }
                _ => p.expect_name(),
            }
        })
    }

    fn subscript(&mut self) -> Result<(), Stop> {
        self.node(symbol::SUBSCRIPT, |p| {
            if p.accept_token(tokenizer::DOT)? {
                p.expect_token(tokenizer::DOT)?;
                return p.expect_token(tokenizer::DOT);
            }

            if p.starts_test()? {
                p.test()?;
                if !p.at_token(tokenizer::COLON)? {
                    return Ok(());
                }
            }
            p.shift();

            if p.starts_test()? {
                p.test()?;
            }
            if p.at_token(tokenizer::COLON)? {
                p.node(symbol::SLICEOP, |p| {
                    p.shift();
                    if p.starts_test()? {
                        p.test()?;
                    }
                    Ok(())
                })?;
            }

            Ok(())
        })
    }

    fn exprlist(&mut self) -> Result<(), Stop> {
        self.node(symbol::EXPRLIST, |p| {
            p.expr()?;
            while p.accept_token(tokenizer::COMMA)? {
                if !p.starts_expr()? {
                    break;
                }
                p.expr()?;
            }
            Ok(())
        })
    }

    fn testlist(&mut self) -> Result<(), Stop> {
        self.node(symbol::TESTLIST, |p| {
            p.test()?;
            p.more_tests()
        })
    }

    fn dictorsetmaker(&mut self) -> Result<(), Stop> {
        self.node(symbol::DICTORSETMAKER, |p| {
            p.test()?;

            if !p.accept_token(tokenizer::COLON)? {
                return p.comprehension_or_list(Self::comp_for);
            }

            p.required_test()?;
            if p.at_keyword(Keyword::For)? {
                return p.comp_for();
            }
            while p.accept_token(tokenizer::COMMA)? {
                if !p.starts_test()? {
                    break;
                }
                p.test()?;
                p.expect_token(tokenizer::COLON)?;
                p.required_test()?;
            }

            Ok(())
        })
    }

    fn classdef(&mut self) -> Result<(), Stop> {
        self.node(symbol::CLASSDEF, |p| {
            p.shift();
            p.expect_name()?;

            if p.accept_token(tokenizer::LPAR)? {
                if p.starts_test()? {
                    p.testlist()?;
                }
                p.expect_token(tokenizer::RPAR)?;
            }

            p.block()
        })
    }

    /// Call arguments: positional and keyword arguments, then `*args`
    /// followed by keyword arguments, then `**kwargs`.
    fn arglist(&mut self) -> Result<(), Stop> {
        self.node(symbol::ARGLIST, |p| {
            loop {
                if p.accept_token(tokenizer::STAR)? {
                    p.required_test()?;
                    while p.accept_token(tokenizer::COMMA)? {
                        if p.accept_token(tokenizer::DOUBLESTAR)? {
                            return p.required_test();
                        }
                        let starts = p.starts_test()?;
                        p.require(starts)?;
                        p.argument()?;
                    }
                    return Ok(());
                }
                if p.accept_token(tokenizer::DOUBLESTAR)? {
                    return p.required_test();
                }

                let starts = p.starts_test()?;
                p.require(starts)?;
                p.argument()?;
                if !p.accept_token(tokenizer::COMMA)? || !p.starts_arglist()? {
                    return Ok(());
                }
            }
        })
    }

    fn argument(&mut self) -> Result<(), Stop> {
        self.node(symbol::ARGUMENT, |p| {
            p.test()?;
            if p.at_keyword(Keyword::For)? {
                return p.comp_for();
            }
            if p.accept_token(tokenizer::EQUAL)? {
                p.required_test()?;
            }
            Ok(())
        })
    }

    fn list_for(&mut self) -> Result<(), Stop> {
        self.node(symbol::LIST_FOR, |p| {
            p.shift();
            let starts = p.starts_expr()?;
            p.require(starts)?;
            p.exprlist()?;
            p.expect_keyword(Keyword::In)?;
            let starts = p.starts_test()?;
            p.require(starts)?;
            p.testlist_safe()?;

            p.list_iter()
        })
    }

    fn list_iter(&mut self) -> Result<(), Stop> {
        let for_clause = self.at_keyword(Keyword::For)?;
        if !for_clause && !self.at_keyword(Keyword::If)? {
            return Ok(());
        }

        self.node(symbol::LIST_ITER, |p| {
            if for_clause {
                return p.list_for();
            }

            p.node(symbol::LIST_IF, |p| {
                p.shift();
                let starts = p.starts_test()?;
                p.require(starts)?;
                p.old_test()?;
                p.list_iter()
            })
        })
    }

    fn comp_for(&mut self) -> Result<(), Stop> {
        self.node(symbol::COMP_FOR, |p| {
            p.shift();
            let starts = p.starts_expr()?;
            p.require(starts)?;
            p.exprlist()?;
            p.expect_keyword(Keyword::In)?;
            let starts = p.starts_or_test()?;
            p.require(starts)?;
            p.or_test()?;

            p.comp_iter()
        })
    }

    fn comp_iter(&mut self) -> Result<(), Stop> {
        let for_clause = self.at_keyword(Keyword::For)?;
        if !for_clause && !self.at_keyword(Keyword::If)? {
            return Ok(());
        }

        self.node(symbol::COMP_ITER, |p| {
            if for_clause {
                return p.comp_for();
            }

            p.node(symbol::COMP_IF, |p| {
                p.shift();
                let starts = p.starts_test()?;
                p.require(starts)?;
                p.old_test()?;
                p.comp_iter()
            })
        })
    }

    fn yield_expr(&mut self) -> Result<(), Stop> {
        self.node(symbol::YIELD_EXPR, |p| {
            p.shift();
            if p.starts_test()? {
                p.testlist()?;
            }
            Ok(())
        })
    }
}
