//! Source text to concrete syntax tree to AST. `descent` parses the tokens
//! into a tree with one node per grammar rule application, numbered as the
//! `symbol` module numbers them, and `cst_to_ast` builds the AST from it.
//! Failures are reported as the exceptions CPython raises for them.

mod descent;

use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::SyntaxError;
use crate::interp::compiler::SyntaxErrorKind;
use crate::interp::compiler::ast;
use crate::interp::compiler::cst_to_ast;
use crate::interp::compiler::cst_to_ast::BuildError;
use crate::interp::compiler::source::BuiltinCodecs;
use crate::interp::compiler::source::SourceCodecs;
use crate::interp::compiler::source::SourceEncoding;
use crate::interp::compiler::source::prepare_source;
use crate::interp::compiler::source::restore_encoding;
use crate::interp::compiler::tokenizer;
use crate::interp::compiler::tokenizer::Status;

use descent::Failure;
use descent::Stop;

/// The deepest nesting of nonterminals a parse may build, counting the
/// start symbol. Deeper input raises `MemoryError`.
pub(crate) const MAX_DEPTH: usize = 1500;

/// A parse failure: the exception CPython raises.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// `SyntaxError`, `IndentationError`, or `TabError`.
    #[error(transparent)]
    Syntax(#[from] SyntaxError),
    /// `ValueError`, from an invalid `\x` escape in a `str` literal.
    #[error("{message}")]
    Value { message: String },
    /// `MemoryError` with no message: the input nests deeper than
    /// `MAX_DEPTH`.
    #[error("parser stack overflow")]
    Memory,
    /// An exception other than `UnicodeError` that a source codec raised.
    #[error(transparent)]
    Codec(crate::interp::compiler::source::CodecError),
    /// `SystemError`: a tree the parser does not produce, as only the
    /// `parser` module can build.
    #[error("{message}")]
    System { message: String },
    /// A tree whose conversion CPython leaves undefined, or whose result
    /// depends on how CPython was built.
    #[error("unsupported: {feature}")]
    Unsupported { feature: String },
}

/// A parsed module and the compiler flags compilation then sees: the given
/// flags plus the `__future__` features the parser detected.
#[derive(Clone, Debug, PartialEq)]
pub struct Parsed {
    pub module: ast::Mod,
    pub flags: CompilerFlags,
}

/// A node of a concrete syntax tree. Terminals hold their token text as a
/// range of `Cst::text`; nonterminals hold children.
#[derive(Clone, Debug)]
pub(crate) struct CstNode {
    pub kind: u16,
    pub start: usize,
    pub end: usize,
    pub lineno: i32,
    pub col_offset: i32,
    pub children: Vec<u32>,
}

/// A concrete syntax tree whose nodes live in one arena, root first.
pub(crate) struct Cst {
    pub nodes: Vec<CstNode>,
    pub text: Vec<u8>,

    /// Whether every token came from the tokenizer, so literals are well
    /// formed. Trees built by the `parser` module may hold any text.
    tokenized: bool,
}

impl Cst {
    /// A tree built from outside the parser.
    pub fn new(nodes: Vec<CstNode>, text: Vec<u8>) -> Self {
        Self {
            nodes,
            text,
            tokenized: false,
        }
    }

    fn from_parser(nodes: Vec<CstNode>, text: Vec<u8>) -> Self {
        Self {
            nodes,
            text,
            tokenized: true,
        }
    }

    pub fn root(&self) -> NodeRef<'_> {
        NodeRef { cst: self, id: 0 }
    }

    pub fn is_tokenized(&self) -> bool {
        self.tokenized
    }
}

/// A node of a `Cst`.
#[derive(Clone, Copy)]
pub(crate) struct NodeRef<'a> {
    cst: &'a Cst,
    id: u32,
}

impl<'a> NodeRef<'a> {
    fn data(self) -> &'a CstNode {
        &self.cst.nodes[self.id as usize]
    }

    pub fn kind(self) -> u16 {
        self.data().kind
    }

    /// Whether this is a token. Trees from the `parser` module store a
    /// node's type as a signed 16-bit value, so negative types are tokens.
    pub fn is_terminal(self) -> bool {
        (self.kind() as i16) < tokenizer::NT_OFFSET as i16
    }

    pub fn len(self) -> usize {
        self.data().children.len()
    }

    pub fn child(self, index: usize) -> Option<NodeRef<'a>> {
        let id = *self.data().children.get(index)?;

        Some(NodeRef { cst: self.cst, id })
    }

    pub fn children(self) -> impl DoubleEndedIterator<Item = NodeRef<'a>> + ExactSizeIterator + 'a {
        let cst = self.cst;
        self.data()
            .children
            .iter()
            .map(move |&id| NodeRef { cst, id })
    }

    /// The token text, or `None` for a nonterminal.
    pub fn text(self) -> Option<&'a [u8]> {
        if !self.is_terminal() {
            return None;
        }
        let data = self.data();

        Some(&self.cst.text[data.start..data.end])
    }

    pub fn lineno(self) -> i32 {
        self.data().lineno
    }

    pub fn location(self) -> ast::Location {
        let data = self.data();

        ast::Location {
            lineno: data.lineno,
            col_offset: data.col_offset,
        }
    }
}

/// A concrete syntax tree with the encoding the source declared, if any,
/// and the given compiler flags plus the `__future__` features the parser
/// detected.
pub(crate) struct ParsedCst {
    pub cst: Cst,
    pub encoding: Option<SourceEncoding>,
    pub flags: CompilerFlags,
}

/// Parses source text into a module as `compile(source, filename, mode,
/// flags | PyCF_ONLY_AST)` does.
pub fn parse(
    source: &[u8],
    filename: &[u8],
    mode: Mode,
    flags: CompilerFlags,
) -> Result<ast::Mod, ParseError> {
    parse_with_flags(source, filename, mode, flags).map(|parsed| parsed.module)
}

/// `parse`, also returning the compiler flags after parsing.
pub fn parse_with_flags(
    source: &[u8],
    filename: &[u8],
    mode: Mode,
    flags: CompilerFlags,
) -> Result<Parsed, ParseError> {
    parse_with_codecs(source, filename, mode, flags, &mut BuiltinCodecs)
}

/// `parse_with_flags` with codecs for coding declarations beyond the
/// built-in ones.
pub fn parse_with_codecs(
    source: &[u8],
    filename: &[u8],
    mode: Mode,
    flags: CompilerFlags,
    codecs: &mut dyn SourceCodecs,
) -> Result<Parsed, ParseError> {
    let parsed = parse_cst(source, filename, mode, flags, codecs)?;
    let module = cst_to_module(
        &parsed.cst,
        parsed.encoding.as_ref(),
        filename,
        parsed.flags,
        codecs,
    )?;

    Ok(Parsed {
        module,
        flags: parsed.flags,
    })
}

/// Parses source text into a concrete syntax tree.
pub(crate) fn parse_cst(
    source: &[u8],
    filename: &[u8],
    mode: Mode,
    flags: CompilerFlags,
    codecs: &mut dyn SourceCodecs,
) -> Result<ParsedCst, ParseError> {
    // A source that cannot be decoded fails before any line is read.
    let prepared = match prepare_source(source, mode == Mode::Exec, codecs) {
        Ok(prepared) => prepared,
        Err(message) => {
            let error = SyntaxError {
                kind: SyntaxErrorKind::SyntaxError,
                message,
                filename: filename.to_vec(),
                lineno: 0,
                offset: Some(0),
                text: None,
            };
            return Err(ParseError::Syntax(error));
        }
    };

    match descent::parse(&prepared.text, mode, flags) {
        Ok(parsed) => {
            let flags = CompilerFlags(flags.0 | parsed.features);
            Ok(ParsedCst {
                cst: Cst::from_parser(parsed.nodes, prepared.text),
                encoding: prepared.encoding,
                flags,
            })
        }
        Err(failure) => Err(failure_error(
            failure,
            filename,
            prepared.encoding.as_ref(),
            codecs,
        )),
    }
}

/// The exception for a failed parse, located at the tokenizer's position.
fn failure_error(
    failure: Failure,
    filename: &[u8],
    encoding: Option<&SourceEncoding>,
    codecs: &mut dyn SourceCodecs,
) -> ParseError {
    const PLAIN: SyntaxErrorKind = SyntaxErrorKind::SyntaxError;
    const INDENTATION: SyntaxErrorKind = SyntaxErrorKind::IndentationError;

    let (kind, message) = match failure.stop {
        // A failure on the first line once the input is exhausted reads as a
        // premature end.
        _ if failure.at_eof && failure.lineno <= 1 => (PLAIN, "unexpected EOF while parsing"),
        Stop::Overflow => return ParseError::Memory,
        Stop::Syntax {
            expected_indent: true,
            ..
        } => (INDENTATION, "expected an indented block"),
        Stop::Syntax {
            token: tokenizer::INDENT,
            ..
        } => (INDENTATION, "unexpected indent"),
        Stop::Syntax {
            token: tokenizer::DEDENT,
            ..
        } => (INDENTATION, "unexpected unindent"),
        Stop::Syntax { .. } => (PLAIN, "invalid syntax"),
        Stop::Token(status) => match status {
            Status::BadToken => (PLAIN, "invalid token"),
            Status::EofInTripleQuoted => (PLAIN, "EOF while scanning triple-quoted string literal"),
            Status::EolInString => (PLAIN, "EOL while scanning string literal"),
            Status::LineContinuation => (
                PLAIN,
                "unexpected character after line continuation character",
            ),
            Status::Dedent => (
                INDENTATION,
                "unindent does not match any outer indentation level",
            ),
            Status::TooDeep => (INDENTATION, "too many levels of indentation"),
            Status::Eof => (PLAIN, "unexpected EOF while parsing"),
            Status::Ok => (PLAIN, "unknown parsing error"),
        },
    };

    // The error line is reported in the source's own encoding.
    let restored = encoding
        .and_then(|encoding| restore_encoding(encoding, &failure.line, failure.offset, codecs));
    let (text, offset) = restored.unwrap_or((failure.line, failure.offset));

    let error = SyntaxError {
        kind,
        message: message.to_owned(),
        filename: filename.to_vec(),
        lineno: failure.lineno,
        offset: Some(u32::try_from(offset).unwrap_or(u32::MAX)),
        text: Some(text),
    };

    ParseError::Syntax(error)
}

/// The module of a concrete syntax tree whose source declared `encoding`.
pub(crate) fn cst_to_module(
    cst: &Cst,
    encoding: Option<&SourceEncoding>,
    filename: &[u8],
    flags: CompilerFlags,
    codecs: &mut dyn SourceCodecs,
) -> Result<ast::Mod, ParseError> {
    let built = if flags.contains(CompilerFlags::SOURCE_IS_UTF8) {
        // Text already decoded to UTF-8 cannot declare an encoding.
        match encoding {
            Some(_) => Err(BuildError::Syntax {
                message: "encoding declaration in Unicode string".to_owned(),
                lineno: 0,
            }),
            None => cst_to_ast::build(
                cst,
                Some(&SourceEncoding::Utf8),
                flags.contains(CompilerFlags::FUTURE_UNICODE_LITERALS),
                codecs,
            ),
        }
    } else {
        cst_to_ast::build(
            cst,
            encoding,
            flags.contains(CompilerFlags::FUTURE_UNICODE_LITERALS),
            codecs,
        )
    };

    built.map_err(|error| build_error(error, filename))
}

fn build_error(error: BuildError, filename: &[u8]) -> ParseError {
    const NO_EXCEPTION: &str = "error return without exception set";

    match error {
        // CPython locates the error by reading the line back, and gives up
        // on line -1 without raising.
        BuildError::Syntax { lineno: -1, .. } => ParseError::System {
            message: NO_EXCEPTION.to_owned(),
        },
        BuildError::Syntax { message, lineno } => ParseError::Syntax(SyntaxError {
            kind: SyntaxErrorKind::SyntaxError,
            message,
            filename: filename.to_vec(),
            lineno,
            offset: None,
            text: None,
        }),
        BuildError::Value { message } => ParseError::Value { message },
        BuildError::Codec(error) => ParseError::Codec(error),
        BuildError::System { message } => ParseError::System { message },
        BuildError::NoException => ParseError::System {
            message: NO_EXCEPTION.to_owned(),
        },
        BuildError::Unsupported { feature } => ParseError::Unsupported { feature },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(source: &[u8], mode: Mode) -> String {
        let parsed = match parse_cst(
            source,
            b"<test>",
            mode,
            CompilerFlags::default(),
            &mut BuiltinCodecs,
        ) {
            Ok(parsed) => parsed,
            Err(error) => return format!("{error:?}"),
        };

        let mut out = String::new();
        let mut pending = vec![(parsed.cst.root(), false)];
        while let Some((node, closing)) = pending.pop() {
            if closing {
                out.push(')');
                continue;
            }
            if let Some(text) = node.text() {
                out.push_str(&format!(
                    "({} {:?} {})",
                    node.kind(),
                    String::from_utf8_lossy(text),
                    node.lineno()
                ));
                continue;
            }
            out.push_str(&format!("({}", node.kind()));
            pending.push((node, true));
            pending.extend(node.children().rev().map(|child| (child, false)));
        }

        out
    }

    #[test]
    fn trees_end_with_an_implied_newline() {
        assert_eq!(
            tree(b"x\n", Mode::Exec),
            "(257(267(268(269(270(327(304(305(306(307(308(310(311(312(313(314(315(316(317(318(1 \"x\" 1))))))))))))))))))(4 \"\" 1)))(4 \"\" 1)(0 \"\" 1))"
        );
        assert_eq!(tree(b"", Mode::Exec), "(257(0 \"\" 1))");
    }

    #[test]
    fn nesting_beyond_the_limit_is_a_memory_error() {
        let depth = |count: usize| format!("{}1\n", "-".repeat(count));
        assert!(
            parse_cst(
                depth(1480).as_bytes(),
                b"",
                Mode::Exec,
                CompilerFlags::default(),
                &mut BuiltinCodecs
            )
            .is_ok()
        );
        assert!(matches!(
            parse_cst(
                depth(1481).as_bytes(),
                b"",
                Mode::Exec,
                CompilerFlags::default(),
                &mut BuiltinCodecs
            ),
            Err(ParseError::Memory)
        ));
    }

    #[test]
    fn future_imports_change_how_print_parses() {
        assert!(
            tree(
                b"from a.b import print_function\nprint(x, end='')\n",
                Mode::Exec
            )
            .contains("(1 \"print\" 2)")
        );
        assert!(
            tree(
                b"from a import print_function\nprint(x, end='')\n",
                Mode::Exec
            )
            .starts_with("Syntax")
        );
    }
}
