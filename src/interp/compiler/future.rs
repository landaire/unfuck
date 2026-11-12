//! `from __future__ import ...` statements at the top of a module.

use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::SyntaxError;
use crate::interp::compiler::SyntaxErrorKind;
use crate::interp::compiler::ast;
use crate::interp::compiler::context::CompileError;

/// The features a module enables with `from __future__` imports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutureFeatures {
    /// `CompilerFlags::FUTURE_*` bits.
    pub features: u32,
    /// The line of the last `from __future__` import in the prologue.
    pub last_import_line: Option<i32>,
}

impl FutureFeatures {
    /// Scans the leading statements of a module. Future imports may follow
    /// one docstring. A late one that shares a line with the statement that
    /// ended the prologue (joined by semicolons) is rejected here; on later
    /// lines the compiler rejects it.
    pub fn from_ast(module: &ast::Mod, filename: &[u8]) -> Result<Self, CompileError> {
        const LATE_IMPORT: &str = "from __future__ imports must occur at the beginning of the file";

        let mut future = Self { features: 0, last_import_line: None };

        let body = match module {
            ast::Mod::Module { body } | ast::Mod::Interactive { body } => body,
            ast::Mod::Expression { .. } | ast::Mod::Suite { .. } => return Ok(future),
        };

        let mut prologue = Prologue::Open;
        let mut previous_line = 0;
        for statement in body {
            let line = statement.location.lineno;
            let on_new_line = line > previous_line;
            previous_line = line;
            if prologue == Prologue::Closed && on_new_line {
                break;
            }

            match &statement.kind {
                ast::StmtKind::ImportFrom { module: Some(module), names, .. } if module.0 == b"__future__" => {
                    if prologue == Prologue::Closed {
                        return Err(syntax_located(LATE_IMPORT.to_owned(), filename, line));
                    }

                    for alias in names {
                        future.features |= feature_flag(c_str(&alias.name.0)).map_err(|message| syntax_located(message, filename, line))?;
                    }
                    future.last_import_line = Some(line);
                }
                ast::StmtKind::Expr { value: ast::Expr { kind: ast::ExprKind::Str { .. }, .. } } if prologue == Prologue::Open => prologue = Prologue::Documented,
                _ => prologue = Prologue::Closed,
            }
        }

        Ok(future)
    }
}

/// How far the scan of a module's leading statements has come.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prologue {
    /// A docstring may still come.
    Open,
    /// The docstring has been seen; only future imports may follow.
    Documented,
    /// Some other statement ended the prologue.
    Closed,
}

/// The compiler flag a feature name enables: 0 for features that are always
/// on, and the SyntaxError message for names that are not features.
fn feature_flag(name: &[u8]) -> Result<u32, String> {
    match name {
        b"nested_scopes" | b"generators" => Ok(0),
        b"division" => Ok(CompilerFlags::FUTURE_DIVISION),
        b"absolute_import" => Ok(CompilerFlags::FUTURE_ABSOLUTE_IMPORT),
        b"with_statement" => Ok(CompilerFlags::FUTURE_WITH_STATEMENT),
        b"print_function" => Ok(CompilerFlags::FUTURE_PRINT_FUNCTION),
        b"unicode_literals" => Ok(CompilerFlags::FUTURE_UNICODE_LITERALS),
        b"braces" => Err("not a chance".to_owned()),
        _ => {
            let mut message = b"future feature ".to_vec();
            message.extend_from_slice(truncate(name, 100));
            message.extend_from_slice(b" is not defined");

            Err(String::from_utf8_lossy(&message).into_owned())
        }
    }
}

/// A SyntaxError with a file and line but no column or source text.
pub(super) fn syntax_located(message: String, filename: &[u8], lineno: i32) -> CompileError {
    CompileError::SyntaxLocated(SyntaxError {
        kind: SyntaxErrorKind::SyntaxError,
        message,
        filename: filename.to_vec(),
        lineno,
        offset: None,
        text: None,
    })
}

/// The bytes before the first NUL, which is where names stop when they are
/// compared or quoted in messages.
pub(super) fn c_str(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

/// At most the first `limit` bytes, as messages quote overlong names.
pub(super) fn truncate(bytes: &[u8], limit: usize) -> &[u8] {
    &bytes[..bytes.len().min(limit)]
}

/// Expected values come from CPython 2.7.18: `compile(src, '<t>', 'exec')`
/// gives the error's `args` and `lineno`, or `co_flags & 0x3e000` on
/// success. Errors raised here have `args == (msg,)`; a late import on a
/// later line is instead reported by the compiler, with a location tuple.
#[cfg(test)]
mod tests {
    use super::*;

    fn location(line: i32) -> ast::Location {
        ast::Location { lineno: line, col_offset: 0 }
    }

    fn stmt(line: i32, kind: ast::StmtKind) -> ast::Stmt {
        ast::Stmt { kind, location: location(line) }
    }

    fn import_from(line: i32, module: &str, names: &[&str]) -> ast::Stmt {
        let names = names.iter().map(|name| ast::Alias { name: ast::Identifier(name.as_bytes().to_vec()), asname: None }).collect();

        stmt(line, ast::StmtKind::ImportFrom { module: Some(ast::Identifier(module.as_bytes().to_vec())), names, level: Some(0) })
    }

    fn import_os(line: i32) -> ast::Stmt {
        let names = vec![ast::Alias { name: ast::Identifier(b"os".to_vec()), asname: None }];

        stmt(line, ast::StmtKind::Import { names })
    }

    fn docstring(line: i32) -> ast::Stmt {
        let value = ast::Expr { kind: ast::ExprKind::Str { s: ast::StrLiteral::Bytes { value: b"doc".to_vec(), interned: false } }, location: location(line) };

        stmt(line, ast::StmtKind::Expr { value })
    }

    fn error(message: &str, lineno: i32) -> CompileError {
        CompileError::SyntaxLocated(SyntaxError {
            kind: SyntaxErrorKind::SyntaxError,
            message: message.to_owned(),
            filename: b"<t>".to_vec(),
            lineno,
            offset: None,
            text: None,
        })
    }

    fn features(body: Vec<ast::Stmt>) -> Result<FutureFeatures, CompileError> {
        FutureFeatures::from_ast(&ast::Mod::Module { body }, b"<t>")
    }

    // "doc"
    // from __future__ import division, print_function
    // from __future__ import nested_scopes, generators, absolute_import, with_statement, unicode_literals
    // x = 1
    #[test]
    fn every_feature_after_docstring() {
        let body = vec![
            docstring(1),
            import_from(2, "__future__", &["division", "print_function"]),
            import_from(3, "__future__", &["nested_scopes", "generators", "absolute_import", "with_statement", "unicode_literals"]),
            import_os(4),
        ];

        assert_eq!(features(body), Ok(FutureFeatures { features: 0x3e000, last_import_line: Some(3) }));
    }

    // from __future__ import braces
    #[test]
    fn braces() {
        assert_eq!(features(vec![import_from(1, "__future__", &["braces"])]), Err(error("not a chance", 1)));
    }

    // from __future__ import nested_scopes, spamspam...  ('spam' * 30)
    #[test]
    fn unknown_feature_name_is_truncated() {
        let name = "spam".repeat(30);
        let message = format!("future feature {} is not defined", "spam".repeat(25));

        assert_eq!(features(vec![import_from(1, "__future__", &["nested_scopes", &name])]), Err(error(&message, 1)));
    }

    // import os; from __future__ import division
    #[test]
    fn late_import_on_the_same_line() {
        let body = vec![import_os(1), import_from(1, "__future__", &["division"])];

        assert_eq!(features(body), Err(error("from __future__ imports must occur at the beginning of the file", 1)));
    }

    // from __future__ import division; import os; from __future__ import generators
    #[test]
    fn late_import_after_valid_one_on_the_same_line() {
        let body = vec![import_from(1, "__future__", &["division"]), import_os(1), import_from(1, "__future__", &["generators"])];

        assert_eq!(features(body), Err(error("from __future__ imports must occur at the beginning of the file", 1)));
    }

    // import os
    // from __future__ import division
    #[test]
    fn late_import_on_a_later_line_is_left_to_the_compiler() {
        let body = vec![import_os(1), import_from(2, "__future__", &["division"])];

        assert_eq!(features(body), Ok(FutureFeatures { features: 0, last_import_line: None }));
    }

    // "a"
    // "b"
    // from __future__ import division
    #[test]
    fn only_one_docstring_is_skipped() {
        let body = vec![docstring(1), docstring(2), import_from(3, "__future__", &["division"])];

        assert_eq!(features(body), Ok(FutureFeatures { features: 0, last_import_line: None }));
    }

    #[test]
    fn expression_mode_has_no_features() {
        let body = ast::Expr { kind: ast::ExprKind::Num { n: ast::Number::Int(1) }, location: location(1) };

        assert_eq!(FutureFeatures::from_ast(&ast::Mod::Expression { body: Box::new(body) }, b"<t>"), Ok(FutureFeatures { features: 0, last_import_line: None }));
    }
}
