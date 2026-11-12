//! Compares the compiler front end with CPython 2.7: `ast.dump(tree,
//! include_attributes=True)` of `compile(..., PyCF_ONLY_AST)`, or the
//! exception it raises. `tests/fixtures/compiler/front_cases.json` holds
//! CPython's results for hand-written sources (regenerate it with
//! `generate_front_fixtures.py`). The ignored `stdlib_corpus` test runs
//! CPython itself over every `.py` file of a standard library:
//!
//! ```text
//! PYTHON27=/path/to/python2.7 PYTHON27_LIB=/path/to/lib/python2.7 \
//!     cargo test --test compiler_front -- --ignored
//! ```

use std::fmt::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value as Json;

use unfuck::interp::compiler::CompilerFlags;
use unfuck::interp::compiler::Mode;
use unfuck::interp::compiler::ParseError;
use unfuck::interp::compiler::SyntaxErrorKind;
use unfuck::interp::compiler::ast::Alias;
use unfuck::interp::compiler::ast::Arguments;
use unfuck::interp::compiler::ast::Comprehension;
use unfuck::interp::compiler::ast::ExceptHandler;
use unfuck::interp::compiler::ast::Expr;
use unfuck::interp::compiler::ast::ExprContext;
use unfuck::interp::compiler::ast::ExprKind;
use unfuck::interp::compiler::ast::Identifier;
use unfuck::interp::compiler::ast::Keyword;
use unfuck::interp::compiler::ast::Location;
use unfuck::interp::compiler::ast::Mod;
use unfuck::interp::compiler::ast::Number;
use unfuck::interp::compiler::ast::Slice;
use unfuck::interp::compiler::ast::Stmt;
use unfuck::interp::compiler::ast::StmtKind;
use unfuck::interp::compiler::ast::StrLiteral;
use unfuck::interp::compiler::parse;
use unfuck::interp::compiler::source::CodecErrorKind;
use unfuck::interp::numbers::float_repr;

/// One field of a node as `ast.dump` formats it.
enum Field<'a> {
    Node(Box<dyn Fn(&mut String) + 'a>),
    Text(String),
}

/// `ast.dump`'s `_format` of a node: fields, then attributes when the
/// class has them.
fn node(out: &mut String, name: &str, fields: Vec<(&str, Field<'_>)>, location: Option<Location>) {
    out.push_str(name);
    out.push('(');
    let has_fields = !fields.is_empty();
    for (index, (field, value)) in fields.into_iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(field);
        out.push('=');
        match value {
            Field::Node(format) => format(out),
            Field::Text(text) => out.push_str(&text),
        }
    }
    if let Some(location) = location {
        out.push_str(if has_fields { ", " } else { " " });
        let _ = write!(out, "lineno={}, col_offset={}", location.lineno, location.col_offset);
    }
    out.push(')');
}

fn list<'a, T>(items: &'a [T], format: impl Fn(&mut String, &'a T) + 'a) -> Field<'a> {
    Field::Node(Box::new(move |out: &mut String| {
        out.push('[');
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            format(out, item);
        }
        out.push(']');
    }))
}

fn exprs(items: &[Expr]) -> Field<'_> {
    list(items, |out, item| dump_expr(out, item))
}

fn stmts(items: &[Stmt]) -> Field<'_> {
    list(items, |out, item| dump_stmt(out, item))
}

fn one(item: &Expr) -> Field<'_> {
    Field::Node(Box::new(move |out: &mut String| dump_expr(out, item)))
}

fn optional(item: &Option<Expr>) -> Field<'_> {
    match item {
        Some(item) => one(item),
        None => Field::Text("None".to_owned()),
    }
}

fn optional_box(item: &Option<Box<Expr>>) -> Field<'_> {
    match item {
        Some(item) => one(item),
        None => Field::Text("None".to_owned()),
    }
}

fn name(identifier: &Identifier) -> Field<'static> {
    Field::Text(bytes_repr(&identifier.0))
}

fn optional_name(identifier: &Option<Identifier>) -> Field<'static> {
    match identifier {
        Some(identifier) => name(identifier),
        None => Field::Text("None".to_owned()),
    }
}

fn singleton(name: &str) -> Field<'static> {
    Field::Text(format!("{name}()"))
}

fn ctx(context: ExprContext) -> Field<'static> {
    singleton(&format!("{context:?}"))
}

/// `repr(str)`.
fn bytes_repr(value: &[u8]) -> String {
    let quote = if value.contains(&b'\'') && !value.contains(&b'"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for &byte in value {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if char::from(byte) == quote => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push(quote);
    out
}

/// `repr(unicode)`; surrogate pairs print as one `\U` escape.
fn unicode_repr(value: &[u16]) -> String {
    let quote = if value.contains(&u16::from(b'\'')) && !value.contains(&u16::from(b'"')) { '"' } else { '\'' };
    let mut out = String::from("u");
    out.push(quote);
    let mut index = 0;
    while index < value.len() {
        let unit = value[index];
        index += 1;
        if (0xd800..0xdc00).contains(&unit) && value.get(index).is_some_and(|low| (0xdc00..0xe000).contains(low)) {
            let code = 0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(value[index]) - 0xdc00);
            index += 1;
            let _ = write!(out, "\\U{code:08x}");
            continue;
        }
        match unit {
            0x5c => out.push_str("\\\\"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            _ if unit == quote as u16 => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(char::from(unit as u8)),
            0..=0xff => {
                let _ = write!(out, "\\x{unit:02x}");
            }
            _ => {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out.push(quote);
    out
}

fn number_repr(number: &Number) -> String {
    match number {
        Number::Int(value) => value.to_string(),
        Number::Long(value) => format!("{value}L"),
        Number::Float(value) => float_repr(*value),
        Number::Complex { real, imag } => {
            let mut imaginary = float_repr(*imag);
            if imaginary.ends_with(".0") {
                imaginary.truncate(imaginary.len() - 2);
            }
            if *real == 0.0 && real.is_sign_positive() {
                return format!("{imaginary}j");
            }
            let mut real_text = float_repr(*real);
            if real_text.ends_with(".0") {
                real_text.truncate(real_text.len() - 2);
            }
            let sign = if imaginary.starts_with('-') { "" } else { "+" };
            format!("({real_text}{sign}{imaginary}j)")
        }
    }
}

fn dump_slice(out: &mut String, slice: &Slice) {
    match slice {
        Slice::Ellipsis => node(out, "Ellipsis", vec![], None),
        Slice::Slice { lower, upper, step } => node(out, "Slice", vec![("lower", optional(lower)), ("upper", optional(upper)), ("step", optional(step))], None),
        Slice::ExtSlice { dims } => node(out, "ExtSlice", vec![("dims", list(dims, dump_slice))], None),
        Slice::Index { value } => node(out, "Index", vec![("value", one(value))], None),
    }
}

fn comprehensions(items: &[Comprehension]) -> Field<'_> {
    list(items, |out, item| node(out, "comprehension", vec![("target", one(&item.target)), ("iter", one(&item.iter)), ("ifs", exprs(&item.ifs))], None))
}

fn arguments(args: &Arguments) -> Field<'_> {
    Field::Node(Box::new(move |out: &mut String| {
        node(
            out,
            "arguments",
            vec![("args", exprs(&args.args)), ("vararg", optional_name(&args.vararg)), ("kwarg", optional_name(&args.kwarg)), ("defaults", exprs(&args.defaults))],
            None,
        )
    }))
}

fn dump_expr(out: &mut String, e: &Expr) {
    let at = Some(e.location);
    match &e.kind {
        ExprKind::BoolOp { op, values } => node(out, "BoolOp", vec![("op", singleton(&format!("{op:?}"))), ("values", exprs(values))], at),
        ExprKind::BinOp { left, op, right } => node(out, "BinOp", vec![("left", one(left)), ("op", singleton(&format!("{op:?}"))), ("right", one(right))], at),
        ExprKind::UnaryOp { op, operand } => node(out, "UnaryOp", vec![("op", singleton(&format!("{op:?}"))), ("operand", one(operand))], at),
        ExprKind::Lambda { args, body } => node(out, "Lambda", vec![("args", arguments(args)), ("body", one(body))], at),
        ExprKind::IfExp { test, body, orelse } => node(out, "IfExp", vec![("test", one(test)), ("body", one(body)), ("orelse", one(orelse))], at),
        ExprKind::Dict { keys, values } => node(out, "Dict", vec![("keys", exprs(keys)), ("values", exprs(values))], at),
        ExprKind::Set { elts } => node(out, "Set", vec![("elts", exprs(elts))], at),
        ExprKind::ListComp { elt, generators } => node(out, "ListComp", vec![("elt", one(elt)), ("generators", comprehensions(generators))], at),
        ExprKind::SetComp { elt, generators } => node(out, "SetComp", vec![("elt", one(elt)), ("generators", comprehensions(generators))], at),
        ExprKind::DictComp { key, value, generators } => {
            node(out, "DictComp", vec![("key", one(key)), ("value", one(value)), ("generators", comprehensions(generators))], at)
        }
        ExprKind::GeneratorExp { elt, generators } => node(out, "GeneratorExp", vec![("elt", one(elt)), ("generators", comprehensions(generators))], at),
        ExprKind::Yield { value } => node(out, "Yield", vec![("value", optional_box(value))], at),
        ExprKind::Compare { left, ops, comparators } => node(
            out,
            "Compare",
            vec![("left", one(left)), ("ops", list(ops, |out, op| out.push_str(&format!("{op:?}()")))), ("comparators", exprs(comparators))],
            at,
        ),
        ExprKind::Call { func, args, keywords, starargs, kwargs } => node(
            out,
            "Call",
            vec![
                ("func", one(func)),
                ("args", exprs(args)),
                ("keywords", list(keywords, |out, keyword: &Keyword| node(out, "keyword", vec![("arg", name(&keyword.arg)), ("value", one(&keyword.value))], None))),
                ("starargs", optional_box(starargs)),
                ("kwargs", optional_box(kwargs)),
            ],
            at,
        ),
        ExprKind::Repr { value } => node(out, "Repr", vec![("value", one(value))], at),
        ExprKind::Num { n } => node(out, "Num", vec![("n", Field::Text(number_repr(n)))], at),
        ExprKind::Str { s } => {
            let text = match s {
                StrLiteral::Bytes { value, .. } => bytes_repr(value),
                StrLiteral::Unicode(value) => unicode_repr(value),
            };
            node(out, "Str", vec![("s", Field::Text(text))], at)
        }
        ExprKind::Attribute { value, attr, ctx: context } => node(out, "Attribute", vec![("value", one(value)), ("attr", name(attr)), ("ctx", ctx(*context))], at),
        ExprKind::Subscript { value, slice, ctx: context } => node(
            out,
            "Subscript",
            vec![("value", one(value)), ("slice", Field::Node(Box::new(move |out: &mut String| dump_slice(out, slice)))), ("ctx", ctx(*context))],
            at,
        ),
        ExprKind::Name { id, ctx: context } => node(out, "Name", vec![("id", name(id)), ("ctx", ctx(*context))], at),
        ExprKind::List { elts, ctx: context } => node(out, "List", vec![("elts", exprs(elts)), ("ctx", ctx(*context))], at),
        ExprKind::Tuple { elts, ctx: context } => node(out, "Tuple", vec![("elts", exprs(elts)), ("ctx", ctx(*context))], at),
    }
}

fn dump_stmt(out: &mut String, s: &Stmt) {
    let at = Some(s.location);
    match &s.kind {
        StmtKind::FunctionDef { name: function, args, body, decorator_list } => node(
            out,
            "FunctionDef",
            vec![("name", name(function)), ("args", arguments(args)), ("body", stmts(body)), ("decorator_list", exprs(decorator_list))],
            at,
        ),
        StmtKind::ClassDef { name: class, bases, body, decorator_list } => node(
            out,
            "ClassDef",
            vec![("name", name(class)), ("bases", exprs(bases)), ("body", stmts(body)), ("decorator_list", exprs(decorator_list))],
            at,
        ),
        StmtKind::Return { value } => node(out, "Return", vec![("value", optional(value))], at),
        StmtKind::Delete { targets } => node(out, "Delete", vec![("targets", exprs(targets))], at),
        StmtKind::Assign { targets, value } => node(out, "Assign", vec![("targets", exprs(targets)), ("value", one(value))], at),
        StmtKind::AugAssign { target, op, value } => node(out, "AugAssign", vec![("target", one(target)), ("op", singleton(&format!("{op:?}"))), ("value", one(value))], at),
        StmtKind::Print { dest, values, nl } => node(
            out,
            "Print",
            vec![("dest", optional(dest)), ("values", exprs(values)), ("nl", Field::Text(if *nl { "True" } else { "False" }.to_owned()))],
            at,
        ),
        StmtKind::For { target, iter, body, orelse } => {
            node(out, "For", vec![("target", one(target)), ("iter", one(iter)), ("body", stmts(body)), ("orelse", stmts(orelse))], at)
        }
        StmtKind::While { test, body, orelse } => node(out, "While", vec![("test", one(test)), ("body", stmts(body)), ("orelse", stmts(orelse))], at),
        StmtKind::If { test, body, orelse } => node(out, "If", vec![("test", one(test)), ("body", stmts(body)), ("orelse", stmts(orelse))], at),
        StmtKind::With { context_expr, optional_vars, body } => {
            node(out, "With", vec![("context_expr", one(context_expr)), ("optional_vars", optional(optional_vars)), ("body", stmts(body))], at)
        }
        StmtKind::Raise { type_, inst, tback } => node(out, "Raise", vec![("type", optional(type_)), ("inst", optional(inst)), ("tback", optional(tback))], at),
        StmtKind::TryExcept { body, handlers, orelse } => node(
            out,
            "TryExcept",
            vec![
                ("body", stmts(body)),
                (
                    "handlers",
                    list(handlers, |out, handler: &ExceptHandler| {
                        node(
                            out,
                            "ExceptHandler",
                            vec![("type", optional(&handler.type_)), ("name", optional(&handler.name)), ("body", stmts(&handler.body))],
                            Some(handler.location),
                        )
                    }),
                ),
                ("orelse", stmts(orelse)),
            ],
            at,
        ),
        StmtKind::TryFinally { body, finalbody } => node(out, "TryFinally", vec![("body", stmts(body)), ("finalbody", stmts(finalbody))], at),
        StmtKind::Assert { test, msg } => node(out, "Assert", vec![("test", one(test)), ("msg", optional(msg))], at),
        StmtKind::Import { names } => node(out, "Import", vec![("names", aliases(names))], at),
        StmtKind::ImportFrom { module, names, level } => node(
            out,
            "ImportFrom",
            vec![("module", optional_name(module)), ("names", aliases(names)), ("level", Field::Text(level.map_or("None".to_owned(), |level| level.to_string())))],
            at,
        ),
        StmtKind::Exec { body, globals, locals } => node(out, "Exec", vec![("body", one(body)), ("globals", optional(globals)), ("locals", optional(locals))], at),
        StmtKind::Global { names } => node(out, "Global", vec![("names", list(names, |out, item| out.push_str(&bytes_repr(&item.0))))], at),
        StmtKind::Expr { value } => node(out, "Expr", vec![("value", one(value))], at),
        StmtKind::Pass => node(out, "Pass", vec![], at),
        StmtKind::Break => node(out, "Break", vec![], at),
        StmtKind::Continue => node(out, "Continue", vec![], at),
    }
}

fn aliases(names: &[Alias]) -> Field<'_> {
    list(names, |out, alias| node(out, "alias", vec![("name", name(&alias.name)), ("asname", optional_name(&alias.asname))], None))
}

fn dump(module: &Mod) -> String {
    let mut out = String::new();
    match module {
        Mod::Module { body } => node(&mut out, "Module", vec![("body", stmts(body))], None),
        Mod::Interactive { body } => node(&mut out, "Interactive", vec![("body", stmts(body))], None),
        Mod::Expression { body } => node(&mut out, "Expression", vec![("body", one(body))], None),
        Mod::Suite { body } => node(&mut out, "Suite", vec![("body", stmts(body))], None),
    }
    out
}

fn latin1(text: &str) -> Vec<u8> {
    text.chars().map(|ch| ch as u32 as u8).collect()
}

/// Our result in the shape `ast_dump.py` prints.
fn describe(source: &[u8], mode: Mode, flags: u32) -> Json {
    match parse(source, b"<fixture>", mode, CompilerFlags(flags)) {
        Ok(module) => serde_json::json!({ "dump": dump(&module) }),
        Err(ParseError::Syntax(error)) => {
            let kind = match error.kind {
                SyntaxErrorKind::SyntaxError => "SyntaxError",
                SyntaxErrorKind::IndentationError => "IndentationError",
                SyntaxErrorKind::TabError => "TabError",
            };
            let text: Option<String> = error.text.map(|text| text.iter().map(|&byte| char::from(byte)).collect());
            serde_json::json!({ "error": kind, "message": error.message, "lineno": error.lineno, "offset": error.offset, "text": text })
        }
        Err(ParseError::Value { message }) => serde_json::json!({ "error": "ValueError", "message": message }),
        Err(ParseError::Memory) => serde_json::json!({ "error": "MemoryError", "message": "" }),
        Err(ParseError::Codec(error)) => {
            let kind = match &error.kind {
                CodecErrorKind::Unicode => "UnicodeError".to_owned(),
                CodecErrorKind::Lookup => "LookupError".to_owned(),
                CodecErrorKind::Other(name) => name.clone(),
            };
            serde_json::json!({ "error": kind, "message": error.message })
        }
        Err(ParseError::System { message }) => serde_json::json!({ "error": "SystemError", "message": message }),
        Err(ParseError::Unsupported { feature }) => serde_json::json!({ "error": "Unsupported", "message": feature }),
    }
}

fn fixture_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compiler")
}

#[test]
fn front_cases_match_cpython() {
    let text = std::fs::read_to_string(fixture_directory().join("front_cases.json")).expect("front_cases.json is readable");
    let cases: Vec<Json> = serde_json::from_str(&text).expect("front_cases.json is valid JSON");

    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap_or_default();
        let source = latin1(case["source"].as_str().unwrap_or_default());
        let mode = match case["mode"].as_str() {
            Some("eval") => Mode::Eval,
            Some("single") => Mode::Single,
            _ => Mode::Exec,
        };
        let flags = case["flags"].as_u64().unwrap_or_default() as u32;

        let ours = describe(&source, mode, flags);
        let expected = narrow_result(case["result"].clone());
        if ours != expected {
            failures.push(format!("{name}:\n  expected {expected}\n  actual   {ours}"));
        }
    }

    assert!(failures.is_empty(), "{} of {} cases differ:\n{}", failures.len(), cases.len(), failures.join("\n"));
}

fn python_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "py") {
                files.push(path);
            }
        }
    }
}

/// Rewrites the escaped surrogate pairs in a `repr` that a wide (UCS4)
/// CPython printed into the `\U` escapes of a narrow build. The front end
/// keeps unicode as UTF-16, as narrow Windows builds do, so `u'\ud834\udd20'`
/// and `u'\U0001d120'` are the same string to it.
fn narrow_repr(text: &str) -> String {
    let surrogate = |text: &str, range: std::ops::RangeInclusive<u32>| {
        let digits = text.strip_prefix("\\u")?.get(..4)?;
        u32::from_str_radix(digits, 16).ok().filter(|unit| range.contains(unit))
    };

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find('\\') {
        out.push_str(&rest[..position]);
        rest = &rest[position..];
        if let (Some(high), Some(low)) = (surrogate(rest, 0xd800..=0xdbff), rest.get(6..).and_then(|tail| surrogate(tail, 0xdc00..=0xdfff))) {
            let code = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
            out.push_str(&format!("\\U{code:08x}"));
            rest = &rest[12..];
            continue;
        }
        let escape_length = rest[1..].chars().next().map_or(1, |next| 1 + next.len_utf8());
        out.push_str(&rest[..escape_length]);
        rest = &rest[escape_length..];
    }
    out.push_str(rest);

    out
}

/// Applies `narrow_repr` to an `ast_dump.py` result.
fn narrow_result(mut result: Json) -> Json {
    if let Some(dump) = result.get_mut("dump") {
        if let Some(text) = dump.as_str() {
            *dump = Json::String(narrow_repr(text));
        }
    }

    result
}

/// The neighborhood of the first difference between two results.
fn first_difference(expected: &str, actual: &str) -> String {
    let at = expected.bytes().zip(actual.bytes()).position(|(left, right)| left != right).unwrap_or(expected.len().min(actual.len()));
    let window = |text: &str| text.get(at.saturating_sub(80)..(at + 80).min(text.len())).unwrap_or_default().to_owned();

    format!("  expected ...{}...\n  actual   ...{}...", window(expected), window(actual))
}

#[test]
#[ignore = "needs PYTHON27 and PYTHON27_LIB"]
fn stdlib_corpus() {
    let python = std::env::var("PYTHON27").expect("PYTHON27 names a CPython 2.7 binary");
    let library = std::env::var("PYTHON27_LIB").expect("PYTHON27_LIB names a CPython 2.7 Lib directory");

    let mut files = Vec::new();
    python_files(Path::new(&library), &mut files);
    files.sort();

    let script = fixture_directory().join("ast_dump.py");
    let mut failures = Vec::new();
    let mut compared = 0;
    for batch in files.chunks(100) {
        let output = Command::new(&python).env_remove("LD_LIBRARY_PATH").arg(&script).args(batch).output().expect("CPython runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let mut expected: Json = serde_json::from_str(line).expect("ast_dump.py prints JSON");
            let path = expected["path"].as_str().unwrap_or_default().to_owned();
            if let Some(object) = expected.as_object_mut() {
                object.remove("path");
            }
            let expected = narrow_result(expected);

            let source = std::fs::read(&path).expect("corpus file is readable");
            let ours = describe(&source, Mode::Exec, 0);
            compared += 1;
            if ours != expected {
                failures.push(format!("{path}\n{}", first_difference(&expected.to_string(), &ours.to_string())));
            }
        }
    }

    for failure in failures.iter().take(10) {
        eprintln!("differs: {failure}");
    }
    assert_eq!(compared, files.len(), "CPython reported on every file");
    assert!(failures.is_empty(), "{} of {} files differ", failures.len(), files.len());
}
