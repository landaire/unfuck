//! Loads what the generator recorded for one source file, parses and
//! compiles the source, and compares the result with CPython's.

use std::cell::Cell;
use std::fs;
use std::panic;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Once;

use serde::Deserialize;
use unfuck::interp::compiler::CompileContext;
use unfuck::interp::compiler::CompileError;
use unfuck::interp::compiler::CompilerFlags;
use unfuck::interp::compiler::Mode;
use unfuck::interp::compiler::ParseError;
use unfuck::interp::compiler::SyntaxError;
use unfuck::interp::compiler::SyntaxErrorKind;
use unfuck::interp::compiler::compile_ast;
use unfuck::interp::compiler::context::CompileWarning;
use unfuck::interp::compiler::context::WarningCategory;
use unfuck::interp::compiler::context::WarningRaised;
use unfuck::interp::compiler::marshal;
use unfuck::interp::compiler::parse_with_flags;
use unfuck::interp::compiler::source::CodecErrorKind;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::marshal::writer::WriteError;

use crate::marshal_diff;

const CORPUS_STACK_SIZE: usize = 256 * 1024 * 1024;
const CORPUS_THREAD: &str = "compiler-corpus";

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("{path}: {source}")]
    Json { path: PathBuf, source: serde_json::Error },
    #[error("{path}: field `{field}` has a character above U+00FF")]
    NotLatin1 { path: PathBuf, field: &'static str },
}

/// `<rel>.json` as the generator writes it.
#[derive(Debug, Deserialize)]
pub struct Record {
    pub filename: String,
    pub mode: ModeName,
    pub error: Option<ErrorRecord>,
    pub warnings: Vec<WarningRecord>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModeName {
    Exec,
    Eval,
    Single,
}

impl ModeName {
    fn mode(self) -> Mode {
        match self {
            Self::Exec => Mode::Exec,
            Self::Eval => Mode::Eval,
            Self::Single => Mode::Single,
        }
    }
}

/// An exception raised by `compile`. Text fields hold one character per
/// byte.
#[derive(Debug, Deserialize)]
pub struct ErrorRecord {
    #[serde(rename = "type")]
    pub type_name: String,
    pub msg: String,
    pub args: Option<ArgsShape>,
    pub filename: Option<String>,
    pub lineno: Option<i64>,
    pub offset: Option<i64>,
    pub text: Option<String>,
}

/// A warning `compile` issued. `filename` and `lineno` are present for
/// `PyErr_WarnExplicit` only.
#[derive(Debug, Deserialize)]
pub struct WarningRecord {
    pub category: String,
    pub message: String,
    pub filename: Option<String>,
    pub lineno: Option<i64>,
}

/// The shape of `SyntaxError.args`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgsShape {
    /// `(msg, (filename, lineno, offset, text))`.
    Location,
    /// `(msg,)`.
    Message,
    Other,
}

/// The output of one corpus run.
#[derive(Default)]
pub struct Summary {
    pub checked: usize,
    pub matched: usize,
    /// `(relative path, report)` for every file that differs or could not
    /// be checked.
    pub failures: Vec<(String, String)>,
}

impl Summary {
    pub fn report(&self, limit: usize) -> String {
        let mut text = format!("{} files checked: {} match, {} differ", self.checked, self.matched, self.failures.len());

        for (rel, report) in self.failures.iter().take(limit) {
            text.push_str(&format!("\n\n{rel}: {report}"));
        }
        if self.failures.len() > limit && limit > 0 {
            text.push_str(&format!("\n\n... and {} more", self.failures.len() - limit));
        }

        text
    }
}

/// Host state of a Linux x64 CPython with default settings: warnings are
/// recorded and never raised.
pub struct CorpusContext {
    pub warnings: Vec<CompileWarning>,
}

impl CompileContext for CorpusContext {
    fn long_width(&self) -> LongWidth {
        LongWidth::Bits64
    }

    fn warn(&mut self, warning: &CompileWarning) -> Result<(), WarningRaised> {
        self.warnings.push(warning.clone());

        Ok(())
    }

    fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>> {
        bytes.iter().map(|&byte| if byte < 0x80 { Some(u16::from(byte)) } else { None }).collect()
    }
}

/// Why the source did not compile.
enum Failure {
    Parse(ParseError),
    Compile(CompileError),
    /// `marshal.dumps` of the compiled code failed.
    Marshal(WriteError),
}

/// The comparable fields of a compile error.
#[derive(Debug, PartialEq, Eq)]
struct ErrorFields {
    type_name: String,
    args: Option<ArgsShape>,
    message: Vec<u8>,
    filename: Option<Vec<u8>>,
    lineno: Option<i64>,
    offset: Option<i64>,
    text: Option<Vec<u8>>,
}

fn latin1_bytes(value: &str, path: &Path, field: &'static str) -> Result<Vec<u8>, FixtureError> {
    value.chars().map(|char| u8::try_from(char).map_err(|_| FixtureError::NotLatin1 { path: path.to_owned(), field })).collect()
}

impl ErrorFields {
    fn from_record(record: &ErrorRecord, path: &Path) -> Result<Self, FixtureError> {
        // CodecErrorKind::Unicode does not name the subclass.
        let type_name = if record.type_name.starts_with("Unicode") { String::from("UnicodeError") } else { record.type_name.clone() };

        Ok(Self {
            type_name,
            args: record.args,
            message: latin1_bytes(&record.msg, path, "msg")?,
            filename: record.filename.as_deref().map(|value| latin1_bytes(value, path, "filename")).transpose()?,
            lineno: record.lineno,
            offset: record.offset,
            text: record.text.as_deref().map(|value| latin1_bytes(value, path, "text")).transpose()?,
        })
    }

    fn message_only(type_name: &str, args: Option<ArgsShape>, message: &str) -> Self {
        Self { type_name: type_name.to_owned(), args, message: message.as_bytes().to_vec(), filename: None, lineno: None, offset: None, text: None }
    }

    fn from_syntax_error(error: &SyntaxError, args: ArgsShape) -> Self {
        let type_name = match error.kind {
            SyntaxErrorKind::SyntaxError => "SyntaxError",
            SyntaxErrorKind::IndentationError => "IndentationError",
            SyntaxErrorKind::TabError => "TabError",
        };

        Self {
            type_name: type_name.to_owned(),
            args: Some(args),
            message: error.message.as_bytes().to_vec(),
            filename: Some(error.filename.clone()),
            lineno: Some(i64::from(error.lineno)),
            offset: error.offset.map(i64::from),
            text: error.text.clone(),
        }
    }

    fn from_failure(failure: &Failure) -> Option<Self> {
        match failure {
            Failure::Parse(ParseError::Syntax(error)) => Some(Self::from_syntax_error(error, ArgsShape::Location)),
            Failure::Parse(ParseError::Value { message }) => Some(Self::message_only("ValueError", None, message)),
            Failure::Parse(ParseError::Memory) => Some(Self::message_only("MemoryError", None, "")),
            Failure::Parse(ParseError::Codec(error)) => {
                let type_name = match &error.kind {
                    CodecErrorKind::Unicode => "UnicodeError",
                    CodecErrorKind::Lookup => "LookupError",
                    CodecErrorKind::Other(name) => name,
                };

                Some(Self::message_only(type_name, None, &error.message))
            }
            Failure::Parse(ParseError::System { message }) => Some(Self::message_only("SystemError", None, message)),
            Failure::Parse(ParseError::Unsupported { .. }) => None,
            Failure::Compile(CompileError::Syntax(error)) => Some(Self::from_syntax_error(error, ArgsShape::Location)),
            Failure::Compile(CompileError::SyntaxLocated(error)) => Some(Self::from_syntax_error(error, ArgsShape::Message)),
            Failure::Compile(CompileError::SyntaxUnlocated { message }) => Some(Self::message_only("SyntaxError", Some(ArgsShape::Message), message)),
            Failure::Compile(CompileError::System { message }) => Some(Self::message_only("SystemError", None, message)),
            Failure::Compile(CompileError::WarningRaised) => None,
            Failure::Marshal(WriteError::Unmarshallable) => Some(Self::message_only("ValueError", None, "unmarshallable object")),
            Failure::Marshal(WriteError::NestedTooDeep) => Some(Self::message_only("ValueError", None, "object too deeply nested to marshal")),
        }
    }

    fn describe(&self) -> String {
        let lossy = |bytes: &Option<Vec<u8>>| bytes.as_deref().map(|bytes| String::from_utf8_lossy(bytes).into_owned());

        format!(
            "{}(args={:?}) msg={:?} filename={:?} lineno={:?} offset={:?} text={:?}",
            self.type_name,
            self.args,
            String::from_utf8_lossy(&self.message),
            lossy(&self.filename),
            self.lineno,
            self.offset,
            lossy(&self.text)
        )
    }
}

impl std::fmt::Debug for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "parse error {error:?}"),
            Self::Compile(error) => write!(formatter, "compile error {error:?}"),
            Self::Marshal(error) => write!(formatter, "marshal error {error:?}"),
        }
    }
}

/// The comparable fields of a warning.
#[derive(Debug, PartialEq, Eq)]
struct WarningFields {
    category: String,
    message: Vec<u8>,
    location: Option<(Vec<u8>, i64)>,
}

impl WarningFields {
    fn from_record(record: &WarningRecord, path: &Path) -> Result<Self, FixtureError> {
        let location = match (&record.filename, record.lineno) {
            (Some(filename), Some(lineno)) => Some((latin1_bytes(filename, path, "warnings.filename")?, lineno)),
            _ => None,
        };

        Ok(Self { category: record.category.clone(), message: latin1_bytes(&record.message, path, "warnings.message")?, location })
    }

    fn from_warning(warning: &CompileWarning) -> Self {
        let category = match warning.category {
            WarningCategory::SyntaxWarning => "SyntaxWarning",
            WarningCategory::DeprecationWarning => "DeprecationWarning",
        };
        let location = warning.location.as_ref().map(|location| (location.filename.clone(), i64::from(location.lineno)));

        Self { category: category.to_owned(), message: warning.message.as_bytes().to_vec(), location }
    }

    fn describe(&self) -> String {
        match &self.location {
            Some((filename, lineno)) => format!("{} {:?} at {}:{lineno}", self.category, String::from_utf8_lossy(&self.message), String::from_utf8_lossy(filename)),
            None => format!("{} {:?} (no location)", self.category, String::from_utf8_lossy(&self.message)),
        }
    }
}

thread_local! {
    /// Set while the compiler runs, so the panic hook stays quiet for
    /// panics that are reported as mismatches.
    static IN_COMPILER: Cell<bool> = const { Cell::new(false) };
}

fn install_quiet_panic_hook() {
    static INSTALL: Once = Once::new();

    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !IN_COMPILER.with(Cell::get) {
                previous(info);
            }
        }));
    });
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }

    String::from("non-string panic payload")
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, FixtureError> {
    fs::read(path).map_err(|source| FixtureError::Io { path: path.to_owned(), source })
}

fn read_text(path: &Path) -> Result<String, FixtureError> {
    fs::read_to_string(path).map_err(|source| FixtureError::Io { path: path.to_owned(), source })
}

/// The relative paths in `<dir>/index.json`, restricted to the
/// comma-separated list in `CORPUS_FILTER` when it is set.
pub fn load_index(dir: &Path) -> Result<Vec<String>, FixtureError> {
    let path = dir.join("index.json");
    let text = read_text(&path)?;
    let index: Vec<String> = serde_json::from_str(&text).map_err(|source| FixtureError::Json { path, source })?;

    let Ok(filter) = std::env::var("CORPUS_FILTER") else {
        return Ok(index);
    };
    let wanted: Vec<&str> = filter.split(',').map(str::trim).filter(|entry| !entry.is_empty()).collect();

    Ok(index.into_iter().filter(|rel| wanted.contains(&rel.as_str())).collect())
}

pub fn fixture_path(dir: &Path, rel: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{rel}{suffix}"))
}

pub fn load_record(dir: &Path, rel: &str) -> Result<Record, FixtureError> {
    let path = fixture_path(dir, rel, ".json");
    let text = read_text(&path)?;

    serde_json::from_str(&text).map_err(|source| FixtureError::Json { path, source })
}

/// Parses, compiles, and marshals `source` as `compile` followed by
/// `marshal.dumps` does, catching panics.
fn compile_source(source: &[u8], filename: &[u8], mode: Mode, context: &mut CorpusContext) -> Result<Result<Vec<u8>, Failure>, String> {
    const MESSAGE_LIMIT: usize = 300;

    IN_COMPILER.with(|flag| flag.set(true));
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let parsed = parse_with_flags(source, filename, mode, CompilerFlags(0)).map_err(Failure::Parse)?;
        let code = compile_ast(&parsed.module, filename, parsed.flags, context).map_err(Failure::Compile)?;

        marshal::dump(&code).map_err(Failure::Marshal)
    }));
    IN_COMPILER.with(|flag| flag.set(false));

    result.map_err(|payload| {
        let message = panic_message(payload.as_ref());
        let shortened: String = message.chars().take(MESSAGE_LIMIT).collect();
        let ellipsis = if shortened.len() < message.len() { "..." } else { "" };

        format!("{shortened}{ellipsis}")
    })
}

/// Compiles `<source_root>/<rel>` and compares the result with the record
/// in `expected_dir`. `None` means everything matches.
pub fn check_file(source_root: &Path, expected_dir: &Path, rel: &str) -> Result<Option<String>, FixtureError> {
    let record_path = fixture_path(expected_dir, rel, ".json");
    let record = load_record(expected_dir, rel)?;
    let source = read_bytes(&source_root.join(rel))?;

    let mut context = CorpusContext { warnings: Vec::new() };
    let result = match compile_source(&source, record.filename.as_bytes(), record.mode.mode(), &mut context) {
        Ok(result) => result,
        Err(message) => return Ok(Some(format!("compiler panicked: {message}"))),
    };

    let mut reports = Vec::new();
    match (&record.error, result) {
        (None, Ok(actual)) => {
            let expected = read_bytes(&fixture_path(expected_dir, rel, ".marshal"))?;
            reports.extend(marshal_diff::describe_difference(&expected, &actual));
        }
        (None, Err(failure)) => reports.push(format!("CPython compiled the file, got {failure:?}")),
        (Some(expected), Ok(_)) => {
            let expected = ErrorFields::from_record(expected, &record_path)?;
            reports.push(format!("expected {}, the file compiled", expected.describe()));
        }
        (Some(expected), Err(failure)) => {
            let expected = ErrorFields::from_record(expected, &record_path)?;

            match ErrorFields::from_failure(&failure) {
                Some(actual) if actual == expected => {}
                Some(actual) => reports.push(format!("error differs\n  expected: {}\n  actual:   {}", expected.describe(), actual.describe())),
                None => reports.push(format!("expected {}, got {failure:?}", expected.describe())),
            }
        }
    }

    let expected_warnings = record.warnings.iter().map(|warning| WarningFields::from_record(warning, &record_path)).collect::<Result<Vec<_>, _>>()?;
    let actual_warnings: Vec<WarningFields> = context.warnings.iter().map(WarningFields::from_warning).collect();
    if expected_warnings != actual_warnings {
        let list = |warnings: &[WarningFields]| warnings.iter().map(WarningFields::describe).collect::<Vec<_>>().join("; ");
        reports.push(format!("warnings differ\n  expected: [{}]\n  actual:   [{}]", list(&expected_warnings), list(&actual_warnings)));
    }

    if reports.is_empty() {
        return Ok(None);
    }

    Ok(Some(reports.join("\n")))
}

/// Runs `work` on a thread whose stack is large enough to build and drop
/// deeply nested trees.
pub fn on_large_stack<T>(work: impl FnOnce() -> T + Send + 'static) -> T
where
    T: Send + 'static,
{
    let worker = std::thread::Builder::new().name(CORPUS_THREAD.to_owned()).stack_size(CORPUS_STACK_SIZE).spawn(work);
    let worker = match worker {
        Ok(worker) => worker,
        Err(error) => panic!("cannot spawn the corpus thread: {error}"),
    };

    match worker.join() {
        Ok(result) => result,
        Err(payload) => panic!("corpus thread panicked: {}", panic_message(payload.as_ref())),
    }
}

/// Checks every file listed in `<expected_dir>/index.json`, reading its
/// source from `source_root`.
pub fn run_corpus(source_root: &Path, expected_dir: &Path) -> Summary {
    install_quiet_panic_hook();
    let source_root = source_root.to_owned();
    let expected_dir = expected_dir.to_owned();

    on_large_stack(move || {
        let mut summary = Summary::default();
        let index = match load_index(&expected_dir) {
            Ok(index) => index,
            Err(error) => {
                summary.failures.push((String::from("index.json"), error.to_string()));
                return summary;
            }
        };

        for rel in index {
            summary.checked += 1;
            match check_file(&source_root, &expected_dir, &rel) {
                Ok(None) => summary.matched += 1,
                Ok(Some(report)) => summary.failures.push((rel, report)),
                Err(error) => summary.failures.push((rel, format!("harness error: {error}"))),
            }
        }

        summary
    })
}
