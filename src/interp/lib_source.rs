//! A module source that compiles pure Python modules from a CPython 2.7
//! `Lib` directory with the interpreter's own compiler.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use crate::interp::compiler::CompileContext;
use crate::interp::compiler::CompileError;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::ParseError;
use crate::interp::compiler::compile_ast;
use crate::interp::compiler::context::CompileWarning;
use crate::interp::compiler::context::WarningRaised;
use crate::interp::compiler::marshal;
use crate::interp::compiler::parse_with_flags;
use crate::interp::hash::LongWidth;
use crate::interp::marshal::writer::WriteError;
use crate::interp::vm::ModuleCode;
use crate::interp::vm::ModuleSource;

#[derive(Debug, thiserror::Error)]
pub enum LibCompileError {
    #[error("{path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("{module}: parse failed: {error:?}")]
    Parse { module: String, error: ParseError },
    #[error("{module}: compile failed: {error:?}")]
    Compile { module: String, error: CompileError },
    #[error("{module}: marshal failed: {error:?}")]
    Marshal { module: String, error: WriteError },
}

/// Compiled modules shared by every clone of a `LibSource`, so each
/// module compiles once per process.
type Cache = Arc<Mutex<HashMap<String, Option<CompiledModule>>>>;

#[derive(Clone)]
struct CompiledModule {
    code: Vec<u8>,
    is_package: bool,
}

/// Finds the listed modules in `lib`. A dotted name maps to a nested path;
/// a package compiles its `__init__.py`. Code filenames are `<name>.py`.
#[derive(Clone)]
pub struct LibSource {
    lib: PathBuf,
    modules: Arc<BTreeSet<String>>,
    long_width: LongWidth,
    cache: Cache,
}

impl LibSource {
    pub fn new(lib: PathBuf, modules: BTreeSet<String>, long_width: LongWidth) -> Self {
        LibSource { lib, modules: Arc::new(modules), long_width, cache: Cache::default() }
    }

    pub fn lib(&self) -> &Path {
        &self.lib
    }

    pub fn provides(&self, name: &str) -> bool {
        self.modules.contains(name)
    }

    /// Compiles `name` from the directory, or `Ok(None)` when it is not
    /// listed or has no source file.
    pub fn compile(&self, name: &str) -> Result<Option<ModuleCode>, LibCompileError> {
        if !self.provides(name) {
            return Ok(None);
        }
        if let Some(cached) = self.cache.lock().ok().and_then(|cache| cache.get(name).cloned()) {
            return Ok(cached.map(|module| module_code(name, module)));
        }

        let relative: PathBuf = name.split('.').collect();
        let module_path = self.lib.join(&relative).with_extension("py");
        let package_path = self.lib.join(&relative).join("__init__.py");
        let (path, is_package) = if module_path.is_file() {
            (module_path, false)
        } else if package_path.is_file() {
            (package_path, true)
        } else {
            self.store(name, None);
            return Ok(None);
        };

        let source = std::fs::read(&path).map_err(|source| LibCompileError::Read { path: path.clone(), source })?;
        let filename = format!("{name}.py");
        let parsed = parse_with_flags(&source, filename.as_bytes(), Mode::Exec, CompilerFlags(0))
            .map_err(|error| LibCompileError::Parse { module: name.to_owned(), error })?;
        let mut context = LibContext { long_width: self.long_width };
        let unit = compile_ast(&parsed.module, filename.as_bytes(), parsed.flags, &mut context)
            .map_err(|error| LibCompileError::Compile { module: name.to_owned(), error })?;
        let code = marshal::dump(&unit).map_err(|error| LibCompileError::Marshal { module: name.to_owned(), error })?;

        let module = CompiledModule { code, is_package };
        self.store(name, Some(module.clone()));

        Ok(Some(module_code(name, module)))
    }

    fn store(&self, name: &str, module: Option<CompiledModule>) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(name.to_owned(), module);
        }
    }
}

fn module_code(name: &str, module: CompiledModule) -> ModuleCode {
    ModuleCode { code: module.code, is_package: module.is_package, filename: format!("{name}.py") }
}

impl ModuleSource for LibSource {
    /// A module that fails to compile is reported as absent; `compile`
    /// returns the reason.
    fn find(&self, name: &str) -> Option<ModuleCode> {
        self.compile(name).ok().flatten()
    }
}

/// Compiles as a CPython with default settings: warnings are discarded and
/// the default encoding is ASCII.
struct LibContext {
    long_width: LongWidth,
}

impl CompileContext for LibContext {
    fn long_width(&self) -> LongWidth {
        self.long_width
    }

    fn warn(&mut self, _warning: &CompileWarning) -> Result<(), WarningRaised> {
        Ok(())
    }

    fn decode_default(&self, bytes: &[u8]) -> Option<Vec<u16>> {
        bytes.iter().map(|&byte| if byte < 0x80 { Some(u16::from(byte)) } else { None }).collect()
    }
}
