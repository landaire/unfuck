//! The CPython standard library modules the interpreter tests import,
//! compiled at test time from the `Lib` directory named by `PYTHON27_LIB`
//! (default: the Windows 2.7.12 `Lib` under Wine, if present).

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;

const DEFAULT_LIB: &str = "/var/mnt/build/winpy/prefix/drive_c/py2712/Lib";

/// The module list `generate_conformance.py` records.
pub fn listed_modules() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interp/stdlib_modules.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));

    text.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect()
}

/// The `Lib` directory, or `None` when none is available.
pub fn lib_directory() -> Option<PathBuf> {
    let path = match std::env::var_os("PYTHON27_LIB") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(DEFAULT_LIB),
    };

    path.join("os.py").is_file().then_some(path)
}

/// A source for the listed modules, or `None` when no `Lib` is available.
pub fn source(long_width: LongWidth) -> Option<LibSource> {
    lib_directory().map(|lib| LibSource::new(lib, listed_modules(), long_width))
}
