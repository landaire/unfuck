//! Runs scripts under the Windows CPython 2.7.12 oracle for differential
//! tests, and loads a driver module next to the standard library in the
//! interpreter.

use std::collections::BTreeSet;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use serde_json::Value as Json;

use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::hash::LongWidth;
use unfuck::interp::lib_source::LibSource;

const DEFAULT_ORACLE: &str = "/var/mnt/build/winpy/winpy2712.sh";

/// Parallel oracle processes and interpreter threads.
pub const WORKERS: usize = 4;

/// The oracle launcher (`CPYTHON_ORACLE`), if present.
pub fn oracle() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("CPYTHON_ORACLE").unwrap_or_else(|| DEFAULT_ORACLE.into()));

    path.is_file().then_some(path)
}

pub fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn windows_path(path: &Path) -> String {
    format!("Z:{}", path.display()).replace('/', "\\")
}

/// Runs `script mode file start` over `inputs` in one oracle process,
/// restarting after a crash. The script writes one JSON line per input
/// line from `start` on. A crashed input yields `None`.
fn run_chunk(oracle: &Path, script: &Path, mode: &str, inputs: &[String], scratch: &Path) -> Vec<Option<Json>> {
    std::fs::write(scratch, inputs.iter().map(|line| format!("{line}\n")).collect::<String>()).expect("scratch file written");
    let mut results = Vec::with_capacity(inputs.len());
    while results.len() < inputs.len() {
        let start = results.len();
        let mut child = Command::new(oracle)
            .arg(windows_path(script))
            .arg(mode)
            .arg(windows_path(scratch))
            .arg(start.to_string())
            .env("WINEDLLOVERRIDES", "winedbg.exe=d")
            .env_remove("LD_LIBRARY_PATH")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("oracle starts");
        let stdout = child.stdout.take().expect("oracle stdout");
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            let Ok(parsed) = serde_json::from_str::<Json>(line.trim_end()) else {
                break;
            };
            results.push(Some(parsed));
            if results.len() == inputs.len() {
                break;
            }
        }
        let _ = child.wait();
        if results.len() < inputs.len() {
            results.push(None);
        }
    }

    results
}

/// Runs the oracle over `inputs` in parallel chunks, keeping their order.
pub fn run(oracle: &Path, script: &Path, mode: &str, inputs: &[String], scratch: &Path) -> Vec<Option<Json>> {
    let chunk = inputs.len().div_ceil(WORKERS).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = inputs
            .chunks(chunk)
            .enumerate()
            .map(|(index, inputs)| {
                let scratch = scratch.join(format!("{mode}-{index}.jsonl"));
                scope.spawn(move || run_chunk(oracle, script, mode, inputs, &scratch))
            })
            .collect();
        handles.into_iter().flat_map(|handle| handle.join().expect("oracle thread completes")).collect()
    })
}

/// A driver module from a fixture directory, then the CPython standard
/// library.
pub struct DriverSource {
    driver: LibSource,
    stdlib: LibSource,
}

impl DriverSource {
    pub fn new(directory: &Path, module: &str, stdlib: LibSource) -> Self {
        Self { driver: LibSource::new(directory.to_path_buf(), BTreeSet::from([module.to_owned()]), LongWidth::Bits32), stdlib }
    }
}

impl ModuleSource for DriverSource {
    fn find(&self, name: &str) -> Option<ModuleCode> {
        if let Some(code) = self.driver.compile(name).expect("driver module compiles") {
            return Some(code);
        }

        self.stdlib.find(name)
    }
}

/// Splits `work` into chunks for interpreter threads, each with a large
/// stack, and gathers what each returns.
pub fn in_threads<T, R>(work: Vec<T>, run: impl Fn(Vec<T>) -> Vec<R> + Send + Sync + Clone + 'static) -> Vec<R>
where
    T: Send + 'static,
    R: Send + 'static,
{
    const STACK_SIZE: usize = 256 * 1024 * 1024;

    let chunk = work.len().div_ceil(WORKERS).max(1);
    let mut chunks = Vec::new();
    let mut work = work.into_iter().peekable();
    while work.peek().is_some() {
        chunks.push(work.by_ref().take(chunk).collect::<Vec<_>>());
    }

    let handles: Vec<_> = chunks
        .into_iter()
        .map(|chunk| {
            let run = run.clone();
            std::thread::Builder::new().stack_size(STACK_SIZE).spawn(move || run(chunk)).expect("interpreter thread starts")
        })
        .collect();

    handles.into_iter().flat_map(|handle| handle.join().expect("interpreter thread completes")).collect()
}

/// A per-process scratch directory.
pub fn scratch_directory(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
    std::fs::create_dir_all(&path).expect("scratch directory created");

    path
}
