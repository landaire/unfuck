#![feature(get_mut_unchecked)]
#![feature(map_first_last)]

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};

use flate2::read::ZlibDecoder;
use rayon::prelude::*;

use log::{debug, error};
use memmap::MmapOptions;
use once_cell::sync::OnceCell;
use py_marshal::{Code, Obj};
use rayon::Scope;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use unfuck::strings::CodeObjString;

pub(crate) static ARGS: OnceCell<Opt> = OnceCell::new();
pub(crate) static FILES_PROCESSED: OnceCell<AtomicUsize> = OnceCell::new();

#[derive(Debug, Clone, StructOpt)]
struct Opt {
    /// Input file. This may be either a `scripts.zip` file containing many
    /// obfuscated .pyc files, or this argument may be a single .pyc file.
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Output directory
    #[structopt(parse(from_os_str))]
    output_dir: PathBuf,

    /// Enable verbose logging
    #[structopt(short = "v")]
    verbose: bool,

    /// Enable verbose debug logging
    #[structopt(short = "mv")]
    more_verbose: bool,

    /// Disable all logging
    #[structopt(short = "q")]
    quiet: bool,

    /// Enable outputting code graphs to dot format
    #[structopt(short = "g")]
    graphs: bool,

    /// Dry run only -- do not write any files
    #[structopt(long = "dry")]
    dry: bool,

    /// Only dump strings frmo the stage4 code. Do not do any further processing
    #[structopt(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Clone, StructOpt)]
enum Command {
    StringsOnly,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    // initialize our globals
    ARGS.set(opt.clone()).unwrap();
    FILES_PROCESSED
        .set(std::sync::atomic::AtomicUsize::new(0))
        .unwrap();

    // Set up our logger if the user passed the debug flag. With reduced
    // functionality enabled we don't want any logging to avoid outputting info
    // for how obfuscation works.
    if opt.quiet {
        // do not initialize the logger
    } else if opt.more_verbose {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .with_module_level("unfuck::smallvm", log::LevelFilter::Debug)
            .init()
            .unwrap();
    } else if opt.verbose {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Debug)
            .init()
            .unwrap();
    } else {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Error)
            .init()
            .unwrap();
    }

    let file = File::open(&opt.input)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let reader = Cursor::new(&mmap);

    let file_count = Arc::new(AtomicUsize::new(0));
    let csv_output = if matches!(opt.cmd, Some(Command::StringsOnly)) {
        Some(Arc::new(Mutex::new(
            csv::WriterBuilder::new().from_path("strings.csv")?,
        )))
    } else {
        None
    };

    match opt.input.extension().map(|ext| ext.to_str().unwrap()) {
        Some("zip") => {
            let mut zip = zip::ZipArchive::new(reader)?;

            let results = Arc::new(Mutex::new(vec![]));
            let scope_result = rayon::scope(|s| -> Result<()> {
                for i in 0..zip.len() {
                    let mut file = zip.by_index(i)?;

                    let file_name = file.name().to_string();
                    debug!("Filename: {:?}", file_name);

                    //if !file_name.ends_with("m032b8507.pyc") {
                    //if !file_name.ends_with("md40d9a59.pyc") {
                    //if !file_name.contains("m07329f60.pyc") {
                    // if !file_name.ends_with("random.pyc") {
                    //     continue;
                    // }

                    let file_path = match file.enclosed_name() {
                        Some(path) => path,
                        None => {
                            error!("File `{:?}` is not a valid path", file_name);
                            continue;
                        }
                    };
                    let target_path = opt.output_dir.join(file_path);

                    if !opt.dry && file.is_dir() {
                        std::fs::create_dir_all(&target_path)?;
                        continue;
                    }

                    let mut decompressed_file = Vec::with_capacity(file.size() as usize);
                    file.read_to_end(&mut decompressed_file)?;

                    let file_count = Arc::clone(&file_count);
                    let csv_output = csv_output.clone();

                    let results = Arc::clone(&results);
                    s.spawn(move |_| {
                        let res = dump_pyc(decompressed_file.as_slice(), &target_path, csv_output);
                        if res.is_ok() {
                            file_count.fetch_add(1, Ordering::Relaxed);
                        }

                        results.lock().unwrap().push((file_name, res))
                    });

                    //break;
                }

                Ok(())
            });

            scope_result?;

            let results = results.lock().unwrap();
            for (filename, result) in &*results {
                if let Err(err) = result {
                    eprintln!("Error dumping {:?}: {}", filename, err);
                }
            }
        }
        _ => {
            let target_path = opt.output_dir.join(opt.input.file_name().unwrap());
            if dump_pyc(&mmap, &target_path, csv_output)? {
                file_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    println!("Extracted {} files", file_count.load(Ordering::Relaxed));

    Ok(())
}

fn dump_pyc(
    decompressed_file: &[u8],
    target_path: &Path,
    strings_output: Option<Arc<Mutex<csv::Writer<std::fs::File>>>>,
) -> Result<bool> {
    Ok(true)
}
