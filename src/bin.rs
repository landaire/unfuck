#![feature(get_mut_unchecked)]
#![feature(map_first_last)]

use anyhow::Context;
use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};

use flate2::read::ZlibDecoder;
use rayon::prelude::*;

use log::{debug, error};
use memmap::MmapOptions;
use once_cell::sync::OnceCell;
use py27_marshal::{Code, Obj};
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

    /// An optional directory for graphs to be written to
    #[structopt(default_value = ".")]
    graphs_dir: PathBuf,

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
    let opt = Arc::new(Opt::from_args());

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

                    let file_path = match file.enclosed_name() {
                        Some(path) => path,
                        None => {
                            error!("File `{:?}` is not a valid path", file_name);
                            continue;
                        }
                    }.to_owned();
                    let target_path = opt.output_dir.join(&file_path);

                    if !opt.dry && file.is_dir() {
                        std::fs::create_dir_all(&target_path)?;
                        continue;
                    }

                    let mut decompressed_file = Vec::with_capacity(file.size() as usize);
                    file.read_to_end(&mut decompressed_file)?;

                    let file_count = Arc::clone(&file_count);
                    let csv_output = csv_output.clone();

                    let results = Arc::clone(&results);
                    let opt = Arc::clone(&opt);
                    s.spawn(move |_| {
                        let res =
                            handle_pyc(&file_path, decompressed_file.as_slice(), &target_path, csv_output, &opt);
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
            let file_name = opt.input.file_name().unwrap();
            let target_path = opt.output_dir.join(file_name);
            let file_name_as_str = Path::new(file_name.to_str().expect("failed to convert input path to a string"));
            if handle_pyc(Path::new(file_name_as_str), &mmap, &target_path, csv_output, &opt)? {
                file_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    println!("Deobfuscated {} files", file_count.load(Ordering::Relaxed));

    Ok(())
}

/// Deobfuscates a PYC file and optionally writes graph files and string
/// output.
fn handle_pyc(
    pyc_path: &Path,
    pyc_file: &[u8],
    target_path: &Path,
    strings_output: Option<Arc<Mutex<csv::Writer<std::fs::File>>>>,
    opt: &Opt,
) -> Result<bool> {
    use std::convert::TryInto;
    let magic = u32::from_le_bytes(pyc_file[0..4].try_into().unwrap());
    let moddate = u32::from_le_bytes(pyc_file[4..8].try_into().unwrap());

    let pyc_file = &pyc_file[8..];

    let deobfuscator = unfuck::Deobfuscator::new(pyc_file);
    let deobfuscator = if opt.graphs {
        deobfuscator.enable_graphs()
    } else {
        deobfuscator
    };

    let deobfuscated_code = deobfuscator.deobfuscate()?;

    // Write the deobfuscated data to our output directory
    if !opt.dry {
        let mut deobfuscated_file= File::create(target_path)?;
        deobfuscated_file.write_all(&magic.to_le_bytes()[..])?;
        deobfuscated_file.write_all(&moddate.to_le_bytes()[..])?;
        deobfuscated_file.write_all(deobfuscated_code.data.as_slice())?;

        // Write the graphs
        for (filename, graph_data) in &deobfuscated_code.graphs {
            let out_file = opt.graphs_dir.join(filename);
            let mut graph_file = File::create(&out_file).with_context(|| format!("attempting to create graph file {:?}", out_file))?;
            graph_file.write_all(graph_data.as_bytes())?;
        }

        if let Some(strings_output) = strings_output {
            let strings = unfuck::dump_strings(pyc_path, pyc_file)?;

            strings.par_iter().for_each(|s| {
                strings_output
                    .lock()
                    .unwrap()
                    .serialize(s)
                    .expect("failed to serialize output string");
            });
        }
    }


    Ok(true)
}
