#![feature(get_mut_unchecked)]
#![feature(map_first_last)]

use anyhow::{Context, Result};

use pydis::opcode::py27::Standard;
use rayon::prelude::*;

use log::error;
use memmap::MmapOptions;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
struct Opt {
    /// Input obfuscated file
    #[structopt(parse(from_os_str))]
    input_obfuscated_file: PathBuf,

    /// Output file name or directory name. If this path is a directory, a file
    /// will be created with the same name as the input. When the `strings-only`
    /// subcommand is applied, this will be where the output strings file is placed.
    #[structopt(parse(from_os_str))]
    output_path: PathBuf,

    /// Enable verbose logging
    #[structopt(short = "v", parse(from_occurrences))]
    verbose: usize,

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

    /// Your favorite Python 2.7 bytecode decompiler. This program assumes the decompiler's
    /// first positional argument is the file to decompile, and it prints the decompiled output
    /// to stdout
    #[structopt(long, default_value = "uncompyle6", env = "UNFUCK_DECOMPILER")]
    decompiler: String,

    /// Only dump strings from the deobfuscated code. Do not do any further processing
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
    } else if opt.verbose == 2 {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .with_module_level("unfuck::smallvm", log::LevelFilter::Debug)
            .init()
            .unwrap();
    } else if opt.verbose == 1 {
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

    let file_name = opt.input_obfuscated_file.file_name().unwrap();
    let file_name_as_str = Path::new(
        file_name
            .to_str()
            .expect("failed to convert input path to a string"),
    );

    // Ensure the output directories are created
    let target_path = if opt.output_path.is_dir() || !opt.output_path.extension().is_some() {
        // The user provided an output directory. We write to dir/<input_file_name>
        std::fs::create_dir_all(&opt.output_path)?;
        opt.output_path.join(file_name)
    } else {
        // The user provided an output file name
        if let Some(output_parent_dir) = opt.output_path.parent() {
            std::fs::create_dir_all(output_parent_dir)?;
        }

        opt.output_path.clone()
    };

    std::fs::create_dir_all(&opt.graphs_dir)?;

    let file = File::open(&opt.input_obfuscated_file)
        .with_context(|| format!("{:?}", opt.input_obfuscated_file))?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let file_count = Arc::new(AtomicUsize::new(0));
    let strings_output_file_name = if let Some(Command::StringsOnly) = opt.cmd {
        if opt.output_path.is_file() {
            // The user provided a fixed file path to save the strings to
            Some(opt.output_path.clone())
        } else {
            // The user provided a directory to save the strings to
            let mut path = opt
                .output_path
                .join(opt.input_obfuscated_file.file_stem().unwrap());

            assert!(
                path.set_extension("csv"),
                "failed to set output strings file extension"
            );
            Some(path)
        }
    } else {
        None
    };

    let csv_output = if let Some(strings_file) = strings_output_file_name.as_ref() {
        Some(Arc::new(Mutex::new(
            csv::WriterBuilder::new().from_path(strings_file)?,
        )))
    } else {
        None
    };

    if handle_pyc(
        Path::new(file_name_as_str),
        &mmap,
        &target_path,
        csv_output,
        &opt,
    )? {
        // todo: if we ever support directories, print this number?
        file_count.fetch_add(1, Ordering::Relaxed);
    }

    match (&opt.dry, &opt.cmd) {
        (true, _) => {
            println!("--dry flag specified, no files written");
        }
        (false, Some(Command::StringsOnly)) => {
            println!(
                "Wrote strings for {:?} to {:?}",
                opt.input_obfuscated_file,
                strings_output_file_name.unwrap()
            );
        }
        (false, None) => {
            println!(
                "Wrote deobfuscated file for {:?} to {:?}",
                opt.input_obfuscated_file, target_path
            );
        }
    }

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

    let deobfuscator = unfuck::Deobfuscator::<Standard>::new(pyc_file);
    let deobfuscator = if opt.graphs {
        deobfuscator.enable_graphs()
    } else {
        deobfuscator
    };

    let deobfuscated_code = deobfuscator.deobfuscate()?;

    // Write the deobfuscated data to our output directory
    if !opt.dry {
        // We do not dump strings if the strings output was provided
        if strings_output.is_none() {
            let mut deobfuscated_file = File::create(target_path)?;
            deobfuscated_file.write_all(&magic.to_le_bytes()[..])?;
            deobfuscated_file.write_all(&moddate.to_le_bytes()[..])?;
            deobfuscated_file.write_all(deobfuscated_code.data.as_slice())?;

            decompile_pyc(target_path, opt.decompiler.as_ref());

            // Write the graphs
            for (filename, graph_data) in &deobfuscated_code.graphs {
                let out_file = opt.graphs_dir.join(filename);
                let mut graph_file = File::create(&out_file)
                    .with_context(|| format!("attempting to create graph file {:?}", out_file))?;
                graph_file.write_all(graph_data.as_bytes())?;
            }
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

/// Runs the decompiler on the provided PYC file
fn decompile_pyc(path: &Path, decompiler: &str) {
    match std::process::Command::new(decompiler).arg(path).output() {
        Ok(output) => {
            io::stdout()
                .write_all(output.stdout.as_slice())
                .expect("failed to write to stdout");
            io::stderr()
                .write_all(output.stderr.as_slice())
                .expect("failed to write to stderr");
        }
        Err(e) => {
            error!("Could not run decompiler: {}", e);
        }
    }
}
