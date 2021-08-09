#![feature(get_mut_unchecked)]
#![feature(map_first_last)]

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::Error;
use flate2::read::ZlibDecoder;
use rayon::prelude::*;

use log::{debug, error};
use memmap::MmapOptions;
use once_cell::sync::OnceCell;
use py_marshal::{Code, Obj};
use rayon::Scope;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::hash::Hash;
use std::io::prelude::*;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use strings::CodeObjString;
use structopt::StructOpt;

/// Representing code as a graph of basic blocks
pub mod code_graph;
/// Deobfuscation module
pub mod deob;
/// Errors
pub mod error;
/// Provides code for partially executing a code object and identifying const conditions
pub mod partial_execution;
/// Python VM
pub mod smallvm;
/// Management of Python strings for string dumping
pub mod strings;

#[derive(Debug)]
struct Deobfuscator<'a> {
    /// Input stream.
    input: &'a [u8],

    /// Output to write dotviz graph to
    enable_dotviz_graphs: bool,
    files_processed: AtomicUsize,
    graphviz_graphs: HashMap<String, String>,
}

impl<'a> Deobfuscator<'a> {
    /// Creates a new instance of a deobfuscator
    pub fn new(input: &'a [u8]) -> Deobfuscator<'a> {
        Deobfuscator {
            input,
            enable_dotviz_graphs: false,
            files_processed: AtomicUsize::new(0),
            graphviz_graphs: HashMap::new(),
        }
    }

    /// Consumes the current Deobufscator object and returns a new one with graph
    /// output enabled.
    pub fn enable_graphs(mut self) -> Deobfuscator<'a> {
        self.enable_dotviz_graphs = true;
        self
    }

    /// Deobfuscates this code object
    pub fn deobfuscate(&self) -> Result<DeobfuscatedCodeObject, Error> {
        deobfuscate_codeobj(self.input, &self.files_processed, self.enable_dotviz_graphs)
    }

    /// Returns the generated graphviz graphs after a [`deobfuscate`] has been called.
    /// Keys are their filenames, values are the dot data.
    pub fn graphs(&self) -> &HashMap<String, String> {
        &self.graphviz_graphs
    }
}


pub struct DeobfuscatedCodeObject {
    /// Serialized code object with no header
    data: Vec<u8>,
    /// Graphs that were generated while deobfuscating this code object and any
    /// nested objects. Keys represent file names and their deobfuscation pass
    /// while the values represent the graphviz data in Dot format
    graphs: HashMap<String, String>,
}

/// Deobfuscates a marshalled code object and returns either the deobfuscated code object
/// or the [`crate::errors::Error`] encountered during execution
pub(crate) fn deobfuscate_codeobj(
    data: &[u8],
    files_processed: &AtomicUsize,
    enable_dotviz_graphs: bool,
) -> Result<DeobfuscatedCodeObject, Error> {
    if let py_marshal::Obj::Code(code) = py_marshal::read::marshal_loads(data).unwrap() {
        // This vector will contain the input code object and all nested objects
        let mut results = vec![];
        let mut mapped_names = HashMap::new();
        let mut graphs = HashMap::new();
        let out_results = Arc::new(Mutex::new(vec![]));
        rayon::scope(|scope| {
            deobfuscate_nested_code_objects(
                Arc::clone(&code),
                scope,
                Arc::clone(&out_results),
                files_processed,
                enable_dotviz_graphs,
            );
        });

        let out_results = Arc::try_unwrap(out_results)
            .unwrap_or_else(|_| panic!("failed to unwrap mapped names"))
            .into_inner()
            .unwrap();
        for result in out_results {
            let result = result?;
            results.push((result.file_number, result.new_bytecode));
            mapped_names.extend(result.mapped_function_names);
            graphs.extend(result.graphviz_graphs);
        }

        // sort these items by their file number. ordering matters since our python code pulls the objects as a
        // stack
        results.sort_by(|a, b| a.0.cmp(&b.0));

        let output_data = crate::deob::rename_vars(
            data,
            &mut results.iter().map(|result| result.1.as_slice()),
            &mapped_names,
        )
        .unwrap();

        Ok(DeobfuscatedCodeObject {
            data: output_data,
            graphs,
        })
    } else {
        Err(Error::InvalidCodeObject)
    }
}

pub(crate) struct DeobfuscatedBytecode {
    pub(crate) file_number: usize,
    pub(crate) new_bytecode: Vec<u8>,
    pub(crate) mapped_function_names: HashMap<String, String>,
    pub(crate) graphviz_graphs: HashMap<String, String>,
}

pub(crate) fn deobfuscate_nested_code_objects(
    code: Arc<Code>,
    scope: &Scope,
    out_results: Arc<Mutex<Vec<Result<DeobfuscatedBytecode, Error>>>>,
    files_processed: &AtomicUsize,
    enable_dotviz_graphs: bool,
) {
    let file_number = files_processed.fetch_add(1, Ordering::Relaxed);

    let task_code = Arc::clone(&code);
    let thread_results = Arc::clone(&out_results);
    scope.spawn(move |_scope| {
        let res = crate::deob::deobfuscate_code(task_code, file_number, enable_dotviz_graphs);
        thread_results.lock().unwrap().push(res);
    });

    // We need to find and replace the code sections which may also be in the const data
    for c in code.consts.iter() {
        if let Obj::Code(const_code) = c {
            let thread_results = Arc::clone(&out_results);
            let thread_code = Arc::clone(const_code);
            // Call deobfuscate_bytecode first since the bytecode comes before consts and other data

            deobfuscate_nested_code_objects(
                thread_code,
                scope,
                thread_results,
                files_processed,
                enable_dotviz_graphs,
            );
        }
    }
}

/// Dumps all strings from a Code object. This will go over all of the `names`, variable names (`varnames`),
/// `consts`, and all strings from any nested code objects.
pub fn dump_codeobject_strings(pyc_filename: &Path, code: Arc<Code>) -> Vec<CodeObjString> {
    let new_strings = Mutex::new(vec![]);
    code.names.par_iter().for_each(|name| {
        new_strings.lock().unwrap().push(CodeObjString::new(
            code.as_ref(),
            pyc_filename,
            crate::strings::StringType::Name,
            name.to_string().as_ref(),
        ))
    });

    code.varnames.par_iter().for_each(|name| {
        new_strings.lock().unwrap().push(CodeObjString::new(
            code.as_ref(),
            pyc_filename,
            crate::strings::StringType::VarName,
            name.to_string().as_ref(),
        ))
    });

    code.consts.as_ref().par_iter().for_each(|c| {
        if let py_marshal::Obj::String(s) = c {
            new_strings.lock().unwrap().push(CodeObjString::new(
                code.as_ref(),
                pyc_filename,
                crate::strings::StringType::Const,
                s.to_string().as_ref(),
            ))
        }
    });

    // We need to find and replace the code sections which may also be in the const data
    code.consts.par_iter().for_each(|c| {
        if let Obj::Code(const_code) = c {
            // Call deobfuscate_bytecode first since the bytecode comes before consts and other data
            let mut strings = dump_codeobject_strings(pyc_filename, Arc::clone(&const_code));
            new_strings.lock().unwrap().append(&mut strings);
        }
    });

    new_strings.into_inner().unwrap()
}
