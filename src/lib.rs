#![feature(get_mut_unchecked)]
#![feature(map_first_last)]

use crate::error::Error;
use pydis::opcode::py27::{self, Standard};
use pydis::prelude::Opcode;
use rayon::prelude::*;

use py27_marshal::{Code, Obj};
use rayon::Scope;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use strings::CodeObjString;

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

pub struct Deobfuscator<'a, O: Opcode<Mnemonic = py27::Mnemonic>> {
    /// Input stream.
    input: &'a [u8],

    /// Output to write dotviz graph to
    enable_dotviz_graphs: bool,
    files_processed: AtomicUsize,
    graphviz_graphs: HashMap<String, String>,
    on_graph_generated: Option<fn(&str, &str)>,
    _opcode_phantom: PhantomData<O>,
}

impl<'a, O: Opcode<Mnemonic = py27::Mnemonic>> Debug for Deobfuscator<'a, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deobfuscator")
            .field("input", &self.input)
            .field("enable_dotviz_graphs", &self.enable_dotviz_graphs)
            .field("files_processed", &self.files_processed)
            .field("graphviz_graphs", &self.graphviz_graphs)
            .field(
                "on_graph_generated",
                if let Some(callback) = &self.on_graph_generated {
                    &"Some(callback)"
                } else {
                    &"None"
                },
            )
            .field("_opcode_phantom", &self._opcode_phantom)
            .finish()
    }
}

impl<'a, O: Opcode<Mnemonic = py27::Mnemonic>> Deobfuscator<'a, O> {
    /// Creates a new instance of a deobfuscator
    pub fn new(input: &'a [u8]) -> Deobfuscator<'a, O> {
        Deobfuscator {
            input,
            enable_dotviz_graphs: false,
            files_processed: AtomicUsize::new(0),
            graphviz_graphs: HashMap::new(),
            on_graph_generated: None,
            _opcode_phantom: Default::default(),
        }
    }

    /// Consumes the current Deobfuscator object and returns a new one with graph
    /// output enabled.
    pub fn enable_graphs(mut self) -> Deobfuscator<'a, O> {
        self.enable_dotviz_graphs = true;
        self
    }

    /// Callback for when a new graph is generated. This may be useful if deobfuscation
    /// fails/panics and graphs can't be written, you can use this functionality
    /// to write graphs on-the-fly
    pub fn on_graph_generated(mut self, callback: fn(&str, &str)) -> Deobfuscator<'a, O> {
        self.on_graph_generated = Some(callback);
        self
    }

    /// Deobfuscates this code object
    pub fn deobfuscate(&self) -> Result<DeobfuscatedCodeObject, Error<O>> {
        deobfuscate_codeobj::<O>(self.input, &self.files_processed, self.enable_dotviz_graphs, self.on_graph_generated)
    }

    /// Returns the generated graphviz graphs after a [`deobfuscate`] has been called.
    /// Keys are their filenames, values are the dot data.
    pub fn graphs(&self) -> &HashMap<String, String> {
        &self.graphviz_graphs
    }
}

pub struct DeobfuscatedCodeObject {
    /// Serialized code object with no header
    pub data: Vec<u8>,
    /// Graphs that were generated while deobfuscating this code object and any
    /// nested objects. Keys represent file names and their deobfuscation pass
    /// while the values represent the graphviz data in Dot format
    pub graphs: HashMap<String, String>,
}

/// Deobfuscates a marshalled code object and returns either the deobfuscated code object
/// or the [`crate::errors::Error`] encountered during execution
pub(crate) fn deobfuscate_codeobj<O: Opcode<Mnemonic = py27::Mnemonic>>(
    data: &[u8],
    files_processed: &AtomicUsize,
    enable_dotviz_graphs: bool,
    on_graph_generated: Option<fn(&str, &str)>,
) -> Result<DeobfuscatedCodeObject, Error<O>> {
    if let py27_marshal::Obj::Code(code) = py27_marshal::read::marshal_loads(data)? {
        // This vector will contain the input code object and all nested objects
        let mut results = vec![];
        let mut mapped_names = HashMap::new();
        let mut graphs = HashMap::new();
        let out_results = Arc::new(Mutex::new(vec![]));
        rayon::scope(|scope| {
            deobfuscate_nested_code_objects::<O>(
                Arc::clone(&code),
                scope,
                Arc::clone(&out_results),
                files_processed,
                enable_dotviz_graphs,
                on_graph_generated,
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

pub(crate) fn deobfuscate_nested_code_objects<O: Opcode<Mnemonic = py27::Mnemonic>>(
    code: Arc<Code>,
    scope: &Scope,
    out_results: Arc<Mutex<Vec<Result<DeobfuscatedBytecode, Error<O>>>>>,
    files_processed: &AtomicUsize,
    enable_dotviz_graphs: bool,
    on_graph_generated: Option<fn(&str, &str)>,
) {
    let file_number = files_processed.fetch_add(1, Ordering::Relaxed);

    let task_code = Arc::clone(&code);
    let thread_results = Arc::clone(&out_results);
    scope.spawn(move |_scope| {
        let res = crate::deob::deobfuscate_code::<O>(task_code, file_number, enable_dotviz_graphs, on_graph_generated);
        thread_results.lock().unwrap().push(res);
    });

    // We need to find and replace the code sections which may also be in the const data
    for c in code.consts.iter() {
        if let Obj::Code(const_code) = c {
            let thread_results = Arc::clone(&out_results);
            let thread_code = Arc::clone(const_code);
            // Call deobfuscate_bytecode first since the bytecode comes before consts and other data

            deobfuscate_nested_code_objects::<O>(
                thread_code,
                scope,
                thread_results,
                files_processed,
                enable_dotviz_graphs,
                on_graph_generated,
            );
        }
    }
}

/// Dumps all strings from a Code object. This will go over all of the `names`, variable names (`varnames`),
/// `consts`, and all strings from any nested code objects.
pub fn dump_strings<'a>(
    pyc_filename: &'a Path,
    data: &[u8],
) -> Result<Vec<CodeObjString<'a>>, Error<Standard>> {
    if let py27_marshal::Obj::Code(code) = py27_marshal::read::marshal_loads(data)? {
        Ok(dump_codeobject_strings(pyc_filename, code))
    } else {
        Err(Error::InvalidCodeObject)
    }
}

/// Dumps all strings from a Code object. This will go over all of the `names`, variable names (`varnames`),
/// `consts`, and all strings from any nested code objects.
fn dump_codeobject_strings(pyc_filename: &Path, code: Arc<Code>) -> Vec<CodeObjString> {
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
        if let py27_marshal::Obj::String(s) = c {
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
