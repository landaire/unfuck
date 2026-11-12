//! The `_symtable` module and its `symtable entry` type, built on the
//! compiler's symbol table.

use std::collections::HashMap;

use crate::interp::builtins::MethodSpec;
use crate::interp::builtins::exec::VmCompileContext;
use crate::interp::builtins::function;
use crate::interp::builtins::install_functions;
use crate::interp::builtins::method;
use crate::interp::builtins::modules::GetSet;
use crate::interp::builtins::modules::TypeSpec;
use crate::interp::builtins::modules::add_member;
use crate::interp::builtins::modules::codecs::args::c_string;
use crate::interp::builtins::modules::codecs::args::first_unknown;
use crate::interp::builtins::modules::codecs::args::varargs;
use crate::interp::builtins::modules::descriptor_mismatch;
use crate::interp::builtins::modules::impl_native_data;
use crate::interp::builtins::modules::native_data;
use crate::interp::builtins::modules::native_type;
use crate::interp::builtins::modules::new_final_type;
use crate::interp::builtins::modules::new_native_object;
use crate::interp::builtins::modules::this;
use crate::interp::builtins::set_attribute;
use crate::interp::builtins::source_codecs::parse_in_vm;
use crate::interp::compiler::CompilerFlags;
use crate::interp::compiler::Mode;
use crate::interp::compiler::symtable::BlockId;
use crate::interp::compiler::symtable::BlockType;
use crate::interp::compiler::symtable::SCOPE_MASK;
use crate::interp::compiler::symtable::SCOPE_OFF;
use crate::interp::compiler::symtable::Scope;
use crate::interp::compiler::symtable::SymbolTable;
use crate::interp::compiler::symtable::def;
use crate::interp::compiler::symtable::opt;
use crate::interp::error::PyResult;
use crate::interp::exceptions::ExceptionKind;
use crate::interp::object::CallArgs;
use crate::interp::object::Layout;
use crate::interp::value::ObjectRef;
use crate::interp::value::PyBytes;
use crate::interp::value::Value;
use crate::interp::vm::Vm;

const ENTRY_TYPE: &str = "symtable entry";

/// One block of a symbol table, as the `symtable entry` objects that
/// `_symtable.symtable` returns.
struct Entry {
    /// The `id` attribute: identifies the syntax tree node, so its value
    /// depends on the host.
    id: Value,
    name: Value,
    symbols: Value,
    varnames: Value,
    children: Value,

    /// Exposed as the `optimized` attribute.
    unoptimized: i64,
    nested: i64,
    kind: i64,
    lineno: i64,
}

impl_native_data!(Entry, "symtable entry");

const FUNCTIONS: &[MethodSpec] = &[function("symtable", symtable)];

pub fn init(vm: &Vm, module: &ObjectRef) -> PyResult<()> {
    native_type(vm, ENTRY_TYPE, create_entry_type)?;
    install_functions(vm, module, FUNCTIONS)?;

    let constants = [
        ("USE", def::USE),
        ("DEF_GLOBAL", def::GLOBAL),
        ("DEF_LOCAL", def::LOCAL),
        ("DEF_PARAM", def::PARAM),
        ("DEF_FREE", def::FREE),
        ("DEF_FREE_CLASS", def::FREE_CLASS),
        ("DEF_IMPORT", def::IMPORT),
        ("DEF_BOUND", def::BOUND),
        ("TYPE_FUNCTION", block_type_value(BlockType::Function)),
        ("TYPE_CLASS", block_type_value(BlockType::Class)),
        ("TYPE_MODULE", block_type_value(BlockType::Module)),
        ("OPT_IMPORT_STAR", opt::IMPORT_STAR),
        ("OPT_EXEC", opt::EXEC),
        ("OPT_BARE_EXEC", opt::BARE_EXEC),
        ("LOCAL", Scope::Local as u32),
        ("GLOBAL_EXPLICIT", Scope::GlobalExplicit as u32),
        ("GLOBAL_IMPLICIT", Scope::GlobalImplicit as u32),
        ("FREE", Scope::Free as u32),
        ("CELL", Scope::Cell as u32),
        ("SCOPE_OFF", SCOPE_OFF),
        ("SCOPE_MASK", SCOPE_MASK),
    ];
    for (name, value) in constants {
        set_attribute(vm, module, name, Value::Int(i64::from(value)))?;
    }

    Ok(())
}

fn create_entry_type(vm: &Vm) -> PyResult<ObjectRef> {
    let class = new_final_type(
        vm,
        TypeSpec { name: ENTRY_TYPE, module: "__builtin__", base: None, layout: Layout::Native, instance_dict: false, methods: &[method("__repr__", entry_repr)] },
    )?;

    let members = [
        GetSet { name: "id", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| entry.id.clone()), set: None },
        GetSet { name: "name", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| entry.name.clone()), set: None },
        GetSet { name: "symbols", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| entry.symbols.clone()), set: None },
        GetSet { name: "varnames", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| entry.varnames.clone()), set: None },
        GetSet { name: "children", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| entry.children.clone()), set: None },
        GetSet { name: "optimized", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| Value::Int(entry.unoptimized)), set: None },
        GetSet { name: "nested", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| Value::Int(entry.nested)), set: None },
        GetSet { name: "type", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| Value::Int(entry.kind)), set: None },
        GetSet { name: "lineno", owner: ENTRY_TYPE, get: |vm, getset, value| read_member(vm, getset, value, |entry| Value::Int(entry.lineno)), set: None },
    ];
    for member in members {
        add_member(vm, &class, member)?;
    }

    Ok(class)
}

fn read_member(vm: &Vm, getset: &GetSet, instance: &Value, read: fn(&Entry) -> Value) -> PyResult<Value> {
    native_data::<Entry>(instance).map(read).ok_or_else(|| descriptor_mismatch(vm, getset, instance))
}

/// The repr shows the `id` attribute, whose value depends on the host, so
/// the text is not reproducible.
fn entry_repr(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    this::<Entry>(vm, &args, ENTRY_TYPE, "__repr__")?;

    Ok(Value::unknown("repr of a symtable entry (AST node address)"))
}

/// `symtable(str, filename, startstr)`.
fn symtable(vm: &Vm, args: CallArgs) -> PyResult<Value> {
    let arguments = varargs(vm, args, "symtable", 3, 3)?;
    if let Some(unknown) = first_unknown(&arguments) {
        return Ok(unknown);
    }

    let [source, filename, start] = arguments.as_slice() else {
        return Err(vm.raise(ExceptionKind::SystemError, "symtable() argument count"));
    };
    let source = c_string(vm, "symtable", 1, source)?;
    let filename = c_string(vm, "symtable", 2, filename)?;
    let start = c_string(vm, "symtable", 3, start)?;

    let mode = match start.as_bytes() {
        b"exec" => Mode::Exec,
        b"eval" => Mode::Eval,
        b"single" => Mode::Single,
        _ => return Err(vm.raise(ExceptionKind::ValueError, "symtable() arg 3 must be 'exec' or 'eval' or 'single'")),
    };

    let parsed = parse_in_vm(vm, source.as_bytes(), filename.as_bytes(), mode, CompilerFlags::default())?;

    let mut context = VmCompileContext::new(vm);
    let table = match SymbolTable::build(&parsed.module, filename.as_bytes(), &mut context) {
        Ok(table) => table,
        Err(error) => return Err(context.into_signal(error)),
    };

    entries(vm, &table)
}

/// The entry objects of every block, returning the top one. Children are
/// created before their parents so each `children` list holds the shared
/// entry objects.
fn entries(vm: &Vm, table: &SymbolTable) -> PyResult<Value> {
    let class = native_type(vm, ENTRY_TYPE, create_entry_type)?;

    let mut preorder = Vec::new();
    let mut pending = vec![table.top()];
    while let Some(id) = pending.pop() {
        preorder.push(id);
        pending.extend(table.block(id).children.iter().copied());
    }

    let mut created: HashMap<BlockId, Value> = HashMap::new();
    for id in preorder.into_iter().rev() {
        let block = table.block(id);

        let symbols = vm.new_dict();
        for name in &block.symbol_order {
            let Some(flags) = block.flags(name) else {
                return Err(vm.raise(ExceptionKind::SystemError, "symbol table entry lacks a symbol it lists"));
            };
            vm.dict_set(&symbols, name_value(name), Value::Int(i64::from(flags)))?;
        }

        let varnames = block.varnames.iter().map(|name| name_value(name)).collect();

        let mut children = Vec::with_capacity(block.children.len());
        for child in &block.children {
            let Some(entry) = created.get(child) else {
                return Err(vm.raise(ExceptionKind::SystemError, "symbol table child block precedes its parent"));
            };
            children.push(entry.clone());
        }

        let entry = Entry {
            id: Value::unknown("symtable entry id (AST node address)"),
            name: name_value(&block.name),
            symbols: Value::Object(symbols),
            varnames: vm.new_list(varnames),
            children: vm.new_list(children),
            unoptimized: i64::from(block.unoptimized),
            nested: i64::from(block.nested),
            kind: i64::from(block_type_value(block.kind)),
            lineno: i64::from(block.lineno),
        };
        created.insert(id, new_native_object(vm, &class, entry));
    }

    created.remove(&table.top()).ok_or_else(|| vm.raise(ExceptionKind::SystemError, "symbol table has no top block"))
}

fn name_value(name: &[u8]) -> Value {
    Value::Str(PyBytes::new(name))
}

/// The `type` attribute: the `_symtable` constants `TYPE_FUNCTION`,
/// `TYPE_CLASS`, and `TYPE_MODULE`.
fn block_type_value(kind: BlockType) -> u32 {
    match kind {
        BlockType::Function => 0,
        BlockType::Class => 1,
        BlockType::Module => 2,
    }
}
