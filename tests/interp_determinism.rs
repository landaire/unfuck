//! The interpreter's output depends only on its input: identities, the
//! fallback ordering, and iteration order never come from the host
//! allocator, address space layout, or hash seeds.

#[path = "support/stdlib.rs"]
mod stdlib;

use std::process::Command;

use unfuck::interp::ModuleCode;
use unfuck::interp::ModuleSource;
use unfuck::interp::Signal;
use unfuck::interp::Value;
use unfuck::interp::Vm;
use unfuck::interp::VmConfig;
use unfuck::interp::lib_source::LibSource;
use unfuck::interp::object::CallArgs;

/// Set in the environment of the child process `separate_processes_agree`
/// starts.
const CHILD_FLAG: &str = "UNFUCK_DETERMINISM_CHILD";
const OUTPUT_START: &str = "--- determinism output start ---\n";
const OUTPUT_END: &str = "\n--- determinism output end ---";

/// Prints identities, address-bearing reprs, and orders derived from them.
const SCRIPT: &str = r#"
import gc
import sys
import _weakref

lines = []

def out(label, value):
    lines.append('%s: %r' % (label, value))

class New(object):
    def method(self):
        pass

class Old:
    def method(self):
        pass

def same_name_class():
    class Same(object):
        pass
    return Same

text = 'determinism' * 3
pair = (1, 'two', 3.0)
big = 10 ** 30
wide = u'unicode text' * 2
instance = New()
classic = Old()
values = [text, pair, big, wide, instance, classic, [], {}, object(), New, Old, len, None, 7, 2.5, (), '', u'', 'x', u'x', True, intern('interned name')]

ids = [id(value) for value in values]
out('ids', ids)
out('hex ids', ['%x' % number for number in ids])
out('hex builtin', [hex(id(text)), hex(id(pair)), hex(id(big)), hex(id(wide))])
out('fresh', [id((1, len(lines))) == id((1, len(lines))), id(10 ** 40) == id(10 ** 40), id(()) == id(tuple()), id('x') == id('xy'[0]), id(intern('interned name')) == ids[-1]])

# Live values have distinct identities, and `is` agrees with `id()`. Equal
# inline numbers and distinct tuples of one length are left out: `is` on
# them is unknown.
assert len(set(ids)) == len(values), ids
assert id(tuple(list(pair))) != id(pair)
heap = [value for value in values if type(value) not in (int, float, bool, type(None))]
probes = heap + ['determinism' * 3, wide[:], 'x' + '', u'x' + u'', tuple(), str(), unicode(), intern('interned' + ' name')]
for left in probes:
    for right in probes:
        assert (left is right) == (id(left) == id(right)), (left, right)
out('hashes', [hash(instance), hash(classic), hash(New), hash(object()), hash(len)])

plain = [object() for index in range(6)]
out('object order', sorted(range(6), key=lambda index: plain[index]))
news = [New() for index in range(6)]
out('instance order', sorted(range(6), key=lambda index: news[index]))
olds = [Old() for index in range(6)]
out('classic order', sorted(range(6), key=lambda index: olds[index]))
same = [same_name_class()() for index in range(6)]
out('same-name class order', sorted(range(6), key=lambda index: same[index]))
mixed = [instance, classic, New(), Old(), object(), (2, 1), 'b', u'a', 10 ** 20, 3, None, [1], {'k': 1}, 1.5, New, Old, len, frozenset([1]), set([2]), same[0], same[1]]
out('mixed order', [mixed.index(item) for item in sorted(mixed)])
out('min max', [mixed.index(min(mixed)), mixed.index(max(mixed))])

by_id = {}
for index, value in enumerate(values):
    by_id[id(value)] = index
out('dict keyed by id', by_id.items())
out('set of ids', list(set(ids)))
by_object = {}
for index, value in enumerate([instance, classic, New, Old, object, len, plain[0], plain[1], news[2], olds[3]]):
    by_object[value] = index
out('dict keyed by object', by_object.values())
out('set of objects', [values.index(item) for item in set([instance, classic, New, Old, len])])

reference = _weakref.ref(instance)
out('reprs', [repr(instance), repr(classic), repr(object()), repr(New.method), repr(instance.method), repr(classic.method), repr(same_name_class), repr(lambda: 0), repr(iter([])), repr(iter(())), repr(reference), repr(_weakref.proxy(instance)), repr(sys._getframe()), repr(same_name_class.func_code), repr(buffer('abc'))])
out('default str', [str(instance), str(object())])
out('format', ['%r %s' % (instance, classic)])

out('modules', sys.modules.keys())
out('modules items', [name for name, module in sys.modules.items() if module is not None])
out('gc', [gc.isenabled(), gc.get_count(), gc.get_threshold(), gc.garbage, gc.is_tracked(pair), gc.is_tracked(text)])
out('builtins', sys.modules['__builtin__'].__dict__.keys())
out('refcounts', [sys.getrefcount(item) for item in [text, pair, big, wide, instance]])
out('flags', sys.flags)
out('path hooks', [sys.path_hooks, sys.meta_path, sys.path_importer_cache.keys()])
out('dir', [dir(instance), dir(classic), dir(sys)])

try:
    import cPickle
except ImportError:
    out('cPickle', 'unavailable')
else:
    shared = ('shared', 10 ** 25, wide)
    payload = [shared, shared, text, text, wide, wide, big, big, pair, pair]
    pickler = cPickle.Pickler(2)
    pickler.dump(payload)
    out('pickle memo', pickler.memo)
    out('pickle memo keys', sorted(pickler.memo.keys()))
    out('pickle', pickler.getvalue())
    out('dumps', cPickle.dumps(payload, 2))
    out('dumps protocol 0', cPickle.dumps(payload, 0))

RESULT = '\n'.join(lines)
"#;

/// The script's modules: the listed standard library modules, when a `Lib`
/// directory is available.
struct ScriptSource {
    stdlib: Option<LibSource>,
}

impl ModuleSource for ScriptSource {
    fn find(&self, name: &str) -> Option<ModuleCode> {
        match self.stdlib.as_ref()?.compile(name) {
            Ok(code) => code,
            Err(error) => panic!("{error}"),
        }
    }
}

fn new_vm() -> Vm {
    let config = VmConfig::windows_x64();
    let source = ScriptSource { stdlib: stdlib::source(config.long_width) };

    match Vm::new(config, Box::new(source)) {
        Ok(vm) => vm,
        Err(_) => panic!("interpreter bootstrap failed"),
    }
}

/// The text the script leaves in `RESULT`.
fn run_script(vm: &Vm) -> String {
    let describe = |signal: Signal| match signal {
        Signal::Raise(exception) => format!("raised {}", vm.describe_exception(&exception)),
        Signal::Halt(halt) => format!("halted: {halt}"),
    };
    let builtin = |name: &str| vm.import_module("__builtin__").and_then(|builtins| vm.getattr_str(&builtins, name)).unwrap_or_else(|signal| panic!("{name}: {}", describe(signal)));

    let code = vm.call(&builtin("compile"), CallArgs::new(vec![Value::str(SCRIPT), Value::str("determinism.py"), Value::str("exec")])).unwrap_or_else(|signal| panic!("compile: {}", describe(signal)));
    let globals = vm.new_dict();
    vm.call(&builtin("eval"), CallArgs::new(vec![code, Value::Object(globals.clone())])).unwrap_or_else(|signal| panic!("script: {}", describe(signal)));

    let result = vm.dict_get_str(&globals, "RESULT").ok().flatten().expect("the script binds RESULT");
    let bytes = result.as_bytes().expect("RESULT is a str");

    String::from_utf8_lossy(bytes).into_owned()
}

/// Runs `body` on a thread whose stack covers the interpreter's recursion.
fn on_interpreter_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    const STACK_SIZE: usize = 256 * 1024 * 1024;

    std::thread::Builder::new().stack_size(STACK_SIZE).spawn(body).expect("thread spawns").join().expect("script thread completes")
}

#[test]
fn two_vms_in_one_process_agree() {
    let (first, second, interleaved) = on_interpreter_stack(|| {
        let first = run_script(&new_vm());

        // The second VM allocates while the third is alive, so neither sees
        // a fresh heap.
        let third_vm = new_vm();
        let second = run_script(&new_vm());
        let interleaved = run_script(&third_vm);

        (first, second, interleaved)
    });

    assert_eq!(first, second);
    assert_eq!(first, interleaved);
}

/// The child half of `separate_processes_agree`. It does nothing unless
/// started by that test.
#[test]
fn determinism_child() {
    if std::env::var_os(CHILD_FLAG).is_none() {
        return;
    }

    let output = on_interpreter_stack(|| run_script(&new_vm()));

    print!("{OUTPUT_START}{output}{OUTPUT_END}");
}

/// Two processes differ in address space layout; the output must not.
#[test]
fn separate_processes_agree() {
    let run_child = || {
        let executable = std::env::current_exe().expect("test executable path");
        let output = Command::new(executable).args(["--exact", "determinism_child", "--nocapture", "--test-threads=1"]).env(CHILD_FLAG, "1").output().expect("child process runs");
        assert!(output.status.success(), "child failed: {}", String::from_utf8_lossy(&output.stderr));

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let start = stdout.find(OUTPUT_START).expect("child output start") + OUTPUT_START.len();
        let end = stdout.find(OUTPUT_END).expect("child output end");

        stdout[start..end].to_owned()
    };

    let first = run_child();
    let second = run_child();

    assert_eq!(first, second);
}
