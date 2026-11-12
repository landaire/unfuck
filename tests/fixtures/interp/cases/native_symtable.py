import _symtable
import symtable
import warnings

# Entry ids and reprs hold AST node addresses.

def K(value):
    return value

def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, str(e), getattr(e, 'lineno', None), getattr(e, 'filename', None))

SOURCE = K('''
import os, sys as system
from collections import namedtuple
glob = 1
def outer(a, b=2, *args, **kw):
    global glob
    glob = a
    c = len(args)
    def inner(d):
        e = d + c
        return [x for x in range(e)] + [b]
    lam = lambda q: q + a
    return inner, lam, (y for y in kw)
class Klass(object):
    attr = 1
    def method(self, value):
        return value + attr
    def other(self):
        return self
    def method(self):
        pass
def unopt():
    exec "z = 1"
def unopt_in():
    exec "z = 1" in {}
def holder():
    v = 1
    class Inner:
        def get(self):
            return v
    return Inner
''')

def table_info(table):
    return (
        table.get_type(), table.get_name(), table.get_lineno(), table.is_optimized(), table.is_nested(),
        table.has_children(), table.has_exec(), table.has_import_star(), list(table.get_identifiers()),
    )

def symbol_info(symbol):
    return (
        symbol.get_name(), symbol.is_referenced(), symbol.is_parameter(), symbol.is_global(),
        symbol.is_declared_global(), symbol.is_local(), symbol.is_free(), symbol.is_imported(),
        symbol.is_assigned(), symbol.is_namespace(), len(symbol.get_namespaces()),
    )

def walk(table, out):
    out.append(table_info(table))
    out.append([symbol_info(table.lookup(name)) for name in table.get_identifiers()])
    if isinstance(table, symtable.Function):
        out.append((table.get_parameters(), table.get_locals(), table.get_globals(), table.get_frees()))
    if isinstance(table, symtable.Class):
        out.append(table.get_methods())
    for child in table.get_children():
        walk(child, out)

top = symtable.symtable(SOURCE, K('mod.py'), 'exec')
RESULT = []
walk(top, RESULT)
RESULT.append(repr(top))
RESULT.append([repr(child) for child in top.get_children()])
RESULT.append(top.lookup('outer').get_namespace().get_name())
RESULT.append(err(top.lookup('Klass').get_namespace().lookup('method').get_namespace))
RESULT.append(err(top.lookup, 'missing'))
RESULT.append(top.get_children()[0] is top.lookup('outer').get_namespace())

raw = _symtable.symtable(SOURCE, K('mod.py'), 'exec')
RESULT.append((raw.name, raw.type, raw.lineno, raw.nested, raw.optimized, raw.varnames, type(raw).__name__, type(raw).__module__))
RESULT.append(raw.symbols.items())
outer = [child for child in raw.children if child.name == 'outer'][0]
RESULT.append((outer.varnames, outer.nested, outer.optimized, outer.type, outer.symbols.items()))
RESULT.append([(child.name, child.lineno, child.nested, child.type) for child in outer.children])
RESULT.append([(child.name, child.optimized) for child in raw.children])
RESULT.append(err(setattr, raw, 'name', 'x'))
RESULT.append(err(type(raw)))
RESULT.append(err(type, 'Sub', (type(raw),), {}))
RESULT.append(repr(type(raw).name))

RESULT.append(sorted(
    (name, getattr(_symtable, name)) for name in dir(_symtable) if name.isupper()
))

expression = symtable.symtable(K('a + (lambda b: b)(c)'), K('<e>'), 'eval')
RESULT.append(table_info(expression))
RESULT.append([table_info(child) for child in expression.get_children()])
single = symtable.symtable(K('x = y\n'), K('<s>'), 'single')
RESULT.append(table_info(single))

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always')
    star = symtable.symtable(K('def f():\n    from os import *\n'), K('<star>'), 'exec')
RESULT.append([(w.category.__name__, str(w.message), w.filename, w.lineno) for w in caught])
RESULT.append([table_info(child) for child in star.get_children()])

with warnings.catch_warnings():
    warnings.simplefilter('error')
    RESULT.append(err(symtable.symtable, K('def f():\n    from os import *\n'), K('<star>'), 'exec'))
    RESULT.append(err(_symtable.symtable, K('x = 1\ndef f():\n    pass\n    from os import *\n'), K('<star2>'), 'exec'))

RESULT.append(err(_symtable.symtable, K('x'), K('f'), K('bad')))
RESULT.append(err(_symtable.symtable, K('def f(:'), K('f'), K('exec')))
RESULT.append(err(_symtable.symtable, K('def f(a, a): pass'), K('dup.py'), K('exec')))
RESULT.append(err(_symtable.symtable, K('def f(a):\n    global a\n'), K('g.py'), K('exec')))
RESULT.append(err(_symtable.symtable, K('def f():\n    exec "x"\n    def g():\n        return x\n'), K('e.py'), K('exec')))
RESULT.append(err(_symtable.symtable, K('x'), K('f')))
RESULT.append(err(_symtable.symtable, K('x'), K('f'), 3))
RESULT.append(err(_symtable.symtable, K('x\0'), K('f'), K('exec')))
RESULT.append(err(lambda: _symtable.symtable(K('x'), K('f'), K('exec'), k=1)))
RESULT.append(err(symtable.symtable, K('1 +'), K('bad.py'), 'exec'))
