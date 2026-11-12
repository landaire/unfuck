# parser.compilest and st.compile: code objects from parsed trees and from
# trees built with sequence2st, evaluated, with file names, future flags,
# source encodings, and the SyntaxErrors of the AST conversion.
import parser


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)


def run(st, **names):
    namespace = dict(names)
    exec st.compile() in namespace
    # The __future__ module is not among the case modules.
    for name in ('__builtins__', 'division', 'print_function', 'unicode_literals'):
        namespace.pop(name, None)
    return sorted(namespace.items())


def rename(st, old, new, line_info=False):
    root = st.tolist(line_info)
    pending = [root]
    while pending:
        node = pending.pop()
        if node[0] == 1 and node[1] == old:
            node[1] = new
        elif node[0] >= 256:
            pending.extend(node[1:])
    return root


program = K('''
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

class Box(object):
    """A box."""
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return 'Box(%r)' % (self.value,)

squares = [i * i for i in range(6) if i % 2]
pairs = dict((k, v) for k, v in zip('abc', range(3)))
try:
    1 / 0
except ZeroDivisionError as e:
    caught = type(e).__name__
total = sum(x for x in squares)
label = 'odd' if total % 2 else 'even'
result = (fib(10), Box([1, 2]), squares, pairs, caught, total, label)
''')

st = parser.suite(program)
code = st.compile()
rebuilt = parser.sequence2st(st.totuple(True))
plain = parser.sequence2st(st.totuple())
renamed = parser.sequence2st(rename(st, 'fib', 'fibonacci', True))

latin = parser.suite(K('# coding: latin-1\nx = "\xe9"\ny = u"\xe9"\n'))
utf8 = parser.suite(K('# coding: utf-8\nx = "\xc3\xa9"\ny = u"\xc3\xa9"\n'))
bom = parser.suite(K('\xef\xbb\xbfx = "\xc3\xa9"\ny = u"\xc3\xa9"\n'))
cp1252 = parser.suite(K('# coding: cp1252\nx = "\x80"\ny = u"\x80"\n'))
declared = parser.sequence2st((339, parser.suite(K('x = "\xc3\xa9"\ny = u"\xc3\xa9"\n')).totuple(), 'iso-8859-1'))

future_print = parser.suite(K('from __future__ import print_function\nprint(1, 2, sep="-")\n'))
future_division = parser.suite(K('from __future__ import division\nx = 1 / 2\n'))
future_unicode = parser.suite(K('from __future__ import unicode_literals\nx = "a"\n'))


printed = []


def fake_print(*args, **kwargs):
    printed.append((args, sorted(kwargs.items())))


exec future_print.compile() in {'print': fake_print}

RESULT = (
    eval(parser.expr(K('1 + 2 * 3')).compile()), eval(parser.compilest(parser.expr(K('[x * 2 for x in "ab"]')))),
    eval(parser.expr(K('a.upper() + b')).compile(), {'a': 'x', 'b': 'y'}),
    eval(parser.sequence2st(parser.expr(K('(lambda *a, **k: (a, sorted(k.items())))(1, 2, z=3)')).totuple()).compile()),
    run(st)[-1], run(rebuilt)[-1], run(plain)[-1], sorted(name for name, _ in run(renamed)),
    code.co_filename, code.co_name, code.co_firstlineno, code.co_names, code.co_flags,
    rebuilt.compile().co_firstlineno, plain.compile().co_firstlineno, plain.compile().co_consts[0].co_firstlineno,
    parser.compilest(st, 'prog.py').co_filename, parser.compilest(st, filename='f.py').co_filename,
    st.compile(filename='g.py').co_filename, parser.compileast(st, 'h.py').co_filename,
    parser.expr(K('x')).compile().co_flags, parser.suite(K('x\n')).compile().co_flags,
    run(latin), run(utf8), run(bom), run(cp1252), run(declared),
    future_print.compile().co_flags, future_division.compile().co_flags, future_unicode.compile().co_flags,
    run(future_division), run(future_unicode), printed,
    err(parser.suite(K('x = 1\n')).compile, 5), err(parser.suite(K('x = 1\n')).compile, 'a\0b'),
    err(parser.compilest), err(parser.compilest, 5), err(parser.compilest, st, 'a', 'b'),
    err(parser.suite(K('del f()\n')).compile), err(parser.suite(K('None = 1\n')).compile, 'n.py'),
    err(parser.suite(K('def f(x, x): pass\n')).compile), err(parser.suite(K('return 1\n')).compile),
    err(parser.suite(K('x = "\\x4"\n')).compile), err(parser.expr(K('(yield)')).compile),
    err(parser.suite, K('# coding: ascii\nx = "\xe9"\n')),
    err(parser.suite(K('# coding: latin-1\nx = u"\\N{nope}"\n')).compile),
    err(parser.suite(K('\n1 = 2\n')).compile), err(parser.sequence2st(parser.suite(K('\n1 = 2\n')).totuple(True)).compile),
    err(parser.sequence2st(parser.suite(K('\n1 = 2\n')).totuple()).compile),
    err(lambda: eval(parser.sequence2st(rename(parser.expr(K('name')), 'name', 'other name')).compile(), {'other name': 5})),
)
