# parser.sequence2st of valid and invalid trees: the ParserError messages of
# the build and of the validate_* functions. Trees CPython 2.7.12 handles
# with an exception left pending (missing encodings, unsized sequences) are
# not asserted.
import parser


def K(value):
    return value


def err(f, *a, **k):
    try:
        result = f(*a, **k)
    except Exception as e:
        return (type(e).__name__, e.args)
    return ('st', result.totuple(True), result.isexpr())


def tree(source, expression=False):
    st = parser.expr(source) if expression else parser.suite(source)
    return st.tolist()


def at(node, path):
    for index in path:
        node = node[index]
    return node


def mutate(source, changes, expression=False):
    # changes: (path, value) pairs; a value of None deletes the node.
    root = tree(source, expression)
    for path, value in changes:
        parent = at(root, path[:-1])
        if value is None:
            del parent[path[-1]]
        else:
            parent[path[-1]] = value
    return err(parser.sequence2st, root)


def find(root, kind, text=None):
    # Path of the first node of the given type (and text) in preorder.
    pending = [(root, ())]
    while pending:
        node, path = pending.pop()
        if node[0] == kind and (text is None or node[1] == text):
            return path
        if node[0] >= 256:
            for index in range(len(node) - 1, 0, -1):
                pending.append((node[index], path + (index,)))
    return None


def replace(source, kind, text, value, expression=False):
    root = tree(source, expression)
    return mutate(source, [(find(root, kind, text), value)], expression)


def retype(source, kind, new_kind, text=None, expression=False):
    root = tree(source, expression)
    path = find(root, kind, text)
    node = at(root, path)
    node[0] = new_kind
    return err(parser.sequence2st, root)


def drop(source, kind, index, expression=False):
    root = tree(source, expression)
    path = find(root, kind)
    return mutate(source, [(path + (index,), None)], expression)


ENDMARKER = (0, '')
NEWLINE = (4, '')
name = lambda text: (1, text)

build = [
    err(parser.sequence2st, ()), err(parser.sequence2st, (1,)), err(parser.sequence2st, ('a',)),
    err(parser.sequence2st, (-3,)), err(parser.sequence2st, (255,)), err(parser.sequence2st, (1000,)),
    err(parser.sequence2st, (257.5,)), err(parser.sequence2st, (258.9, NEWLINE, ENDMARKER)),
    err(parser.sequence2st, (2 ** 70,)), err(parser.sequence2st, (257L, ENDMARKER)),
    err(parser.sequence2st, (True,)), err(parser.sequence2st, (257,)), err(parser.sequence2st, (258,)),
    err(parser.sequence2st, (257, 5)), err(parser.sequence2st, (257, ('x',))), err(parser.sequence2st, (257, ())),
    err(parser.sequence2st, (257, (1,))), err(parser.sequence2st, (257, (1, 'a', 1, 1))),
    err(parser.sequence2st, (257, (1, 5))), err(parser.sequence2st, (257, (1, u'a'))),
    err(parser.sequence2st, (257, (1, 'a', 'b'))), err(parser.sequence2st, (257, (1, 'a', 5L))),
    err(parser.sequence2st, (257, (1, 'a', 1.0))), err(parser.sequence2st, (257, (900, 'a'))),
    err(parser.sequence2st, (257, ENDMARKER)), err(parser.sequence2st, [257, [4, ''], [0, '']]),
    err(parser.sequence2st, (257, (0, '', 7))), err(parser.sequence2st, (257, (0, '', True))),
    err(parser.sequence2st, (257, (0, 'abc\0def'))), err(parser.sequence2st, (257, {})),
    err(parser.sequence2st, (257, 'ab')), err(parser.sequence2st, (257, (1L, 'a'))),
    err(parser.sequence2st, (258, NEWLINE, ENDMARKER)), err(parser.sequence2st, (300, NEWLINE, ENDMARKER)),
    err(parser.sequence2st, (339, (257, ENDMARKER), 'utf-8')), err(parser.sequence2st, (339, (257, ENDMARKER), 'x\0y')),
    err(parser.sequence2st, (339, (257, NEWLINE), 'utf-8')), err(parser.sequence2st, (339, (258, ENDMARKER), 'latin-1')),
    err(parser.sequence2st, (339, (257, ENDMARKER), 'a', 'b')),
    err(parser.sequence2st, 5), err(parser.sequence2st, None), err(parser.sequence2st, {257: 1}),
    err(parser.sequence2st), err(parser.sequence2st, (257, ENDMARKER), 1), err(parser.sequence2st, sequence=(257, ENDMARKER)),
    err(parser.tuple2st, (257, NEWLINE, NEWLINE, ENDMARKER)), err(parser.sequence2ast, (258, (1, 'x'))),
    err(parser.tuple2ast, (257, (267,), ENDMARKER)), err(parser.sequence2st, (257, (300, (4, '')), ENDMARKER)),
]

validate = [
    replace('if a:\n    pass\n', 1, 'if', name('iff')),
    replace('if a:\n    pass\nelse:\n    pass\n', 1, 'else', name('elsee')),
    replace('if a:\n    pass\nelif b:\n    pass\n', 1, 'elif', name('el')),
    drop('if a:\n    pass\n', 293, 4),
    drop('if a:\n    pass\nelif b:\n    pass\n', 293, 7),
    replace('x = 1\n', 22, None, (11, ':')),
    replace('x = 1\n', 22, None, (22, '==')),
    replace('x += 1\n', 37, None, (14, '+')),
    replace('x = 1\n', 270, None, [304, [2, '1']]),
    retype('x = 1\n', 270, 304),
    retype('x = 1\n', 268, 292),
    retype('if a: pass\n', 293, 300),
    retype('a is b\n', 1, 1, 'is'),
    replace('a is b\n', 1, 'is', name('isnt')),
    replace('a < b\n', 20, None, (14, '+')),
    replace('a < b\n', 309, None, [309, name('not'), name('is')]),
    replace('a < b\n', 309, None, [309, (20, '<'), (20, '<')]),
    replace('f(x for x in y)\n', 330, None, [330, [331, [304, [305, [306, [307, [308, [310, [311, [312, [313, [314, [315, [316, [317, [318, name('x')]]]]]]]]]]]]]], [336, name('for'), [326, [310, [311, [312, [313, [314, [315, [316, [317, [318, name('x')]]]]]]]]]], name('in'), [305, [306, [307, [308, [310, [311, [312, [313, [314, [315, [316, [317, [318, name('y')]]]]]]]]]]]]]]], (12, ','), [331, [304, [305, [306, [307, [308, [310, [311, [312, [313, [314, [315, [316, [317, [318, name('z')]]]]]]]]]]]]]]]]),
    drop('f(*a)\n', 330, 1),
    replace('f(*a)\n', 16, None, (36, '**')),
    replace('f(**a)\n', 36, None, (16, '*')),
    replace('def f(a, b): pass\n', 12, None, (13, ';')),
    replace('def f(a, *b): pass\n', 16, None, (36, '**')),
    replace('def f(a=1): pass\n', 22, None, (11, ':')),
    drop('def f(a): pass\n', 263, 2),
    replace('def f(a): pass\n', 1, 'def', name('fed')),
    replace('class C: pass\n', 1, 'class', name('klass')),
    drop('class C(B): pass\n', 329, 3),
    replace('try:\n    pass\nfinally:\n    pass\n', 1, 'finally', name('final')),
    drop('try:\n    pass\nexcept:\n    pass\n', 296, 3),
    drop('try:\n    pass\nfinally:\n    pass\n', 296, 3),
    drop('try:\n    pass\nexcept A:\n    pass\n', 299, 2),
    replace('try:\n    pass\nexcept A, e:\n    pass\n', 12, None, (11, ':')),
    replace('while a:\n    pass\n', 1, 'while', name('whilst')),
    replace('for a in b:\n    pass\n', 1, 'in', name('on')),
    replace('with a as b:\n    pass\n', 1, 'as', name('to')),
    replace('@d\ndef f(): pass\n', 50, None, (16, '*')),
    replace('global a, b\n', 12, None, (13, ';')),
    drop('global a\n', 289, 2),
    drop('exec a in b\n', 290, 3),
    drop('assert a, b\n', 291, 4),
    replace('print >> a, b\n', 35, None, (34, '<<')),
    drop('print >> a\n', 272, 3),
    replace('del a\n', 1, 'del', name('dl')),
    replace('return a\n', 1, 'return', name('ret')),
    drop('raise a, b\n', 280, 4),
    replace('import a.b as c\n', 1, 'as', name('az')),
    replace('import a, b\n', 12, None, (13, ';')),
    replace('from a import (b, c)\n', 8, None, (27, '}')),
    replace('from a import b as c\n', 1, 'as', name('az')),
    replace('from . import b\n', 1, 'import', name('imp')),
    replace('x = [a, b]\n', 12, None, (13, ';')),
    replace('x = [a for b in c]\n', 1, 'for', name('fr')),
    replace('x = [a for b in c if d]\n', 1, 'if', name('iff')),
    replace('x = (a for b in c)\n', 1, 'in', name('inn')),
    replace('x = {a: b, c: d}\n', 11, None, (12, ',')),
    replace('x = {a, b}\n', 12, None, (11, ':')),
    replace('x = {a: b for c in d}\n', 11, None, (12, ',')),
    replace('x = a[1:2:3]\n', 11, None, (12, ',')),
    replace('x = a[...]\n', 23, None, (11, ':')),
    replace('x = a.b\n', 23, None, (12, ',')),
    replace('x = a ** b\n', 36, None, (16, '*')),
    replace('x = a * b\n', 16, None, (14, '+')),
    replace('x = a + b\n', 14, None, (16, '*')),
    replace('x = a << b\n', 34, None, (14, '+')),
    replace('x = a & b\n', 19, None, (18, '|')),
    replace('x = a ^ b\n', 33, None, (19, '&')),
    replace('x = a | b\n', 18, None, (33, '^')),
    replace('x = -a\n', 15, None, (16, '*')),
    replace('x = not a\n', 1, 'not', name('nt')),
    replace('x = a or b\n', 1, 'or', name('orr')),
    replace('x = a and b\n', 1, 'and', name('nd')),
    replace('x = a if b else c\n', 1, 'else', name('els')),
    replace('x = lambda: a\n', 1, 'lambda', name('lam')),
    replace('x = `a`\n', 25, None, (7, '(')),
    replace('x = ()\n', 8, None, (9, '[')),
    replace('x = (yield a)\n', 1, 'yield', name('yld')),
    replace('pass\n', 1, 'pass', name('pas')),
    replace('while 1: break\n', 1, 'break', name('brk')),
    replace('while 1: continue\n', 1, 'continue', name('cont')),
    replace('x = 1; y = 2\n', 13, None, (12, ',')),
    replace('x = 1\n', 4, None, (11, ':')),
    replace('if a:\n    pass\n', 5, None, (6, '')),
    replace('if a:\n    pass\n', 6, None, (6, 'x')),
    drop('if a:\n    pass\n', 300, 2),
    replace('a, b = c\n', 12, None, (13, ';')),
    replace('x = "a" "b"\n', 3, '"b"', (2, '1')),
    replace('x = [1, 2]\n', 9, None, (7, '(')),
    replace('a + 1', 14, None, (16, '*'), True),
    replace('a + 1', 4, None, (0, ''), True),
]

RESULT = (build, validate)
