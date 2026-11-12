# parser.expr/suite trees in tuple and list form, with line and column
# information, round trips through sequence2st, comparisons, and the
# module's attributes. col_info without line_info is not asserted: 2.7.12
# leaves items of the result unset.
import copy
import parser


def K(value):
    return value


def err(f, *a, **k):
    try:
        result = f(*a, **k)
    except Exception as e:
        return (type(e).__name__, e.args)
    if isinstance(result, parser.STType):
        return ('st', result.totuple(True))
    return ('ok', result)


sources = [
    K('x = 1\n'),
    K('if a:\n    b = [i for i in c if i]\nelif d:\n    pass\nelse:\n    e = {1: 2}\n'),
    K('def f(a, (b, c)=d, *e, **g):\n    """doc"""\n    return lambda x=1: x ** -2\n'),
    K('class C(B):\n    @dec(1)\n    def m(self): yield self[1:2, ...]\n'),
    K('try:\n    import os.path as p, sys\nexcept (A, B) as e:\n    raise\nfinally:\n    from . import x\n'),
    K('with a as b, c:\n    print >> f, 1, 2,\n    exec "x" in g\n'),
    K('while 1:\n\tfor x, in y: continue\n\tbreak\nelse: del a[0], b.c\n'),
    K('global a, b; assert x, "m"; x += `y`; z = a if b else c; q = {1, 2}\n'),
    K('x = 1'),
    K('\n\n# comment\n'),
]
expressions = [K('1'), K('a + b * -c'), K('(yield)'), K('f(*a, **k)'), K('a < b <= c is not d not in e'), K('x[::2], y'), K('"a" "b" u"c"'), K('{a: b for a in c}')]

suites = [parser.suite(source) for source in sources]
exprs = [parser.expr(source) for source in expressions]

roundtrips = []
for st in suites + exprs:
    plain = st.totuple()
    lined = st.totuple(True)
    listed = st.tolist(line_info=True)
    rebuilt = parser.sequence2st(plain)
    relined = parser.tuple2st(lined)
    from_list = parser.sequence2st(listed)
    roundtrips.append((
        rebuilt == st, relined == st, from_list == st, rebuilt.totuple() == plain,
        relined.totuple(True) == lined, from_list.isexpr(), from_list.issuite(),
        rebuilt.totuple(True) == lined,
    ))

latin = parser.suite(K('# -*- coding: latin-1 -*-\nx = "\xe9"\n'))
utf8 = parser.suite(K('# coding: utf-8\nx = u"\xc3\xa9"\n'))
utf8_short = parser.expr(K('# coding: utf8\n"a"\n'))
bom = parser.suite(K('\xef\xbb\xbfx = 1\n'))

ordering = [
    cmp(parser.expr('a'), parser.expr('b')), cmp(parser.expr('b'), parser.expr('a')),
    cmp(parser.expr('a'), parser.expr('a.b')), cmp(parser.expr('1'), parser.suite('1')),
    cmp(parser.suite('x\n'), parser.suite('x\ny\n')), cmp(parser.expr('aa'), parser.expr('a')),
    parser.expr('1') == parser.expr('1'), parser.expr('1') != parser.expr('2'),
    parser.expr('1') < parser.expr('2'), parser.expr('1') == 1, parser.expr('1') == None,
    parser.expr('1') > None, latin == parser.sequence2st(latin.totuple()),
]

# The deepest parenthesized expression the parser accepts; tuple forms
# only, as dropping nested lists that deep exhausts the harness stack.
deep = parser.expr(K('(' * 98 + 'x' + ')' * 98))
deep_rebuilt = parser.sequence2st(deep.totuple(True))
deep_checks = (
    deep_rebuilt == deep, eval(deep_rebuilt.compile(), {'x': 3}), deep.__sizeof__(), deep_rebuilt.__sizeof__(),
    cmp(deep, parser.expr(K('(' * 98 + 'y' + ')' * 98))), err(parser.expr, K('(' * 99 + 'x' + ')' * 99)),
)

RESULT = (
    suites[0].totuple(), suites[0].totuple(1, 1), suites[1].tolist(True, True),
    suites[2].totuple(line_info=1, col_info=1), suites[8].totuple(True, True), suites[9].totuple(True, True),
    exprs[1].tolist(), exprs[0].totuple(True, True), exprs[6].totuple(True), parser.st2tuple(exprs[2], True),
    parser.st2list(ast=exprs[3], line_info=1), parser.ast2tuple(exprs[4]), parser.ast2list(exprs[5], 0, 0),
    roundtrips, deep_checks,
    latin.totuple(True), utf8.totuple(), utf8_short.totuple(), bom.totuple(),
    parser.sequence2st(latin.totuple()).totuple(), latin.issuite(), utf8_short.isexpr(),
    [parser.isexpr(st) for st in exprs[:2] + suites[:2]], [parser.issuite(st) for st in exprs[:2] + suites[:2]],
    ordering,
    exprs[0].__sizeof__(), suites[0].__sizeof__(), latin.__sizeof__(), parser.sequence2st(suites[1].totuple()).__sizeof__(),
    copy.copy(suites[1]) == suites[1], copy.copy(exprs[1]).totuple(True) == exprs[1].totuple(True),
    parser._pickler(exprs[0])[1], parser._pickler(exprs[0])[0] is parser.sequence2st,
    err(parser._pickler, 1), err(parser._pickler), err(parser._pickler, exprs[0], x=1),
    err(parser.expr, K('a +')), err(parser.suite, K('def f(:\n  pass')), err(parser.suite, K('if 1:\npass\n')),
    err(parser.suite, K('  x = 1\n')), err(parser.expr, K('"abc')), err(parser.suite, K('x = 1\n\ty = 2\n')),
    err(parser.expr), err(parser.expr, 5), err(parser.expr, 'a\0b'), err(parser.expr, u'1 + 1'),
    err(parser.expr, source='x'), err(parser.suite, 'x', 'y'), err(parser.expr, src='x'),
    err(parser.st2tuple), err(parser.st2tuple, 1), err(parser.st2list, exprs[0], 1, 2, 3),
    err(exprs[0].totuple, 1, 2, 3), err(exprs[0].isexpr, 1), err(parser.isexpr, 5), err(parser.issuite),
    err(parser.STType.totuple, 5), err(parser.STType), err(hash, exprs[0]),
    err(type, 'X', (parser.STType,), {}),
    parser.STType is parser.ASTType, parser.STType.__name__, parser.STType.__module__,
    parser.__version__, parser.ParserError.__module__,
    parser.ParserError.__mro__[1:] == (Exception, BaseException, object), parser.ParserError.__name__,
)
