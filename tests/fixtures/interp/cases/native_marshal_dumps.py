# marshal.dumps across versions 0-2.
import marshal


def K(x):
    return x


def t(f):
    try:
        return f()
    except Exception as e:
        return (type(e).__name__, str(e))


values = [
    None, True, False, Ellipsis, StopIteration,
    K(0), K(-1), K(2147483647), K(-2147483648), K(2147483648), K(-2147483649),
    K(0L), K(1L), K(-1L), K(32767L), K(32768L), K(2) ** 100, -K(2) ** 100,
    K(0.0), K(-0.0), K(0.1), K(1.5), K(1e300) * 10, -K(1e300) * 10, K(1e22), K(123456789.125),
    K(1j), complex(K(1.5), -K(2.0)),
    K(''), K('a'), K('ab'), K('hello world'), K('abc') + K('def'), intern(K('xy') + K('z')),
    K(u''), K(u'abc'), K(u'\xe9\u20ac'), K(u'\ud800'), K(u'\udc00x'),
    (), (K(1),), (K(1), K('ab'), K('ab')), [], [K(1), [K(2), [K(3)]]],
    {}, {K('a'): K(1)}, {K(1): K('x'), K('k'): [K(2)]},
    set(), set([K(1)]), frozenset(), frozenset([K('ab')]),
    [K('name'), K('name'), (K('name'), K('other'))],
]

RESULT = []
for value in values:
    RESULT.append([t(lambda: marshal.dumps(value, version)) for version in (0, 1, 2)])

RESULT.append(t(lambda: marshal.dumps(K(1.5), -1)))
RESULT.append(t(lambda: marshal.dumps(K(1.5), 5)))
RESULT.append(marshal.dumps(K(1)) == marshal.dumps(K(1), marshal.version))
RESULT.append(marshal.version)


class S(str):
    pass


class I(int):
    pass


class L(list):
    pass


import array
RESULT.append(t(lambda: marshal.dumps(S('xy'))))
RESULT.append(t(lambda: marshal.dumps(bytearray('ab'))))
RESULT.append(t(lambda: marshal.dumps(array.array('b', [1, 2, 3]))))
RESULT.append(t(lambda: marshal.dumps(I(5))))
RESULT.append(t(lambda: marshal.dumps(L())))
RESULT.append(t(lambda: marshal.dumps(object())))
RESULT.append(t(lambda: marshal.dumps([K(1), object(), K(2)])))
RESULT.append(t(lambda: marshal.dumps(NotImplemented)))
RESULT.append(t(lambda: marshal.dumps(len)))

deep = []
for i in range(2100):
    deep = [deep]
RESULT.append(t(lambda: marshal.dumps(deep)))
shallow = []
for i in range(1990):
    shallow = [shallow]
RESULT.append(len(t(lambda: marshal.dumps(shallow))))
recursive = []
recursive.append(recursive)
RESULT.append(t(lambda: marshal.dumps(recursive)))
mixed = [object()]
for i in range(2100):
    mixed = [mixed]
RESULT.append(t(lambda: marshal.dumps(mixed)))

RESULT.append(t(lambda: marshal.dumps()))
RESULT.append(t(lambda: marshal.dumps(1, 2, 3)))
RESULT.append(t(lambda: marshal.dumps(1, 'x')))
RESULT.append(t(lambda: marshal.dumps(1, 1.5)))
RESULT.append(t(lambda: marshal.dumps(1, version=2)))
RESULT.append(t(lambda: marshal.dump(1, None)))
RESULT.append(t(lambda: marshal.dump(1)))
RESULT.append(t(lambda: marshal.load(None)))
RESULT.append(t(lambda: marshal.load()))
