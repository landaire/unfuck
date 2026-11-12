# marshal.loads: round trips and malformed data.
import marshal


def K(x):
    return x


def t(f):
    try:
        return f()
    except Exception as e:
        return (type(e).__name__, str(e))


values = [
    None, True, False, Ellipsis, StopIteration, K(0), K(-5), K(2147483647), K(2) ** 100, -K(2) ** 70,
    K(2147483648), K(-2147483649), K(2) ** 62,
    K(1.5), K(-0.0), K(1e300) * 10, K(2j), K(''), K('ab'), K(u'\xe9x'), K(u'\ud800'),
    (K(1), (K(2),)), [K(1), K('a')], {K('a'): (K(1), K(2))}, set([K(1), K(2)]), frozenset([K(3)]),
]
RESULT = []
for value in values:
    for version in (0, 1, 2):
        loaded = marshal.loads(marshal.dumps(value, version))
        RESULT.append((type(loaded).__name__, repr(loaded) == repr(value)))

RESULT.append(marshal.loads(K('I\x05\x00\x00\x00\x00\x00\x00\x00')))
RESULT.append(marshal.loads(K('I\x00\x00\x00\x80\x00\x00\x00\x00')))
RESULT.append(marshal.loads(K('I\xff\xff\xff\x7f\xff\xff\xff\xff')))
RESULT.append(marshal.loads(K('I\x01')))
RESULT.append(marshal.loads(K('i\x01')))
RESULT.append(marshal.loads(K('N trailing')))
RESULT.append(marshal.loads(K(u'N')))
RESULT.append(marshal.loads(K('t\x01\x00\x00\x00aR\x00\x00\x00\x00')))
RESULT.append(marshal.loads(K('(\x02\x00\x00\x00t\x02\x00\x00\x00abR\x00\x00\x00\x00')))
RESULT.append(marshal.loads(K('f\x041e99999')))
RESULT.append(marshal.loads(K('f\x021\x00')))
RESULT.append(marshal.loads(K('f\x03inf')))
RESULT.append(marshal.loads(K('x\x011\x02-2')))
RESULT.append(marshal.loads(K('l\x02\x00\x00\x00\x01\x00\x01\x00')))
RESULT.append(marshal.loads(K('l\xfe\xff\xff\xff\xff\x7f\x01\x00')))
RESULT.append(marshal.loads(K('{N[\x01\x00\x00\x00N0')))

bad = [
    '', '0', 'Z', 'i', 'f\x05abc', 'g\x00\x00', 'y\x00', 'fx', 'f\x03abc', 'f\x05 1.0 ',
    'x\x011\x01q', 's\xff\xff\xff\xff', 's\x05\x00\x00\x00ab', 's\xff\xff\xff\x7f',
    't\xff\xff\xff\xff', 'u\xff\xff\xff\xff', 'u\x01\x00\x00\x00\xff', 'u\x02\x00\x00\x00\xc3',
    'R\x00\x00\x00\x00', 't\x01\x00\x00\x00aR\x01\x00\x00\x00',
    '(\xff\xff\xff\xff', '(\x01\x00\x00\x000', '(\x02\x00\x00\x00N', '[\xff\xff\xff\xff',
    '[\x01\x00\x00\x000', '<\xff\xff\xff\xff', '<\x01\x00\x00\x000', '<\x01\x00\x00\x00[\x00\x00\x00\x00',
    '>\x01\x00\x00\x00{0', '<\xff\xff\xff\x7f',
    'l\x00\x00\x00\x80', 'l\x02\x00\x00\x00\x01\x00', 'l\x01\x00\x00\x00\x00\x80',
    'l\x01\x00\x00\x00\x00\x00', 'l\xff\xff\xff\x7f',
    '{', '{N', '{[\x00\x00\x00\x00N[\x00\x00\x00\x00Ni\x01\x00\x00\x00',
    '{[\x00\x00\x00\x00NZ0', '{(\x01\x00\x00\x00ZNi\x02\x00\x00\x00Z',
    'c\x00\x00\x00\x00', 'c' + '\x00' * 16 + 's\x00\x00\x00\x00N',
    'c' + '\x00' * 16 + 's\x00\x00\x00\x000',
    '?', '\xff', 'S',
]
for data in bad:
    RESULT.append((data, t(lambda: marshal.loads(data))))

deep = '(\x01\x00\x00\x00' * 2001 + 'N'
RESULT.append(t(lambda: marshal.loads(deep)))
RESULT.append(len(marshal.loads('(\x01\x00\x00\x00' * 1999 + 'N')))

RESULT.append(t(lambda: marshal.loads()))
RESULT.append(t(lambda: marshal.loads(1)))
RESULT.append(t(lambda: marshal.loads(bytearray('N'))))
RESULT.append(t(lambda: marshal.loads('N', 'N')))
RESULT.append(t(lambda: marshal.loads(s='N')))
