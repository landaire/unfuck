# Prints, as JSON lines, the results CPython 2.7.18 gives for the object
# operations the peephole optimizer folds. The `compiler::fold` test
# `matches_cpython` runs it:
#
#   PYTHON27=python2.7 cargo test --lib compiler::fold -- --ignored
#
# Operands are built at run time so that neither the peephole optimizer nor
# PyCode_New touches them. Each line is one case:
#   {"k": "bin", "op": ..., "l": obj, "r": obj, "res": obj or null,
#    "same": operands the result is identical to ("l", "r"),
#    "w": deprecation warnings issued}
#   {"k": "un", "op": ..., "x": obj, "res": obj or null}
#   {"k": "float", "v": bits, "code": c, "prec": n, "alt": b, "res": text}
# An object is ["none"], ["ellipsis"], ["int", decimal], ["long", decimal],
# ["float", bits], ["complex", bits, bits], ["str", hex, interned],
# ["unicode", [utf-16 units]], or ["tuple", [objects]]; bits are the
# big-endian IEEE 754 bytes in hex. "res" is null where CPython raises.

import json
import operator
import random
import struct
import sys
import warnings

INF = float('inf')
NAN = float('nan')

def bits(value):
    return struct.pack('>d', value).encode('hex')

def is_interned(value):
    if len(value) == 0:
        return value is ''
    if len(value) == 1:
        return value is chr(ord(value))
    return intern(value[:1] + value[1:]) is value

def encode(value):
    if value is None:
        return ['none']
    if value is Ellipsis:
        return ['ellipsis']
    kind = type(value)
    if kind is int:
        return ['int', str(value)]
    if kind is long:
        return ['long', str(value)]
    if kind is float:
        return ['float', bits(value)]
    if kind is complex:
        return ['complex', bits(value.real), bits(value.imag)]
    if kind is str:
        return ['str', value.encode('hex'), is_interned(value)]
    if kind is unicode:
        data = value.encode('utf-16-le')
        return ['unicode', list(struct.unpack('<%dH' % (len(data) // 2), data))]
    if kind is tuple:
        return ['tuple', [encode(item) for item in value]]
    raise TypeError(kind)

def S(value, interned):
    """A str operand with the given interning, built at run time."""
    if interned:
        return intern(value[:1] + value[1:])
    if len(value) == 0:
        # string_repeat allocates a fresh, uninterned empty string.
        return 'x' * (len(sys.argv) - 1)
    return '%s' % value

def fresh(value):
    return S(value, False)

BINARY = [
    ('power', pow),
    ('multiply', operator.mul),
    ('true_divide', operator.truediv),
    ('floor_divide', operator.floordiv),
    ('modulo', operator.mod),
    ('add', operator.add),
    ('subtract', operator.sub),
    ('subscript', operator.getitem),
    ('lshift', operator.lshift),
    ('rshift', operator.rshift),
    ('and', operator.and_),
    ('xor', operator.xor),
    ('or', operator.or_),
]
ARITHMETIC = BINARY[:7]
BINARY_BY_NAME = dict(BINARY)

UNARY = [
    ('negative', operator.neg),
    ('convert', repr),
    ('invert', operator.invert),
]

out = sys.stdout

def emit(record):
    out.write(json.dumps(record, sort_keys=True, separators=(',', ':')))
    out.write('\n')

def huge(name, left, right):
    integral = (int, long)
    if type(left) not in integral or type(right) not in integral:
        return False
    if name == 'power':
        return abs(left) > 1 and right > 0 and right * left.bit_length() > 2 ** 24
    if name == 'lshift':
        return left != 0 and right > 2 ** 24
    return False

def binary_case(name, left, right):
    if huge(name, left, right):
        # CPython spends minutes or runs out of memory; fold.rs treats
        # results above 2**24 bits as a MemoryError instead.
        return
    function = BINARY_BY_NAME[name]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        try:
            result = function(left, right)
        except Exception:
            result = None
            raised = True
        else:
            raised = False
    warned = len([w for w in caught if w.category is DeprecationWarning])
    same = []
    if not raised:
        same = [side for side, operand in (('l', left), ('r', right)) if result is operand]
    emit({'k': 'bin', 'op': name, 'l': encode(left), 'r': encode(right),
          'res': None if raised else encode(result), 'same': same, 'w': warned})

def unary_case(name, function, operand):
    try:
        result = function(operand)
    except Exception:
        result = None
        raised = True
    else:
        raised = False
    emit({'k': 'un', 'op': name, 'x': encode(operand),
          'res': None if raised else encode(result)})

def all_ops(values, ops):
    for left in values:
        for right in values:
            for name, _ in ops:
                binary_case(name, left, right)

MAXINT = sys.maxint
INTS = [0, 1, -1, 2, 7, 64, 2 ** 31 - 1, -2 ** 31, 3037000499, -3037000500,
        MAXINT, -MAXINT - 1]
LONGS = [0L, -1L, 5L, -7L, 2 ** 64, -(2 ** 64) - 1, 10 ** 30, 2 ** 53 + 1, 2 ** 63]
FLOATS = [0.0, -0.0, 1.5, -2.5, 3.0, 1e308, 5e-324, INF, -INF, NAN, 0.1]
COMPLEXES = [0j, 1 + 2j, -1.5 - 0.5j, 2j, complex(INF, 0.0), complex(1e308, 1e308),
             complex(-0.0, -0.0), complex(NAN, 1.0), complex(-1.0, 1e-300)]
MIXED = [0, 3, -2, MAXINT, 0L, -(2 ** 70), 2 ** 1100, 0.0, -0.0, 2.5, INF, NAN,
         0j, 1 - 1j, complex(0.5, -0.0)]

all_ops(INTS, BINARY)
all_ops([0, 3, -5, 64, MAXINT, 2 ** 64, -(2 ** 70), 7L, 0L, -1L], BINARY[8:])
all_ops([3, 7L, -7L, 2 ** 64 + 3, -(2 ** 64) - 3, 10 ** 30], [('power', pow), ('true_divide', None), ('floor_divide', None), ('modulo', None), ('multiply', None)])
all_ops(LONGS, ARITHMETIC)
all_ops(FLOATS, ARITHMETIC)
all_ops(COMPLEXES, ARITHMETIC)
all_ops(MIXED, ARITHMETIC)

for base in [2, -2, 3, -3, 10, 2 ** 31, MAXINT, 2L, -1, 1, 0, 0L, -1L]:
    for exponent in [0, 1, 2, 31, 32, 62, 63, 64, 65, 100, -1, -2, 2 ** 64, 0.5, -0.5]:
        binary_case('power', base, exponent)

for base in [2.0, -2.0, 0.5, 10.0, -1.0, 1.0, 1e-300, 1.0000001, -8.0]:
    for exponent in [2.0, -2.0, 0.5, 1e10, -1e10, 400.0, -400.0, 1075.0, -1075.0, 3.0, 1e300, INF, -INF, NAN]:
        binary_case('power', base, exponent)

for base in [1 + 1j, 2j, -1 + 1e-300j, 1e-200j, 1e200 + 1e200j, 0j, 2 + 0j]:
    for exponent in [0, 1, 2, 3, -1, -2, 100, 101, -101, 1e308, 0.5, 1j, 1e308j, 1 + 1j, -1 + 0j, complex(1e10, 0.0)]:
        binary_case('power', base, exponent)

for left in [(1 << 62), 3, -1, 7L, 0, 1L]:
    for right in [0, 1, 31, 32, 63, 64, 100, -1, 2 ** 64, -(2 ** 64)]:
        binary_case('lshift', left, right)
        binary_case('rshift', left, right)

for numerator in [1, -1, 10 ** 400, -(10 ** 400), 2 ** 1100 + 1, 3, 7, 10 ** 20, 0, 2 ** 1074]:
    for denominator in [3, -3, 10 ** 400, 2 ** 1100, 2 ** 2000, 7, 10 ** 20 + 1, -1, 2 ** 1074, 2 ** 1075, 0]:
        binary_case('true_divide', numerator, denominator)
        binary_case('true_divide', long(numerator), long(denominator))

STRS = [S('', True), S('', False), S('a', True), S('a', False), S('ab', True),
        S('ab', False), S('a b', False), S("it's", False), S('\x00\xff', False),
        S('0123456789', False)]
UNICODES = [u'', u'a', u'\xe9t\xe9', u'\u20ac', u'\ud800', u'\ud800\udc00x']
TUPLES = [(), (1,), (S('a b', False), 2.5), ((1, 2), (3,)), (None, Ellipsis)]
COUNTS = [-1, 0, 1, 2, 3, 7, 10, 21, 2L, 2 ** 64, -(2 ** 64), MAXINT, 2.0, S('2', True)]
INDEXES = [0, 1, -1, 2, -2, 5, -5, 1L, -1L, 2 ** 64, -(2 ** 64), 0.0, S('0', True)]

for sequence in STRS + UNICODES + TUPLES:
    for count in COUNTS:
        binary_case('multiply', sequence, count)
        binary_case('multiply', count, sequence)
    for index in INDEXES:
        binary_case('subscript', sequence, index)
    for other in STRS + UNICODES + TUPLES + [1, None]:
        binary_case('add', sequence, other)
    for name in ['power', 'subtract', 'true_divide', 'floor_divide', 'lshift', 'and']:
        binary_case(name, sequence, sequence)
        binary_case(name, sequence, 2)

binary_case('add', S('\xe9', False), u'a')
binary_case('add', u'a', S('\xe9', False))
binary_case('add', S('a b', False), S('c d', False))
binary_case('add', S('0123456789', False), S('01234567890', False))
binary_case('add', S('0123456789', False), S('0123456789x', False))

for operand in [None, Ellipsis, 0, 1, -1, 7, -MAXINT - 1, MAXINT, 2 ** 64, -(2 ** 64), 0L, 5L,
                0.0, -0.0, 1.5, -2.5, 0.1, 1e16, 1e-5, 1e22, 123456789.0, 5e-324, INF, -INF, NAN,
                0j, 1j, -1j, 1 + 2j, -1.5 - 0.5j, complex(-0.0, 0.0), complex(0.0, -0.0), complex(INF, NAN),
                complex(1e16, 1e-5)] + STRS + [S('\t\n\r\\"\'', False), S("'", False), S('"', False),
                S('\x7f\x80\x1f', False)] + UNICODES + [u'\'"', u"'", u'\\\t\n\r\x00\x7f\xff\u0100\uffff',
                u'\U0001f600', u'\ud800\ud800', u'\udc00', u'x\ud800'] + TUPLES + [(1,), ((),), (2 ** 64, 1j, u'u')]:
    for name, function in UNARY:
        unary_case(name, function, operand)

FORMATS = [
    ('%s', [S('abc', False), 5, -5, 2 ** 64, 1.5, 1e100, 0.1, 1 + 2j, 3j, None, Ellipsis, (1, 2), (S('x', True),),
            (), (1,), ((1, 2),), (u'u',), u'abc', (u'\xe9',), (S('\xe9', False),), 1e16, -0.0]),
    ('%r', [S('a', True), 5, 2 ** 64, 1.5, u'\xe9', (1,), (S("'", False),), 1j]),
    ('%d', [5, -5, 2 ** 64, -(2 ** 64), 3.99, -3.99, 1e20, INF, NAN, 1j, S('5', True), None, (5,), 2 ** 63 - 1.0]),
    ('%i|%u', [(5, -5), (2 ** 64, -(2 ** 64)), (0, 0L)]),
    ('%x %X %o', [(255, 255, 8), (-255, -255, -8), (255L, 255L, 8L), (-255L, -255L, -8L), (0, 0L, 0), (-MAXINT - 1, -MAXINT - 1, -MAXINT - 1)]),
    ('%#x|%#X|%#o', [(255, 255, 8), (-255L, 0L, 0), (0, 0, 0L), (0L, -1, 1L)]),
    ('%+d|% d|%05d', [(5, 5, -5), (-5, -5, 5), (0, 0L, -0.5)]),
    ('%-5d|%5s|%-3s|', [(1, S('ab', True), S('x', True))]),
    ('%.3d|%.0d|%.0x|%#.0o|%#.3o', [(5, 0, 0, 0, 8), (-5, 0L, 0L, 0L, 8L)]),
    ('%#08x|%08X|%-#8o|', [(-255, 255, 8), (255L, -255L, 8L)]),
    ('%*d|%-*d', [(5, 3, 4, 2), (-5, 3, 2, 1), (5L, 3, 1, 1), (1.0, 3, 1, 1)]),
    ('%.*f|%.*s', [(2, 3.14159, 1, S('ab', True)), (-1, 2.5, 0, S('ab', True)), (2L, 1.0, 1, S('a', True))]),
    ('%e|%E|%f|%F', [(1.5, 1.5, 1.5, 1.5), (INF, -INF, NAN, INF), (1e300, 1e-300, 1e-7, 7)]),
    ('%g|%G', [(0.0001, 1e-5), (123456.0, 1234567.0), (1e16, 1L), (NAN, -INF), (-0.0, 5)]),
    ('%.0f|%.0e|%#.0f|%#.0e', [(0.5, 0.5, 0.5, 0.5), (1.5, 2.5, 2.5, 1.5), (-0.4, 9.5, 0.4, 0.0)]),
    ('%.2f|%.3g|%#.3g', [(0.125, 0.0001234, 1.0), (0.005, 12345.0, 0.0), (2 ** 64, 1e-10, 100.0)]),
    ('%f', [1e60, 1e15, 1.0, 2.0 ** 70]),
    ('%c', [65, 255, 256, -1, 65L, 65.0, S('a', True), S('ab', True), u'\xe9', u'a', None, 2 ** 64]),
    ('%c%c', [(97, u'b'), (u'b', 97)]),
    ('%5%|%-5%|%%', [()]),
    ('%5%%', [()]),
    ('%', [()]),
    ('%.', [()]),
    ('%(a)s', [5, (1,), S('a', True)]),
    ('%s %s', [5, (1,), (1, 2), (1, 2, 3)]),
    ('abc', [(), 5, (1,), S('', True), u'']),
    ('', [()]),
    ('%s%s', [(S('a', True), u'b'), (u'a', S('b', True)), (u'a', 2 ** 64)]),
    ('\xe9%s', [(u'x',), (S('x', True),)]),
    ('x%s\xe9', [(u'x',)]),
    ('%-*s|', [(3, u'a'), (-2, u'b')]),
    ('%y', [5]),
    ('%ld|%hd|%Ld', [(1, 2, 3)]),
    ('%s', [(1, 2)]),
    ('%10s', [u'a', S('a', True)]),
    ('%.117d', [1]),
    ('%.116d', [1]),
    ('%.30d', [2 ** 64]),
    ('%099999999999999999999d', [1]),
    ('%.99999999999d', [1]),
    ('%.1000g', [0.1]),
    ('%.1000f', [0.1]),
    ('%x', [1.5, -2.5, 1e20, 1j]),
    ('%o|%x', [(8.0, 255.9)]),
    ('%c', [0x41]),
]

for template, arguments in FORMATS:
    for argument in arguments:
        binary_case('modulo', fresh(template) if template else S('', True), argument)
        if not any(ord(c) > 127 for c in template):
            binary_case('modulo', unicode(template), argument)

for argument in [u'\uffff', 0xffff, 0x10000, 65.7, -1, 2 ** 64, S('\xe9', False), S('a', True), 1j]:
    binary_case('modulo', u'%c', argument)

binary_case('modulo', S('%s', False), u'\xe9')
binary_case('modulo', u'%s|%r', (S('\xe9', False), 1))
binary_case('modulo', u'%s', S('\xe9', False))
binary_case('modulo', u'%r', S('\xe9', False))

random.seed(27)
special = [0.0, -0.0, 1.0, 0.1, 0.5, 1.5, 2.5, 0.125, 0.375, 5e-324, 1e-310, 2.2250738585072014e-308,
           1.7976931348623157e308, 1e16, 1e17, 9.999999999999999e15, 123456789012345678.0, 1e-4, 9.9999e-5,
           1e-5, 0.3, 2.0 / 3, 1e22, 1e23, 4.35, 0.0045, 999999.5, 9.5, 0.05, INF, -INF, NAN]
values = special + [struct.unpack('>d', struct.pack('>Q', random.getrandbits(64)))[0] for _ in range(150)]
values += [random.uniform(-1e6, 1e6) for _ in range(60)]
values += [random.choice([1, -1]) * random.randint(0, 10 ** 8) / 1000.0 for _ in range(60)]
for value in values:
    emit({'k': 'float', 'v': bits(value), 'code': 'r', 'prec': 0, 'alt': False, 'res': repr(value)})
    emit({'k': 'float', 'v': bits(value), 'code': 's', 'prec': 12, 'alt': False, 'res': str(value)})
    for spec in ['%.3e', '%.0e', '%.17g', '%#.6g', '%.2f', '%.0f', '%#.0f', '%G', '%#.20e', '%.25f']:
        flags = spec[1:-1]
        alt = flags.startswith('#')
        if alt:
            flags = flags[1:]
        precision = int(flags[1:]) if flags.startswith('.') else 6
        emit({'k': 'float', 'v': bits(value), 'code': spec[-1], 'prec': precision, 'alt': alt, 'res': spec % value})
