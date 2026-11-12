# _struct argument conversion, partial writes, and Struct object state.
import _struct as struct
import warnings

caught = []


def record(message, category, filename, lineno, file=None, line=None):
    caught.append((category.__name__, str(message)))


warnings.showwarning = record
warnings.simplefilter('always')


def attempt(function, *args, **keywords):
    del caught[:]
    try:
        result = function(*args, **keywords)
    except Exception as error:
        result = (type(error).__name__, error.args)
    return (result, list(caught))


class Index(object):
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


class Int(object):
    def __init__(self, value):
        self.value = value

    def __int__(self):
        return self.value


class Both(object):
    def __index__(self):
        raise TypeError('no index')

    def __int__(self):
        return 7


class IndexOverflow(object):
    def __index__(self):
        raise OverflowError('too big')


class IntRaises(object):
    def __int__(self):
        raise KeyError('k')


class FloatIndex(float):
    def __index__(self):
        return 12


class IntSub(int):
    def __index__(self):
        return 9


class Classic:
    def __int__(self):
        return 3


class ClassicIndex:
    def __index__(self):
        return 4


class ClassicEmpty:
    pass


class Float(object):
    def __float__(self):
        return 2.5


class FloatBad(object):
    def __float__(self):
        return 5


class Truth(object):
    def __nonzero__(self):
        raise ValueError('truth')


VALUES = [Index(5), Index(2.5), Index(2 ** 70), Int(6), Int('x'), Int(True), Both(), IndexOverflow(), IntRaises(),
          FloatIndex(1.5), IntSub(1), Classic(), ClassicIndex(), ClassicEmpty(), 1.9, -1.9, 1e300, float('inf'),
          1j, 'a', None, [], Float()]
results = []
for value in VALUES:
    results.append([attempt(struct.pack, code, value) for code in ('b', '<H', '>H', '>i', 'Q', '>q', '?')])
results.append([attempt(struct.pack, code, value) for code in ('d', '<f', 'f') for value in (Float(), FloatBad(), 2 ** 1024, 2 ** 200, 'x', 7)])
results.append([attempt(struct.pack, '<f', value) for value in (3.4028234663852886e38, 3.4028235677973362e38, 3.4028235677973366e38, -1e39, 1e-46)])
results.append(attempt(struct.pack, '?', Truth()))
results.append(attempt(struct.pack, 'i?', 'x', Truth()))

for fmt, value in [('>q', 2 ** 64 + 258), ('>q', -2 ** 63 - 258), ('>Q', 2 ** 64 + 258), ('>Q', -1), ('<q', 2 ** 64 + 258), ('>h', 70000)]:
    region = bytearray('\xaa' * 10)
    results.append((fmt, attempt(struct.pack_into, fmt, region, 1, value), str(region)))
for fmt, values in [('<i3sxh', (9, 'a', 'x')), ('<i3sxh', ('x', 'a', 3)), ('0p', ('zz',)), ('b0p', (7, 'zz')), ('0p2s', ('', ''))]:
    region = bytearray('\xaa' * 12)
    results.append((fmt, attempt(struct.pack_into, fmt, region, 1, *values), str(region), attempt(struct.pack, fmt, *values) if struct.calcsize(fmt) else None))
# Only layouts with a nonzero size are packed here.
edge = bytearray('abcd')
results.append((attempt(struct.pack_into, '0p', edge, 4, 'zz'), str(edge)))

layout = struct.Struct('<hi')
for offset in [Index(1), Int(1), 1.5, 'x', None, True, 2L, -6, -7, 3, Int(2.5)]:
    results.append((attempt(layout.unpack_from, 'abcdefgh', offset), attempt(layout.pack_into, bytearray(8), offset, 1, 2)))
for data in ['abcdef', u'abcdef', u'ab\xe9def', bytearray('abcdef'), buffer('xxabcdef', 2), 5, None, 'abc']:
    results.append((attempt(layout.unpack, data), attempt(layout.unpack_from, data), attempt(struct.unpack, '<hi', data)))
for target in ['abcdef', u'abcdef', buffer('abcdefgh'), memoryview('abcdefgh'), memoryview(bytearray(8)), None, 5]:
    results.append(attempt(layout.pack_into, target, 0, 1, 2))
results.append([attempt(layout.pack_into, *args) for args in [(), (bytearray(8),), (bytearray(8), 0), (bytearray(8), 0, 1)]])
results.append([attempt(struct.pack_into, *args) for args in [(), ('<hi',), ('z', bytearray(8))]])
results.append([attempt(struct.unpack_from, *args) for args in [(), ('<hi',), ('z',), ('<hi', 'abcdef', 0, 1)]])
results.append(attempt(struct.unpack_from, '<h', buffer='abc', offset=1))
results.append(attempt(struct.unpack_from, '<h', 'abc', bogus=1))
results.append([attempt(struct.unpack, *args) for args in [('<h',), ('z', 'a'), ('z', 'a', 'b')]])
results.append(attempt(struct.unpack, '<h', 'ab', x=1))
results.append(attempt(struct.calcsize, '<h', x=1))
results.append(attempt(struct._clearcache, 1))

empty = struct.Struct.__new__(struct.Struct, 'ignored', key=1)
results.append((empty.format, empty.size, attempt(empty.pack, 1), attempt(empty.unpack, 'abc'),
                attempt(empty.unpack_from, 'abc', -4), attempt(empty.pack_into), attempt(empty.pack_into, bytearray(1), 0)))
empty.__init__('i')
results.append((empty.format, empty.size, attempt(empty.__init__, 'z'), empty.format, empty.size, empty.pack(5)))
results.append((attempt(empty.__init__, u'\xe9'), empty.format, attempt(empty.__init__), attempt(empty.__init__, format='h'), empty.format))
results.append((attempt(struct.Struct.__new__), attempt(struct.Struct.__new__, int), attempt(struct.Struct, bytearray('i')), attempt(struct.Struct, None)))


class Named(str):
    pass


named = struct.Struct(Named('2h'))
results.append((type(named.format).__name__, type(struct.Struct(u'2h').format).__name__, named.size))
results.append([struct.Struct(fmt).__sizeof__() for fmt in ['', '3i', '0s', '0i', '3x', '10s3i', '2c3s4p']])
results.append((attempt(named.__sizeof__, 1), attempt(setattr, named, 'format', 'x'), attempt(setattr, named, 'x', 1)))
struct._clearcache()
results.append((struct.calcsize(u'3h'), struct.calcsize('3h'), struct.pack(u'h', 1)))
results.append([attempt(struct.unpack, fmt, data) for fmt, data in [('0p', ''), ('5p', '\x09bcde'), ('5p', '\x00bcde'), ('1p', '\x05'), ('x?x', 'a\x02b')]])
results.append(struct.unpack('<f', '\x01\x00\x80\x7f')[0] != 0)
results.append([str(struct.pack(fmt, struct.unpack(source, bits)[0])).encode('hex') for fmt, source, bits in [
    ('<f', '<f', '\x01\x00\x80\x7f'), ('<d', '<f', '\x01\x00\x80\x7f'), ('<f', '<d', '\x01\x00\x00\x00\x00\x00\xf0\x7f'),
    ('<d', '<d', '\x01\x00\x00\x00\x00\x00\xf0\x7f'), ('<f', '<d', '\x00\x00\x00\x00\x00\x00\xf8\xff'), ('>f', '<f', '\x01\x00\xc0\xff')]])

RESULT = results


class Plain(struct.Struct):
    pass


class Slotted(struct.Struct):
    __slots__ = ('a', 'b')


class SlottedChild(Slotted):
    pass


class DictSlot(struct.Struct):
    __slots__ = ('__dict__',)


class Empty(struct.Struct):
    __slots__ = ()


RESULT.append([kind('3i').__sizeof__() for kind in (Plain, Slotted, SlottedChild, DictSlot, Empty)])
