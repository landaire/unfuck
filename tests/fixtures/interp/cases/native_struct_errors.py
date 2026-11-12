import _struct as struct

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

class Index(object):
    def __index__(self):
        return 7

class Int(object):
    def __int__(self):
        return 8

class BadInt(object):
    def __int__(self):
        return 'a'

class Flt(object):
    def __float__(self):
        return 2.5

P = struct.pack
RESULT = (
    [err(P, f, v) for f, v in [
        ('b', 200), ('B', -1), ('B', 256), ('h', 40000), ('H', -1), ('<h', 40000), ('<H', 70000),
        ('>h', 40000), ('>H', 70000), ('>H', -1), ('i', 2 ** 31), ('<i', -2 ** 31 - 1), ('>i', 2 ** 31),
        ('I', -1), ('I', 2 ** 32), ('>I', 2 ** 32), ('l', 2 ** 63), ('L', -1), ('q', 2 ** 63),
        ('Q', -1), ('Q', 2 ** 64), ('<Q', -1), ('>q', -2 ** 63 - 1),
        ('i', 'a'), ('i', None), ('i', 1e309), ('i', 1e309 - 1e309), ('P', 1e309),
        ('P', 2 ** 64), ('P', -2 ** 70), ('P', 1.5), ('P', -1),
        ('f', 'x'), ('<f', 1e300), ('<f', 2 ** 2000), ('d', 2 ** 2000),
        ('c', 'ab'), ('c', u'a'), ('s', 1), ('p', 1), ('5s', u'ab'),
        ('i', Index()), ('i', Int()), ('Q', Index()), ('q', Int()), ('i', BadInt()),
        ('f', Index()), ('d', Flt()), ('i', True),
    ]],
    err(P, 'ii', 1), err(P, 'i', 1, 2), err(P), err(P, 'i', x=1),
    err(struct.unpack, 'i'), err(struct.unpack, 'i', 'abc'), err(struct.unpack, 'i', 5),
    err(struct.unpack, 'i', u'ab\xe9d'), err(struct.unpack, 'i', 'abcd', 'x'), err(struct.unpack, '0p', ''),
    err(struct.calcsize, 'z'), err(struct.calcsize, '99999999999999999999'),
    err(struct.calcsize, '9223372036854775807q'), err(struct.calcsize, '4 i'), err(struct.calcsize, 5),
    err(struct.calcsize, '<P'), err(struct.calcsize), err(struct.calcsize, 'i', 'i'),
    err(struct.unpack_from, 'i', 'abcdef', 3), err(struct.unpack_from, 'i', 'abcdef', -9),
    err(struct.unpack_from, 'i'), err(struct.unpack_from), err(struct.unpack_from, 'i', None),
    err(struct.unpack_from, 'i', 5), err(struct.unpack_from, 'i', 'abcd', 1.0),
    err(struct.unpack_from, 'i', 'abcd', 'x'), err(struct.unpack_from, 'i', 'abcd', 0, 1),
    err(struct.unpack_from, 'i', 'abcd', bogus=1),
    err(struct.pack_into, 'i', 'abcd', 0, 1), err(struct.pack_into, 'i', 5, 0, 1),
    err(struct.pack_into, 'i'), err(struct.pack_into, 'i', 'x'), err(struct.pack_into, 'i', 'x', 0),
    err(struct.pack_into, 'i', u'x', 0, 1), err(struct.pack_into, 'i', None, 0, 1),
    err(struct._clearcache, 1),
    issubclass(struct.error, Exception), struct.error.__module__, struct.error.__name__,
)
