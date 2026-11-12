import _struct as struct

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

s = struct.Struct('<hi')

class Sub(struct.Struct):
    def __init__(self, fmt):
        struct.Struct.__init__(self, '>' + fmt)
        self.extra = 1

    def total(self, data):
        return sum(self.unpack(data))

x = Sub('hh')
k = struct.Struct(format=u'2b')
r = struct.Struct('i')
r.__init__('q')

RESULT = (
    s.format, s.size, s.pack(1, 2), s.unpack(s.pack(1, 2)), s.unpack_from('abcdefg', 1),
    s.unpack_from(buffer='abcdefg'), s.unpack_from('abcdefg', offset=-6),
    err(s.pack, 1), err(s.unpack, 'ab'), err(s.unpack), err(s.unpack_from),
    err(s.pack_into, 'abcdef', 0, 1, 2), err(s.pack_into),
    err(setattr, s, 'size', 3),
    x.format, x.size, x.extra, x.pack(1, 2), x.total('\x00\x01\x00\x02'), type(x).__name__,
    isinstance(x, struct.Struct), k.format, k.size, k.pack(1, -1), r.size, r.format,
    err(struct.Struct, 5), err(struct.Struct), err(struct.Struct, 'z'), err(struct.Struct, 'i', 'i'),
    struct.Struct.__name__, struct.Struct.__module__,
)
