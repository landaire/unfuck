B = bytearray
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class Index(object):
    def __index__(self):
        return 3

def alloc(value):
    return (value, value.__alloc__(), value.__sizeof__())

def reinit():
    b = B('abcdef')
    b.__init__('xy')
    return alloc(b)

class Sub(B):
    pass

RESULT = [
    alloc(B()), alloc(B('a')), alloc(B('abcdefghij')), alloc(B([1, 2, 3])), alloc(B(5)), alloc(B(0)),
    alloc(B(3L)), alloc(B(True)), alloc(B(Index())), alloc(B(B('xyz'))), alloc(B(x for x in [65, 66])),
    B(['a', 66, True, 67L]), B(u'abc\xe9', 'utf-8'), B(u'ab', 'utf-16'), B(u'ab', 'hex'), B('abc', 'utf-16'),
    B(source='ab'), B(u'ab', encoding='ascii', errors='strict'), reinit(),
    err(B, -1), err(B, [256]), err(B, [-1]), err(B, 1.5), err(B, None), err(B, u'a'), err(B, 'a', None),
    err(B, 1, 'utf8'), err(B, encoding='utf8'), err(B, 'ab', 'bogus'), err(B, u'ab', 'string_escape'),
    err(B, u'\xe9', 'ascii'), err(B, ['ab']), err(B, [1.5]), err(B, [type('S', (str,), {})('a')]),
    err(B, 1, 2, 3, 4), err(B, 10 ** 20),
    type(Sub('ab')).__name__, Sub('ab'), Sub('ab') == 'ab', list(Sub('ab')),
    bytearray.fromhex(u' 01 ff '), bytearray.fromhex('0a 1B'), type(Sub.fromhex('01')).__name__,
    err(bytearray.fromhex, '0g'), err(bytearray.fromhex, '1 '), err(bytearray.fromhex, u'0a1'), err(bytearray.fromhex, 1),
    B('a\xff').__reduce__(), repr(B()), repr(B('a\'b"c\\\x7f\x80\x00\t\n\r')), repr(B("a'b")), str(B('a\xff')),
    err(hash, B()), bool(B()), bool(B('\x00')),
]
