B = bytearray
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

def setitem(index, value):
    b = B('abc')
    b[index] = value
    return b, b.__alloc__()

def delitem(index):
    b = B('abcdef')
    del b[index]
    return b, b.__alloc__()

def slices():
    b = B('0123456789')
    b[2:4] = 'xyz'
    b[:0] = [65, 66]
    b[-3:] = B()
    b[::3] = 'QRST'
    c = B('abc')
    c[0:2] = c
    d = B('abcdef')
    d[1:5] = []
    return b, b.__alloc__(), c, d, d.__alloc__(), b[1:4], b[::-2], b[100:], b[-2]

def grow():
    b = B()
    sizes = []
    for i in range(20):
        b.append(i)
        sizes.append(b.__alloc__())
    for i in range(20):
        b.pop()
        sizes.append(b.__alloc__())
    return sizes

def extend():
    b = B('ab')
    b.extend('cdef')
    sizes = [b.__alloc__()]
    b.extend([1, 2])
    sizes.append(b.__alloc__())
    b.extend(B('xyz'))
    sizes.append(b.__alloc__())
    b.extend(x for x in [7])
    return b, sizes

def failed_extend():
    b = B('ab')
    return err(b.extend, [1, 'ab']), b

def misc():
    b = B('xy')
    b.insert(-10, 65)
    b.insert(100, 66)
    b.insert(1, 'C')
    first = b.pop(0)
    b.remove('B')
    b.reverse()
    return b, b.__alloc__(), first

def inplace():
    b = B('ab')
    b *= 3
    sizes = [b.__alloc__()]
    b += 'cd'
    sizes.append(b.__alloc__())
    b += B('e')
    b *= 0
    sizes.append(b.__alloc__())
    return b, sizes

RESULT = [
    setitem(0, 'z'), setitem(-1, 0x41), setitem(True, 66L), setitem(slice(0, 1), [1, 2, 3]),
    setitem(slice(0, 2), 'xyz'), setitem(slice(1, 1), (x for x in [65])), setitem(slice(None, None, 2), 'xy'),
    setitem(slice(None, None, 2), ''), setitem(slice(None, None, -1), 'xyz'), setitem(slice(3, 1), 'Q'),
    err(setitem, 0, 'zz'), err(setitem, 0, 256), err(setitem, 0, 1.5), err(setitem, 0, u'a'), err(setitem, 'x', 1),
    err(setitem, 5, 1), err(setitem, slice(0, 1), 5), err(setitem, slice(0, 1), u'a'),
    err(setitem, slice(None, None, 2), 'xyz'), err(setitem, slice(None, None, 0), 'a'),
    delitem(0), delitem(-1), delitem(slice(1, 3)), delitem(slice(None, None, 2)), delitem(slice(None, None, -2)),
    err(delitem, 10), err(delitem, 'a'),
    slices(), grow(), extend(), failed_extend(), misc(), inplace(),
    err(B().extend, 5), err(B().extend, u'ab'), err(B('a').pop, 5), err(B().pop), err(B('abc').remove, 100),
    err(B('abc').remove, 'z'), err(B('a').append, 'ab'), err(B('a').insert, 0), err(B('a').insert, 1.5, 1),
    err(B('a').__getitem__, 'x'), err(B('a').__getitem__, 10 ** 20), err(B('a').__getitem__, 1),
]

def iadd_self(text, pops):
    b = B(text)
    for _ in range(pops):
        b.pop()
    b += b
    return b

class BadIndex(object):
    def __index__(self):
        raise TypeError('no index')
    def __iter__(self):
        return iter([65, 66])

RESULT += [err(iadd_self, 'a', 0), err(iadd_self, 'abcd', 1), err(iadd_self, 'abcdefgh', 6), iadd_self('', 0), B(BadIndex())]
