from array import array

def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, str(e))

def setitem(index, value):
    b = array('i', [1, 2, 3, 4, 5])
    b[index] = value
    return b, b.__sizeof__()

def delitem(index):
    b = array('i', [1, 2, 3, 4, 5])
    del b[index]
    return b, b.__sizeof__()

def slices():
    b = array('h', range(10))
    b[2:4] = array('h', [7, 7, 7])
    del b[:2]
    b[-3:] = array('h')
    c = array('h', [1, 2])
    c[0:1] = c
    return b, c, b[1:3], b[-2:], b[:100], b[5:2], b.__sizeof__()

def grow():
    b = array('d')
    sizes = []
    for i in range(20):
        b.append(i)
        sizes.append(b.__sizeof__())
    for i in range(20):
        b.pop()
        sizes.append(b.__sizeof__())
    return sizes

def mutate():
    b = array('h', [1, 2, 3, 2])
    b.insert(-9, 7)
    b.insert(99, 8)
    b.insert(1, 9)
    b.remove(2)
    first = b.pop(0)
    b.extend([4, 5])
    b.extend(array('h', [6]))
    b.fromlist([10, 11])
    b.fromstring('\x0c\x00')
    b.reverse()
    c = array('h', [1, 256])
    c.byteswap()
    d = array('d', [1.0])
    d.byteswap()
    return b, first, b.count(2), b.index(4), 4 in b, 99 in b, c, d.tostring(), b.__sizeof__()

def partial(method, items):
    b = array('h', [1])
    return err(getattr(b, method), items), b

def iadd(other):
    b = array('i', [1])
    b += other
    return b

def imul(other):
    b = array('i', [1, 2])
    b *= other
    return b, b.__sizeof__()

class Sub(array):
    pass

class Twice(object):
    def __rmul__(self, other):
        return 'rmul'
    def __radd__(self, other):
        return 'radd'

a = array('i', [1, 2, 3, 4, 5])
RESULT = [
    a[0], a[-1], a[1:3], a[::2], a[::-1], a[10:], a[True], err(lambda: a[10]), err(lambda: a['x']), err(lambda: a[2 ** 70]),
    setitem(0, 9), setitem(slice(1, 3), array('i', [7])), setitem(slice(None, None, 2), array('i', [7, 8, 9])),
    setitem(slice(None, None, 2), array('i')), setitem(slice(3, 1), array('i', [6])), err(setitem, slice(1, 3), [7]),
    err(setitem, slice(1, 3), array('l', [7])), err(setitem, slice(None, None, 2), array('i', [7])), err(setitem, 9, 1),
    err(setitem, 'x', 1), err(setitem, 0, 'x'), delitem(0), delitem(slice(1, 3)), delitem(slice(None, None, -2)), err(delitem, 9),
    slices(), grow(), mutate(), partial('extend', [2, 'x', 3]), partial('fromlist', [2, 'x']), err(array('h').fromlist, (1,)),
    err(array('h').extend, array('b')), err(array('h').fromstring, '\x01'), array('h', [1]).fromstring(u'ab'), err(array('h').fromunicode, u'a'),
    err(array('u').fromunicode, 'ab'), array('u', u'ab').tounicode(), err(array('h').tounicode), err(array('h', [1]).index, 9),
    err(array('h', [1]).remove, 9), err(array('h').pop), err(array('h', [1]).pop, 5), err(array('h', [1]).fromstring, array('h', [1])),
    a + array('i', [9]), err(lambda: a + [1]), err(lambda: a + array('l', [1])), err(lambda: [1] + a), err(lambda: 'x' + a),
    a * 2, 2 * a, a * -1, err(lambda: a * 'x'), err(lambda: a * 1.5), err(a.__mul__, 'x'), err(a.__rmul__, 1.5), a.__rmul__(2),
    iadd(array('i', [2])), err(iadd, [2]), err(iadd, array('b', [2])), imul(2), imul(0), imul(-1), err(imul, 'x'), a * Twice(), a + Twice(),
    array('h', [1, 2]) < array('h', [1, 3]), array('h', [1]) == array('d', [1.0]), array('h', [1]) == [1], array('h', [1, 2]) > array('h', [1]),
    array('h', [2]) >= array('h', [1, 5]), err(hash, array('h')), list(array('h', [1, 2])), type(iter(array('h'))).__name__, len(a),
    bool(array('h')), bool(array('h', [0])), array('h', [1, 2]).__reduce__(), array('h', [1]).__copy__(), array('h', [1]).__deepcopy__({}),
    Sub('h', [1]), type(Sub('h', [1]) + array('h')), type(Sub('h', [1, 2])[0:1]), Sub('h', [3]).__reduce__()[0] is Sub, Sub('h', [1]) == array('h', [1]),
    a.__getslice__(1, 3), err(array('h').tofile, 5), err(array('h').fromfile, 5, 1), err(array('h').write, object()), err(array('h').read, 1, 1),
    array('h', [1]).buffer_info()[1], __import__('array').ArrayType is array, sorted([array('h', [2]), array('h', [1])]),
]

class Declines(array):
    def __mul__(self, other):
        return NotImplemented
    def __add__(self, other):
        return 'add'

class AddOnly(bytearray):
    def __add__(self, other):
        return 'add'

def augmented_bytes(value):
    value += 'x'
    return value

class DeclinesBytes(bytearray):
    def __mul__(self, other):
        return NotImplemented

def augmented(value):
    value += array('h', [1])
    return value

def scaled(value):
    value *= 2
    return value

class Shrink(object):
    def __init__(self, target):
        self.target = target
    def __index__(self):
        del self.target[:]
        return 0

def shrinking_get():
    b = array('h', [1, 2, 3])
    return b[Shrink(b):]

RESULT += [
    err(lambda: Declines('h', [1]) * 2), 2 * Declines('h', [1]), Declines('h', [1]) + array('h'), augmented(Declines('h', [3])), scaled(Declines('h', [4])),
    err(lambda: DeclinesBytes('a') * 2), scaled(DeclinesBytes('a')), AddOnly('a') * 2, augmented_bytes(AddOnly('a')), err(lambda: iter(array('h', [1])).next(1)), err(array('h').__iter__, 1), Declines('h').__sizeof__(),
    shrinking_get(), err(array.__new__, object, 'h'), err(array.__new__, 1),
]
