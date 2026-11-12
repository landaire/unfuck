import array

def attempt(function, *args, **keywords):
    try:
        result = function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))
    if isinstance(result, buffer):
        return ('buffer', str(result), len(result))
    return result

def K(value):
    return value

def assign(target, key, value):
    target[key] = value

def delete(target, key):
    del target[key]

def assign_slice(target, low, high, value):
    target[low:high] = value

def delete_slice(target, low, high):
    del target[low:high]

text = K('abcdef')
b = buffer(text)
part = buffer(text, 1, 3)
mutable = bytearray(K('hello'))
live = buffer(mutable, 1, 3)
items = array.array('h', [1, 2, 3])

construction = [
    attempt(buffer, text),
    attempt(buffer, text, 2),
    attempt(buffer, text, 2, 2),
    attempt(buffer, text, 10),
    attempt(buffer, text, 1, 100),
    attempt(buffer, text, 0, -1),
    attempt(buffer, text, -1),
    attempt(buffer, text, 0, -2),
    attempt(buffer, [1], -1),
    attempt(buffer, text, 'x'),
    attempt(buffer, text, 1.0),
    attempt(buffer),
    attempt(buffer, text, 1, 2, 3),
    attempt(buffer, text, offset=1),
    attempt(buffer, memoryview(text)),
    attempt(buffer, 1),
    attempt(buffer, [1]),
    attempt(buffer, items),
    attempt(buffer, items, 2, 3),
    attempt(buffer, mutable),
    attempt(buffer, buffer(text, 2), 1),
    attempt(buffer, buffer(text, 2, 2), 1, 10),
    attempt(buffer, buffer(text, 2, 2), 5),
    attempt(buffer.__new__, buffer, text, 3),
    attempt(buffer.__new__, int, text),
    attempt(buffer.__new__),
    attempt(type, 'Sub', (buffer,), {}),
    type(b).__name__,
    [name for name in ['__add__', '__cmp__', '__delitem__', '__delslice__', '__getitem__', '__getslice__', '__hash__', '__len__', '__mul__', '__repr__', '__rmul__', '__setitem__', '__setslice__', '__str__'] if name not in dir(buffer)],
]

views = [
    str(part), len(part), part[0], part[-1], part[::2], part[1:], part[3:1], part[-2:], part[::-1],
    b[5:0:-2], b[-100:100], b[True], b[slice(None, None, 2 ** 70)],
    attempt(lambda: b[10]), attempt(lambda: b[-7]), attempt(lambda: b['x']), attempt(lambda: b[1.0]),
    attempt(lambda: b[2 ** 70]), attempt(lambda: b[1:4:0]), attempt(lambda: b['a':'b']),
    b[1:2 ** 70], b[-2 ** 70:2],
    b.__getitem__(slice(0, 2)), b.__getitem__(-1), b.__getslice__(-2, 4),
    attempt(b.__getslice__, 1), attempt(b.__getslice__, 'a', 2), attempt(b.__getitem__, 10),
    list(b), tuple(buffer(K('xy'))), 'c' in b, 'q' in b, 1 in b,
    bool(buffer(K(''))), bool(part), '%s' % part, str(b), unicode(buffer(K('ab'))),
]

mutable[1] = 'X'
after_store = str(live)
del mutable[:]
after_clear = (str(live), len(live))
mutable.extend(K('abcdefgh'))
after_extend = str(live)

errors = [
    attempt(assign, b, 0, 'x'),
    attempt(assign, b, slice(0, 1), 'x'),
    attempt(delete, b, 0),
    attempt(assign_slice, b, 0, 1, 'x'),
    attempt(delete_slice, b, 0, 1),
    attempt(b.__setitem__, 0, 'x'),
    attempt(b.__delitem__, 0),
    attempt(b.__setslice__, 0, 1, 'x'),
    attempt(b.__delslice__, 0, 1),
    attempt(buffer.__len__, 'x'),
    attempt(buffer.__str__, 'x'),
    attempt(buffer.__getitem__),
    attempt(setattr, b, 'x', 1),
    attempt(getattr, b, 'x'),
]

operators = [
    b + K('x'), b + buffer(K('zz')), b + bytearray(K('q')), b + items,
    attempt(lambda: b + 1), attempt(lambda: b + memoryview(K('x'))), attempt(lambda: buffer(K('')) + [1]),
    buffer(K('')) + K('q'), buffer(K('')) + items, attempt(lambda: K('x') + b), attempt(lambda: 1 + b),
    b * 2, 2 * b, b * -1, b * 0, attempt(lambda: b * 2.0), attempt(lambda: b * (2 ** 62)),
    b.__mul__(2), b.__rmul__(2), attempt(b.__mul__, 2.0), b.__add__(K('x')),
    attempt(b.__add__, memoryview(K('x'))),
]

comparisons = [
    b < buffer(K('b')), b == buffer(K('abcdef')), b != buffer(K('abcdef')), b == b,
    cmp(buffer(K('ab')), buffer(K('abc'))), cmp(buffer(K('ac')), buffer(K('ab'))), cmp(buffer(K('')), buffer(K(''))),
    buffer(K('ab')) <= buffer(K('ab')), b == K('abcdef'), K('abcdef') == b, b < K('a'), b > 1, b > None,
    attempt(b.__cmp__, K('a')), b.__cmp__(buffer(K('a'))),
    [str(item) for item in sorted([buffer(K('b')), buffer(K('a')), buffer(K('ab'))])],
]

hashing = [
    hash(buffer(K('abc'))) == hash('abc'), hash(buffer(K('xabcx'), 1, 3)) == hash('abc'), hash(buffer(K(''))),
    b.__hash__() == hash('abcdef'), attempt(lambda: {buffer(K('ab')): 1}['ab']),
    {buffer(K('ab')): 1}[buffer(K('ab'))],
]
cached = buffer(mutable)
first = hash(cached)
mutable[0] = 'j'
hashing.append(hash(cached) == first)
hashing.append(hash(buffer(mutable)) == first)

shape = repr(part)
fresh = repr(buffer(buffer(text, 2, 2), 5, 3))
reprs = [
    shape.startswith('<read-only buffer for 0x'), shape.endswith('>'), ', size 3, offset 1 at 0x' in shape,
    ', size -1, offset 0 at ' in repr(b), ', size 0, offset 7 at ' in fresh,
]

RESULT = [construction, views, (after_store, after_clear, after_extend), errors, operators, comparisons, hashing, reprs]
