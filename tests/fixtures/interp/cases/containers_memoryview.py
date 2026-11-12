def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


m = memoryview('abc')
attributes = (m.format, m.itemsize, m.ndim, m.shape, m.strides, m.suboffsets, m.readonly, len(m))
reads = (m.tolist(), m[1], m[-1], m[1:].tobytes(), m[5:].tobytes(), m[-2:-1].tobytes(), list(m), m.tobytes(), type(m[0:1]).__name__)
compares = (m == 'abc', m != 'abd', m == bytearray('abc'), m == memoryview('abc'), m == 1, m != 1, 'abc' == m)

b = bytearray('hello')
view = memoryview(b)
part = view[1:3]
part[0] = 'X'
part[1:] = bytearray('Y')
shared = (str(b), view.readonly, view.tobytes(), part.tobytes(), view.shape)
b[0] = 'J'
seen = view.tobytes()
locked = (failure(b.append, 1), failure(b.extend, 'xy'), failure(b.pop), failure(b.remove, 'J'), failure(b.insert, 0, 'a'), failure(b.__delitem__, 0), failure(b.__setitem__, slice(0, 2), 'q'), failure(b.__init__, 'zz'))
b[0:2] = 'AB'
same_size = str(b)
nested = memoryview(view)
del view, part
still_locked = failure(b.append, 1)
del nested
released = (failure(b.append, ord('!')), str(b))

errors = (
    failure(memoryview, 1), failure(memoryview, u'a'), failure(memoryview), failure(memoryview, 'a', 'b'),
    failure(memoryview, object='q').tobytes(), failure(m.__getitem__, 5), failure(m.__getitem__, -4),
    failure(m.__getitem__, 'x'), failure(m.__getitem__, slice(None, None, 2)), failure(m.__setitem__, 0, 'x'),
    failure(m.__delitem__, 0), failure(hash, m),
)
w = memoryview(bytearray('ab'))
write_errors = (
    failure(w.__setitem__, 0, 'ab'), failure(w.__delitem__, 0), failure(w.__setitem__, 0, 1),
    failure(w.__setitem__, 0, u'a'), failure(w.__setitem__, 5, 'a'), failure(w.__setitem__, 'k', 'a'),
    failure(w.__setitem__, slice(0, 2, 2), 'a'), failure(w.__setitem__, -1, memoryview('z')), w.tobytes(),
)
buffers = (bytearray('x') + memoryview('yz'), 'abc'.find(memoryview('c')) if False else None, bytearray('abc').find(memoryview('c')), bytearray(memoryview('mv')))

RESULT = (attributes, reads, compares, shared, seen, locked, same_size, still_locked, released, errors, write_errors, buffers)
