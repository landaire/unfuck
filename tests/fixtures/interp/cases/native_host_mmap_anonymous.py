import mmap


def K(x):
    return x


def attempt(f, *args):
    try:
        return f(*args)
    except Exception as e:
        return (type(e).__name__, e.args)


m = mmap.mmap(K(-1), K(16))
out = [len(m), m[:], m.tell(), m[0], m[-1], attempt(m.__getitem__, 16), attempt(m.__getitem__, -17)]
m[0] = K('a')
m[-1] = K('z')
out.append(m[:])
out.append([attempt(m.__setitem__, 0, 'ab'), attempt(m.__setitem__, 0, u'a'), attempt(m.__setitem__, 0, 1), attempt(m.__setitem__, 20, 'a')])
out.append([attempt(m.__delitem__, 0), attempt(m.__delitem__, slice(0, 2)), attempt(m.__delslice__, 0, 2), attempt(m.__delitem__, 99)])
out.append([attempt(m.__setitem__, slice(0, 2), 'abc'), attempt(m.__setitem__, slice(0, 2), u'ab'), attempt(m.__setitem__, slice(0, 2), bytearray('ab'))])
m[1:4] = K('bcd')
out.append(m[:])
m[::2] = K('ABCDEFGH')
out.append(m[:])
out.append([m[::3], m[::-1], m[5:2], m[-3:], m[2:100], m[K(-5):K(3)], m.__getslice__(-5, 3), m.__getslice__(3, -1)])
m.__setslice__(-5, 2, 'xy')
out.append(m[:])
out.append([attempt(m.__setslice__, 3, 1, ''), attempt(m.__setslice__, 3, 1, 'a'), attempt(m.__setitem__, slice(10, 2, -3), 'ABC'), m[:]])
out.append([attempt(m.__getitem__, 'x'), attempt(m.__setitem__, 'x', 'a'), attempt(m.__getitem__, 1.0), attempt(m.__getitem__, 2 ** 70), attempt(m.__setitem__, 2 ** 70, 'a'), attempt(m.__getitem__, slice(None, None, 0)), m[True], m[-1L]])
out.append([attempt(lambda: 'a' in m), attempt(lambda: list(m)[:3]), attempt(lambda: iter(m).next()), sorted(m)[:2], list(reversed(m))[:2], bool(m), hash(m) == hash(m), m == m, m != m])
out.append([m.find('B'), m.find('B', 3), m.find('B', -16), m.find('', 5), m.find('', 99), m.find('zz'), m.rfind('B'), m.rfind(''), m.rfind('', 3, 7), m.find('B', 0, 1), m.find('B', 0, -100), m.find(u'B')])
out.append([attempt(m.find), attempt(m.find, 1), attempt(m.find, bytearray('B')), attempt(m.find, 'B', 1, 2, 3), attempt(m.find, 'B', 'x'), attempt(m.find, 'a', None)])
m.seek(0)
out.append([m.find('A'), m.tell()])
m.seek(5)
out.append([m.find('A'), m.rfind('A'), m.find('y'), m.rfind('x')])
out.append([attempt(m.seek, 17), attempt(m.seek, -1), attempt(m.seek, 0, 3), attempt(m.seek, 1, 2), m.seek(0, 2), m.tell(), m.seek(-3, 1), m.tell(), attempt(m.seek, -14, 1), attempt(m.seek, -17, 2), attempt(m.seek, 2 ** 63 - 1, 1), attempt(m.seek), attempt(m.seek, 'x'), attempt(m.seek, 0, 'x')])
m.seek(0)
out.append([m.read(3), m.read(-1), m.tell(), m.read(5), attempt(m.read), attempt(m.read, None), attempt(m.read_byte), attempt(m.read, 1.5)])
m.seek(0)
out.append([m.read_byte(), m.tell(), attempt(m.read_byte, 1)])
m.seek(0)
m.write('l1\nl2\n')
m.seek(0)
out.append([m.readline(), m.readline(), m.readline(), m.readline(), m.tell()])
m.seek(14)
out.append([attempt(m.write, 'abc'), m.tell(), attempt(m.write, 'ab'), m.tell(), attempt(m.write, ''), attempt(m.write, u'x'), attempt(m.write, 1), attempt(m.write, bytearray('x'))])
m.seek(15)
out.append([attempt(m.write_byte, 'q'), attempt(m.write_byte, 'q'), attempt(m.write_byte, 'qq'), attempt(m.write_byte, 1), attempt(m.write_byte, u'q'), attempt(m.write_byte)])
out.append(m[:])
out.append([attempt(m.move, 0, 8, 8), m[:], attempt(m.move, 0, 9, 8), attempt(m.move, -1, 0, 1), attempt(m.move, 0, 0), attempt(m.move, 0, 0, 0), attempt(m.move, 16, 16, 0), attempt(m.move, 1, 0, 3), m[:], attempt(m.move, 17, 0, 0)])
out.append([attempt(m.size, 1), attempt(m.tell, 1), attempt(m.close, 1), attempt(m.readline, 1), attempt(m.flush, 0, 17), attempt(m.flush, 1, 2, 3)])
out.append([attempt(m.__len__, 1), attempt(m.__getitem__), attempt(mmap.mmap.size, 1), attempt(mmap.mmap.size), attempt(mmap.mmap.__new__, int)])
m.close()
m.close()
closed = [lambda: len(m), lambda: m[0], lambda: m[0:1], m.tell, m.read_byte, m.readline, lambda: m.read(1), lambda: m.find('a'), lambda: m.seek(0), lambda: m.write('a'), lambda: m.write_byte('a'), lambda: m.move(0, 0, 0), m.flush, lambda: m.resize(1), lambda: m.__setitem__(0, 'a'), lambda: m.__setslice__(0, 1, 'a'), lambda: m.__getslice__(0, 1), lambda: m.read(), lambda: m.find(), lambda: m.__delitem__(0), lambda: 'x' in m, lambda: list(m), lambda: bool(m), lambda: m.size(1), lambda: m[:]]
out.append([attempt(f) for f in closed])
out.append([type(m).__name__, type(m).__module__, repr(m)[:20], attempt(setattr, m, 'x', 1), attempt(lambda: m.x)])


class S(mmap.mmap):
    pass


s = S(-1, 3)
s.attribute = 5
s[1] = 'q'
out.append([type(s).__name__, len(s), s[:], s.attribute, isinstance(s, mmap.mmap), attempt(mmap.mmap.__new__, mmap.mmap, -1, 1).__class__.__name__])
RESULT = out
