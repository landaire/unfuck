import mmap


def K(x):
    return x


def attempt(f, *args, **keywords):
    try:
        return f(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)


out = []
r = mmap.mmap(-1, 8, access=K(mmap.ACCESS_READ))
c = mmap.mmap(-1, 8, access=mmap.ACCESS_COPY)
w = mmap.mmap(-1, 8, access=mmap.ACCESS_WRITE)
out.append([attempt(r.write, 'x'), attempt(r.write_byte, 'x'), attempt(r.__setitem__, 0, 'x'), attempt(r.__setitem__, slice(0, 1), 'x'), attempt(r.__setslice__, 0, 1, 'x'), attempt(r.move, 0, 0, 0), attempt(r.resize, 4), attempt(c.resize, 4)])
out.append([attempt(r.__setitem__, 0, 'xy'), attempt(r.__setslice__, 0, 1, 'xy'), attempt(r.write, 1), attempt(r.write_byte, 1)])
out.append([r[:], r.read(2), r.tell(), r.readline(), r.find('\0'), r.flush(), c.flush(), attempt(r.flush, 9)])
c[0] = 'Z'
c.write('q')
c.seek(3)
c.write_byte('w')
out.append([c[:], attempt(c.move, 1, 0, 2), c[:], c.tell()])
w[:] = '01234567'
w.move(2, 0, 4)
out.append(w[:])
for access in (-1, 4, 2 ** 20, 'x', 1.0):
    out.append(attempt(lambda: mmap.mmap(-1, 1, access=access)[:]))
RESULT = out
