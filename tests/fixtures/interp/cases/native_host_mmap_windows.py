import mmap


def K(x):
    return x


def attempt(f, *args, **keywords):
    try:
        f(*args, **keywords)
        return 'accepted'
    except Exception as e:
        if type(e).__name__ == 'WindowsError':
            return ('WindowsError', e.args[0])
        return (type(e).__name__, e.args)


def compute():
    out = [dir(mmap), [(name, getattr(mmap, name)) for name in dir(mmap) if name.isupper()]]
    # Native types of the interpreter keep __module__ in their dict.
    out.append([sorted(name for name in mmap.mmap.__dict__ if name != '__module__'), mmap.error.__mro__[1].__name__])
    m = mmap.mmap(K(-1), K(10))
    out.append([m.size(), m.flush(), m.flush(0, 5), m.flush(10, 0), m.flush(4, 0), m.__sizeof__(), mmap.mmap(0, 4).size()])
    out.append([attempt(m.resize, 32), attempt(len, m), attempt(m.size), attempt(lambda: m[0]), attempt(m.close)])
    m = mmap.mmap(-1, 16)
    out.append([attempt(m.resize, 'x'), attempt(m.resize, -1), attempt(len, m)])
    m = mmap.mmap(-1, 3)
    out.append([attempt(lambda: m + m), attempt(lambda: m * 2), attempt(lambda: 2 * m), attempt(lambda: m + 1), attempt(m.__mul__, 'x'), attempt(m.__rmul__, 2)])
    out.append([attempt(m.move, 'x', 0, 0), attempt(m.move, 1.5, 0, 0), attempt(m.move, 0, 2 ** 32 - 1, 1), attempt(m.move, 2 ** 64, 0, 0)])
    m.close()
    out.append([attempt(lambda: m + m), attempt(lambda: m * 2), attempt(m.size, 1)])
    out.append([
        attempt(mmap.mmap, -1, 0), attempt(mmap.mmap, -1, -1), attempt(mmap.mmap, -1, 10, offset=-1),
        attempt(mmap.mmap, -1, 10, offset=1), attempt(mmap.mmap, -1, 10, offset=65536), attempt(mmap.mmap, -1, 10, offset=1.0),
        attempt(mmap.mmap, -1, 10, None, 4), attempt(mmap.mmap, -1, 10, ''), attempt(mmap.mmap, -1, 10, None),
        attempt(mmap.mmap, -1, 10, 'a\0b'), attempt(mmap.mmap, -1, 10, 5), attempt(mmap.mmap, -1, 10, u'a\0'),
        attempt(mmap.mmap, -1), attempt(mmap.mmap), attempt(mmap.mmap, 'x', 1), attempt(mmap.mmap, -1, 'x'),
        attempt(mmap.mmap, -1, 1.5), attempt(mmap.mmap, -1.0, 1), attempt(mmap.mmap, -1, 1, None, 'x'),
        attempt(mmap.mmap, -1, 1, None, 0, 'x'), attempt(mmap.mmap, -1, 1, None, 0, 0, 1), attempt(mmap.mmap, -1, 1, foo=1),
        attempt(mmap.mmap, -1, 1, fileno=1), attempt(mmap.mmap, -1, 2 ** 63), attempt(mmap.mmap, -1, 1, None, 0, 2 ** 63),
        attempt(mmap.mmap, -2, 1), attempt(mmap.mmap, 4096, 1), attempt(mmap.mmap, -2, -1), attempt(mmap.mmap, -2, 1, access=7),
        attempt(mmap.mmap, length=3, fileno=-1), attempt(mmap.mmap, -1, 0, access=7),
    ])
    return out


RESULT = compute()
