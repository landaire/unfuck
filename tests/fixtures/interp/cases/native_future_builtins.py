import future_builtins as f
import itertools


def K(value):
    return value


def err(fn, *a, **k):
    try:
        return ('ok', fn(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


class I(object):
    def __index__(self):
        return 42


class Bad(object):
    def __index__(self):
        return 'x'


class C:
    pass


class CI:
    def __index__(self):
        return 7


class Sub(long):
    pass


out = []
out.append([f.hex(K(x)) for x in (0, 255, -255, 2 ** 70, -2 ** 70, 0L, 10L, True, I(), Sub(31))])
out.append([f.oct(K(x)) for x in (0, 8, -8, 2 ** 70, -2 ** 70, 0L, False, I(), Sub(9))])
out.append(err(f.hex, 1.0))
out.append(err(f.oct, 'x'))
out.append(err(f.hex, Bad()))
out.append(err(f.hex, C()))
out.append(err(f.oct, CI()))
out.append(err(f.hex))
out.append(err(f.hex, 1, 2))
out.append(err(f.oct, x=1))
out.append(err(f.ascii))
out.append((f.ascii(u'\xe9'), f.ascii('a\n'), f.ascii([1, 'b'])))
out.append((f.map is itertools.imap, f.filter is itertools.ifilter, f.zip is itertools.izip))
out.append(list(f.map(abs, [-1, 2])))
out.append(list(f.filter(None, [0, 1, 2])))
out.append(list(f.zip('ab', [1, 2, 3])))
out.append(sorted(k for k in dir(f) if not k.startswith('__')))
out.append((f.__name__, f.hex.__name__))

RESULT = out
