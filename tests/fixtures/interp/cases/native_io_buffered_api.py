# Buffered stream surface: construction and re-initialization, argument
# errors, closed, detached and uninitialized objects, conversion of raw
# results, reentrancy, repr, and BufferedRWPair forwarding. Objects stay
# referenced until the end so that no finalizer adds calls to the logs.

import io
import warnings

keep = []


def plain(value):
    if isinstance(value, (int, long, str, unicode, float, bool, type(None))):
        return value
    if isinstance(value, tuple):
        return tuple(plain(item) for item in value)
    return type(value).__name__


def attempt(function, *args, **kwargs):
    try:
        return ('ok', plain(function(*args, **kwargs)))
    except Exception as e:
        return (type(e).__name__, str(e))


class R(io.RawIOBase):
    def __init__(self, data='abcdefghijklmnopqrstuvwxyz', r=True, w=True, s=True):
        self.d = bytearray(data)
        self.p = 0
        self.r, self.w, self.s = r, w, s
        self.readinto_result = None
        self.write_result = None
        self.seek_result = None
        self.tell_result = None
        self.read_result = None
        self.log = []

    def readable(self):
        return self.r

    def writable(self):
        return self.w

    def seekable(self):
        return self.s

    def readinto(self, b):
        self.log.append(('readinto', len(b)))
        piece = bytes(self.d[self.p:self.p + len(b)])
        b[:len(piece)] = piece
        if self.readinto_result is not None:
            b[:] = 'z' * len(b)
            return self.readinto_result
        self.p += len(piece)
        return len(piece)

    def read(self, *args):
        if self.read_result is not None:
            return self.read_result
        return io.RawIOBase.read(self, *args)

    def write(self, b):
        self.log.append(('write', len(b)))
        if self.write_result is not None:
            return self.write_result
        self.d[self.p:self.p + len(b)] = b.tobytes()
        self.p += len(b)
        return len(b)

    def seek(self, o, w=0):
        self.log.append(('seek', o, w))
        if self.seek_result is not None:
            return self.seek_result
        self.p = [o, self.p + o, len(self.d) + o][w]
        return self.p

    def tell(self):
        self.log.append(('tell',))
        if self.tell_result is not None:
            return self.tell_result
        return self.p

    def truncate(self, *args):
        self.log.append(('truncate',) + plain(args))
        return plain(args)


class Ix(object):
    def __init__(self, value):
        self.value = value

    def __index__(self):
        return self.value


class BadIndex(object):
    def __index__(self):
        raise KeyError('k')


out = []
B = io.BufferedReader
W = io.BufferedWriter
X = io.BufferedRandom


def construction():
    b = B(R(), 4)
    keep.append(b)
    out.append(attempt(b.__init__, R(r=False)))
    out.append(attempt(b.read, 1))
    out.append(attempt(lambda: b.closed))
    out.append(attempt(lambda: b.raw))
    out.append(attempt(b.__sizeof__))
    out.append(attempt(repr, b))
    out.append(attempt(b.__init__, R(), 8))
    out.append(attempt(b.read, 3))
    out.append(attempt(b.__sizeof__))
    for args, kwargs in (((R(r=False), 0), {}), ((R(), 0), {}), ((R(), -1), {}), ((R(), None), {}), ((R(), 'x'), {}), ((R(), 2.5), {}),
                         ((R(),), {'buffer_size': 3}), ((), {'raw': R(), 'buffer_size': 3}), ((R(), 3, 4), {}), ((), {}), ((R(),), {'foo': 1}),
                         ((5,), {}), ((R(r=None),), {}), ((R(r=1),), {})):
        result = attempt(B, *args, **kwargs)
        out.append(('reader', result))
    for args in ((R(), 3, 4, 5), (R(w=False),), (R(w=1),)):
        out.append(('writer', attempt(W, *args)))
    for args in ((R(s=False),), (R(s=0, r=False),), (R(r=False, s=False),), (R(w=False),)):
        out.append(('random', attempt(X, *args)))

    class Tagged(R):
        def __init__(self, tag, tell_value=0, **kwargs):
            R.__init__(self, **kwargs)
            self.tag = tag
            self.tell_value = tell_value

        def tell(self):
            return self.tell_value

    def tag_of(b):
        raw = b.raw
        return None if raw is None else raw.tag

    failures = (lambda b: b.__init__(Tagged('new', r=False)), lambda b: b.__init__(Tagged('new'), 0), lambda b: b.__init__(Tagged('new'), 'x'),
                lambda b: b.__init__(), lambda b: b.__init__(Tagged('new', tell_value=-1)), lambda b: b.__init__(Tagged('new', tell_value='x')))
    for failure in failures:
        b = B(Tagged('old'), 4)
        keep.append(b)
        out.append((attempt(failure, b), tag_of(b), attempt(b.__sizeof__), attempt(b.read, 1), attempt(b.tell), attempt(lambda: b.closed), attempt(repr, b)))
    b = B(Tagged('old'), 4)
    keep.append(b)
    b.detach()
    out.append((attempt(b.__init__, Tagged('new', r=False)), tag_of(b), attempt(b.read, 1)))
    out.append((attempt(b.__init__, Tagged('new')), tag_of(b), attempt(b.read, 1)))

    with warnings.catch_warnings():
        warnings.simplefilter('error')
        out.append(attempt(W, R(), 3, 4))
        out.append(attempt(W, R(), 3, -234))
        out.append(attempt(X, R(), 3, 5))
        out.append(attempt(io.BufferedRWPair, R(), R(), 3, 4))


def closed_streams():
    calls = (('read', ('x',)), ('read', (-2,)), ('read', (1,)), ('read1', (-1,)), ('read1', ('x',)), ('read1', ()), ('peek', ('x',)), ('peek', (1,)),
             ('readline', ('x',)), ('readline', (2,)), ('write', (5,)), ('write', ('ab',)), ('write', (u'\xe9',)), ('write', (u'ab',)), ('seek', (0, 3)),
             ('seek', ('x',)), ('seek', (1.5,)), ('seek', (0, 'x')), ('seek', (0,)), ('tell', ()), ('truncate', ()), ('flush', ()), ('next', ()),
             ('readinto', (bytearray(2),)), ('close', ()), ('isatty', ()), ('fileno', ()), ('readable', ()), ('writable', ()), ('seekable', ()),
             ('detach', ()))
    for kind in (B, W, X):
        raw = R()
        b = kind(raw, 4)
        keep.append(b)
        raw.close()
        for name, args in calls:
            method = getattr(b, name, None)
            if method is None:
                out.append((kind.__name__, name, 'missing'))
                continue
            out.append((kind.__name__, name, attempt(method, *args)))
        out.append((attempt(lambda: b.closed), attempt(repr, b), attempt(lambda: b.name), attempt(lambda: b.mode)))


def detached_streams():
    names = ('read', 'write', 'seek', 'tell', 'flush', 'close', 'readinto', 'peek', 'read1', 'readline', 'truncate', 'fileno', 'isatty', '__sizeof__',
             'detach', 'readable', 'next')
    for kind in (B, W, X):
        b = kind(R(), 4)
        keep.append(b)
        out.append(attempt(b.detach))
        for name in names:
            method = getattr(b, name, None)
            if method is not None:
                out.append((name, attempt(method), attempt(method, 1, 2, 3), attempt(method, x=1)))
        out.append((attempt(lambda: b.closed), attempt(lambda: b.raw), attempt(repr, b), attempt(setattr, b, 'raw', 5)))
    b = B.__new__(B)
    keep.append(b)
    out.append((attempt(b.read), attempt(lambda: b.closed), attempt(b.close), attempt(lambda: b.raw), attempt(b.__sizeof__), attempt(b.detach),
                attempt(b.tell), attempt(repr, b)))


def raw_results():
    settings = (('readinto_result', -1), ('readinto_result', 100), ('readinto_result', 'x'), ('readinto_result', 2.0), ('readinto_result', 2 ** 70),
                ('readinto_result', -2 ** 70), ('readinto_result', True), ('readinto_result', Ix(2)), ('readinto_result', BadIndex()),
                ('readinto_result', 3L), ('write_result', -1), ('write_result', 100), ('write_result', 'x'), ('write_result', 2 ** 70),
                ('write_result', BadIndex()), ('write_result', 3L), ('write_result', Ix(2)), ('seek_result', -1), ('seek_result', 'x'),
                ('seek_result', 2 ** 70), ('seek_result', -2 ** 70), ('seek_result', Ix(2 ** 70)), ('seek_result', BadIndex()), ('seek_result', None),
                ('seek_result', True), ('tell_result', -5), ('tell_result', 'x'), ('tell_result', 2 ** 70), ('tell_result', Ix(3)),
                ('tell_result', BadIndex()), ('read_result', u'abc'), ('read_result', 5), ('read_result', bytearray('ab')))
    for setting, value in settings:
        for kind in (B, W, X):
            raw = R()
            b = kind(raw, 4)
            keep.append(b)
            setattr(raw, setting, value)
            results = []
            for name, args in (('read', (6,)), ('read', ()), ('write', ('abcdefgh',)), ('seek', (2,)), ('tell', ()), ('flush', ())):
                if setting == 'readinto_result' and name == 'read' and not args:
                    continue
                method = getattr(b, name, None)
                if method is not None:
                    results.append((name, attempt(method, *args)))
            out.append((setting, plain(value), kind.__name__, results, list(raw.log)))


def arguments():
    for kind in (B, W, X):
        b = kind(R(), 4)
        keep.append(b)
        for name in ('read', 'readline', 'seek', 'truncate', 'write', 'read1', 'peek'):
            method = getattr(b, name, None)
            if method is None:
                continue
            values = (2 ** 63, -2 ** 63, 2 ** 70, Ix(2 ** 70), Ix(2), 2 ** 63 - 1, -2 ** 63 - 1, True, 1.5, None, 'x')
            if name in ('read1', 'peek'):
                values = (-2 ** 63, 2 ** 63 - 1, True, 1.5, None, 'x', 5L)
            if name == 'write':
                values = (2 ** 63, 2 ** 70, True, 1.5, None, 'x')
            out.append((kind.__name__, name, [attempt(method, value) for value in values]))
        out.append([attempt(b.seek, 0, whence) for whence in (2 ** 63, True, None, 3, -1, 'x', 1.0)])
        for name, args, kwargs in (('read', (), {'n': 2}), ('readline', (), {'limit': 2}), ('peek', (), {'n': 2}), ('write', (), {'b': 'x'}),
                                   ('seek', (0,), {'whence': 1}), ('truncate', (), {'pos': 1}), ('read1', (), {'n': 1})):
            method = getattr(b, name, None)
            if method is not None:
                out.append((kind.__name__, name, attempt(method, *args, **kwargs)))
    w = W(R())
    keep.append(w)
    for value in (bytearray('xy'), memoryview('xyz'), buffer('xyzw'), u'ab', u'\xe9', ['a'], (1,)):
        out.append(attempt(w.write, value))
    x = X(R(), 4)
    keep.append(x)
    for value in (bytearray(3), memoryview(bytearray(3)), 'abc', 5, memoryview('abc')):
        out.append(attempt(x.readinto, value))
    out.append(attempt(x.readinto))
    out.append(attempt(x.readinto, bytearray(2), 1))
    out.append(list(B(R('a\nbb\nccc'), 2)))
    r = B(R('abcdefgh'), 4)
    keep.append(r)
    out.append((attempt(r.read, 2 ** 63 - 1), attempt(r.read, 2 ** 63 - 33), attempt(r.read, 2), attempt(r.read, 2 ** 63 - 1)))
    raw = R('abcdefgh')
    x = X(raw, 4)
    keep.append(x)
    out.append((attempt(x.write, 'q'), attempt(x.read, 2 ** 63 - 1), attempt(x.tell), list(raw.log)))


def reentrancy():
    class Reenter(R):
        def readinto(self, b):
            for name, args in (('read', (1,)), ('write', ('a',)), ('seek', (0,)), ('flush', ()), ('peek', ()), ('readline', ()), ('tell', ()),
                               ('truncate', ()), ('close', ())):
                method = getattr(self.owner, name, None)
                if method is not None:
                    self.inner.append((name, attempt(method, *args)))
            return 0

        def write(self, b):
            return self.readinto(b)

    for kind in (B, X):
        raw = Reenter()
        raw.inner = []
        b = kind(raw, 4)
        keep.append(b)
        raw.owner = b
        out.append((attempt(b.read, 2), raw.inner))


def names():
    class NoName(R):
        @property
        def name(self):
            raise KeyError('n')

    class BaseName(R):
        @property
        def name(self):
            raise KeyboardInterrupt()

    class Named(R):
        name = 'file.bin'
        mode = 'rb'

    out.append((repr(B(NoName())), repr(B(Named())), B(Named()).mode, repr(W(Named())), repr(X(Named()))))
    try:
        out.append(repr(B(BaseName())))
    except KeyboardInterrupt:
        out.append('KeyboardInterrupt propagated')

    class Sub(B):
        pass

    out.append((repr(Sub(Named())), repr(Sub(R()))))


def pairs():
    P = io.BufferedRWPair
    p = P(R('xyz'), R(), 2)
    keep.append(p)
    calls = (('read', (1, 2)), ('read', ()), ('peek', (1, 2)), ('read1', ()), ('readinto', ()), ('write', ()), ('write', (1,)), ('flush', (1,)),
             ('readable', (1,)), ('writable', (1,)), ('isatty', (1,)), ('close', (1,)), ('detach', ()), ('fileno', ()), ('seek', (0,)), ('tell', ()),
             ('truncate', ()), ('read', (1,)), ('peek', ()), ('read1', (5,)), ('readinto', (bytearray(2),)), ('write', ('ab',)), ('flush', ()),
             ('readable', ()), ('writable', ()), ('isatty', ()))
    for name, args in calls:
        out.append(('pair', name, attempt(getattr(p, name), *args)))
    for name, kwargs in (('read', {'n': 1}), ('isatty', {'x': 1}), ('close', {'x': 1}), ('write', {'b': 'x'}), ('peek', {'n': 1})):
        out.append(('pair', name, attempt(getattr(p, name), **kwargs)))
    for args, kwargs in (((), {'reader': R(), 'writer': R()}), ((R(), R()), {'foo': 1}), ((R(), R(), 2), {'buffer_size': 3}), ((R(),), {'writer': R()}),
                         ((R(), R()), {'max_buffer_size': 3}), ((R(), R(), 2, 3, 4), {}), ((R(r=False), R()), {}), ((R(), R(w=False)), {}),
                         ((R(), R(), 0), {}), ((R(r=False), R(), 0), {}), ((1, R()), {}), ((R(), R(), 'x'), {})):
        out.append(('pair new', attempt(P, *args, **kwargs)))
    p = P(R('ab'), R())
    keep.append(p)
    out.append(attempt(p.__init__, R('c', r=False), R()))
    out.append(attempt(p.read, 1))
    out.append(attempt(p.__init__, R('cd'), R(w=False)))
    out.append(attempt(p.read, 1))
    out.append(attempt(p.__init__, R('ef'), R()))
    out.append(attempt(p.read))
    out.append(attempt(lambda: p.closed))
    p = P.__new__(P)
    keep.append(p)
    out.append((attempt(p.read), attempt(lambda: p.closed), attempt(p.close), attempt(p.isatty), attempt(p.write, 'a')))

    class Closer(R):
        def __init__(self, tag, fail, log):
            R.__init__(self)
            self.tag, self.fail, self.shared = tag, fail, log

        def close(self):
            self.shared.append(self.tag)
            R.close(self)
            if self.fail:
                raise IOError(self.tag)

        def isatty(self):
            self.shared.append(('isatty', self.tag))
            return self.answer

    for reader_fails in (False, True):
        for writer_fails in (False, True):
            shared = []
            p = P(Closer('reader', reader_fails, shared), Closer('writer', writer_fails, shared))
            keep.append(p)
            out.append((attempt(p.close), shared, attempt(lambda: p.closed)))
    for reader_answer, writer_answer in ((False, False), (True, False), (False, True), (0, False), (False, 0), (None, 1), (2, False)):
        shared = []
        reader = Closer('reader', False, shared)
        writer = Closer('writer', False, shared)
        reader.answer, writer.answer = reader_answer, writer_answer
        p = P(reader, writer)
        keep.append(p)
        out.append((attempt(p.isatty), shared))


def closing():
    class Failing(R):
        def __init__(self, fail_close):
            R.__init__(self)
            self.fail_close = fail_close

        def close(self):
            self.log.append(('close',))
            R.close(self)
            if self.fail_close:
                raise IOError('close failed')

    class FailingFlush(W):
        def flush(self):
            self.raw.log.append(('flush override',))
            raise IOError('flush failed')

    for fail_close in (False, True):
        for kind in (W, FailingFlush):
            raw = Failing(fail_close)
            b = kind(raw, 4)
            keep.append(b)
            b.write('ab')
            out.append((kind.__name__, fail_close, attempt(b.close), list(raw.log), attempt(lambda: b.closed), attempt(b.close)))
    raw = R()
    b = FailingFlush(raw, 4)
    keep.append(b)
    out.append((attempt(b.detach), attempt(lambda: b.raw is raw)))


def extremes():
    # Absolute positions near the limits of a signed 64-bit integer.
    class Far(R):
        def __init__(self, start):
            R.__init__(self)
            self.p = start

        def readinto(self, b):
            self.log.append(('readinto', len(b)))
            b[:4] = 'abcd'[:len(b)]
            self.p += min(4, len(b))
            return min(4, len(b))

    for start in (2 ** 63 - 1, 2 ** 63 - 3, -2 ** 63):
        for kind in (B, W, X):
            raw = Far(start)
            b = kind(raw, 4)
            keep.append(b)
            results = []
            for name, args in (('read', (2,)), ('tell', ()), ('write', ('x',)), ('tell', ()), ('seek', (1, 1)), ('seek', (-2 ** 63,)), ('seek', (2 ** 63 - 1,)),
                               ('peek', ()), ('seek', (-1, 1)), ('seek', (2 ** 63 - 2,)), ('tell', ())):
                method = getattr(b, name, None)
                if method is not None:
                    results.append((name, attempt(method, *args)))
            out.append((start, kind.__name__, results, list(raw.log)))


construction()
extremes()
closed_streams()
detached_streams()
raw_results()
arguments()
reentrancy()
names()
pairs()
closing()
RESULT = out
