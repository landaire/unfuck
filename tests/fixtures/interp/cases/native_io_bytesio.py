import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


b = io.BytesIO()
written = b.write('abc')
value = b.getvalue()

s = io.BytesIO('line one\nline two\n\nlast')
reads = (s.read(4), s.read(0), s.tell(), s.readline(), s.readline(3), s.readline(), s.readline(-1), s.readline(None), s.readline(), s.read(), s.read(5))
s.seek(0)
lines = s.readlines()
s.seek(0)
limited = s.readlines(10)
s.seek(0)
iterated = list(s)
s.seek(0)
next_line = s.next()

p = io.BytesIO('hello')
seeks = (p.seek(2), p.read(), p.seek(-2, 2), p.read(), p.seek(-1, 1), p.read(), p.seek(-10, 1), p.tell(), p.seek(10), p.tell(), p.read())
p.write('X')
padded = p.getvalue()
truncated = (p.truncate(3), p.tell(), p.getvalue(), p.truncate(), p.getvalue(), p.truncate(100), p.getvalue())

w = io.BytesIO('0123456789')
w.seek(3)
w.write('ab')
w.writelines(['c', 'd'])
overwrite = (w.getvalue(), w.tell(), w.read1(2), w.read1(-1))

sizes = []
grow = io.BytesIO()
for chunk in ['a', 'bb', 'ccc', 'd' * 20, 'e' * 3]:
    grow.write(chunk)
    sizes.append(grow.__sizeof__())
grow.truncate(2)
sizes.append(grow.__sizeof__())

state = io.BytesIO('xyz')
state.read(1)
plain_state = state.__getstate__()
state.extra = 5
dict_state = state.__getstate__()
restored = io.BytesIO()
restored.__setstate__(('restored', 3, {'k': 1}))
restored_state = (restored.read(), restored.k, restored.tell())

closed = io.BytesIO('data')
closed.close()

flags = (b.readable(), b.writable(), b.seekable(), b.isatty(), b.flush(), b.closed, closed.closed)

with io.BytesIO('ctx') as managed:
    managed_value = managed.read()

RESULT = (
    written, type(written).__name__, value,
    reads, lines, limited, iterated, next_line,
    seeks, padded, truncated, overwrite, sizes,
    plain_state, dict_state, restored_state,
    flags, managed.closed, managed_value,
    failure(closed.read), failure(closed.getvalue), failure(closed.tell), failure(closed.write, 'a'),
    failure(closed.seek, 0), failure(closed.readable), failure(closed.next), failure(closed.__getstate__),
    failure(closed.__sizeof__) > 0, failure(closed.close),
    failure(b.write, u'abc'), failure(b.write, 1), failure(b.read, 'x'), failure(b.read, 1.5),
    failure(b.seek), failure(b.seek, 1.5), failure(b.seek, 0, 1.5), failure(b.seek, 0, 3),
    failure(b.seek, -1), failure(b.truncate, -1), failure(b.readinto, 'abc'), failure(b.readinto),
    failure(b.tell, 1), failure(b.readline, 'x'), failure(b.readlines, 'x'),
    failure(io.BytesIO, 1), failure(io.BytesIO, u'ab'), failure(io.BytesIO, 'a', 'b'),
    failure(io.BytesIO, x=1), io.BytesIO(initial_bytes='kw').getvalue(), io.BytesIO(None).getvalue(),
    failure(io.BytesIO().__setstate__, 1), failure(io.BytesIO().__setstate__, ('a', 'b', None)),
    failure(io.BytesIO().__setstate__, ('a', -1, None)), failure(io.BytesIO().__setstate__, ('a', 1, 5)),
    failure(io.BytesIO.read, 1),
)


class Tagged(io.BytesIO):
    def __init__(self, data, tag):
        io.BytesIO.__init__(self, data)
        self.tag = tag


class Slotted(io.BytesIO):
    __slots__ = ('a', 'b')


class Lazy(io.BytesIO):
    def __init__(self):
        pass


tagged = Tagged('a\nb', 'x')
lazy = Lazy()
lazy.write('q')
SUBCLASSES = (Slotted().__sizeof__(), tagged.tag, list(tagged), tagged.__getstate__(), isinstance(tagged, io.BufferedIOBase), lazy.getvalue(), failure(io.BytesIO.__new__, 1), failure(io.BytesIO.__new__, int))
RESULT = RESULT + (SUBCLASSES,)
