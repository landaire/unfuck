import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


def stream_report(newline):
    s = io.StringIO(u'a\r\nb\rc\nd', newline=newline)
    value = s.getvalue()
    lines = s.readlines()
    s.seek(0)
    first = s.readline(1), s.readline(2), s.readline()
    s.seek(0, 2)
    s.write(u'\ne\r')
    return (value, lines, first, s.getvalue(), s.newlines, s.tell(), s.__getstate__())


reports = [stream_report(newline) for newline in (None, '', '\n', '\r', '\r\n')]

s = io.StringIO(u'a\nb')
readlines = s.readlines()
t = io.StringIO()
t.write(u'hello')
t.seek(10)
t.write(u'x')
padded = t.getvalue()
t.seek(0)
reads = (t.read(2), t.read(-1), t.read(), t.tell(), t.seek(0, 1), t.seek(0, 0), t.truncate(3), t.getvalue(), t.tell(), t.truncate(), t.getvalue())

u = io.StringIO(u'one\ntwo\n')
iterated = list(u)
u.seek(0)
next_line = u.next()

state = io.StringIO(u'x\r\ny', newline=None)
state.read(1)
saved = state.__getstate__()
restored = io.StringIO()
restored.__setstate__((u'p\r\nq', '', 1, {'tag': 2}))
restored_report = (restored.getvalue(), restored.tell(), restored.tag, restored.readline(), restored.__getstate__())

closed = io.StringIO(u'data')
closed.close()

uninitialized = io.StringIO.__new__(io.StringIO)
closed_early = io.StringIO.__new__(io.StringIO)
closed_early.close()


class Sub(io.StringIO):
    def readline(self, limit=-1):
        return 'not unicode'


flags = (s.readable(), s.writable(), s.seekable(), s.line_buffering, s.closed, s.encoding, s.errors, closed.closed)

RESULT = (
    reports, readlines, padded, reads, iterated, next_line, saved, restored_report, flags,
    type(s.tell()).__name__, type(s.write(u'')).__name__,
    failure(closed.read), failure(closed.getvalue), failure(closed.tell), failure(closed.write, u'a'),
    failure(closed.seek, 0), failure(closed.readable), failure(closed.next), failure(lambda: closed.newlines),
    failure(list, closed), failure(closed.__setstate__, (u'', None, 0, None)),
    failure(uninitialized.read), failure(lambda: uninitialized.closed), failure(uninitialized.write, u'x'),
    failure(uninitialized.close), failure(closed_early.__setstate__, (u'x', '\n', 0, None)), failure(closed_early.read),
    failure(io.StringIO, 'abc'), failure(io.StringIO, u'', 'x'), failure(io.StringIO, u'', 5),
    failure(io.StringIO().write, 'x'), failure(io.StringIO().seek, 1, 1), failure(io.StringIO().seek, -1),
    failure(io.StringIO().seek, 0, 5), failure(io.StringIO().truncate, -2), failure(io.StringIO().read, 'x'),
    failure(io.StringIO().__setstate__, 1), failure(io.StringIO().__setstate__, (u'', None, 'x', None)),
    failure(io.StringIO().__setstate__, (u'', None, -1, None)), failure(io.StringIO().__setstate__, (u'', None, 0, 7)),
    failure(list, Sub(u'abc')),
    io.StringIO(u'a\nb\nc').readlines(2),
)
