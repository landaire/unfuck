import _io
import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


class Reader(io.RawIOBase):
    def __init__(self, data):
        self.data = data
        self.position = 0
        self.flushes = 0

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = len(self.data)
        chunk = self.data[self.position:self.position + size]
        self.position += len(chunk)
        return chunk

    def flush(self):
        self.flushes += 1
        return io.RawIOBase.flush(self)


class Peeker(Reader):
    def peek(self, size):
        return self.data[self.position:]


class Writer(io.BufferedIOBase):
    def __init__(self):
        self.parts = []

    def write(self, data):
        self.parts.append(data)
        return len(data)


class Chunks(io.RawIOBase):
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def read(self, size=-1):
        if size >= 0 and self.chunks:
            return self.chunks.pop(0)
        return ''


r = Reader('one\ntwo\nthree')
line_reads = (r.readline(), r.readline(2), r.readline(-1), r.readline(), r.readline())
r = Reader('a\nb\nc\n')
iterated = list(r)
r = Reader('a\nbb\nccc\n')
hinted = r.readlines(3)
p = Peeker('xy\nz')
peeked = (p.readline(), p.readline(1), p.readline())

closing = Reader('')
before = closing.closed
closing.close()
closing.close()
after = (closing.closed, closing.flushes, hasattr(closing, "__IOBase_closed"))

with Reader('ctx') as managed:
    entered = managed.closed

w = Writer()
w.writelines(['a', 'b'])

base = _io._IOBase()
raw = _io._RawIOBase()

RESULT = (
    line_reads, iterated, hinted, peeked, before, after, managed.closed, entered, w.parts,
    Chunks(['ab', 'cd']).readall(), Chunks([]).readall(), Chunks(['x']).read(),
    issubclass(io.BytesIO, io.BufferedIOBase), issubclass(io.StringIO, io.TextIOBase),
    issubclass(io.FileIO, io.RawIOBase), isinstance(io.BytesIO(), io.IOBase),
    isinstance(io.StringIO(), io.IOBase), issubclass(io.TextIOWrapper, io.TextIOBase),
    issubclass(io.BufferedRWPair, io.BufferedIOBase), isinstance(Reader(''), io.IOBase),
    [cls.__name__ for cls in io.RawIOBase.__mro__], [cls.__name__ for cls in io.BytesIO.__mro__],
    [cls.__name__ for cls in io.StringIO.__mro__], [cls.__name__ for cls in _io.UnsupportedOperation.__mro__],
    io.UnsupportedOperation is _io.UnsupportedOperation, _io.DEFAULT_BUFFER_SIZE, io.SEEK_END,
    failure(base.seek, 0), failure(base.tell), failure(base.truncate), failure(base.fileno),
    base.readable(), base.writable(), base.seekable(), base.isatty(), base._checkClosed(),
    failure(base._checkReadable), failure(base._checkWritable), failure(base._checkSeekable),
    io.BytesIO()._checkReadable(), failure(base.tell, 1), failure(base.flush, 1),
    failure(raw.read), failure(raw.read, 1), failure(raw.read, None), failure(lambda: raw.readinto('x')),
    failure(_io._BufferedIOBase().read), failure(_io._BufferedIOBase().read1, 1), failure(_io._BufferedIOBase().write, 'x'),
    failure(_io._BufferedIOBase().detach), failure(_io._BufferedIOBase().readinto, 'x'), failure(_io._BufferedIOBase().readinto),
    failure(_io._TextIOBase().read), failure(_io._TextIOBase().readline), failure(_io._TextIOBase().write, u'x'),
    failure(_io._TextIOBase().detach), _io._TextIOBase().encoding, _io._TextIOBase().newlines, _io._TextIOBase().errors,
    isinstance(failure(base.seek, 0), tuple), issubclass(_io.UnsupportedOperation, ValueError),
    issubclass(_io.UnsupportedOperation, IOError), issubclass(_io.BlockingIOError, IOError),
    _io.BlockingIOError(1, 'x', 3).characters_written, _io.BlockingIOError(1, 'x').characters_written,
    _io.BlockingIOError(1, 'x').args, failure(_io.BlockingIOError, 1),
    failure(_io.open), failure(_io.open, 1, 2, 3, 4, 5, 6, 7, 8), failure(_io.open, [1]),
    failure(_io.open, 'f', 'rr'), failure(_io.open, 'f', 'q'), failure(_io.open, 'f', 'rw'),
    failure(_io.open, 'f', 'tb'), failure(_io.open, 'f', 'Uw'), failure(_io.open, 'f', 'rb', encoding='x'),
    failure(_io.open, 'f', 'rb', errors='x'), failure(_io.open, 'f', 'rb', newline='x'), failure(_io.open, 'f', 5),
    failure(_io.FileIO), failure(_io.FileIO, 1.5), failure(_io.FileIO, -1), failure(_io.FileIO, 'f', 'q'),
    failure(_io.FileIO, 'f', 'rw'), failure(_io.FileIO, 'f', 'b'),
    failure(_io.FileIO, 'f', 'r', False), failure(_io.FileIO, [1]),
    failure(_io.FileIO.read, 1), failure(_io.FileIO.read), failure(_io.TextIOWrapper.write, 1, 'x'),
    failure(_io.FileIO.closed.__get__, 1), repr(_io.FileIO.closed), repr(_io._IOBase.closed),
    failure(_io.BufferedReader), failure(_io.BufferedRWPair, 1), failure(_io.TextIOWrapper),
    failure(_io.open, -1), failure(_io.open, 'x', 'b'), failure(_io.open, 'x', closefd=False),
    failure(_io.open, 1.5), failure(_io.FileIO, 2 ** 40), failure(_io.TextIOWrapper, 1, newline='bad'),
    _io.FileIO.__module__, _io.TextIOWrapper.__name__, _io.IncrementalNewlineDecoder.__module__,
)
