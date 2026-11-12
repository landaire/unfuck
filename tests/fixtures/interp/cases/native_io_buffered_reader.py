import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


class Raw(io.RawIOBase):
    def __init__(self, data, chunk=None):
        self.data = data
        self.position = 0
        self.chunk = chunk
        self.calls = []

    def readable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, b):
        size = len(b)
        if self.chunk is not None:
            size = min(size, self.chunk)
        piece = self.data[self.position:self.position + size]
        self.calls.append(('readinto', type(b).__name__, len(b), getattr(b, 'readonly', None), len(piece)))
        b[:len(piece)] = piece
        self.position += len(piece)
        return len(piece)

    def tell(self):
        self.calls.append(('tell',))
        return self.position

    def seek(self, offset, whence=0):
        self.calls.append(('seek', offset, whence))
        if whence == 0:
            self.position = offset
        elif whence == 1:
            self.position += offset
        else:
            self.position = len(self.data) + offset
        return self.position


data = ''.join(chr(ord('a') + index % 26) for index in range(40)) + '\nline two\nlast'
raw = Raw(data, chunk=7)
reader = io.BufferedReader(raw, buffer_size=16)
reads = (reader.read(3), reader.peek(1)[:5], reader.read1(4), reader.read(20), reader.tell(), reader.readline(), reader.readline(4), reader.readline(), reader.read(), reader.read(), reader.tell())
calls = list(raw.calls)

raw = Raw(data)
reader = io.BufferedReader(raw, 8)
seeks = (reader.read(2), reader.seek(5), reader.read(2), reader.seek(-1, 1), reader.read(1), reader.seek(-3, 2), reader.read(), reader.seek(0), reader.tell())
seek_calls = list(raw.calls)

source = io.BytesIO('first\nsecond\nthird')
reader = io.BufferedReader(source)
iterated = list(reader)
reader.seek(0)
target = bytearray(4)
into = (reader.readinto(target), str(target), reader.read(), reader.raw is source, reader.closed, reader.readable(), reader.writable(), reader.seekable(), reader.__sizeof__())
detached = reader.detach()
after_detach = (detached is source, failure(reader.read), failure(lambda: reader.closed), reader.raw, failure(reader.detach))

closing = io.BufferedReader(io.BytesIO('abc'))
closing.close()
closed = (closing.closed, failure(closing.read), failure(closing.readline), failure(closing.seek, 0), closing.close())

errors = (
    failure(io.BufferedReader, io.BytesIO(), 0), failure(io.BufferedReader, io.BytesIO(), -1),
    failure(io.BufferedReader), failure(io.BufferedReader, 1), failure(io.BufferedReader(io.BytesIO('x')).read, -2),
    failure(io.BufferedReader(io.BytesIO('x')).read1, -1), failure(io.BufferedReader(io.BytesIO('x')).read1),
    failure(io.BufferedReader(io.BytesIO('x')).seek, 0, 3), failure(io.BufferedReader(io.BytesIO('x')).read, 'q'),
    failure(io.BufferedReader.__new__(io.BufferedReader).read), repr(io.BufferedReader(io.BytesIO())),
    failure(io.BufferedReader(io.BytesIO('x')).write, 'y'), io.BufferedReader(io.BytesIO('xyz')).read1(0),
)


class Short(io.RawIOBase):
    def readable(self):
        return True

    def readinto(self, b):
        return len(b) + 1


class Blocking(io.RawIOBase):
    def readable(self):
        return True

    def readinto(self, b):
        return None


misbehaving = (failure(io.BufferedReader(Short()).read, 1), io.BufferedReader(Blocking()).read(5), io.BufferedReader(Blocking()).peek(), failure(io.BufferedReader(Short()).readline))

RESULT = (reads, calls, seeks, seek_calls, iterated, into, after_detach, closed, errors, misbehaving)
