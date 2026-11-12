import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


class Sink(io.RawIOBase):
    def __init__(self, limit=None):
        self.parts = []
        self.limit = limit
        self.position = 0

    def writable(self):
        return True

    def readable(self):
        return True

    def seekable(self):
        return True

    def write(self, b):
        data = b.tobytes()
        if self.limit is not None:
            data = data[:self.limit]
        self.parts.append((type(b).__name__, b.readonly, data))
        self.position += len(data)
        return len(data)

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        self.parts.append(('seek', offset, whence))
        if whence == 0:
            self.position = offset
        elif whence == 1:
            self.position += offset
        return self.position


sink = Sink()
writer = io.BufferedWriter(sink, buffer_size=8)
written = (writer.write('abc'), writer.write('defgh'), writer.write('ijklmnopqrstuvwxyz'), writer.write(bytearray('12')), writer.write(memoryview('34')), writer.tell())
before_flush = list(sink.parts)
writer.flush()
after_flush = list(sink.parts)

partial = Sink(limit=3)
writer = io.BufferedWriter(partial, 4)
writer.write('0123456789')
writer.flush()
partial_parts = list(partial.parts)

store = io.BytesIO()
writer = io.BufferedWriter(store)
writer.write('hello ')
writer.writelines(['wor', 'ld'])
unflushed = store.getvalue()
writer.seek(0)
seeked = store.getvalue()
writer.write('J')
writer.close()
closed = (store.closed, writer.closed, failure(writer.write, 'x'), failure(writer.flush))

random = io.BufferedRandom(io.BytesIO('0123456789'), 4)
mixed = (random.read(2), random.write('ab'), random.read(2), random.tell(), random.seek(0), random.read(), random.seek(1), random.write('Z'), random.flush(), random.raw.getvalue(), random.peek(1)[:1], random.truncate(5), random.raw.getvalue())
target = bytearray(3)
random.seek(0)
mixed_into = (random.readinto(target), str(target))

pair = io.BufferedRWPair(io.BytesIO('pair data'), io.BytesIO())
pair_ops = (pair.read(4), pair.peek(2)[:2], pair.read1(2), pair.write('out'), pair.flush(), pair.readable(), pair.writable(), pair.isatty(), pair.closed, pair.close(), pair.closed)

errors = (
    failure(io.BufferedWriter, io.BytesIO(), 0), failure(io.BufferedWriter(io.BytesIO()).write, 1),
    failure(io.BufferedWriter(io.BytesIO()).write), io.BufferedWriter(io.BytesIO()).write(u'uni'),
    failure(io.BufferedRWPair, io.BytesIO()), failure(io.BufferedRWPair.__new__(io.BufferedRWPair).read),
    failure(io.BufferedRandom, Sink(), 4), io.BufferedWriter(io.BytesIO()).__sizeof__(),
    failure(io.BufferedWriter(io.BytesIO()).read), failure(io.BufferedWriter(io.BytesIO()).seek, 0, 9),
)

RESULT = (written, before_flush, after_flush, partial_parts, unflushed, seeked, closed, mixed, mixed_into, pair_ops, errors)


class Growing(io.RawIOBase):
    def __init__(self, source):
        self.source = source

    def writable(self):
        return True

    def write(self, b):
        try:
            self.source.append(120)
        except BufferError as e:
            self.error = str(e)
        return len(b)


source = bytearray('abc')
growing = Growing(source)
grown = (io.BufferedWriter(growing, 2).write(source), str(source), growing.error)


class Resizing(io.BufferedIOBase):
    def read(self, size):
        try:
            self.target.append(120)
        except BufferError as e:
            self.error = str(e)
        return 'a'


resizing = Resizing()
resizing.target = bytearray('zz')
resized = (resizing.readinto(resizing.target), str(resizing.target), resizing.error)


class Position(object):
    def __int__(self):
        return 3


class OddTell(io.BytesIO):
    def tell(self):
        io.BytesIO.tell(self)
        return Position()


odd = io.TextIOWrapper(OddTell('abcdef'), encoding='ascii', newline='\n')
odd.read(1)
odd_cookie = odd.tell()
RESULT = RESULT + (grown, resized, odd_cookie)
