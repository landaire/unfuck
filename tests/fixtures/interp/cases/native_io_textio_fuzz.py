import codecs
import io

# Random operation sequences over TextIOWrapper, drawn from a fixed linear
# congruential generator so that every interpreter replays the same run.
# Each step records its result and every call the wrapper made on its
# buffer and codec objects.

STATE = [20161111]


def draw(count):
    STATE[0] = (STATE[0] * 1103515245 + 12345) % 2147483648
    # int() keeps the type the same where C long is 32 bits wide.
    return int((STATE[0] >> 8) % count)


def pick(items):
    return items[draw(len(items))]


CALLS = []


def calls():
    taken = CALLS[:]
    del CALLS[:]
    return taken


def wrap_codec(base):
    info = codecs.lookup(base)

    class Decoder(object):
        def __init__(self, *arguments):
            CALLS.append(('D.new',) + arguments)
            self.inner = info.incrementaldecoder(*arguments)

        def decode(self, *arguments):
            text = self.inner.decode(*arguments)
            CALLS.append(('D.decode',) + arguments + (text,))
            return text

        def getstate(self):
            state = self.inner.getstate()
            CALLS.append(('D.getstate', state))
            return state

        def setstate(self, state):
            CALLS.append(('D.setstate', state))
            return self.inner.setstate(state)

        def reset(self):
            CALLS.append(('D.reset',))
            return self.inner.reset()

    class Encoder(object):
        def __init__(self, *arguments):
            CALLS.append(('E.new',) + arguments)
            self.inner = info.incrementalencoder(*arguments)

        def encode(self, *arguments):
            data = self.inner.encode(*arguments)
            CALLS.append(('E.encode',) + arguments + (data,))
            return data

        def setstate(self, state):
            CALLS.append(('E.setstate', state))
            return self.inner.setstate(state)

        def reset(self):
            CALLS.append(('E.reset',))
            return self.inner.reset()

    return codecs.CodecInfo(info.encode, info.decode, incrementalencoder=Encoder, incrementaldecoder=Decoder, name='log-' + base)


def search(name):
    if name.startswith('log-'):
        return wrap_codec(name[4:].replace('_', '-'))


codecs.register(search)


class Recorder(io.BufferedIOBase):
    """A buffer that records each call. With `short`, read1 returns at most
    that many bytes."""

    def __init__(self, data, short):
        self.store = io.BytesIO(data)
        self.short = short

    def read1(self, size):
        CALLS.append(('read1', size))
        if self.short:
            size = min(size, self.short)
        return self.store.read(size)

    def read(self, *arguments):
        CALLS.append(('read',) + arguments)
        return self.store.read(*arguments)

    def write(self, data):
        CALLS.append(('write', data))
        return self.store.write(data)

    def flush(self):
        CALLS.append(('flush',))

    def seek(self, *arguments):
        CALLS.append(('seek',) + arguments)
        return self.store.seek(*arguments)

    def tell(self):
        CALLS.append(('tell',))
        return self.store.tell()

    def truncate(self, *arguments):
        CALLS.append(('truncate',) + arguments)
        return self.store.truncate(*arguments)

    def readable(self):
        CALLS.append(('readable',))
        return True

    def writable(self):
        CALLS.append(('writable',))
        return True

    def seekable(self):
        CALLS.append(('seekable',))
        return True

    @property
    def closed(self):
        CALLS.append(('closed',))
        return self.store.closed

    def value(self):
        return self.store.getvalue()


ALPHABETS = {
    'ascii': u'ab\r\n',
    'latin-1': u'ab\xe9\r\n',
    'cp1252': u'a\xe9\u20ac\r\n',
    'utf-8': u'a\xe9\u20ac\r\n',
    'utf-8-sig': u'ab\u20ac\r\n',
    'utf-16': u'a\u20ac\r\n',
}
ENCODINGS = sorted(ALPHABETS)
NEWLINES = [None, '', '\n', '\r', '\r\n']
CHUNKS = [1, 2, 3, 4, 5, 7, 16, 8192]


def text(alphabet, length):
    return u''.join(pick(alphabet) for _ in range(length))


def attempt(function, *arguments):
    try:
        return function(*arguments)
    except StopIteration:
        return 'StopIteration'
    except Exception as error:
        return (type(error).__name__, str(error))


def scenario(index, keep):
    encoding = pick(ENCODINGS)
    alphabet = ALPHABETS[encoding]
    newline = pick(NEWLINES)
    kind = pick(['record', 'record', 'short', 'bytes', 'random'])
    logged = kind in ('record', 'short') or draw(2) == 1
    data = text(alphabet, draw(24)).encode(encoding)
    line_buffering = draw(4) == 0

    if kind == 'record':
        buffer = Recorder(data, 0)
    elif kind == 'short':
        buffer = Recorder(data, 1 + draw(3))
    elif kind == 'bytes':
        buffer = io.BytesIO(data)
    else:
        buffer = io.BufferedRandom(io.BytesIO(data), 1 + draw(8))

    name = 'log-' + encoding if logged else encoding
    stream = io.TextIOWrapper(buffer, name, None, newline, line_buffering)
    keep.append((buffer, stream))
    stream._CHUNK_SIZE = pick(CHUNKS)

    steps = [(encoding, newline, kind, logged, line_buffering, data, stream._CHUNK_SIZE, calls())]
    cookies = [0]

    def record(label, function, *arguments):
        result = attempt(function, *arguments)
        steps.append((label, arguments, result, calls()))
        return result

    for _ in range(18 + draw(10)):
        action = draw(20)
        if action < 4:
            size = pick([0, 1, 1, 2, 3, 5, 8, -1, None])
            record('read', stream.read, size)
        elif action < 7:
            limit = pick([None, None, 0, 1, 2, 5, -1])
            if limit is None:
                record('readline', stream.readline)
            else:
                record('readline', stream.readline, limit)
        elif action < 9:
            record('next', stream.next)
        elif action < 12:
            cookie = record('tell', stream.tell)
            if isinstance(cookie, (int, long)):
                cookies.append(cookie)
        elif action < 14:
            record('seek', stream.seek, pick(cookies))
        elif action == 14:
            whence = pick([1, 2])
            record('seek', stream.seek, 0, whence)
        elif action < 17:
            record('write', stream.write, text(alphabet, draw(6)))
        elif action == 17:
            record('flush', stream.flush)
        elif action == 18:
            stream._CHUNK_SIZE = pick(CHUNKS)
            steps.append(('chunk', stream._CHUNK_SIZE, calls()))
        else:
            record('truncate', stream.truncate)

    record('flush', stream.flush)
    if isinstance(buffer, Recorder):
        content = buffer.value()
    elif kind == 'bytes':
        content = buffer.getvalue()
    else:
        content = buffer.raw.getvalue()
    steps.append(('end', stream.newlines, content, calls()))
    return steps


def checked_walk(keep):
    # Every saved cookie must restore the character read after it.
    found = []
    for encoding in ENCODINGS:
        for newline in NEWLINES:
            source = text(ALPHABETS[encoding], 12)
            stream = io.TextIOWrapper(io.BytesIO(source.encode(encoding)), encoding, None, newline)
            keep.append(stream)
            stream._CHUNK_SIZE = pick(CHUNKS)
            seen = []
            while True:
                cookie = stream.tell()
                character = stream.read(1)
                if not character:
                    break
                seen.append((cookie, character))
            back = []
            for cookie, character in reversed(seen):
                stream.seek(cookie)
                back.append(stream.read(1) == character)
            found.append((encoding, newline, seen, all(back)))
    return found


KEEP = []
RESULT = ([scenario(index, KEEP) for index in range(40)], checked_walk(KEEP))
