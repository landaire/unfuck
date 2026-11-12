import codecs
import io

# The calls TextIOWrapper makes on its buffer, codec objects, and itself,
# and its argument and state errors.

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


STATE = {}


class OddDecoder(object):
    def __init__(self, errors='strict'):
        pass

    def decode(self, data, final=False):
        CALLS.append(('odd.decode', data, final))
        return STATE.get('decode', lambda data: data.decode('ascii'))(data)

    def getstate(self):
        CALLS.append(('odd.getstate',))
        return STATE.get('state', ('', 0))

    def setstate(self, state):
        CALLS.append(('odd.setstate', state))

    def reset(self):
        CALLS.append(('odd.reset',))


class OddEncoder(object):
    def __init__(self, errors='strict'):
        pass

    def encode(self, text, final=False):
        CALLS.append(('odd.encode', text))
        return STATE.get('encode', lambda text: text.encode('ascii'))(text)

    def setstate(self, state):
        CALLS.append(('odd.esetstate', state))

    def reset(self):
        CALLS.append(('odd.ereset',))


def search(name):
    if name.startswith('log-'):
        return wrap_codec(name[4:].replace('_', '-'))
    if name == 'odd':
        return codecs.CodecInfo(None, None, incrementalencoder=OddEncoder, incrementaldecoder=OddDecoder, name='odd')
    if name.startswith('quote'):
        return codecs.lookup('ascii')


codecs.register(search)


class Recorder(io.BufferedIOBase):
    def __init__(self, data='', readable=True, writable=True, seekable=True, **extra):
        self.store = io.BytesIO(data)
        self.flags = (readable, writable, seekable)
        self.extra = extra

    def read1(self, size):
        CALLS.append(('read1', size))
        if 'read1' in self.extra:
            return self.extra['read1']
        return self.store.read(size)

    def read(self, *arguments):
        CALLS.append(('read',) + arguments)
        return self.store.read(*arguments)

    def write(self, data):
        CALLS.append(('write', data))
        return self.store.write(data)

    def flush(self):
        CALLS.append(('flush',))
        if 'flush' in self.extra:
            return self.extra['flush']()

    def seek(self, *arguments):
        CALLS.append(('seek',) + arguments)
        result = self.store.seek(*arguments)
        return self.extra.get('seek', result)

    def tell(self):
        CALLS.append(('tell',))
        return self.extra.get('tell', self.store.tell())

    def truncate(self, *arguments):
        CALLS.append(('truncate',) + arguments)
        return self.store.truncate(*arguments)

    def readable(self):
        CALLS.append(('readable',))
        return self.flags[0]

    def writable(self):
        CALLS.append(('writable',))
        return self.flags[1]

    def seekable(self):
        CALLS.append(('seekable',))
        return self.flags[2]

    def isatty(self):
        CALLS.append(('isatty',))
        return False

    def fileno(self):
        CALLS.append(('fileno',))
        return 7

    def close(self):
        CALLS.append(('close',))
        self.store.close()
        return self.extra.get('close')

    @property
    def closed(self):
        CALLS.append(('closed',))
        return self.store.closed

    @property
    def name(self):
        CALLS.append(('name',))
        if 'name' in self.extra:
            return self.extra['name']
        raise AttributeError('name')

    def value(self):
        return self.store.getvalue()


KEEP = []


def attempt(function, *arguments, **keywords):
    try:
        result = function(*arguments, **keywords)
    except StopIteration:
        result = 'StopIteration'
    except Exception as error:
        result = (type(error).__name__, str(error))
    KEEP.append(result)
    if isinstance(result, io.TextIOWrapper):
        result = 'wrapper'
    elif isinstance(result, Recorder):
        result = 'recorder'
    return (result, calls())


def wrapper(data='', encoding='log-ascii', newline='\n', chunk=None, line_buffering=False, **flags):
    buffer = Recorder(data, **flags)
    stream = io.TextIOWrapper(buffer, encoding, None, newline, line_buffering)
    if chunk is not None:
        stream._CHUNK_SIZE = chunk
    KEEP.append((buffer, stream))
    calls()
    return buffer, stream


T = io.TextIOWrapper
B = io.BytesIO

construction = []
for flags in [{}, {'readable': False}, {'writable': False}, {'seekable': False}, {'writable': False, 'seekable': False}, {'seekable': 'yes', 'readable': 1}]:
    construction.append(attempt(T, Recorder('abc', **flags), 'log-utf-8', None, ''))
for tell in [0, 3, 0.0, 'x']:
    construction.append(attempt(T, Recorder('', tell=tell), 'log-utf-16'))
construction.append(attempt(T))
construction.append(attempt(T, B(), 'ascii', None, None, 0, 5))
construction.append(attempt(T, B(), foo=1))
construction.append(attempt(T, B(), 5))
construction.append(attempt(T, B(), 'asc\0ii'))
construction.append(attempt(T, B(), 'nope'))
construction.append(attempt(T, B(), 'ascii', 5))
construction.append(attempt(T, B(), 'ascii', None, 5))
construction.append(attempt(T, B(), 'ascii', None, 'x'))
construction.append(attempt(T, B(), 'ascii', None, '\n\r'))
construction.append(attempt(T, B(), 'ascii', None, None, 'x'))
construction.append(attempt(T, B(), 'ascii', None, None, 1.5))
construction.append(attempt(lambda: T(B(), 'ascii', None, None, 2).line_buffering))
construction.append(attempt(lambda: T(B(), u'latin-1', u'replace', u'\r').encoding))
construction.append(attempt(T, None, 'ascii'))
construction.append(attempt(lambda: T(buffer=B(), encoding='ascii').encoding))

reinit = []
for arguments in [(B('abc'), 'ascii', None, 'bad'), (B('abc'), 'nope'), (B('abc'), 5), (B('xyz'), 'ascii')]:
    stream = T(B('qq'), 'latin-1', 'replace', '\r', True)
    KEEP.append(stream)
    outcome = attempt(stream.__init__, *arguments)
    reinit.append((outcome, stream.encoding, stream.line_buffering, stream.buffer is None, attempt(getattr, stream, 'errors'), attempt(stream.read)))

blank = T.__new__(T)
uninitialized = [attempt(repr, blank), blank.encoding, blank.buffer, blank.line_buffering]
for name, arguments in [('read', ()), ('read', ('x',)), ('readline', ()), ('write', (u'x',)), ('write', ('x',)), ('tell', ()), ('tell', (1,)), ('seek', (0,)), ('seek', ()), ('flush', ()), ('close', ()), ('detach', ()), ('fileno', ()), ('isatty', ()), ('seekable', ()), ('readable', ()), ('writable', ()), ('truncate', ()), ('next', ())]:
    uninitialized.append((name, attempt(getattr(blank, name), *arguments)))
for name in ['errors', 'closed', 'name', 'newlines', '_CHUNK_SIZE']:
    uninitialized.append((name, attempt(getattr, blank, name)))
uninitialized.append(attempt(setattr, blank, '_CHUNK_SIZE', 5))
uninitialized.append(attempt(delattr, blank, '_CHUNK_SIZE'))

attributes = []
buffer, stream = wrapper('abc')
for value in [0, -1, 'x', 1.5, 10L, True, 2147483648L, None]:
    attributes.append((value, attempt(setattr, stream, '_CHUNK_SIZE', value), stream._CHUNK_SIZE))
for name in ['encoding', 'line_buffering', 'buffer', 'newlines', 'name', 'errors', 'closed']:
    attributes.append((name, attempt(setattr, stream, name, 1)))
stream.other = 5
attributes.append((stream.other, attempt(lambda: stream.mode)))
attributes.append(attempt(repr, stream))
attributes.append(attempt(repr, wrapper('', name='file.txt')[1]))
attributes.append(attempt(repr, wrapper('', name=u'\xe9')[1]))
attributes.append(attempt(repr, wrapper('', name=5)[1]))
attributes.append(attempt(repr, T(B(), "quote'x")))
attributes.append(attempt(repr, T(B(), 'ASCII')))
for newline in [None, '', '\n', '\r', '\r\n']:
    source = T(B('a\r\nb\rc\nd'), 'ascii', None, newline)
    KEEP.append(source)
    before = source.newlines
    lines = source.readlines()
    attributes.append((newline, before, lines, source.newlines))
attributes.append(attempt(lambda: wrapper('a', readable=False)[1].newlines))

forwarding = []
buffer, stream = wrapper('abc')
for name in ['fileno', 'isatty', 'seekable', 'readable', 'writable']:
    forwarding.append((name, attempt(getattr(stream, name))))
forwarding.append(attempt(stream.flush, 1))
forwarding.append(attempt(stream.truncate, 1, 2))
forwarding.append(attempt(stream.truncate))
forwarding.append(attempt(stream.truncate, 2))
forwarding.append(attempt(stream.truncate, 'x'))
forwarding.append(attempt(wrapper('abc', flush=lambda: 42)[1].flush))

arguments = []
for name, values in [('read', [-5, None, 'x', 1.5, 2L]), ('readline', ['x', None, 1.5, 2L]), ('write', ['x', 5, u'\xe9'])]:
    for value in values:
        arguments.append((name, value, attempt(getattr(wrapper('abc')[1], name), value)))
arguments.append(attempt(wrapper('abc')[1].read, 1, 2))
arguments.append(attempt(wrapper('abc')[1].read, n=1))
arguments.append(attempt(wrapper('abc')[1].readline, 1, 2))
arguments.append(attempt(wrapper('abc')[1].write))
for seek in [('x',), (1.5,), (0, 'x'), (0, 1.5), (), (-1,), (-2 ** 70,), (0, 3), (1, 1), (1, 2), (-1, 1), (0, 1L), (True,)]:
    arguments.append((seek, attempt(wrapper('abcdef')[1].seek, *seek)))

cookies = []
for cookie in [1 << 64, (1 << 64) | 2, (2 << 128) | 1, (2 << 128) | (1 << 96) | 1, (3 << 96) | 1, (1 << 160) | (3 << 96) | (1 << 128) | 1, (1 << 160) | 3, 1 << 167, 1 << 168, 0xffffffff << 64, 0xffffffff << 96, (2 << 160) | 1, (1 << 160) | (1 << 128) | (2 << 96) | 4]:
    buffer, stream = wrapper('ab\ncd\n')
    outcome = attempt(stream.seek, cookie)
    cookies.append((cookie, outcome, attempt(stream.tell), attempt(stream.read)))

modes = []
buffer, stream = wrapper('abc\ndef\n', seekable=False)
for name, operation in [('read', lambda: stream.read(2)), ('tell', stream.tell), ('seek', lambda: stream.seek(0)), ('seek1', lambda: stream.seek(0, 1)), ('seek5', lambda: stream.seek(0, 5)), ('truncate', stream.truncate), ('readline', stream.readline), ('next', stream.next), ('write', lambda: stream.write(u'x')), ('flush', stream.flush)]:
    modes.append(('unseekable', name, attempt(operation)))
buffer, stream = wrapper('abc\ndef\n', readable=False)
for name, operation in [('write', lambda: stream.write(u'x')), ('read', lambda: stream.read(2)), ('readline', stream.readline), ('readall', stream.read), ('next', stream.next), ('tell', stream.tell), ('seek', lambda: stream.seek(0)), ('tell', stream.tell)]:
    modes.append(('unreadable', name, attempt(operation)))
buffer, stream = wrapper('abc\ndef\n', writable=False)
for name, operation in [('write', lambda: stream.write(u'x')), ('empty', lambda: stream.write(u'')), ('read', lambda: stream.read(2)), ('tell', stream.tell), ('seek', lambda: stream.seek(3))]:
    modes.append(('unwritable', name, attempt(operation)))

pending = []
buffer, stream = wrapper('', chunk=4)
for text in [u'a', u'bc', u'd', u'e', u'fghij', u'', u'k', u'lmnopqrs', u'tu']:
    pending.append(attempt(stream.write, text))
pending.append(attempt(stream.flush))
for newline in ['', '\n', '\r', '\r\n']:
    buffer, stream = wrapper('', newline=newline, line_buffering=True)
    for text in [u'a', u'b\n', u'c\r', u'd\r\ne', u'']:
        pending.append((newline, attempt(stream.write, text)))
    buffer, stream = wrapper('', newline=newline)
    for text in [u'a\nb', u'c\r', u'd\r\ne']:
        pending.append((newline, attempt(stream.write, text)))
    pending.append((newline, attempt(stream.flush), buffer.value()))
buffer, stream = wrapper('abc\ndef\n')
for name, operation in [('write', lambda: stream.write(u'XY')), ('read', lambda: stream.read(2)), ('tell', stream.tell), ('seek', lambda: stream.seek(0)), ('write', lambda: stream.write(u'U')), ('detach', stream.detach)]:
    pending.append((name, attempt(operation)))
buffer, stream = wrapper('ab')
pending.append(attempt(stream.write, u'x'))
pending.append(attempt(stream.read, 0))

iteration = []
buffer, stream = wrapper('abc\ndef\n')
for name, operation in [('next', stream.next), ('tell', stream.tell), ('read', lambda: stream.read(1)), ('next', stream.next), ('next', stream.next), ('tell', stream.tell), ('seek', lambda: stream.seek(1)), ('next', stream.next), ('seek1', lambda: stream.seek(0, 1)), ('flush', stream.flush), ('tell', stream.tell)]:
    iteration.append((name, attempt(operation)))
for setup in [lambda stream: stream.seek(0), lambda stream: stream.read(1), lambda stream: None, lambda stream: stream.seek(3), lambda stream: stream.read(0)]:
    buffer, stream = wrapper('abc\ndef\nghi\n', chunk=5)
    setup(stream)
    calls()
    iteration.append((attempt(stream.next), attempt(stream.flush), attempt(stream.tell)))

replays = []
for encoding, data, newline, chunk, steps in [
    ('log-utf-8', u'ab\xe9cd\u20ac\nxy\r\nz\rlast'.encode('utf-8'), None, 4, [3, 0, 2, 5, 8, 20]),
    ('log-utf-8', u'ab\xe9cd\u20ac\nxy\r\nz\rlast'.encode('utf-8'), '', 4, [1, 3, 4, 9]),
    ('log-utf-16', u'ab\ncd'.encode('utf-16'), '\n', 4, [1, 2, 3, 5]),
    ('log-utf-8', 'ab\xe2', '\n', None, [2, 1]),
    ('log-ascii', 'ab\rcd\r', '', 3, [1, 2, 3, 2]),
    ('log-ascii', 'ab\rcd\r', None, 3, [1, 2, 3, 2]),
]:
    buffer, stream = wrapper(data, encoding, newline, chunk)
    for size in steps:
        replays.append((attempt(stream.read, size), attempt(stream.tell)))
buffer = Recorder('ab\xe2')
stream = T(buffer, 'log-utf-8', 'replace', '\n')
KEEP.append(stream)
calls()
replays.append((attempt(stream.read, 2), attempt(stream.read, 1)))
cookie = stream.tell()
replays.append((cookie, calls(), attempt(stream.seek, cookie), attempt(stream.read)))
for encoding, data, newline, chunk, limits in [
    ('log-ascii', 'ab\r\ncd\r\n', '\r\n', 3, [None, None, None]),
    ('log-ascii', 'ab\r\ncd\r\n', '\r\n', 3, [3, 1]),
    ('log-ascii', 'abcdefgh\nij', '\n', 3, [5, 2, 10, None, None]),
    ('log-ascii', 'ab\rcd\r', '', 3, [None, None, None]),
    ('log-ascii', 'ab\rcd\r', None, 3, [None, None, None]),
    ('log-utf-8', 'ab\xe2', '\n', None, [None, None]),
]:
    buffer, stream = wrapper(data, encoding, newline, chunk)
    for limit in limits:
        line = attempt(stream.readline) if limit is None else attempt(stream.readline, limit)
        replays.append((line, attempt(stream.tell)))

odd = []
for state in [(u'', 0), ('', 'x'), ('', 1.5), ('', 7L), ('', True), ('ab', 1), (bytearray('ab'), 1), ['', 3]]:
    STATE.clear()
    STATE['state'] = state
    buffer, stream = wrapper('abcdef', 'odd')
    first = attempt(stream.read, 1)
    STATE['state'] = ('', 0)
    buffer, stream = wrapper('abcdef', 'odd')
    stream.read(1)
    calls()
    STATE['state'] = state
    odd.append((state, first, attempt(stream.tell)))
STATE.clear()
for decode in [lambda data: data, lambda data: 5, lambda data: bytearray(data)]:
    STATE['decode'] = decode
    odd.append((attempt(wrapper('abcdef', 'odd')[1].read, 1), attempt(wrapper('abcdef', 'odd')[1].read), attempt(wrapper('abcdef', 'odd')[1].readline)))
STATE.clear()
for encode in [lambda text: u'x', lambda text: bytearray('x')]:
    STATE['encode'] = encode
    buffer, stream = wrapper('', 'odd')
    odd.append((attempt(stream.write, u'abc'), attempt(stream.flush), buffer.value()))
STATE.clear()
for result in [u'abc', None, 5, bytearray('abc')]:
    odd.append((attempt(wrapper('abcdef', 'odd', read1=result)[1].read, 1), attempt(wrapper('abcdef', 'log-ascii', read1=result)[1].readline)))
for tell in [7, 7.5, 'x', -50]:
    buffer, stream = wrapper('abc', tell=tell)
    before = attempt(stream.tell)
    stream.read(1)
    calls()
    odd.append((tell, before, attempt(stream.tell)))
buffer, stream = wrapper('abc', seek='moved')
odd.append((attempt(stream.seek, 0), attempt(stream.seek, 0, 2)))


class Sub(io.TextIOWrapper):
    pass


def traced(name):
    base = getattr(io.TextIOWrapper, name)

    def method(self, *arguments):
        CALLS.append(('self.' + name,) + arguments)
        return base(self, *arguments)
    return method


for name in ['flush', 'tell', 'seek', 'close', 'readline', 'read', 'write', 'detach', 'truncate', 'next']:
    setattr(Sub, name, traced(name))


def traced_closed(self):
    CALLS.append(('self.closed',))
    return io.TextIOWrapper.closed.__get__(self)


Sub.closed = property(traced_closed)

subclass = []
buffer = Recorder('abc\ndef\nghi\n')
stream = Sub(buffer, 'log-ascii', None, '\n')
KEEP.append(stream)
calls()
for name, operation in [('read', lambda: stream.read(2)), ('tell', stream.tell), ('seek', lambda: stream.seek(0)), ('seek1', lambda: stream.seek(0, 1)), ('seek2', lambda: stream.seek(0, 2)), ('seek0', lambda: stream.seek(0)), ('list', lambda: list(stream)), ('seek0', lambda: stream.seek(0)), ('next', stream.next), ('tell', stream.tell), ('write', lambda: stream.write(u'x\n')), ('truncate', stream.truncate), ('repr', lambda: repr(stream)), ('close', stream.close), ('close', stream.close), ('detach', stream.detach)]:
    subclass.append((name, attempt(operation)))
buffer = Recorder('')
stream = Sub(buffer, 'log-ascii', None, '\n', True)
KEEP.append(stream)
calls()
subclass.append(attempt(stream.write, u'x\ny'))
subclass.append(attempt(stream.detach))
subclass.append(attempt(stream.detach))
subclass.append(attempt(stream.close))

ending = []
buffer, stream = wrapper('abc')
stream.detach()
for name in ['encoding', 'errors', 'line_buffering', 'buffer', 'closed', 'name', 'newlines', '_CHUNK_SIZE']:
    ending.append(('detached', name, attempt(getattr, stream, name)))
ending.append(attempt(setattr, stream, '_CHUNK_SIZE', 5))
ending.append(attempt(delattr, stream, '_CHUNK_SIZE'))
for name, arguments in [('read', ()), ('read', ('x',)), ('readline', ()), ('write', (u'x',)), ('write', ('x',)), ('tell', ()), ('seek', (0,)), ('flush', ()), ('close', ()), ('detach', ()), ('fileno', ()), ('isatty', ()), ('seekable', ()), ('truncate', ()), ('next', ())]:
    ending.append(('detached', name, attempt(getattr(stream, name), *arguments)))
ending.append(attempt(repr, stream))
buffer, stream = wrapper('abc')
ending.append(attempt(stream.close))
for name in ['encoding', 'errors', 'closed', 'name', 'newlines', '_CHUNK_SIZE']:
    ending.append(('closed', name, attempt(getattr, stream, name)))
for name, arguments in [('read', ()), ('read', ('x',)), ('readline', ()), ('write', (u'x',)), ('write', ('x',)), ('tell', ()), ('seek', (0,)), ('seek', (0, 'x')), ('seek', (0, 5)), ('flush', ()), ('close', ()), ('fileno', ()), ('isatty', ()), ('seekable', ()), ('truncate', ('x',)), ('next', ()), ('detach', ())]:
    ending.append(('closed', name, attempt(getattr(stream, name), *arguments)))
ending.append(attempt(repr, stream))


def failing_flush():
    raise IOError('flush fails')


buffer, stream = wrapper('abc', flush=failing_flush)
ending.append((attempt(stream.close), stream.closed))
buffer, stream = wrapper('abc', close=7)
ending.append(attempt(stream.close))


class FailingClose(Recorder):
    def close(self):
        CALLS.append(('close',))
        raise ValueError('close fails')


stream = io.TextIOWrapper(FailingClose('abc', flush=failing_flush), 'ascii')
KEEP.append(stream)
calls()
ending.append(attempt(stream.close))

RESULT = (construction, reinit, uninitialized, attributes, forwarding, arguments, cookies, modes, pending, iteration, replays, odd, subclass, ending)
