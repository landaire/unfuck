# Random operation sequences on buffered streams over raw streams that log
# every call. Raw streams return short reads and writes, block now and then,
# and report invalid positions after bad seeks. Each scenario records the
# results and the raw call log; the first scenarios are kept whole and the
# rest as digests.

import hashlib
import io

state = [20161227]


def below(n):
    state[0] = (state[0] * 1103515245 + 12345) % 2 ** 31
    return int((state[0] >> 8) % n)


def pick(items):
    return items[below(len(items))]


class Raw(io.RawIOBase):
    def __init__(self, data, chunk, limit, rpattern, wpattern):
        self.data = bytearray(data)
        self.position = 0
        self.chunk = chunk
        self.limit = limit
        self.rpattern = rpattern
        self.wpattern = wpattern
        self.rcount = 0
        self.wcount = 0
        self.log = []

    def readable(self):
        self.log.append(('readable',))
        return True

    def writable(self):
        self.log.append(('writable',))
        return True

    def seekable(self):
        self.log.append(('seekable',))
        return True

    def readinto(self, b):
        if self.rpattern:
            self.rcount += 1
            if self.rpattern[(self.rcount - 1) % len(self.rpattern)] == 'N':
                self.log.append(('readinto-none', len(b)))
                return None
        size = len(b)
        if self.chunk is not None:
            size = min(size, self.chunk)
        piece = bytes(self.data[self.position:self.position + size])
        self.log.append(('readinto', type(b).__name__, len(b), b.readonly, len(piece)))
        b[:len(piece)] = piece
        self.position += len(piece)
        return len(piece)

    def write(self, b):
        if self.wpattern:
            self.wcount += 1
            if self.wpattern[(self.wcount - 1) % len(self.wpattern)] == 'N':
                self.log.append(('write-none', len(b)))
                return None
        data = b.tobytes()
        if self.limit is not None:
            data = data[:self.limit]
        self.log.append(('write', type(b).__name__, b.readonly, len(b), data))
        end = self.position + len(data)
        if end > len(self.data):
            self.data.extend('\0' * (end - len(self.data)))
        self.data[self.position:end] = data
        self.position = end
        return len(data)

    def tell(self):
        self.log.append(('tell', self.position))
        return self.position

    def seek(self, offset, whence=0):
        if whence == 0:
            self.position = offset
        elif whence == 1:
            self.position += offset
        else:
            self.position = len(self.data) + offset
        self.log.append(('seek', offset, whence, self.position))
        return self.position

    def truncate(self, *args):
        self.log.append(('truncate',) + args)
        size = args[0] if args and args[0] is not None else self.position
        del self.data[size:]
        return size

    @property
    def closed(self):
        self.log.append(('closed',))
        return io.RawIOBase.closed.__get__(self)

    def isatty(self):
        self.log.append(('isatty',))
        return False

    def flush(self):
        self.log.append(('flush',))
        return io.RawIOBase.flush(self)

    def close(self):
        self.log.append(('close',))
        return io.RawIOBase.close(self)


def call(obj, op):
    name, args = op[0], op[1:]
    try:
        if name == 'readinto':
            b = bytearray(args[0])
            n = obj.readinto(b)
            return ('ok', n, str(b))
        if name == 'next':
            return ('ok', obj.next())
        if name == 'closed':
            return ('ok', obj.closed)
        result = getattr(obj, name)(*args)
        if isinstance(result, Raw):
            result = 'raw stream'
        return ('ok', result)
    except io.BlockingIOError as e:
        return ('err', 'BlockingIOError', e.args, e.characters_written)
    except Exception as e:
        return ('err', type(e).__name__, str(e))


def random_op(kind, size):
    readers = ['read', 'read', 'read1', 'peek', 'readline', 'readinto', 'seek', 'tell', 'next']
    writers = ['write', 'write', 'flush', 'seek', 'tell', 'truncate']
    names = {'reader': readers + ['flush'], 'writer': writers, 'random': readers + writers, 'pair': ['read', 'read1', 'peek', 'readinto', 'write', 'write', 'flush']}[kind]
    if below(60) == 0:
        return (pick(['close', 'detach', 'closed', 'isatty', 'readable', 'writable', 'seekable']),)
    name = pick(names)
    if name in ('read', 'readinto'):
        n = pick([-1, None, 0, 1, 2, 3, size - 1, size, size + 1, 2 * size, 3 * size + 1, below(4 * size + 2)])
        if name == 'readinto':
            n = max(0, n or 0)
        return (name,) if n is None and below(2) else (name, n)
    if name == 'read1':
        return (name, pick([0, 1, 2, size, size + 3, below(3 * size + 1)]))
    if name == 'peek':
        return (name,) if below(2) else (name, below(2 * size + 1))
    if name == 'readline':
        return (name,) if below(5) < 3 else (name, pick([-1, 0, 1, 2, below(3 * size + 1)]))
    if name == 'write':
        length = pick([0, 1, 2, size - 1, size, size + 1, 2 * size + 1, below(3 * size + 2)])
        return (name, ''.join(pick('XYZ\n') for _ in range(max(0, length))))
    if name == 'seek':
        whence = pick([0, 0, 1, 1, 2])
        if whence == 0:
            return (name, below(70))
        if whence == 1:
            return (name, below(24) - 12, 1)
        return (name, -below(21), 2)
    if name == 'truncate':
        return (name,) if below(2) else (name, below(70))
    return (name,)


def scenario():
    kind = pick(['reader', 'writer', 'random', 'random', 'pair'])
    size = below(10) + 1
    data = ''.join(pick('abcdefgh\n') for _ in range(below(60)))
    chunk = pick([None, None, below(7) + 1])
    limit = pick([None, None, below(5) + 1])
    rpattern = pick([None, None, None, 'N', 'YN', 'YYN', 'NYY'])
    wpattern = pick([None, None, None, 'N', 'YN', 'YYN', 'NYY'])
    raw = Raw(data, chunk, limit, rpattern, wpattern)
    if kind == 'pair':
        other = Raw('', chunk, limit, rpattern, wpattern)
        other.log = raw.log
        obj = io.BufferedRWPair(raw, other, size)
    else:
        obj = {'reader': io.BufferedReader, 'writer': io.BufferedWriter, 'random': io.BufferedRandom}[kind](raw, size)
    trace = [(kind, size, data, chunk, limit, rpattern, wpattern, list(raw.log))]
    for step in range(30):
        op = random_op(kind, size)
        del raw.log[:]
        trace.append((op, call(obj, op), list(raw.log)))
    del raw.log[:]
    return trace


traces = [scenario() for _ in range(300)]
RESULT = (traces[:6], [hashlib.md5(repr(trace)).hexdigest() for trace in traces[6:]])
