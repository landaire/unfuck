# The Pickler type: file objects, list mode, memo, fast mode, and
# persistent ids.
import cPickle
import cStringIO
import re


def K(x):
    return x


def attempt(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception as e:
        return (type(e).__name__, re.sub(' at 0x[0-9a-fA-F]+', '', str(e)))


class Sink(object):
    def __init__(self):
        self.calls = []

    def write(self, data):
        self.calls.append(data)


RESULT = []

for protocol in (0, 1, 2):
    sink = Sink()
    pickler = cPickle.Pickler(sink, protocol)
    RESULT.append(pickler.dump([K('x') * 300, K('y') * 100, K('z') * 200]) is pickler)
    RESULT.append(sink.calls)
    sink = Sink()
    cPickle.dump([K(1), K('two')], sink, protocol)
    RESULT.append(sink.calls)

stream = cStringIO.StringIO()
p = cPickle.Pickler(stream, 2)
shared = [K(1)]
p.dump(shared)
p.dump(shared)
p.clear_memo()
p.dump(shared)
RESULT.append(stream.getvalue())
RESULT.append(sorted(v[0] for v in p.memo.values()))
RESULT.append(p.memo.values()[0][1] is shared)

for protocol in (0, 1, 2):
    p = cPickle.Pickler(protocol)
    s = [K('s') * 2]
    big = K('b') * 200
    p.dump([s, s, big, big, (K(1), K(2))])
    RESULT.append(attempt(p.getvalue, 0))
    RESULT.append(attempt(p.getvalue))
    RESULT.append(attempt(p.getvalue))
    RESULT.append(p.dump(K(5), 1))

p = cPickle.Pickler()
RESULT.append((p.binary, p.fast))
p = cPickle.Pickler(protocol=2)
RESULT.append(p.binary)
p.dump(K(1))
p.clear_memo()
RESULT.append(attempt(p.getvalue))
lst = [K(1)]
p = cPickle.Pickler(1)
p.dump([lst, lst])
p.clear_memo()
RESULT.append(attempt(p.getvalue))
p = cPickle.Pickler(None)
RESULT.append(p.dump([K(1)]) is p)
RESULT.append(attempt(p.getvalue))
RESULT.append(len(p.memo))

p = cPickle.Pickler(None, 2)
RESULT.append((p.binary, p.fast, p.memo, p.PicklingError is cPickle.PicklingError))
RESULT.append(attempt(getattr, p, 'persistent_id'))
RESULT.append(attempt(getattr, p, 'inst_persistent_id'))
RESULT.append(attempt(setattr, p, 'memo', K(5)))
RESULT.append(attempt(delattr, p, 'memo'))
RESULT.append(attempt(delattr, p, 'persistent_id'))
RESULT.append(attempt(delattr, p, 'binary'))
RESULT.append(attempt(setattr, p, 'binary', 'x'))
RESULT.append(attempt(setattr, p, 'PicklingError', 1))
RESULT.append(attempt(setattr, p, 'other', 1))
RESULT.append(attempt(p.dump))
RESULT.append(attempt(p.dump, 1, 2, 3))
RESULT.append(attempt(p.clear_memo, 1))
RESULT.append(attempt(p.getvalue, 1, 2))
p.binary = 0
stream = cStringIO.StringIO()
p = cPickle.Pickler(stream, 2)
p.binary = 0
p.dump([K(1), K('ab'), K(1.5)])
RESULT.append(stream.getvalue())
P = type(p)
RESULT.append((P.__name__, P.__module__, repr(P)))
RESULT.append(attempt(P))
RESULT.append(sorted(k for k in P.__dict__ if not k.startswith('__')))
RESULT.append([type(P.__dict__[k]).__name__ for k in ('binary', 'fast', 'memo', 'persistent_id')])


def persistent(obj):
    if isinstance(obj, str) and obj.startswith('ext'):
        return obj.upper()
    return None


def persistent_bin(obj):
    if isinstance(obj, int) and obj > 100:
        return 'id%d' % obj
    return None


for protocol in (0, 1, 2):
    stream = cStringIO.StringIO()
    p = cPickle.Pickler(stream, protocol)
    p.persistent_id = persistent
    p.dump([K('ext1'), K('plain'), K('ext2'), K('plain')])
    RESULT.append(stream.getvalue())
    stream = cStringIO.StringIO()
    p = cPickle.Pickler(stream, protocol)
    p.persistent_id = persistent_bin
    RESULT.append(attempt(lambda: p.dump([K(5), K(500)]) is p))
    RESULT.append(stream.getvalue())
    stream = cStringIO.StringIO()
    p = cPickle.Pickler(stream, protocol)
    p.inst_persistent_id = persistent
    p.dump([K('ext1'), K(3), set([K(1)])])
    RESULT.append(stream.getvalue())

for protocol in (0, 1, 2):
    stream = cStringIO.StringIO()
    p = cPickle.Pickler(stream, protocol)
    p.fast = 1
    shared = [K(1)]
    p.dump([shared, shared, K('abc'), K('abc')])
    RESULT.append(stream.getvalue())
    deep = []
    for i in range(60):
        deep = [deep]
    p.dump(deep)
    loop = []
    loop.append(loop)
    for i in range(60):
        loop = [loop]
    message = attempt(p.dump, loop)
    RESULT.append((message[0], message[1].split(' at ')[0]))
