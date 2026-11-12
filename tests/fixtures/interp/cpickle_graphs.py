# Pickles generated object graphs with cPickle and records the bytes.
#
# The graphs mix scalars, strings and unicode that are created fresh or
# shared, nested containers with shared parts and cycles, classic and
# new-style instances, and objects with reductions. Whether cPickle
# memoizes a string, tuple, or instance depends on how many references it
# has, so the builder drops its own references before anything is pickled.
import cPickle
import cStringIO
import imp
import re
import sys

HELPERS = imp.new_module('cpickle_graph_helpers')
sys.modules['cpickle_graph_helpers'] = HELPERS


def export(obj):
    obj.__module__ = 'cpickle_graph_helpers'
    setattr(HELPERS, obj.__name__, obj)
    return obj


class Random(object):
    """A linear congruential generator, so that every interpreter builds
    the same graphs."""

    def __init__(self, seed):
        self.state = seed

    def below(self, bound):
        self.state = (self.state * 1103515245 + 12345) % 2147483648
        return (self.state >> 8) % bound


@export
class Classic:
    pass


@export
class ClassicArgs:
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def __getinitargs__(self):
        return (self.first, self.second)


@export
class ClassicState:
    def __init__(self, state):
        self.state = state

    def __getstate__(self):
        return self.state

    def __setstate__(self, state):
        self.state = state


@export
class Plain(object):
    pass


@export
class Slotted(object):
    __slots__ = ('x', 'y')


@export
class WithArgs(object):
    def __new__(cls, *args):
        self = object.__new__(cls)
        self.args = args
        return self

    def __getnewargs__(self):
        return self.args


@export
def rebuild(*args):
    return list(args)


@export
class Reduced(object):
    def __init__(self, parts):
        self.parts = parts

    def __reduce__(self):
        return (rebuild, self.parts)


@export
class ReducedFull(object):
    def __init__(self, state, items, pairs):
        self.state = state
        self.items = items
        self.pairs = pairs

    def __reduce__(self):
        return (rebuild, (), self.state, iter(self.items), iter(self.pairs))


@export
class Listed(list):
    pass


@export
class Mapped(dict):
    pass


INTS = [0, 1, -1, 7, 255, 256, 65535, 65536, -256, -65536, 2147483647, -2147483648, 2147483648, -2147483649, 4611686018427387904]
LONGS = [0L, 1L, -1L, 127L, 128L, 255L, 256L, -128L, -129L, -256L, -257L, 2L ** 31, -(2L ** 31), 2L ** 63, -(2L ** 63) - 1, 2L ** 64, 3L ** 100, -(7L ** 200), 2L ** 2040, -(2L ** 2047)]
FLOATS = [0.0, -0.0, 1.0, 0.1, 1.5, -2.5e-300, 1e22, 1e16, 1e15, 1.0 / 3, 123456789.125, float('inf'), float('-inf')]
TEXT = u'ab\\\n\r\t\x00\x7f\x80\xe9\u20ac\ud800\udc00\U00012345 '


class Builder(object):
    def __init__(self, seed):
        self.random = Random(seed)
        # Objects that may be referenced again; cleared before pickling.
        self.pool = []

    def text(self, length):
        parts = []
        for _ in range(length):
            parts.append(TEXT[self.random.below(len(TEXT))])
        return u''.join(parts)

    def string(self):
        length = [0, 1, 2, 3, 5, 40, 255, 256, 300][self.random.below(9)]
        chars = 'xy\'"\\\n\x00\xff'
        parts = []
        for _ in range(length):
            parts.append(chars[self.random.below(len(chars))])
        return ''.join(parts)

    def scalar(self):
        kind = self.random.below(12)
        if kind == 0:
            return [None, True, False][self.random.below(3)]
        if kind <= 2:
            return INTS[self.random.below(len(INTS))] + 0
        if kind == 3:
            return LONGS[self.random.below(len(LONGS))] + 0L
        if kind == 4:
            return FLOATS[self.random.below(len(FLOATS))]
        if kind <= 7:
            return self.string()
        return self.text([0, 1, 2, 3, 6, 120][self.random.below(6)])

    def reuse(self):
        if not self.pool:
            return self.scalar()
        return self.pool[self.random.below(len(self.pool))]

    def remember(self, value):
        if self.random.below(3) == 0:
            self.pool.append(value)
        return value

    def items(self, depth, count):
        result = []
        for _ in range(count):
            result.append(self.value(depth - 1))
        return result

    def value(self, depth):
        if depth <= 0:
            return self.scalar() if self.random.below(4) else self.reuse()
        kind = self.random.below(16)
        if kind <= 2:
            return self.remember(self.scalar())
        if kind == 3:
            return self.reuse()
        if kind == 4:
            return self.remember(tuple(self.items(depth, self.random.below(6))))
        if kind == 5:
            value = self.remember([])
            value.extend(self.items(depth, self.random.below(8)))
            if self.random.below(4) == 0:
                value.append(value)
            return value
        if kind == 6:
            value = self.remember({})
            for item in self.items(depth, self.random.below(6)):
                key = self.scalar()
                # None hashes by its address, which differs between builds
                # and would reorder the dict.
                if key is None:
                    continue
                value[key] = item
            if self.random.below(4) == 0:
                value['self'] = value
            return value
        if kind == 7:
            value = self.remember(Classic())
            value.left = self.value(depth - 1)
            value.right = self.value(depth - 1)
            return value
        if kind == 8:
            return self.remember(ClassicArgs(self.value(depth - 1), self.scalar()))
        if kind == 9:
            return self.remember(ClassicState(self.value(depth - 1)))
        if kind == 10:
            value = self.remember(Plain())
            value.contents = self.value(depth - 1)
            if self.random.below(3) == 0:
                value.me = value
            return value
        if kind == 11:
            value = Slotted()
            value.x = self.value(depth - 1)
            if self.random.below(2):
                value.y = self.scalar()
            return self.remember(value)
        if kind == 12:
            return self.remember(WithArgs(self.scalar(), self.value(depth - 1)))
        if kind == 13:
            return self.remember(Reduced(tuple(self.items(depth, self.random.below(4)))))
        if kind == 14:
            pairs = []
            for item in self.items(depth, self.random.below(3)):
                pairs.append((self.scalar(), item))
            return self.remember(ReducedFull(self.value(depth - 1), self.items(depth, self.random.below(3)), pairs))
        value = self.remember(Listed(self.items(depth, self.random.below(4))))
        value.extra = self.scalar()
        return value


def graph(seed):
    builder = Builder(seed)
    root = builder.value(4)
    del builder.pool[:]
    return root


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        text = '%s: %s' % (type(error).__name__, re.sub(' at (0x)?[0-9a-fA-F]+', '', str(error)))
        # The traceback would keep the failed call's frames, and the objects
        # they reference, alive.
        del error
        sys.exc_clear()
        return text


def through_pickler(value, protocol, fast):
    stream = cStringIO.StringIO()
    pickler = cPickle.Pickler(stream, protocol)
    pickler.fast = fast
    pickler.dump(value)
    return stream.getvalue()


def collected(value, protocol):
    pickler = cPickle.Pickler(protocol)
    pickler.dump(value)
    return pickler.getvalue()


def reloaded(data, protocol):
    return cPickle.dumps(cPickle.loads(data), protocol)


def skimmed(data):
    return repr(cPickle.Unpickler(cStringIO.StringIO(data)).noload())


def record(value):
    out = []
    for protocol in (0, 1, 2):
        data = attempt(cPickle.dumps, value, protocol)
        out.append(data)
        out.append(attempt(through_pickler, value, protocol, 1))
        out.append(attempt(collected, value, protocol))
        if not data.startswith('PicklingError') and not data.startswith('RuntimeError'):
            out.append(attempt(reloaded, data, protocol))
            out.append(attempt(skimmed, data))
    return out


def batches(value):
    return [attempt(cPickle.dumps, value, protocol) for protocol in (0, 1, 2)]


RESULT = []
for seed in range(60):
    RESULT.append(record(graph(seed)))

# Lists and dicts longer than one APPENDS or SETITEMS batch.
long_list = []
for index in range(2001):
    long_list.append(index % 300)
long_dict = {}
for index in range(1001):
    long_dict[index] = index % 7
RESULT.append(batches(long_list))
RESULT.append(batches(long_dict))
RESULT.append(batches(Mapped(long_dict)))
RESULT.append(batches(Listed(long_list)))
