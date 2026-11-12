# operator.index and the other index conversions (number_index,
# _PyEval_SliceIndex, sequence_repeat) on old-style instances, which always
# have an nb_index slot: one without __index__ raises "object cannot be
# interpreted as an index", and __index__ results must be int or long.
import operator


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


class Plain:
    pass


class Indexed:
    def __index__(self):
        return 2


class LongIndexed:
    def __index__(self):
        return 3L


class BadIndexed:
    def __index__(self):
        return 'x'


class Dynamic:
    def __getattr__(self, name):
        if name == '__index__':
            return lambda: 1
        raise AttributeError(name)


class Raising:
    def __index__(self):
        raise ValueError('boom')


class NewPlain(object):
    pass


class NewIndexed(object):
    def __index__(self):
        return 1


instances = [Plain(), Indexed(), LongIndexed(), BadIndexed(), Dynamic(), Raising(), NewPlain(), NewIndexed()]
seq = [10, 20, 30, 40]

RESULT = [
    (
        type(value).__name__ if not hasattr(value, '__class__') else value.__class__.__name__,
        err(operator.index, value),
        err(operator.__index__, value),
        err(lambda: seq[value]),
        err(lambda: 'abcd'[value]),
        err(lambda: (1, 2, 3, 4)[value]),
        err(lambda: seq[value:]),
        err(lambda: seq[:value]),
        err(lambda: 'abcd'[value:3]),
        err(lambda: seq[value::2]),
        err(lambda: seq * value),
        err(lambda: value * seq),
        err(lambda: 'ab' * value),
        err(lambda: (1,) * value),
        err(lambda: slice(value, None).indices(4)),
        err(lambda: bytearray('abcd')[value]),
        err(lambda: xrange(10)[value]),
        err(lambda: seq.pop(value) if False else list(seq).__getitem__(value)),
        err(lambda: operator.getitem(seq, value)),
        err(lambda: operator.getslice(seq, value, 3)),
        err(lambda: operator.repeat(seq, value)),
    )
    for value in instances
]

# PyIndex_Check tests the slot without binding; slot_nb_index binds
# __index__ once per conversion.
binds = []


class CountingIndex(object):
    def __get__(self, instance, owner):
        binds.append(owner.__name__)
        return lambda: 2


class Described(object):
    __index__ = CountingIndex()


described = Described()
bind_counts = []
for operation in (
    lambda: seq[described], lambda: seq[described:], lambda: 'ab' * described,
    lambda: operator.index(described), lambda: xrange(5)[described], lambda: slice(described, None).indices(4),
):
    before = len(binds)
    bind_counts.append((err(operation), len(binds) - before))

RESULT.append(bind_counts)

# ISINDEX accepts every classic instance, so __getslice__ sees converted
# bounds or the conversion error.


class Sliced(object):
    def __getslice__(self, low, high):
        return ('getslice', low, high)

    def __getitem__(self, key):
        return ('getitem', type(key).__name__)


RESULT.append([err(lambda: Sliced()[value:2]) for value in instances + [described]])
