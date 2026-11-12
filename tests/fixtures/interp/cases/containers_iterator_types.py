import collections

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))

def K(value):
    return value

class Indexed(object):
    def __getitem__(self, index):
        if index < 3:
            return index
        raise IndexError(index)

class Sized(Indexed):
    def __len__(self):
        return 5

class Classic:
    def __getitem__(self, index):
        raise IndexError(index)

class ListLen(list):
    def __len__(self):
        return 100

def callable_source():
    return 1

samples = [
    iter(K([1, 2])), reversed(K([1, 2])), iter(K((1, 2))), iter(K('ab')),
    iter(K(u'ab')), iter(xrange(K(3))), reversed(xrange(K(3))),
    iter(K(set([1]))), iter(K(frozenset([1]))), iter(K({1: 2})),
    K({1: 2}).iterkeys(), K({1: 2}).itervalues(), K({1: 2}).iteritems(),
    iter(K({1: 2}).viewkeys()), iter(K({1: 2}).viewvalues()),
    iter(K({1: 2}).viewitems()), iter(callable_source, 1),
    iter(bytearray(K('ab'))), iter(Indexed()), reversed(K((1, 2))),
    reversed(K('ab')), enumerate(K('ab')), iter(type.__dict__),
]

def hints(iterator):
    hint = getattr(iterator, '__length_hint__', None)
    if hint is None:
        return None
    values = [hint()]
    for _ in range(3):
        try:
            next(iterator)
        except StopIteration:
            pass
        values.append(hint())
    return values

def mutated():
    values = []
    items = K([1, 2, 3])
    iterator = iter(items)
    next(iterator)
    del items[:]
    values.append(iterator.__length_hint__())
    array = bytearray(K('abc'))
    iterator = iter(array)
    next(iterator)
    next(iterator)
    del array[:]
    values.append(iterator.__length_hint__())
    mapping = {1: 2, 3: 4}
    iterator = iter(mapping)
    mapping[5] = 6
    values.append(iterator.__length_hint__())
    items = K([1, 2, 3])
    iterator = reversed(items)
    del items[1:]
    values.append(iterator.__length_hint__())
    values.append(iter(Sized()).__length_hint__())
    values.append(iter(ListLen([1, 2])).__length_hint__())
    values.append(attempt(iter(Classic()).__length_hint__))
    return values

def same_size_hint():
    mapping = {0: 0, 1: 1, 2: 2}
    iterator = mapping.iterkeys()
    next(iterator)
    for old, new in [(2, 142), (1, 235), (235, 398), (0, 33), (398, 227), (142, 21)]:
        del mapping[old]
        mapping[new] = new
    items = set([1, 2, 3])
    set_iterator = iter(items)
    next(set_iterator)
    items.remove(3)
    items.add(9)
    return [iterator.__length_hint__(), set_iterator.__length_hint__()]

listiterator = type(iter([]))
RESULT = [
    [type(sample).__name__ for sample in samples],
    [hints(sample) for sample in samples[:18]],
    attempt(hints, iter(Indexed())),
    mutated(),
    attempt(listiterator.next, iter(())),
    attempt(listiterator.__length_hint__, iter(())),
    attempt(listiterator.__iter__, [], 1),
    attempt(listiterator.next, iter([1]), 1),
    attempt(listiterator.__length_hint__, iter([1]), 1),
    attempt(type(iter(set())).next, iter([1])),
    attempt(type(reversed(())).__length_hint__, iter([1])),
    hasattr(iter(callable_source, 1), '__length_hint__'),
    hasattr(enumerate(''), '__length_hint__'),
    same_size_hint(),
    attempt(type(reversed(())).__length_hint__, 42, 1),
    attempt(type(K('x')._formatter_parser()).__iter__, 42),
    attempt(type(K('x')._formatter_field_name_split()[1]).__iter__, 42),
    attempt(type(K('x')._formatter_parser()).next, 42),
    sorted(name for name in dir(listiterator) if not name.startswith('__') or name in ('__length_hint__', '__iter__')),
]
