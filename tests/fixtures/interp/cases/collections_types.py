from collections import Counter
from collections import OrderedDict
from collections import defaultdict
from collections import deque
from collections import namedtuple
import copy


def K(value):
    return value


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


def ordered_dict_results():
    od = OrderedDict()
    for key in K(('z', 'a', 'm', 'b')):
        od[key] = len(key) + len(od)
    keys = od.keys()
    od['a'] = 99
    after_update = od.items()
    del od['m']
    popped = od.pop('z')
    missing_default = od.pop('nothing', K('dflt'))
    od['q'] = K(5)
    last = od.popitem()
    first = od.popitem(last=False)
    od.update([(K('x'), 1), (K('y'), 2)], w=3)
    od.setdefault(K('s'), K(7))
    reordered = OrderedDict(K([('a', 1), ('b', 2)]))
    reversed_order = OrderedDict(K([('b', 2), ('a', 1)]))
    plain = dict(K([('a', 1), ('b', 2)]))
    copied = od.copy()
    copied['new'] = 1
    deep = copy.deepcopy(OrderedDict(K([('k', [1, 2])])))
    fromkeys = OrderedDict.fromkeys(K('cab'), K(0))
    return (
        keys, after_update, popped, missing_default, last, first, od.items(), list(reversed(od)),
        reordered == reversed_order, reordered == plain, plain == reversed_order, reordered != reversed_order,
        repr(reordered), repr(OrderedDict()), copied.keys(), od.keys(), type(copied).__name__,
        deep.items(), fromkeys.items(), od.values(), list(od.iteritems()), od.viewkeys() == set(od),
        error(lambda: OrderedDict().popitem()), error(lambda: OrderedDict(1, 2)), error(lambda: od.pop('gone')),
        isinstance(od, dict), len(od), 'x' in od, od.get('nothing', K('g')),
    )


def counter_results():
    words = Counter(K('abracadabrab'))
    common = words.most_common(2)
    total = sorted(words.most_common())
    left = Counter(a=3, b=1, c=0)
    right = Counter(a=1, b=2, d=4)
    added = sorted((left + right).items())
    subtracted = sorted((left - right).items())
    union = sorted((left | right).items())
    intersection = sorted((left & right).items())
    updated = Counter(K('aab'))
    updated.update(K('abc'))
    updated.update({K('a'): 10})
    updated.subtract(K('aaaz'))
    updated.subtract(c=5)
    elements = sorted(Counter(a=2, b=1, c=0, d=-1).elements())
    from_mapping = Counter({K('x'): 2, K('y'): 1})
    deleted = Counter(K('aab'))
    del deleted['a']
    del deleted['missing']
    return (
        common, total, added, subtracted, union, intersection, sorted(updated.items()), elements,
        words['zz'], sorted(from_mapping.items()), repr(Counter(K('aab'))), repr(Counter()),
        sorted(deleted.items()), isinstance(words, dict), type(words.copy()).__name__,
        error(lambda: Counter.fromkeys(K('ab'))), error(lambda: Counter(K('a'), K('b'))),
        sorted(Counter(K('abc')).keys()), sum(words.values()),
    )


Point = namedtuple('Point', K('x y'))
Row = namedtuple('Row', [K('name'), K('count'), K('ratio')])
Renamed = namedtuple('Renamed', K('a def a _b'), rename=True)


def namedtuple_results():
    point = Point(K(1), y=K(2))
    made = Point._make([K(3), K(4)])
    replaced = point._replace(y=K(20))
    row = Row(K('n'), K(3), K(0.5))
    x, y = point
    return (
        point, repr(made), replaced, point._asdict().items(), Point._fields, Row._fields, Renamed._fields,
        point.x + point.y, x, y, row.ratio, point[1], tuple(point), point == (1, 2), len(row),
        isinstance(point, tuple), type(point._asdict()).__name__, Point.__name__,
        error(lambda: Point(1)), error(lambda: Point._make([1, 2, 3])), error(lambda: point._replace(z=1)),
        error(lambda: namedtuple('Bad', 'x def')), error(lambda: namedtuple('Bad', 'x x')),
        error(lambda: namedtuple('Bad', '_x')), error(lambda: setattr(point, 'x', 5)),
        point.__getnewargs__(), vars(point).items(),
    )


def deque_results():
    bounded = deque(range(K(5)), maxlen=K(3))
    bounded.append(K(10))
    bounded.appendleft(K(-1))
    rotated = deque(range(K(6)))
    rotated.rotate(K(2))
    rotate_right = list(rotated)
    rotated.rotate(K(-3))
    extended = deque(K([1]))
    extended.extend(K([2, 3]))
    extended.extendleft(K([0, -1]))
    popped = (extended.pop(), extended.popleft())
    extended.remove(K(1))
    counted = deque(K('abcab')).count(K('a'))
    reversed_items = list(reversed(deque(K('xyz'))))
    cleared = deque(K([1, 2]))
    cleared.clear()
    return (
        list(bounded), bounded.maxlen, repr(bounded), rotate_right, list(rotated), list(extended), popped,
        counted, reversed_items, repr(cleared), repr(deque()), repr(deque(K([1, 2]), K(5))), deque(K('ab')) == deque(K('ab')),
        deque(K([1, 2])) < deque(K([1, 3])), error(lambda: deque().pop()), error(lambda: deque(K([1])).remove(K(2))),
        error(lambda: deque(maxlen=-1)), deque(K('abc'))[1], deque(K('abc'))[-1], len(deque(K('abc'))),
        list(copy.copy(bounded)), deque().maxlen,
    )


def defaultdict_results():
    groups = defaultdict(list)
    for word in K(['apple', 'avocado', 'banana', 'cherry', 'blueberry']):
        groups[word[0]].append(word)
    counts = defaultdict(int)
    for letter in K('mississippi'):
        counts[letter] += 1
    missing = defaultdict(lambda: K('none'))
    direct = missing.__missing__(K('k'))
    nested = defaultdict(lambda: defaultdict(int))
    nested['a']['b'] += 1
    no_factory = defaultdict()
    copied = copy.copy(counts)
    return (
        sorted(groups.items()), sorted(counts.items()), direct, sorted(missing.items()), nested['a']['b'],
        groups.default_factory, counts.default_factory, no_factory.default_factory,
        repr(defaultdict(int, {K(1): K(2)})), repr(defaultdict(None)), repr(defaultdict(list)),
        error(lambda: no_factory['x']), error(lambda: no_factory.__missing__('y')),
        type(copied).__name__, sorted(copied.items()), copied.default_factory,
        counts.get('zzz'), 'zzz' in counts,
    )


RESULT = (ordered_dict_results(), counter_results(), namedtuple_results(), deque_results(), defaultdict_results())
