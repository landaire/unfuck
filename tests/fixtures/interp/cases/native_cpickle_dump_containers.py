# cPickle.dumps of tuples, lists, dicts, and shared or recursive structures.
import cPickle


def K(x):
    return x


def every(value):
    return [cPickle.dumps(value, protocol) for protocol in (0, 1, 2)]


shared = [K(1)]
recursive_list = [K(1)]
recursive_list.append(recursive_list)
recursive_dict = {K('k'): K(1)}
recursive_dict[K('self')] = recursive_dict
holder = []
recursive_tuple = (holder, K(2))
holder.append(recursive_tuple)
holder4 = []
recursive_tuple4 = (holder4, K(1), K(2), K(3))
holder4.append(recursive_tuple4)

VALUES = [
    (), (K(1),), (K(1), K(2)), (K(1), K(2), K(3)), (K(1), K(2), K(3), K(4)),
    ((),), ((K(1),), (K(2), K(3))),
    [], [K(1)], [K(1), K(2)], [[], [[]]],
    {}, {K('a'): K(1)}, {K('a'): K(1), K('b'): [K(2)]},
    [shared, shared, (shared, shared)],
    recursive_list, recursive_dict, recursive_tuple, holder, recursive_tuple4,
    [K('abc'), K('abc'), K(u'xyz'), K(u'xyz')],
    range(1001), range(2000), range(2001),
    dict((i, i) for i in range(1001)),
    dict((str(i), i) for i in range(2500)),
    set([K(1), K(2)]), frozenset([K(3)]),
    [K(1.5), K(10 ** 20), None, True],
]

RESULT = [every(value) for value in VALUES]
