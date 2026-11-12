from _collections import defaultdict


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


lists = defaultdict(lambda: [])
first = lists['a']
second = lists['b']
counter = defaultdict(lambda: 0)
for ch in 'abracadabra':
    counter[ch] += 1
none_factory = defaultdict()

dd = defaultdict(lambda: 1)
dd.default_factory = None
errors = [error(action) for action in (
    lambda: none_factory['missing'],
    lambda: defaultdict(1),
    lambda: defaultdict(None, 1, 2),
    lambda: dd[1],
)]
del dd.default_factory


class Doubling(defaultdict):
    def __missing__(self, key):
        return key * 2


doubling = Doubling(lambda: 0)


class Plain(defaultdict):
    pass


plain = Plain(lambda: 'z', {1: 2}, k=3)
created = plain[5]
copied = counter.copy()
copied['a'] = 100
from_pairs = defaultdict(None, [(1, 2), (3, 4)], q=7)
calls = []
logged = defaultdict(lambda: len(calls))
logged['x']
logged['x']

RESULT = (sorted([k for k in lists]), first, second, sorted([(k, counter[k]) for k in counter]), errors,
          doubling['ab'], len(doubling), sorted([(k, plain[k]) for k in plain]), created, counter['a'], copied['a'],
          type(copied).__name__, sorted([(k, from_pairs[k]) for k in from_pairs]), dd.default_factory,
          repr(defaultdict(None)), repr(defaultdict(int, {1: 2})), repr(Plain(int)), isinstance(doubling, dict),
          len(counter), defaultdict.__module__, len(logged), 'missing' in none_factory, type(plain).__name__)
