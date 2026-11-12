class Missing(dict):
    def __missing__(self, key):
        return ('missing', key)

class Logged(dict):
    def __init__(self, *args, **kwargs):
        self.log = []
        super(Logged, self).__init__(*args, **kwargs)
    def __setitem__(self, key, value):
        self.log.append(key)
        dict.__setitem__(self, key, value * 10)
    def __getitem__(self, key):
        return dict.__getitem__(self, key) + 1

class Counter(dict):
    def __missing__(self, key):
        return 0

m = Missing(a=1)
logged = Logged({'x': 1})
logged['y'] = 2
counts = Counter()
for word in ['a', 'b', 'a', 'c', 'a']:
    counts[word] = counts[word] + 1

RESULT = (m['a'], m['b'], m.get('b'), 'b' in m, logged['y'], logged.log, dict(logged), sorted(counts.items()), isinstance(m, dict), repr(m), Missing.__name__)
