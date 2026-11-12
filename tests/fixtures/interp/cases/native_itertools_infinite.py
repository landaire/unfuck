from itertools import count, cycle, repeat, islice, izip

def take(it, n):
    return [x for x in islice(it, n)]

def err(f):
    try:
        f()
    except Exception as e:
        return (type(e).__name__, e.args)
    return None

c = count(5)
first = take(c, 3)
after = repr(c)
reprs = [repr(count()), repr(count(1.5, 0.5)), repr(count(5L)), repr(count(5, 1.0)), repr(count(2 ** 70)), repr(count(start=3, step=2)), repr(count(-4, -2))]
floats = take(count(1.5, 0.5), 3)
longs = take(count(2 ** 64, 2 ** 63), 3)
neg = take(count(10, -3), 4)
cyc = take(cycle('abc'), 8)
empty_cycle = [x for x in cycle([])]

class Noisy(object):
    def __init__(self):
        self.calls = 0
    def __iter__(self):
        return self
    def next(self):
        self.calls += 1
        if self.calls > 2:
            raise StopIteration
        return self.calls

n = Noisy()
lazy_cycle = take(cycle(n), 7)
r = repeat('x', 3)
hint = r.__length_hint__()
rep = [x for x in r]
rep_reprs = [repr(repeat(1, 3)), repr(repeat('a')), repr(repeat(1, -5)), repr(repeat(1, times=-5)), repr(r)]
inf = take(repeat(None), 3)
zipped = [p for p in izip(count(), 'ab')]
errors = [
    err(lambda: count('a')),
    err(lambda: count(1, 'a')),
    err(lambda: count(1, 2, 3)),
    err(lambda: count(foo=1)),
    err(lambda: cycle()),
    err(lambda: cycle(1, 2)),
    err(lambda: cycle(x=1)),
    err(lambda: cycle(1)),
    err(lambda: repeat()),
    err(lambda: repeat(1, 'a')),
    err(lambda: repeat(1, 2.0)),
    err(lambda: repeat(1).__length_hint__()),
]
RESULT = (first, after, reprs, floats, longs, neg, cyc, empty_cycle, lazy_cycle, n.calls, hint, rep, rep_reprs, inf, zipped, errors)
