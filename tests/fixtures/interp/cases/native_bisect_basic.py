import _bisect as b

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

class Seq(object):
    def __init__(self, items):
        self.items = items
        self.log = []
    def __len__(self):
        return len(self.items)
    def __getitem__(self, i):
        return self.items[i]
    def insert(self, i, x):
        self.log += [(i, x)]
        self.items[i:i] = [x]

class K(object):
    def __init__(self, v, tag):
        self.v = v
        self.tag = tag
    def __lt__(self, other):
        return self.v < other.v
    def __repr__(self):
        return 'K(%r)' % self.tag

a = [1, 2, 2, 2, 3, 5]
ins = [1, 3, 5]
b.insort(ins, 4)
b.insort_left(ins, 3)
b.insort_right(ins, 0)
b.insort(ins, 9, lo=2)
b.insort_left(ins, 2, 0, 2)
s = Seq([10, 20, 30])
b.insort(s, 25)
b.insort_left(s, 10)
keys = [K(1, 'a'), K(2, 'b')]
b.insort_right(keys, K(1, 'c'))
b.insort_left(keys, K(2, 'd'))
RESULT = (
    b.bisect(a, 2), b.bisect_right(a, 2), b.bisect_left(a, 2), b.bisect_left(a, 0), b.bisect(a, 9),
    b.bisect(a, 2, 4), b.bisect_left(a, 2, 0, 2), b.bisect(a, 2, lo=1, hi=3), b.bisect(a, 4, hi=-1),
    b.bisect(a, 4, 0, -5), b.bisect('aceg', 'd'), b.bisect((1, 3, 5), 3), b.bisect_left([], 1),
    ins, s.items, s.log, [k.tag for k in keys],
    err(b.bisect, a, 1, -1), err(b.insort, a, 1, lo=-2), err(b.bisect, a), err(b.bisect, a, 1, 0, 1, 2),
    err(b.bisect, a, 1, 1.5), err(b.bisect, a, 1, foo=1), err(b.bisect, a, 1, 0, 10),
    err(b.bisect, 5, 1), err(b.insort, (1, 2), 1), err(b.bisect, a, 1, 'x'),
)
