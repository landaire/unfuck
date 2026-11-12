import _heapq as h

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

class K(object):
    def __init__(self, v, tag):
        self.v = v
        self.tag = tag
    def __lt__(self, other):
        return self.v < other.v
    def __repr__(self):
        return self.tag + repr(self.v)

class OnlyLe:
    def __init__(self, v):
        self.v = v
    def __le__(self, other):
        return self.v <= other.v
    def __repr__(self):
        return 'L' + repr(self.v)

class Shrink(object):
    def __init__(self, v, heap):
        self.v = v
        self.heap = heap
    def __lt__(self, other):
        del self.heap[0]
        return True

heap = []
for v in [5, 3, 8, 1, 9, 2, 7]:
    h.heappush(heap, v)
pushed = [v for v in heap]
popped = [h.heappop(heap) for _ in range(3)]
data = [9, 4, 7, 1, 8, 2, 6, 3, 5, 0]
h.heapify(data)
heapified = [v for v in data]
r1 = h.heapreplace(data, 10)
r2 = h.heappushpop(data, -1)
r3 = h.heappushpop(data, 11)
drained = []
while data:
    drained += [h.heappop(data)]
old = []
for v in [3, 1, 2]:
    h.heappush(old, OnlyLe(v))
oldpop = [h.heappop(old) for _ in range(3)]
ties = [K(1, 'a'), K(3, 'b'), K(1, 'c'), K(2, 'd'), K(3, 'e'), K(1, 'f'), K(2, 'g')]
sh = []
sh += [Shrink(1, sh), Shrink(0, sh)]
RESULT = (
    pushed, popped, heapified, r1, r2, r3, drained, oldpop,
    h.nlargest(3, [5, 1, 8, 3, 9, 2]), h.nsmallest(3, [5, 1, 8, 3, 9, 2]),
    h.nlargest(10, [3, 1, 2]), h.nsmallest(10, iter([3, 1, 2])), h.nlargest(0, [1]), h.nsmallest(-1, [1]),
    h.nlargest(2, []), h.nsmallest(2, 'hello'),
    h.nlargest(4, ties), h.nsmallest(4, ties), h.nlargest(7, ties), h.nsmallest(5, ties),
    h.heappushpop([], 3),
    err(h.heappop, []), err(h.heappop), err(h.heappop, (1,)), err(h.heappush, [1]),
    err(h.heappush, (), 1), err(h.heapreplace, [], 1), err(h.heapify, 'x'), err(h.heapify, [], k=1),
    err(h.nlargest, 'a', []), err(h.nlargest, 2), err(h.nsmallest, 1.5, []), err(h.nlargest, 2, 5),
    err(h.heappush, sh, Shrink(-1, sh)),
)
