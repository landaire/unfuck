def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class Point(tuple):
    __slots__ = ()
    def __new__(cls, x, y):
        return tuple.__new__(cls, (x, y))
    @property
    def x(self):
        return self[0]
    def __repr__(self):
        return 'Point' + tuple.__repr__(self)

class Loose(tuple):
    pass

p = Point(1, 2)
loose = Loose([3, 4])
loose.extra = 'attribute'
t = (1, 2, 3, 2, 1)
methods = (t.count(1), t.count(9), t.index(2), t.index(2, 2), t.index(1, -1), len(t), 2 in t, t[1:4], t[::-1], t * 2, 2 * t, t + (9,))
explicit = (tuple.__getitem__(t, 0), tuple.__len__(t), tuple.__contains__(t, 3), tuple.__add__((1,), (2,)), tuple.__mul__((1,), 2), tuple.__getnewargs__(t), tuple.__eq__(t, [1]), tuple.__lt__((1,), (2,)))
subclass = (p, p.x, p[1], p + (3,), type(p + (3,)).__name__, hash(p) == hash((1, 2)), p == (1, 2), loose, loose.extra, tuple(loose), type(tuple(loose)).__name__, len(p))
built = (tuple(), tuple([1, 2]), tuple('ab'), tuple(xrange(3)), tuple({8: 1, 16: 2}), tuple(t) is t)
hashes = (hash(()), hash((1,)), hash((1, 2)), hash(('a', (2, 3.5))))
errors = (err(t.index, 9), err(tuple.__add__, (1,), [1]), err(hash, ([],)), err(tuple, 5), err(tuple.__len__, []), err(t.__getitem__, 10), err(Point, 1))

RESULT = (methods, explicit, subclass, built, hashes, errors, (1, 2) < (1, 2, 0), (2,) > (1, 5))
