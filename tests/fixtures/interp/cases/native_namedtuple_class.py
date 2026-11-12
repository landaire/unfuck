from collections import namedtuple


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


Point = namedtuple('Point', 'x y')
p = Point(1, y=2)
q = Point._make([3, 4])
r = p._replace(x=5)


class Point3(Point):
    __slots__ = ()

    def total(self):
        return self.x + self.y


p3 = Point3(7, 8)
Single = namedtuple('Single', ['only'])
Empty = namedtuple('Empty', '')
Renamed = namedtuple('Renamed', 'a def b a _c 1d', rename=True)
FromUnicode = namedtuple(u'FromUnicode', u'left, right')
Defaulted = namedtuple('Defaulted', 'a b c')
Defaulted.__new__.func_defaults = (None, 0)

errors = [error(action) for action in (
    lambda: Point(1),
    lambda: Point(1, 2, 3),
    lambda: Point(1, x=2),
    lambda: Point._make([1]),
    lambda: p._replace(z=1),
    lambda: namedtuple('P', 'a a'),
    lambda: namedtuple('P', 'a class'),
    lambda: namedtuple('P', '1a'),
    lambda: namedtuple('P', '_a'),
    lambda: namedtuple('P', 'a-b'),
    lambda: namedtuple('', 'a'),
    lambda: namedtuple('P'),
    lambda: namedtuple('P', 'a', foo=1),
    lambda: namedtuple('P', 'a', typename='Q'),
    lambda: namedtuple('P', 'a', False, False, 1),
    lambda: p.__setattr__('x', 3),
    lambda: Single(),
)]

RESULT = (p, q, r, p.x, p.y, p[0], p[-1], len(p), p == (1, 2), hash(p) == hash((1, 2)), isinstance(p, tuple),
          Point._fields, Point.__module__, Point.__name__, Point.__slots__, Point.__getstate__(p),
          p.__getnewargs__(), [k for k in Point.__dict__], p3, p3.total(), type(p3._replace(x=0)).__name__,
          Single(9), Single._fields, Empty(), Empty._fields, Renamed._fields,
          FromUnicode._fields, type(FromUnicode.__name__).__name__, Defaulted(1), Defaulted(1, 2, 3), errors,
          Point.__new__.__name__, Point._make.__name__, Point.__repr__.__module__,
          Point.__new__.func_code.co_varnames,
          Point._make.func_defaults[1] is len, sorted(Point.__new__.func_globals.keys()), [x for x in p],
          p.count(1), p.index(2))
