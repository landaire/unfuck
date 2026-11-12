import operator as o

def err(f, *a):
    try:
        return ('ok', f(*a))
    except Exception as e:
        return (type(e).__name__, e.args)

class C(object):
    def __eq__(self, other):
        return 'eq-result'
    def __lt__(self, other):
        return 'lt-result'

c = C()
x = []
RESULT = (
    o.lt(1, 2), o.le(2, 2), o.eq(1, 1.0), o.ne(1, 2), o.gt(3, 2), o.ge(1, 2),
    o.__lt__('a', 'b'), o.__le__((1,), (1, 2)), o.__eq__([1], [1]), o.__ne__('a', 'a'),
    o.__gt__(2, 1), o.__ge__(2, 3),
    o.eq(c, 1), o.lt(c, 1), o.gt(1, c),
    o.is_(x, x), o.is_([], []), o.is_not(x, x), o.is_not(None, 1),
    o.isCallable(len), o.isCallable(1), o.isCallable(C), o.isCallable(c),
    err(o.lt, 1), err(o.is_, 1), err(o.isCallable),
)
