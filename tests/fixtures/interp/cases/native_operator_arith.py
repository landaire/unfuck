import operator as o

def err(f, *a):
    try:
        return ('ok', f(*a))
    except Exception as e:
        return (type(e).__name__, e.args)

class V(object):
    def __init__(self, v):
        self.v = v
    def __add__(self, other):
        return ('add', self.v, other)
    def __iadd__(self, other):
        return ('iadd', self.v, other)
    def __neg__(self):
        return ('neg', self.v)
    def __index__(self):
        return 7
    def __lt__(self, other):
        return 'lt'

lst = [1]
same = o.iadd(lst, [2])
RESULT = (
    o.add(2, 3), o.__add__('a', 'b'), o.sub(5, 7), o.mul(3, 4), o.__mul__([0], 2),
    o.div(7, 2), o.__div__(7.0, 2), o.truediv(7, 2), o.floordiv(-7, 2), o.mod(-7, 3),
    o.pow(2, 10), o.__pow__(2, -1), o.lshift(1, 70), o.rshift(256, 3),
    o.and_(12, 10), o.or_(12, 10), o.xor(12, 10), o.__and__(True, False),
    o.neg(5), o.pos(-5), o.abs(-3.5), o.__abs__(-2), o.inv(5), o.invert(0), o.__inv__(-1),
    o.not_(0), o.__not__([1]), o.truth(''), o.truth(3),
    o.isub(10, 3), o.imul(3, 3), o.idiv(9, 2), o.itruediv(9, 2), o.ifloordiv(9, 2), o.imod(9, 4),
    o.ipow(3, 2), o.ilshift(1, 3), o.irshift(8, 1), o.iand(6, 3), o.ior(6, 3), o.ixor(6, 3),
    same is lst, lst,
    o.add(V(1), 2), o.iadd(V(1), 2), o.neg(V(3)), o.index(V(0)), o.__index__(5), o.index(True),
    err(o.add, 1), err(o.__add__, 1, 2, 3), err(o.neg), err(o.__neg__, 1, 2),
    err(o.add, 1, 'a'), err(o.neg, 'a'), err(o.abs, 'a'), err(o.index, 1.5), err(o.div, 1, 0),
    err(o.pow, 1),
)
