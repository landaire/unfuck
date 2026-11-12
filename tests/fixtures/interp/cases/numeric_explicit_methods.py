def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

ints = (int.__add__(1, 2), int.__add__(1, 2L), int.__add__(1, 2.0), int.__radd__(1, 2), int.__sub__(5, 3), int.__rsub__(5, 3), int.__mul__(3, True), int.__div__(7, 2), int.__floordiv__(-7, 2), int.__mod__(-7, 2), int.__divmod__(-7, 2), int.__rdivmod__(2, 7), int.__pow__(2, 10), int.__pow__(2, 10, 7), int.__pow__(3, 4, -5), int.__rpow__(2, 3), int.__lshift__(1, 4), int.__rshift__(256, 4), int.__and__(12, 10), int.__or__(12, 10), int.__xor__(12, 10), int.__and__(True, True))
longs = (long.__add__(1L, 2), long.__radd__(1L, 2), long.__mul__(2L, 3L), long.__add__(1L, 2.0), long.__pow__(2L, 5, 3), long.__floordiv__(-7L, 2))
floats = (float.__add__(1.0, 2), float.__add__(1.0, 2L), float.__radd__(1.5, 1), float.__add__(1.0, 'a'), float.__mod__(-7.0, 2), float.__rmod__(2.0, -7), float.__divmod__(7.5, 2), float.__pow__(2.0, 3), float.__eq__(1.0, 1), float.__lt__(1.0, 2L), float.__eq__(1.0, 'a'), float.__ne__(1.0, 1.0))
unary = (int.__neg__(5), int.__pos__(-5), int.__abs__(-5), int.__invert__(5), int.__nonzero__(0), int.__int__(True), int.__long__(5), int.__float__(5), int.__index__(5), int.__trunc__(5), int.__hash__(-1), int.__hex__(255), int.__hex__(-255), int.__oct__(8), int.__oct__(0), int.__repr__(5), int.__str__(5), long.__repr__(5L), long.__str__(5L), long.__hex__(255L), long.__oct__(8L), long.__oct__(0L), long.__int__(5L), type(long.__int__(5L)).__name__, long.__int__(2 ** 70), float.__neg__(1.5), float.__abs__(-1.5), float.__int__(-2.5), float.__long__(2.5), float.__repr__(0.1), float.__str__(1.0 / 3), float.__nonzero__(0.0))
compares = (int.__cmp__(1, 2), int.__cmp__(2, 2), int.__cmp__(3, 2), err(int.__cmp__, 1, 2L), err(long.__cmp__, 1L, 2), long.__cmp__(1L, 2L), err(int.__cmp__, True, 1), int.__cmp__(1, True), cmp(1, 2.0), cmp('a', 'b'), cmp([1], [1]))
coerced = (int.__coerce__(1, 2), int.__coerce__(1, 2L), int.__coerce__(1, 2.0), long.__coerce__(1L, 2), float.__coerce__(1.0, 2), float.__coerce__(1.0, 2L), float.__coerce__(1.0, 'a'), int.__coerce__(True, 2))
newargs = ((5).__getnewargs__(), (5L).__getnewargs__(), (2.5).__getnewargs__(), (5).conjugate(), (-5L).conjugate())
bools = (bool.__and__(True, False), bool.__and__(True, 1), bool.__or__(False, False), bool.__xor__(True, True), bool.__rand__(True, 3), bool.__repr__(True), bool.__str__(False), True & True, True | 0, True ^ 2, True + True, -True, ~False)
errors = (err(int.__add__, 'a', 1), err(int.__add__, 5L, 1), err(int.__add__), err(int.__add__, 1), err(int.__pow__, 2, -1, 5), err(int.__pow__, 2, 3, 0), err(float.__pow__, 2.0, 3, 5), err(int.__int__, 'a'), err(float.__add__, 1, 2.0), err(bool.__and__, 1, 1), err(int.__neg__, 1, 2))

RESULT = (ints, longs, floats, unary, compares, coerced, newargs, bools, errors)
