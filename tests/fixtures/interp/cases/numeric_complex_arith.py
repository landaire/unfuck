import warnings

def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

def warned(function, *args):
    outcomes = []
    for action in ('error', 'ignore'):
        with warnings.catch_warnings():
            warnings.simplefilter(action)
            try:
                outcomes.append(function(*args))
            except Exception as e:
                outcomes.append((type(e).__name__, e.args))
    return outcomes

a = 1 + 2j
b = 3 - 4j
basic = [a + b, a - b, a * b, a / b, b / a, a + 1, 1 + a, a - 2L, 2L - a, a * 1.5, 1.5 * a, a / 2, 2 / a,
         True + a, a * False, -a, +a, abs(b), abs(-0.0j), a ** 2, a ** -2, a ** 0, 0j ** 0, a ** 0.5, 2 ** a,
         a ** b, 1j ** 1j, (-1) ** 0.5j, pow(a, 3), a.__truediv__(b), a.__rsub__(1), a.__radd__('x'),
         a.__pow__(2), a.__rpow__(2), complex.__add__(a, 2), complex.__mul__(a, 'x')]
basic = [repr(v) for v in basic]

division = [err(lambda: a / 0), err(lambda: a / 0j), err(lambda: 1 / 0j), err(lambda: 0j ** -1),
            err(lambda: 0j ** 1j), err(lambda: (1e200 + 1e200j) ** 3), err(lambda: pow(a, 2, 3)),
            err(lambda: pow(2.0, 2, 1j)), err(lambda: pow(1j, 2.0, 3)), err(lambda: pow(2, 1j, 3)),
            err(lambda: a << 1), err(lambda: a & 1), err(lambda: ~a), err(lambda: abs(complex(1e308, 1e308))),
            err(lambda: a + 'x'), err(lambda: 'x' * a), err(lambda: a + 10 ** 400), repr(1j * float('inf'))]

# Each warning comes from its own line: the warnings registry is keyed by
# line, and the interpreter does not track frame lines.
floor = []
floor.append(warned(lambda: a // b))
floor.append(warned(lambda: a % b))
floor.append(warned(lambda: divmod(a, b)))
floor.append(warned(lambda: divmod(7, 2j)))
floor.append(warned(lambda: a // 0j))
floor.append(warned(lambda: a % 0))
floor.append(warned(lambda: divmod(a, 0j)))
floor.append(warned(lambda: 5.5 // a))

import operator
true = [repr(operator.truediv(a, b)), repr(operator.truediv(3, 1 + 1j)), err(operator.truediv, a, 0j), repr(operator.floordiv(1.0, 1j) if False else 0)]

class Radd(object):
    def __radd__(self, other):
        return ('radd', other)
    def __rsub__(self, other):
        return NotImplemented

coerce = [repr(a.__coerce__(1)), repr(a.__coerce__(2.5)), repr(a.__coerce__(1j)), a.__coerce__('x'),
          a + Radd(), err(lambda: a - Radd()), sum([1j, 2, 3.5]), sum([], 0j)]
coerce = [repr(v) for v in coerce]

RESULT = (basic, division, floor, true, coerce)
