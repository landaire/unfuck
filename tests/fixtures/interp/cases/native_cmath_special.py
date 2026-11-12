# Every function over every pair of special classes of real and imaginary
# parts, which selects each special-value table entry and the direct
# computations for infinite arguments. Finite results are compared at 12
# significant digits. The NaN results come from Py_NAN, the x86 default NaN
# with the sign bit set, so their signs are compared too. polar() is left
# out of the sign comparison: its modulus comes from c_abs.
import cmath
import math

inf = 1e308 * 10
nan = inf - inf


def show(value):
    if isinstance(value, complex):
        return "(%.12g, %.12g)" % (value.real, value.imag)
    if isinstance(value, float):
        return "%.12g" % value
    if isinstance(value, tuple):
        return tuple(show(item) for item in value)
    return repr(value)


def attempt(function, *args):
    try:
        return show(function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))


functions = ["acos", "acosh", "asin", "asinh", "atan", "atanh", "cos", "cosh", "exp", "log", "log10",
             "sin", "sinh", "sqrt", "tan", "tanh", "phase", "polar", "isinf", "isnan"]
parts = [-inf, -2.3, -0.0, 0.0, 2.3, inf, nan]
rect_parts = [-inf, -2.3, -0.0, 0.0, 2.3, inf, nan, 1.0, -1.0]



def nan_signs(value):
    if isinstance(value, complex):
        return nan_signs(value.real), nan_signs(value.imag)
    if isinstance(value, float) and value != value:
        return math.copysign(1, value)
    return None


def signs(function, *args):
    try:
        return nan_signs(function(*args))
    except Exception as e:
        return type(e).__name__


RESULT = (
    [(name, [[attempt(getattr(cmath, name), complex(x, y)) for y in parts] for x in parts]) for name in functions],
    [[attempt(cmath.rect, r, phi) for phi in rect_parts] for r in rect_parts],
    [attempt(cmath.log, complex(x, y), 2) for x in parts for y in parts],
    [attempt(cmath.log, 2, complex(x, y)) for x in parts for y in parts],
    [(name, [signs(getattr(cmath, name), complex(x, y)) for x in parts for y in parts])
     for name in functions if name != "polar"],
    [signs(cmath.rect, r, phi) for r in rect_parts for phi in rect_parts],
    [signs(cmath.log, complex(x, y), 2) for x in parts for y in parts],
)
