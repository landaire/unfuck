# Results of libm-dependent computations are compared at 12 significant
# digits: CPython's Windows build uses _math.c's asinh and log1p and the
# CRT libm, and Wine's CRT rounds these differently from msvcr90 in the last
# ulp.
import cmath


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
             "sin", "sinh", "sqrt", "tan", "tanh"]
inputs = [0.5, -0.5, 2.0, -3.0, 1j, -2j, complex(0.3, 0.4), complex(-1.5, 2.5), complex(3, -4), complex(-0.7, -0.2),
          complex(10, 10), complex(1e-8, -1e-8), complex(0.9, 0.5), 1]

RESULT = (
    [n for n in dir(cmath) if not n.startswith("_")],
    repr(cmath.pi), repr(cmath.e),
    [(name, [attempt(getattr(cmath, name), z) for z in inputs]) for name in functions],
    [attempt(cmath.log, z, base) for z, base in [(8, 2), (100, 10), (1j, 2), (complex(3, 4), 1j), (-8, -2),
                                                (0.5, 0.25), (10, complex(0.5, 0.5))]],
    [attempt(cmath.phase, z) for z in [1, -1, 1j, -1j, complex(1, 1), complex(-3, -4), 0, 2.5]],
    [attempt(cmath.polar, z) for z in [1, -1, 1j, complex(3, 4), complex(-3, -4), 0, -2.5]],
    [attempt(cmath.rect, r, phi) for r, phi in [(1, 0), (2, cmath.pi / 2), (2, cmath.pi), (3, -cmath.pi / 4),
                                                (-1, 1), (0, 1), (5, 0.0), (1.5, 2)]],
    [attempt(cmath.isinf, z) for z in [1, complex(1e308, 1e308), 1e308 * 10, complex(0, -1e308 * 10)]],
    [attempt(cmath.isnan, z) for z in [1, 1j, complex(0, (1e308 * 10) - (1e308 * 10))]],
    type(cmath.sqrt(4)).__name__, type(cmath.phase(4)).__name__, type(cmath.isnan(4)).__name__,
    repr(cmath.sqrt(-4)), repr(cmath.sqrt(complex(3, 4))), repr(cmath.exp(0)), repr(cmath.log(1)),
    repr(cmath.polar(complex(3, 4))), repr(cmath.rect(2, 0)),
)
