# Branch cuts with signed zeros, the rescaled paths for very large and very
# small arguments, and overflow. Results are compared at 12 significant
# digits. The CRT atan2 sets no errno when the angle underflows, so phase()
# returns a zero there.
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


cuts = [
    ("sqrt", [complex(-1, 0.0), complex(-1, -0.0), complex(-4, -0.0), complex(-0.0, 0.0), complex(-0.0, -0.0),
              complex(0.0, -0.0)]),
    ("log", [complex(-1, 0.0), complex(-1, -0.0), complex(-2.5, -0.0)]),
    ("log10", [complex(-10, 0.0), complex(-10, -0.0)]),
    ("acos", [complex(2, 0.0), complex(2, -0.0), complex(-2, 0.0), complex(-2, -0.0), complex(0.5, -0.0)]),
    ("asin", [complex(2, 0.0), complex(2, -0.0), complex(-2, 0.0), complex(-2, -0.0), complex(-0.0, -0.0)]),
    ("atan", [complex(0.0, 2), complex(-0.0, 2), complex(0.0, -2), complex(-0.0, -2), complex(-0.0, 0.5)]),
    ("acosh", [complex(0.5, 0.0), complex(0.5, -0.0), complex(-2, 0.0), complex(-2, -0.0), complex(1, -0.0)]),
    ("asinh", [complex(0.0, 2), complex(-0.0, 2), complex(0.0, -2), complex(-0.0, -2), complex(-0.0, -0.0)]),
    ("atanh", [complex(2, 0.0), complex(2, -0.0), complex(-2, 0.0), complex(-2, -0.0), complex(-0.5, -0.0),
               complex(-0.0, 0.0)]),
    ("phase", [complex(-1, 0.0), complex(-1, -0.0), complex(0.0, 0.0), complex(-0.0, 0.0), complex(0.0, -0.0),
               complex(-0.0, -0.0)]),
    ("polar", [complex(-1, -0.0), complex(-0.0, 0.0)]),
    ("cos", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("cosh", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("sin", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("sinh", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("tan", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("tanh", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
    ("exp", [complex(-0.0, -0.0), complex(0.0, -0.0)]),
]

extremes = [
    ("sqrt", [complex(1e-320, 1e-320), complex(-1e-320, 5e-324), complex(5e-324, 0.0), complex(1e308, 1e308),
              complex(-1e308, -1e308), complex(1e-310, 3.0)]),
    ("log", [complex(5e-324, 5e-324), complex(1e-320, -0.0), complex(1e308, 1e308), complex(-1.7e308, 1e308),
             complex(0.0, 0.0), complex(-0.0, -0.0), complex(0.6, 0.8), complex(1.0, 1e-10), complex(0.71, 0.0)]),
    ("log10", [complex(0.0, 0.0), complex(1e308, -1e308), complex(1e-320, 0.0)]),
    ("acos", [complex(1e308, 1e308), complex(-1e308, 1e308), complex(-1e308, -1.0), complex(1e-320, 1e-320)]),
    ("acosh", [complex(1e308, 1e308), complex(-1e308, -1.0), complex(1e-320, -1e-320)]),
    ("asin", [complex(1e308, 1e308), complex(-1e308, -1e308)]),
    ("asinh", [complex(1e308, 1e308), complex(-1e308, -1e308), complex(1e308, -1.0), complex(-1e308, 1.0)]),
    ("atan", [complex(1e200, 1e200), complex(0.0, 1.0), complex(0.0, -1.0), complex(1e-200, 1.0)]),
    ("atanh", [complex(1e200, 1e200), complex(-1e200, -1.0), complex(1, 0.0), complex(1, -0.0), complex(-1, 0.0),
               complex(1, 1e-200), complex(1, -1e-200), complex(-1, 1e-200), complex(0.999, 0.0)]),
    ("exp", [complex(709.5, 0.0), complex(709.5, 1.0), complex(710, 0.0), complex(1000, 0.0), complex(-1000, 1.0),
             complex(800, 3.0)]),
    ("cosh", [complex(709.5, 1.0), complex(-710, 0.5), complex(711, 1.0), complex(1000, 0.0), complex(-1000, 0.0)]),
    ("sinh", [complex(709.5, 1.0), complex(-710, 0.5), complex(711, 1.0), complex(-1000, 0.0)]),
    ("cos", [complex(1.0, 710), complex(0.5, -711), complex(0.0, 1000)]),
    ("sin", [complex(1.0, 710), complex(0.5, -711), complex(0.0, -1000)]),
    ("tanh", [complex(1000, 1.0), complex(-1000, -1.0), complex(710, 2.0), complex(20, 1e300)]),
    ("tan", [complex(1.0, 1000), complex(-1.0, -1000)]),
    ("phase", [complex(1e300, 1e-300), complex(-1e300, 1e-300), complex(1e300, -1e-300)]),
    ("polar", [complex(1e308, 1e308), complex(-1.7e308, 1.7e308), complex(1e-320, 1e-320)]),
    ("rect", [(1e308, 0.5), (-1e308, 2.0), (1e-320, 1.0), (0.0, -0.0), (-0.0, -0.0), (-2.0, -0.0)]),
]

RESULT = (
    [(name, [attempt(getattr(cmath, name), z) for z in values]) for name, values in cuts],
    [(name, [attempt(getattr(cmath, name), *(z if isinstance(z, tuple) else (z,))) for z in values])
     for name, values in extremes],
)
