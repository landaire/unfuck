# Argument conversion (PyComplex_AsCComplex for "D", PyFloat_AsDouble for
# "d"), argument count and keyword errors, and log with a base.
import cmath


def show(value):
    if isinstance(value, complex):
        return "(%.12g, %.12g)" % (value.real, value.imag)
    if isinstance(value, float):
        return "%.12g" % value
    if isinstance(value, tuple):
        return tuple(show(item) for item in value)
    return repr(value)


def attempt(function, *args, **kwargs):
    try:
        return show(function(*args, **kwargs))
    except Exception as e:
        return (type(e).__name__, str(e))


class NewComplex(object):
    def __complex__(self):
        return complex(-4, -0.0)


class ClassicComplex:
    def __complex__(self):
        return -9j


class BadComplex(object):
    def __complex__(self):
        return 4.0


class ClassicBadComplex:
    def __complex__(self):
        return 4


class NewFloat(object):
    def __float__(self):
        return -4.0


class ClassicFloat:
    def __float__(self):
        return 2.25


class BadFloat(object):
    def __float__(self):
        return 3


class ClassicPlain:
    pass


class Plain(object):
    pass


class FloatSubclass(float):
    pass


class ComplexSubclass(complex):
    pass


class RaisingComplex(object):
    def __complex__(self):
        raise KeyError("inside")


arguments = [4, -4, 4L, -(10 ** 20), 10 ** 400, True, False, 2.25, FloatSubclass(-9.0), ComplexSubclass(0, -4),
             NewComplex(), ClassicComplex(), BadComplex(), ClassicBadComplex(), NewFloat(), ClassicFloat(),
             BadFloat(), ClassicPlain(), Plain(), RaisingComplex(), "4", u"4", None, [4]]

RESULT = (
    [attempt(cmath.sqrt, value) for value in arguments],
    [attempt(cmath.phase, value) for value in arguments],
    [attempt(cmath.isnan, value) for value in arguments[:6]],
    [attempt(cmath.rect, value, 0.5) for value in arguments],
    attempt(cmath.rect, 1, 2j), attempt(cmath.rect, 2, NewFloat()), attempt(cmath.rect, ClassicFloat(), 10 ** 400),
    attempt(cmath.log, NewComplex(), ClassicFloat()), attempt(cmath.log, 8, BadComplex()),
    attempt(cmath.log, "8", 2), attempt(cmath.log, 8, "2"),
    [attempt(cmath.log, x, base) for x, base in [(0, 2), (2, 0), (1, 1), (2, 1), (0, 0), (8, 2L), (-1, -1),
                                                 (1e308 * 10, 2), (2, 1e308 * 10)]],
    attempt(cmath.sqrt), attempt(cmath.sqrt, 1, 2), attempt(cmath.sqrt, z=1), attempt(cmath.acos, 1, z=1),
    attempt(cmath.phase), attempt(cmath.phase, 1, 2), attempt(cmath.polar, 1, 2), attempt(cmath.polar, z=1),
    attempt(cmath.isinf), attempt(cmath.isinf, 1, 2), attempt(cmath.isnan, 1, 2),
    attempt(cmath.log), attempt(cmath.log, 1, 2, 3), attempt(cmath.log, 1, base=2),
    attempt(cmath.rect), attempt(cmath.rect, 1), attempt(cmath.rect, 1, 2, 3), attempt(cmath.rect, r=1, phi=2),
    attempt(cmath.exp, 1000), attempt(cmath.exp, 10 ** 3), attempt(cmath.log, 0), attempt(cmath.log10, 0L),
    attempt(cmath.atanh, 1), attempt(cmath.atanh, -1.0), attempt(cmath.cosh, 1000), attempt(cmath.sinh, -1000),
    attempt(cmath.polar, complex(1e308, 1.7e308)), attempt(cmath.rect, 2.0, 1e308 * 10),
)
