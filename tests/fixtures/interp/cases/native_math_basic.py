import math

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

values = [
    math.pi, math.e,
    math.sin(1.0), math.cos(1.0), math.tan(1.0), math.asin(0.5), math.acos(0.5), math.atan(0.5),
    math.sinh(1.5), math.cosh(1.5), math.tanh(1.5),
    math.exp(2), math.log(10), math.log(8, 2), math.log(100, 10), math.log10(1000), math.sqrt(2),
    math.ceil(2.1), math.ceil(-2.1), math.floor(2.9), math.floor(-2.9), math.ceil(5), math.floor(True),
    math.fabs(-3), math.fabs(-0.0),
    math.degrees(math.pi), math.radians(180), math.degrees(1),
    math.hypot(3, 4), math.copysign(2, -0.0), math.copysign(-3.0, 1),
    math.fmod(7, 3), math.fmod(-7.5, 2), math.fmod(7, -3),
    math.modf(3.25), math.modf(-3.25), math.modf(-3.0), math.modf(0.0),
    math.frexp(8.0), math.frexp(-0.3), math.frexp(0), math.frexp(5e-324), math.frexp(1e308),
    math.ldexp(0.75, 4), math.ldexp(1, -1074), math.ldexp(1, -1075), math.ldexp(3, -1075), math.ldexp(1.5, 1023),
    math.pow(2, 10), math.pow(2.5, -2), math.pow(-8, 3), math.pow(4, 0.5),
    math.isinf(1e308 * 10), math.isinf(1e308), math.isnan(((1e308 * 10) - (1e308 * 10))), math.isnan(1),
    math.atan2(1, 1), math.atan2(-1, -1), math.atan2(0.0, -1), math.atan2(-0.0, -1),
]
types = [type(math.ceil(1)).__name__, type(math.floor(2L)).__name__, type(math.frexp(3.0)[1]).__name__]
RESULT = (values, types, attempt(math.sqrt, -1), attempt(math.log, 0), attempt(math.exp, 1000), attempt(math.pow, 10, 400))
