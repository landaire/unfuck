import math

inf = (1e308 * 10)
nan = ((1e308 * 10) - (1e308 * 10))

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, e.args)

pow_cases = [(nan, 0), (nan, 2), (1, nan), (2, nan), (inf, 3), (-inf, 3), (-inf, 2), (inf, 0), (-inf, -3), (-inf, -2),
             (1, inf), (-1, -inf), (2, inf), (0.5, inf), (0.5, -inf), (2, -inf), (0.0, -inf), (0.0, -1), (-2, 0.5), (0.0, 0)]
atan2_cases = [(inf, inf), (-inf, inf), (inf, -inf), (-inf, -inf), (inf, 1), (-inf, 1), (1, inf), (1, -inf), (-1, -inf),
               (0.0, 0.0), (-0.0, 0.0), (0.0, -0.0), (-0.0, -0.0), (nan, 1), (1, nan)]
fmod_cases = [(1, inf), (-1, -inf), (inf, 1), (1, 0), (nan, 1), (1, nan), (inf, inf), (-0.0, 3)]
hypot_cases = [(inf, nan), (nan, -inf), (nan, 1), (1e308, 1e308), (-0.0, 0.0)]
copysign_cases = [(1, nan), (inf, -1), (nan, -1)]
one_arg = [math.sin, math.cos, math.tan, math.sqrt, math.exp, math.log, math.log10, math.log1p, math.atan,
           math.asin, math.acos, math.sinh, math.cosh, math.tanh, math.ceil, math.floor, math.fabs, math.expm1,
           math.acosh, math.asinh, math.atanh, math.modf, math.frexp]
one_inputs = [inf, -inf, nan, -2.0, 0.0, -0.0, 3.0]
RESULT = (
    [attempt(math.pow, x, y) for x, y in pow_cases],
    [attempt(math.atan2, y, x) for y, x in atan2_cases],
    [attempt(math.fmod, x, y) for x, y in fmod_cases],
    [attempt(math.hypot, x, y) for x, y in hypot_cases],
    [attempt(math.copysign, x, y) for x, y in copysign_cases],
    [[attempt(f, x) for x in one_inputs] for f in one_arg],
    attempt(math.cosh, 1000), attempt(math.sinh, -1000), attempt(math.exp, -1000), attempt(math.ldexp, 1, 2000),
    attempt(math.ldexp, -1, 1024), attempt(math.ldexp, inf, -5), attempt(math.ldexp, nan, 5), attempt(math.ldexp, 0.0, 99999),
    attempt(math.log, -inf), attempt(math.log, inf, 2), attempt(math.log, 2, 1), attempt(math.log, 2, 0.5),
)
