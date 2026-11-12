import math

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, e.args)

inf = (1e308 * 10)
nan = ((1e308 * 10) - (1e308 * 10))
inputs = [0.5, 1.5, 2.5, 3.3, 4.0, 7.75, 10.1, 23.0, 24.0, 30.5, 141.5, 171.6, 171.7, 250.0, 1e-25, -1e-25,
          -0.5, -1.5, -2.25, -10.3, -150.2, -180.5, -250.5, -2.0, 0.0, -0.0, inf, -inf, nan]
erf_inputs = [0.0, -0.0, 0.1, 0.5, 1.0, 1.4999, 1.5, 2.0, 3.7, 5.9, 29.0, 30.0, -0.3, -1.6, -4.0, 1e-300, inf, -inf, nan]
RESULT = (
    [attempt(math.gamma, x) for x in inputs],
    [attempt(math.lgamma, x) for x in inputs],
    [attempt(math.erf, x) for x in erf_inputs],
    [attempt(math.erfc, x) for x in erf_inputs],
    [attempt(math.acosh, x) for x in [1.0, 1.25, 1.5, 1.75, 2.5, 3.0, 5.0, 101.0, 100001.0, inf, nan]],
    [attempt(math.asinh, x) for x in [0.0, -0.0, 1e-30, 0.25, 0.5, 0.7, 2.0, 5.0, 100000.0, 1e10, -0.7, -5.0, inf, -inf]],
    [attempt(math.atanh, x) for x in [0.0, -0.0, 1e-30, 0.25, 0.6666666666666666, -0.25, nan]],
    [attempt(math.expm1, x) for x in [0.0, -0.0, 1e-30, 1e-10, 0.001, 0.1, 0.5, 0.69, 1.0, 10.0, -0.3, -0.7, -inf]],
    [attempt(math.log1p, x) for x in [0.0, -0.0, 1e-30, 1e-10, 0.001, 0.25, 0.7, 1.0, 10.0, -0.5, -0.2, inf]],
    attempt(math.atanh, 1), attempt(math.atanh, -1.0), attempt(math.acosh, 0.5), attempt(math.log1p, -1), attempt(math.log1p, -2),
    attempt(math.expm1, 710), attempt(math.expm1, -inf),
)
