import math

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, e.args)

inf = (1e308 * 10)
nan = ((1e308 * 10) - (1e308 * 10))
tenths = [0.1] * 10
mixed = [1e100, 1.0, -1e100, 1e-100, 1e50, -1.0, -1e50]
results = [
    attempt(math.fsum, []), attempt(math.fsum, tenths), sum(tenths), attempt(math.fsum, mixed),
    attempt(math.fsum, [1e-16, 1, 1e16]), attempt(math.fsum, [1, 1e16, 1e-16]), attempt(math.fsum, [2.0 ** 53, -0.5, -2.0 ** -54]),
    attempt(math.fsum, [2.0 ** 53, 1.0, 2.0 ** -100]), attempt(math.fsum, [2.0 ** 53 - 1.0, 0.5, 2.0 ** -54]),
    attempt(math.fsum, [1.7976931348623157e+308, -1.7976931348623157e+308, 1.0]), attempt(math.fsum, (x * 0.001 for x in range(1000))),
    attempt(math.fsum, [1, 2L, True, 0.5]), attempt(math.fsum, [-0.0]), attempt(math.fsum, [1e308, 1e308]),
    attempt(math.fsum, [1e308, 1e-308, -1e308]), attempt(math.fsum, [inf, 1.0, inf]), attempt(math.fsum, [inf, -inf]),
    attempt(math.fsum, [nan, 1.0]), attempt(math.fsum, [-inf, 1e308, 1e308]), attempt(math.fsum, [inf, nan]),
    attempt(math.fsum, 5), attempt(math.fsum, [1.0, 'a']), attempt(math.fsum, [10 ** 400]), attempt(math.fsum, {1.5: 0, 2.5: 1}),
]
RESULT = results
