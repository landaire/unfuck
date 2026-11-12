import math

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, e.args)

big = 10 ** 400
results = [
    attempt(math.log, big), attempt(math.log10, big), attempt(math.log, big, 10), attempt(math.log, 2 ** 1023 + 2 ** 970),
    attempt(math.log, 2 ** 1024), attempt(math.log, 2 ** 1024 - 1), attempt(math.log, 3 ** 2000, 3), attempt(math.log10, 10 ** 308 * 10L),
    attempt(math.log, 0L), attempt(math.log, -big), attempt(math.log10, -5L), attempt(math.log, 7L), attempt(math.log, 1, big),
    attempt(math.sqrt, big), attempt(math.sqrt, 10 ** 300), attempt(math.exp, 5L), attempt(math.atan2, big, 1),
    attempt(math.ldexp, 1.0, 2 ** 70), attempt(math.ldexp, 1.0, -2 ** 70), attempt(math.ldexp, 0.5, 5L), attempt(math.ldexp, 1, True),
    attempt(math.ldexp, 1.0, 1.0), attempt(math.ldexp, 1.0, None), attempt(math.isinf, big), attempt(math.frexp, 2 ** 100),
    attempt(math.factorial, 0), attempt(math.factorial, 5), attempt(math.factorial, 20), attempt(math.factorial, 21),
    attempt(math.factorial, 30L), attempt(math.factorial, 6.0), attempt(math.factorial, True), attempt(math.factorial, -1),
    attempt(math.factorial, -1.0), attempt(math.factorial, 2.5), attempt(math.factorial, (1e308 * 10)), attempt(math.factorial, ((1e308 * 10) - (1e308 * 10))),
    attempt(math.factorial, 2 ** 70), attempt(math.factorial, 1e300), attempt(math.factorial, 'a'), attempt(math.factorial, None),
    attempt(math.trunc, 3.7), attempt(math.trunc, -3.7), attempt(math.trunc, 1e20), attempt(math.trunc, 5), attempt(math.trunc, 5L),
    attempt(math.trunc, True), attempt(math.trunc, (1e308 * 10)), attempt(math.trunc, ((1e308 * 10) - (1e308 * 10))), attempt(math.trunc, 'x'),
]
kinds = [type(math.factorial(20)).__name__, type(math.factorial(21)).__name__, type(math.factorial(3L)).__name__,
         type(math.trunc(2.5)).__name__, type(math.trunc(1e20)).__name__, type(math.trunc(2L)).__name__]
RESULT = (results, kinds)
