def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

ints = [(a // b, a % b, divmod(a, b), a / b) for a in (7, -7) for b in (2, -2)]
longs = [(a // b, a % b) for a in (7L, -7L) for b in (2, -2L)]
floats = [(a // b, a % b, divmod(a, b), a / b) for a in (7.5, -7.5) for b in (2.0, -2)]
zeros = (0.0 % -3.0, -0.0 % 3.0, 3.0 % -3.0, -3.0 % 3.0, 0 // 5, -1 // 5, 1 // -5, 5.0 // 0.3, -5.0 // 0.3)
truediv = (7 .__truediv__(2), (7).__rtruediv__(2), 1e300 * 10, 2 ** -1, 2.0 ** -1, (-8) ** 2, 2 ** 0.5)
errors = (
    err(lambda: 1 // 0),
    err(lambda: 1 % 0),
    err(lambda: 1L / 0),
    err(lambda: 1.0 / 0),
    err(lambda: 1.0 // 0),
    err(lambda: 1.0 % 0),
    err(divmod, 1.0, 0),
    err(divmod, 1, 0),
    err(lambda: 0.0 ** -1),
    err(lambda: (-8.0) ** 0.5),
    err(lambda: 1 << -1),
    err(lambda: 2 ** 10000 / 1.0),
    err(lambda: 1 / 0.0),
)

RESULT = (ints, longs, floats, zeros, truediv, errors)
