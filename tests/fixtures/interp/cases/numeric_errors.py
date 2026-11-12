def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class NoNumber(object):
    pass

RESULT = [
    err(int, NoNumber()),
    err(long, NoNumber()),
    err(float, NoNumber()),
    err(lambda: 1 + 'a'),
    err(lambda: 1.0 & 1),
    err(lambda: -'a'),
    err(lambda: ~1.5),
    err(abs, 'a'),
    err(int, '12', 99),
    err(int.__new__, 5),
    err(int.__new__, str),
    err(float.__new__),
    err(lambda: int(x='5', y=1)),
    err(float, 1, 2),
    err(int.__new__, int, 2 ** 70),
]
