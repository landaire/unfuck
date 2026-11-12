import math

def attempt(function, *args, **kwargs):
    try:
        return repr(function(*args, **kwargs))
    except Exception as e:
        return (type(e).__name__, e.args)

class Number(object):
    def __float__(self):
        return 2.25

class WrongFloat(object):
    def __float__(self):
        return 3

class Classic:
    pass

class ClassicNumber:
    def __float__(self):
        return 6.25
    def __int__(self):
        return 4

class ClassicTrunc:
    def __trunc__(self):
        return 7

class ClassicFloatTrunc:
    def __trunc__(self):
        return 4.5

class ClassicBadTrunc:
    def __trunc__(self):
        return 'x'

class Integer(object):
    def __int__(self):
        return 6L

class Truncated(object):
    def __trunc__(self):
        return 'truncated'

RESULT = [
    attempt(math.sqrt, Number()), attempt(math.sqrt, WrongFloat()), attempt(math.sqrt, ClassicNumber()),
    attempt(math.sqrt, '4'), attempt(math.sqrt, None),
    attempt(math.sqrt, [4]), attempt(math.sqrt), attempt(math.sqrt, 1, 2), attempt(math.sqrt, x=4),
    attempt(math.atan2, 1), attempt(math.atan2, 1, 2, 3), attempt(math.atan2, 1, y=2), attempt(math.pow, 'a', 2), attempt(math.hypot, 3, Number()),
    attempt(math.log), attempt(math.log, 1, 2, 3), attempt(math.log, Number(), Number()),
    attempt(math.ldexp, 1), attempt(math.ldexp, 'a', 1), attempt(math.ldexp, Number(), 2),
    attempt(math.factorial, Integer()), attempt(math.factorial, ClassicNumber()), attempt(math.factorial, ClassicTrunc()), attempt(math.factorial, ClassicFloatTrunc()), attempt(math.factorial, ClassicBadTrunc()), attempt(math.factorial, Truncated()),
    attempt(math.factorial, Number()),
    attempt(math.trunc, Truncated()), attempt(math.trunc, ClassicTrunc()),
    attempt(math.fsum, [Number()]), attempt(math.isnan, Number()),
    attempt(math.fmod, 1), attempt(math.fsum), attempt(math.factorial, 1, 2), attempt(math.modf, Number()),
]
