# The `n` argument format: integers as they are, other objects through
# `__long__` or `__int__` (never `__index__`), and the overflow messages of
# a build whose C long is narrower than Py_ssize_t.

import _io


class Int(object):
    def __int__(self):
        return 2


class IntLong(object):
    def __int__(self):
        return 2L


class IntHuge(object):
    def __int__(self):
        return 2 ** 70


class IntFloat(object):
    def __int__(self):
        return 2.5


class IntRaises(object):
    def __int__(self):
        raise KeyError('k')


class Long(object):
    def __long__(self):
        return 2L


class LongInt(object):
    def __long__(self):
        return 2


class LongFloat(object):
    def __long__(self):
        return 2.5


class LongNone(object):
    def __long__(self):
        return None


class Both(object):
    def __int__(self):
        return 2

    def __long__(self):
        return 3L


class BothBadLong(object):
    def __int__(self):
        return 2

    def __long__(self):
        return 'x'


class IndexAndInt(object):
    def __index__(self):
        return 5

    def __int__(self):
        return 2


class Index(object):
    def __index__(self):
        return 2


class Trunc(object):
    def __trunc__(self):
        return 2


class IntBool(object):
    def __int__(self):
        return True


class LongSub(long):
    pass


class IntGivesLongSub(object):
    def __int__(self):
        return LongSub(4)


class Classic:
    def __int__(self):
        return 2


class ClassicLong:
    def __long__(self):
        return 2L


class ClassicBoth:
    def __int__(self):
        return 2

    def __long__(self):
        return 3L


class ClassicIndex:
    def __index__(self):
        return 2


class ClassicTrunc:
    def __trunc__(self):
        return 2


class ClassicTruncFloat:
    def __trunc__(self):
        return 2.5


class ClassicIntFloat:
    def __int__(self):
        return 2.5


class ClassicEmpty:
    pass


class SubInt(int):
    def __int__(self):
        return 7

    def __long__(self):
        return 8L


class SubLong(long):
    def __int__(self):
        return 7

    def __long__(self):
        return 8L


class SubFloat(float):
    pass


class Negative(object):
    def __int__(self):
        return -1


def attempt(function, *args):
    try:
        result = function(*args)
        return ('ok', result if isinstance(result, (int, long, str, unicode, bool)) else type(result).__name__)
    except Exception as e:
        return (type(e).__name__, str(e))


values = [Int(), IntLong(), IntHuge(), IntFloat(), IntRaises(), Long(), LongInt(), LongFloat(), LongNone(), Both(), BothBadLong(), IndexAndInt(), Index(),
          Trunc(), IntBool(), IntGivesLongSub(), Classic(), ClassicLong(), ClassicBoth(), ClassicIndex(), ClassicTrunc(), ClassicTruncFloat(),
          ClassicIntFloat(), ClassicEmpty(), SubInt(3), SubLong(3), SubFloat(2.0), Negative(), True, 2L, 2 ** 40, 2 ** 63 - 34, 2 ** 63, -2 ** 63,
          -2 ** 63 - 1, 2 ** 64, -2 ** 64, 2 ** 70, 'x', None, 2.0, [1], u'1', 1j]

RESULT = []
for value in values:
    RESULT.append((value.__class__.__name__ if not isinstance(value, (bool, long)) else repr(value),
                   attempt(range(20).pop, value),
                   attempt('ab'.zfill, value),
                   attempt(u'ab'.zfill, value),
                   attempt(lambda width: str(bytearray('ab').zfill(width)), value),
                   attempt('ab'.ljust, value),
                   attempt('ab'.rjust, value),
                   attempt(bytearray('abcd').pop, value),
                   attempt(_io.BufferedReader(_io.BytesIO('abcdef')).read1, value),
                   attempt(lambda index: [0, 1].insert(index, 9), value)))
