K = lambda value: value


def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, e.args)


class Lookup(object):
    def __getitem__(self, key):
        return key * 2


class Point(object):
    x = 3


class Old:
    pass


RESULT = (
    # Unknown codes and conversions in messages.
    err(format, u'x', u'\x7f'), err(format, u'x', u'\x20'), err(format, u'x', u'!'), err(format, 'x', '\xff'),
    err(K('{!\x7f}').format, 1), err(K('{!\xe9}').format, 1), err(K(u'{!\xe9}').format, 1), err(K('{!~}').format, 1),
    err(format, u'x', u',\xe9'), err(format, 'x', ','),
    # A field index reaches a Python __getitem__ as an int, a dict as a long.
    K('{0[0]!r}').format(Lookup()), err(K('{0[1]}').format, {}), K('{0[1]}').format({1: 'one'}),
    err(K('{0[0]}').format, Point()), err(K('{0[a]}').format, Point()), err(K('{0[a]}').format, u'abc'),
    # Floats without a type switch to an exponent one digit early.
    format(1.5, '.1'), format(15.0, '.1'), format(0.5, '.0'), format(5.0, '.2'), format(55.0, '.2'),
    format(1e10, ''), format(1e11, ''), format(123456789012.0, ''), format(0.0, '.0'),
    format(1.5 + 2.5j, '.0'), format(complex(0.0, -0.0), ''), format(complex(-0.0, 0.0), 'g'),
    format(float('inf'), '010,'), format(-1234567, '015,'), format(1234.5, '011,.2f'), format(0, '04,'),
    format(1234, '0=9,'), format(1234, '0>9,'), format(-12345.678, '015,.2e'),
    err(format, 1 + 2j, '0>10'), err(format, 1 + 2j, '=#05'), err(format, 1.5, '#.2147483648'),
    err(format, 'abc', '=#5'), err(format, 5, '.2z'), err(format, 2 ** 70, '#,x'),
    format(1e16, '.20'), format(0.1, '.17'), format(1.5, '.2147483647'),
)
