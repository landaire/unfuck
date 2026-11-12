K = lambda value: value


def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, e.args)


class Counted(object):
    calls = 0

    def __str__(self):
        Counted.calls += 1
        return u'u%d' % Counted.calls


class Plain(object):
    calls = 0

    def __str__(self):
        Plain.calls += 1
        return 's%d' % Plain.calls


class ClassicTrunc:
    def __trunc__(self):
        return 4


class ClassicLong:
    def __long__(self):
        return 3L


class Number(object):
    def __float__(self):
        return 1.25


class FloatSub(float):
    def __int__(self):
        return 66


class Lookup(object):
    def __getitem__(self, key):
        return key + '!'


def widened():
    Counted.calls = 0
    Plain.calls = 0
    first = K('%s|%s|%s') % (Plain(), Counted(), Plain())
    second = K('%*s|%s') % (5, Counted(), Plain())
    return first, second, Counted.calls, Plain.calls


RESULT = (
    # A key's value is the next argument until something consumes it.
    K('%(a)%%s') % {'a': 1}, err(lambda: K('%(a)*d') % {'a': 3}), err(lambda: K('%(a)s%s') % {'a': 1}),
    K('%(a)%%s') % {'a': u'x'}, K('%s %(a)s') % {'a': u'x'},
    # A conversion character is sign-extended unless digits precede it.
    err(lambda: K('%\xe9') % 1), err(lambda: K('%5\xe9') % 1), err(lambda: K('%.5\xe9') % 1), err(lambda: K('%5.\xe9') % 1),
    err(lambda: K('%5l\xe9') % 1), err(lambda: K(u'%\x1e') % 1), err(lambda: K(u'%\x1f') % 1), err(lambda: K(u'%\x7f') % 1),
    err(lambda: K('%i') % 'x'), err(lambda: K('%u') % 'x'), err(lambda: K(u'%i') % None),
    err(lambda: K(u'%f') % 'x'), err(lambda: K(u'%f') % 1j), err(lambda: K('%f') % 1j), K('%f') % Number(),
    K('%d') % ClassicTrunc(), K('%x') % ClassicLong(), K('%.0d') % ClassicLong(), err(lambda: K('%d') % Number()),
    K(u'%c') % FloatSub(1.5), err(lambda: K('%c') % FloatSub(1.5)), K(u'%c') % 65.9,
    K('%#.0o') % 0L, K('%#.0x') % 0, K('%.*d') % (-1, 0),
    K('%(x)s %(y)r') % Lookup(), err(lambda: K('') % xrange(2)), K('') % [], K('') % buffer('a'),
    widened(),
    err(lambda: K('\xff%s\xff') % u'x'), err(lambda: K('%s%z') % (Counted(),)),
)
