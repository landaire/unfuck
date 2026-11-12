# timedelta construction, normalization, arithmetic, and errors.
from datetime import timedelta


def K(value):
    return value


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Span(timedelta):
    pass


class Big(int):
    pass


td = timedelta(K(1), K(2), K(3))
neg = -timedelta(K(0), K(1))
mixed = timedelta(weeks=K(1.5), days=K(-0.25), hours=K(2.5), minutes=K(-1), seconds=K(0.000001), milliseconds=K(1.5), microseconds=K(0.6))
span = Span(hours=K(25))

construction = [
    repr(td), repr(neg), repr(mixed), repr(timedelta()), repr(timedelta(K(0), K(0), K(-1))),
    repr(timedelta(seconds=K(86400 * 3 + 7))), repr(timedelta(microseconds=K(-1500000))),
    repr(timedelta(days=K(2 ** 40) // K(2 ** 40))), repr(timedelta(K(1L), K(True))),
    repr(timedelta(microseconds=K(0.5))), repr(timedelta(microseconds=K(1.5))), repr(timedelta(microseconds=K(-0.5))),
    repr(timedelta(seconds=K(1e-7))), repr(timedelta(days=K(1e-12))),
    repr(span), type(span).__name__, repr(Span(K(1), K(2), K(3))),
]

strings = [str(td), str(neg), str(mixed), str(timedelta()), str(timedelta(K(-1))), str(timedelta(K(2), K(59))), str(timedelta(K(1), K(3600), K(5))), str(span)]

arithmetic = [
    repr(td + neg), repr(td - neg), repr(neg - td), repr(td * K(3)), repr(K(3) * td), repr(td * K(-2L)), repr(td * K(True)),
    repr(td // K(7)), repr(td / K(7)), repr(neg // K(3)), repr(-td), repr(+td), repr(abs(neg)), repr(abs(td)),
    repr(span + span), type(span + span).__name__, type(-span).__name__, type(span * 2).__name__,
    repr(Big(4) * td), repr(td * Big(4)), repr(timedelta.max - timedelta.max), repr(timedelta.min + timedelta.max),
]

comparisons = [
    td == timedelta(K(1), K(2), K(3)), td != neg, td < neg, td > neg, td <= td, td >= neg,
    td == K(1), td != K(1), neg < td, sorted([td, neg, timedelta()]), timedelta(0) == timedelta(),
    hash(td) == hash(timedelta(seconds=K(86402), microseconds=K(3))), hash(td), hash(timedelta()), hash(neg),
    bool(timedelta()), bool(neg), bool(timedelta(microseconds=K(1))),
]

attributes = [
    td.days, td.seconds, td.microseconds, neg.days, neg.seconds, td.total_seconds(), neg.total_seconds(),
    timedelta.max.total_seconds(), repr(timedelta.min), repr(timedelta.max), repr(timedelta.resolution),
    td.__reduce__(), span.__reduce__()[1], type(timedelta.days).__name__,
    timedelta.__module__, timedelta.__name__, repr(timedelta),
    repr(timedelta(*td.__reduce__()[1])),
]

errors = [error(action) for action in (
    lambda: timedelta(K('1')),
    lambda: timedelta(seconds=K(None)),
    lambda: timedelta(K(1), K(2), K(3), K(4), K(5), K(6), K(7), K(8)),
    lambda: timedelta(K(1), days=K(2)),
    lambda: timedelta(bogus=K(1)),
    lambda: timedelta(K(1000000000)),
    lambda: timedelta(K(-1000000000)),
    lambda: timedelta(K(999999999), K(86400)),
    lambda: timedelta(K(2 ** 31)),
    lambda: timedelta(K(-2 ** 31 - 1)),
    lambda: timedelta(K(2 ** 40)),
    lambda: timedelta(seconds=K(2 ** 31 * 86400)),
    lambda: timedelta(hours=K(2 ** 60)),
    lambda: timedelta(days=K(3e9)),
    lambda: td * K(2 ** 40),
    lambda: timedelta.max + timedelta(K(0), K(0), K(1)),
    lambda: timedelta.min - timedelta(K(0), K(0), K(1)),
    lambda: -timedelta.min,
    lambda: td * K(10 ** 9),
    lambda: td * K(1.5),
    lambda: td / K(0),
    lambda: td // K(0.5),
    lambda: td + K(1),
    lambda: K(1) - td,
    lambda: td < K(1),
    lambda: K(1) >= td,
    lambda: timedelta(days=K(float('inf'))),
    lambda: timedelta(days=K(float('nan'))),
    lambda: td.total_seconds(K(1)),
    lambda: setattr(td, 'days', 1),
    lambda: timedelta.__add__(1, td),
    lambda: timedelta.__new__(int),
    lambda: K(1.0) / td,
    lambda: hash(timedelta.max),
)]

RESULT = (construction, strings, arithmetic, comparisons, attributes, errors)
