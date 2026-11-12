# Aware time and datetime through tzinfo subclasses written in Python:
# offsets, conversions, comparison, hashing, and tzinfo method errors.
from datetime import datetime, time, timedelta, tzinfo

ZERO = timedelta(0)
HOUR = timedelta(hours=1)


def K(value):
    return value


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Fixed(tzinfo):
    def __init__(self, minutes, name):
        self.offset = timedelta(minutes=minutes)
        self.name = name

    def utcoffset(self, dt):
        return self.offset

    def tzname(self, dt):
        return self.name

    def dst(self, dt):
        return ZERO

    def __repr__(self):
        return 'Fixed(%r)' % self.name

    def __getinitargs__(self):
        return (self.offset.seconds // 60 + self.offset.days * 1440, self.name)


class Eastern(tzinfo):
    """US Eastern with the 1987-2006 rules, from the library reference."""

    def utcoffset(self, dt):
        return timedelta(hours=-5) + self.dst(dt)

    def tzname(self, dt):
        return 'EDT' if self.dst(dt) else 'EST'

    def dst(self, dt):
        if dt is None or dt.tzinfo is None:
            return ZERO
        start = first_sunday_on_or_after(datetime(dt.year, 4, 1, 2))
        end = first_sunday_on_or_after(datetime(dt.year, 10, 25, 1))
        if start <= dt.replace(tzinfo=None) < end:
            return HOUR
        return ZERO

    def __repr__(self):
        return 'Eastern()'


def first_sunday_on_or_after(dt):
    days_to_go = 6 - dt.weekday()
    if days_to_go:
        dt += timedelta(days_to_go)
    return dt


class Bad(tzinfo):
    def __init__(self, result):
        self.result = result

    def utcoffset(self, dt):
        return self.result

    def dst(self, dt):
        return self.result

    def tzname(self, dt):
        return self.result


class Naive(tzinfo):
    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return None


class Flip(tzinfo):
    # dst() is None once the local time moves, which fromutc reports.
    def utcoffset(self, dt):
        return 2 * HOUR

    def dst(self, dt):
        return HOUR if dt.hour == 0 else None


utc = Fixed(K(0), 'UTC')
naive_zone = Naive()
flip = Flip()
plus = Fixed(K(90), 'P%M')
minus = Fixed(K(-330), 'M')
eastern = Eastern()

a = datetime(K(2002), K(3), K(1), K(12), K(0), tzinfo=plus)
b = datetime(K(2002), K(3), K(1), K(10), K(30), tzinfo=utc)
c = datetime(K(2002), K(3), K(1), K(5), K(0), tzinfo=minus)
naive = datetime(K(2002), K(3), K(1), K(10), K(30))

aware = [
    repr(a), str(a), a.isoformat(), c.isoformat(), a.utcoffset(), c.utcoffset(), a.dst(), a.tzname(), c.tzname(),
    a == b, a != b, a < c, a - b, b - c, c - a, a + HOUR, repr(a.replace(tzinfo=None)), repr(a.timetz()), repr(a.time()),
    hash(a) == hash(b), hash(a) == hash(c), hash(a), repr(a.timetuple()), repr(a.utctimetuple()), repr(c.utctimetuple()),
    repr(a.astimezone(utc)), repr(c.astimezone(plus)), a.astimezone(plus) is a, repr(utc.fromutc(b)),
    repr(datetime.fromtimestamp(K(1e9), plus)), repr(datetime.fromtimestamp(K(0), tz=minus)),
    repr(datetime.combine(a.date(), time(K(1), tzinfo=minus))), repr(datetime.max.replace(tzinfo=plus).utctimetuple()),
    repr(datetime.min.replace(tzinfo=plus).utctimetuple()), repr(datetime.min.replace(tzinfo=minus).utctimetuple()),
]

dst = []
for when in [datetime(K(2002), K(4), K(7), K(6)), datetime(K(2002), K(4), K(7), K(7)), datetime(K(2002), K(10), K(27), K(5)), datetime(K(2002), K(10), K(27), K(6)), datetime(K(2002), K(10), K(27), K(7))]:
    local = when.replace(tzinfo=utc).astimezone(eastern)
    dst.append((repr(local), local.tzname(), local.timetuple().tm_isdst, str(local.utcoffset()), local.isoformat()))
dst.append(repr(datetime(K(2002), K(7), K(4), K(12), tzinfo=eastern).utctimetuple()))
dst.append(repr(datetime(K(2002), K(7), K(4), K(12), tzinfo=eastern) - datetime(K(2002), K(1), K(4), K(12), tzinfo=eastern)))
dst.append(repr(datetime(K(2002), K(7), K(4), K(12), tzinfo=eastern) - datetime(K(2002), K(7), K(4), K(12), tzinfo=utc)))

t1 = time(K(12), K(0), tzinfo=plus)
t2 = time(K(10), K(30), tzinfo=utc)
t3 = time(K(0), K(30), tzinfo=plus)
times = [
    repr(t1), str(t1), t1.isoformat(), t1.utcoffset(), t1.tzname(), t1.dst(), t1 == t2, t1 < time(K(11), tzinfo=utc),
    hash(t1) == hash(t2), hash(t3) == hash((K(-1), K(0), K(0), K(0))), bool(time(K(1), K(30), tzinfo=plus)), bool(t3),
    repr(t1.replace(tzinfo=None)), t1.__reduce__(), repr(time(*t1.__reduce__()[1])),
    time(K(1), tzinfo=Naive()) == time(K(1)), hash(time(K(1), tzinfo=Naive())) == hash(time(K(1))),
]

pickled = [
    a.__reduce__(), repr(datetime(*a.__reduce__()[1])), utc.__reduce__(), repr(Fixed(*utc.__reduce__()[1])), tzinfo().__reduce__(),
    Naive().__reduce__(), repr(type(tzinfo(K(1), K(2)))),
]

mixed = [
    datetime(K(2002), K(1), K(1), tzinfo=Naive()) == datetime(K(2002), K(1), K(1)),
    datetime(K(2002), K(1), K(1), tzinfo=Naive()) - datetime(K(2002), K(1), K(1)),
]

errors = [error(action) for action in (
    lambda: a < naive,
    lambda: a == naive,
    lambda: b != naive,
    lambda: a - naive,
    lambda: naive - a,
    lambda: t1 < time(K(1)),
    lambda: t1 == time(K(12), K(0), tzinfo=Naive()),
    lambda: naive.astimezone(utc),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Naive()).astimezone(utc),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(K(1))).utcoffset(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(timedelta(K(0), K(30)))).utcoffset(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(timedelta(K(1)))).utcoffset(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(timedelta(K(-1)))).utcoffset(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(timedelta(K(-2)))).dst(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(timedelta(K(0), K(0), K(1)))).isoformat(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(K(1))).tzname(),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(K(u'x'))).tzname(),
    lambda: time(tzinfo=Bad(K(1.5))).utcoffset(),
    lambda: hash(time(tzinfo=Bad(K('x')))),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=Bad(K(1))) == datetime(K(2000), K(1), K(1), tzinfo=utc),
    lambda: utc.fromutc(naive),
    lambda: utc.fromutc(K(1)),
    lambda: plus.fromutc(b),
    lambda: Naive().fromutc(datetime(K(2000), K(1), K(1), tzinfo=Naive())),
    lambda: naive_zone.fromutc(datetime(K(2000), K(1), K(1), tzinfo=naive_zone)),
    lambda: flip.fromutc(datetime(K(2000), K(1), K(1), tzinfo=flip)),
    lambda: tzinfo().utcoffset(None),
    lambda: tzinfo().dst(None),
    lambda: tzinfo().tzname(None),
    lambda: tzinfo().tzname(),
    lambda: tzinfo.fromutc(K(1), naive),
    lambda: datetime(K(9999), K(12), K(31), K(23), tzinfo=minus).astimezone(utc),
    lambda: datetime(K(1), K(1), K(1), tzinfo=plus).astimezone(utc),
    lambda: datetime.fromtimestamp(K(0), K(1)),
    lambda: datetime.now(tz=K(1)),
    lambda: a.strftime(K('%')),
    lambda: datetime(K(1850), K(1), K(1), tzinfo=Bad(K(1))).strftime(K('%z')),
)]

RESULT = (aware, dst, times, pickled, mixed, errors, tzinfo.__module__)
