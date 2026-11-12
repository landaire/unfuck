# Random dates, times, datetimes, and timedeltas from a fixed seed:
# construction, normalization, arithmetic, comparison, hashing, and
# formatting, compared with CPython. Some timestamps fall outside the span
# the Windows CRT gmtime accepts.
from datetime import date, datetime, time, timedelta, tzinfo, MAXYEAR


def K(value):
    return value


STATE = [20161103]


def rnd(n):
    STATE[0] = (STATE[0] * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
    return (STATE[0] >> 33) % n


def pick(items):
    return items[rnd(len(items))]


def run(action):
    try:
        return repr(action())
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Fixed(tzinfo):
    def __init__(self, minutes):
        self.minutes = minutes

    def utcoffset(self, dt):
        return timedelta(minutes=self.minutes)

    def dst(self, dt):
        return timedelta(minutes=self.minutes % 7)

    def tzname(self, dt):
        return 'Z%d%%' % self.minutes

    def __repr__(self):
        return 'Fixed(%d)' % self.minutes


MAX_ORDINAL = date.max.toordinal()


def random_ordinal():
    return pick([1, 2, 365, 366, MAX_ORDINAL - 1, MAX_ORDINAL, rnd(MAX_ORDINAL) + 1, rnd(MAX_ORDINAL) + 1, rnd(MAX_ORDINAL) + 1])


def random_date():
    return date.fromordinal(K(random_ordinal()))


def random_clock():
    return (rnd(24), rnd(60), rnd(60), pick([0, 0, rnd(1000000), 999999, 1]))


def random_datetime(zone=None):
    d = random_date()
    h, m, s, us = random_clock()
    return datetime(K(d.year), K(d.month), K(d.day), K(h), K(m), K(s), K(us), zone)


def random_number():
    kind = rnd(6)
    if kind == 0:
        return rnd(2000001) - 1000000
    if kind == 1:
        return (rnd(2000001) - 1000000) / 1000.0
    if kind == 2:
        return (rnd(2000001) - 1000000) / float(pick([3, 7, 1000, 1000000, 86400]))
    if kind == 3:
        return pick([0.5, -0.5, 1.5, -2.5, 1e-7, -1e-7, 0.4999999, 2 ** 31 + 0.25])
    if kind == 4:
        return long(rnd(100)) - 50
    return rnd(100) - 50 + rnd(1000000) * 1e-6


KEYWORDS = ['days', 'seconds', 'microseconds', 'milliseconds', 'minutes', 'hours', 'weeks']


def random_delta_arguments():
    arguments = {}
    for name in KEYWORDS:
        if rnd(3) == 0:
            value = random_number()
            if name in ('weeks', 'days') and isinstance(value, float):
                value = value / 1000
            arguments[name] = value
    return arguments


def random_delta():
    return pick([
        timedelta(K(rnd(2000001) - 1000000), K(rnd(86400)), K(rnd(1000000))),
        timedelta(K(rnd(201) - 100), K(rnd(200001) - 100000), K(rnd(2000001) - 1000000)),
        timedelta(seconds=K(rnd(10 ** 6) - 5 * 10 ** 5)),
        timedelta(microseconds=K(rnd(10 ** 9) - 5 * 10 ** 8)),
        timedelta(days=K(pick([-999999999, 999999999, 3652058, -3652058]))),
    ])


deltas = []
for index in range(80):
    arguments = random_delta_arguments()
    made = run(lambda: timedelta(**arguments))
    deltas.append((sorted(arguments.items()), made))
for index in range(80):
    a = random_delta()
    b = random_delta()
    n = pick([0, 1, -1, 2, 7, -13, 1000, -2000, long(3)])
    deltas.append((
        repr(a), str(a), str(b), a.total_seconds(), run(lambda: a + b), run(lambda: a - b), run(lambda: -a), run(lambda: abs(b)),
        run(lambda: a * n), run(lambda: n * b), run(lambda: a // n), run(lambda: b / n),
        a < b, a <= b, a == b, a != b, a > b, a >= b, bool(a), hash(a) == hash(timedelta(a.days, a.seconds, a.microseconds)), hash(a),
        a.__reduce__()[1],
    ))

dates = []
for index in range(80):
    d = random_date()
    e = random_date()
    shift = random_delta()
    dates.append((
        repr(d), str(d), d.ctime(), d.toordinal(), d.weekday(), d.isoweekday(), d.isocalendar(), repr(d.timetuple()),
        run(lambda: d + shift), run(lambda: shift + d), run(lambda: d - shift), repr(d - e), d < e, d == e, d >= e, hash(d),
        run(lambda: d.replace(day=K(pick([1, 28, 29, 30, 31])))), run(lambda: d.replace(year=K(pick([1, 4, 100, 400, 1900, 2000, MAXYEAR])))),
        run(lambda: d.strftime(K('%Y|%m|%d|%j|%U|%W|%w|%y|%f|%z|%Z|%%|%H'))), d.__reduce__(),
        run(lambda: date(K(rnd(10001)), K(rnd(14)), K(rnd(33)))),
    ))

datetimes = []
for index in range(80):
    a = random_datetime()
    b = random_datetime()
    shift = random_delta()
    sep = pick(['T', ' ', 'x', '\xff'])
    datetimes.append((
        repr(a), str(a), a.isoformat(sep), a.ctime(), repr(a.timetuple()), repr(a.utctimetuple()), repr(a.date()), repr(a.time()),
        run(lambda: a + shift), run(lambda: a - shift), repr(a - b), a < b, a == b, a > b, hash(a),
        run(lambda: a.replace(hour=K(rnd(25)), microsecond=K(rnd(1000001)))),
        run(lambda: a.strftime(K('%Y-%m-%d %H:%M:%S.%f|%j|%z|%Z'))), a.__reduce__(), repr(datetime(*a.__reduce__()[1])),
        repr(datetime.combine(a.date(), b.timetz())),
        run(lambda: datetime(K(rnd(10001)), K(rnd(14)), K(rnd(33)), K(rnd(25)), K(rnd(61)), K(rnd(61)), K(rnd(1000001)))),
    ))

stamps = []
for index in range(80):
    whole = pick([
        rnd(32535291599 + 43200 + 1) - 43200,
        rnd(32535291599 + 43200 + 1) - 43200,
        -43201 - rnd(10 ** 6),
        32535291600 + rnd(10 ** 6),
    ])
    fraction = pick([0, 0.5, -0.5, 0.25, 0.9999996, 0.0000004, rnd(1000000) / 1000000.0])
    stamps.append(run(lambda: datetime.utcfromtimestamp(K(whole + fraction))))

zones = []
for index in range(80):
    za = Fixed(rnd(2879) - 1439)
    zb = Fixed(rnd(2879) - 1439)
    a = random_datetime(za)
    b = random_datetime(zb)
    shift = random_delta()
    zones.append((
        repr(a), str(a), a.utcoffset(), a.dst(), a.tzname(), repr(a.timetuple()), repr(a.utctimetuple()),
        run(lambda: a - b), a == b, a < b, a >= b, run(lambda: a + shift), run(lambda: a.astimezone(zb)),
        run(lambda: hash(a) == hash(a.astimezone(zb))), run(lambda: a.strftime(K('%z|%Z|%f'))),
        run(lambda: zb.fromutc(a.replace(tzinfo=zb))),
    ))

times = []
for index in range(80):
    h, m, s, us = random_clock()
    zone = pick([None, Fixed(rnd(2879) - 1439), Fixed(0)])
    t = time(K(h), K(m), K(s), K(us), zone)
    u = time(*random_clock())
    times.append((
        repr(t), str(t), t.isoformat(), t.utcoffset(), t.tzname(), bool(t), hash(t), run(lambda: t < u), run(lambda: t == u),
        run(lambda: t.strftime(K('%H:%M:%S.%f|%z|%Z'))), t.__reduce__(), run(lambda: t.replace(minute=K(rnd(61)))),
        run(lambda: time(K(rnd(25)), K(rnd(61)), K(rnd(61)), K(rnd(1000001)))),
    ))

states = []
for index in range(40):
    raw_date = chr(rnd(256)) + chr(rnd(256)) + chr(rnd(12) + 1) + chr(rnd(256))
    raw_clock = chr(rnd(24)) + chr(rnd(256)) + chr(rnd(256)) + chr(rnd(256)) + chr(rnd(256)) + chr(rnd(256))
    d = date(K(raw_date))
    dt = datetime(K(raw_date + raw_clock))
    t = time(K(raw_clock))
    states.append((
        repr(d), d.toordinal(), d.weekday(), d.isocalendar(), d.ctime(), repr(d.timetuple()), run(lambda: d + timedelta(1)),
        repr(dt), dt.isoformat(), run(lambda: dt + timedelta(0)), repr(dt - datetime(2000, 1, 1)), hash(dt), repr(t), hash(t), bool(t),
    ))

RESULT = (deltas, dates, datetimes, stamps, zones, times, states)
