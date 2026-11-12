# Naive datetime and time: construction, arithmetic, formatting, UTC
# timestamps, comparison, and pickle state. The Windows CRT gmtime rejects
# timestamps more than 12 hours before the epoch or 13 hours past
# 3000-12-31 23:59:59.
from datetime import date, datetime, time, timedelta


def K(value):
    return value


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Moment(datetime):
    pass


dt = datetime(K(2004), K(2), K(29), K(13), K(5), K(9), K(123))
plain = datetime(K(1999), K(12), K(31), K(23), K(59))
moment = Moment(K(2010), K(6), K(1), K(12))
t = time(K(7), K(8), K(9), K(10))

datetimes = [
    repr(dt), str(dt), dt.isoformat(), dt.isoformat(K(' ')), dt.isoformat(sep=K('x')), repr(plain), str(plain), dt.ctime(),
    repr(moment), str(moment), repr(datetime(K(2000), K(1), K(1), K(0), K(0), K(5))),
    [dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond, dt.tzinfo],
    repr(dt.date()), repr(dt.time()), repr(dt.timetz()), repr(dt.timetuple()), repr(dt.utctimetuple()),
    dt.utcoffset(), dt.dst(), dt.tzname(), dt.toordinal(), dt.weekday(), dt.isocalendar(),
    repr(datetime.combine(date(K(2001), K(2), K(3)), time(K(4), K(5)))), repr(Moment.combine(dt, t)),
    repr(datetime.fromordinal(K(730000))), repr(Moment.fromordinal(K(1))),
    repr(datetime.min), repr(datetime.max), repr(datetime.resolution),
]

timestamps = [repr(datetime.utcfromtimestamp(K(value))) for value in (0, 1, 951782400.5, 1e9 + 0.9999996, 1234567890.123456, 32535244799, -1, -0.5, -0.0000001, -43200, 32535291599)] + [
    repr(Moment.utcfromtimestamp(K(86400))), repr(datetime.utcfromtimestamp(K(10L))),
]

arithmetic = [
    repr(dt + timedelta(K(1), K(3600), K(999999))), repr(timedelta(K(-1)) + dt), repr(dt - timedelta(K(0), K(0), K(124))),
    repr(dt - plain), repr(plain - dt), repr(dt - dt), repr(moment + timedelta(K(1))), type(moment - timedelta(K(1))).__name__,
    repr(moment - dt), repr(datetime.max - datetime.min), repr(dt.replace(hour=K(0), microsecond=K(0))),
    type(moment.replace(year=K(2011))).__name__, repr(dt.replace(K(2005), K(3), K(1), K(2), K(3), K(4), K(5))),
]

comparisons = [
    dt == datetime(K(2004), K(2), K(29), K(13), K(5), K(9), K(123)), dt != plain, dt > plain, plain < dt, dt <= dt, dt >= moment,
    dt == date(K(2004), K(2), K(29)), dt != date(K(2004), K(2), K(29)), dt == K(1), sorted([moment, dt, plain]) == [plain, dt, moment],
    hash(dt) == hash(datetime(K(2004), K(2), K(29), K(13), K(5), K(9), K(123))), hash(dt), hash(plain),
    hash(datetime(K(2000), K(1), K(1))) == hash(date(K(2000), K(1), K(1))),
]

times = [
    repr(t), str(t), t.isoformat(), repr(time()), repr(time(K(1), K(2), K(3))), str(time(K(23), K(59))), repr(time.min), repr(time.max), repr(time.resolution),
    [t.hour, t.minute, t.second, t.microsecond, t.tzinfo, t.utcoffset(), t.dst(), t.tzname()],
    bool(time()), bool(time(K(0), K(0), K(0), K(1))), bool(t), t < time(K(8)), t == time(K(7), K(8), K(9), K(10)), t == K(1), t != K(1),
    hash(t) == hash(time(K(7), K(8), K(9), K(10))), hash(t), repr(t.replace(hour=K(1))), repr(time(minute=K(5))), format(t, ''),
]

state = [
    dt.__reduce__(), plain.__reduce__(), t.__reduce__(), moment.__reduce__()[1], repr(datetime(*dt.__reduce__()[1])), repr(time(*t.__reduce__()[1])),
    repr(datetime(K('\x07\xd0\x01\x01\xff\x00\x00\x00\x00\x01'))), repr(time(K('\x17\xff\x00\x00\x00\x01'))),
    repr(Moment(K('\x07\xd0\x01\x01\x00\x00\x00\x00\x00\x01'))),
]

errors = [error(action) for action in (
    lambda: datetime(K(2000), K(1)),
    lambda: datetime(K(2000), K(1), K(1), K(24)),
    lambda: datetime(K(2000), K(1), K(1), K(0), K(60)),
    lambda: datetime(K(2000), K(1), K(1), K(0), K(0), K(60)),
    lambda: datetime(K(2000), K(1), K(1), K(0), K(0), K(0), K(1000000)),
    lambda: datetime(K(2000), K(1), K(1), tzinfo=K(1)),
    lambda: datetime(K(2000), K(1), K(1), K(1), K(2), K(3), K(4), None, K(5)),
    lambda: datetime(K('\x07\xd0\x01\x01\x00\x00\x00\x00\x00\x01'), K(1)),
    lambda: time(K(24)),
    lambda: time(K(-1)),
    lambda: time(tzinfo=K('x')),
    lambda: time(K('\x18\x00\x00\x00\x00\x01')),
    lambda: time(K('\x10\x00\x00\x00\x00\x01'), K(1)),
    lambda: datetime.max + timedelta(K(0), K(0), K(1)),
    lambda: datetime.min - timedelta(K(0), K(0), K(1)),
    lambda: dt + dt,
    lambda: dt - K(1),
    lambda: dt < K(1),
    lambda: dt < date(K(2000), K(1), K(1)),
    lambda: date(K(2000), K(1), K(1)) > dt,
    lambda: t < K(1),
    lambda: t + timedelta(K(1)),
    lambda: dt.isoformat(K('ab')),
    lambda: dt.isoformat(K(u'a')),
    lambda: dt.isoformat(K(None)),
    lambda: dt.astimezone(K(1)),
    lambda: dt.astimezone(),
    lambda: datetime.combine(K(1), t),
    lambda: datetime.combine(dt, K(None)),
    lambda: datetime.combine(dt),
    lambda: datetime.utcfromtimestamp(K('x')),
    lambda: datetime.utcfromtimestamp(K(-43201)),
    lambda: datetime.utcfromtimestamp(K(-43200.5)),
    lambda: datetime.utcfromtimestamp(K(-86400 * 365)),
    lambda: datetime.utcfromtimestamp(K(32535291600)),
    lambda: datetime.utcfromtimestamp(K(32535291599.5)),
    lambda: datetime.utcfromtimestamp(K(1e11)),
    lambda: datetime.utcfromtimestamp(K(1e20)),
    lambda: datetime.utcfromtimestamp(K(2 ** 2000)),
    lambda: datetime.fromtimestamp(K(1e20)),
    lambda: datetime.fromtimestamp(tz=None),
    lambda: datetime.now(K(1)),
    lambda: datetime.utcnow(K(1)),
    lambda: datetime.strptime(K(1), K('%Y')),
    lambda: datetime.strptime(K('2000')),
    lambda: dt.strftime(K('%')),
    lambda: datetime(K(1800), K(1), K(1)).strftime(K('%f')),
    lambda: t.strftime(K('%z%')),
    lambda: time.strftime(),
    lambda: dt.replace(K(1), K(2), K(3), K(4), K(5), K(6), K(7), None, K(9)),
    lambda: dt.replace(day=K(32)),
    lambda: t.replace(K(1), K(2), K(3), K(4), None, K(6)),
    lambda: datetime.date(K(1)),
    lambda: datetime.hour.__get__(date(K(2000), K(1), K(1))),
)]

RESULT = (datetimes, timestamps, arithmetic, comparisons, times, state, errors, datetime.__bases__, issubclass(datetime, date))
