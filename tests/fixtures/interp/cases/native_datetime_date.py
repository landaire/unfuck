# date construction, calendar arithmetic, formatting, comparison, and
# pickle state. strftime output depends on the host locale, so only its
# errors are asserted.
from datetime import date, datetime, timedelta, MINYEAR, MAXYEAR


def K(value):
    return value


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Day(date):
    def isoformat(self):
        return 'day:' + date.isoformat(self)


class Stamp(object):
    def timetuple(self):
        return ()


d = date(K(2000), K(2), K(29))
first = date(K(1), K(1), K(1))
last = date(K(9999), K(12), K(31))
day = Day(K(2016), K(1), K(3))

basics = [
    repr(d), str(d), d.isoformat(), d.ctime(), repr(day), str(day), day.isoformat(), format(day, ''),
    d.year, d.month, d.day, d.toordinal(), first.toordinal(), last.toordinal(),
    repr(date.fromordinal(K(730179))), repr(date.fromordinal(K(1))), repr(date.fromordinal(K(3652059))),
    repr(Day.fromordinal(K(736000))), d.weekday(), d.isoweekday(), last.weekday(),
    [date(K(y), K(m), K(dd)).isocalendar() for (y, m, dd) in [(2003, 12, 29), (2004, 1, 1), (2005, 1, 2), (2008, 12, 29), (2009, 12, 31), (2010, 1, 3), (1, 1, 1), (9999, 12, 31)]],
    repr(d.timetuple()), d.timetuple().tm_yday, repr(date.min), repr(date.max), repr(date.resolution),
    MINYEAR, MAXYEAR, format(d, ''), format(d, u''), type(format(d, u'')).__name__,
    [date(K(1900), K(3), K(1)).toordinal() - date(K(1900), K(2), K(28)).toordinal(), date(K(2100), K(3), K(1)).weekday()],
]

arithmetic = [
    repr(d + timedelta(K(1))), repr(timedelta(K(366)) + d), repr(d - timedelta(K(60))), repr(d - first), repr(first - d),
    repr(d + timedelta(K(0), K(86399))), repr(d - timedelta(K(0), K(1))), repr(day + timedelta(K(1))), type(day - timedelta(K(1))).__name__,
    repr(last - first), repr(d.replace(year=K(2001), day=K(28))), repr(day.replace(K(2017))), type(day.replace(K(2017))).__name__,
    repr(date(K(2001), K(1), K(31)) + timedelta(K(29))), repr(date(K(2000), K(12), K(31)) + timedelta(K(1))),
]

comparisons = [
    d == date(K(2000), K(2), K(29)), d != first, d < last, last > d, first <= first, d >= last,
    d == K(1), d != K(1), sorted([last, d, first]), d == datetime(K(2000), K(2), K(29)), d != datetime(K(2000), K(2), K(29)),
    date.__eq__(d, datetime(K(2000), K(2), K(29))), date.__lt__(d, Stamp()), d == Stamp(),
    hash(d) == hash(date(K(2000), K(2), K(29))), hash(d), hash(day) == hash(date(K(2016), K(1), K(3))),
    {d: 1}[date(K(2000), K(2), K(29))],
]

state = [
    d.__reduce__(), day.__reduce__(), repr(date(*d.__reduce__()[1])), repr(date(K('\x07\xd0\x02\x1d'))),
    repr(date(K('\x00\x00\x01\x00'))), repr(Day(K('\x07\xd0\x01\x01'))), repr(date.__new__(Day, K(2000), K(1), K(1))),
]

errors = [error(action) for action in (
    lambda: date(),
    lambda: date(K(1), K(2)),
    lambda: date(K(1), K(2), K(3), K(4)),
    lambda: date(K(0), K(1), K(1)),
    lambda: date(K(10000), K(1), K(1)),
    lambda: date(K(2000), K(13), K(1)),
    lambda: date(K(2001), K(2), K(29)),
    lambda: date(K(2000), K(1), K(0)),
    lambda: date(K(2000.0), K(1), K(1)),
    lambda: date(K('2000'), K(1), K(1)),
    lambda: date(year=K(2000), month=K(1), dy=K(1)),
    lambda: date(K(2000), K(1), K(1), year=K(2000)),
    lambda: date(K('\x07\xd0\x0d\x01')),
    lambda: date.fromordinal(K(0)),
    lambda: date.fromordinal(K(3652060)),
    lambda: date.fromordinal(K(1.5)),
    lambda: date.fromordinal(),
    lambda: date.fromordinal(ordinal=K(5)),
    lambda: last + timedelta(K(1)),
    lambda: first - timedelta(K(1)),
    lambda: d + K(1),
    lambda: d - K(1),
    lambda: d - datetime(K(2000), K(1), K(1)),
    lambda: d < K(1),
    lambda: d < datetime(K(2000), K(1), K(1)),
    lambda: d.replace(K(1), K(2), K(3), K(4)),
    lambda: d.replace(month=K(13)),
    lambda: d.isoformat(K(1)),
    lambda: d.strftime(),
    lambda: d.strftime(K(1)),
    lambda: d.strftime(K('%')),
    lambda: d.strftime(K('%Y%')),
    lambda: date(K(1899), K(12), K(31)).strftime(K('%Y')),
    lambda: format(d, K(1)),
    lambda: d.__format__(),
    lambda: date.today(K(1)),
    lambda: date.fromtimestamp(K('x')),
    lambda: date.fromtimestamp(),
    lambda: setattr(d, 'year', 1),
    lambda: date.isoformat(K(1)),
    lambda: date.year.__get__(K(1)),
    lambda: date.__new__(timedelta, K(1), K(1), K(1)),
)]

RESULT = (basics, arithmetic, comparisons, state, errors, date.__module__, repr(date), repr(type(d.year)))
