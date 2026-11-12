# time.strftime in the C locale and the datetime strftime methods built on
# it. %Z and %z need the host time zone.
import time
from datetime import date, datetime, time as clock, timedelta, tzinfo


def K(value):
    return value


def error(action):
    try:
        return repr(action())
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Fixed(tzinfo):
    def __init__(self, minutes, name):
        self.offset = timedelta(minutes=minutes)
        self.name = name

    def utcoffset(self, dt):
        return self.offset

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return self.name


PORTABLE = '%a %A %b %B %d %H %I %j %m %M %p %S %U %w %W %y %Y %%'

tuples = [
    (2003, 1, 2, 4, 5, 6, 3, 2, 0),
    (2003, 1, 1, 0, 0, 0, 2, 1, 0),
    (2003, 12, 31, 12, 59, 59, 2, 365, 0),
    (2004, 12, 31, 23, 0, 0, 4, 366, 1),
    (2003, 1, 5, 13, 0, 0, 6, 5, -1),
    (1900, 1, 1, 0, 0, 0, 0, 1, 0),
    (9999, 12, 31, 0, 0, 0, 4, 365, 0),
    (99, 1, 1, 0, 0, 0, 0, 1, 0),
    (0, 1, 1, 0, 0, 0, 0, 1, 0),
    (2003, 0, 0, 0, 0, 0, 9, 0, 0),
    [2003, 7, 4, 15, 30, 0, 4, 185, 0],
    time.struct_time((2010, 6, 15, 8, 9, 10, 1, 166, 0)),
]
formatted = [time.strftime(K(PORTABLE), K(value)) for value in tuples]

plain = [time.strftime(K(text), (2003, 1, 2, 4, 5, 6, 3, 2, 0)) for text in ('', 'plain', '%%%%', '100%%', 'x%Hy%Mz')]

windows = [error(lambda: time.strftime(K(text), (2003, 1, 2, 4, 5, 6, 3, 2, 0))) for text in (
    '%c', '%x', '%X', '%#c', '%#x', '%#d %#j %#H', '%Q', '%E', '%Ec', '%Od', '%5Y', '%', 'a%', '%#',
)]

errors = [error(action) for action in (
    lambda: time.strftime(K('%Y'), (2003, 13, 1, 0, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 32, 0, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 24, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 0, 60, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 0, 0, 62, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 0, 0, 0, -2, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 0, 0, 0, 0, 367, 0)),
    lambda: time.strftime(K('%Y'), (150, 1, 1, 0, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K(1), tuples[0]),
    lambda: time.strftime(),
    lambda: time.strftime(K('%Y'), (2003, 1, 1)),
    lambda: time.strftime(K('%Y'), (2003, 1, 1, 0, 0, 0, 0, 1, 0, 0)),
    lambda: time.strftime(K('%Y'), ('x', 1, 1, 0, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), (2003.5, 1, 1, 0, 0, 0, 0, 1, 0)),
    lambda: time.strftime(K('%Y'), K(5)),
    lambda: time.strftime(K('%Y'), K('abc')),
    lambda: time.strftime(K('%Y'), [2003, 'a', 1, 0, 0, 0, 0, 1, 0]),
    lambda: time.strftime(K('%Y'), (2 ** 40, 1, 1, 0, 0, 0, 0, 1, 0)),
)]

moment = datetime(K(2004), K(2), K(29), K(13), K(5), K(9), K(123))
aware = moment.replace(tzinfo=Fixed(K(-330), 'Mid%Zone'))
methods = [
    date(K(2001), K(2), K(3)).strftime(K('%Y-%m-%d %A %j %U %W')),
    moment.strftime(K('%H:%M:%S.%f %I %p %y')),
    moment.strftime(K('[%z|%Z|%f]')),
    aware.strftime(K('%H:%M %z %Z %%Z')),
    aware.time().strftime(K('%H %f')),
    aware.timetz().strftime(K('%z %Z %f')),
    clock(K(23), K(1), K(2), K(5)).strftime(K('%I:%M:%S %p %f %Y-%m-%d %j')),
    format(date(K(1999), K(12), K(31)), K('%d %B %Y')),
    format(moment, K('%c'.replace('c', 'B'))),
    format(moment, K('%c %x %X')),
    format(clock(K(1)), K('%H')),
    format(moment, K(u'%Y')),
    error(lambda: date(K(1899), K(12), K(31)).strftime(K('%Y'))),
    error(lambda: moment.strftime(K('%'))),
    date(K(1900), K(1), K(1)).strftime(K('%a %U %W')),
]

RESULT = (formatted, plain, windows, errors, methods)
