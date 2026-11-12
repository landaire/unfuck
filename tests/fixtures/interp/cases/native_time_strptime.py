# time.strptime and datetime.strptime through _strptime, under the host
# time zone in native_time_strptime.timezone.
import time
from datetime import datetime, date


def K(value):
    return value


def error(action):
    try:
        return repr(action())
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Stamp(datetime):
    pass


zone = (time.tzname, time.timezone, time.altzone, time.daylight)

parsed = [error(lambda: time.strptime(K(text), K(format))) for text, format in [
    ('2001-02-03 04:05:06', '%Y-%m-%d %H:%M:%S'),
    ('Sat Feb  3 04:05:06 2001', '%a %b %d %H:%M:%S %Y'),
    ('03/02/01', '%d/%m/%y'),
    ('69', '%y'),
    ('68', '%y'),
    ('12 AM', '%I %p'),
    ('12 pm', '%I %p'),
    ('Thursday 1 January', '%A %d %B'),
    ('2004 60', '%Y %j'),
    ('2004 10 1', '%Y %U %w'),
    ('2004 10 1', '%Y %W %w'),
    ('EST', '%Z'),
    ('edt', '%Z'),
    ('utc', '%Z'),
    ('100%', '%d%%'),
    ('  7   8', '%H %M'),
    ('2001', '%Y %m'),
    ('2001 x', '%Y'),
    ('xyz', '%Q'),
    ('1', '%'),
    ('31 2', '%d %m'),
    ('2001-02-03', '%Y-%m-%d'),
]]

converted = [
    repr(datetime.strptime(K('2001-02-03 04:05:06.7'), K('%Y-%m-%d %H:%M:%S.%f'))),
    repr(datetime.strptime(K('Mar 5 2010 1:02:03 PM'), K('%b %d %Y %I:%M:%S %p'))),
    repr(Stamp.strptime(K('12'), K('%H'))),
    repr(datetime.strptime(K('000123'), K('%f'))),
    error(lambda: datetime.strptime(K('2001'), K('%Y %H'))),
    error(lambda: datetime.strptime(K('1234567'), K('%f'))),
    error(lambda: time.strptime(K(1))),
    error(lambda: time.strptime()),
    error(lambda: time.strptime(K('1'), K('%d'), K('x'))),
    error(lambda: time.strptime(K('1'), format=K('%d'))),
    repr(time.strptime(K('Mon Jan  1 00:00:00 2001'))),
]

formatted = [
    time.strftime(K('%Z'), (2001, 1, 1, 0, 0, 0, 0, 1, 0)),
    time.strftime(K('%Z'), (2001, 7, 1, 0, 0, 0, 6, 182, 1)),
    time.strftime(K('%z'), (2001, 1, 1, 0, 0, 0, 0, 1, 0)),
    time.strftime(K('%z'), (2001, 7, 1, 0, 0, 0, 6, 182, 1)),
]

RESULT = (zone, parsed, converted, formatted)
