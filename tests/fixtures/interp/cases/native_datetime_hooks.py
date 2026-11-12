# Calls datetime makes into Python code: tz.fromutc for now(tz), whose
# result is the only observable part of the unknown current time, and the
# result shapes of _strptime._strptime, replaced here by a stand-in module.
import sys
import time as _time
from datetime import date, datetime, timedelta, tzinfo


def K(value):
    return value


def error(action):
    try:
        return repr(action())
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


class Stamp(datetime):
    pass


class Probe(tzinfo):
    def __init__(self):
        self.seen = []

    def fromutc(self, dt):
        self.seen.append((dt.tzinfo is self, isinstance(dt, datetime), type(dt).__name__))
        return 'converted'


class Fixed(tzinfo):
    def utcoffset(self, dt):
        return timedelta(hours=1)

    def dst(self, dt):
        return timedelta(0)

    def __repr__(self):
        return 'Fixed()'


class Items(object):
    def __init__(self, *items):
        self.items = items

    def __len__(self):
        return len(self.items)

    def __getitem__(self, index):
        return self.items[index]


class Broken(Items):
    def __getitem__(self, index):
        raise KeyError(index)


class Stand(object):
    # datetime keeps the first _strptime it imports for the rest of the
    # process; once this case is done, it passes calls to the real module.
    active = True
    result = None
    calls = []

    def _strptime(self, string, format):
        if not Stand.active:
            return __import__('_strptime')._strptime(string, format)
        Stand.calls.append((string, format))
        return Stand.result


class Recorder(datetime):
    # Constructors of the current or local time call cls(...) with fields
    # the host determines; only the call's shape is observable.
    calls = []

    def __new__(cls, *args):
        Recorder.calls.append((len(args), type(args[-1]).__name__))
        return datetime.__new__(cls, *args)

    def __init__(self, *args):
        Recorder.calls.append('init')


class Day(date):
    calls = []

    def __new__(cls, *args):
        Day.calls.append(len(args))
        return date.__new__(cls, *args)


probe = Probe()
now = [datetime.now(probe), Stamp.now(tz=probe), probe.seen, error(lambda: datetime.now(tzinfo()))]

constructed = [type(value).__name__ for value in (
    Recorder.now(), Recorder.now(probe), Recorder.utcnow(), Recorder.today(), Recorder.fromtimestamp(K(0)),
    Recorder.fromtimestamp(K(86400), probe), Day.today(), Day.fromtimestamp(K(0)),
)] + [repr(Recorder.utcfromtimestamp(K(90061.5))), repr(Recorder.fromtimestamp(K(0), Fixed()))]
constructed += [Recorder.calls, Day.calls, isinstance(Recorder.now(), Recorder)]

fields = (2001, 2, 3, 4, 5, 6)
shapes = [
    (fields, 7),
    [list(fields) + [9, 9], 8],
    Items(Items(*fields), 9),
    (_time.struct_time(fields + (5, 34, -1)), 700000),
    (fields, True),
    ((True,) + fields[1:], 0),
    None,
    (fields,),
    (fields, 0, 0),
    (fields[:5], 0),
    ((2001L,) + fields[1:], 0),
    (fields, 0L),
    (fields, 0.5),
    'ab',
    {0: fields, 1: 0},
    Broken(fields, 0),
    (Broken(*fields), 0),
    ((2001, 13) + fields[2:], 0),
]

saved = sys.modules.get('_strptime')
sys.modules['_strptime'] = Stand()
try:
    parsed = []
    for shape in shapes:
        Stand.result = shape
        parsed.append(error(lambda: datetime.strptime(K('text'), K('format'))))
    Stand.result = (fields, 1)
    parsed.append(error(lambda: Stamp.strptime(K('other'), K('%Y'))))
finally:
    Stand.active = False
    if saved is None:
        del sys.modules['_strptime']
    else:
        sys.modules['_strptime'] = saved

RESULT = (now, constructed, parsed, Stand.calls)
