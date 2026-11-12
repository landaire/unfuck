# Copying and reducing datetime objects through their __reduce__ state,
# including tzinfo subclasses that reduce through __getinitargs__.
import copy
from datetime import date, datetime, time, timedelta, tzinfo


def K(value):
    return value


class Fixed(tzinfo):
    def __init__(self, minutes=0, name='UTC'):
        self.offset = timedelta(minutes=minutes)
        self.name = name

    def utcoffset(self, dt):
        return self.offset

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return self.name

    def __getinitargs__(self):
        return (self.offset.days * 1440 + self.offset.seconds // 60, self.name)

    def __repr__(self):
        return 'Fixed(%r)' % self.name


class Stamp(datetime):
    pass


zone = Fixed(K(-90), 'X')
plain = [
    timedelta(K(1), K(2), K(3)), timedelta(K(-5)), date(K(2000), K(2), K(29)), date.max,
    time(K(1), K(2), K(3), K(4)), datetime(K(2001), K(2), K(3), K(4), K(5), K(6), K(7)), datetime.min, time.max,
]
values = plain + [time(K(5), tzinfo=zone), datetime(K(2001), K(2), K(3), K(4), tzinfo=zone), Stamp(K(1999), K(1), K(1)), zone]

round_trips = []
for value in values:
    for protocol in (0, 1, 2):
        reduced = value.__reduce_ex__(protocol)
        restored = reduced[0](*reduced[1])
        if len(reduced) > 2 and reduced[2]:
            restored.__dict__.update(reduced[2])
        round_trips.append((repr(reduced[1]), repr(restored), type(restored).__name__, repr(restored) == repr(value)))

copies = [repr(copy.copy(value)) for value in values]
aware = copy.copy(values[9])

RESULT = (round_trips, copies, aware.utcoffset(), aware.tzinfo.name, aware.tzinfo is zone, [sorted(name for name in dir(cls) if name != '__module__') for cls in (date, datetime, time, timedelta, tzinfo)], [type(vars(cls)[name]).__name__ for cls, name in ((date, 'year'), (time, 'hour'), (timedelta, 'days'), (date, 'max'))])
