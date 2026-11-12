import time
t = time.gmtime(1234567890.7)
epoch = time.gmtime(0)
leap = time.gmtime(951782400)
last = time.gmtime(32535244799)
fields = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, t.tm_wday, t.tm_yday, t.tm_isdst)
built = time.struct_time((2001, 2, 3, 4, 5, 6, 0, 34, -1))
RESULT = (
    repr(epoch), fields, t[0], t[-1], t[2:5], len(t), leap, repr(last),
    type(t).__name__, t == fields, time.gmtime(5L)[5], time.gmtime(True)[5],
    time.gmtime(86399.999)[3:6], repr(built), built.tm_isdst, time.struct_time.n_fields, time.accept2dyear,
)
