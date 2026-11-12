def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

s = 'hello world'
RESULT = (
    s.startswith('hello'), s.startswith('world'), s.startswith('world', 6), s.startswith('wor', 6, 8), s.startswith('wor', 6, 9),
    s.endswith('world'), s.endswith('hello', 0, 5), s.endswith('hell', 0, -7), s.endswith(''), s.startswith(''),
    s.startswith(('x', 'he')), s.startswith(()), s.endswith(('x', 'y')),
    s.startswith('', 11), s.startswith('', 12), s.endswith('', 12), s.endswith('', 5, 3),
    u'abc'.startswith(u'', 3), u'abc'.startswith(u'', 4), u'abc'.endswith(u'', 4), u'abc'.startswith(u'', 2, 1),
    s.startswith(u'hel'), u'abc'.endswith('bc'), s.endswith((u'x', 'world')),
    err(s.startswith, 1), err(u'a'.endswith, 2), err(s.startswith, (1,)), err(u'a'.startswith, (1,)),
    err(s.startswith),
)
