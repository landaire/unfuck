K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class S(str):
    def __str__(self):
        return 'S-str'
class T(str):
    pass
class V(unicode):
    def __unicode__(self):
        return u'V-uni'
s = S('Hello')
t = T('a,b')
v = V(u'xy')
RESULT = (
    s.upper(), s.split('l'), t.split(','), type(t.split(',')[0]).__name__, K('%s') % s, K('%s') % t, '{}'.format(s), str(s), unicode(s),
    unicode(v), K('%s') % v, v.upper(), len(v), 'l' in s, s.find('l'), str.upper(s), t + t, type(t + t).__name__, t * 2,
    format(s, '>7'), s.__format__(''), repr(s), repr(v), s == 'Hello', 'Hello' == s, v == u'xy', hash(t) == hash('a,b'),
    str.__new__(T, 'q'), type(str.__new__(T, 'q')).__name__, unicode.__new__(V, 'w'), err(unicode.__new__, T),
)
