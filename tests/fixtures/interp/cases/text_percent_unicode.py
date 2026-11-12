K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class US(object):
    def __str__(self):
        return u'uni-str'
RESULT = (
    K('a%sb') % u'x', K('a%s%sb') % ('y', u'x'), K('%s:%d:%s') % (u'u', 3, 'z'), K('%5s|') % u'ab', K('%c') % u'\xe9', K('x%c') % u'q',
    K('%s') % US(), K(u'%s') % US(), K(u'%s-%s') % ('a', u'b'), K(u'%d %x %.2f') % (5, 255, 1.5), K(u'%r') % u'\xe9', K(u'%5.1s|') % 'abc',
    K(u'%c%c') % (u'\u20ac', 0x263a), K(u'%c') % 'a', K(u'%c') % 66.7, err(lambda: K(u'%c') % 'ab'), err(lambda: K(u'%c') % '\xe9'), err(lambda: K(u'%c') % None),
    err(lambda: K('\xe9%s') % u'x'), err(lambda: K('%s\xe9') % u'x'), err(lambda: K('%s %s') % (u'a',)), err(lambda: K('%s') % (u'a', 1)),
    K('%(a)s %(b)s') % {'a': 'x', 'b': u'y'}, K('%*s|') % (4, u'ab'), type(K('%s') % 'a').__name__, type(K('%s') % u'a').__name__,
    err(lambda: K(u'%y') % 1), err(lambda: K(u'%\u20ac') % 1),
)
