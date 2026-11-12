K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    K('%.3s|') % u'abcdef', K('%-5s|') % u'a', K('%5r|') % u'a', K('x%sy%dz') % (u'A', 7), K('%*s%s') % (3, 'a', u'b'), K('%c%s') % (u'\xe9', 'x'),
    K('%s %(k)s') % {'k': 1} if False else 'skip', K('%(k)s %(u)s') % {'k': 'K', 'u': u'U'}, K('%%%s') % u'p', type(K('%%%s') % u'p').__name__,
    err(lambda: K(u'%s') % 'caf\xc3\xa9'), K(u'%s') % 'plain', K(u'%-4d|%+.1f') % (3, 2.25), K(u'%o %X %#x') % (8, 255, 255), K(u'%5.2e') % 12345.678,
    K(u'%(a)s-%(b)r') % {'a': u'\u20ac', 'b': 'b'}, K(u'%s') % ((u'a', 'b'),), K(u'%s') % [u'a'], K('%r') % [u'\xe9'], K('%s') % {1: u'x'},
    K('%s') % 12345678901234567890, K('%r') % 12345678901234567890, K('%r') % 1.5, K('%s') % 1.5, K('%s') % 1e16, K('%r') % 1e16, K('%s') % -0.0,
)
