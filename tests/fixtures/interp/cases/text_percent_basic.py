K = lambda value: value
INF = 1e300 * 1e300
NAN = INF - INF
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class R(object):
    def __repr__(self):
        return 'R()'
    def __str__(self):
        return 'r-str'
RESULT = (
    K('%s') % 'x', K('%s') % (1,), K('%s %s') % (1, 2), K('%r') % 'x', K('%r') % (u'x',), K('%s|%r') % (R(), R()), K('%d') % 5, K('%i') % -5, K('%%') % (), K('100%%') % (),
    K('%s') % ((1, 2),), K('%s') % [1, 2], K('%s') % None, K('%s') % 5L, K('%d') % 5L, K('%d') % (10**20), K('%d') % 3.9, K('%d') % -3.9, K('%d') % True, K('%s') % True,
    K('%d') % 1e20, K('abc') % (), K('abc') % {}, K('abc') % [],
    err(lambda: K('abc') % 5), err(lambda: K('%s %s') % (1,)), err(lambda: K('%s') % (1, 2)), err(lambda: K('%d') % 'x'), err(lambda: K('%d') % None),
    err(lambda: K('%f') % 'x'), err(lambda: K('%d') % NAN), err(lambda: K('%d') % INF), err(lambda: K('abc') % 'x'),
    err(lambda: K(u'abc') % []), K(u'%s') % 1, K(u'%r') % 'a', K('%5%') % (), K('%-5%|') % (),
)
