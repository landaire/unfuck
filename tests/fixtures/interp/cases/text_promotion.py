K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    K('abc') + u'd', K(u'a') + 'bc', 'a,b'.split(u','), 'abc'.replace('b', u'x'), 'xax'.strip(u'x'),
    'abc'.find(u'c'), 'abc'.startswith(u'a'), 'abc'.partition(u'b'), u'abc'.split('b'),
    u'a' in 'abc', 'a' in u'abc', 'abc' == u'abc', u'abc' == 'abc', 'abc' < u'abd',
    err(lambda: K('\xe9') + u'a'), err('\xe9'.find, u'a'), err(lambda: u'a' in '\xe9'), '\xe9' == u'\xe9',
    err(lambda: K('a') + 1), err(lambda: K(u'a') + 1), err('a'.__add__, 1), err(u'a'.__add__, 1), 'a'.__add__(u'b'),
    K('ab') * 3, K(u'ab') * 2, K(3) * 'x', K('ab') * -1, 'ab'.__mul__(2), err('a'.__mul__, 1.5),
)
