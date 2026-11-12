def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

s = 'abcabcabc'
u = u'abcabcabc'
RESULT = (
    s.find('c'), s.find('c', 3), s.find('c', 3, 5), s.find('c', -4), s.find('c', -4, -2), s.find('z'),
    s.rfind('c'), s.rfind('c', 0, 8), s.rfind('ab', -3), s.find(''), s.find('', 9), s.find('', 10), s.rfind(''), s.rfind('', 2, 5),
    s.find('a', None, None), s.find('a', 1, None), s.find('c', 2, 1),
    s.index('b'), s.rindex('b'), err(s.index, 'z'), err(s.rindex, 'a', 1, 2),
    s.count('a'), s.count('abc'), s.count(''), s.count('', 3), s.count('', 20), s.count('a', 1, -1), 'aaaa'.count('aa'),
    u.find(u'c', 3), u.rfind(u'c'), u.count(u''), u.index(u'b', 2), err(u.index, u'z'),
    s.find(u'b'), s.rfind(u'c'), s.count(u'a'),
    err(s.find), err(s.find, 1), err(u.find, 1), err(s.find, 'a', 'x'), err(s.find, 'a', 1, 2, 3),
    s.find('a', 10**30), s.find('a', -10**30),
)
