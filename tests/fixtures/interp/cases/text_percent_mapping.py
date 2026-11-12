K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class M(object):
    def __getitem__(self, key):
        return key.upper()
class Old:
    def __getitem__(self, key):
        return key * 2
d = {'name': 'bob', 'n': 3, 'f': 1.5, 'k(x)': 'paren'}
RESULT = (
    K('%(name)s is %(n)d') % d, K('%(n)05d|%(f).2f') % d, K('%(name)r') % d, K('%(k(x))s') % d, K('%(name)s %(name)s') % d, K('%(n)s%%') % d,
    K('%(abc)s') % M(), K('%(ab)s') % Old(), K(u'%(abc)s') % M(), K(u'%(name)s') % d, K('%s') % d == str(d), K('%(name)s') % {'name': u'\xe9'},
    err(lambda: K('%(name)s') % ('a',)), err(lambda: K('%(missing)s') % d), err(lambda: K('%(name') % d), err(lambda: K('%(name)s %s') % d),
    err(lambda: K('%(n)*d') % d), K('[%(n)-4d]') % d, K('%(name)s %%') % d, err(lambda: K(u'%(x)s') % ['a']), err(lambda: K('%()s') % d),
)
