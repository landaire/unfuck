class Example(object):
    alpha = 1
    beta = 2

proxy = Example.__dict__
names = sorted(name for name in proxy.keys() if name in ('alpha', 'beta'))
values = (proxy['alpha'], proxy.get('beta'), proxy.get('gamma', 'default'), 'alpha' in proxy, proxy.has_key('beta'), 'gamma' in proxy)
copied = proxy.copy()
copied['alpha'] = 100
items = sorted(item for item in proxy.items() if item[0] in ('alpha', 'beta'))
iterated = sorted(name for name in proxy if name in ('alpha', 'beta'))
counts = (len(proxy) == len(proxy.keys()), type(copied).__name__, Example.alpha, type(proxy).__name__)
try:
    proxy['missing']
    missing = None
except KeyError as e:
    missing = e.args

RESULT = (names, values, items, iterated, counts, missing, sorted(v for k, v in proxy.iteritems() if k == 'beta'))
