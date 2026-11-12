d = {'a': 1, 'b': 2, 'c': 3}
got = (d.get('a'), d.get('z'), d.get('z', 'default'))
set_default = (d.setdefault('a', 100), d.setdefault('d'), d.setdefault('e', []))
d['e'].append('appended')
popped = (d.pop('a'), d.pop('zz', 'fallback'), {}.pop([], 'unhashable but empty'))
has = (d.has_key('b'), d.has_key('a'), 'c' in d, 'a' not in d)
order = []
popper = dict.fromkeys(range(0, 64, 8))
while popper:
    order.append(popper.popitem())
it = d.iteritems()
first = it.next()
views = (sorted(d.keys()), sorted(d.values()), len(d))
cleared = dict(d)
cleared.clear()
explicit = (dict.__getitem__(d, 'b'), dict.__contains__(d, 'b'), dict.__len__(d), dict.get(d, 'c'))
dict.__setitem__(d, 'f', 6)
dict.__delitem__(d, 'b')
eq = (d == dict(d), d != {}, dict.__eq__(d, []), dict.__lt__(d, d))

RESULT = (got, set_default, popped, has, order, first, views, cleared, explicit, sorted(d.items()), eq)
