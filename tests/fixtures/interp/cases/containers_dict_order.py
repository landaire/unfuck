# Integer keys hash to themselves, so these collide in an 8-slot table.
d = {}
for k in (8, 16, 24, 1, 9, 17):
    d[k] = k * 2
after_inserts = d.keys()
del d[16]
del d[1]
after_deletes = d.keys()
d[32] = 'reuses a dummy'
d[1] = 'back'
d[16] = 'back too'
after_reinsert = d.items()

# Growth past two thirds of the table reinserts in slot order.
grown = {}
for k in (5, 13, 21, 29, 37, 45):
    grown[k] = None
grown_order = list(grown)
for k in (5, 21, 37):
    del grown[k]
grown[53] = None
grown[61] = None
grown_after = list(grown)

# String keys and overwriting an existing key keep its slot.
s = {}
for name in ('alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta'):
    s[name] = len(name)
s['beta'] = 'replaced'
del s['gamma']
s['theta'] = 8
strings = s.items()

mixed = {1: 'int', 1.0: 'float', True: 'bool', 2L: 'long'}
negative = {-1: 'a', -2: 'b', 0: 'c', -8: 'd'}

RESULT = (after_inserts, after_deletes, after_reinsert, grown_order, grown_after, strings, mixed, negative.keys(), list(d.itervalues()))
