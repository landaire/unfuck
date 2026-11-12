d = {'a': 1, 'b': 2, 'c': 3}
keys = d.viewkeys()
items = d.viewitems()
values = d.viewvalues()
before = (len(keys), sorted(keys), 'a' in keys, ('a', 1) in items, ('a', 2) in items, 1 in values)
d['d'] = 4
after = (len(keys), sorted(items), sorted(values))
ops = (sorted(keys & set(['a', 'z'])), sorted(keys | ['z']), sorted(keys - set(['a'])), sorted(keys ^ set(['a', 'q'])), sorted(['a', 'x'] & keys))
compare = (keys == set(['a', 'b', 'c', 'd']), keys != set(), keys < set(['a', 'b', 'c', 'd', 'e']), set(['a']) <= keys, keys == ['a', 'b', 'c', 'd'])
small = {8: 1, 16: 2}
small_repr = (repr(small.viewkeys()), repr(small.viewvalues()), repr(small.viewitems()))
names = (type(keys).__name__, type(values).__name__, type(items).__name__)
order = (list(small.viewkeys()), list(small.viewitems()), keys.__contains__('a'))

RESULT = (before, after, ops, compare, small_repr, names, order)
