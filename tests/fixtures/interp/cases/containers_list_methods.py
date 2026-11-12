l = [3, 1, 2]
l.append(4)
l.extend((5, 6))
l.extend(l)
l.insert(0, 'first')
l.insert(-1, 'before last')
l.insert(100, 'end')
l.insert(-100, 'start')
inserted = list(l)
popped = (l.pop(), l.pop(0), l.pop(-2), l.pop(3))
l.remove(1)
removed = list(l)
counted = ([1, 2, 1, 1.0, True].count(1), [[1], [1]].count([1]))
indexed = ([5, 6, 7, 6].index(6), [5, 6, 7, 6].index(6, 2), [5, 6, 7, 6].index(6, -1), [5, 6, 7, 6].index(5, -10, 10))
r = [1, 2, 3]
r.reverse()
iadd = [1]
iadd += (2, 3)
iadd += 'ab'
imul = [1, 2]
imul *= 3
zero = [1, 2]
zero *= -1
explicit = (list.__add__([1], [2]), list.__mul__([0], 3), list.__rmul__([1], 2), list.__contains__([1, 2], 2), list.__len__([1, 2]), list.__getitem__([1, 2, 3], -1), list.__getitem__([1, 2, 3], slice(None, None, -1)))
cmp_results = (list.__eq__([1], [1]), list.__lt__([1], [2]), list.__eq__([1], (1,)), [1, 2] < [1, 2, 0], [2] > [1, 9])
reinit = [1, 2, 3]
reinit.__init__('xy')
nested = [[]] * 3
nested[0].append(1)

RESULT = (inserted, popped, removed, counted, indexed, r, iadd, imul, zero, explicit, cmp_results, reinit, nested, list(reversed([1, 2, 3])))
