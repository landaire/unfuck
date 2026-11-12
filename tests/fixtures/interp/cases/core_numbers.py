big = 2 ** 62 * 4
values = [7 / 2, -7 / 2, 7 // -2, -7 % 3, 7 % -3, 2 ** -1, 1 << 70, big, big - big, type(big - big).__name__]
mixed = sorted([3, None, 'b', 1.5, (1,), [2], 'a', u'c', 2L, True])
comparisons = (1 == 1.0, 1 < 1.5, 'a' < u'b', (1, 2) < (1, 3), [1] < (1,), None < 0)
floats = (repr(0.1), str(0.1), repr(1e16), repr(1e-5), str(1.0 / 3), repr(-0.0), 1e300 * 1e10)
RESULT = (values, mixed, comparisons, floats, hash(-1), hash(2 ** 64), hash(0.5), hash('abc'), hash(u'abc'), hash((1, 'a')))
