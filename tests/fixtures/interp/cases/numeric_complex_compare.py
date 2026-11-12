def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

a = 1 + 0j
equal = [a == 1, 1 == a, a == 1.0, a == 1L, a == True, a != 1, 2j == 2j, 2j != 2j, 2j == 2, (1 + 1j) == 1,
         complex(2 ** 53 + 1) == 2 ** 53 + 1, complex(2 ** 53) == 2 ** 53 + 1, a == 'x', a != None,
         complex('nan') == complex('nan'), 1j in [1, 1j], [1j] == [1j], (1j, 2) == (1j, 2.0),
         a.__eq__(1), a.__eq__('x'), a.__ne__(2.0), err(a.__lt__, 1), a.__lt__('x')]
equal = [repr(v) for v in equal]

ordering = [err(lambda: 1j < 2j), err(lambda: 1j > 1), err(lambda: 2 <= 1j), err(lambda: 1.5 >= 1j),
            err(lambda: True < 1j), err(lambda: 10 ** 30 < 1j), err(cmp, 1j, 2j), cmp(1j, 1j), err(cmp, 1, 1j),
            err(sorted, [2j, 1j]), err(max, 1j, 2j), err(min, [1, 1j]), 1j < 'a', 'a' > 1j, None < 1j, 1j < None, 1j < [], cmp(1j, 'a'), sorted([1j, 'a']),
            err(complex.__lt__, 1j, 2), err(complex.__ge__, 1j, 1j)]

keys = {1: 'int', 1.0: 'float', 1 + 0j: 'complex', 2j: 'imag'}
hashes = [hash(1 + 0j) == hash(1), hash(2.5 + 0j) == hash(2.5), hash(1j), hash(-1 - 1j), hash(3 + 4j),
          hash(complex(-1, 0)), hash(complex(0, -1)), hash(complex(1e300, 1e-300)), hash(complex('nan')),
          hash(complex('inf', '-inf') if False else complex(float('inf'), float('-inf'))), sorted(keys.values()),
          len(set([1, 1.0, 1 + 0j, 1j, 1j])), keys[1j * 2]]

RESULT = (equal, ordering, hashes)
