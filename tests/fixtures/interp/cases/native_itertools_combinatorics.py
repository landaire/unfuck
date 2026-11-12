from itertools import product, permutations, combinations, combinations_with_replacement, count

def err(f):
    try:
        f()
    except Exception as e:
        return (type(e).__name__, e.args)
    return None

prod = [x for x in product('ab', [1, 2, 3])]
prod_rep = [x for x in product([0, 1], repeat=3)]
prod_none = [x for x in product()]
prod_zero = [x for x in product('ab', repeat=0)]
prod_empty = [x for x in product('ab', [])]
perm = [x for x in permutations([1, 2, 3])]
perm2 = [x for x in permutations('abcd', 2)]
perm_float = [x for x in permutations([1, 2, 3], 2.7)]
perm_big = [x for x in permutations([1], 3)]
perm_zero = [x for x in permutations([1, 2], 0)]
comb = [x for x in combinations('abcde', 3)]
comb_zero = [x for x in combinations('ab', 0)]
comb_big = [x for x in combinations('ab', 3)]
cwr = [x for x in combinations_with_replacement('abc', 2)]
cwr_empty = [x for x in combinations_with_replacement('', 2)]
cwr_zero = [x for x in combinations_with_replacement('', 0)]

class Sub(count):
    def double(self):
        return self.next() * 2

s = Sub(10, 5)
sub = (s.next(), s.double(), repr(s), isinstance(s, count), type(s).__name__)

class Iter(permutations):
    pass
sub_perm = [x for x in Iter('ab')]

errors = [
    err(lambda: product([1], repeat=-1)),
    err(lambda: product([1], foo=1)),
    err(lambda: product(1)),
    err(lambda: product([1], repeat=1.5)),
    err(lambda: combinations([1], -1)),
    err(lambda: combinations(1, -1)),
    err(lambda: combinations([1])),
    err(lambda: combinations([1], 1.5)),
    err(lambda: combinations([1], 'a')),
    err(lambda: combinations([1], 2 ** 80)),
    err(lambda: combinations_with_replacement([1], -1)),
    err(lambda: permutations([1], -1)),
    err(lambda: permutations([1], 'a')),
    err(lambda: permutations()),
    err(lambda: permutations([1], 2 ** 80)),
]
RESULT = (prod, prod_rep, prod_none, prod_zero, prod_empty, perm, perm2, perm_float, perm_big, perm_zero, comb, comb_zero, comb_big, cwr, cwr_empty, cwr_zero, sub, sub_perm, errors)
