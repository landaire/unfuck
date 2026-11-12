# dict.fromkeys sizes the new table from the source's entry count before
# filling it, which decides where colliding keys land.
def keys_of(size):
    return [8 * k for k in range(1, size)] + [1]

sizes = [5, 6, 11, 12, 21, 22, 43, 44]
from_set = [dict.fromkeys(set(keys_of(n))).keys() for n in sizes]
from_frozenset = [dict.fromkeys(frozenset(keys_of(n))).keys() for n in sizes]
from_dict = [dict.fromkeys(dict.fromkeys(keys_of(n))).keys() for n in sizes]

RESULT = (from_set, from_frozenset, from_dict)
