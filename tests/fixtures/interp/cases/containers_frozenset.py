class FS(frozenset):
    pass

f = frozenset([1, 2, 3])
g = frozenset([3, 2, 1])
same_hash = hash(f) == hash(g)
hashes = (hash(frozenset()), hash(frozenset([1])), hash(frozenset(['a', 'b'])), hash(frozenset(range(10))))
as_key = {f: 'found'}[g]
identity = (frozenset(f) is f, f.copy() is f)
sub = FS([1, 2])
sub_results = (type(sub.copy()).__name__, sub.copy() is sub, type(sub | f).__name__, type(sub.union()).__name__, sub == frozenset([1, 2]), hash(sub) == hash(frozenset([1, 2])))
eq = (f == set([1, 2, 3]), set([1, 2, 3]) == f, f <= set([1, 2, 3, 4]))
nested = frozenset([frozenset([1]), frozenset([2])])
set_of_sets = set([frozenset([1, 2]), frozenset([2, 1])])
names = (repr(frozenset()), repr(frozenset([5])), repr(sub), repr(set()))

RESULT = (same_hash, hashes, as_key, identity, sub_results, eq, len(nested), len(set_of_sets), names, list(frozenset([32, 0, 16, 8])))
