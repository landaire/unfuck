records = [('b', 2), ('a', 2), ('c', 1), ('a', 1), ('b', 1), ('c', 2)]
by_number = sorted(records, key=lambda record: record[1])
by_letter_reverse = sorted(records, key=lambda record: record[0], reverse=True)
calls = []
def by_cmp(x, y):
    calls.append(1)
    return cmp(x[1], y[1])
with_cmp = list(records)
with_cmp.sort(by_cmp)
with_both = list(records)
with_both.sort(cmp=lambda x, y: cmp(y, x), key=lambda record: record[0])
stable_reverse = sorted([(1, 'a'), (0, 'b'), (1, 'c'), (0, 'd')], key=lambda pair: pair[0], reverse=True)
mixed = sorted([3, 1.5, 2L, -1, True])
strings = sorted(['b', 'A', 'a', 'B'])
nested = sorted([[2, 1], [1, 2], [1, 1], [2]])
in_place = [5, 2, 8, 1]
result = in_place.sort()
by_positional = [3, 1, 2]
by_positional.sort(None, None, True)

def mutate():
    victim = [3, 2, 1]
    def key(item):
        victim.append(item)
        return item
    try:
        victim.sort(key=key)
    except ValueError as e:
        return (e.args, victim)

def bad_reverse():
    try:
        [1].sort(reverse=None)
    except TypeError as e:
        return e.args

RESULT = (by_number, by_letter_reverse, with_cmp, len(calls) > 0, with_both, stable_reverse, mixed, strings, nested, in_place, result, by_positional, mutate(), bad_reverse())
