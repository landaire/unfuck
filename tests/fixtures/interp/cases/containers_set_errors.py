def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

def unhashable():
    return set([[1]])

def or_list():
    return set([1]) | [2]

def sub_tuple():
    return set([1]) - (1,)

def changed():
    s = set([1, 2, 3])
    for item in s:
        s.add(item + 10)

def kwargs():
    return set(x=1)

RESULT = [
    err(set([1]).remove, 2),
    err(set([1]).remove, (1, 2)),
    err(set().pop),
    err(unhashable),
    err(set([1]).add, {}),
    err(or_list),
    err(sub_tuple),
    err(set.__cmp__, set(), set()),
    err(set.__cmp__, set(), [1]),
    err(set.__cmp__, set(), frozenset()),
    err(set, 1, 2),
    err(kwargs),
    err(set, 5),
    err(changed),
    err(lambda: frozenset().add(1)),
    err(set.add, frozenset(), 1),
    err(set([1]).union, 5),
    err(hash, set()),
    err(set([1]).symmetric_difference),
    err(set().issubset, 3),
    set([1]) < [1],
    set([1]) == [1],
    set([1]) != [1],
]
