def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

def concat():
    return [1] + (2,)

def multiply():
    return [1] * 1.5

RESULT = [
    err([].pop),
    err([1].pop, 5),
    err([1].pop, 1.5),
    err([1].pop, 'a'),
    err([1].remove, 2),
    err([1].index, 2),
    err([1].index, 'two'),
    err([1].index, 1, 'a'),
    err([].insert, 1),
    err([].append),
    err([].append, 1, 2),
    err([].reverse, 1),
    err(list.append, (), 1),
    err(list.append),
    err(list.__add__, [1], (1,)),
    err(list.__mul__, [1], 1.5),
    err(concat),
    err(multiply),
    err(list, 1),
    err(list, [], []),
    err(hash, []),
    err([].sort, 1, 2, 3, 4),
    err(list.__getitem__, [1], 3),
    err(list.__setitem__, [1], 3, 0),
    err(list.__delitem__, [1], 3),
    err(list.__new__, dict),
]
