def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

def mutate_while_iterating():
    d = {1: 1, 2: 2}
    for k in d:
        d[k + 10] = 0

def missing():
    return {}['missing']

def missing_tuple():
    return {}[(1, 2)]

RESULT = [
    err(missing),
    err(missing_tuple),
    err({}.popitem),
    err({}.pop, 'x'),
    err(dict, 1, 2),
    err(dict, [1]),
    err(dict, [(1, 2, 3)]),
    err(dict, 5),
    err({}.update, {}, {}),
    err(dict.fromkeys),
    err({}.get),
    err({}.setdefault, 1, 2, 3),
    err({}.keys, 1),
    err({}.has_key),
    err(dict.__setitem__, {}, [], 1),
    err(hash, {}),
    err(mutate_while_iterating),
    err(dict.get, [], 1),
    err(dict.__new__, list),
    err({}.__delitem__, 'gone'),
]
