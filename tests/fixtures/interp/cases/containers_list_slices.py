def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

l = range(10)
l[2:5] = ['a', 'b']
replaced = list(l)
l[::3] = [0, 0, 0]
extended = list(l)
del l[::2]
deleted_step = list(l)
del l[1:3]
deleted = list(l)
l[len(l):] = [99]
appended = list(l)
l[:0] = [-1, -2]
prepended = list(l)
m = [1, 2, 3, 4, 5]
m[1:4] = m
self_assigned = list(m)
n = [1, 2, 3, 4, 5, 6]
n[::-2] = 'abc'
reverse_extended = n
legacy = [1, 2, 3, 4, 5]
legacy.__setslice__(1, 3, ['x'])
legacy.__delslice__(-5, 1)
legacy_get = ([1, 2, 3].__getslice__(-1, 5), [1, 2, 3].__getslice__(2, 1), (1, 2, 3).__getslice__(1, 100))
slices = (range(10)[::-3], range(10)[8:2:-2], range(10)[-3:], range(10)[100:], range(10)[-100:2], (1, 2, 3, 4)[::2])

def size_mismatch():
    q = range(6)
    q[::2] = [1, 2]

def zero_step():
    return range(3)[::0]

def bad_index():
    return [1]['a']

def assign_out_of_range():
    q = [1]
    q[5] = 0

RESULT = (replaced, extended, deleted_step, deleted, appended, prepended, self_assigned, reverse_extended, legacy, legacy_get, slices, err(size_mismatch), err(zero_step), err(bad_index), err(assign_out_of_range))
