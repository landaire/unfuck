from itertools import groupby, tee, chain

def err(f):
    try:
        f()
    except Exception as e:
        return (type(e).__name__, e.args)
    return None

groups = [(k, [x for x in g]) for k, g in groupby('aaabbcaa')]
keyed = [(k, [x for x in g]) for k, g in groupby([1, 3, 2, 4, 5, 7], key=lambda x: x % 2)]
gb = groupby('aabbbc')
k1, g1 = gb.next()
k2, g2 = gb.next()
stale = [x for x in g1]
current = [x for x in g2]
k3, g3 = gb.next()
partial = g3.next()
gb2 = groupby('xxyy')
ka, ga = gb2.next()
first_of_a = ga.next()
kb, gb_ = gb2.next()
rest_b = [x for x in gb_]
rest_a = [x for x in ga]
end = err(gb2.next)
empty = [k for k, g in groupby([])]
grouper_type = type(g1).__name__

a, b = tee(iter([1, 2, 3, 4]))
a_first = [a.next(), a.next()]
b_all = [x for x in b]
a_rest = [x for x in a]
t = tee('xyz', 3)
t_len = len(t)
t0 = t[0].next()
c = t[0].__copy__()
copied = ([x for x in c], [x for x in t[0]], [x for x in t[1]])
zero = tee([1], 0)

pulls = []
def gen():
    for i in range(3):
        global pulls
        pulls = pulls + [i]
        yield i
p, q = tee(gen())
order = (p.next(), len(pulls))
q_first = q.next()
pulls_after = len(pulls)
tt = tee(p)
same = tt[0] is p
tee_type = type(p).__name__
nested = tee(p, 2)
nested_vals = ([x for x in nested[0]], [x for x in nested[1]])

errors = [
    err(lambda: tee([1], -1)),
    err(lambda: tee([1], n=2)),
    err(lambda: tee([1], 2, 3)),
    err(lambda: tee()),
    err(lambda: tee([1], 2.0)),
    err(lambda: tee([1], 'a')),
    err(lambda: tee(1)),
    err(lambda: groupby()),
    err(lambda: groupby([1], 2, 3)),
    err(lambda: groupby(5)),
    err(lambda: [k for k, g in groupby([1, 2], key=lambda x: 1 // (x - 2))]),
]
RESULT = (groups, keyed, k1, k2, stale, current, k3, partial, ka, first_of_a, kb, rest_b, rest_a, end, empty, grouper_type, a_first, b_all, a_rest, t_len, t0, copied, zero, order, q_first, pulls_after, same, tee_type, nested_vals, errors)
