import operator as o

def err(f, *a):
    try:
        return ('ok', f(*a))
    except Exception as e:
        return (type(e).__name__, e.args)

class G(object):
    def __getitem__(self, i):
        return i * 10
class S(G):
    def __len__(self):
        return 10
    def __getslice__(self, i, j):
        return ('slice', i, j)
class Old:
    pass
class OldSeq:
    def __getitem__(self, i):
        return i
class N(object):
    def __int__(self):
        return 2

d = {'a': 1}
o.setitem(d, 'b', 2)
o.__setitem__(d, 'c', 3)
o.delitem(d, 'a')
lst = [0, 1, 2, 3, 4, 5]
ir = [1]
ir2 = o.irepeat(ir, 3)
ic = [1]
ic2 = o.iconcat(ic, (2,))
RESULT = (
    o.concat([1], [2]), o.__concat__('a', 'b'), o.concat((1,), (2,)),
    o.repeat('ab', 3), o.__repeat__([0], 2), o.repeat((1,), N()),
    ir2 is ir, ir, ic2 is ic, ic,
    o.contains([1, 2], 2), o.__contains__('abc', 'd'), o.sequenceIncludes((1,), 1),
    o.indexOf([5, 6, 7, 6], 6), o.countOf([1, 2, 1, 1], 1), o.countOf('banana', 'a'),
    o.getitem([1, 2, 3], -1), o.__getitem__({'k': 'v'}, 'k'),
    o.getslice(S(), 1, 2), o.__getslice__(S(), -4, 3),
    sorted([(k, d[k]) for k in d]), lst,
    [o.isNumberType(v) for v in (1, 1L, 1.0, True, 'a', N(), Old(), None, [])],
    [o.isSequenceType(v) for v in ('a', u'a', [], (), {}, G(), S(), Old(), OldSeq(), 1)],
    [o.isMappingType(v) for v in ('a', [], (), {}, G(), S(), Old(), OldSeq(), 1)],
    o._compare_digest('abc', 'abc'), o._compare_digest('abc', 'abd'), o._compare_digest(u'x', u'x'),
    o._compare_digest('a', 'ab'),
    err(o.concat, 1, 2), err(o.repeat, 1, 2), err(o.repeat, [1], 'a'),
    err(o.repeat, [1], 1.5), err(o.repeat, [1]), err(o.irepeat, 1, 2), err(o.iconcat, 1, [1]),
    err(o.indexOf, [1], 2), err(o.countOf, 1, 2), err(o.indexOf, 3, 1),
    err(o.getslice, S(), 'a', 2), err(o.getslice, S(), 1.0, 2), err(o.getslice, S(), 1), err(o.getslice, S(), N(), 2),
    err(o.getitem, [1], 5), err(o.setitem, (1,), 0, 2), err(o.delitem, {}, 'x'),
    err(o._compare_digest, 1, 1), err(o._compare_digest, 'a', 1), err(o._compare_digest, u'a', 'a'),
)
