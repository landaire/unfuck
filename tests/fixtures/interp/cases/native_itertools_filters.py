from itertools import chain, compress, dropwhile, takewhile, ifilter, ifilterfalse, imap, starmap, izip, izip_longest

def err(f):
    try:
        f()
    except Exception as e:
        return (type(e).__name__, e.args)
    return None

seen = []
def pred(x):
    global seen
    seen = seen + [x]
    return x < 3

shared = iter([1, 2, 3, 4, 5])
taken = [x for x in takewhile(pred, shared)]
rest = [x for x in shared]
dropped = [x for x in dropwhile(lambda x: x < 3, [1, 2, 3, 1, 5])]
chained = [x for x in chain('ab', [], (1, 2), 'c')]
from_it = [x for x in chain.from_iterable(['xy', [3]])]
bad_chain = chain([1], 2, [3])
bad_first = bad_chain.next()
bad_err = err(bad_chain.next)
bad_after = [x for x in bad_chain]
comp = [x for x in compress('abcdef', [1, 0, 1, 0, 1])]
comp_kw = [x for x in compress(selectors=[0, 1], data='xy')]
filt = [x for x in ifilter(lambda x: x % 2, range(8))]
filt_none = [x for x in ifilter(None, [0, 1, '', 'a', None, 2])]
filt_bool = [x for x in ifilter(bool, [0, 3])]
filtf = [x for x in ifilterfalse(lambda x: x % 2, range(8))]
filtf_none = [x for x in ifilterfalse(None, [0, 1, '', 'a', None])]
mapped = [x for x in imap(lambda a, b: a * b, [1, 2, 3], [4, 5])]
mapped_none = [x for x in imap(None, 'abc', [1, 2])]
src_a = iter([1, 2, 3])
src_b = iter([10])
consumed = [x for x in imap(None, src_a, src_b)]
leftover = [x for x in src_a]
star = [x for x in starmap(pow, [(2, 3), [3, 2]])]
zipped = [x for x in izip('abc', [1, 2])]
zip_empty = [x for x in izip()]
zl = [x for x in izip_longest('abc', [1], fillvalue='-')]
zl_default = [x for x in izip_longest([1, 2], [])]
zl_extra = err(lambda: izip_longest([1], [], foo=2, fillvalue=3))

def boom(x):
    raise KeyError(x)

errors = [
    err(lambda: compress([1])),
    err(lambda: compress()),
    err(lambda: compress(1, 2, 3)),
    err(lambda: compress([1], [1], data=[1])),
    err(lambda: [x for x in takewhile(boom, [7])]),
    err(lambda: [x for x in imap(boom, [8])]),
    err(lambda: imap(None)),
    err(lambda: imap(None, 1)),
    err(lambda: izip(1)),
    err(lambda: izip(x=1)),
    err(lambda: izip_longest([1], 2)),
    err(lambda: izip_longest([1], foo=2)),
    err(lambda: chain.from_iterable()),
    err(lambda: chain(x=1)),
    err(lambda: starmap(pow)),
    err(lambda: [x for x in starmap(pow, [2])]),
    err(lambda: dropwhile(None)),
    err(lambda: takewhile(None, [1], 3)),
    err(lambda: ifilter(None)),
    err(lambda: ifilterfalse(None)),
    err(lambda: ifilter(None, 5)),
]
RESULT = (taken, seen, rest, dropped, chained, from_it, bad_first, bad_err, bad_after, comp, comp_kw, filt, filt_none, filt_bool, filtf, filtf_none, mapped, mapped_none, consumed, leftover, star, zipped, zip_empty, zl, zl_default, zl_extra, errors)
