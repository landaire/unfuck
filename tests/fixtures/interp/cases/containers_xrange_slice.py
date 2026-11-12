def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

ranges = (list(xrange(5)), list(xrange(2, 10, 3)), list(xrange(10, 0, -4)), list(xrange(0)), list(xrange(5, 1)), list(xrange(-3, 3)))
lengths = (len(xrange(10)), len(xrange(0, 10, 3)), len(xrange(10, 0, -3)), len(xrange(1, 1)))
items = (xrange(10)[3], xrange(10)[-1], xrange(5, 50, 5)[2], xrange(10, 0, -2)[-1])
reprs = (repr(xrange(5)), repr(xrange(1, 5)), repr(xrange(1, 10, 3)), repr(xrange(10, 0, -3)), repr(xrange(0)))
reversed_ranges = (list(reversed(xrange(5))), list(reversed(xrange(1, 10, 3))), list(reversed(xrange(0))), list(xrange(4).__reversed__()))
contains = (3 in xrange(5), 7 in xrange(5), bool(xrange(0)))
errors = (err(xrange, 1.5), err(xrange, 0, 1, 0), err(xrange), err(xrange, 1, 2, 3, 4), err(xrange, 'a'), err(xrange(3).__getitem__, 3), err(lambda: xrange(5)[1:2]), err(lambda: xrange(5)['a']))
slices = (slice(3), slice(1, 2), slice(1, 2, 3), slice(None, None, -1).indices(5), slice(1, 2).indices(-1), slice(-3, None).indices(10), slice(2, 100, 2).indices(10), slice(None, None, -2).indices(0))
fields = (slice(1, 2, 3).start, slice(1, 2, 3).stop, slice(1, 2, 3).step, slice(5).start, slice(5).stop)
slice_errors = (err(slice), err(slice, 1, 2, 3, 4), err(slice(None, None, 0).indices, 5), err(slice('a').indices, 5), err(hash, slice(1)))

RESULT = (ranges, lengths, items, reprs, reversed_ranges, contains, errors, slices, fields, slice_errors, range(10)[slice(2, 8, 3)])
