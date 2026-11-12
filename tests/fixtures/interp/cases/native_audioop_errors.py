import audioop as a

def K(x):
    return x

def err(f, *args, **kwargs):
    try:
        return ('ok', f(*args, **kwargs))
    except Exception as e:
        return (type(e).__name__, e.args)

D = K('abcd')
RESULT = (
    err(a.max, D, 3), err(a.max, 'abc', 2), err(a.max, 'abc', 4), err(a.max, D), err(a.max, D, 2, 3),
    err(a.max, D, size=2), err(a.max, 5, 2), err(a.max, None, 2), err(a.max, D, 2.0), err(a.max, D, 'x'),
    err(a.max, bytearray('ab'), 1), err(a.max, K(u'\xe9'), 1), err(a.max, K(u'ab'), 2),
    err(a.getsample, 'abc', 2, 'x'), err(a.mul, 'abc', 2, 'x'), err(a.tomono, 'abc', 2, 1, 'x'),
    err(a.tostereo, 'abc', 3, 'x', 1), err(a.bias, 'abc', 2, 1.5), err(a.lin2lin, 'abc', 2, None),
    err(a.max, D, 2 ** 31), err(a.max, D, -2 ** 31 - 1), err(a.getsample, D, 2, 2 ** 31),
    err(a.findmax, D, 2 ** 31), err(a.mul, D, 2 ** 31, 1), err(a.ratecv, D, 2, 1, 2 ** 31, 1, None),
    err(a.getsample, D, 2, 2), err(a.getsample, D, 2, -1), err(a.getsample, D, 1, 3),
    err(a.findfit, 'abc', D), err(a.findfit, D, 'abc'), err(a.findfit, 'ab', D), err(a.findfit, D, 7),
    err(a.findfactor, D, 'ab'), err(a.findfactor, 'abc', 'ab'),
    err(a.findmax, D, 3), err(a.findmax, D, -1), err(a.findmax, 'abc', 1),
    err(a.mul, D, 1, 'x'), err(a.mul, D, 1, 1j), err(a.mul, D, 1, 2 ** 2000),
    err(a.tomono, 'abc', 1, 1, 1), err(a.tomono, D, 4, 1, 1), err(a.tomono, 'ab', 1, 1),
    err(a.add, D, 'ab', 1), err(a.add, 'abc', 'abc', 2), err(a.add, D, 3, 1),
    err(a.lin2lin, D, 1, 3), err(a.lin2lin, D, 3, 1),
    err(a.ulaw2lin, D, 3), err(a.alaw2lin, D, 0), err(a.lin2ulaw, 'abc', 2),
    err(a.lin2adpcm, D, 2, 5), err(a.lin2adpcm, D, 2, (1,)), err(a.lin2adpcm, D, 2, (1, 2, 3)),
    err(a.lin2adpcm, D, 2, (40000, 0)), err(a.lin2adpcm, D, 2, (0, 89)), err(a.lin2adpcm, D, 2, (0, -1)),
    err(a.lin2adpcm, D, 2, (1.5, 0)), err(a.adpcm2lin, D, 3, None), err(a.adpcm2lin, D, 2, [0, 0]),
    err(a.ratecv, D, 2, 1, 1, 1), err(a.ratecv, D, 2, 1, 1, 1, None, 1, 1, 1),
    err(a.ratecv, D, 3, 1, 1, 1, None), err(a.ratecv, D, 2, 0, 1, 1, None),
    err(a.ratecv, D, 4, 2 ** 30, 1, 1, None), err(a.ratecv, D, 2, 1, 1, 1, None, 0),
    err(a.ratecv, D, 2, 1, 1, 1, None, 1, -1), err(a.ratecv, 'abc', 2, 1, 1, 1, None),
    err(a.ratecv, D, 2, 1, 0, 1, None), err(a.ratecv, D, 2, 1, 1, -1, None),
    err(a.ratecv, D, 2, 1, 1, 1, (1,)),
    err(a.ratecv, D, 2, 1, 1, 1, (1, [])), err(a.ratecv, D, 2, 1, 1, 1, (1.5, ())),
    err(a.ratecv, D, 2, 1, 1, 1, 5), err(a.ratecv, D, 2, 1, 1, 1, [1, ()]), err(a.ratecv, D, 2, 1, 1, 1, 'ab'),
    err(a.ratecv, D, 2, 1, 1, 1, (1, ())), 
    err(a.ratecv, D, 2, 1, 1, 1, (-1, ((1,),))), err(a.ratecv, D, 2, 1, 1, 1, (-1, (('x', 1),))),
    issubclass(a.error, Exception), a.error.__module__, a.error.__name__, a.max.__doc__, a.__doc__,
)
