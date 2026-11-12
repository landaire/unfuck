from array import array

def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, str(e))

class Index(object):
    def __int__(self):
        return 7

values = ['x', 'xy', u'x', 1.5, 2 ** 7, -2 ** 7 - 1, 2 ** 8, -1, 2 ** 15, 2 ** 16, 2 ** 31, -2 ** 31 - 1, 2 ** 32, 2 ** 63, -2 ** 63 - 1, 2 ** 64, None, True, 10L, bytearray('q'), Index()]
RESULT = [(code, [err(lambda: array(code, [value]).tolist()) for value in values]) for code in 'cbBuhHiIlLfd']
RESULT += [
    err(array, 'x'), err(array, 'ab'), err(array, 1), array(u'b', [1]), err(array, 'b', 5), err(lambda: array('b', initializer=[1])),
    array('h', '\x01\x00\x02\x00'), err(array, 'h', 'abc'), err(array, 'b', u'ab'), array('u', u'ab'), array('b', (x for x in [1, 2])),
    array('d', (1, 2.5)), array('c', 'ab'), array('B', bytearray('ab')), array('f', [0.1])[0], array('f', [1e300])[0],
    repr(array('i', [1, 2])), repr(array('c', 'ab')), repr(array('u', u'ab')), repr(array('d')), str(array('f', [0.5])),
    [(code, array(code).itemsize, array(code).typecode) for code in 'cbBhHiIlLfd'], array('I', [1])[0], array('L', [2 ** 63])[0],
    array('b', [-1]).tostring(), array('h', [1, -2]).tostring(), array('d', [1.5]).tostring(), array('i', [-1]).tolist(),
]
