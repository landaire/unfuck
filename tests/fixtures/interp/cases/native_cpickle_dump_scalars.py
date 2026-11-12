# cPickle.dumps of scalars at every protocol.
import cPickle


def K(x):
    return x


def every(value):
    return [cPickle.dumps(value, protocol) for protocol in (0, 1, 2)]


VALUES = [
    None, True, False,
    K(0), K(1), K(-1), K(255), K(256), K(65535), K(65536), K(-256),
    K(2147483647), K(-2147483648), K(2147483648), K(-2147483649),
    K(9223372036854775807), K(-9223372036854775808),
    K(0L), K(1L), K(-1L), K(127L), K(128L), K(255L), K(-128L), K(-129L), K(-32768L),
    K(9223372036854775808L), K(-9223372036854775809L), K(2 ** 2040), K(-(2 ** 2047)), K(2 ** 2048),
    K(0.0), K(-0.0), K(1.0), K(0.1), K(1e22), K(-2.5e-300), K(1.0 / 3), float('inf'), float('-inf'),
    K(''), K('a'), K('ab'), K("it's"), K('"q"'), K('\x00\xff\n\\'), K('x' * 255), K('y' * 256),
    K(u''), K(u'a'), K(u'ab'), K(u'\xe9\u20ac'), K(u'back\\slash\nnew'), K(u'\x00\x7f\x80\xff\u0100'),
]

RESULT = [every(value) for value in VALUES]
RESULT.append(cPickle.dumps(K(1), -1))
RESULT.append(cPickle.dumps(K(1), protocol=1))
RESULT.append(len(cPickle.dumps('z' * 70000, 1)))
# The sign of float('nan') is a property of float(), not of cPickle.
RESULT.append(cPickle.dumps(float('nan'), 0).lower())
