import cmath
import cPickle
import marshal
import math
import pickle
import struct


def K(value):
    return value


def h(x):
    return struct.pack('<d', x).encode('hex')


def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


inf = float(K('inf'))
nan = float(K('nan'))
negnan = float(K('-nan'))

bits = (
    h(nan), h(negnan), h(float(K(u'nan'))), h(float(K(u'-nan'))),
    h(inf * K(0)), h(K(0) * inf), h(inf - inf), h(inf + -inf), h(inf / inf),
    h(-nan), h(-negnan), h(abs(nan)), h(abs(negnan)), h(+negnan),
    h(nan + K(1)), h(negnan + K(1)), h(nan * K(2)), h(negnan * K(2)),
    h(nan ** K(1)), h(K(2.0) ** nan), h(nan % K(1.0)), h(divmod(inf, K(1.0))[0]),
    h(math.copysign(K(1), nan)), h(math.copysign(K(1), negnan)),
    h(math.copysign(nan, K(-1))), h(math.copysign(negnan, K(1))),
    h(float.fromhex(K('nan'))), h(float.fromhex(K('-nan'))),
    h(marshal.loads(marshal.dumps(nan))), h(marshal.loads(marshal.dumps(negnan))),
    h(pickle.loads(pickle.dumps(nan, 2))), h(cPickle.loads(cPickle.dumps(nan, 2))),
    h(pickle.loads(pickle.dumps(nan, 0))), h(cPickle.loads(cPickle.dumps(negnan, 0))),
    h(struct.unpack('<d', struct.pack('<d', negnan))[0]),
    h(struct.unpack('<f', struct.pack('<f', nan))[0]),
    h(struct.unpack('<f', struct.pack('<f', negnan))[0]),
    h((complex(inf, K(0)) * K(0)).real), h((complex(inf, K(0)) * K(0)).imag),
    h(complex(K('nan')).real), h(complex(K('-nan')).real),
    h(cmath.sqrt(complex(nan, K(0))).real), h(cmath.exp(complex(nan, K(0))).imag),
    h(math.sqrt(nan)), h(math.exp(nan)), h(math.sin(nan)), h(math.fmod(nan, K(1))),
    h(math.ldexp(nan, K(1))), h(math.atan2(nan, K(1))), h(round(nan)), h(round(negnan)),
    h(min(nan, K(1.0))), h(math.floor(nan)), h(float(K('NaN'))), h(float(K(' +nan '))),
)

text = (repr(nan), repr(negnan), str(-nan), nan.hex(), negnan.hex(), '%f' % negnan, '%e' % nan, format(negnan, 'g'))

errors = (
    err(math.sqrt, K(-1)), err(math.fmod, inf, K(1)), err(int, nan), err(long, nan),
    err(pow, K(-1.0), K(0.5)), err(math.sin, inf), err(math.fsum, [inf, -inf]),
    err(nan.as_integer_ratio),
)

RESULT = (bits, text, errors)
