import audioop as a
import struct

def K(x):
    return x

def pack(fmt, values):
    return struct.pack('<%d%s' % (len(values), fmt), *values)

V1 = pack('b', [0, 1, -1, 127, -128, 50, -50, 3, 3, -7])
V2 = pack('h', [0, 1, -1, 32767, -32768, 1000, -1000, 12345, 12345, -7])
V4 = pack('i', [0, 1, -1, 2147483647, -2147483648, 100000, -100000, 123456789, 123456789, -7])
DATA = [(K(V1), 1), (K(V2), 2), (K(V4), 4)]
RAMP = K(pack('h', [i * 997 % 4001 - 2000 for i in range(64)]))
SHORT = K(pack('h', [3, -5, 700, 2]))
EMPTY = K('')

rows = []
for data, w in DATA:
    rows.append((
        w,
        [a.getsample(data, w, i) for i in range(len(data) // w)],
        a.max(data, w), a.minmax(data, w), a.avg(data, w), a.rms(data, w),
        a.avgpp(data, w), a.maxpp(data, w), a.cross(data, w),
        a.mul(data, w, 3), a.mul(data, w, 2), a.mul(data, w, -1), a.mul(data, w, K(float('nan'))),
        a.mul(data, w, 0.5), a.mul(data, w, -1.7), a.mul(data, w, 2.5),
        a.tomono(data, w, 2, 1), a.tomono(data, w, 1, -1), a.tomono(data, w, 0.5, -0.25),
        a.tostereo(data, w, 1, -2), a.tostereo(data, w, 0.7, -0.3),
        a.add(data, a.reverse(data, w), w),
        a.bias(data, w, 100), a.bias(data, w, -3000000000 // 2),
        a.reverse(data, w),
        [a.lin2lin(data, w, w2) for w2 in (1, 2, 4)],
        a.lin2ulaw(data, w), a.lin2alaw(data, w),
        a.ulaw2lin(a.lin2ulaw(data, w), w), a.alaw2lin(a.lin2alaw(data, w), w),
        a.lin2adpcm(data, w, None), a.lin2adpcm(data, w, (100, 20)),
        a.adpcm2lin(a.lin2adpcm(data, w, None)[0], w, None),
        a.ratecv(data, w, 1, 8000, 11025, None),
        a.ratecv(data, w, 2, 44100, 22050, None, 3, 1),
        a.ratecv(data, w, 1, 3, 2, (-1, ((5, -5),))),
        a.max(EMPTY, w), a.minmax(EMPTY, w), a.avg(EMPTY, w), a.rms(EMPTY, w), a.cross(EMPTY, w),
        a.ratecv(EMPTY, w, 1, 1, 2, None),
    ))

ALL = K(''.join(chr(i) for i in range(256)))
RESULT = (
    rows,
    a.ulaw2lin(ALL, 2), a.alaw2lin(ALL, 2), a.ulaw2lin(ALL, 1), a.alaw2lin(ALL, 4),
    a.adpcm2lin(ALL, 2, None), a.adpcm2lin(ALL, 1, (-32768, 88)),
    a.lin2ulaw(K(pack('h', range(-32768, 32768, 61))), 2),
    a.lin2alaw(K(pack('h', range(-32768, 32768, 61))), 2),
    a.lin2adpcm(RAMP, 2, None),
    a.findfit(RAMP, SHORT), a.findfit(SHORT, SHORT), a.findfactor(RAMP[:8], SHORT),
    a.findmax(RAMP, 5), a.findmax(RAMP, 0), a.findmax(SHORT, 4),
    a.ratecv(RAMP, 2, 2, 7, 5, None, 1, 7),
    a.ratecv(RAMP, 2, 1, 5, 7, (3, ((1, 2),))),
    a.max(K(pack('i', [-2147483648])), 4), a.rms(K(pack('i', [-2147483648])), 4),
    a.maxpp(K(pack('i', [-2147483648, 2147483647, -2147483648, 0])), 4),
    a.avgpp(K(pack('i', [-2147483648, 2147483647, -2147483648, 2147483647])), 4),
    a.mul(K(u'ab'), 1, 1),
)
