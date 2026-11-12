import zlib

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

c = 'x\x9c+.H\xccUH\xccKQHMO/V(\x1e\xe5Ay\x00\x17\xb2bI'
raw = 'KLJ\x06\x00'
D = zlib.decompress
RESULT = (
    D(c), D(c, 15), D(c, 0), D(c, 47), D(c, 15, 1), D(c + 'junk'), D(raw, -15), D(raw, -8),
    D('x\x9c\x03\x00\x00\x00\x00\x01'), err(D, u'x'),
    err(D, c[:-2]), err(D, c[:5]), err(D, 'xx'), err(D, 'x'), err(D, ''), err(D, raw[:2], -15),
    err(D, c, 7), err(D, c, 99), err(D, c, -16), err(D, c, 16), err(D, c, 9),
    err(D, c[:-1] + '\x00'), err(D, 'x\xbb\x00\x00\x00\x00'), err(D, 'y\x9c'), err(D, '\x8a\x0c'),
    err(D, 5), err(D, c, 1.5), err(D, c, 15, 'a'), err(D), err(D, c, 15, 1, 1),
)
