from _struct import pack, unpack


def bits(x):
    return '%016x' % unpack('<Q', pack('<d', x))[0]


def fl(b):
    return unpack('<d', pack('<Q', b))[0]


def show(f):
    try:
        z = f()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)
    if isinstance(z, tuple):
        return ';'.join(bits(p.real) + ',' + bits(p.imag) for p in z)
    return bits(z.real) + ',' + bits(z.imag)


inf = float('inf')
P1, P2, P3, P4 = [fl(0x7ff8000000000000 + n) for n in (1, 2, 3, 4)]
values = [complex(x, y) for x in (-0.0, 1.5, inf, P1) for y in (0.0, 2.0, -inf, P2)]
divisors = [complex(x, y) for x in (0.0, 5.0, -4.0, inf, P3) for y in (0.0, 3.0, 4.0, -inf, P4)]
rows = []
for a in values:
    for b in divisors:
        rows.append(show(lambda: a / b))
        rows.append(show(lambda: divmod(a, b)))
        rows.append(show(lambda: a * b))
        rows.append(show(lambda: a + b))
for a in [complex(x, y) for x in (0.0, 1.5, -2.0, inf, P1, 1e200, 1e-200) for y in (0.0, 0.75, P2, inf, 1e200)]:
    for n in (-3, -1, 0, 1, 2, 3, 7, 64, 100):
        rows.append(show(lambda: a ** n))
    for e in (complex(0, P4), complex(1, inf), complex(P3, 0), complex(0.5, 0), complex(-1, 0.5), complex(101, 0)):
        if a.real == a.real and a.imag == a.imag and e.real == e.real and e.imag == e.imag and e.imag == 0 and e.real != 0.5 and e.real != 101:
            continue
        r = show(lambda: a ** e)
        if 'Error' in r or any(part[:3] in ('7ff', 'fff') for part in r.split(',')):
            rows.append(r)
for r, i in [(-0.0, 5 + 0j), (-0.0, complex(-0.0, 0.0)), (complex(-0.0, 0.0), 0j), (complex(0, P1), P2), (complex(P1, 0), complex(0, P2)), (1, inf + 0j)]:
    rows.append(show(lambda: complex(r, i)))
for s in ['1+-1j', '( 1-2j )', '-J', 'infj', '-nanj', '1e309j', '((1))', '1 +2j']:
    rows.append(show(lambda: complex(s)))
RESULT = rows
