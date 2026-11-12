def err(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class WithComplex(object):
    def __complex__(self):
        return 3 + 4j

class WithFloat(object):
    def __float__(self):
        return 2.5

class OldComplex:
    def __complex__(self):
        return 1j

class OldFloat:
    def __float__(self):
        return 1.5

class Sub(complex):
    pass

class SubRepr(complex):
    def __repr__(self):
        return 'SubRepr!'

values = [
    complex(), complex(1), complex(2L), complex(1.5), complex(True), complex(1, 2), complex(1.5, -2.5),
    complex(1j), complex(1j, 1j), complex(1 + 2j, 3 + 4j), complex(real=1, imag=2), complex(imag=3),
    complex('1'), complex('1j'), complex('-1.5+2.5j'), complex(' ( 1-2j ) '), complex('j'), complex('-j'),
    complex('1+j'), complex('1e3-1e-3J'), complex(u'2+3j'), complex('inf'), complex('nan'),
    complex('-infj'), complex('infinity+nanj'),
    complex(WithComplex()), complex(WithFloat()), complex(OldComplex()), complex(OldFloat()),
    complex(WithFloat(), WithFloat()), complex(1, WithFloat()),
]
reprs = [repr(v) for v in values]

errors = [
    err(complex, '1+2'), err(complex, '(1+2j'), err(complex, ''), err(complex, '1j2'), err(complex, 'abc'),
    err(complex, '1', 2), err(complex, 1, '2'), err(complex, None), err(complex, []), err(complex, 1, None),
    err(complex, 1, 2, 3), err(complex, foo=1), err(complex, u'1\x00'),
]

z = 3 - 4j
attributes = (z.real, z.imag, z.conjugate(), z.__getnewargs__(), type(z.real).__name__, type(z).__name__,
              err(setattr, z, 'real', 1), (1j).conjugate(), complex.conjugate(2j))

s = Sub(1, 2)
subclass = (repr(s), type(s).__name__, type(s + 1).__name__, type(-s).__name__, type(+s).__name__,
            repr(SubRepr(1)), str(SubRepr(1)), complex(s) is s, type(complex(s)).__name__, isinstance(s, complex),
            Sub('1+1j') == 1 + 1j, Sub(WithComplex()))
c = complex(1, 2)
identity = (complex(c) is c, (+c) is c, Sub(c) is c, complex(Sub(5)) == 5)

RESULT = (reprs, errors, attributes, subclass, identity)
