import math
import struct

def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

z = 1 + 2j
conversions = [err(float, z), err(int, z), err(long, z), err(math.sqrt, z), err(round, z), err(math.floor, z),
               err(lambda: '%d' % z), err(lambda: '%x' % z), err(lambda: '%f' % z), err(lambda: '%g' % z),
               err(lambda: '%c' % z), '%s|%r' % (z, z), err(struct.pack, 'd', z), err(struct.pack, 'i', z),
               err(lambda: [1, 2][z]), err(lambda: 'ab' * z), err(range, z), err(chr, z), err(hex, z),
               err(oct, z), err(complex.__int__, z), err(complex.__float__, z), err(complex.__long__, z),
               err(lambda: z.__trunc__()), err(divmod, z, 'x'), err(abs, 'x')]

class Number(object):
    def __init__(self, value):
        self.value = value
    def __complex__(self):
        return complex(self.value, 1)

uses = [bool(0j), bool(1e-300j), not 0j, abs(3 + 4j), abs(-2j), sum([1j] * 3), max([1, 2]),
        isinstance(1j, complex), issubclass(complex, object), type(1j) is complex, complex.__name__,
        repr(complex(Number(2))), [1j] * 2, (1j,) + (2,), {1j: 1}[1j], 1j.real, (2 - 3j).imag,
        sorted(['b', 1j, 'a'], key=lambda v: str(v)), repr(eval(repr(1.5 - 0j)) if False else 0),
        divmod(4 + 0j, 2)[0] if False else 'skipped']
uses = [repr(v) for v in uses]

class Declining(complex):
    def __add__(self, other):
        return NotImplemented
    def __lt__(self, other):
        return NotImplemented

class Converts(complex):
    def __int__(self):
        return 65
    def __float__(self):
        return 7.5

subclasses = [err(lambda: Declining(1, 2) + 2), repr(2 + Declining(1, 2)), repr(Declining(1, 2) + 1j),
              type(Declining(1, 2) < 2).__name__, err(lambda: Declining(1, 2) < 1j), chr(Converts(1, 2)),
              unichr(Converts(1, 2)), len(range(Converts(1, 2))), '%c' % Converts(1, 2), round(Converts(1, 2)),
              err(lambda: pow(2.0, 1j, 5)), err(lambda: pow(1j, 2.0, 5)), err(chr, 1.5), err(chr, 2 ** 70)]
subclasses = [repr(v) for v in subclasses]

RESULT = (conversions, uses, subclasses)
