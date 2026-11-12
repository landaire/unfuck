# Differential test of _struct over pseudo-random formats and values.
import _struct as struct


class Generator(object):
    # A 64-bit xorshift generator, so the case needs no random module.
    def __init__(self, seed):
        self.state = seed & 0xffffffffffffffff or 1

    def next(self):
        x = self.state
        x ^= (x << 13) & 0xffffffffffffffff
        x ^= x >> 7
        x ^= (x << 17) & 0xffffffffffffffff
        self.state = x
        return x

    def below(self, bound):
        return self.next() % bound

    def pick(self, items):
        return items[self.below(len(items))]


def attempt(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as error:
        return (type(error).__name__, error.args)


rng = Generator(0x9e3779b97f4a7c15)

ORDERS = ['', '@', '=', '<', '>', '!']
CODES = 'xcbB?hHiIlLqQfdsp'
EDGES = [0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32768, -32769, 65535, 65536,
         2 ** 31 - 1, 2 ** 31, -2 ** 31, -2 ** 31 - 1, 2 ** 32 - 1, 2 ** 32, 2 ** 63 - 1, 2 ** 63,
         -2 ** 63, -2 ** 63 - 1, 2 ** 64 - 1, 2 ** 64, True, False, 5L]
FLOATS = [0.0, -0.0, 1.5, -2.25, 1e300, -1e300, 3.4028234663852886e38, 3.4028235677973366e38,
          1e-45, 1e-320, float('inf'), -float('inf'), 7, 2 ** 70, 0.1]


def value_for(code):
    if code == 'c':
        return rng.pick(['a', '\x00', '\xff', 'ab', '', 5])
    if code in 'sp':
        return rng.pick(['', 'a', 'abc', 'abcdefghij', 'x' * 300, u'a', 3])
    if code == '?':
        return rng.pick([0, 1, '', 'a', [], [0], None, 2.5])
    if code in 'fd':
        return rng.pick(FLOATS + [rng.below(2 ** 64) * 1.0 - 2 ** 63, 'x'])
    if rng.below(8) == 0:
        return rng.pick(['x', None, 2.5, -1.5, 1e20])
    if rng.below(3) == 0:
        return rng.pick(EDGES)
    bits = rng.pick([7, 8, 15, 16, 31, 32, 63, 64])
    return rng.below(2 ** bits) - rng.below(2) * 2 ** (bits - 1)


def make_format():
    order = rng.pick(ORDERS)
    parts = []
    for _ in range(rng.below(5) + 1):
        code = rng.pick(CODES)
        count = rng.pick(['', '', '', '0', '1', '2', '3', '7'])
        space = rng.pick(['', '', ' ', '\t'])
        parts.append(space + count + code)
    return order + ''.join(parts)


def values_for(fmt):
    values = []
    count = ''
    body = fmt.lstrip('@=<>!')
    for char in body:
        if char.isdigit():
            count += char
            continue
        if char.isspace():
            continue
        repeat = int(count) if count else 1
        count = ''
        if char == 'x':
            continue
        if char in 'sp':
            values.append(value_for(char))
        else:
            values.extend(value_for(char) for _ in range(repeat))
    return values


results = []
for _ in range(700):
    fmt = make_format()
    size = attempt(struct.calcsize, fmt)
    values = values_for(fmt)
    packed = attempt(struct.pack, fmt, *values)
    if isinstance(packed, str):
        unpacked = attempt(struct.unpack, fmt, packed)
        repacked = attempt(struct.pack, fmt, *unpacked) if isinstance(unpacked, tuple) else None
        results.append((fmt, size, packed, unpacked, repacked == packed))
    else:
        results.append((fmt, size, packed))
    if isinstance(size, int):
        data = ''.join(chr(rng.below(256)) for _ in range(size + 2))
        results.append(attempt(struct.unpack, fmt, data[:size]))
        results.append(attempt(struct.unpack_from, fmt, data, rng.below(4) - 1))
        buffer = bytearray('\xaa' * (size + 3))
        outcome = attempt(struct.pack_into, fmt, buffer, rng.below(5) - 2, *values)
        results.append((outcome, str(buffer)))
        results.append(attempt(struct.pack, fmt, *(values + [1])))
        results.append(attempt(struct.unpack, fmt, data))

BAD = ['z', '<P', '2 i', 'i<', '99999999999999999999', '9223372036854775807sb', 'b4611686018427387903q',
       '384307168202282325b', '100000000000000b', 'i\x00garbage', ' <i', '<<i', '1152921504606846975qz', '9223372036854775801s0q']
for fmt in BAD:
    results.append((fmt, attempt(struct.calcsize, fmt), attempt(lambda: struct.Struct(fmt).size)))

RESULT = results
