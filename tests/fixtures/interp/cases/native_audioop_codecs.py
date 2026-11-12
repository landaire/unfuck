import audioop as a
import hashlib
import struct


def digest(data):
    return hashlib.md5(data).hexdigest()


class Lcg(object):
    def __init__(self, seed):
        self.state = seed

    def next(self, bound):
        # int() keeps results plain ints where C long is 32 bits.
        self.state = int((self.state * 1103515245 + 12345) & 0x7FFFFFFF)
        return (self.state >> 8) % bound

    def sample(self, width):
        # Mostly 16-bit audio levels, with some full-scale values.
        bits = 8 * width
        value = (self.next(1 << 16) << 16) | self.next(1 << 16)
        if self.next(4) == 0 or width == 1:
            return (value & ((1 << bits) - 1)) - (1 << (bits - 1))
        return ((value & 0xFFFF) - 0x8000) << (bits - 16)


ALL_16 = struct.pack('<65536h', *range(-32768, 32768))
ALL_8 = ''.join(chr(code) for code in range(256))
ALL_32 = struct.pack('<65536i', *[sample * 65536 + (sample & 0xFFFF) for sample in range(-32768, 32768)])
FORMATS = {1: 'b', 2: 'h', 4: 'i'}

rows = []
for name in ('lin2ulaw', 'lin2alaw'):
    encode = getattr(a, name)
    rows.append((name, 1, digest(encode(ALL_8, 1))))
    rows.append((name, 2, digest(encode(ALL_16, 2))))
    rows.append((name, 4, digest(encode(ALL_32, 4))))

for name in ('ulaw2lin', 'alaw2lin'):
    decode = getattr(a, name)
    for width in (1, 2, 4):
        rows.append((name, width, digest(decode(ALL_8, width))))

lcg = Lcg(20261111)
for width in (1, 2, 4):
    for trial in range(8):
        frames = 1 + lcg.next(300)
        samples = [lcg.sample(width) for _ in range(frames)]
        data = struct.pack('<%d%s' % (frames, FORMATS[width]), *samples)
        state = None if trial == 0 else (lcg.next(65536) - 32768, lcg.next(89))
        encoded, encoded_state = a.lin2adpcm(data, width, state)
        codes = ''.join(chr(lcg.next(256)) for _ in range(frames))
        decoded, decoded_state = a.adpcm2lin(codes, width, state)
        rows.append(('adpcm', width, trial, state, digest(encoded), encoded_state, digest(decoded), decoded_state))

RESULT = rows
