# Differential test of binascii over pseudo-random inputs.
import binascii


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

    def text(self, alphabet, limit):
        return ''.join(self.pick(alphabet) for _ in range(self.below(limit + 1)))

    def data(self, limit):
        return ''.join(chr(self.below(256)) for _ in range(self.below(limit + 1)))


def attempt(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as error:
        return (type(error).__name__, error.args)


rng = Generator(0x2545f4914f6cdd1d)
results = []

BASE64 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') + ['='] * 8 + ['\n', ' ', '!', '\xff', '-']
UU = [chr(i) for i in range(32, 97)] + ['\n', '\r', '`', ' ', 'a', '\x00', '\x7f', '\t']
HQX = list('!"#$%&\'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr') + ['\n', '\r', ':', '7', '\x00']
HEX = list('0123456789abcdefABCDEF') + ['g', ' ', 'G']
QP = list('ab .=_\t\r\n\r\n') + ['=', '=', '=4', '=41', '=3d', '=\n', '=\r\n', '=\r', '\xe9', '\x00', '~', 'x' * 30, 'y' * 70, ' ' * 5]
TEXT = list('ab .=_\t') + ['\n', '\r\n', '\r', '\x00', '\x7f', '\xff', '.', '..', 'x' * 30, 'y' * 70, ' ' * 3, '\t\n', ' \r\n']

for _ in range(150):
    data = rng.data(60)
    results.append(('base64', attempt(binascii.b2a_base64, data), attempt(binascii.hexlify, data), attempt(binascii.b2a_hqx, data), attempt(binascii.rlecode_hqx, data)))
    results.append(('uu', attempt(binascii.b2a_uu, data[:rng.below(50)])))
    encoded = binascii.b2a_base64(data)
    results.append(binascii.a2b_base64(encoded) == data)

for _ in range(300):
    results.append(('a2b_base64', attempt(binascii.a2b_base64, rng.text(BASE64, 24))))
    results.append(('a2b_uu', attempt(binascii.a2b_uu, rng.text(UU, 70))))
    line = binascii.b2a_uu(rng.data(45))
    cut = rng.below(len(line) + 1)
    results.append(('a2b_uu cut', attempt(binascii.a2b_uu, line[:cut] + rng.text(UU, 3))))
    results.append(('a2b_hqx', attempt(binascii.a2b_hqx, rng.text(HQX, 20))))
    results.append(('unhexlify', attempt(binascii.unhexlify, rng.text(HEX, 12))))

for _ in range(200):
    runs = ''.join(rng.pick(['a', '\x90', 'b', '\x00']) * rng.below(8) for _ in range(rng.below(8)))
    results.append(('rle', attempt(binascii.rlecode_hqx, runs)))
    results.append(('unrle', attempt(binascii.rledecode_hqx, runs)))
    coded = binascii.rlecode_hqx(runs)
    results.append(binascii.rledecode_hqx(coded) == runs)

SEEDS = [0, 1, -1, 2 ** 31 - 1, -2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 40 + 7, -2 ** 40, 0x12345, 0xffff, 0x10000]
for _ in range(200):
    data = rng.data(40)
    seed = rng.pick(SEEDS) if rng.below(3) else rng.below(2 ** 33) - 2 ** 32
    small = rng.pick([0, 1, -1, 0xffff, 0x10000, 0x12345, -5, 2 ** 31 - 1, -2 ** 31]) if rng.below(2) else rng.below(2 ** 31)
    results.append(('crc', binascii.crc32(data), attempt(binascii.crc32, data, seed), attempt(binascii.crc_hqx, data, small)))

for _ in range(250):
    text = rng.text(TEXT, 14)
    options = {}
    for name in ('quotetabs', 'istext', 'header'):
        if rng.below(2):
            options[name] = rng.below(2)
    encoded = attempt(binascii.b2a_qp, text, **options)
    header = options.get('header', 0)
    results.append(('b2a_qp', options, encoded, attempt(binascii.a2b_qp, encoded, header=header) == text if isinstance(encoded, str) else None))
    results.append(('a2b_qp', attempt(binascii.a2b_qp, rng.text(QP, 10), rng.below(2))))

# Line lengths around the soft break limit, where trailing whitespace
# becomes an escape.
for count in range(72, 79):
    for tail in [' \n', '\t\n', ' ', '  \n', ' \r\n', '=\n', 'a\n']:
        data = 'x' * count + tail
        results.append(('qp-edge', data, binascii.b2a_qp(data), binascii.b2a_qp(data, quotetabs=True), binascii.b2a_qp(data, istext=False), binascii.b2a_qp(data, header=True)))

RESULT = results
