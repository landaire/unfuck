# Differential test of the charmap codec over pseudo-random tables.
import _codecs
import codecs


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


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, error.args)


calls = []


class Recording(object):
    # A mapping that records each key it is asked for.
    def __init__(self, entries):
        self.entries = entries

    def __getitem__(self, key):
        calls.append(key)
        return self.entries[key]


def substitute(error):
    calls.append(('handler', error.start, error.end))
    return (u'?' * (error.end - error.start), error.end)


codecs.register_error('charmap.random', substitute)

rng = Generator(0xd1b54a32d192ed03)
HANDLERS = ['strict', 'replace', 'ignore', 'xmlcharrefreplace', 'backslashreplace', 'charmap.random']


def make_unit(spread):
    choice = rng.below(10)
    if choice == 0:
        return 0xfffe
    if choice == 1:
        return rng.below(128)
    return rng.below(spread) % 0xd800


def make_table():
    spread = rng.pick([256, 1024, 4096, 40000, 0xd800])
    units = [make_unit(spread) for _ in range(256)]
    if rng.below(4):
        units[0] = 0
        for index in range(1, 256):
            if units[index] == 0:
                units[index] = 0xfffe
    if rng.below(5) == 0:
        units[rng.below(255) + 1] = units[rng.below(256)]
    return u''.join(unichr(unit) for unit in units)


def block_table(blocks):
    units = [0] + [index * 128 + 5 for index in range(1, blocks + 1)]
    units += [0xfffe] * (256 - len(units))
    return u''.join(unichr(unit) for unit in units)


results = []
for blocks in (253, 254, 255):
    built = _codecs.charmap_build(block_table(blocks))
    results.append((blocks, type(built).__name__, built.size() if type(built) is not dict else len(built)))

for _ in range(60):
    table = make_table()
    built = _codecs.charmap_build(table)
    if type(built) is dict:
        summary = ('dict', len(built), sorted(built.items())[:8])
    else:
        summary = (type(built).__name__, built.size())
    pool = [table[rng.below(256)] for _ in range(12)] + [u'\x00', u'a', u'?', u'&', u'#', u';', u'1', u'\u1234', u'\x80', u'\\', u'x']
    texts = [u''.join(rng.pick(pool) for _ in range(rng.below(10))) for _ in range(6)]
    data = [''.join(chr(rng.below(256)) for _ in range(rng.below(10))) for _ in range(4)]
    encoded = [attempt(_codecs.charmap_encode, text, rng.pick(HANDLERS), built) for text in texts]
    decoded = [attempt(_codecs.charmap_decode, chunk, rng.pick(['strict', 'replace', 'ignore', 'charmap.random']), table) for chunk in data]
    roundtrip = [attempt(_codecs.charmap_encode, value[0], 'strict', built) for value in decoded if isinstance(value[0], unicode)]
    results.append((summary, encoded, decoded, roundtrip))

VALUES = [None, 0, 65, 255, 256, -1, 'x', 'xy', '', u'x', u'', u'xy', u'\ufffe', 0xfffe, 0x10ffff, 0x110000, 2.5, 3L, True]
for _ in range(80):
    entries = {}
    for key in range(0x3f, 0x50):
        if rng.below(3):
            entries[key] = rng.pick(VALUES)
    recording = Recording(entries)
    text = u''.join(unichr(0x3f + rng.below(18)) for _ in range(rng.below(8)))
    data = ''.join(chr(0x3f + rng.below(18)) for _ in range(rng.below(8)))
    del calls[:]
    encoded = attempt(_codecs.charmap_encode, text, rng.pick(HANDLERS), recording)
    encode_calls = list(calls)
    del calls[:]
    decoded = attempt(_codecs.charmap_decode, data, rng.pick(['strict', 'replace', 'ignore', 'charmap.random']), recording)
    results.append((text, encoded, encode_calls, data, decoded, list(calls)))

sample = _codecs.charmap_build(block_table(3))
results.append((type(sample).__name__, attempt(type(sample)), attempt(sample.size, 1), attempt(type(sample).size, 5),
                attempt(_codecs.charmap_build, u'abc'), attempt(_codecs.charmap_build, 'x' * 256), attempt(_codecs.charmap_decode, 'a', 'strict', sample),
                attempt(_codecs.charmap_encode, u'a', 'strict', 5), attempt(_codecs.charmap_decode, 'a', 'strict', [])))

RESULT = results


def second_fails(error):
    calls.append(('second', error.start, error.end))
    return (u'\u9999' if len(calls) == 2 else u'a', error.end)


codecs.register_error('charmap.second', second_fails)
del calls[:]
try:
    _codecs.charmap_encode(u'a&a%%a#', 'charmap.second', {0x61: 'A'})
except UnicodeEncodeError as error:
    RESULT.append((error.args, error.start, error.end, list(calls)))
RESULT.append(attempt(_codecs.charmap_encode, u'aa&\u0100a%%a', 'xmlcharrefreplace', _codecs.charmap_build(u'\x00a&#;38' + u'\ufffe' * 249)))
