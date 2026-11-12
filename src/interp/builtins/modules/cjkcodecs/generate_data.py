# Writes data/*.bin, the mapping tables of the interpreter's CJK codecs, by
# probing the codecs of the Python 2.7 that runs this script. Run it under
# the CPython 2.7.12 build the client embeds:
#
#   winpy2712.sh 'Z:\...\cjkcodecs\generate_data.py'
#
# Every table is derived from codec behavior alone: each byte sequence a
# codec accepts is decoded and every code point is encoded. Character sets
# that several codecs share are stored once, and each codec's deviations
# from the composition of shared sets are stored as override tables.
#
# Decoding table (".bin", magic "CJKD"), little-endian:
#   u16 run count, u16 astral count, u16 pair count, u16 removed count
#   runs: u16 first key, u16 length, u32 index of the first value
#   values: u16 BMP code point per key of each run
#   astral: u16 key, u32 code point
#   pairs: u16 key, u16 first code point, u16 second code point
#   removed: u16 key that maps to nothing even where a later table maps it
# Encoding override table (magic "CJKE"):
#   u32 count, then u32 code point, u8 length, 4 bytes (length 0: none)
# Range table (magic "CJKR"):
#   u16 count, then u16 first index, u16 length, u16 first code point

import codecs
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')

STATELESS = ['gb2312', 'gbk', 'gb18030', 'big5', 'cp950', 'big5hkscs', 'shift_jis', 'cp932', 'euc_jp', 'shift_jis_2004',
             'shift_jisx0213', 'euc_jis_2004', 'euc_jisx0213', 'euc_kr', 'cp949', 'johab']
THREE_BYTE = ['euc_jp', 'euc_jis_2004', 'euc_jisx0213']


def item(text):
    """The decoded value of one code: a code point or a pair."""
    if len(text) == 1:
        return ord(text)
    if len(text) == 2 and 0xd800 <= ord(text[0]) < 0xdc00 and 0xdc00 <= ord(text[1]) < 0xe000:
        return 0x10000 + ((ord(text[0]) - 0xd800) << 10) + (ord(text[1]) - 0xdc00)
    if len(text) == 2:
        return (ord(text[0]), ord(text[1]))
    raise ValueError('unexpected decoding %r' % text)


def try_decode(codec, data):
    try:
        return data.decode(codec)
    except UnicodeDecodeError:
        return None


def try_encode(codec, text):
    try:
        return text.encode(codec)
    except UnicodeEncodeError:
        return None


def single_bytes(codec):
    found = {}
    for byte in range(256):
        text = try_decode(codec, chr(byte))
        if text is not None:
            found[byte] = item(text)
    return found


def double_bytes(codec):
    """Two-byte codes: a lead that does not decode alone and a trail."""
    singles = single_bytes(codec)
    found = {}
    for lead in range(256):
        if lead in singles:
            continue
        for trail in range(256):
            text = try_decode(codec, chr(lead) + chr(trail))
            if text:
                found[(lead << 8) | trail] = item(text)
    return found


def triple_bytes(codec, prefix):
    found = {}
    for second in range(256):
        for third in range(256):
            text = try_decode(codec, chr(prefix) + chr(second) + chr(third))
            if text:
                found[(second << 8) | third] = item(text)
    return found


def seven_bit(table):
    """Codes with both bytes in A1-FE, keyed by their 7-bit form."""
    return dict((key - 0x8080, value) for key, value in table.items() if 0xa1 <= key >> 8 <= 0xfe and 0xa1 <= key & 0xff <= 0xfe)


def iso_charset(codec, designation):
    """The 94x94 set a designation selects, keyed by 7-bit code."""
    found = {}
    for first in range(0x21, 0x7f):
        for second in range(0x21, 0x7f):
            prefix = '\x1b' + designation
            text = try_decode(codec, prefix + chr(first) + chr(second))
            if text:
                found[(first << 8) | second] = item(text)
    return found


def sjis_to_jis(key):
    """Plane-1 Shift_JIS code to 7-bit JIS row and cell, or None."""
    lead, trail = key >> 8, key & 0xff
    if not (0x81 <= lead <= 0x9f or 0xe0 <= lead <= 0xef) or not (0x40 <= trail <= 0xfc) or trail == 0x7f:
        return None
    row = (lead - 0x81 if lead < 0xe0 else lead - 0xc1) * 2 + 0x21
    if trail >= 0x9f:
        return ((row + 1) << 8) | (trail - 0x9f + 0x21)
    return (row << 8) | (trail - 0x40 + 0x21 - (1 if trail > 0x7f else 0))


def sjis_plane2(key):
    """JIS X 0213 plane-2 Shift_JIS code to 7-bit row and cell, or None."""
    lead, trail = key >> 8, key & 0xff
    if not 0xf0 <= lead <= 0xfc or not (0x40 <= trail <= 0xfc) or trail == 0x7f:
        return None
    low_rows = {0xf0: 1, 0xf1: 3, 0xf2: 5, 0xf3: 13, 0xf4: 15}
    high_rows = {0xf0: 8, 0xf1: 4, 0xf2: 12, 0xf3: 14, 0xf4: 78}
    if trail >= 0x9f:
        row = high_rows.get(lead, 80 + (lead - 0xf5) * 2)
        return ((row + 0x20) << 8) | (trail - 0x9f + 0x21)
    row = low_rows.get(lead, 79 + (lead - 0xf5) * 2)
    return ((row + 0x20) << 8) | (trail - 0x40 + 0x21 - (1 if trail > 0x7f else 0))


class Layers(object):
    """Lookup through tables in order; each is (table, removed, key map)."""

    def __init__(self, *layers):
        self.layers = layers

    def __call__(self, key):
        for table, removed, convert in self.layers:
            converted = convert(key) if convert else key
            if converted is None:
                continue
            if converted in removed:
                return None
            if converted in table:
                return table[converted]
        return None


def euc(key):
    if 0xa1 <= key >> 8 <= 0xfe and 0xa1 <= key & 0xff <= 0xfe:
        return key - 0x8080
    return None


def difference(actual, model, keys):
    """The entries and removals that turn `model` into `actual`."""
    entries = dict((key, value) for key, value in actual.items() if model(key) != value)
    removed = set(key for key in keys if key not in actual and model(key) is not None)
    return entries, removed


def write_decoding(name, table, removed=()):
    keys = sorted(key for key, value in table.items() if isinstance(value, int) and value < 0x10000)
    runs = []
    for key in keys:
        if runs and runs[-1][0] + runs[-1][1] == key:
            runs[-1][1] += 1
        else:
            runs.append([key, 1])
    astral = sorted((key, value) for key, value in table.items() if isinstance(value, int) and value >= 0x10000)
    pairs = sorted((key, value) for key, value in table.items() if isinstance(value, tuple))
    removed = sorted(removed)
    parts = ['CJKD', struct.pack('<HHHH', len(runs), len(astral), len(pairs), len(removed))]
    index = 0
    for first, length in runs:
        parts.append(struct.pack('<HHI', first, length, index))
        index += length
    for key in keys:
        parts.append(struct.pack('<H', table[key]))
    for key, value in astral:
        parts.append(struct.pack('<HI', key, value))
    for key, (first, second) in pairs:
        parts.append(struct.pack('<HHH', key, first, second))
    for key in removed:
        parts.append(struct.pack('<H', key))
    write_file(name, ''.join(parts))


def write_encoding(name, entries):
    parts = ['CJKE', struct.pack('<I', len(entries))]
    for code_point in sorted(entries):
        data = entries[code_point]
        if data is None:
            data = ''
        assert len(data) <= 4
        parts.append(struct.pack('<IB', code_point, len(data)) + data.ljust(4, '\0'))
    write_file(name, ''.join(parts))


def write_ranges(name, runs):
    parts = ['CJKR', struct.pack('<H', len(runs))]
    for first_index, length, first_code_point in runs:
        parts.append(struct.pack('<HHH', first_index, length, first_code_point))
    write_file(name, ''.join(parts))


def write_file(name, data):
    with open(os.path.join(DATA, name + '.bin'), 'wb') as handle:
        handle.write(data)
    sys.stdout.write('%s: %d bytes\n' % (name, len(data)))


def text_of(code_point):
    if code_point < 0x10000:
        return unichr(code_point)
    code_point -= 0x10000
    return unichr(0xd800 + (code_point >> 10)) + unichr(0xdc00 + (code_point & 0x3ff))


def gb18030_ranges():
    """Runs of four-byte gb18030 codes that map to consecutive BMP code points."""
    runs = []
    for index in range(39420):
        b4 = index % 10
        b3 = index // 10 % 126
        b2 = index // 1260 % 10
        b1 = index // 12600
        text = try_decode('gb18030', chr(0x81 + b1) + chr(0x30 + b2) + chr(0x81 + b3) + chr(0x30 + b4))
        assert text is not None and len(text) == 1
        code_point = ord(text)
        if runs and runs[-1][0] + runs[-1][1] == index and runs[-1][2] + runs[-1][1] == code_point:
            runs[-1][1] += 1
        else:
            runs.append([index, 1, code_point])
    for previous, current in zip(runs, runs[1:]):
        assert previous[2] + previous[1] <= current[2]
    return runs


def gb18030_four(code_point, runs):
    if code_point >= 0x10000:
        index = code_point - 0x10000 + 189000
    else:
        index = None
        for first_index, length, first_code_point in runs:
            if first_code_point <= code_point < first_code_point + length:
                index = first_index + code_point - first_code_point
        if index is None:
            return None
    b4 = index % 10
    b3 = index // 10 % 126
    b2 = index // 1260 % 10
    b1 = index // 12600
    return chr(0x81 + b1) + chr(0x30 + b2) + chr(0x81 + b3) + chr(0x30 + b4)


# Unicode compatibility jamo of the initial, medial, and final positions.
INITIALS = [0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145, 0x3146, 0x3147, 0x3148,
            0x3149, 0x314a, 0x314b, 0x314c, 0x314d, 0x314e]
FINALS = [None, 0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313a, 0x313b, 0x313c, 0x313d, 0x313e,
          0x313f, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145, 0x3146, 0x3147, 0x3148, 0x314a, 0x314b, 0x314c, 0x314d, 0x314e]


def euc_kr_composed(code_point, inverse):
    """The eight-byte KS X 1001 composition of a Hangul syllable."""
    if not 0xac00 <= code_point <= 0xd7a3:
        return None
    index = code_point - 0xac00
    initial, medial, final = index // 588, index // 28 % 21, index % 28
    parts = [inverse[INITIALS[initial]], inverse[0x314f + medial], inverse[FINALS[final]] if FINALS[final] else '\xa4\xd4']
    return '\xa4\xd4' + ''.join(parts)


def first_match(sequences):
    inverse = {}
    pairs = {}
    for data, value in sequences:
        if isinstance(value, tuple):
            pairs.setdefault(value, data)
        else:
            inverse.setdefault(value, data)
    return inverse, pairs


def compute_encoding_overrides(codec, sequences, fallback):
    inverse, pairs = first_match(sequences)
    entries = {}
    for code_point in range(0x110000):
        if 0xd800 <= code_point < 0xe000:
            continue
        expected = inverse.get(code_point)
        if expected is None:
            expected = fallback(code_point, inverse)
        actual = try_encode(codec, text_of(code_point))
        if actual != expected:
            entries[code_point] = actual
    for (first, second), data in pairs.items():
        actual = try_encode(codec, unichr(first) + unichr(second))
        assert actual == data, (codec, first, second, actual, data)
    return entries


def sequences_of(singles, doubles, triples, preferred):
    """Decodable byte sequences in the order the first-match inverse
    visits them: single bytes, two-byte codes, then three-byte codes, those
    with keys in `preferred` first."""
    order = []
    for byte in sorted(singles):
        order.append((chr(byte), singles[byte]))
    for key in sorted(doubles):
        order.append((chr(key >> 8) + chr(key & 0xff), doubles[key]))
    for key in sorted(triples, key=lambda key: (key - 0x8080 not in preferred, key)):
        order.append(('\x8f' + chr(key >> 8) + chr(key & 0xff), triples[key]))
    return order


def no_fallback(code_point, inverse):
    return None


def main():
    if not os.path.isdir(DATA):
        os.makedirs(DATA)

    singles = dict((codec, single_bytes(codec)) for codec in STATELESS)
    doubles = dict((codec, double_bytes(codec)) for codec in STATELESS)
    triples = dict((codec, triple_bytes(codec, 0x8f)) for codec in THREE_BYTE)
    every_key = range(0x10000)

    # Shared character sets.
    gb2312 = seven_bit(doubles['gb2312'])
    ksx1001 = seven_bit(doubles['cp949'])
    jisx0208 = seven_bit(doubles['euc_jp'])
    jisx0212 = dict((key - 0x8080, value) for key, value in triples['euc_jp'].items())
    big5 = doubles['big5']

    plane1_2004 = seven_bit(doubles['euc_jis_2004'])
    plane1_2000 = seven_bit(doubles['euc_jisx0213'])
    jisx0213_1 = dict((key, value) for key, value in plane1_2000.items() if jisx0208.get(key) != value)
    jisx0213_2004 = dict((key, value) for key, value in plane1_2004.items() if plane1_2000.get(key) != value)
    assert all(key in plane1_2004 for key in plane1_2000)
    plane2_2004 = dict((key - 0x8080, value) for key, value in triples['euc_jis_2004'].items())
    jisx0213_2 = dict((key, value) for key, value in plane2_2004.items() if jisx0212.get(key) != value)
    plane2_2000 = dict((key - 0x8080, value) for key, value in triples['euc_jisx0213'].items())

    gbk, gbk_removed = difference(doubles['gbk'], Layers((gb2312, (), euc)), every_key)
    gb18030, gb18030_removed = difference(dict((key, value) for key, value in doubles['gb18030'].items() if not 0x30 <= key & 0xff <= 0x39),
                                          Layers((gbk, gbk_removed, None), (gb2312, (), euc)), every_key)
    cp949, cp949_removed = difference(doubles['cp949'], Layers((ksx1001, (), euc)), every_key)
    cp950, cp950_removed = difference(doubles['cp950'], Layers((big5, (), None)), every_key)
    hkscs, hkscs_removed = difference(doubles['big5hkscs'], Layers((big5, (), None)), every_key)
    cp932, cp932_removed = difference(doubles['cp932'], Layers((jisx0208, (), sjis_to_jis)), every_key)
    assert not gbk_removed and not gb18030_removed and not cp949_removed and not cp950_removed and not cp932_removed

    write_decoding('gb2312', gb2312)
    write_decoding('gbk', gbk)
    write_decoding('gb18030', gb18030)
    write_ranges('gb18030_ranges', gb18030_ranges())
    write_decoding('ksx1001', ksx1001)
    write_decoding('cp949', cp949)
    write_decoding('big5', big5)
    write_decoding('cp950', cp950)
    write_decoding('big5hkscs', hkscs, hkscs_removed)
    write_decoding('jisx0208', jisx0208)
    write_decoding('jisx0212', jisx0212)
    write_decoding('cp932', dict(cp932.items() + [(byte, value) for byte, value in singles['cp932'].items() if value != byte and not 0xa1 <= byte <= 0xdf]))
    write_decoding('jisx0213_1', jisx0213_1)
    write_decoding('jisx0213_2004', jisx0213_2004)
    write_decoding('jisx0213_2', jisx0213_2)

    # Codec-specific deviations from the shared sets.
    plane2_model = Layers((jisx0213_2, (), None), (jisx0212, (), None))
    plane2_2000_entries, plane2_2000_removed = difference(plane2_2000, plane2_model, every_key)
    assert not plane2_2000_removed
    write_decoding('jisx0213_2_2000', plane2_2000_entries)
    assert not difference(plane2_2004, plane2_model, every_key)[0]

    for codec, plane1 in [('shift_jis_2004', (jisx0208, jisx0213_1, jisx0213_2004)), ('shift_jisx0213', (jisx0208, jisx0213_1))]:
        layers = [(table, (), sjis_to_jis) for table in plane1] + [(jisx0213_2, (), sjis_plane2)]
        entries, removed = difference(doubles[codec], Layers(*layers), every_key)
        assert not removed
        entries.update((byte, value) for byte, value in singles[codec].items() if value != byte and not 0xa1 <= byte <= 0xdf)
        write_decoding(codec, entries)

    for codec, final in [('iso2022_jp_2004', 'Q'), ('iso2022_jp_3', 'O')]:
        plane1 = iso_charset(codec, '$(' + final)
        plane1_model = Layers(*[(table, (), None) for table in (jisx0208, jisx0213_1, jisx0213_2004 if final == 'Q' else {})])
        entries, removed = difference(plane1, plane1_model, every_key)
        assert not removed
        plane2 = iso_charset(codec, '$(P')
        assert not any(difference(plane2, Layers((jisx0213_2, (), None)), every_key))
        write_decoding(codec, entries)

    # ISO-2022-JP-2 reaches ISO-8859-7 through a single shift, keyed by
    # the byte after it.
    greek = {}
    for byte in range(0x80):
        text = try_decode('iso2022_jp_2', '\x1b.F\x1bN' + chr(byte))
        if text:
            greek[byte] = item(text)
    write_decoding('iso8859_7', greek)

    # Stateless codecs encode with the first byte sequence that decodes to
    # a code point; these tables list where they do something else.
    gb_runs = gb18030_ranges()
    fallbacks = {
        'gb18030': lambda code_point, inverse: gb18030_four(code_point, gb_runs),
        'euc_kr': euc_kr_composed,
    }
    for codec in STATELESS:
        preferred = jisx0213_2 if codec in ('euc_jis_2004', 'euc_jisx0213') else {}
        sequences = sequences_of(singles[codec], doubles[codec], triples.get(codec, {}), preferred)
        entries = compute_encoding_overrides(codec, sequences, fallbacks.get(codec, no_fallback))
        write_encoding(codec + '_encode', entries)


main()
