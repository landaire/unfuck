# Writes database.bin, the character data of the unicodedata module, by
# querying the module of the Windows CPython 2.7.12 build for every code
# point under its current database and under ucd_3_2_0. Characters outside
# the BMP are queried as surrogate pairs, which that narrow build accepts.
#
#   winpy2712.sh generate_database.py database.bin
#
# Layout (little-endian):
#   b"UCDB" magic
#   four string lists (categories, bidirectional classes, east asian widths,
#     decomposition tags): u8 count, then u8 length and bytes per string
#   numeric values: u16 count, then f64 each
#   records: u16 count, then 9 bytes each: category, bidirectional,
#     combining, width, flags, decimal, digit (0xff: none), numeric (u16,
#     0xffff: none). Flags: bit 0 mirrored, bit 1 named, bits 2-5 whether
#     NFC, NFD, NFKC, NFKD return a single-character input unchanged.
#   two run lists, current then 3.2.0: u32 count, then u32 first code point
#     and u16 record per run
#   two decomposition lists, current then the 3.2.0 entries that differ:
#     u32 count, then u32 code point, u8 tag (0xff: none), u8 length and
#     u32 code points
#   two composition exclusion lists, current then 3.2.0: u32 count, then
#     u32 code points of characters whose canonical pair does not compose

import struct
import sys
import unicodedata

CURRENT = unicodedata
OLD = unicodedata.ucd_3_2_0
FORMS = ('NFC', 'NFD', 'NFKC', 'NFKD')
NONE_BYTE = 0xff
NONE_NUMERIC = 0xffff
NO_TAG = 0xff


class Probe(unicode):
    """Distinguishes a returned input from a computed equal result."""


def character(code):
    if code < 0x10000:
        return unichr(code)
    code -= 0x10000
    return unichr(0xd800 + (code >> 10)) + unichr(0xdc00 + (code & 0x3ff))


class Interner(object):
    def __init__(self):
        self.items = []
        self.index = {}

    def get(self, item):
        if item not in self.index:
            self.index[item] = len(self.items)
            self.items.append(item)
        return self.index[item]


def split_decomposition(text):
    fields = text.split()
    tag = None
    if fields and fields[0].startswith('<'):
        tag = fields.pop(0)
    return tag, [int(field, 16) for field in fields]


def format_decomposition(tag, codes):
    fields = ([tag] if tag else []) + ['%04X' % code for code in codes]
    return ' '.join(fields)


def main():
    categories = Interner()
    bidis = Interner()
    widths = Interner()
    tags = Interner()
    numerics = Interner()
    records = Interner()

    runs = {CURRENT: [], OLD: []}
    decompositions = {CURRENT: {}, OLD: {}}

    for code in range(0x110000):
        text = character(code)
        for database in (CURRENT, OLD):
            numeric = database.numeric(text, None)
            decimal = database.decimal(text, None)
            digit = database.digit(text, None)
            flags = database.mirrored(text)
            assert flags in (0, 1)
            if database.name(text, None) is not None:
                flags |= 2
            for bit, form in enumerate(FORMS):
                if type(database.normalize(form, Probe(text))) is Probe:
                    flags |= 4 << bit
            record = (
                categories.get(database.category(text)),
                bidis.get(database.bidirectional(text)),
                database.combining(text),
                widths.get(database.east_asian_width(text)),
                flags,
                NONE_BYTE if decimal is None else decimal,
                NONE_BYTE if digit is None else digit,
                NONE_NUMERIC if numeric is None else numerics.get(struct.pack('<d', numeric)),
            )
            index = records.get(record)
            series = runs[database]
            if not series or series[-1][1] != index:
                series.append((code, index))

            decomposition = database.decomposition(text)
            if decomposition:
                tag, codes = split_decomposition(decomposition)
                assert format_decomposition(tag, codes) == decomposition, decomposition
                if tag is not None:
                    tags.get(tag)
                decompositions[database][code] = (tag, codes)

    exclusions = {}
    for database in (CURRENT, OLD):
        excluded = []
        for code, (tag, codes) in sorted(decompositions[database].items()):
            if tag is None and len(codes) == 2 and database.normalize('NFC', character(code)) != character(code):
                excluded.append(code)
        exclusions[database] = excluded

    out = []
    out.append('UCDB')
    for strings in (categories.items, bidis.items, widths.items, tags.items):
        out.append(struct.pack('<B', len(strings)))
        for string in strings:
            out.append(struct.pack('<B', len(string)) + string)
    out.append(struct.pack('<H', len(numerics.items)))
    out.extend(numerics.items)
    out.append(struct.pack('<H', len(records.items)))
    for record in records.items:
        out.append(struct.pack('<BBBBBBBH', *record))
    for database in (CURRENT, OLD):
        out.append(struct.pack('<I', len(runs[database])))
        for start, index in runs[database]:
            out.append(struct.pack('<IH', start, index))

    current = decompositions[CURRENT]
    changed = dict((code, value) for code, value in decompositions[OLD].items() if current.get(code) != value)
    for code in current:
        if code not in decompositions[OLD]:
            changed[code] = (None, [])
    for entries in (current, changed):
        out.append(struct.pack('<I', len(entries)))
        for code, (tag, codes) in sorted(entries.items()):
            tag_index = NO_TAG if tag is None else tags.get(tag)
            out.append(struct.pack('<IBB', code, tag_index, len(codes)))
            out.append(''.join(struct.pack('<I', value) for value in codes))
    for database in (CURRENT, OLD):
        out.append(struct.pack('<I', len(exclusions[database])))
        out.append(''.join(struct.pack('<I', code) for code in exclusions[database]))

    assert len(tags.items) < NO_TAG
    data = ''.join(out)
    with open(sys.argv[1], 'wb') as handle:
        handle.write(data)


main()
