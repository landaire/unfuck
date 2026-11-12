import _struct as struct

def roundtrip(fmt, *values):
    packed = struct.pack(fmt, *values)
    return (packed, struct.unpack(fmt, packed), struct.calcsize(fmt))

RESULT = (
    roundtrip('<bBhHiIlLqQ', -1, 255, -2, 65535, -3, 4294967295, -4, 4294967295, -5, 18446744073709551615),
    roundtrip('>bBhHiIlLqQ', -1, 255, -2, 65535, -3, 4294967295, -4, 4294967295, -5, 18446744073709551615),
    roundtrip('!hi', 258, 16909060),
    roundtrip('=hi', 258, 16909060),
    roundtrip('@bhbibq', 1, 2, 3, 4, 5, 6),
    roundtrip('bhbibq', 1, 2, 3, 4, 5, 6),
    roundtrip('lL', -7, 7),
    roundtrip('P', 12345),
    roundtrip('<fd', 1.5, -2.25),
    roundtrip('>fd', 1.5, -2.25),
    roundtrip('fd?', 0.1, 1e300, 5),
    roundtrip('c3s2xp', 'z', 'abcdef', 'q'),
    roundtrip('5p', 'abcdefgh'),
    roundtrip('0s3x', ''),
    roundtrip('?', []),
    struct.pack('3s', 'a'),
    struct.pack('0p2s', '', ''),
    struct.pack('i', 1.7),
    struct.pack('<I', True),
    struct.pack('f', 1e300),
    struct.unpack('>Q', '\xff' * 8),
    struct.unpack('<q', '\xff' * 8),
    struct.unpack('5p', '\x09abcd'),
    struct.unpack('i', u'abcd'),
    struct.unpack_from('<h', 'abcdef', 3),
    struct.unpack_from('<h', 'abcdef', -2),
    struct.unpack_from('<h', buffer='xyz'),
    struct.unpack_from('<h', 'xyz', offset=1),
    [struct.calcsize(f) for f in ['', 'ci', '@ci', '=ci', 'bq', 'b?h', 'hP', 'ib', ' i  h ', '4', '3i4', 'i\0q', '10x']],
    struct.calcsize(u'2h'),
    struct.__version__, struct._PY_STRUCT_RANGE_CHECKING, struct._PY_STRUCT_FLOAT_COERCE,
    struct._clearcache(),
)
