import cPickle


def K(x):
    return x


def load(data):
    try:
        value = cPickle.loads(K(data))
    except Exception as e:
        return ('error', type(e).__name__, e.args)
    return (type(value).__name__, value)


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


PICKLES = [
    # Truncated data and end of input.
    '',
    'I1\n',
    '(',
    'J\x01\x00',
    'K',
    'T\x05\x00\x00\x00ab',
    'U\x05ab',
    'X\x05\x00\x00\x00ab',
    'G\x00\x00',
    '\x8a\x02\x01',
    '\x00',
    'N\x00',
    'I',
    'I\n.',
    'L\n.',
    'F\n.',
    'S\n.',
    'V',
    'c__builtin__\n',
    'c__builtin__\n\n.',
    'p\n.',
    'g\n.',
    # Bad text values.
    'Iabc\n.',
    'I12x\n.',
    'I1 \n.',
    'I0x\n.',
    'I08\n.',
    'I1\x002\n.',
    'Labc\n.',
    'L12x\n.',
    'L' + 'x' * 300 + '\n.',
    'L1.5\n.',
    'Fabc\n.',
    'F1.5x\n.',
    'F1.5 \n.',
    'F 1.5\n.',
    'F1e999\n.',
    'F-1e999\n.',
    'F' + '9' * 300 + 'x\n.',
    "Sabc\n.",
    "S'abc\n.",
    "S'abc\"\n.",
    "S'\n.",
    "S'\\x4'\n.",
    "S'abc\\'\n.",
    'V\\u12\n.',
    'V\\U00110000\n.',
    'X\x01\x00\x00\x00\xff.',
    'X\x02\x00\x00\x00\xc3(.',
    'X\x01\x00\x00\x00\xe2.',
    'T\xff\xff\xff\xff.',
    'X\xff\xff\xff\xff.',
    '\x8b\xff\xff\xff\xff.',
    # Unknown opcodes and protocols.
    'Z.',
    '\xff.',
    '\x80\x03.',
    '\x80\xffN.',
    # Stack and mark errors.
    '.',
    't.',
    'l.',
    'd.',
    'e.',
    'u.',
    '1.',
    '0.',
    '2.',
    'a.',
    'K\x01a.',
    's.',
    'K\x01K\x02s.',
    ']K\x01K\x02s.',
    '}(K\x01u.',
    'b.',
    'K\x01b.',
    'R.',
    'K\x01R.',
    '\x81.',
    'K\x01\x81.',
    ')\x81.',
    'K\x01)\x81.',
    'c__builtin__\nlen\nK\x01\x81.',
    'o.',
    '(o.',
    'p0\n.',
    'q\x00.',
    'r\x00\x00\x00\x00.',
    '\x85.',
    'K\x01\x86.',
    'K\x01K\x02\x87.',
    'Q.',
    # Memo misses.
    'g0\n.',
    'gabc\n.',
    'h\x00.',
    'h\xff.',
    'j\x00\x00\x00\x00.',
    'j\x01\x02\x03\x04.',
    'j\xff\xff\xff\x7f.',
    'K\x01p1\n0g01\n.',
    # Persistent ids without a hook.
    'P1\n.',
    'K\x01Q.',
    # Globals. A module the interpreter cannot find reads as an opaque host
    # module, so missing modules are not compared.
    'ccopy_reg\nno_such_name\n.',
    'c__builtin__\nno_such_name\n.',
    '(i__builtin__\nno_such_name\n.',
    # Extension codes.
    '\x82\x00.',
    '\x83\x00\x00.',
    '\x84\x00\x00\x00\x00.',
    '\x84\xff\xff\xff\xff.',
    '\x82\x7f.',
    # Odd SETITEMS.
    '}(K\x01K\x02K\x03u.',
    # DICT drops an odd key.
    '(K\x01K\x02K\x03d.',
    # APPENDS to a non-list without an append method.
    'K\x01(K\x02e.',
    # BUILD state checks.
    "c__builtin__\nobject\n)\x81K\x01b.",
    "c__builtin__\nobject\n)\x81K\x01K\x02\x86b.",
    "c__builtin__\nobject\n)\x81}K\x01\x86b.",
]

RESULT = [(data, load(data)) for data in PICKLES] + [
    failure(cPickle.loads),
    failure(cPickle.loads, 'N.', 1),
    failure(cPickle.loads, u'N.'),
    failure(cPickle.loads, bytearray('N.')),
    failure(cPickle.loads, None),
    failure(cPickle.load),
    failure(cPickle.load, 1),
    failure(cPickle.Unpickler),
    failure(cPickle.Unpickler, None),
    failure(cPickle.Unpickler, 'abc'),
]

# A tuple or list built over a consumed MARK raises SystemError, whose
# message names a build-specific source path.
try:
    cPickle.loads(K('c__builtin__\nlist\n)(Rt.'))
except SystemError:
    RESULT.append('tuple SystemError')
try:
    cPickle.loads(K('c__builtin__\nlist\n)(Rl.'))
except SystemError:
    RESULT.append('list SystemError')
