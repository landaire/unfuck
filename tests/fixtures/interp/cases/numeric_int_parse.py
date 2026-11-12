def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

parsed = (int('42'), int('  -17  '), int('+5'), int('- 5'), int('0x1f', 16), int('1f', 16), int('0x1f', 0), int('010', 0), int('0o17', 0), int('0b101', 0), int('z', 36), int('777', 8), int('0', 0), int(u' 12 '), int('11', 2), int('9' * 25), int('-' + '9' * 25))
types = (type(int('9' * 25)).__name__, type(int('5')).__name__, type(long('5')).__name__)
longs = (long('10L'), long('0x10', 16), long(' -7 '), long('0', 0), long('017', 0), long('ff', 16), long(u'12'))
errors = (
    err(int, '10L'),
    err(int, 'abc'),
    err(int, ' abc '),
    err(int, ''),
    err(int, '09', 0),
    err(int, '0x', 16),
    err(int, '1', 1),
    err(int, '1', 37),
    err(int, 5, 10),
    err(int, '5', 1.5),
    err(int, None),
    err(int, []),
    err(long, 'abc'),
    err(long, '09', 0),
    err(long, '1', 1),
    err(long, 5, 10),
    err(long, None),
    err(int, '1\x002'),
    err(int, '1_000'),
    err(int, '1.5'),
)
missing = err(lambda: int(base=10))

RESULT = (parsed, types, longs, errors, missing, int(), long(), int(x='3'), int('11', base=3))
