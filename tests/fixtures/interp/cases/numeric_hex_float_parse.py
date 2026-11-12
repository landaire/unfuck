from _struct import pack, unpack


def bits(x):
    return '%016x' % unpack('<Q', pack('<d', x))[0]


rows = []
for s in ['0x1.00000000000008p0', '0x1.00000000000018p0', '0x1.000000000000080000001p0', '0x1p-1075', '0x1.8p-1075', '0x3p-1076', '0x0.fffffffffffff8p-1022',
          '0x1.fffffffffffff8p1023', '0x1.fffffffffffff7p1023', '0x1p', '0x.p1', ' -0x0p0 ', '-nan', 'infinity', 'infinit', '0x' + '0' * 300 + '1p-1074', '0x1' + '0' * 300 + 'p-2200', '0x1p-99999999999999999999', '0x0p99999999999999999999', '1e5', 'FF.8']:
    try:
        rows.append(bits(float.fromhex(s)))
    except Exception as e:
        rows.append('%s: %s' % (type(e).__name__, e))
for x in [5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, -0.0, 0.1]:
    rows.append(x.hex())
for s in ['0x', '0x10', '010', '08', '0b1', '0o7', '0b', '00x10', '- 0x10', '0L']:
    for base in (0, 2, 8, 16):
        for f in (int, long):
            try:
                rows.append(str(f(s, base)))
            except ValueError as e:
                rows.append(str(e))
RESULT = rows
