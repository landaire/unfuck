import binascii as b

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

RESULT = (
    err(b.unhexlify, 'abc'), err(b.unhexlify, 'zz'), err(b.a2b_hex, 'g0'),
    err(b.hexlify, 5), err(b.hexlify, None), err(b.hexlify), err(b.hexlify, 'a', 'b'), err(b.hexlify, data='a'),
    err(b.a2b_base64, 'YWJ'), err(b.a2b_base64, 'Y'), err(b.b2a_uu, 'x' * 46), err(b.a2b_uu, '!\x7f'),
    err(b.a2b_uu, '!800 x'), err(b.a2b_hqx, 'AB'), err(b.a2b_hqx, '\x01'),
    err(b.rledecode_hqx, '\x90\x01'), err(b.rledecode_hqx, 'a\x90'), err(b.rledecode_hqx, '\x90'),
    err(b.crc_hqx, 'a', 2 ** 40), err(b.crc_hqx, 'a', 2 ** 31), err(b.crc_hqx, 'a', -2 ** 31 - 1),
    err(b.crc_hqx, 'a', 1.0), err(b.crc_hqx, 'a'), err(b.crc_hqx, 'a', 'x'),
    err(b.crc32, 'a', 1.5), err(b.crc32, 'a', 'x'), err(b.crc32), err(b.crc32, 'a', 1, 2), err(b.crc32, 5),
    err(b.b2a_qp, data='x', bogus=1), err(b.b2a_qp), err(b.b2a_qp, 'x', 1, 1, 1, 1), err(b.a2b_qp, 'x', header=1.5),
    issubclass(b.Error, Exception), issubclass(b.Incomplete, Exception), issubclass(b.Error, ValueError),
    b.Error.__module__, b.Incomplete.__name__,
)
