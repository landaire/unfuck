# Decimal, digit, and numeric values over the BMP and of sample characters
# beyond it, which a narrow build takes as surrogate pairs.
import hashlib
import unicodedata as u


def digest(values):
    return hashlib.md5(repr(values)).hexdigest()


def numbered(function):
    return [(code, function(unichr(code), None)) for code in range(0x10000) if function(unichr(code), None) is not None]


def err(function, *args):
    try:
        return ('ok', function(*args))
    except Exception as error:
        return (type(error).__name__, error.args)


decimals = numbered(u.decimal)
digits = numbered(u.digit)
numerics = numbered(u.numeric)

RESULT = (
    len(decimals), len(digits), len(numerics),
    digest(decimals), digest(digits), digest(numerics),
    decimals[::17], digits[::13], numerics[::7],
    [u.numeric(unichr(code), 'x') for code in range(0x2150, 0x2190)],
    [u.numeric(unichr(code), 'x') for code in (0xf33, 0x3405, 0x4e07, 0x5146, 0x5344, 0x96f6, 0xf96b, 0xbc, 0x2cfd)],
    [u.digit(unichr(code), -1) for code in range(0x2460, 0x2500, 3)],
    [u.decimal(unichr(code), -1) for code in range(0xff10, 0xff1a)],
    u.decimal(u'9'), u.digit(u'\xb2'), u.numeric(u'\xbd'), u.numeric(u'7'),
    err(u.decimal, u'a'), err(u.digit, u'a'), err(u.numeric, u'a'),
    err(u.decimal, u'\xb2'), err(u.digit, u'\xbd'),
    u.decimal(u'a', None), u.digit(u'a', 5), u.numeric(u'a', []),
    [[err(function, text) for text in (u'\U00010107', u'\U0001D7CE', u'\U0001D7FF', u'\U000104A0', u'\U00012400',
                                       u'\U0001D360', u'\U00020001', u'\U0001F600', u'\U0001D7CEx')]
     for function in (u.decimal, u.digit, u.numeric)],
)
