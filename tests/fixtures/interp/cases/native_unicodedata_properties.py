# Character properties over the BMP and of sample characters beyond it,
# which a narrow build takes as surrogate pairs. Digests cover every BMP
# code point; the samples show values where a digest differs.
import hashlib
import unicodedata as u


def digest(values):
    return hashlib.md5(repr(values)).hexdigest()


def every(function):
    return [function(unichr(code)) for code in range(0x10000)]


def sample(function, step):
    return [function(unichr(code)) for code in range(0, 0x10000, step)]


FUNCTIONS = [u.category, u.bidirectional, u.combining, u.mirrored, u.east_asian_width, u.decomposition]
ASTRAL = [u'\U00010000', u'\U0001D11E', u'\U0001D165', u'\U0001D7CE', u'\U0001F600', u'\U00020000', u'\U0002F800',
          u'\U000E0001', u'\U000F0000', u'\U0010FFFF', u'\ud834\udd1e', u'\ud834', u'\U0001D11Ex']


def K(value):
    return value


def err(function, *args):
    try:
        return ('ok', function(*args))
    except Exception as error:
        return (type(error).__name__, error.args)


RESULT = (
    [digest(every(function)) for function in FUNCTIONS],
    [sample(function, 251) for function in FUNCTIONS],
    [u.category(unichr(code)) for code in range(0x300, 0x380)],
    [u.combining(unichr(code)) for code in range(0x591, 0x5c8)],
    [u.bidirectional(unichr(code)) for code in range(0x200b, 0x2070)],
    [u.mirrored(unichr(code)) for code in range(0x2200, 0x2240)],
    [u.east_asian_width(unichr(code)) for code in range(0xff00, 0xfff0, 3)],
    [u.decomposition(unichr(code)) for code in range(0x1e00, 0x1e40)],
    [u.decomposition(unichr(code)) for code in (0xa0, 0xbd, 0x1f1, 0x2460, 0x3300, 0xfb01, 0xfdfa, 0xfe70, 0xff21, 0xac00, 0xd7a3)],
    u.category(u'\ud800'), u.category(u'\udfff'), u.category(u'\ue000'), u.category(u'\uffff'),
    [[err(function, K(text)) for text in ASTRAL] for function in FUNCTIONS],
)
