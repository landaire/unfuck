# Normalization of every BMP character alone and of combining sequences.
import hashlib
import unicodedata as u


def digest(values):
    return hashlib.md5(repr(values)).hexdigest()


def err(function, *args):
    try:
        return ('ok', function(*args))
    except Exception as error:
        return (type(error).__name__, error.args)


def K(value):
    return value


class Text(unicode):
    pass


FORMS = ['NFC', 'NFD', 'NFKC', 'NFKD']

characters = [unichr(code) for code in range(0x10000)]

SEQUENCES = [
    u'A\u0301', u'a\u0323\u0302', u'a\u0302\u0323', u'e\u0301\u0301', u'\u1e0a\u0323', u'\u1e0c\u0307',
    u'q\u0307\u0323', u'\u212b', u'\u00c5\u0328', u'o\u0328\u0304', u'\u03b1\u0313\u0301\u0345',
    u'\u1100\u1161', u'\u1100\u1161\u11a8', u'\u1100\u1161\u11c2', u'\uac00\u11a8', u'\u1112\u1175\u11c2',
    u'\u1100\u1100\u1161\u1161', u'\u0915\u093c', u'\u0928\u093c', u'\u0b47\u0b3e', u'\u0bc6\u0bbe',
    u'\u05d0\u05b7\u05bc', u'\u0627\u0653', u'\u30ab\u3099', u'\u30cf\u309a', u'\u3300\u3099',
    u'\ufb2c\u05b0', u'\u0344\u0308', u'\u0f73\u0f71', u'\u0f40\u0fb5', u'a\u0300\u0315\u0300\u05ae',
    u'\u00e0\u05ae', u'\u1e9b\u0323', u'\ufdfa\u0301', u'\u2126\u0301', u'x\ud800',
    u'\u0041\u030a\u0301\u0327', u'Ste\u0301phane \u2460\ufb01', u'\u0308\u0301a', u'abc',
    u'\u1100\u1176', u'\u1100\u1176\u11a8', u'\u1100\u1161\u11a7', u'\uac00\u11a7', u'\u1112\u1175\u11a7',
    u'\uf900', u'\ufa6c', u'\ufad0', u'\U0001d15e', u'\U0001d160\u0301', u'\U0002f800', u'\U0002f9d0x',
    u'\U0001d400', u'a\U0001d167\u0301',
]

RESULT = (
    [digest([u.normalize(form, character) for character in characters]) for form in FORMS],
    [[u.normalize(form, character) for character in characters[::263]] for form in FORMS],
    [[u.normalize(form, unichr(code)) for code in range(0x1f00, 0x1f40)] for form in ('NFC', 'NFD')],
    [[u.normalize(form, unichr(code)) for code in range(0x3280, 0x3300, 5)] for form in ('NFKC', 'NFKD')],
    [[u.normalize(form, K(sequence)) for sequence in SEQUENCES] for form in FORMS],
    [u.normalize('NFC', u.normalize('NFD', unichr(code))) == u.normalize('NFC', unichr(code)) for code in range(0xac00, 0xd7a4, 97)],
    u.normalize('NFC', K(u'')), err(u.normalize, 'NFX', u'a'), err(u.normalize, 'nfc', u'a'), err(u.normalize, 'NFX', u''),
    err(u.normalize, 'NFC', 'a'), err(u.normalize, u'NFC', u'a'), err(u.normalize, u'NF\xc7', u'a'),
    err(u.normalize, 'NFC\0', u'a'), err(u.normalize, 5, u'a'), err(u.normalize, 'NFC'), err(u.normalize, 'NFC', u'a', 1),
    type(u.normalize('NFC', Text(u'abc'))).__name__, type(u.normalize('NFD', Text(u'\xe9'))).__name__,
    type(u.normalize('NFD', Text(u''))).__name__,
)
