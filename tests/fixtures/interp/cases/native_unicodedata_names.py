# Character names over the BMP and lookup by name.
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


names = [u.name(unichr(code), None) for code in range(0x10000)]
named = [code for code in range(0x10000) if names[code] is not None]

RESULT = (
    len(named), digest(names), names[::211],
    names[0xac00:0xac20], names[0xd7a0:0xd7b2], names[0x4db0:0x4dc2], names[0x9fc8:0x9fd0],
    all(u.lookup(names[code]) == unichr(code) for code in named),
    all(u.lookup(names[code].lower()) == unichr(code) for code in named[::5] if not names[code].startswith(('HANGUL SYLLABLE ', 'CJK UNIFIED IDEOGRAPH-'))),
    [u.lookup(name) for name in (K('SPACE'), K('latin small letter a'), K('HANGUL SYLLABLE GA'), K('HANGUL SYLLABLE HIH'), K('CJK UNIFIED IDEOGRAPH-4E00'), K(u'Euro Sign'))],
    err(u.lookup, bytearray('SPACE')),
    err(u.lookup, K('BOGUS NAME')), err(u.lookup, K('hangul syllable ga')), err(u.lookup, K('CJK UNIFIED IDEOGRAPH-4e00')),
    err(u.lookup, K('CJK UNIFIED IDEOGRAPH-9FCC')), err(u.lookup, K('HANGUL SYLLABLE GX')), err(u.lookup, K('a\0b')),
    err(u.lookup, K('\xff')), err(u.lookup, K(u'\xe9')), err(u.lookup, 5), err(u.lookup), err(u.lookup, 'a', 'b'),
    err(u.name, u'\u0378'), err(u.name, u'\ud800'), u.name(u'\u0378', 'none'), u.name(u'\x00', 0),
    err(u.name, u'ab'), err(u.name, u''), err(u.name, 'a'), err(u.name), err(u.name, u'a', 1, 2), err(u.name, None),
    [err(u.lookup, K(name)) for name in ('MUSICAL SYMBOL G CLEF', 'LINEAR B SYLLABLE B008 A', 'CJK UNIFIED IDEOGRAPH-20000',
                                         'CJK UNIFIED IDEOGRAPH-2A6D6', 'CJK UNIFIED IDEOGRAPH-2A6D7', 'GRINNING FACE',
                                         'mathematical bold capital a')],
    [err(u.name, K(text)) for text in (u'\U0001D11E', u'\U00020000', u'\U0001F600', u'\U000E0001')],
)
