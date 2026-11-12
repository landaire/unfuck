# The Unicode 3.2.0 database object, the UCD type, and argument errors.
import hashlib
import unicodedata as u


def digest(values):
    return hashlib.md5(repr(values)).hexdigest()


def err(function, *args):
    try:
        return ('ok', function(*args))
    except Exception as error:
        return (type(error).__name__, error.args)


old = u.ucd_3_2_0
characters = [unichr(code) for code in range(0x10000)]

FUNCTIONS = [old.category, old.bidirectional, old.combining, old.mirrored, old.east_asian_width, old.decomposition]
VALUES = [old.decimal, old.digit, old.numeric, old.name]

changed = [code for code in range(0x10000) if old.category(unichr(code)) != u.category(unichr(code))]

RESULT = (
    old.unidata_version, u.unidata_version, type(old).__name__, type(old).__module__, repr(u.UCD),
    isinstance(old, u.UCD), type(u.UCD.__dict__['unidata_version']).__name__,
    [digest([function(character) for character in characters]) for function in FUNCTIONS],
    [digest([function(character, None) for character in characters]) for function in VALUES],
    len(changed), changed[::23],
    [(old.category(unichr(code)), old.bidirectional(unichr(code)), old.east_asian_width(unichr(code)), old.name(unichr(code), None)) for code in changed[::41]],
    [old.numeric(unichr(code), None) for code in (0x31, 0xbd, 0x2155, 0x2189, 0x3405, 0xf96b, 0x1813, 0x19da)],
    [old.decimal(unichr(code), None) for code in (0x31, 0xb2, 0x1369, 0x19da, 0x1813, 0x2070)],
    [old.digit(unichr(code), None) for code in (0x31, 0xb2, 0x2460, 0x19da)],
    [old.mirrored(unichr(code)) for code in (0x28, 0x2201, 0x2215, 0x2216, 0x22f2, 0x27c3)],
    [old.lookup(name) for name in ('SPACE', 'latin small letter a', 'HANGUL SYLLABLE GA', 'CJK UNIFIED IDEOGRAPH-9FCB')],
    err(old.lookup, 'ARABIC SIGN SAFHA'), err(old.lookup, 'BOGUS'), err(old.name, u'\u0606'),
    [old.normalize(form, u'\u1e9b\u0323\uac00\u0606\ufb01\u0344') for form in ('NFC', 'NFD', 'NFKC', 'NFKD')],
    [[old.normalize(form, unichr(code)) for code in range(0, 0x10000, 389)] for form in ('NFC', 'NFKD')],
    digest([old.normalize('NFKC', character) for character in characters]),
    err(u.UCD), err(u.UCD.category, u'a'), err(u.UCD.category, old), err(u.UCD.category),
    err(setattr, old, 'unidata_version', '1'), err(setattr, old, 'x', 1),
    err(u.category, 'a'), err(u.category, None), err(u.category, u'ab'), err(u.category, u''), err(u.category),
    err(u.category, u'a', u'b'), err(old.category, 'a'), err(old.category, u'ab'), err(old.decimal),
    err(u.decimal, u'a', 1, 2), err(lambda: u.category(c=u'a')), err(u.normalize, 'NFC', None),
    err(type, 'X', (u.UCD,), {}),
)
