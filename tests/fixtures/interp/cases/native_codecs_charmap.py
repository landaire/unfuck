import _codecs
import strop


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


# A cp1252-like table: 0x80 is the euro sign, 0x81 is undefined.
identity = _codecs.latin_1_decode(strop.maketrans('', ''))[0]
table = identity[:128] + u'\u20ac\ufffe' + identity[130:]
encoding_map = _codecs.charmap_build(table)
mapping = {0x41: u'alpha', 0x42: 0x3b2, 0x43: None, 0x44: u'', 0x45: 0x1f600}
fallback = _codecs.charmap_build(u'\x01' + table[1:])
reverse = {0x3b1: 0x61, 0x3b2: 'beta', 0x3b3: None}

RESULT = (
    _codecs.charmap_decode('A\x80B\xff', 'strict', table),
    failure(_codecs.charmap_decode, 'A\x81B', 'strict', table),
    _codecs.charmap_decode('A\x81B', 'replace', table),
    _codecs.charmap_decode('A\x81B', 'ignore', table),
    _codecs.charmap_decode('ab\xe9'),
    _codecs.charmap_decode('ab', None, None),
    _codecs.charmap_decode('ABDZ', 'replace', mapping),
    failure(_codecs.charmap_decode, 'C', 'strict', mapping),
    _codecs.charmap_decode('E', 'strict', mapping)[1],
    failure(_codecs.charmap_decode, 'A', 'strict', {0x41: 0x110000}),
    failure(_codecs.charmap_decode, 'A', 'strict', {0x41: 'str'}),
    failure(_codecs.charmap_decode, 'AB', 'strict', {0x41: 0xfffe}),
    failure(_codecs.charmap_decode, 'B', 'strict', {0x42: u'\ufffe'}),
    type(encoding_map).__name__,
    encoding_map.size(),
    _codecs.charmap_encode(u'A\u20ac\xff\x00', 'strict', encoding_map),
    failure(_codecs.charmap_encode, u'a\x81\u3042b', 'strict', encoding_map),
    _codecs.charmap_encode(u'a\x81\u3042b', 'replace', encoding_map),
    _codecs.charmap_encode(u'a\x81\u3042b', 'ignore', encoding_map),
    _codecs.charmap_encode(u'a\x81\u3042b', 'xmlcharrefreplace', encoding_map),
    _codecs.charmap_encode(u'a\x81\u3042b', 'backslashreplace', encoding_map),
    _codecs.charmap_encode(u'\u03b1\u03b2', 'strict', reverse),
    failure(_codecs.charmap_encode, u'\u03b1\u03b3\u03b4\u03b1', 'strict', reverse),
    failure(_codecs.charmap_encode, u'\u03b3', 'replace', reverse),
    failure(_codecs.charmap_encode, u'\u03b1', 'strict', {0x3b1: 300}),
    failure(_codecs.charmap_encode, u'\u03b1', 'strict', {0x3b1: u'x'}),
    _codecs.charmap_encode(u'ab\xe9'),
    type(_codecs.charmap_build(u'\x01' + table[1:])).__name__,
    (fallback[1], fallback[0x20ac], fallback[0xfffe], len(fallback)),
    failure(_codecs.charmap_build, 'abc'),
    failure(_codecs.charmap_build, u'abc'),
    failure(type(encoding_map)),
)
