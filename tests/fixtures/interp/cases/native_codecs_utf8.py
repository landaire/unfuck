import _codecs


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


text = u'caf\xe9 \u20ac \u4e2d'
encoded = _codecs.utf_8_encode(text)
astral = '\xf0\x9f\x98\x80'

RESULT = (
    encoded,
    _codecs.utf_8_decode(encoded[0]),
    _codecs.utf_8_decode(encoded[0], 'strict', True)[0] == text,
    _codecs.utf_8_encode(_codecs.utf_8_decode(astral)[0])[0] == astral,
    _codecs.utf_8_decode(astral)[1],
    _codecs.utf_8_decode('ab\xe2\x82'),
    _codecs.utf_8_decode('ab\xe2\x82', None, False),
    _codecs.utf_8_decode('ab\xc3', 'strict', 0),
    failure(_codecs.utf_8_decode, 'ab\xe2\x82', 'strict', True),
    failure(_codecs.utf_8_decode, 'a\xffb'),
    failure(_codecs.utf_8_decode, 'a\xe2\x28\xa1'),
    failure(_codecs.utf_8_decode, '\xe0\x80\x80'),
    failure(_codecs.utf_8_decode, '\xf0\x9f\x28'),
    failure(_codecs.utf_8_decode, '\xc0\xaf'),
    _codecs.utf_8_decode('a\xffb\xe2\x28\xa1', 'replace'),
    _codecs.utf_8_decode('a\xffb\xe2\x28\xa1', 'ignore'),
    _codecs.utf_8_decode('\xed\xa0\x80'),
    _codecs.utf_8_encode('plain'),
    _codecs.utf_8_encode(u''),
    _codecs.utf_8_decode(u'abc'),
    failure(_codecs.utf_8_decode, u'\xe9'),
    failure(_codecs.utf_8_decode, 1),
    failure(_codecs.utf_8_decode, 'a', 1),
    failure(_codecs.utf_8_decode, 'a', None, 'x'),
    failure(_codecs.utf_8_decode, 'a', 'strict', 1, 2),
    failure(_codecs.utf_8_encode, 1),
    failure(_codecs.utf_8_encode, '\xff'),
    failure(_codecs.utf_8_encode),
    failure(_codecs.utf_8_decode, 'a\xff', 'bogus'),
)
