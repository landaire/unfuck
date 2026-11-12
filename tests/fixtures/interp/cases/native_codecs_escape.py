import _codecs


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


text = u'a\\b\t\n\r\x00\x7f\xe9\u20ac\'"'

RESULT = (
    _codecs.unicode_escape_encode(text),
    _codecs.unicode_escape_decode(_codecs.unicode_escape_encode(text)[0])[0] == text,
    _codecs.unicode_escape_decode('\\x41\\u20ac\\U0000004a\\101\\7\\q\\\n!'),
    _codecs.unicode_escape_decode('\\a\\b\\f\\v\\\'\\"'),
    failure(_codecs.unicode_escape_decode, 'ab\\'),
    failure(_codecs.unicode_escape_decode, 'a\\x4'),
    failure(_codecs.unicode_escape_decode, 'a\\u12g4b'),
    failure(_codecs.unicode_escape_decode, '\\U00110000'),
    _codecs.unicode_escape_decode('a\\x4zb\\', 'replace'),
    _codecs.unicode_escape_decode('a\\u12', 'ignore'),
    _codecs.raw_unicode_escape_encode(u'a\\b\xe9\u20ac'),
    _codecs.raw_unicode_escape_decode('a\\u20ac\\\\u20ac\\x41\\U0000004a'),
    failure(_codecs.raw_unicode_escape_decode, 'a\\u20'),
    failure(_codecs.raw_unicode_escape_decode, '\\U00110000'),
    _codecs.raw_unicode_escape_decode('a\\u2x', 'replace'),
    _codecs.escape_encode('a\'b"\\\t\n\r\x00\x7f\xff'),
    _codecs.escape_decode('a\\x41\\n\\101\\q\\\nz'),
    _codecs.escape_decode(u'a\\n'),
    failure(_codecs.escape_decode, 'ab\\'),
    failure(_codecs.escape_decode, 'a\\x4'),
    _codecs.escape_decode('a\\x4zb', 'replace'),
    _codecs.escape_decode('a\\xzb', 'ignore'),
    failure(_codecs.escape_decode, 'a\\x4', 'bogus'),
    failure(_codecs.escape_encode, u'a'),
    _codecs.readbuffer_encode('a\x00b'),
    _codecs.readbuffer_encode(u'ab'),
    _codecs.charbuffer_encode('xyz', None),
    failure(_codecs.charbuffer_encode, 1),
    failure(_codecs.readbuffer_encode, 1),
    failure(_codecs.readbuffer_encode, u'\xe9'),
)
