import _codecs


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


mixed = u'a\xe9\xe8b\u20acc'

RESULT = (
    _codecs.ascii_encode(u'plain'),
    _codecs.ascii_decode('plain'),
    _codecs.latin_1_encode(u'caf\xe9'),
    _codecs.latin_1_decode('caf\xe9\xff'),
    failure(_codecs.ascii_encode, mixed),
    failure(_codecs.latin_1_encode, mixed),
    failure(_codecs.ascii_decode, 'a\xff\xfeb'),
    _codecs.ascii_encode(mixed, 'replace'),
    _codecs.ascii_encode(mixed, 'ignore'),
    _codecs.ascii_encode(mixed, 'xmlcharrefreplace'),
    _codecs.ascii_encode(mixed, 'backslashreplace'),
    _codecs.latin_1_encode(mixed, 'replace'),
    _codecs.latin_1_encode(mixed, 'backslashreplace'),
    _codecs.ascii_decode('a\xff\xfeb', 'replace'),
    _codecs.ascii_decode('a\xff\xfeb', 'ignore'),
    failure(_codecs.ascii_decode, 'a\xff', 'xmlcharrefreplace'),
    failure(_codecs.ascii_decode, 'a\xff', 'backslashreplace'),
    failure(_codecs.ascii_encode, mixed, 'bogus'),
    _codecs.ascii_encode(u'abc', 'bogus'),
    failure(_codecs.latin_1_decode, 'a', 'x\x00y'),
    _codecs.latin_1_encode('bytes'),
    failure(_codecs.latin_1_encode, 'bytes\xff'),
    failure(_codecs.ascii_encode, None),
)
