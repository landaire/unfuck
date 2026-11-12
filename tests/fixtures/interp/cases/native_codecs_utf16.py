import _codecs


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


text = u'A\xe9\u20ac'

RESULT = (
    _codecs.utf_16_encode(text),
    _codecs.utf_16_le_encode(text),
    _codecs.utf_16_be_encode(text),
    _codecs.utf_16_encode(text, 'strict', 1),
    _codecs.utf_16_encode(text, 'strict', -1),
    _codecs.utf_16_decode('\xff\xfeA\x00\xe9\x00'),
    _codecs.utf_16_decode('\xfe\xff\x00A\x00\xe9'),
    _codecs.utf_16_decode('A\x00\xe9\x00'),
    _codecs.utf_16_le_decode('\xff\xfeA\x00'),
    _codecs.utf_16_be_decode('\x00A\x20\xac'),
    _codecs.utf_16_decode('A\x00b'),
    _codecs.utf_16_decode('A\x00=\xd8', 'strict', False),
    _codecs.utf_16_decode('', 'strict', True),
    failure(_codecs.utf_16_decode, 'A\x00b', 'strict', True),
    failure(_codecs.utf_16_le_decode, 'A\x00=\xd8', 'strict', True),
    failure(_codecs.utf_16_le_decode, '=\xd8A\x00', 'strict', True),
    failure(_codecs.utf_16_le_decode, '\x00\xdcA\x00', 'strict', True),
    _codecs.utf_16_le_decode('\x00\xdcA\x00b', 'replace', True),
    _codecs.utf_16_ex_decode('\xff\xfea\x00'),
    _codecs.utf_16_ex_decode('\xfe\xff\x00a', None, 0, 1),
    _codecs.utf_16_ex_decode('a\x00', None, 7, 1),
    _codecs.utf_16_ex_decode(''),
    _codecs.utf_32_encode(text),
    _codecs.utf_32_be_encode(text),
    _codecs.utf_32_le_decode('A\x00\x00\x00\xac\x20\x00\x00'),
    _codecs.utf_32_decode('\x00\x00\xfe\xff\x00\x00\x00A'),
    _codecs.utf_32_decode('A\x00\x00\x00b', 'strict', False),
    failure(_codecs.utf_32_decode, 'A\x00\x00\x00b', 'strict', True),
    failure(_codecs.utf_32_le_decode, '\x00\x00\x11\x00', 'strict', True),
    _codecs.utf_32_le_decode('\x00\x00\x11\x00A\x00\x00\x00', 'ignore', True),
    _codecs.utf_32_ex_decode('\xff\xfe\x00\x00A\x00\x00\x00'),
    _codecs.utf_16_le_decode(_codecs.utf_16_le_encode(u'\U0001f600')[0])[0] == u'\U0001f600',
    _codecs.utf_32_be_decode(_codecs.utf_32_be_encode(u'x\U0001f600')[0])[0] == u'x\U0001f600',
    failure(_codecs.utf_16_encode, text, 'strict', 'x'),
    failure(_codecs.utf_16_encode, text, 'strict', 1.5),
)
