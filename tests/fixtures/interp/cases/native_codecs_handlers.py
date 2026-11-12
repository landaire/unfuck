import _codecs

seen = [()]


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


def tagging(error):
    seen[0] = seen[0] + ((type(error).__name__,) + error.args,)
    return (u'<' + error.args[0] + u'>', error.args[3])


def skip_to_end(error):
    return (u'!', -1)


def bad_tuple(error):
    return (u'x',)


def bad_type(error):
    return ('x', 1)


def far(error):
    return (u'x', 100)


def raising(error):
    raise KeyError('from handler')


for name, handler in (('test.tag', tagging), ('test.end', skip_to_end), ('test.badtuple', bad_tuple), ('test.badtype', bad_type), ('test.far', far), ('test.raise', raising)):
    _codecs.register_error(name, handler)

strict = _codecs.lookup_error('strict')
error = UnicodeDecodeError('ascii', 'a\xff', 1, 2, 'ordinal not in range(128)')

RESULT = (
    _codecs.ascii_decode('a\xffb', 'test.tag'),
    _codecs.ascii_encode(u'a\xe9\xe8b', 'test.tag'),
    _codecs.utf_8_decode('x\xe2\x82', 'test.tag', True),
    _codecs.latin_1_encode(u'ab\u20acc\u20acd', 'test.end'),
    seen[0],
    failure(_codecs.ascii_decode, '\xff', 'test.badtuple'),
    failure(_codecs.ascii_encode, u'\xff', 'test.badtype'),
    failure(_codecs.ascii_decode, '\xff', 'test.far'),
    failure(_codecs.ascii_encode, u'\xff', 'test.raise'),
    failure(strict, error),
    failure(strict, 1),
    failure(strict),
    failure(_codecs.lookup_error('replace'), ValueError('x')),
    failure(_codecs.lookup_error('ignore'), KeyError()),
    failure(_codecs.lookup_error('xmlcharrefreplace'), error),
    failure(_codecs.lookup_error('backslashreplace'), 5),
    _codecs.lookup_error('test.tag') is tagging,
)
