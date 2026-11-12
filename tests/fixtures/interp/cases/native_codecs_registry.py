import _codecs

log = [()]


def encoder(text, errors='strict'):
    return ('enc:' + text, len(text))


def decoder(data, errors='strict'):
    return (u'dec:' + data, errors)


def search(name):
    if name == 'my-codec' or name == 'bad' or name == 'none-codec':
        log[0] = log[0] + (name,)
    if name == 'my-codec':
        return (encoder, decoder, None, None)
    if name == 'bad':
        return (encoder, decoder)
    return None


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


_codecs.register(search)
first = _codecs.lookup('My Codec')
second = _codecs.lookup('MY-CODEC')

RESULT = (
    first[0] is encoder,
    second is first,
    log[0],
    _codecs.encode('x', 'my-codec'),
    _codecs.decode('y', 'My Codec', 'ignore'),
    failure(_codecs.lookup, 'None Codec'),
    failure(_codecs.lookup, 'bad'),
    failure(_codecs.lookup, 1),
    failure(_codecs.lookup),
    failure(_codecs.register, 1),
    failure(_codecs.register_error, 'x', 1),
    failure(_codecs.lookup_error, 'nope'),
    repr(_codecs.lookup_error('strict')),
    repr(_codecs.lookup_error('backslashreplace')),
    _codecs.lookup_error('ignore') is _codecs.lookup_error('ignore'),
    log[0],
)
