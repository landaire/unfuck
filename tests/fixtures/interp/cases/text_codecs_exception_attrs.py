import _codecs as codecs
K = lambda value: value
def fields(f, *a):
    try:
        f(*a)
    except UnicodeError as e:
        return (type(e).__name__, e.encoding, e.object, e.start, e.end, e.reason, e.args, str(e))
    return 'no error'

def handler(error):
    return (u'<%d:%d>' % (error.start, error.end), error.end)

codecs.register_error('test.attrs', handler)

RESULT = [
    fields(u'caf\xe9'.encode, 'ascii'), fields(u'a\u20ac\u20acb'.encode, 'latin-1'), fields('caf\xe9'.decode, 'ascii'),
    fields('a\xe2\x82'.decode, 'utf-8'), fields('\xff'.decode, 'utf-16'), fields('\\u12'.decode, 'unicode_escape'),
    fields('\\U00110000'.decode, 'raw_unicode_escape'), fields(unicode, 'x\xe9', 'utf-8'), fields(str, K(u'\xe9')),
    fields(lambda: K(u'a') + '\xe9'), fields('\xe9'.encode, 'utf-8'), fields(bytearray('\xe9').decode, 'utf-8'),
    'a\xffb\xfe'.decode('ascii', 'test.attrs'), u'a\xe9b\u20ac'.encode('ascii', 'test.attrs'), 'a\xffb'.decode('utf-8', 'test.attrs'),
]
