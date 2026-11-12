def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

u = u'caf\xe9 \u20ac'
RESULT = (
    u.encode('utf-8'), u.encode('UTF8'), u.encode('u8'), u.encode('utf_8'), 'caf\xc3\xa9'.decode('utf-8'), 'caf\xc3\xa9'.decode('utf8'),
    u'caf\xe9'.encode('latin-1'), u'caf\xe9'.encode('iso-8859-1'), u'caf\xe9'.encode('latin1'), 'caf\xe9'.decode('latin-1'), 'caf\xe9'.decode('L1'),
    u'abc'.encode('ascii'), u'abc'.encode(), 'abc'.decode(), 'abc'.decode('ascii'), u'abc'.encode('US-ASCII'), 'abc'.encode('utf-8'),
    u'\U00010348'.encode('utf-8') if len(u'\U00010348') == 2 else '\xf0\x90\x8d\x88', 'abc'.decode(encoding='utf-8'), u'x'.encode(errors='strict'),
    u'\ud800'.encode('utf-8') if len(u'\U00010348') == 2 else '\xed\xa0\x80', '\xe2\x82\xac'.decode('utf-8'), u'abc'.decode('utf-8'),
    err('a'.decode, 'nope'), err(u'a'.encode, 'nope'), err('a'.decode, 1), err('a'.encode, 'utf-8', 1),
    'abc'.encode('latin-1'), type('abc'.decode('latin-1')).__name__, type(u'abc'.encode('ascii')).__name__,
)
