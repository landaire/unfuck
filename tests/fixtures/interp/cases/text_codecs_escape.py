def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    'a\\nb\\t\\x41\\101\\\\\\\'\\"\\q\\\nz'.decode('string_escape'), 'a\nb\'\x00\xff\\'.encode('string_escape'), '"'.encode('string-escape'),
    err('\\x4'.decode, 'string_escape'), err('ab\\'.decode, 'string_escape'), '\\x4g'.decode('string_escape', 'replace'), '\\x4g'.decode('string_escape', 'ignore'),
    'a\\u20ac\\x41\\n\\101\\N'.replace('\\N', '').decode('unicode_escape'), u'a\u20ac\xe9\n\\\''.encode('unicode_escape'), '\xe9'.decode('unicode-escape'),
    err('\\u12'.decode, 'unicode_escape'), err('\\x1'.decode, 'unicode_escape'), err('ab\\'.decode, 'unicode_escape'), err('\\U00110000'.decode, 'unicode_escape'),
    '\\u12z'.decode('unicode_escape', 'replace'), '\\U0001F600'.decode('unicode_escape') == u'\U0001F600', '\\q\\8'.decode('unicode_escape'),
    'a\\u20ac\\\\u20ac\\x41'.decode('raw_unicode_escape'), u'a\u20ac\xe9\\'.encode('raw_unicode_escape'), err('\\u12'.decode, 'raw_unicode_escape'),
    u'ab'.encode('utf-16'), u'ab'.encode('utf-16-le'), u'ab'.encode('utf-16-be'), '\xff\xfea\x00'.decode('utf-16'), '\xfe\xff\x00a'.decode('utf-16'),
    'a\x00'.decode('utf-16'), '\xff\xfea\x00'.decode('utf-16-le'), err('a'.decode, 'utf-16'), err('\x00\xd8'.decode, 'utf-16-le'),
    err('\x00\xdc'.decode, 'utf-16-le'), err('\x00\xd8a\x00'.decode, 'utf-16-le'), '\x00\xd8a\x00'.decode('utf-16-le', 'replace'),
    'abc'.encode('hex'), '616263'.decode('hex'), 'ABCDEF'.decode('hex'), err('abc'.decode, 'hex'), err('zz'.decode, 'hex'), u'ab'.encode('hex'),
)
