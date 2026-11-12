K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    err(u'caf\xe9'.encode, 'ascii'), err(u'\xe9\xe8x'.encode, 'ascii'), err(u'a\u20acb'.encode, 'latin-1'), err(u'\u20ac\u20ac'.encode, 'latin-1'),
    err('caf\xe9'.decode, 'ascii'), err('a\xff\xfeb'.decode, 'ascii'), err('\xff'.decode, 'utf-8'), err('\xc3'.decode, 'utf-8'),
    err('a\xe2\x82'.decode, 'utf-8'), err('\xe2\x28\xa1'.decode, 'utf-8'), err('\xe2\x82\x28'.decode, 'utf-8'), err('\xc0\xaf'.decode, 'utf-8'),
    err('\xe0\x80\x80'.decode, 'utf-8'), err('\xf0\x80\x80\x80'.decode, 'utf-8'), err('\xf4\x90\x80\x80'.decode, 'utf-8'), err('\xf5'.decode, 'utf-8'),
    'a\xffb\xc3'.decode('utf-8', 'replace'), 'a\xffb\xc3'.decode('utf-8', 'ignore'), '\xe2\x82\x28x'.decode('utf-8', 'replace'),
    u'a\xe9\u20acb'.encode('ascii', 'replace'), u'a\xe9\u20acb'.encode('ascii', 'ignore'), u'a\xe9\u20acb'.encode('ascii', 'xmlcharrefreplace'),
    u'a\xe9\u20acb'.encode('latin-1', 'backslashreplace'), 'a\xffb'.decode('ascii', 'replace'), 'a\xffb'.decode('latin-1', 'bogus'),
    err(u'\xe9'.encode, 'ascii', 'bogus'), err('\xff'.decode, 'ascii', 'bogus'), err('\xff'.decode, 'utf-8', 'xmlcharrefreplace'),
    err(str, u'\xe9'), err(unicode, '\xe9'), err(lambda: K(u'\xe9') + '\xe9'), err(u'\xe9'.decode, 'utf-8'), err('\xe9'.encode, 'utf-8'),
    err(u'\xe9'.encode, 'string_escape'),
)
