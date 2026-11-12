def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class S(str):
    pass
class U(unicode):
    pass
class Uni(object):
    def __unicode__(self):
        return u'uni\xe9'
    def __str__(self):
        return 'plain'
class StrOnly(object):
    def __str__(self):
        return 'only'
class StrUnicode(object):
    def __str__(self):
        return u'from str'
class Old:
    def __unicode__(self):
        return u'old'
s = S('abc')
u = U(u'xyz')
RESULT = (
    str(), str(5), str(5L), str(-12345678901234567890L), str(1.5), str(None), str(u'abc'), str(s), type(str(s)) is str,
    unicode(), unicode(5), unicode(2L), unicode('abc'), unicode(u'abc'), unicode(Uni()), unicode(StrOnly()), unicode(StrUnicode()), unicode(Old()),
    unicode('caf\xc3\xa9', 'utf-8'), unicode('abc', 'ascii', 'strict'), unicode('a\xffb', 'ascii', 'replace'), unicode('a\xffb', errors='ignore'),
    unicode(string='kw'), str(object='kw2'),
    err(unicode, u'abc', 'utf-8'), err(unicode, 5, 'utf-8'), err(unicode, 'abc', 'nope'), err(unicode, '41', 'hex'), err(unicode, '\xe9'),
    err(basestring), isinstance('a', basestring), isinstance(u'a', basestring), isinstance(s, str), isinstance(u, unicode),
    s, u, s.upper(), type(s.upper()) is str, s + 'd', len(s), s[1], u[::-1], type(u).__name__, S(), U(),
    err(str.__new__, int), err(str, 1, 2), unicode(KeyError('k')), str(KeyError('k')),
)
