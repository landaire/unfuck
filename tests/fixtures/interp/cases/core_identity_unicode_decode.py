# Identity of unicode built by decoders, cPickle, and formatting: only the
# ASCII and Latin-1 decoders of one byte and indexing share the Latin-1
# one-character objects; the others allocate new objects.
import codecs
import cPickle


def K(x):
    return x


a = K(u'abc')[0]
probes = [
    ('index_shared', lambda: K(u'xa')[1] is a),
    ('unichr', lambda: unichr(K(97)) is a),
    ('ascii', lambda: K('a').decode('ascii') is a),
    ('latin1', lambda: K('a').decode('latin-1') is a),
    ('latin1_e9', lambda: K('\xe9').decode('latin-1') is K(u'\xe9x')[0]),
    ('utf8', lambda: K('a').decode('utf-8') is a),
    ('utf16', lambda: K('a\x00').decode('utf-16-le') is a),
    ('unicode_escape', lambda: K('a').decode('unicode-escape') is a),
    ('raw_unicode_escape', lambda: K('a').decode('raw-unicode-escape') is a),
    ('codecs_utf8', lambda: codecs.utf_8_decode(K('a'))[0] is a),
    ('codecs_latin1', lambda: codecs.latin_1_decode(K('a'))[0] is a),
    ('codecs_ascii', lambda: codecs.ascii_decode(K('a'))[0] is a),
    ('charmap_none', lambda: codecs.charmap_decode(K('a'))[0] is a),
    ('unicode_str', lambda: unicode(K('a')) is a),
    ('pickle_unicode', lambda: cPickle.loads(K('Va\n.')) is a),
    ('pickle_binunicode', lambda: cPickle.loads(K('X\x01\x00\x00\x00a.')) is a),
    ('percent', lambda: K(u'%s') % a is a),
    ('format', lambda: K(u'{}').format(a) is a),
    ('join', lambda: K(u'').join([a, K(u'')]) is a),
    ('upper', lambda: K(u'A').lower() is a),
    ('translate', lambda: K(u'b').translate({98: 97}) is a),
    ('literal', lambda: K(u'a') is a),
    ('empty_utf8', lambda: K('').decode('utf-8') is K(u'')),
    ('empty_concat', lambda: K(u'') + K(u'') is K(u'')),
    ('repeat0', lambda: a * K(0) is K(u'')),
]


def r(f):
    try:
        return f()
    except Exception as ex:
        return 'E:' + type(ex).__name__


RESULT = [(name, r(f)) for name, f in probes]
