# Identity of unicode results: the shared empty and Latin-1 one-character
# objects, and the methods that return an exact unicode itself.


def K(x):
    return x


class U(unicode):
    pass


a = K(u'abc')
e = K(u'')
probes = [
    ('index', lambda: a[0] is K(u'a')),
    ('index_wide', lambda: K(u'\u20ac')[0] is K(u'\u20ac')[0]),
    ('slice_full', lambda: a[:] is a),
    ('slice_step', lambda: a[::1] is a),
    ('slice_empty', lambda: a[1:1] is e),
    ('unicode', lambda: unicode(a) is a),
    ('sub_unicode', lambda: unicode(U(a)) is a),
    ('concat_empty', lambda: a + e is a),
    ('concat_empty_left', lambda: e + a is a),
    ('concat_str_empty', lambda: a + K('') is a),
    ('repeat1', lambda: a * K(1) is a),
    ('repeat0', lambda: a * K(0) is e),
    ('strip', lambda: a.strip() is a),
    ('replace', lambda: a.replace(K(u'x'), K(u'y')) is a),
    ('replace_same', lambda: a.replace(K(u'a'), K(u'a')) is a),
    ('lower', lambda: a.lower() is a),
    ('upper', lambda: a.upper() is a),
    ('title', lambda: K(u'Abc').title() is K(u'Abc')),
    ('center', lambda: a.center(K(2)) is a),
    ('zfill', lambda: a.zfill(K(2)) is a),
    ('split', lambda: a.split()[0] is a),
    ('partition', lambda: a.partition(K(u','))[0] is a),
    ('join1', lambda: K(u'-').join([a]) is a),
    ('expandtabs', lambda: a.expandtabs() is a),
    ('decode_char', lambda: K('a').decode('ascii') is K(u'a')),
    ('empty_join', lambda: e.join([]) is e),
    ('id_empty', lambda: id(e) == id(a[0:0])),
]


def r(f):
    try:
        return f()
    except Exception as ex:
        return 'E:' + type(ex).__name__


RESULT = [(name, r(f)) for name, f in probes]
