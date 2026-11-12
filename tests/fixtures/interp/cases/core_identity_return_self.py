# Methods that return an exact str itself instead of a copy.
import string


def K(x):
    return x


class S(str):
    pass


a = K('abc')
sub = S(K('abc'))
probes = [
    ('slice_full', lambda: a[:]),
    ('slice_full2', lambda: a[0:3]),
    ('slice_big', lambda: a[-10:10]),
    ('slice_step1', lambda: a[::1]),
    ('str', lambda: str(a)),
    ('concat_empty', lambda: a + K('')),
    ('concat_empty_left', lambda: K('') + a),
    ('repeat1', lambda: a * K(1)),
    ('rrepeat1', lambda: K(1) * a),
    ('join1', lambda: K('-').join([a])),
    ('join1_tuple', lambda: K('-').join((a,))),
    ('strip', lambda: a.strip()),
    ('lstrip', lambda: a.lstrip()),
    ('rstrip', lambda: a.rstrip()),
    ('strip_chars', lambda: a.strip(K('x'))),
    ('replace', lambda: a.replace(K('x'), K('y'))),
    ('replace_count0', lambda: a.replace(K('a'), K('y'), K(0))),
    ('replace_same', lambda: a.replace(K('a'), K('a'))),
    ('center', lambda: a.center(K(2))),
    ('ljust', lambda: a.ljust(K(3))),
    ('rjust', lambda: a.rjust(K(1))),
    ('zfill', lambda: a.zfill(K(2))),
    ('translate_none', lambda: a.translate(None)),
    ('translate_table', lambda: a.translate(string.maketrans('', ''))),
    ('translate_del', lambda: a.translate(None, K('x'))),
    ('expandtabs', lambda: a.expandtabs()),
    ('upper', lambda: K('ABC').upper()),
    ('lower', lambda: a.lower()),
    ('format_spec', lambda: format(a, K(''))),
    ('format_method', lambda: a.__format__(K(''))),
    ('percent_s', lambda: K('%s') % a),
    ('split_none', lambda: a.split()[0]),
    ('split_sep', lambda: a.split(K(','))[0]),
    ('rsplit_none', lambda: a.rsplit()[0]),
    ('partition', lambda: a.partition(K(','))[0]),
    ('rpartition', lambda: a.rpartition(K(','))[2]),
    ('splitlines', lambda: a.splitlines()[0]),
    ('encode', lambda: a.encode(K('ascii'))),
    ('decode_encode', lambda: a.decode(K('ascii'))),
    ('intern', lambda: intern(a)),
    ('getattr', lambda: getattr(a, '__str__')()),
    ('string_strip', lambda: string.strip(a)),
    ('min1', lambda: min([a])),
    ('sub_strip', lambda: sub.strip()),
    ('sub_str', lambda: str(sub)),
]


def r(f):
    try:
        x = f()
        return x is a if not isinstance(x, unicode) else 'u'
    except Exception as e:
        return 'E:' + type(e).__name__


RESULT = [(name, r(f)) for name, f in probes]
