# Identity of str values: the one-character cache, the empty string, and
# distinct objects that are equal.
import binascii


def K(x):
    return x


def fresh(text):
    return binascii.unhexlify(binascii.hexlify(text))


a = K('abc')
probes = [
    ('char_cache', lambda: chr(K(97)) is K('a')),
    ('fresh_char', lambda: fresh('a') is K('a')),
    ('fresh_char_index', lambda: fresh('ab')[0] is K('a')),
    ('empty', lambda: K('') is a[0:0]),
    ('fresh_equal', lambda: fresh('abc') is a),
    ('two_fresh', lambda: fresh('xyz') is fresh('xyz')),
    ('concat_distinct', lambda: a + K('d') is a + K('d')),
    ('intern_fresh', lambda: intern(fresh('abc')) is a),
    ('id_equal', lambda: id(a) == id(a[:])),
    ('id_distinct', lambda: id(fresh('abc')) != id(a)),
    ('dict_key', lambda: [k for k in {fresh('key'): 1}][0] is K('key')),
    ('list_index', lambda: [fresh('abc'), a].index(a)),
    ('str_new', lambda: str.__new__(str, a) is a),
]


def r(f):
    try:
        return f()
    except Exception as ex:
        return 'E:' + type(ex).__name__


RESULT = [(name, r(f)) for name, f in probes]
