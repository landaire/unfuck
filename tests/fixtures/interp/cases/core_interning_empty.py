# Empty and one-character results. Strings that _PyString_Resize shrinks to
# empty stay distinct from the interned empty string.
import marshal, binascii, struct, cStringIO, string, strop, zlib


def K(x):
    return x


class S(str):
    pass


def m(x):
    return marshal.dumps(x)[0]


e = K('')
a = K('abc')
probes = [
    ('repeat0', lambda: a * K(0)),
    ('repeat_neg', lambda: a * K(-1)),
    ('empty_repeat', lambda: e * K(3)),
    ('sub_concat', lambda: S(e) + e),
    ('sub_concat_type', lambda: type(S(e) + e).__name__),
    ('concat_sub_empty', lambda: e + S(a)),
    ('slice_empty', lambda: a[1:1]),
    ('slice_empty_step', lambda: a[2:1:1]),
    ('format_spec_empty', lambda: format(e, K('s'))),
    ('join_empty', lambda: e.join([e, e])),
    ('join_none', lambda: e.join([])),
    ('upper_empty', lambda: e.upper()),
    ('strip_empty', lambda: K('  ').strip()),
    ('replace_empty', lambda: K('aa').replace(K('a'), e)),
    ('translate_delete', lambda: a.translate(None, a)),
    ('translate_table_delete', lambda: a.translate(string.maketrans(e, e), a)),
    ('strop_translate', lambda: strop.translate(a, string.maketrans(e, e), a)),
    ('encode_ascii_ignore', lambda: K(u'\u20ac').encode('ascii', 'ignore')),
    ('encode_latin1_ignore', lambda: K(u'\u20ac').encode('latin-1', 'ignore')),
    ('escape_encode_empty', lambda: e.encode('string_escape')),
    ('format_method_empty', lambda: K('{0}').format(e)),
    ('percent_empty', lambda: K('%s') % e),
    ('decompress_empty', lambda: zlib.decompress(K('x\x9c\x03\x00\x00\x00\x00\x01'))),
    ('split_empty', lambda: K(',').split(K(','))[0]),
    ('str_sub_empty', lambda: str(S(e))),
    ('unhexlify_empty', lambda: binascii.unhexlify(e)),
    ('b2a_hex_empty', lambda: binascii.b2a_hex(e)),
    ('struct_empty', lambda: struct.pack('')),
    ('cstringio_empty', lambda: cStringIO.StringIO(e).getvalue()),
    ('cstringio_read_empty', lambda: cStringIO.StringIO(a).read(K(0))),
    ('encode_empty', lambda: K(u'').encode('ascii')),
    ('encode_utf8_empty', lambda: K(u'').encode('utf-8')),
    ('str_unicode_empty', lambda: str(K(u''))),
    ('expandtabs_empty', lambda: e.expandtabs()),
    ('zfill_empty', lambda: e.zfill(K(0))),
    ('center_empty', lambda: e.center(K(0))),
    ('lower_empty', lambda: e.lower()),
    ('chr_join', lambda: e.join(map(chr, []))),
    ('repr_empty_list', lambda: repr([])),
    ('marshal_loads_empty', lambda: marshal.loads(K('s\x00\x00\x00\x00'))),
    ('decode_hex', lambda: e.decode('hex')),
    ('getslice_sub', lambda: S(a)[0:0]),
    ('str_mul_sub', lambda: S(a) * 1),
    ('str_mul_sub_type', lambda: type(S(a) * 1).__name__),
    ('readline', lambda: cStringIO.StringIO(e).readline()),
    ('split_sep_concat', lambda: (a + K('x')).split(K('x'))[1]),
    ('partition_none', lambda: a.partition(K(','))[1]),
    ('rjust1', lambda: K('a').rjust(K(2))),
    ('hex_int', lambda: hex(K(1))),
    ('str_neg', lambda: str(K(-1))),
    ('str_float_nan', lambda: str(K(1e300) * 0)),
    ('long_str', lambda: str(K(1L))),
    ('long_repr', lambda: repr(K(1L))),
    ('oct_long', lambda: oct(K(1L))),
    ('bool_repr', lambda: repr(K(False))),
    ('none_repr', lambda: repr(None)),
    ('ellipsis', lambda: repr(Ellipsis)),
    ('notimpl', lambda: repr(NotImplemented)),
    ('type_name', lambda: int.__name__),
    ('func_name', lambda: m.__name__),
    ('lambda_name', lambda: (lambda: 0).__name__),
    ('method_name', lambda: a.upper.__name__),
    ('builtin_name', lambda: len.__name__),
    ('module_name', lambda: string.__name__),
    ('class_name', lambda: S.__name__),
    ('doc', lambda: S.__doc__),
    ('file', lambda: string.__file__[0]),
]


def r(f):
    try:
        x = f()
        return m(x), len(x)
    except Exception as ex:
        return 'E:' + type(ex).__name__


RESULT = [(name, r(f)) for name, f in probes]
