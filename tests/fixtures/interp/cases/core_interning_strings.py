# marshal.dumps type codes ('t' interned, 's' not) of strings built by
# the common string operations.
import marshal, binascii, struct, cStringIO, string, strop, operator


def K(x):
    return x


def m(x):
    try:
        return marshal.dumps(x)[0]
    except Exception as e:
        return type(e).__name__


a = K('abc')
one = K('q')
u = K(u'x')
probes = [
    ('index', lambda: a[1]),
    ('index_neg', lambda: a[-1]),
    ('slice1', lambda: a[1:2]),
    ('slice_step', lambda: a[::3]),
    ('slice_step2', lambda: a[::2]),
    ('slice_full', lambda: a[:]),
    ('iter', lambda: list(a)[0]),
    ('chr', lambda: chr(K(65))),
    ('split', lambda: K('a b').split()[0]),
    ('split_sep', lambda: K('a,b').split(',')[0]),
    ('rsplit', lambda: K('a b').rsplit()[1]),
    ('partition', lambda: K('a,b').partition(',')[0]),
    ('partition_sep', lambda: K('a,b').partition(',')[1]),
    ('splitlines', lambda: K('a\nb').splitlines()[0]),
    ('join1', lambda: K('').join([K('a'), K('b')])),
    ('join_single', lambda: K('-').join([one])),
    ('concat', lambda: K('a') + K('b')),
    ('concat1', lambda: one + K('')),
    ('repeat', lambda: one * K(1)),
    ('repeat2', lambda: K('ab') * K(2)),
    ('percent', lambda: K('%s') % one),
    ('percent2', lambda: K('%s') % K('ab')),
    ('percent_d', lambda: K('%d') % K(5)),
    ('format', lambda: K('{}').format(one)),
    ('format_d', lambda: K('{}').format(K(5))),
    ('builtin_format', lambda: format(K(5))),
    ('builtin_format_s', lambda: format(one, K(''))),
    ('upper', lambda: one.upper()),
    ('lower', lambda: K('Q').lower()),
    ('swapcase', lambda: one.swapcase()),
    ('capitalize', lambda: one.capitalize()),
    ('title', lambda: one.title()),
    ('strip', lambda: K(' q ').strip()),
    ('strip_none', lambda: one.strip()),
    ('lstrip', lambda: K(' q').lstrip()),
    ('rstrip', lambda: K('q ').rstrip()),
    ('strip_chars', lambda: K('xqx').strip(K('x'))),
    ('replace', lambda: K('a').replace(K('a'), K('b'))),
    ('replace_none', lambda: one.replace(K('z'), K('y'))),
    ('replace_delete', lambda: K('ab').replace(K('a'), K(''))),
    ('center', lambda: one.center(K(1))),
    ('ljust', lambda: K('').ljust(K(1))),
    ('zfill', lambda: K('').zfill(K(1))),
    ('expandtabs', lambda: one.expandtabs()),
    ('translate', lambda: one.translate(None)),
    ('translate_table', lambda: one.translate(string.maketrans('q', 'r'))),
    ('str_int', lambda: str(K(5))),
    ('repr_int', lambda: repr(K(5))),
    ('str_long', lambda: str(K(5L))),
    ('hex', lambda: hex(K(5))),
    ('oct', lambda: oct(K(0))),
    ('str_float', lambda: str(K(5.0))),
    ('str_bool', lambda: str(K(True))),
    ('str_none', lambda: str(None)),
    ('str_str', lambda: str(one)),
    ('str_unicode', lambda: str(u)),
    ('encode_ascii', lambda: u.encode('ascii')),
    ('encode_latin1', lambda: u.encode('latin-1')),
    ('encode_utf8', lambda: u.encode('utf-8')),
    ('encode_utf8_long', lambda: K(u'xy').encode('utf-8')),
    ('decode', lambda: one.decode('ascii').encode('ascii')),
    ('str_encode_hex', lambda: K('A').encode('hex')),
    ('unhexlify', lambda: binascii.unhexlify(K('41'))),
    ('a2b_hex', lambda: binascii.a2b_hex(K('4142'))),
    ('hexlify', lambda: binascii.hexlify(K(''))),
    ('struct_pack', lambda: struct.pack('B', K(65))),
    ('struct_pack_c', lambda: struct.unpack('c', K('A'))[0]),
    ('struct_unpack_s', lambda: struct.unpack('1s', K('A'))[0]),
    ('cstringio_getvalue', lambda: cStringIO.StringIO(K('ab') + K('c')).read(K(1))),
    ('cstringio_full', lambda: cStringIO.StringIO(one).getvalue()),
    ('marshal_loads', lambda: marshal.loads(K('s\x01\x00\x00\x00A'))),
    ('marshal_loads_t', lambda: marshal.loads(K('t\x02\x00\x00\x00AB'))),
    ('repr_str', lambda: repr(one)),
    ('backquote', lambda: repr(K(1))),
    ('getitem_op', lambda: operator.getitem(a, K(0))),
    ('min', lambda: min(a)),
    ('sorted', lambda: sorted(a)[0]),
    ('reversed', lambda: list(reversed(a))[0]),
    ('enumerate', lambda: list(enumerate(a))[0][1]),
    ('zip', lambda: zip(a)[0][0]),
    ('map', lambda: map(None, a)[0]),
    ('filter', lambda: filter(None, a)),
    ('filter1', lambda: filter(None, one)),
    ('tuple', lambda: tuple(a)[0]),
    ('set', lambda: list(set(one))[0]),
    ('strop_upper', lambda: strop.upper(one)),
    ('strop_join', lambda: strop.join([K('a'), K('b')], K(''))),
    ('string_join', lambda: string.join([K('a'), K('b')], K(''))),
    ('bytearray_str', lambda: str(bytearray(K('a')))),
    ('bytearray_bytes', lambda: bytes(bytearray(K('ab')))),
    ('memoryview_tobytes', lambda: memoryview(K('ab')).tobytes()),
    ('memoryview_index', lambda: memoryview(K('ab'))[0]),
    ('unicode_index', lambda: str(u[0])),
    ('ord_chr', lambda: chr(ord(one))),
    ('mod_long', lambda: K('%s') % K(5L)),
    ('raw_tuple', lambda: str(K(()))),
    ('dict_repr', lambda: str(K({}))),
]

def r(f):
    try:
        return m(f())
    except Exception as e:
        return 'E:' + type(e).__name__


RESULT = [(name, r(f)) for name, f in probes]
