import binascii
import _codecs as codecs
import cStringIO
import strop
import _struct as struct
import zlib
B = bytearray
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

def pack_into(offset):
    b = B(6)
    struct.pack_into('<HH', b, offset, 1, 0x203)
    return b

def struct_pack_into():
    b = B('xxxxxxxx')
    struct.Struct('>I').pack_into(b, 2, 0x41424344)
    return b

ba = B('ab\x01')
s = 'xab\x01b'
RESULT = [
    binascii.hexlify(ba), binascii.unhexlify(B('6162')), binascii.crc32(ba), binascii.b2a_base64(ba), binascii.a2b_hex(B('41')),
    struct.unpack('3B', ba), struct.unpack_from('B', ba, 1), struct.Struct('3B').unpack(ba), pack_into(0), pack_into(-4),
    struct_pack_into(), err(pack_into, 4), err(struct.pack_into, 'B', 'abc', 0, 1), err(struct.pack_into, 'B', u'abc', 0, 1),
    codecs.utf_8_decode(ba), codecs.latin_1_decode(ba), codecs.ascii_decode(ba), codecs.utf_16_le_decode(B('a\x00')),
    codecs.charmap_decode(ba), cStringIO.StringIO(ba).read(),
    err(codecs.escape_decode, ba), err(codecs.readbuffer_encode, ba), err(codecs.charbuffer_encode, ba),
    err(codecs.lookup, B('utf8')), err(strop.split, ba), err(zlib.crc32, ba), err(zlib.adler32, ba),
    s.find(ba), s.rfind(B('b')), s.index(B('b')), s.count(B('b')), s.startswith(B('xa')), s.endswith((B('z'), B('b'))),
    s.split(B('a')), s.rsplit(B('b'), 1), s.partition(B('a')), s.rpartition(B('b')), s.replace(B('a'), B('A')),
    'abc'.translate(None, B('b')), 'abc'.translate(str(B(range(256))[::-1])), 'ab'.__add__(B('c')),
    err(s.strip, B('x')), err(lambda: s in B('x')),
]
