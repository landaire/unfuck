import binascii
import _codecs as codecs
import cStringIO
import _struct as struct
import zlib
import re
from array import array

def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, str(e))

def pack_into(target, offset):
    struct.pack_into('<H', target, offset, 0x102)
    return target

def bytearray_mul(count):
    b = bytearray('ab')
    b *= count
    return b

class Twice(object):
    def __rmul__(self, other):
        return 'rmul'

c = array('c', 'ab')
h = array('h', [1, 2])
RESULT = [
    binascii.hexlify(h), binascii.crc32(c), struct.unpack('hh', h), struct.unpack_from('h', h, 2), pack_into(array('h', [0, 0]), 2),
    pack_into(array('B', [9, 9, 9]), -2), err(pack_into, array('B', [0]), 0), zlib.crc32(h), zlib.adler32(c), codecs.escape_decode(c),
    codecs.utf_8_decode(c), codecs.readbuffer_encode(h), err(codecs.charbuffer_encode, c), cStringIO.StringIO(c).read(),
    err(unicode, c, 'ascii'), err(lambda: u'x' + c), err(u'xab'.find, c), err('xab'.find, c), err(''.join, [c]), bytearray(h),
    bytearray(c), err(lambda: bytearray('x') + c), err(bytearray('xab').find, c), err(int, array('c', '12')),
    re.match('a', c).group(), re.findall('[ab]', array('B', [97, 120, 98])),
    re.findall(u'[ac\u2603\u0100\u0300x]', u'abc\u2603x\u0300'), re.sub(u'[\u0100-\u0102\u2603q]', u'-', u'a\u0101b\u2603q'),
    re.compile(u'[a\u2603\u0100-\u0300]').match(u'\u0200').group(), re.findall(u'[^a\u2603\u0100\u0300]', u'a\u2603b'),
    err(bytearray('ab').__mul__, 'x'), err(bytearray('ab').__rmul__, 1.5), err(lambda: bytearray('ab') * 'x'), err(lambda: 'x' * bytearray('ab')),
    bytearray('ab') * Twice(), err(bytearray_mul, 'x'), bytearray_mul(2), err(lambda: [1] * bytearray('ab')), 3 * bytearray('a'),
    err(lambda: bytearray('a') * 2 ** 70),
]
