import _io
import _md5
import _sha
import _struct
import array
import audioop
import binascii
import cStringIO
import hashlib
import re
import zlib

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, str(e))

def K(value):
    return value

data = buffer(K('xxabcdxx'), 2, 4)
samples = buffer(K('\x01\x00\x02\x00\xff\xff'))
items = array.array('h', [1, 2, 3])

def bytes_write(value):
    stream = _io.BytesIO()
    stream.write(value)
    return stream.getvalue()

def pack_into(target):
    _struct.pack_into('b', target, 0, 1)
    return target

def pack_into_view(storage, start):
    _struct.pack_into('b', memoryview(storage)[start:], 0, 1)
    return storage

RESULT = [
    binascii.hexlify(data), binascii.crc32(data), binascii.b2a_base64(data), binascii.a2b_hex(buffer(K('6162'))),
    pack_into_view(bytearray(1), 0), pack_into_view(bytearray(K('xyz')), 1), attempt(pack_into, memoryview(K('ab'))),
    hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), _md5.new(data).hexdigest(), _sha.new(data).hexdigest(),
    audioop.max(samples, 2), audioop.rms(samples, 2), audioop.add(samples, samples, 2),
    zlib.crc32(data), zlib.adler32(data), zlib.decompress(buffer(K('x\x9c\xcbH\xcd\xc9\xc9\x07\x00\x06,\x02\x15'))),
    _struct.unpack('4s', data), _struct.unpack_from('2s', data, 1), _struct.unpack_from('h', buffer(items), 2),
    attempt(pack_into, data),
    cStringIO.StringIO(data).read(), bytes_write(data),
    bytearray(data), bytearray(buffer(items)), memoryview(data).tobytes(), memoryview(buffer(K('abc'), 1))[0],
    attempt(''.join, [data, 'c']), 'ab'.join(buffer(K('xy'))),
    'abcd'.startswith(data), 'zabcd'.find(data), 'abcd'.replace(data, 'x'), u'abcd'.find(data), 'xbx'.find(buffer(u'b')),
    u'z' + data, unicode(data, 'ascii'), attempt(unicode, buffer(u'\u20ac'), 'ascii'), 'abc'.translate(None, buffer(K('b'))),
    re.match('a(b)', data).group(1), re.findall('[bc]', data),
    int(buffer(K('12'))), long(buffer(K('12'))), float(buffer(K('1.5'))),
]
