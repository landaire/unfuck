import array
import binascii
import cStringIO
import io
import mmap
import re
import struct
import zlib


def K(x):
    return x


def attempt(f, *args):
    try:
        return f(*args)
    except Exception as e:
        return (type(e).__name__, e.args)


m = mmap.mmap(K(-1), K(8))
m.write('abcdefgh')
r = mmap.mmap(-1, 8, access=mmap.ACCESS_READ)
c = mmap.mmap(-1, 8, access=mmap.ACCESS_COPY)
out = []
out.append([attempt(memoryview, m), attempt(bytearray, m), attempt(lambda: 'xy' + m), attempt(''.join, [m]), attempt(lambda: m in 'x')])
out.append([attempt(struct.pack_into, 'h', m, 0, 0x4142), m[:], attempt(struct.pack_into, 'h', r, 0, 1), attempt(struct.pack_into, 'h', c, 6, 0x4142), c[:]])
out.append([attempt(struct.pack_into, '4s', m, 6, 'xyzw'), attempt(struct.pack_into, 'h', m, -2, 0x3132), m[:]])
out.append([attempt(struct.unpack_from, 'h', m, 0), attempt(struct.unpack, '8s', m), attempt(struct.unpack_from, '2s', r, 3), attempt(struct.unpack, 'h', m)])
a = array.array('c')
out.append([attempt(a.fromstring, m), a.tostring(), attempt(array.array('b').fromstring, r)])
out.append([attempt(binascii.hexlify, m), attempt(zlib.crc32, m), attempt(binascii.crc32, r)])
out.append([attempt(lambda: 'xBAcdy'.find(m)), attempt(lambda: 'BAcdef12'.startswith(m)), attempt(lambda: 'abc'.find(r)), attempt(lambda: 'q'.join(['a', 'b']).count(m))])
out.append([attempt(lambda: cStringIO.StringIO(m).read()), attempt(lambda: io.BytesIO(m).read())])
out.append([attempt(lambda: re.search('c(d.)', m).group(1)), attempt(lambda: re.findall('[a-z]', m)), attempt(lambda: re.match('x', r))])
m[0] = 'Q'
out.append([attempt(binascii.hexlify, m), attempt(struct.unpack_from, 'c', m)])
closed = mmap.mmap(-1, 8)
closed.close()
out.append([
    attempt(struct.unpack_from, 'h', closed), attempt(struct.pack_into, 'h', closed, 0, 1), attempt(bytearray, closed),
    attempt(array.array('c').fromstring, closed), attempt(binascii.hexlify, closed), attempt(zlib.crc32, closed),
    attempt(cStringIO.StringIO, closed), attempt(memoryview, closed),
    attempt(struct.unpack, '8s', closed), attempt(lambda: 'abc'.find(closed)), attempt(lambda: 'x'.translate(closed)),
    attempt(lambda: 'abc'.startswith(closed)), attempt(re.search, 'a', closed),
    attempt(io.FileIO, closed), attempt(io.FileIO, closed, 'q'),
])
RESULT = out
