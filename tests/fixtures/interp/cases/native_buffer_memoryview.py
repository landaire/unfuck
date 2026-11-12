import _struct
import array
import binascii
import _io

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))

def K(value):
    return value

view = memoryview(K('abcd'))
mutable = memoryview(bytearray(K('wxyz')))
items = array.array('b', [1, 2, 3])

def bytes_write(value):
    stream = _io.BytesIO()
    stream.write(value)
    return stream.getvalue()

RESULT = [
    attempt(bytearray, view),
    attempt(bytearray, mutable[1:3]),
    attempt(_struct.unpack_from, 'bb', view, 1),
    attempt(_struct.unpack_from, 'b', items),
    attempt(binascii.hexlify, view),
    attempt(binascii.hexlify, items),
    attempt(memoryview, items),
    attempt(lambda: view == K('abcd')),
    attempt(lambda: mutable == bytearray(K('wxyz'))),
    attempt(lambda: view == items),
    attempt(bytes_write, view),
    attempt(bytes_write, bytearray(K('q'))),
    attempt(bytes_write, items),
    attempt(bytes_write, u'x'),
    attempt(K('ab').startswith, view),
    attempt(_io.FileIO, items),
    attempt(K('abc').translate, None, view),
]
