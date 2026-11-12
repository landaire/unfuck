import zlib

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

long_text = 'hello world' * 1000
RESULT = (
    zlib.crc32(''), zlib.crc32('abc'), zlib.crc32('abc', -1), zlib.crc32('abc', 2 ** 40),
    zlib.crc32(long_text), zlib.crc32(u'abc'), zlib.crc32('def', zlib.crc32('abc')),
    zlib.adler32(''), zlib.adler32('abc'), zlib.adler32('abc', 2 ** 32 + 5), zlib.adler32('\xff' * 6000),
    zlib.adler32(long_text), zlib.adler32('x', -1), zlib.adler32('short text', -1), zlib.adler32('', -1),
    zlib.adler32('\xff' * 20, 0xfff0fff0),
    err(zlib.crc32, 'abc', 1.5), err(zlib.crc32, 'abc', 'x'), err(zlib.crc32, 5), err(zlib.crc32, None),
    err(zlib.adler32), err(zlib.adler32, 'a', 1, 2), err(zlib.crc32, 'a', start=1),
    zlib.MAX_WBITS, zlib.DEFLATED, zlib.DEF_MEM_LEVEL, zlib.Z_BEST_SPEED, zlib.Z_BEST_COMPRESSION,
    zlib.Z_DEFAULT_COMPRESSION, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_DEFAULT_STRATEGY,
    zlib.Z_FINISH, zlib.Z_NO_FLUSH, zlib.Z_SYNC_FLUSH, zlib.Z_FULL_FLUSH, zlib.__version__,
    issubclass(zlib.error, Exception), zlib.error.__module__,
)
