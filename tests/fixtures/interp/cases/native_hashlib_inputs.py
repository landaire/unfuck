import hashlib
import _md5
import _sha256

def K(value):
    return value

class Text(str):
    pass

constructors = [hashlib.md5, hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512, _md5.new, _sha256.sha256]

def updated(f, data):
    hash = f(K('prefix'))
    hash.update(data)
    return hash.hexdigest()

RESULT = (
    [f(bytearray(K('abc'))).hexdigest() == f(K('abc')).hexdigest() for f in constructors],
    [f(K(u'abc')).hexdigest() == f(K('abc')).hexdigest() for f in constructors],
    [f(Text(K('abc'))).hexdigest() == f(K('abc')).hexdigest() for f in constructors],
    [updated(f, bytearray(K('\x00\xff') * 70)) for f in constructors],
    [updated(f, K(u'unicode text')) for f in constructors],
    [hashlib.new(name, bytearray(K('abc'))).hexdigest() for name in ['MD5', 'sha256']],
    [hashlib.new(name, K(u'abc')).hexdigest() for name in ['SHA1', 'sha512']],
    hashlib.md5(bytearray()).hexdigest(), hashlib.sha256(u'').hexdigest(),
    hashlib.md5(K('abc')).hexdigest(),
)
