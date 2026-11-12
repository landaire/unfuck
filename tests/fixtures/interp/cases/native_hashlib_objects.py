import hashlib
import _md5
import _sha
import _sha256
import _sha512

def K(value):
    return value

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

def lifecycle(f):
    original = f(K('abc'))
    copy = original.copy()
    original.update(K('def'))
    first = original.digest()
    original.update(K('ghi'))
    copy.update(K('xyz'))
    return (copy.hexdigest(), first == f(K('abcdef')).digest(), original.hexdigest(), original.hexdigest() == f(K('abcdefghi')).hexdigest())

def piecewise(f):
    hash = f()
    for chunk in [K('a') * 63, K('b'), K('c') * 65, '', K('d') * 129]:
        hash.update(chunk)
    return hash.hexdigest() == f(K('a') * 63 + K('b') + K('c') * 65 + K('d') * 129).hexdigest()

constructors = [
    hashlib.md5, hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512,
    _md5.new, _sha.new, _sha256.sha224, _sha256.sha256, _sha512.sha384, _sha512.sha512,
]
builtin = constructors[6:]

def attributes(hash):
    return (hash.name, hash.digest_size, hash.block_size, hash.digestsize, type(hash).__name__, type(hash).__module__)

RESULT = (
    [lifecycle(f) for f in constructors],
    [piecewise(f) for f in constructors],
    [(int(f().digest_size), int(f().block_size), int(f().digestsize)) for f in constructors],
    [attributes(f()) for f in builtin],
    [repr(f()).startswith('<%s.%s object at 0x' % (type(f()).__module__, type(f()).__name__)) for f in builtin],
    [hashlib.new(name).name for name in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']],
    [hashlib.new(name, K('abc')).hexdigest() == hashlib.new(name.lower(), K('abc')).hexdigest() for name in ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']],
    _md5.MD5Type is type(_md5.new()), _md5.digest_size, hasattr(_md5, 'md5'),
    _sha.blocksize, _sha.digestsize, _sha.digest_size,
    sorted(name for name in dir(_sha256) if not name.startswith('__')),
    sorted(name for name in dir(_sha512) if not name.startswith('__')),
    type(_sha256.sha224()) is type(_sha256.sha256()), type(_sha256.sha224().copy()).__name__, type(_sha512.sha384().copy()).__name__,
    _sha.new(string=K('abc')).hexdigest(), _sha256.sha256(string=K('abc')).hexdigest(), _sha512.sha384(string='').hexdigest(),
    err(_md5.new, string='abc'), err(_md5.new, 'a', 'b'), err(_sha.new, 'a', 'b'), err(_sha256.sha256, foo='a'),
    err(_md5.new, 5), err(_sha.new, None), err(_sha512.sha512, 1.5),
    err(_md5.new().update), err(_md5.new().update, 'a', 'b'), err(_sha256.sha224().update, 5),
    err(_sha512.sha512().digest, 1), err(_sha.new().copy, 1), err(_md5.new().hexdigest, x=1),
    err(setattr, _md5.new(), 'name', 'x'), err(setattr, _sha.new(), 'digest_size', 1),
    err(setattr, _sha256.sha256(), 'digest_size', 1), err(setattr, _sha512.sha512(), 'block_size', 1),
    err(_md5.MD5Type), err(type(_sha256.sha256()).update, _sha256.sha224(), 'a'),
    err(_md5.new, u'caf\xe9'),
)
