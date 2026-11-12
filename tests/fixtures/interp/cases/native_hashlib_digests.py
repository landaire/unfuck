import hashlib
import _md5
import _sha
import _sha256
import _sha512

def K(value):
    return value

inputs = ['', K('abc'), K('The quick brown fox jumps over the lazy dog'), K('0123456789abcdef') * 9, K('\xff\x00') * 1000]

constructors = [
    hashlib.md5, hashlib.sha1, hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512,
    _md5.new, _sha.new, _sha256.sha224, _sha256.sha256, _sha512.sha384, _sha512.sha512,
]

RESULT = (
    [[f(data).hexdigest() for data in inputs] for f in constructors],
    [[f(data).digest() for data in inputs[:3]] for f in constructors],
    [f().hexdigest() for f in constructors],
    [hashlib.new(name, K('abc')).hexdigest() for name in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']],
    [len(f().digest()) for f in constructors],
)
