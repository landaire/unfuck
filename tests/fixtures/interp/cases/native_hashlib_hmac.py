import binascii
import hashlib
import hmac

def K(value):
    return value

def pbkdf2(*args, **kwargs):
    return binascii.hexlify(hashlib.pbkdf2_hmac(*args, **kwargs))

mac = hmac.new(K('key'), K('The quick brown fox'), hashlib.sha256)
copy = mac.copy()
mac.update(K(' jumps over the lazy dog'))

RESULT = (
    hmac.new(K('key'), K('message')).hexdigest(),
    hmac.new(K('key'), K('message'), hashlib.md5).hexdigest(),
    hmac.new(K('key'), K('message'), hashlib.sha256).hexdigest(),
    hmac.new(K('key'), K('message'), hashlib.sha1).hexdigest(),
    hmac.new(K('key'), K('message'), hashlib.sha512).hexdigest(),
    hmac.new(K('k') * 200, K('message'), hashlib.sha256).hexdigest(),
    hmac.new(K('k') * 200, K('message'), hashlib.sha384).hexdigest(),
    hmac.new(K(''), K(''), hashlib.md5).digest(),
    mac.hexdigest(), copy.hexdigest(), int(mac.digest_size),
    hmac.compare_digest(mac.digest(), hmac.new(K('key'), K('The quick brown fox jumps over the lazy dog'), hashlib.sha256).digest()),
    pbkdf2('sha1', K('password'), K('salt'), 1),
    pbkdf2('sha1', K('password'), K('salt'), 2, 25),
    pbkdf2('sha256', K('password'), K('salt'), 3),
    pbkdf2('sha512', K('passwordPASSWORDpassword'), K('saltSALTsaltSALT'), 2, 100),
    pbkdf2('md5', K('p') * 100, K('s'), 2, dklen=40),
)
