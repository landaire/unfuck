import _ssl

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

def call(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)

COMMON = [
    'ALERT_DESCRIPTION_ACCESS_DENIED', 'ALERT_DESCRIPTION_BAD_CERTIFICATE',
    'ALERT_DESCRIPTION_BAD_CERTIFICATE_HASH_VALUE', 'ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE',
    'ALERT_DESCRIPTION_BAD_RECORD_MAC', 'ALERT_DESCRIPTION_CERTIFICATE_EXPIRED',
    'ALERT_DESCRIPTION_CERTIFICATE_REVOKED', 'ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN',
    'ALERT_DESCRIPTION_CERTIFICATE_UNOBTAINABLE', 'ALERT_DESCRIPTION_CLOSE_NOTIFY',
    'ALERT_DESCRIPTION_DECODE_ERROR', 'ALERT_DESCRIPTION_DECOMPRESSION_FAILURE',
    'ALERT_DESCRIPTION_DECRYPT_ERROR', 'ALERT_DESCRIPTION_HANDSHAKE_FAILURE',
    'ALERT_DESCRIPTION_ILLEGAL_PARAMETER', 'ALERT_DESCRIPTION_INSUFFICIENT_SECURITY',
    'ALERT_DESCRIPTION_INTERNAL_ERROR', 'ALERT_DESCRIPTION_NO_RENEGOTIATION',
    'ALERT_DESCRIPTION_PROTOCOL_VERSION', 'ALERT_DESCRIPTION_RECORD_OVERFLOW',
    'ALERT_DESCRIPTION_UNEXPECTED_MESSAGE', 'ALERT_DESCRIPTION_UNKNOWN_CA',
    'ALERT_DESCRIPTION_UNKNOWN_PSK_IDENTITY', 'ALERT_DESCRIPTION_UNRECOGNIZED_NAME',
    'ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE', 'ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION',
    'ALERT_DESCRIPTION_USER_CANCELLED', 'CERT_NONE', 'CERT_OPTIONAL', 'CERT_REQUIRED',
    'HAS_ALPN', 'HAS_ECDH', 'HAS_SNI', 'HAS_TLS_UNIQUE',
    'OP_CIPHER_SERVER_PREFERENCE', 'OP_NO_COMPRESSION', 'OP_NO_SSLv3', 'OP_NO_TLSv1',
    'OP_NO_TLSv1_1', 'OP_NO_TLSv1_2',
    'PROTOCOL_SSLv23', 'PROTOCOL_TLSv1', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1_2',
    'SSL_ERROR_EOF', 'SSL_ERROR_INVALID_ERROR_CODE', 'SSL_ERROR_SSL', 'SSL_ERROR_SYSCALL',
    'SSL_ERROR_WANT_CONNECT', 'SSL_ERROR_WANT_READ', 'SSL_ERROR_WANT_WRITE',
    'SSL_ERROR_WANT_X509_LOOKUP', 'SSL_ERROR_ZERO_RETURN',
    'VERIFY_CRL_CHECK_CHAIN', 'VERIFY_CRL_CHECK_LEAF', 'VERIFY_DEFAULT', 'VERIFY_X509_STRICT',
    'VERIFY_X509_TRUSTED_FIRST',
]

ERRORS = ['SSLError', 'SSLZeroReturnError', 'SSLWantReadError', 'SSLWantWriteError', 'SSLSyscallError', 'SSLEOFError']

def hierarchy():
    rows = []
    for name in ERRORS:
        cls = getattr(_ssl, K(name))
        rows.append((cls.__name__, cls.__module__, sorted(cls.__dict__.keys()),
                     [base.__name__ for base in cls.__mro__], cls.__mro__[-7].__module__))
    return rows

def errors():
    e = _ssl.SSLError(K(1), K('message'))
    plain = _ssl.SSLWantReadError(K('only'))
    try:
        raise _ssl.SSLEOFError(K(8), K('EOF occurred'))
    except IOError as caught:
        eof = (type(caught).__name__, str(caught))
    rows = [str(e), e.args, str(plain), eof, isinstance(e, IOError), issubclass(_ssl.SSLZeroReturnError, IOError)]
    named = _ssl.SSLError(K(1), K('m'), K('f'))
    rows.append((named.args, named.errno, named.strerror, named.filename, str(named)))
    named.strerror = K('z')
    rows.append(str(named))
    named.args = (K(5),)
    rows.append((str(named), named.strerror))
    plain.strerror = K(u'u')
    rows.append((repr(str(plain)), plain.errno))
    rows.append(call(str, _ssl.SSLError(K(1), K(2))))
    io = IOError(K(1), K('m'), K('f'))
    rows.append((io.args, str(io), repr(io)))
    io.filename = None
    rows.append(str(io))
    del io.filename
    rows.append((str(io), io.filename))
    many = IOError(K(1), K(2), K(3), K(4))
    rows.append((str(many), many.errno, str(IOError(K(1))), str(OSError(K(2), K('x')))))
    rows.append(repr(EnvironmentError(K(1), K('a'), K('b'))))
    return rows

def objects():
    rows = []
    for args in [(), (K(-1),), (K('x'),), (K(1.5),), (K(1), K(2))]:
        rows.append(call(_ssl.nid2obj, *args))
    for args in [(), (K('a\0b'),), (K(1),), (K('2.5'), K(1), K(2))]:
        rows.append(call(_ssl.txt2obj, *args))
    rows.append(call(_ssl.txt2obj, K('2.5.4.3'), bogus=K(1)))
    rows.append(call(_ssl.nid2obj, nid=K(1)))
    return rows

def functions():
    return [
        attempt(_ssl.RAND_add), attempt(_ssl.RAND_add, K('x')), attempt(_ssl.RAND_add, K(1), K(1.0)),
        attempt(_ssl.RAND_add, K('x'), K('y')), attempt(_ssl.RAND_add, K('x'), K(1.0), K(2)),
        _ssl.RAND_add(K('seed'), K(1.0)), _ssl.RAND_add(K(u'seed'), K(2)), _ssl.RAND_add(K('a\0b'), K(0.5)),
        attempt(_ssl.RAND_add, x=K(1)), attempt(_ssl.RAND_status, K(1)),
        attempt(_ssl.get_default_verify_paths, K(1)), len(_ssl.get_default_verify_paths()),
        _ssl.get_default_verify_paths()[0], _ssl.get_default_verify_paths()[2],
        attempt(_ssl._test_decode_cert), attempt(_ssl._test_decode_cert, K(1)),
        attempt(_ssl._test_decode_cert, K('a\0b')), attempt(_ssl._test_decode_cert, K('a'), K('b')),
        attempt(_ssl._test_decode_cert, path=K('a')),
        _ssl.__name__,
        [name in dir(_ssl) for name in ('OPENSSL_VERSION', 'OPENSSL_VERSION_INFO', 'OPENSSL_VERSION_NUMBER', '_OPENSSL_API_VERSION')],
    ]

# The client links a different OpenSSL than the python.org build, so the
# SSLv2 and SSLv3 protocols, OP_ALL, OP_NO_SSLv2, OP_SINGLE_DH_USE, and
# OP_SINGLE_ECDH_USE are left out.
def windows():
    names = ('PROTOCOL_TLS', 'HAS_TLSv1_3', 'OP_NO_TLSv1_3', 'RAND_egd', 'HAS_NPN', 'RAND_status')
    return [
        [hasattr(_ssl, name) for name in names], _ssl.HAS_NPN,
        call(_ssl.enum_certificates), call(_ssl.enum_certificates, K(1)), call(_ssl.enum_crls, store_name=K(None)),
    ]

RESULT = [
    [(name, getattr(_ssl, name)) for name in COMMON],
    hierarchy(), errors(), objects(), functions(), windows(),
]
