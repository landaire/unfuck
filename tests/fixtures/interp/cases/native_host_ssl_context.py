import _ssl

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

def assign(context, name, value):
    setattr(context, name, value)

def remove(context, name):
    delattr(context, name)

class Callback(object):
    def __call__(self, *args):
        return None

Context = _ssl._SSLContext

class SubContext(Context):
    pass

def bookkeeping():
    c = Context(K(_ssl.PROTOCOL_SSLv23))
    steps = [c.verify_mode, type(c.verify_mode).__name__, c.check_hostname, c.verify_flags, type(c.options).__name__]
    steps.append(c.options & K(_ssl.OP_NO_SSLv3) != 0)
    steps.append(c.options & K(_ssl.OP_NO_TLSv1) != 0)
    c.options |= K(_ssl.OP_NO_TLSv1)
    steps.append(c.options & K(_ssl.OP_NO_TLSv1) != 0)
    c.options &= ~K(_ssl.OP_NO_TLSv1)
    steps.append(c.options & K(_ssl.OP_NO_TLSv1) != 0)
    steps.append(attempt(assign, c, 'check_hostname', K(True)))
    c.verify_mode = K(_ssl.CERT_REQUIRED)
    steps.append(c.verify_mode)
    c.check_hostname = K(1)
    steps.append(c.check_hostname)
    steps.append(attempt(assign, c, 'verify_mode', K(_ssl.CERT_NONE)))
    c.verify_mode = K(_ssl.CERT_OPTIONAL)
    steps.append(c.verify_mode)
    c.check_hostname = K(0)
    c.verify_mode = K(_ssl.CERT_NONE)
    steps.append((c.verify_mode, c.check_hostname))
    c.verify_flags = K(_ssl.VERIFY_CRL_CHECK_LEAF)
    steps.append(c.verify_flags)
    c.verify_flags = K(0x100)
    steps.append(c.verify_flags)
    c.verify_flags = K(0)
    steps.append(c.verify_flags)
    steps.append(sorted(c.session_stats().items()))
    steps.append(sorted(c.cert_store_stats().items()))
    steps.append(c.get_ca_certs())
    steps.append(c.get_ca_certs(binary_form=K(True)))
    steps.append(c.set_servername_callback(K(None)))
    steps.append(c.set_servername_callback(Callback()))
    return steps

def subclassing():
    s = SubContext(K(_ssl.PROTOCOL_TLSv1))
    return [type(s).__name__, isinstance(s, Context), s.verify_mode, s.check_hostname]

c = Context(K(_ssl.PROTOCOL_TLSv1_2))
RESULT = [
    Context.__module__, Context.__name__,
    _ssl._SSLSocket.__module__, _ssl._SSLSocket.__name__,
    type(Context.__dict__['options']).__name__, type(Context.__dict__['verify_mode']).__name__,
    type(Context.__dict__['check_hostname']).__name__, type(Context.__dict__['verify_flags']).__name__,
    type(_ssl._SSLSocket.__dict__['context']).__name__,
    attempt(Context), attempt(Context, K(99)), attempt(Context, K(-1)), attempt(Context, K('x')),
    attempt(Context, K(1.5)), attempt(Context, protocol=K(77)), attempt(Context, K(2), K(3)),
    attempt(Context, K(2), x=K(1)),
    attempt(_ssl._SSLSocket), attempt(type, 'X', (_ssl._SSLSocket,), {}),
    bookkeeping(), subclassing(),
    attempt(assign, c, 'verify_mode', K(3)), attempt(assign, c, 'verify_mode', K(-1)),
    attempt(assign, c, 'verify_mode', K('x')), attempt(assign, c, 'verify_mode', K(1.0)),
    attempt(assign, c, 'options', K('x')), attempt(assign, c, 'options', K(1.5)),
    attempt(assign, c, 'verify_flags', K('x')),
    attempt(remove, c, 'verify_mode'), attempt(remove, c, 'check_hostname'),
    attempt(c.set_ciphers), attempt(c.set_ciphers, K(1)), attempt(c.set_ciphers, K('a\0b')),
    attempt(c.set_ciphers, K('a'), K('b')), attempt(c.set_ciphers, ciphers=K('a')),
    attempt(c._set_alpn_protocols, K(None)),
    attempt(c._set_alpn_protocols), attempt(c._set_alpn_protocols, K('a'), K('b')),
    attempt(c.load_cert_chain), attempt(c.load_cert_chain, K(1)), attempt(c.load_cert_chain, K('a\0b')),
    attempt(c.load_cert_chain, K('a'), K(1)), attempt(c.load_cert_chain, K('a'), None, K(1)),
    attempt(c.load_cert_chain, K('a'), x=K(1)), attempt(c.load_cert_chain, K('a'), K('b'), K('c'), K('d')),
    attempt(c.load_verify_locations), attempt(c.load_verify_locations, None, None, None),
    attempt(c.load_verify_locations, K(1)), attempt(c.load_verify_locations, None, K(2)),
    attempt(c.load_verify_locations, cadata=K(3)), attempt(c.load_verify_locations, cadata=K(u'\xe9')),
    attempt(c.load_verify_locations, cadata=K('')), attempt(c.load_verify_locations, cadata=K(u'')),
    attempt(c.load_verify_locations, x=K(1)),
    attempt(c.load_dh_params), attempt(c.load_dh_params, K('a'), K('b')),
    attempt(c.session_stats, K(1)), attempt(c.cert_store_stats, K(1)), attempt(c.set_default_verify_paths, K(1)),
    attempt(c.get_ca_certs, K(1), K(2)), attempt(c.get_ca_certs, x=K(1)),
    attempt(c.set_ecdh_curve), attempt(c.set_ecdh_curve, K(1)),
    attempt(c.set_servername_callback), attempt(c.set_servername_callback, K(1)),
    attempt(c.set_servername_callback, K(1), K(2)), attempt(c.set_servername_callback, cb=K(None)),
    attempt(c._wrap_socket), attempt(c._wrap_socket, K(1), K(0)), attempt(c._wrap_socket, K(1)),
    attempt(c._wrap_socket, K(1), K(2), K(3), K(4), K(5)),
    attempt(Context.options.__get__, K(1)), attempt(Context.set_ciphers, K(1), K('a')),
    attempt(_ssl._SSLSocket.do_handshake, K(1)), attempt(_ssl._SSLSocket.read, K(1), K(1)),
    attempt(_ssl._SSLSocket.cipher),
    attempt(c._set_npn_protocols, K(1)), attempt(c.load_dh_params, K(1)),
    attempt(c._set_npn_protocols, K('\x02h2')), attempt(c._set_npn_protocols, bytearray(K('\x02h2'))),
    attempt(assign, c, 'verify_flags', K(1.5)), attempt(remove, c, 'options'), attempt(remove, c, 'verify_flags'),
    attempt(assign, c, 'verify_flags', K(-1)),
]
