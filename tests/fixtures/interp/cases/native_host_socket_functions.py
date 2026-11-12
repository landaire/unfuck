import _socket as m

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)

def host(function, *args, **keywords):
    # Host results are never inspected: only whether validation accepted the call.
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

RESULT = [
    m.htons(K(1)), m.ntohs(K(0x0102)), m.htons(K(0x12345)), m.htons(K(0)),
    attempt(m.htons, K(-1)), attempt(m.htons, K(1.5)), attempt(m.htons, K('x')), attempt(m.htons),
    attempt(m.ntohs, K(1), K(2)), attempt(m.htons, x=K(1)),
    m.htonl(K(1)), m.ntohl(K(0x01020304)), m.htonl(K(2147483647)), m.htonl(K(2147483648)), m.htonl(K(True)),
    m.htonl(K(0L)), m.ntohl(K(4294967295)),
    attempt(m.htonl, K(-1)), attempt(m.htonl, K(-1L)), attempt(m.htonl, K(1.5)), attempt(m.ntohl, K('x')),
    attempt(m.htonl), attempt(m.htonl, K(1), K(2)),
    [attempt(m.inet_aton, K(a)) for a in ['1.2.3.4', '127.1', '0x7f.1', '01.02.03.010', '1.2.65535',
                                          '1.16777215', '0X10', '255.255.255.255', '1.2.3.0377',
                                          '256.1.1.1', 'abc', '1.2.3.4x', '1..2', '1.2.3.4.5',
                                          '1.2.3.', '0x', '1.2.3.256', '1.2.65536', '-1', ' 1.2.3.4',
                                          '4294967295', '1.2.3.4 x', ' ', '', '  ', '0x100000000', '1 2', '08']],
    attempt(m.inet_aton, K('1.2.3.4\0')), attempt(m.inet_aton, K(1)), attempt(m.inet_aton), m.inet_aton(K(u'1.2.3.4')),
    m.inet_ntoa(K('\x01\x02\x03\x04')), m.inet_ntoa(K('\xff\x00\x80\x7f')), m.inet_ntoa(K(u'abcd')),
    attempt(m.inet_ntoa, K('abc')), attempt(m.inet_ntoa, K('abcde')), attempt(m.inet_ntoa, K(5)),
    attempt(m.inet_ntoa, K(bytearray('abcd'))), attempt(m.inet_ntoa, K(u'\xe9bcd')),
    m.getdefaulttimeout(), attempt(m.setdefaulttimeout, K(-1)), attempt(m.setdefaulttimeout, K('x')),
    m.setdefaulttimeout(K(3)), m.getdefaulttimeout(), m.setdefaulttimeout(K(0.5)), m.getdefaulttimeout(),
    m.setdefaulttimeout(K(None)), m.getdefaulttimeout(), attempt(m.getdefaulttimeout, K(1)),
    attempt(m.setdefaulttimeout), attempt(m.setdefaulttimeout, K(1j)),
    attempt(m.getservbyport, K(-1)), attempt(m.getservbyport, K(70000)), attempt(m.getservbyport, K('x')),
    attempt(m.getservbyport, K(1), K(2)), attempt(m.getservbyport),
    attempt(m.gethostbyname, K(1)), attempt(m.gethostbyname), attempt(m.gethostbyname, K('a\0b')),
    attempt(m.gethostbyname_ex, K(None)), attempt(m.gethostbyaddr, K(1), K(2)),
    attempt(m.gethostname, K(1)), attempt(m.gethostname, x=K(1)),
    attempt(m.getservbyname, K(1)), attempt(m.getservbyname, K('a'), K(2)), attempt(m.getservbyname),
    attempt(m.getprotobyname, K(1)),
    attempt(m.getaddrinfo, K(1), K(2)), attempt(m.getaddrinfo, K('a')), attempt(m.getaddrinfo, K(None), K(None), K('x')),
    attempt(m.getaddrinfo, K(None), K(1), K(2), K(3), K(4), K(5), K(6)),
    attempt(m.getnameinfo, K(1), K(2)), attempt(m.getnameinfo, K(('a',)), K(0)),
    attempt(m.getnameinfo, K(('a', 1, 2 ** 21)), K(0)), attempt(m.getnameinfo, K((1, 1)), K(0)),
    attempt(m.getnameinfo, K(('a', 1, 2, 3, 4)), K(0)), attempt(m.getnameinfo, K(('a', 1)), K('x')),
    attempt(m.getnameinfo, K(('a', 'x')), K(0)),
    [m.gethostbyname(K(a)) for a in ['1.2.3.4', '<broadcast>', ' 1. 2.3.4', '-0.1.2.3', '01.2.3.4', '255.255.255.255']],
    host(m.gethostname), host(m.getaddrinfo, K(None), K(80)),
]
