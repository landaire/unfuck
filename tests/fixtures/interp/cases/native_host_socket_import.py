import socket
import _socket
import types

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

# The `_socket.socket` a wrapper holds is unknown; closing replaces it with `_closedsocket`.
s = socket.socket()
wrapped = [type(s).__name__]
s.close()
wrapped.extend([type(s._sock).__name__, attempt(s.recv, K(1)), attempt(s.fileno)])

socket.setdefaulttimeout(K(3.5))
defaulted = [socket.getdefaulttimeout(), host(socket.socket, socket.AF_INET, socket.SOCK_DGRAM)]
socket.setdefaulttimeout(K(None))

class A(object):
    pass

class B(object):
    pass

def f(self):
    return 'f'

B.a_only = types.MethodType(f, None, (A,))
B.bad = types.MethodType(f, None, None)
B.own = types.MethodType(f, None, B)
methods = [
    B.a_only.im_self is None, B().a_only.im_self is None, B().own.im_self is not None, attempt(lambda: B.bad), attempt(lambda: B().bad), B().own(),
    attempt(types.MethodType.__new__, int, f, None, int), attempt(types.MethodType.__new__, K(1), f, None, int),
    attempt(types.MethodType.__new__), attempt(types.MethodType, f), attempt(types.MethodType, K(1), None, int),
    attempt(types.MethodType, f, None), attempt(types.MethodType, f, None, int, x=1),
]

f = socket._fileobject(None)

RESULT = [
    isinstance(socket.socket, type), socket.socket.__name__, socket.SocketType is socket.socket,
    socket.error is _socket.error, socket.timeout is _socket.timeout, socket._realsocket is _socket.socket,
    socket._fileobject.__name__, socket._fileobject.default_bufsize, f.name, f.closed, f.bufsize,
    socket.AF_INET, socket.SOCK_STREAM, socket.has_ipv6, socket.EBADF, socket.EINTR,
    'create_connection' in socket.__all__, 'getfqdn' in socket.__all__, 'socket' in socket.__all__,
    callable(socket.getfqdn), socket._GLOBAL_DEFAULT_TIMEOUT is not None,
    socket._delegate_methods, socket.inet_ntoa(K('\x7f\x00\x00\x01')), socket.htons(K(1)),
    (10035, socket.errorTab[10035]), (10060, socket.errorTab[10060]), len(socket.errorTab),
    attempt(socket.socket, K('x')), attempt(socket.create_connection, K(('a', 1, 2))),
    wrapped, defaulted, methods,
]
