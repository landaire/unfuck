import sys
import weakref
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

S = m.socket

# A socket object without an OS socket (`sock_new` alone).
u = S.__new__(S)
fresh = [repr(u), u.family, u.type, u.proto, u.timeout, u.fileno() == -1, u.gettimeout()]
u_checks = [
    attempt(u.bind, K(('1.2.3.4', 5))), attempt(u.connect, K(('1.2.3.4', 5))), attempt(u.connect_ex, K(('a', 1))),
    attempt(u.accept), attempt(u.getsockname), attempt(u.getpeername), attempt(u.recvfrom, K(5)),
    attempt(u.recvfrom, K(-1)), attempt(u.recv, K(-1)), attempt(u.recv, K('x')), attempt(u.recv),
    attempt(u.recv_into, K('abc')), attempt(u.recv_into, K(bytearray(3)), K(-1)),
    attempt(u.recv_into, K(bytearray(3)), K(5)), attempt(u.recv_into, buffer=K(bytearray(3)), nbytes=K(5)),
    attempt(u.recv_into), attempt(u.recv_into, K(bytearray(3)), bogus=K(1)),
    attempt(u.recvfrom_into, K(bytearray(3)), K(5)), attempt(u.recvfrom_into, K(bytearray(3)), K(2)),
    attempt(u.recvfrom_into, K(bytearray(3)), K(-2)),
    attempt(u.sendto, K('a')), attempt(u.sendto, K('a'), K(1), K(2), K(3)), attempt(u.sendto, K('a'), K(('x', 1))),
    attempt(u.sendto, K(1), K(('x', 1))), attempt(u.sendto, K('a'), K('f'), K(('x', 1))), attempt(u.sendto, K('a'), x=K(1)),
    attempt(u.send, K(1)), attempt(u.send, K(u'\xe9')), attempt(u.sendall), attempt(u.send, K('a'), K('b')),
    attempt(u.getsockopt, K(1)), attempt(u.getsockopt, K(1), K(2), K(2000)), attempt(u.getsockopt, K(1), K(2), K(-1)),
    attempt(u.getsockopt, K('a'), K(2)),
    attempt(u.setsockopt, K(1), K(2), K(3.5)), attempt(u.setsockopt, K('a'), K(2), K(3)), attempt(u.setsockopt, K(1), K(2)),
    attempt(u.listen, K('x')), attempt(u.listen), attempt(u.shutdown, K(None)),
    attempt(u.settimeout, K(-1)), attempt(u.settimeout, K('x')), attempt(u.settimeout),
    attempt(u.setblocking, K('x')), attempt(u.gettimeout, K(1)), attempt(u.fileno, K(1)),
]
timeouts = []
for action, argument in [('settimeout', 2), ('settimeout', None), ('settimeout', 0.25), ('setblocking', 1),
                         ('setblocking', 0), ('setblocking', 1.5), ('setblocking', False), ('settimeout', 0)]:
    getattr(u, action)(K(argument))
    timeouts.append((u.timeout, u.gettimeout()))

closed = [u.close(), repr(u), u.close()]

attributes = [
    attempt(setattr, u, 'family', K(3)), attempt(setattr, u, 'timeout', K(1.0)), attempt(setattr, u, 'x', K(1)),
    repr(S.__dict__['timeout']), repr(S.__dict__['family']),
    S.__module__, S.__name__,
    attempt(S.__dict__['family'].__get__, K(5)),
    type(weakref.ref(u)).__name__,
]

class Sub(S):
    pass

s2 = Sub.__new__(Sub)
s2.x = K(1)
subclass = [repr(s2), s2.x, isinstance(s2, S), s2.family]

construction = [
    attempt(S, K('x')), attempt(S, K(1), K(2), K(3), K(4)), attempt(S, family=K('x')), attempt(S, foo=K(1)),
    attempt(S, K(2), family=K(2)), attempt(S, K(1.5)),
    attempt(S.__init__, K(5)), attempt(S.accept, K(5)), attempt(S.__new__, int), attempt(S.__new__),
    attempt(S.recv, K(5), K(1)),
]

# Creating a socket asks the host, which may fail: the object is unknown, so only the
# validation of the call is checked.
opened = [host(S), host(S, m.AF_INET, m.SOCK_DGRAM), host(S, proto=K(0), type=K(1)), attempt(S, family=K(None))]
v = S.__new__(S)
reinitialized = [host(S.__init__, v, K(2)), attempt(S.__init__, v, K('x')), attempt(S.__init__, v, K(1), K(2), K(3), K(4))]

RESULT = [fresh, u_checks, timeouts, closed, attributes, subclass, construction, opened, reinitialized]
