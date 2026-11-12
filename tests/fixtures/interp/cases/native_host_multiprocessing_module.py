# _multiprocessing imports cPickle and the multiprocessing package when it
# initializes; stand-ins in sys.modules keep this case independent of them.
# Handles are high numbers that no test process has open, since the objects
# close them when collected. Instances of subclasses are not made: their
# deallocation frees them with PyObject_Del and crashes CPython.
import sys

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

class Refused(Exception):
    pass

pickled = []

def dumps(obj, protocol):
    pickled.append((obj, protocol))
    if obj == 'not a string':
        return 5
    if obj == 'unicode':
        return u'\xe9'
    raise Refused('dumps')

class Namespace(object):
    pass

fake_pickle = Namespace()
fake_pickle.dumps = dumps
fake_pickle.loads = lambda data: data
fake_pickle.HIGHEST_PROTOCOL = 2
fake_package = Namespace()
fake_package.BufferTooShort = Refused
sys.modules['cPickle'] = fake_pickle
sys.modules['multiprocessing'] = fake_package

import _multiprocessing as M

C = M.Connection

class Sub(C):
    pass

def connection_checks():
    c = C(K(1001), writable=False)
    w = C(1001, readable=K(0))
    rw = C(1003)
    states = [repr(c), repr(w), repr(rw), (rw.closed, rw.readable, rw.writable, rw.fileno()),
              (c.closed, c.readable, c.writable), (w.closed, w.readable, w.writable),
              repr(C(1004, 0)), repr(C(1004, 1, 0)), Sub.__mro__ == (Sub, C, object)]
    closed = C(1006)
    closed_states = [closed.close(), closed.closed, attempt(closed.fileno), repr(closed), closed.close(),
                     closed.readable, closed.writable]
    constructor = [
        attempt(C), attempt(C, 1001, 0, 0), attempt(C, 1001, readable='x'), attempt(C, 1001, foo=1),
        attempt(C, 1, 2, 3, 4), attempt(C, 1001, 1.5), attempt(C, handle=1001, writable=[]),
    ]
    checks = [
        attempt(c.send_bytes, 'abc'), attempt(c.send, 1), attempt(w.recv_bytes), attempt(w.recv),
        attempt(w.poll, 'x'), attempt(w.recv_bytes_into, 1),
        attempt(w.send_bytes), attempt(w.send_bytes, 1), attempt(w.send_bytes, 'abc', -1),
        attempt(w.send_bytes, 'abc', 4), attempt(w.send_bytes, 'abc', 1, -1),
        attempt(w.send_bytes, 'abc', 1, 3), attempt(w.send_bytes, 'abc', 1.0),
        attempt(w.send_bytes, bytearray('ab'), 3), attempt(w.send_bytes, 'a', kw=1),
        attempt(w.send_bytes, u'abc', 4), attempt(w.send_bytes, 'abc', 0, 1, 2),
        attempt(w.send), attempt(w.send, 1, 2), attempt(w.send, x=1), attempt(w.fileno, 1),
        attempt(w.close, 1), attempt(w.recv, 1),
        attempt(c.recv_bytes, -1), attempt(c.recv_bytes, 1, 2), attempt(c.recv_bytes, 'x'),
        attempt(c.recv_bytes_into), attempt(c.recv_bytes_into, 'abc'),
        attempt(c.recv_bytes_into, bytearray(3), -1), attempt(c.recv_bytes_into, bytearray(3), 4),
        attempt(c.poll, 1, 2), attempt(c.poll, 'x'), attempt(c.poll, timeout=1),
        attempt(C.close, 1), attempt(C.close), attempt(C.closed.__get__, 1),
        attempt(C.__repr__, 1), attempt(setattr, rw, 'x', 1), attempt(setattr, rw, 'closed', 1),
    ]
    sends = [attempt(w.send, K('data')), attempt(w.send, 'not a string'), attempt(w.send, 'unicode'),
             attempt(w.send_bytes, K(u'\xe9')), attempt(c.send_bytes, u'\xe9'), pickled]
    import weakref
    reference = weakref.ref(rw)
    states.append(reference() is rw)
    return [states, closed_states, constructor, checks, sends]

def semlock_checks():
    S = M.SemLock
    return [
        attempt(S), attempt(S, 'x', 1, 1), attempt(S, 1, 'x', 1), attempt(S, 1, 1, 1, 5),
        attempt(S, 5, 1, 1), attempt(S, -1, 1, 1), attempt(S, 1, 1, 1, foo=2), attempt(S, kind=1),
        attempt(S._rebuild), attempt(S.acquire, 1), attempt(S.release, 1),
        attempt(S._count, 1), attempt(S.handle.__get__, 1), attempt(S.kind.__get__, 1),
        type(S.handle).__name__, type(S._rebuild).__name__,
        [name for name in dir(S) if not name.startswith('__')], S.SEM_VALUE_MAX,
    ]

def windows_checks():
    S = M.SemLock
    r = S._rebuild(K(12345), 0, 7)
    s = S._rebuild(2 ** 64 + 9, 1, 3)
    rebuilt = [type(r).__name__, r.handle, r.kind, r.maxvalue, r._count(), r._is_mine(),
               attempt(r.release), attempt(r.__exit__, 1, 2, 3), r._after_fork(), r._count(),
               s.handle, s.kind, attempt(s.acquire, block='x'), attempt(s.acquire, timeout='x'),
               attempt(s.acquire, 1, 1e10), attempt(s.acquire, 1, 1, 1), attempt(s.__enter__, foo=1),
               attempt(s.__exit__, k=1), attempt(setattr, s, 'kind', 1),
               attempt(S._rebuild, 'x', 1, 2), attempt(S._rebuild, 1, 'x', 2), attempt(S._rebuild, 1, 2),
               attempt(S._rebuild, 1, 1, K(2 ** 31))]
    W = M.win32
    win32 = [
        sorted((name, str(getattr(W, name))) for name in dir(W) if name.isupper()),
        sorted(name for name in dir(W) if not name.startswith('_') and not name.isupper()),
        repr(W), attempt(W), attempt(type, 'X', (W,), {}),
        attempt(W.CloseHandle), attempt(W.CloseHandle, 'x'), attempt(W.CloseHandle, 1, 2),
        attempt(W.CloseHandle, 1.5), attempt(W.CloseHandle, x=1),
        attempt(W.ConnectNamedPipe, 1), attempt(W.ConnectNamedPipe, 1, 'x'),
        attempt(W.CreateFile, 'a', 1, 2, 3, 4, 5), attempt(W.CreateFile, 1, 1, 2, 3, 4, 5, 6),
        attempt(W.CreateFile, 'a', 'b', 2, 3, 4, 5, 6), attempt(W.CreateNamedPipe, 'a'),
        attempt(W.CreateNamedPipe, None, 1, 2, 3, 4, 5, 6, 7),
        attempt(W.ExitProcess), attempt(W.ExitProcess, 'x'), attempt(W.ExitProcess, 1.5),
        attempt(W.OpenProcess, 1, 'x', 2), attempt(W.OpenProcess, 1), attempt(W.OpenProcess, 'x', 1, 2),
        attempt(W.SetNamedPipeHandleState, 1, 'x', None, None), attempt(W.SetNamedPipeHandleState, 1, None, None),
        attempt(W.SetNamedPipeHandleState, 1, None, None, float('nan')),
        attempt(W.SetNamedPipeHandleState, 1, None, None, float('inf')),
        attempt(W.WaitNamedPipe, 'a', 'b'), attempt(W.WaitNamedPipe, None, 1), attempt(W.GetLastError, x=1),
    ]
    P = M.PipeConnection
    p = P(1007, writable=False)
    pipes = [repr(p), (p.closed, p.readable, p.writable, p.fileno()), p.close(), repr(p), attempt(p.fileno),
             attempt(P), attempt(P, 'x'), attempt(P, 1007, 0, 0), attempt(P.close, C(1008)),
             attempt(C.close, P(1008)), P.__doc__ == C.__doc__, P.__mro__ == (P, object)]
    handles = [attempt(C, 'x'), attempt(C, 5.0), attempt(C, -1L), attempt(C, 2 ** 63), attempt(C, 2 ** 64 - 2),
               repr(C(2 ** 64 + 1009)), C(2 ** 64 + 1009).fileno(), attempt(C, 2 ** 70 - 1),
               attempt(C(1010).send_bytes, u'abc', 0, 2 ** 70),
               repr(C(K(2 ** 31 + 1009))), C(2 ** 31 + 1009).fileno(), attempt(C, K(-2 ** 31))]
    buffers = [attempt(M.address_of_buffer, 'abc'), attempt(M.address_of_buffer, 1),
               attempt(M.address_of_buffer), attempt(M.address_of_buffer, 1, 2),
               attempt(M.address_of_buffer, u'ab'),
               attempt(M.address_of_buffer, memoryview(bytearray(3))), attempt(M.address_of_buffer, x=1),
               len(M.address_of_buffer(bytearray(5))), M.address_of_buffer(bytearray(5))[1],
               M.address_of_buffer(bytearray())[1]]
    module = [sorted(name for name in dir(M) if not name.startswith('__')), M.flags, M.__doc__]
    return [rebuilt, win32, pipes, handles, buffers, module]

common = [connection_checks(), semlock_checks()]
RESULT = [common, windows_checks()]
