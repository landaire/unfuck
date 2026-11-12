import _socket
RESULT = [
    sorted((n, v) for n, v in vars(_socket).items() if n.isupper() and isinstance(v, (int, long))),
    _socket.has_ipv6,
    _socket.SocketType is _socket.socket,
    repr(_socket.socket),
    [c.__name__ for c in _socket.error.__mro__],
    [(c.__name__, c.__module__, c.__bases__[0].__name__) for c in (_socket.error, _socket.herror, _socket.gaierror, _socket.timeout)],
    issubclass(_socket.timeout, IOError),
]
