import socket, ssl, subprocess, select, mmap, signal, multiprocessing, hotshot, cProfile

windows_only = []
for name in ('_winreg', 'msvcrt', '_subprocess'):
    try:
        __import__(name)
        windows_only.append(name)
    except ImportError:
        pass

modules = [module.__name__ for module in (socket, ssl, subprocess, select, mmap, signal, multiprocessing, hotshot, cProfile)]
relations = [
    issubclass(ssl.SSLError, socket.error),
    issubclass(socket.error, IOError),
    ssl.SSLSocket.__bases__ == (socket.socket,),
    socket.socket.__name__,
    ssl.CERT_REQUIRED,
    ssl.PROTOCOL_SSLv23,
    ssl.SSLContext.__bases__[0].__name__,
    subprocess.mswindows,
    subprocess.Popen.__name__,
    signal.getsignal(signal.SIGINT) is signal.default_int_handler,
    multiprocessing.cpu_count.__name__,
    multiprocessing.BufferTooShort.__mro__[1].__name__,
    hotshot.Profile.__name__,
    cProfile.Profile.__bases__[0].__name__,
    mmap.mmap(-1, 3)[:],
]
RESULT = (modules, windows_only, relations)
