import signal

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except BaseException as e:
        return (type(e).__name__, e.args)

def describe(handler):
    if handler is None:
        return 'None'
    if handler is signal.SIG_DFL:
        return 'SIG_DFL'
    if handler is signal.SIG_IGN:
        return 'SIG_IGN'
    if handler is signal.default_int_handler:
        return 'default_int_handler'
    return 'callable'

def handler(number, frame):
    return number

class Callable(object):
    def __call__(self, number, frame):
        return number

instance = Callable()
common = [
    describe(signal.getsignal(K(2))),
    describe(signal.signal(K(2), handler)),
    signal.getsignal(K(2)) is handler,
    signal.signal(K(2), signal.SIG_IGN) is handler,
    describe(signal.getsignal(K(2))),
    describe(signal.signal(K(2), K(0))),
    describe(signal.getsignal(K(2))),
    describe(signal.signal(K(2), instance)),
    signal.getsignal(K(2)) is instance,
    describe(signal.signal(K(2), signal.default_int_handler)),
    describe(signal.getsignal(K(15))),
    describe(signal.signal(K(15), len)),
    signal.getsignal(K(15)) is len,
    describe(signal.signal(K(15), signal.SIG_DFL)),
    attempt(signal.signal, K(2), K(5)),
    attempt(signal.signal, K(2), None),
    attempt(signal.signal, K(2), K(0L)),
    attempt(signal.signal, K(2), False),
    attempt(signal.signal, K(2), 'handler'),
    attempt(signal.signal, K(2)),
    attempt(signal.signal, K(2), handler, K(3)),
    attempt(signal.signal, 'x', handler),
    attempt(signal.signal, K(2.0), handler),
    attempt(signal.signal, K(2), handler, extra=K(1)),
    describe(signal.getsignal(K(2))),
    attempt(signal.getsignal, K(0)),
    attempt(signal.getsignal, K(-1)),
    attempt(signal.getsignal),
    attempt(signal.getsignal, K(1), K(2)),
    attempt(signal.getsignal, sig=K(2)),
    attempt(signal.getsignal, K('2')),
    attempt(signal.default_int_handler),
    attempt(signal.default_int_handler, K(2), None),
    attempt(signal.default_int_handler, frame=None),
    attempt(signal.set_wakeup_fd, K(-1)),
    attempt(signal.set_wakeup_fd, K(-1)),
    attempt(signal.set_wakeup_fd, K(-5)),
    attempt(signal.set_wakeup_fd, K('x')),
    attempt(signal.set_wakeup_fd, K(1.5)),
    attempt(signal.set_wakeup_fd),
    signal.SIG_DFL, signal.SIGINT, signal.SIGILL, signal.SIGFPE, signal.SIGSEGV, signal.SIGTERM,
]

def windows():
    return [
    sorted(name for name in dir(signal) if not name.startswith('__')),
    [describe(signal.getsignal(number)) for number in range(1, signal.NSIG)],
    signal.NSIG, signal.SIGBREAK, signal.CTRL_C_EVENT, signal.CTRL_BREAK_EVENT,
    signal.SIG_IGN, type(signal.SIG_IGN).__name__, type(signal.SIG_DFL).__name__,
    attempt(signal.signal, K(0), K(0)),
    attempt(signal.signal, K(1), K(0)),
    attempt(signal.signal, K(3), handler),
    attempt(signal.signal, K(23), handler),
    attempt(signal.signal, K(13), K(5)),
    describe(signal.signal(K(21), handler)),
    describe(signal.signal(K(21), signal.SIG_DFL)),
    attempt(signal.getsignal, K(23)),
    attempt(signal.set_wakeup_fd, K(4096)),
    attempt(signal.getsignal, K(2 ** 64)),
    signal.SIGABRT,
    ]
RESULT = [common, windows()]
