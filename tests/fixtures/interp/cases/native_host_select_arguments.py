import select

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)

class Negative(object):
    def fileno(self):
        return -3

class Text(object):
    def fileno(self):
        return 'x'

class Huge(object):
    def fileno(self):
        return 2 ** 40

class Failing(object):
    def fileno(self):
        raise KeyError('fileno')

class Raising(object):
    @property
    def __int__(self):
        raise KeyError('__int__')

class Classic:
    def __float__(self):
        return 'x'

def empty_sets():
    # Winsock rejects three empty sets with WSAEINVAL; the message text is the host's.
    try:
        select.select([], [], [], 0)
    except select.error as e:
        return (type(e).__name__, e.args[0])

RESULT = [
    attempt(select.select, [], [], [], K('x')), attempt(select.select, [], [], [], K(1e300)),
    attempt(select.select, [], [], [], K(2 ** 70)), attempt(select.select, [], [], [], K(3j)),
    attempt(select.select, [], [], [], Classic()), attempt(select.select, [], [], [], Raising()),
    attempt(select.select, K(1), [], []), attempt(select.select, [], K(None), []),
    attempt(select.select, [Negative()], [], []), attempt(select.select, [Text()], [], []),
    attempt(select.select, [Huge()], [], []), attempt(select.select, [K(-1)], [], []),
    attempt(select.select, [K(2 ** 40)], [], []), attempt(select.select, [Failing()], [], []),
    attempt(select.select, [], [], [K(-5)]), attempt(select.select, (K(-2),), [], []),
    attempt(select.select, [], []), attempt(select.select, [], [], [], K(1), K(2)),
    attempt(select.select, [], [], [], timeout=K(1)), attempt(select.select, [K(-1)], [], [], K('x')),
    empty_sets(), attempt(select.select, [], [], [], K(2 ** 31)), attempt(select.select, [K(0)] * 513, [], [], 0),
    select.error.__module__, [c.__name__ for c in select.error.__mro__],
    sorted(name for name in dir(select) if not name.startswith('_')),
]
