# The builtins print(), bin(), and coerce().
import __builtin__

builtin_print = getattr(__builtin__, 'print')


def K(value):
    return value


def attempt(function):
    try:
        return function()
    except Exception as error:
        return (type(error).__name__, str(error))


class Writer(object):
    def __init__(self):
        self.parts = []

    def write(self, text):
        self.parts.append(text)


results = []
writer = Writer()
builtin_print(K(1), K('a'), K(2.5), file=writer)
builtin_print(K(u'\xe9'), K('b'), sep=K('-'), end=K('!'), file=writer)
builtin_print(file=writer)
builtin_print(K('x'), K('y'), sep=None, end=None, file=writer)
builtin_print(K('x'), sep=K(u'|'), file=writer)
results.append(writer.parts)
results.append(attempt(lambda: builtin_print(K('x'), sep=K(1), file=writer)))
results.append(attempt(lambda: builtin_print(K('x'), end=K(2), file=writer)))
results.append(attempt(lambda: builtin_print(K('x'), bogus=K(1))))
results.append(attempt(lambda: builtin_print(K('x'), file=K(5))))

results.append([bin(K(value)) for value in (0, 1, 5, -5, 255, 2 ** 70, -(2 ** 70), True)])
results.append(bin(K(5L)))
results.append(attempt(lambda: bin(K(1.5))))
results.append(attempt(lambda: bin(K('1'))))
results.append(attempt(lambda: bin()))


class Indexable(object):
    def __index__(self):
        return K(6)


results.append(bin(Indexable()))

results.append(coerce(K(1), K(2L)))
results.append(coerce(K(2L), K(1)))
results.append(coerce(K(1), K(2.5)))
results.append(coerce(K(1.5), K(2L)))
results.append(coerce(K(1), K(1j)))
results.append(coerce(K(True), K(3)))
results.append(attempt(lambda: coerce(K('a'), K('b'))))
results.append(attempt(lambda: coerce(K('a'), K(1))))
results.append(attempt(lambda: coerce(K(1))))
results.append(attempt(lambda: coerce(K(2 ** 2000), K(1.0))))


class Coercing(object):
    def __coerce__(self, other):
        return (K('mine'), other)


results.append(coerce(Coercing(), K(4)))
results.append(coerce(K(4), Coercing()))

RESULT = results
