# The exception classes of Objects/exceptions.c: their fields, __init__
# argument handling, __str__ forms, pickling support, and class
# attributes.
import exceptions


def K(value):
    return value


def attempt(function):
    try:
        return function()
    except Exception as error:
        return (type(error).__name__, str(error))


results = []
results.append(attempt(lambda: UnicodeEncodeError(K('a'))))
results.append(attempt(lambda: UnicodeEncodeError(K(1), u'x', 0, 1, 'r')))
results.append(attempt(lambda: UnicodeEncodeError('a', K('x'), 0, 1, 'r')))
results.append(attempt(lambda: UnicodeEncodeError('a', u'x', K(1.5), 1, 'r')))
results.append(attempt(lambda: UnicodeEncodeError('a', u'x', K('q'), 1, 'r')))
results.append(attempt(lambda: UnicodeEncodeError('a', u'x', 0, 1, K(5))))
results.append(attempt(lambda: UnicodeDecodeError('a', K(u'x'), 0, 1, 'r')))
results.append(attempt(lambda: UnicodeTranslateError(u'x', 0, 1, K(5))))
results.append(attempt(lambda: ValueError(x=K(1))))

error = UnicodeEncodeError('a', K(u'xyz'), 0, 1, 'r')
error.start = K(1.7)
results.append((error.start, error.args))
results.append(attempt(lambda: setattr(error, 'start', K('x'))))
results.append(attempt(lambda: delattr(error, 'start')))
del error.reason
results.append(attempt(lambda: str(error)))
results.append((error.encoding, error.object, error.start, error.end, error.reason))

results.append(attempt(lambda: str(IOError(2, 'no', K(u'f')))))
results.append(attempt(lambda: str(IOError(2, K(u'n\xe9')))))
environment = IOError(K(2), 'missing', 'name.txt')
results.append((str(environment), environment.errno, environment.strerror, environment.filename, environment.args, environment.__reduce__()))
environment.filename = None
results.append(str(environment))
del environment.filename
results.append((str(environment), environment.filename))
results.append((IOError(K(1)).errno, str(OSError(1, 2, 3, 4)), OSError(1, 2, 3, 4).errno))

for arguments in [(K(2), 'missing', 'f.txt'), (K(5), 'denied'), (K(123456), 'x'), (K(1),), ()]:
    windows = WindowsError(*arguments)
    results.append((str(windows), windows.errno, windows.winerror, windows.strerror, windows.filename, windows.args,
                    windows.__reduce__()))
results.append((WindowsError.__mro__, issubclass(WindowsError, OSError)))

# The base name splits at the platform separator, a backslash on Windows.
results.append(attempt(lambda: str(SyntaxError('m', ('c.py', K(3), 1, 't')))))
results.append(attempt(lambda: str(SyntaxError('m', (K('a\\b\\c.py'), 3, 1, 't')))))
results.append(attempt(lambda: str(SyntaxError('m', (K('a/b/c.py'), 3, 1, 't')))))
results.append(attempt(lambda: SyntaxError('m', (1, 2))))
syntax = SyntaxError(K('m'))
results.append((syntax.msg, syntax.filename, syntax.lineno, syntax.text, syntax.print_file_and_line, str(syntax)))
syntax.lineno = K(4)
results.append(str(syntax))

results.append(attempt(lambda: (ValueError(K('a')).__reduce__(), IOError(1, 'a', 'f').__reduce__())))
value = ValueError(K(1))
value.__dict__
results.append(value.__reduce__())
results.append(attempt(lambda: ValueError.__new__(KeyError)))
results.append(attempt(lambda: ValueError.__init__(K(5))))
results.append(attempt(lambda: BaseException.__getslice__(ValueError(1, 2, 3), K(-2), 9)))
message = ValueError(K('m'))
del message.message
results.append(attempt(lambda: message.message))
message.message = K('again')
results.append((message.message, message.__dict__, message.args))
results.append(attempt(lambda: unicode(KeyError(K(u'\xe9')))))
results.append(attempt(lambda: str(KeyError(K('k')))))
results.append(attempt(lambda: int(ValueError())))
results.append(attempt(lambda: ValueError().__setstate__(K(5))))
restored = ValueError()
restored.__setstate__({'flag': K(1)})
results.append(restored.__dict__)
results.append(attempt(lambda: str(UnicodeDecodeError('utf8', K('ab'), 1, 2, 'bad'))))
results.append(attempt(lambda: str(UnicodeTranslateError(K(u'ab'), 0, 2, 'bad'))))
results.append(attempt(lambda: KeyError.__str__(ValueError('x'))))
results.append((SystemExit(K(1), 2).code, SystemExit().code, SystemExit(K(3)).code))
results.append((ValueError.__module__, int.__module__, type(None).__module__, ValueError.__name__, ValueError.__bases__, ValueError.__mro__))
results.append(attempt(lambda: setattr(int, '__module__', 'x')))
results.append(attempt(lambda: setattr(type('C', (object,), {}), '__doc__', 'x')))
results.append(sorted(key for key in exceptions.BaseException.__dict__))
results.append(sorted(key for key in exceptions.EnvironmentError.__dict__))
results.append(sorted(key for key in exceptions.UnicodeEncodeError.__dict__))
results.append(sorted(key for key in exceptions.SystemExit.__dict__))
results.append(sorted(key for key in exceptions.KeyError.__dict__))
results.append(sorted(key for key in exceptions.ValueError.__dict__))
results.append(repr(exceptions.EnvironmentError.__dict__['errno']))
results.append(type(ValueError.__dict__['__new__']).__name__)


class Custom(ValueError):
    def __str__(self):
        return u'custom'


results.append((str(Custom()), unicode(Custom()), Custom(K(1)).__reduce__()))


state = ValueError()
state.__setstate__({u'name': K(1)})
results.append(state.__dict__)
results.append(str(UnicodeEncodeError(K('x\xff'), u'a', 0, 1, K('r\xfe'))))


class Intish(object):
    def __int__(self):
        return K(7)


class Both(object):
    def __int__(self):
        return K(7)

    def __long__(self):
        return K(8L)


# On Windows x64 `PyInt_AsSsize_t` prefers `__long__`.
both = UnicodeEncodeError('x', u'abcdefghij', 0, 9, 'r')
both.end = Both()
both.start = Both()
results.append((both.end, both.start, str(both)))
offset = UnicodeEncodeError('x', u'abcdefghij', 0, 9, 'r')
offset.end = Intish()
results.append(offset.end)
results.append(attempt(lambda: type.__dict__['__bases__'].__set__(ValueError, (object,))))
results.append(attempt(lambda: type.__dict__['__name__'].__set__(int, 'x')))
results.append(attempt(lambda: type.__dict__['__module__'].__set__(int, 'x')))
results.append(attempt(lambda: setattr(int, 'extra', 1)))


class Meta(type):
    @property
    def __doc__(cls):
        return K('meta doc')


class WithMeta(object):
    __metaclass__ = Meta


results.append(WithMeta.__doc__)
results.append([attempt(lambda: coerce(a, b)) for a, b in [([], []), ((), ()), (None, None), (bytearray(), bytearray())]])
results.append(attempt(lambda: coerce(set(), set())))
results.append(attempt(lambda: coerce(K(u'a'), K(u'b'))))

RESULT = results
